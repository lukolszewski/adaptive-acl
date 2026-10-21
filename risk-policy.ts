/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Deterministic auto-mode risk policy (docs/CLASSIFIER-SPEC.md §2).
 *
 * evaluateToolCall(tool, input, ctx) → PolicyDecision
 *
 * Bash is parsed with tree-sitter-bash and walked under docs/LAYER0-WALKER-SPEC.md
 * (bash-ast.ts → bash-walker.ts), which yields a trustworthy argv per simple command and
 * refuses to produce one at all (`unproven`) for anything it cannot prove literal.
 * Each simple command is then classified by a verb handler (risk-handlers.ts), `cd`
 * updates the effective cwd, and the compound result is the most restrictive segment.
 *
 * Two exits when the AST will not vouch for the structure:
 *   - `malformed` (unterminated quote, control characters, over-long input) →
 *     `unparseable: true`, the existing fix-and-retry path;
 *   - otherwise → an `unknown` `unproven_structure` segment, so the effect model judges
 *     it. The legacy lexer engine still runs, but **escalation only**: its `ask`/`never`
 *     verdicts survive, its `allow` verdicts are demoted to `unknown`. It can never
 *     lower a tier and can never authorise a command the AST does not understand.
 */

import path from "node:path"
import { existsSync, readFileSync } from "node:fs"
import { lexShellChecked, type SimpleCommand, type Word } from "./shell-lexer.ts"
import { parseBashCommand, toLegacyCommand, type AstCommand } from "./bash-ast.ts"
import { analyzerDownNotice, isAnalyzerDownReason, PARSER_UNAVAILABLE_REASON } from "./bash-parser.ts"
import { classifyPath, displayPath, expandTilde, type PathClass, type PathContext } from "./risk-paths.ts"
import { classifyVerb, type HandlerContext } from "./risk-handlers.ts"

export type Tier = "allow" | "ask" | "never" | "unknown"

/** "target"/"scope" drive prompts, grant options and grant matching. "path"
 *  marks files an ALLOW-tier segment touches — consulted ONLY by the ledger's
 *  named-forbid scan ("do not delete X" must bind even where the tables say
 *  allow); every other consumer filters on target/scope and ignores it. */
export type Entity = { kind: "target" | "scope" | "path"; value: string }

export type SegmentDecision = {
	tier: Tier
	/** Category from the spec tables (e.g. delete_recursive, read_only, unknown_command). */
	category: string
	entities: Entity[]
	/** One line, plain words, for prompts and for the model ("recursively delete ./build"). */
	description: string
	/** Segment text (for the model on unknown, for the prompt otherwise). */
	command: string
	/** Inline code (heredoc / -c) for unknown interpreter segments. */
	inlineCode?: string
}

export type PolicyDecision = {
	tier: Tier
	category: string
	entities: Entity[]
	description: string
	reason: string
	segments: SegmentDecision[]
	/** Segments that need the model (tier === "unknown"). */
	unknown: SegmentDecision[]
	/** The command could not be tokenised cleanly (unterminated quote/heredoc/
	 *  substitution). The segment list is unreliable — the gate should refuse and
	 *  ask the model to fix/simplify, not trust the fabricated segments. */
	unparseable?: boolean
}

export type PolicyOptions = {
	cwd: string
	project?: string
	home?: string
	env?: Record<string, string | undefined>
	/** Current git branch of the session (pi's sessionManager.getGitBranch), so a bare `git push` names its target. */
	gitBranch?: string
	/** Filesystem probes (package.json scripts, node_modules/.bin) — disable in tests. */
	fs?: boolean
	/** Recursion guard. */
	depth?: number
	/**
	 * A parse the caller already holds, so the hot path does not walk the same command twice. Must be the
	 * parse of `command` — the only caller is `bash-audit.ts`, which parses once and threads the result here.
	 * Without this, `auditBashCommand` and `evaluateBash` each ran the walker on the same string, which is not
	 * only wasted work: the two runs could disagree if one hit `parser-unavailable` while the other did not,
	 * i.e. two different verdicts for one command.
	 */
	preParsed?: ReturnType<typeof parseBashCommand>
}

const TIER_RANK: Record<Tier, number> = { allow: 0, ask: 1, unknown: 2, never: 3 }

export function mergeDecisions(segs: SegmentDecision[], commandText: string): PolicyDecision {
	if (segs.length === 0) {
		const d: SegmentDecision = { tier: "unknown", category: "unknown_command", entities: [], description: `run \`${commandText}\``, command: commandText }
		return { tier: "unknown", category: d.category, entities: [], description: d.description, reason: "could not parse command", segments: [d], unknown: [d] }
	}
	let top = segs[0]!
	for (const s of segs) if (TIER_RANK[s.tier] > TIER_RANK[top.tier]) top = s
	// `unknown` sorts above `ask` here (it may need a model call) but is *weaker* at the
	// gate: a classifier can wave it through, whereas `ask` needs a human. The gate
	// re-applies that floor from the residual segments, so an `ask` segment hidden under
	// an `unknown` top must still show in what we report — otherwise the prompt the user
	// sees describes only the innocent half of the command.
	const same = top.tier === "unknown" ? segs.filter((s) => s.tier === "unknown" || s.tier === "ask") : segs.filter((s) => s.tier === top.tier)
	const entities = dedupeEntities(same.flatMap((s) => s.entities))
	const categories = [...new Set(same.map((s) => s.category))]
	const description = same.length === 1 ? top.description : same.map((s) => s.description).join("; ")
	return {
		tier: top.tier,
		category: categories.join("+"),
		/** Strictest segment irrespective of merge order — the gate's floor. */
		entities,
		description,
		reason: `${top.tier}: ${description}`,
		segments: segs,
		unknown: segs.filter((s) => s.tier === "unknown"),
	}
}

export function dedupeEntities(list: Entity[]): Entity[] {
	const seen = new Set<string>()
	const out: Entity[] = []
	for (const e of list) {
		const k = `${e.kind}:${e.value}`
		if (!seen.has(k) && e.value) { seen.add(k); out.push(e) }
	}
	return out
}

export function seg(tier: Tier, category: string, description: string, command: string, entities: Entity[] = [], extra?: Partial<SegmentDecision>): SegmentDecision {
	return { tier, category, description, command, entities: dedupeEntities(entities), ...extra }
}

export const target = (v: string): Entity => ({ kind: "target", value: v })
export const scope = (v: string): Entity => ({ kind: "scope", value: v })
export const pathTouched = (v: string): Entity => ({ kind: "path", value: v })

// ------------------------------------------------------------------ tool-level

const READ_TOOLS = new Set(["read", "grep", "find", "ls", "glob", "web_search", "web_read", "fetch", "web_fetch", "plan_ready", "todo", "todo_read", "todo_write", "list_skills", "memory_search", "think"])

export function evaluateToolCall(tool: string, input: Record<string, unknown>, opts: PolicyOptions): PolicyDecision {
	try {
		return evaluateToolCallInner(tool, input, opts)
	} catch (err) {
		const text = `${tool} ${safeJson(input)}`
		return mergeDecisions([seg("unknown", "unknown_tool", `call tool ${tool} (policy error: ${String(err).slice(0, 80)})`, text)], text)
	}
}

function safeJson(v: unknown): string {
	try { return JSON.stringify(v)?.slice(0, 800) ?? "" } catch { return "" }
}

function evaluateToolCallInner(tool: string, input: Record<string, unknown>, opts: PolicyOptions): PolicyDecision {
	const ctx = makeCtx(opts)
	if (tool === "bash") {
		return evaluateBash(String(input.command ?? ""), opts)
	}
	if (tool === "edit" || tool === "write") {
		const p = String(input.path ?? "")
		const content = typeof input.content === "string" ? input.content : typeof input.new_string === "string" ? input.new_string : ""
		const pc = classifyPath(p, ctx)
		const d = decideWrite(pc, ctx, tool, content)
		return mergeDecisions([d], `${tool} ${p}`)
	}
	if (tool === "read" || tool === "grep" || tool === "find" || tool === "ls" || tool === "glob") {
		const p = String(input.path ?? input.file ?? "")
		if (p) {
			const pc = classifyPath(p, ctx)
			if (pc.isSecret) return mergeDecisions([seg("ask", "read_secret", `read secret-bearing path ${displayPath(pc, ctx)}`, `${tool} ${p}`, [target(displayPath(pc, ctx))])], `${tool} ${p}`)
		}
		return mergeDecisions([seg("allow", "read_only", `${tool} ${p || "(project)"}`, `${tool} ${p}`)], `${tool} ${p}`)
	}
	if (READ_TOOLS.has(tool)) {
		return mergeDecisions([seg("allow", "read_only", `${tool}`, tool)], tool)
	}
	// Unknown tool → the model sees the JSON input.
	const text = `${tool} ${JSON.stringify(input).slice(0, 1500)}`
	return mergeDecisions([seg("unknown", "unknown_tool", `call tool ${tool}`, text)], text)
}

/** The project root layer 0 resolved its entities against. Grant matching MUST use this exact value:
 *  entities are rendered project-relatively (`./a/b`), so a matcher given a different root silently
 *  resolves them somewhere else and every in-project grant misses. */
export function policyProject(opts: PolicyOptions): string {
	return path.resolve(opts.project ?? opts.cwd)
}

function makeCtx(opts: PolicyOptions): PathContext {
	const home = opts.home ?? process.env.HOME ?? "/nonexistent"
	return { cwd: path.resolve(opts.cwd), project: policyProject(opts), home }
}

export function decideWrite(pc: PathClass, ctx: PathContext, verb: string, content?: string): SegmentDecision {
	const disp = displayPath(pc, ctx)
	const cmd = `${verb} ${pc.raw}`
	if (pc.unresolvedRoot) return seg("ask", "write_outside", `${verb} to unresolved path ${pc.raw}`, cmd, [target(pc.raw)])
	if (pc.isDevice) return seg("never", "device_write", `write to device ${pc.abs}`, cmd, [target(pc.abs!)])
	if (pc.abs === "/dev/null" || pc.abs === "/dev/stdout" || pc.abs === "/dev/stderr") return seg("allow", "write_project", `${verb} ${disp}`, cmd)
	if (pc.abs && /\/\.ssh\/authorized_keys$/.test(pc.abs)) return seg("never", "persistent_access", `modify SSH authorized_keys (${disp})`, cmd, [target(disp)])
	if (pc.abs && /^\/etc\/(sudoers|passwd|shadow|fstab|gshadow)/.test(pc.abs)) {
		if (content && /NOPASSWD\s*:\s*ALL/i.test(content)) return seg("never", "privilege_persist", `grant passwordless sudo via ${disp}`, cmd, [target(disp)])
		return seg("ask", "write_sensitive", `${verb} system file ${disp}`, cmd, [target(disp)])
	}
	if (pc.isSecret) return seg("ask", "write_sensitive", `${verb} secret-bearing file ${disp}`, cmd, [target(disp)])
	if (pc.isGitInternal) return seg("ask", "write_sensitive", `${verb} inside .git (${disp})`, cmd, [target(disp)])
	// A scope entity here is what makes one approval cover the directory instead of one file. Without
	// it the dialog offers only the exact target, so four files in `deploy/systemd/` cost four prompts
	// and four rules — the shape of the complaint this branch exists to answer.
	// The secret branch above deliberately gets no scope: a folder grant over `~/.ssh` would authorise
	// credentials the user never looked at, and a `**` rule can never match a secret anyway.
	if (pc.isSensitiveConfig) return seg("ask", "write_sensitive", `${verb} sensitive config ${disp}`, cmd, [target(disp), scope(path.posix.dirname(pc.abs!) + "/")])
	// `pc.stagedConfig` arrives here too: config-shaped by name, staged inside the project, and inert
	// until an install step that the gate inspects on its own. See risk-paths.ts for the reasoning.
	if (pc.insideProject) return seg("allow", "write_project", `${verb} ${disp}`, cmd, [pathTouched(disp)])
	if (pc.isTemp) return seg("allow", "write_project", `${verb} ${disp} (temp location)`, cmd, [pathTouched(disp)])
	return seg("ask", "write_outside", `${verb} outside the project: ${disp}`, cmd, [target(disp), scope(path.posix.dirname(pc.abs!) + "/")])
}

// ------------------------------------------------------------------ bash

const MAX_DEPTH = 4

/** Argument values the parser replaced with a runtime placeholder are not literals. */
function keepEntity(e: Entity): boolean {
	return !/__CMDSUB_OUTPUT__|__TRACKED_VAR__/.test(e.value)
}

// ------------------------------------------------------------------ stored secrets in remote systems

/** Reading a stored secret out of a system that is not this filesystem. `ask`, never auto. */
export const READ_SECRET_REMOTE = "read_secret_remote"

/**
 * One way a command-line client fetches a value that is stored somewhere else.
 *
 * **The noun decides, never the output flag.** `-o jsonpath={.data.password}`, `-o yaml`, `--decode` and
 * `--with-decryption` all move the same bytes, and leaving them out does not make the call less sensitive —
 * `kubectl get secret prod-db` and `kubectl get secret prod-db -o jsonpath=…` read the same object, and the
 * value is in the response either way. An implementation that keyed on the flag would wave through the
 * default output of every client on this list, which is exactly how the gap was made.
 *
 * One row carries a flag at all — `--with-decryption` on SSM — and there it is an *extra* trigger next to the
 * name, never the only one: SSM answers `get-parameter` with ciphertext without it, while a plain-string
 * parameter called `/app/db-password` hands the value over with no flag at all, so the name must also decide.
 * The generic key/value rows (`vault kv`, `consul kv`) have no secret noun — their noun is `kv` — so there the
 * entry's own name is the only thing that tells `consul kv get config/app` from `consul kv get secret/db/password`.
 */
type StoreRead = {
	/** argv[0] basenames whose grammar this row describes. */
	clients: readonly string[]
	/**
	 * Consecutive operand words that put the call on a stored value. `a|b` offers alternatives; a trailing group
	 * suffix counts as the word before the dot (`secrets.v1` is `secrets`), a slash form carries its own entry
	 * name (`secret/db-password`), and a comma list matches on any of its parts (`secret,configmap`) — so none
	 * of the three spellings is a way around the row.
	 */
	path: readonly string[]
	/** The prompt's phrase, e.g. "read Kubernetes secret". */
	what: string
	/** How the entry is spelled in the entity a grant stores (the prefix carries the store name and the
	 *  separator); a trailing separator is dropped when the command names no entry at all. */
	entityPrefix: string
	/** Flags that carry the entry's name (`--name x` and `--name=x` both count). */
	nameFlags?: readonly string[]
	/** Otherwise the entry is the operand straight after the path words. */
	nameIsOperand?: boolean
	/** …or the first operand after them that reads like a secret, skipping option words rather than
	 *  stopping at them (`docker exec -it web cat /run/secrets/db` names the entry third). */
	nameAmongOperands?: boolean
	/** Generic key/value store: escalate on the entry's name, or on `disclosedBy`. */
	nameDecides?: boolean
	/** A flag that means the value was actually handed over (not the trigger — an additional one). */
	disclosedBy?: readonly string[]
	/** Flags whose value is appended to the entity as `@value` (namespace, project, vault). */
	scopeFlags?: readonly string[]
	/** Also treat `-A`/`--all-namespaces` as the scope, the way the kubectl table reads it. */
	allScopesFlags?: readonly string[]
}

const SECRET_STORE_READS: readonly StoreRead[] = [
	// `get`/`describe` are otherwise benign verbs — that is the whole reason this was missed. The noun is the risk.
	{ clients: ["kubectl", "oc"], path: ["get|describe", "secret|secrets"], what: "read Kubernetes secret", entityPrefix: "secret/", nameIsOperand: true, scopeFlags: ["-n", "--namespace"], allScopesFlags: ["-A", "--all-namespaces"] },
	{ clients: ["helm"], path: ["get", "values|all|manifest"], what: "read helm release values", entityPrefix: "helm-values:", nameIsOperand: true, scopeFlags: ["-n", "--namespace"] },
	{ clients: ["docker", "podman", "nerdctl"], path: ["secret|secrets", "inspect"], what: "read a container-store secret", entityPrefix: "docker-secret:", nameIsOperand: true },
	{
		// `docker exec web cat /run/secrets/db-password`: the file lives in the container's filesystem, so
		// `classifyPath` never sees it — the mounted secret has no path in our path space to be marked by.
		clients: ["docker", "podman", "nerdctl"],
		path: ["exec"],
		what: "read a mounted secret from inside a container",
		entityPrefix: "container-secret:",
		nameAmongOperands: true,
		nameDecides: true,
	},
	{ clients: ["aws"], path: ["secretsmanager", "get-secret-value|batch-get-secret-value"], what: "read an AWS Secrets Manager secret", entityPrefix: "aws-secret:", nameFlags: ["--secret-id", "--secret-id-list"] },
	{ clients: ["aws"], path: ["ssm", "get-parameter|get-parameters|get-parameters-by-path"], what: "read an SSM parameter", entityPrefix: "ssm-parameter:", nameFlags: ["--name", "--names", "--path"], nameDecides: true, disclosedBy: ["--with-decryption"] },
	{ clients: ["gcloud"], path: ["secrets", "versions", "access"], what: "read a Secret Manager version", entityPrefix: "gcloud-secret:", nameFlags: ["--secret"], scopeFlags: ["--project"] },
	{ clients: ["az"], path: ["keyvault", "secret", "show"], what: "read a Key Vault secret", entityPrefix: "keyvault-secret:", nameFlags: ["--name", "-n"], scopeFlags: ["--vault-name"] },
	{ clients: ["vault"], path: ["kv", "get|read"], what: "read a Vault KV entry", entityPrefix: "vault:", nameIsOperand: true, nameDecides: true, scopeFlags: ["-namespace", "-mount"] },
	{ clients: ["vault"], path: ["read"], what: "read a Vault path", entityPrefix: "vault:", nameIsOperand: true, nameDecides: true, scopeFlags: ["-namespace"] },
	{ clients: ["consul"], path: ["kv", "get|get-all"], what: "read a Consul KV entry", entityPrefix: "consul-kv:", nameIsOperand: true, nameDecides: true, scopeFlags: ["-namespace"] },
	{ clients: ["op"], path: ["read"], what: "read a 1Password item field", entityPrefix: "1password:", nameIsOperand: true },
	{ clients: ["op"], path: ["item", "get"], what: "read a 1Password item", entityPrefix: "1password:", nameIsOperand: true, scopeFlags: ["--vault"] },
	{ clients: ["bw"], path: ["get", "password|item|login|ssh-key|card|identity|notes"], what: "read a Bitwarden vault entry", entityPrefix: "bitwarden:", nameIsOperand: true },
	{ clients: ["pass"], path: ["show"], what: "read a pass entry", entityPrefix: "pass:", nameIsOperand: true },
	{ clients: ["security"], path: ["find-generic-password|find-internet-password|dump-keychain"], what: "read a login-keychain item", entityPrefix: "keychain:", nameFlags: ["-s", "-a", "-l"] },
]

/**
 * The cloud instance-metadata services: a link-local HTTP endpoint that hands out the credentials attached
 * to *this machine*. `curl 169.254.169.254/latest/meta-data/iam/security-credentials/app` returns live keys
 * and the curl table classifies it as a GET (`read_only`), so it needs its own row here rather than one in
 * the curl handler: the client is a browser, the store is the cloud provider.
 */
const METADATA_CLIENTS = new Set(["curl", "wget", "http", "https", "fetch"])
const METADATA_ENDPOINTS = [
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.goog",
	"metadata.microsoft.com",
	"metadata.tencentyun.com",
	"100.100.100.200", // Alibaba Cloud
]

/**
 * An entry name whose own words say it holds a credential. Only consulted for `nameDecides` rows — a
 * generic key/value store, where `secret` is nowhere in the argv. Deliberately narrow on single words:
 * `key` alone would match `monkey`, `keyboard` and `/apps/keycloak`, so it appears only in its compound
 * spellings and as a key-file extension.
 */
const SECRET_NAME_RE =
	/(secret|password|passwd|pwd|passphrase|token|credential|api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|signing[-_]?key|encryption[-_]?key|session[-_]?token|bearer|cookie|\bdsn\b|connection[-_]?string|kubeconfig|\b(otp|totp|mfa)\b|\bseed\b|private|\.key$|\.pem$|\.p12$|\.pfx$)/i

/**
 * Words whose only job is to run another command unchanged (§11.2 — the same class the verb tables peel).
 * The privilege ones are here too, and only so the noun behind them is still seen: `sudo kubectl get secret
 * prod-db` is already `ask` from the privilege escalation, and adding the store read to it costs nothing but
 * names the entry in the prompt. Recognition only — the tier still comes from the verb tables.
 */
const TRANSPARENT_WRAPPERS = new Set([
	"timeout", "time", "nice", "ionice", "nohup", "stdbuf", "setsid", "chronic", "unbuffer", "script",
	"command", "builtin", "exec", "flock", "taskset", "numactl", "strace", "ltrace", "env", "xargs",
	"sudo", "doas", "pkexec", "su",
])

/** The shape of a command word. Anything on the head of the argv that is not this — an option, an
 *  assignment, a bare duration — is an argument belonging to the wrapper in front of it. */
function couldStartACommand(word: string): boolean {
	if (word.startsWith("-")) return false
	if (word.includes("=")) return false
	return !/^\d/.test(word)
}

/** Past any run of transparent wrappers, together with the words each one owns. */
function peelTransparentWrappers(argv: readonly string[]): readonly string[] {
	let i = 0
	while (i < argv.length && TRANSPARENT_WRAPPERS.has(path.posix.basename(argv[i]!))) {
		do {
			i++
		} while (i < argv.length && !couldStartACommand(argv[i]!))
	}
	return argv.slice(i)
}

/**
 * Does one operand word satisfy a path entry? An entry accepts the bare word, an API-group spelling
 * (`secrets.v1`), the slash form the same CLIs take (`kubectl get secret/db-password`), and one name in a
 * comma list (`kubectl get secret,configmap` returns the secret's data too) — the last one also carries the
 * entry's name, which the caller reads back out of the matched token.
 */
function wordMatches(spec: string, word: string): boolean {
	return spec.split("|").some((alt) =>
		word.split(",").some((name) => name === alt || name.startsWith(alt + ".") || name.startsWith(alt + "/")),
	)
}

/**
 * Index of the last word of the path run, or -1. Only operand words are considered; an option word is
 * skipped but its value is not, because telling the two apart needs a flag table per client and a stray
 * value after the run cannot match anything the row is looking for.
 */
function findPathRun(argv: readonly string[], words: readonly string[]): number {
	const operands: number[] = []
	for (let i = 1; i < argv.length; i++) if (!argv[i]!.startsWith("-")) operands.push(i)
	outer: for (let start = 0; start + words.length <= operands.length; start++) {
		for (let k = 0; k < words.length; k++) {
			if (!wordMatches(words[k]!, argv[operands[start + k]!]!)) continue outer
		}
		return operands[start + words.length - 1]!
	}
	return -1
}

/** The value of the first of `flags` that appears, as `--flag value` or `--flag=value`. */
function flagValue(argv: readonly string[], flags: readonly string[] | undefined): string | undefined {
	if (!flags) return undefined
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!
		for (const f of flags) {
			if (a === f) return argv[i + 1] && !argv[i + 1]!.startsWith("-") ? argv[i + 1] : undefined
			if (a.startsWith(f + "=")) return a.slice(f.length + 1)
		}
	}
	return undefined
}

/** Is any of `flags` present, as `--flag` or `--flag=…`? */
function hasAnyFlag(argv: readonly string[], flags: readonly string[] | undefined): boolean {
	if (!flags) return false
	return argv.some((a) => flags.some((f) => a === f || a.startsWith(f + "=")))
}

/** The operand words after the path run, up to the first option word — the kubectl spelling, where
 *  `-o jsonpath={…}` must not be mistaken for a second secret name. */
function operandsAfter(argv: readonly string[], from: number): string[] {
	const out: string[] = []
	for (let i = from + 1; i < argv.length && !argv[i]!.startsWith("-"); i++) out.push(argv[i]!)
	return out
}

/** Every operand word after the path run, option words skipped rather than honoured as a stop. */
function allOperandsAfter(argv: readonly string[], from: number): string[] {
	const out: string[] = []
	for (let i = from + 1; i < argv.length; i++) if (!argv[i]!.startsWith("-")) out.push(argv[i]!)
	return out
}

export type StoredSecretRead = { description: string; entity: string }

/**
 * Does this argv read a stored secret out of a remote system? Returns the prompt line and the entity a
 * grant would name, or null. Takes the walker's own argv — it does not tokenise anything.
 */
export function storedSecretRead(argv: readonly string[]): StoredSecretRead | null {
	const run = peelTransparentWrappers(argv)
	const client = run.length ? path.posix.basename(run[0]!) : ""
	if (!client) return null
	for (const row of SECRET_STORE_READS) {
		if (!row.clients.includes(client)) continue
		const end = findPathRun(run, row.path)
		if (end < 0) continue
		const inline = run[end]!.includes("/") ? run[end]!.slice(run[end]!.indexOf("/") + 1) : undefined
		const named =
			flagValue(run, row.nameFlags) ??
			(inline && !inline.includes(",") ? inline : undefined) ??
			(row.nameAmongOperands ? allOperandsAfter(run, end).find(readsLikeSecret) : undefined) ??
			(row.nameIsOperand ? operandsAfter(run, end)[0] ?? allOperandsAfter(run, end)[0] : undefined)
		if (row.nameDecides && !readsLikeSecret(named) && !hasAnyFlag(run, row.disclosedBy)) continue
		const scope = flagValue(run, row.scopeFlags) ?? (hasAnyFlag(run, row.allScopesFlags) ? "ALL" : undefined)
		const entity = named ? `${row.entityPrefix}${named}${scope ? `@${scope}` : ""}` : row.entityPrefix.replace(/[:/]+$/, "")
		const description = named ? `${row.what} ${named}` : `${row.what} (the entry is not named on the command line)`
		return { description, entity }
	}
	return metadataEndpointRead(run)
}

/** A metadata-service URL on the command line is a read of the machine's own attached credentials. */
function metadataEndpointRead(argv: readonly string[]): StoredSecretRead | null {
	if (!METADATA_CLIENTS.has(argv.length ? path.posix.basename(argv[0]!) : "")) return null
	const hit = argv.slice(1).find((a) => METADATA_ENDPOINTS.some((host) => a.includes(host)))
	if (!hit) return null
	const clean = hit.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").slice(0, 96)
	return { description: `read cloud instance metadata ${clean}`, entity: `metadata:${clean}` }
}

function readsLikeSecret(name: string | undefined): boolean {
	return !!name && SECRET_NAME_RE.test(name)
}

/**
 * The remote-secret rule applied to the leg that made the call.
 *
 * Rows the verb tables already rate `ask` or `never` are kept — `kubectl delete secret x` stays where the
 * mutation tables put it — and rows they rate `allow` or `unknown` are **replaced**, not added to. That is
 * not tidiness: `unknown` sorts *above* `ask` in `TIER_RANK`, so an appended row would leave the verdict
 * `unknown` for `vault kv get secret/prod/db` and hand it to the effect model, which may wave it through.
 * Where layer 0 can name the risk it states it, and the human decides.
 */
function withStoredSecretRead(rows: SegmentDecision[], argv: string[], text: string): SegmentDecision[] {
	const hit = storedSecretRead(argv)
	if (!hit) return rows
	const kept = rows.filter((s) => s.tier === "ask" || s.tier === "never")
	return [...kept, seg("ask", READ_SECRET_REMOTE, hit.description, text, [target(hit.entity)])]
}

// ------------------------------------------------------------------ bash (AST engine)

export function evaluateBash(command: string, opts: PolicyOptions): PolicyDecision {
	const text = command.trim()
	if (!text) return mergeDecisions([seg("allow", "read_only", "empty command", "")], "")
	// Fork bomb: a function that pipes into itself and backgrounds ( :(){ :|:& };: and variants)
	const fb = /(\S+)\s*\(\)\s*\{[^}]*\1[^}]*\|[^}]*\1[^}]*&[^}]*\}/
	if (fb.test(text)) {
		return mergeDecisions([seg("never", "process_massacre", "fork bomb (self-replicating function)", text)], text)
	}
	const depth = opts.depth ?? 0
	if (depth > MAX_DEPTH) {
		// too deeply nested to analyse reliably — treat like an unparseable command
		const d = mergeDecisions([seg("ask", "unparseable_command", "command is too deeply nested to analyse", text)], text)
		return { ...d, unparseable: true, reason: "nesting too deep to classify safely" }
	}
	// Reuse the caller's parse when it has one; see PolicyOptions.preParsed.
	const ast = opts.preParsed ?? parseBashCommand(text)
	if (ast.kind === "unproven") return unprovenDecision(text, ast.reason, ast.malformed, opts)

	const base = makeCtx(opts)
	const state: WalkState = { cwd: base.cwd, vars: {}, prevArgv: null }
	const segs: SegmentDecision[] = []
	for (const c of ast.commands) {
		const ctx: PathContext = { ...base, cwd: state.cwd }
		for (const e of c.envVars) state.vars[e.name] = e.value
		const argv = c.argv.slice()
		let out: SegmentDecision[] = []
		if (argv.length === 0) {
			// assignment-only or redirect-only command: the redirects are still writes
		} else if (argv[0] === "cd" || argv[0] === "pushd") {
			const dest = argv.slice(1).find((a) => !a.startsWith("-"))
			if (dest === undefined) state.cwd = base.home
			else if (dest !== "-") state.cwd = path.resolve(state.cwd, expandTilde(dest, base.home))
			out = [seg("allow", "read_only", `cd ${dest ?? "~"}`, c.text)]
		} else {
			const hctx: HandlerContext = {
				ctx,
				opts: { ...opts, cwd: state.cwd, depth: depth + 1 },
				vars: state.vars,
				cmd: toLegacyCommand(c),
				pipedFrom: c.connector === "|" || c.connector === "|&" ? state.prevArgv : null,
				pipesTo: nextPipesTo(ast.commands, c),
				evaluateBash: (s, o) => evaluateBash(s, { ...opts, ...o, depth: depth + 1 }),
				decideWrite: (pc, verb) => decideWrite(pc, ctx, verb),
				classify: (p) => classifyPath(p, ctx),
				display: (pc) => displayPath(pc, ctx),
			}
			out = withStoredSecretRead(classifyVerb(argv, hctx), argv, c.text)
		}
		out = out.concat(astRedirectDecisions(c, ctx))
		segs.push(...(c.opaque ? opaqueSegments(out, text) : out))
		state.prevArgv = argv
	}
	return mergeDecisions(segs, text)
}

/** The next command in a pipeline that this one feeds, if any. */
function nextPipesTo(all: AstCommand[], c: AstCommand): string[] | null {
	const i = all.indexOf(c)
	const next = i >= 0 ? all[i + 1] : undefined
	return next && (next.connector === "|" || next.connector === "|&") ? next.argv : null
}

/**
 * A command whose arguments contain `__CMDSUB_OUTPUT__`/`__TRACKED_VAR__` has runtime
 * values where a literal was expected: `cat "$HOME/x"` arrives as `cat __TRACKED_VAR__/x`,
 * which would otherwise classify as a project-relative path. Allow verdicts become
 * `unknown` (the effect model decides); stricter verdicts stand.
 */
function opaqueSegments(segs: SegmentDecision[], fullCommand: string): SegmentDecision[] {
	if (segs.length === 0) return [seg("unknown", "unproven_value", "command with a runtime-determined argument", fullCommand)]
	return segs.map((s) =>
		s.tier === "allow"
			? { ...s, tier: "unknown" as const, category: "unproven_value", description: `${s.description} (argument value is runtime-determined)`, command: fullCommand, entities: s.entities.filter(keepEntity) }
			: { ...s, entities: s.entities.filter(keepEntity) },
	)
}

/**
 * The AST refused to produce argv. Either the command is broken (fix-and-retry) or it
 * uses shell structure we refuse to analyse; in the second case run the legacy engine
 * for escalation only — its `never`/`ask` verdicts survive, its `allow` verdicts do not.
 */
function unprovenDecision(text: string, reason: string, malformed: boolean, opts: PolicyOptions): PolicyDecision {
	// The engine says whether the input was malformed (fix-and-retry) or merely unproven (the
	// effect model decides). Deciding it here from the reason text would tie the policy to one
	// engine's wording, and the two walkers describe the same failure with different words.
	if (malformed) {
		const d = mergeDecisions([seg("ask", "unparseable_command", `command does not parse: ${reason}`, text)], text)
		return { ...d, unparseable: true, reason }
	}
	// A dead analyzer is not a command defect. With no grammar loaded every bash command lands here, including
	// `cat` of one literal file, and the sentence below would blame the command for the plugin's own fault.
	// The §12 id stays in the text on purpose: `reportedConstruct` reads the construct out of this description to
	// pick the advice, so a paraphrase alone would leave it guessing and hand back brace-group advice.
	const note = seg(
		"unknown",
		"unproven_structure",
		isAnalyzerDownReason(reason)
			? `${analyzerDownNotice()} — the command was never examined (${PARSER_UNAVAILABLE_REASON})`
			: `cannot verify command structure (${reason})`,
		text,
	)
	let legacy: PolicyDecision | null = null
	try {
		legacy = evaluateBashLegacy(text, { ...opts, depth: (opts.depth ?? 0) + 1 })
	} catch {
		legacy = null
	}
	if (!legacy || legacy.unparseable || legacy.segments.length === 0) return mergeDecisions([note], text)
	if (legacy.tier !== "allow") {
		// The legacy engine already found something that needs the user (or the model).
		// Keep that verdict exactly as today — unverified structure must not make a
		// command *cheaper* to approve than the tables already decided.
		const description = `${legacy.description} (command structure not verified: ${reason})`
		return { ...legacy, description, reason: `${legacy.tier}: ${description}` }
	}
	// Legacy saw nothing worth gating — but it is the engine we no longer trust for
	// structure, so "all clear" here downgrades to "the model decides".
	const escalated = legacy.segments.map((s) => ({
		...s,
		tier: "unknown" as const,
		category: "unproven_structure",
		description: `${s.description} (structure not verified: ${reason})`,
	}))
	return mergeDecisions([note, ...escalated], text)
}

function astRedirectDecisions(c: AstCommand, ctx: PathContext): SegmentDecision[] {
	const out: SegmentDecision[] = []
	for (const r of c.redirects) {
		if (r.fdDup) continue
		if (r.op === "<" || r.op === "<<<") {
			const pc = classifyPath(r.target, ctx)
			if (pc.isSecret) out.push(seg("ask", "read_secret", `read secret-bearing file ${displayPath(pc, ctx)}`, c.text, [target(displayPath(pc, ctx))]))
			continue
		}
		if (r.op === "<>") continue
		const pc = classifyPath(r.target, ctx)
		out.push(decideWrite(pc, ctx, r.op === ">>" || r.op === "&>>" ? "append to" : "write", undefined))
	}
	return out
}

// ------------------------------------------------------------------ bash (legacy lexer)

/**
 * Pre-AST engine. Retained for two jobs only: the malformed-input check inside
 * `bash-ast.ts`, and escalation on `unproven` commands (see `unprovenDecision`). Its
 * verdicts are never trusted on their own — an `allow` from here means "unknown".
 * Exported so tests can compare the two engines on one input (`risk-policy.test.ts`).
 */
export function evaluateBashLegacy(command: string, opts: PolicyOptions): PolicyDecision {
	const text = command.trim()
	if (!text) return mergeDecisions([seg("allow", "read_only", "empty command", "")], "")
	const depth = opts.depth ?? 0
	// Fail closed on genuinely malformed input (unterminated quote/heredoc/
	// substitution): the lexer would otherwise emit confident phantom segments
	// from the unparsed remainder. Refuse and let the caller ask the model to fix.
	let cmds: SimpleCommand[]
	try {
		const lexed = lexShellChecked(text)
		if (!lexed.ok) {
			const d = mergeDecisions([seg("ask", "unparseable_command", `command does not parse: ${lexed.reason}`, text)], text)
			return { ...d, unparseable: true, reason: lexed.reason ?? "command does not parse cleanly" }
		}
		cmds = lexed.commands
	} catch {
		const d = mergeDecisions([seg("ask", "unparseable_command", "command could not be parsed", text)], text)
		return { ...d, unparseable: true, reason: "command could not be parsed" }
	}
	const base = makeCtx(opts)
	const state: WalkState = { cwd: base.cwd, vars: {}, prevArgv: null }
	const segs: SegmentDecision[] = []
	for (let i = 0; i < cmds.length; i++) {
		const c = cmds[i]!
		const next = cmds[i + 1]
		const ctx: PathContext = { ...base, cwd: state.cwd }
		for (const a of c.assignments) {
			if (!a.hasExpansion) state.vars[a.name] = a.value
			else state.vars[a.name] = substituteVars(a.value, state.vars)
		}
		// substitutions run first (their output feeds the command)
		for (const sub of c.substitutions) {
			const inner = evaluateBash(sub, { ...opts, cwd: state.cwd, depth: depth + 1 })
			segs.push(...inner.segments.map((s) => ({ ...s, description: `${s.description} (in command substitution)` })))
		}
		if (c.argv.length === 0) {
			// pure assignment or redirect-only
			for (const r of c.redirects) segs.push(...redirectDecisions(c, ctx, opts))
			continue
		}
		const hctx: HandlerContext = {
			ctx, opts: { ...opts, cwd: state.cwd, depth: depth + 1 }, vars: state.vars, cmd: c,
			pipedFrom: c.connector === "|" || c.connector === "|&" ? state.prevArgv : null,
			pipesTo: next && (next.connector === "|" || next.connector === "|&") ? wordsOf(next) : null,
			evaluateBash: (s, o) => evaluateBash(s, { ...opts, ...o, depth: depth + 1 }),
			decideWrite: (pc, verb) => decideWrite(pc, ctx, verb),
			classify: (p) => classifyPath(substituteVars(p, state.vars), ctx),
			display: (pc) => displayPath(pc, ctx),
		}
		const argv = c.argv.map((w) => substituteVars(w.value, state.vars))
		// `cd` updates cwd for later segments
		if (argv[0] === "cd" || argv[0] === "pushd") {
			const dest = argv.slice(1).find((a) => !a.startsWith("-"))
			if (dest === undefined) state.cwd = base.home
			else if (dest === "-") { /* unknown previous dir; keep */ }
			else if (/^\$|`/.test(dest)) { /* unresolved; keep, but later relative paths may be wrong → handled by unresolved flag */ }
			else state.cwd = path.resolve(state.cwd, expandTilde(dest, base.home))
			segs.push(seg("allow", "read_only", `cd ${dest ?? "~"}`, c.raw))
		} else {
			segs.push(...classifyVerb(argv, hctx))
		}
		segs.push(...redirectDecisions(c, ctx, opts))
		state.prevArgv = argv
	}
	return mergeDecisions(segs, text)
}

type WalkState = { cwd: string; vars: Record<string, string>; prevArgv: string[] | null }

function wordsOf(c: SimpleCommand): string[] {
	return c.argv.map((w: Word) => w.value)
}

export function substituteVars(s: string, vars: Record<string, string>): string {
	if (!s.includes("$")) return s
	return s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a, b) => {
		const name = a ?? b
		if (name === "PWD") return "."
		if (name === "HOME") return "~"
		if (name in vars) return vars[name]!
		return m
	})
}

function redirectDecisions(c: SimpleCommand, ctx: PathContext, opts: PolicyOptions): SegmentDecision[] {
	const out: SegmentDecision[] = []
	for (const r of c.redirects) {
		const t = r.target.value
		if (r.op === "<" || r.op === "<<<") {
			const pc = classifyPath(t, ctx)
			if (pc.isSecret) out.push(seg("ask", "read_secret", `read secret-bearing file ${displayPath(pc, ctx)}`, c.raw, [target(displayPath(pc, ctx))]))
			continue
		}
		if (r.op === "<>" ) continue
		const pc = classifyPath(t, ctx)
		out.push(decideWrite(pc, ctx, r.op === ">>" || r.op === "&>>" ? "append to" : "write", undefined))
	}
	return out
}

// ------------------------------------------------------------------ fs probes (optional)

export function readPackageScript(project: string, name: string, enabled: boolean | undefined): string | null {
	if (enabled === false) return null
	try {
		const pj = path.join(project, "package.json")
		if (!existsSync(pj)) return null
		const json = JSON.parse(readFileSync(pj, "utf-8")) as { scripts?: Record<string, string> }
		const s = json.scripts?.[name]
		return typeof s === "string" ? s : null
	} catch {
		return null
	}
}

export function hasLocalBin(project: string, name: string, enabled: boolean | undefined): boolean {
	if (enabled === false) return false
	try {
		return existsSync(path.join(project, "node_modules", ".bin", name))
	} catch {
		return false
	}
}
