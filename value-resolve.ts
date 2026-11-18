/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Layer 2 of `plan-runtime-values.md`: fill in the run-time values a command carries, so the gate
 * judges the command that will actually run instead of a hole in it.
 *
 * Layer 0 refuses to call a run-time value a fact (§6.5), which is right — but it also means
 * `wc -l "$F"` is judged on a shape rather than a target. This module fills the hole when the value
 * is knowable before the command runs:
 *
 *   - a variable from the environment the bash tool hands its shell, or from an assignment written
 *     earlier in the same command (`X=$(git rev-parse HEAD); git show "$X"`);
 *   - a substitution whose own command is on the explicit read-only list below *and* that layer 0
 *     rates `allow` on its own.
 *
 * Two rules keep this from being a loosening:
 *
 *   - a substitution is executed only when its inner command is one simple command, with no
 *     redirect, no here-document, no second command, no env prefix, a verb from `READ_ONLY_VERBS`,
 *     and an `allow` verdict from `evaluateBash` in this very path space. Nothing else is ever run:
 *     no `mktemp`, no `curl`/`wget`, no interpreter, no `timeout`, nothing with a pipe into another
 *     verb. A failure, a non-zero exit or a cap hit is "not resolved", never a guess.
 *   - anything that could change how the shell reads the value refuses: an internal newline, an
 *     empty value, or an unquoted value carrying whitespace or a glob character (`*?[`), because
 *     the shell would split or match it into an argv this module did not judge.
 *
 * The concrete command is the input with each slot's span replaced by its single-quoted value, so a
 * partial slot (`"exit $X"`) keeps the literal text around it. `gate.ts` then judges that string
 * exactly like any other command; the original text is never rewritten, only judged (the shell will
 * run the substitution again, so a value can differ between this resolve and execution — the
 * read-only, deterministic list is what keeps that window small).
 *
 * Pure: no child processes and no pi imports. The runner is injected by the caller, so tests drive
 * every branch with a fake that records what it was asked to run.
 */

import { parseBashTemplate, type Slot, type TemplateCommand, type TemplateParse } from "./bash-ast.ts"
import { evaluateBash, type PolicyOptions } from "./risk-policy.ts"
import { redactForClassifier } from "./classifier-redact.ts"

/**
 * The one thing this module cannot do purely: run a command substitution. `timeoutMs` and
 * `maxBytes` are always {@link RESOLVE_TIMEOUT_MS} / {@link RESOLVE_MAX_BYTES}; stdin is closed;
 * `ok: false` covers a non-zero exit, a spawn failure and a kill for the cap alike.
 */
export type Runner = (
	script: string,
	opts: { cwd: string; timeoutMs: number; maxBytes: number },
) => Promise<{ ok: boolean; stdout: string }>

/** One filled-in value, with the expansion as it was written at the use site (`$F`, `$(git rev-parse HEAD)`). */
export type ResolvedValue = { source: string; value: string }

export type ResolveResult = { concrete: string; values: ResolvedValue[] } | { unresolved: string }

export type ResolveSpace = { cwd: string; project: string; home: string }

export type ResolveOptions = {
	/** Runs one read-only substitution. Never called for anything else. */
	run: Runner
	/** The environment the shell this command will run in receives. */
	env: Record<string, string | undefined>
	/** Where `~`, relative paths and the project boundary are for layer 0. */
	space: ResolveSpace
	/** Template parse, injectable for tests. */
	parse?: (command: string) => TemplateParse
}

export const RESOLVE_TIMEOUT_MS = 2000
export const RESOLVE_MAX_BYTES = 4096

/**
 * Verbs a substitution may run. Every entry is read-only, deterministic enough to judge, makes no
 * network call and starts no process work of its own. Deliberately absent: `mktemp` (a fresh path
 * each run is a new target every time), `curl`/`wget`, every interpreter, `timeout`, `find` (it has
 * `-exec`/`-delete`), `sed`/`awk` (they write files with `-i`/`-i inplace`).
 */
const READ_ONLY_VERBS = new Set([
	"pwd", "date", "seq", "id", "uptime", "basename", "dirname", "wc", "grep", "ls", "cat", "head",
	"tail", "uname", "hostname", "whoami", "nproc",
])

/** `git` read verbs. `diff`, `config` and `branch` are accepted only in their read-only spelling. */
const GIT_VERBS: Record<string, (args: readonly string[]) => boolean> = {
	"rev-parse": () => true,
	"merge-base": () => true,
	"ls-files": () => true,
	log: () => true,
	"rev-list": () => true,
	diff: (args) => args.includes("--name-only"),
	config: (args) => args.includes("--get"),
	branch: (args) => args.includes("--show-current"),
}

/** Layer 0's own tables, at the same path space the caller gave us, with no filesystem probes. */
function policyFor(space: ResolveSpace, env: Record<string, string | undefined>): PolicyOptions {
	return { cwd: space.cwd, project: space.project, home: space.home, env, fs: false }
}

// --------------------------------------------------------------------------- entry point

/**
 * Fill in every slot of `command`, or say why not. All-or-nothing on purpose: a partially filled
 * command would be a command nobody wrote and nobody approved.
 */
export async function resolveCommand(command: string, opts: ResolveOptions): Promise<ResolveResult> {
	const parse = opts.parse ?? parseBashTemplate
	let parsed: TemplateParse
	try {
		parsed = parse(command)
	} catch (err) {
		// The template parse is a separate walk that may not exist yet; a refusal here is "not
		// resolved", never an error the gate has to know about.
		return { unresolved: `template parse unavailable (${errText(err)})` }
	}
	if (parsed.kind !== "simple") return { unresolved: `command structure not verifiable (${parsed.reason})` }

	const slots = parsed.commands
		.flatMap((c) => c.slots)
		.slice()
		.sort((a, b) => a.span[0] - b.span[0])
	if (slots.length === 0) return { unresolved: "no run-time values" }

	const values: ResolvedValue[] = []
	const edits: Array<{ start: number; end: number; value: string }> = []
	for (const slot of slots) {
		const answer = await expandSlot(slot, command, parsed, opts)
		if (!answer.ok) return { unresolved: answer.reason }
		values.push({ source: command.slice(slot.span[0], slot.span[1]), value: answer.value })
		edits.push(replacement(slot, command, answer.value))
	}
	return { concrete: splice(command, edits), values }
}

/**
 * The span to replace and the text to put there, chosen by the quoting the slot sits in. `Slot.span`
 * covers the expansion alone (`"$F"` → `$F`), so the replacement has to be written for its context:
 *
 *   - `"$F"` (quoted, whole): the quotes go with it — `'val'` inside double quotes would be a value
 *     that literally starts with a quote;
 *   - `"exit $F"` (quoted, part of a word): the value, escaped for double quotes, so the literal text
 *     around it stays literal;
 *   - `$F` (unquoted, part of a word): one single-quoted word, which bash then reads as one word.
 */
function replacement(slot: Slot, command: string, value: string): { start: number; end: number; value: string } {
	if (!slot.quoted) return { start: slot.span[0], end: slot.span[1], value: singleQuote(value) }
	const [start, end] = slot.span
	if (slot.whole && command[start - 1] === '"' && command[end] === '"') {
		return { start: start - 1, end: end + 1, value: singleQuote(value) }
	}
	return { start, end, value: value.replace(/[\\"$`]/g, (ch) => `\\${ch}`) }
}

/** One slot's value, or the reason it stays unknown. */
async function expandSlot(
	slot: Slot,
	command: string,
	parsed: Extract<TemplateParse, { kind: "simple" }>,
	opts: ResolveOptions,
): Promise<Answer> {
	if (slot.span[0] < 0 || slot.span[1] > command.length || slot.span[1] <= slot.span[0]) {
		return { ok: false, reason: "slot span does not lie inside the command" }
	}
	// A substitution carries its own source text (`Slot.inner`), so it needs nothing from the use
	// site; a variable is looked up in the assignment before it, then in the environment.
	const value =
		slot.source === "cmdsub" ? await runReadOnly((slot.inner ?? "").trim(), opts) : await resolveVariable(slot, command, parsed, opts)
	if (!value.ok) return value
	return checkValue(slot, value.value)
}

/** `$NAME` forms this resolver will look up at all: a shell variable name and nothing else. */
const VAR_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/

type Answer = { ok: true; value: string } | { ok: false; reason: string }

// --------------------------------------------------------------------------- variables

/**
 * `$X`: the assignment written before it in this command wins (bash semantics: it shadows the
 * environment), then the environment. An assignment that exists but cannot be resolved is final —
 * falling back to the environment would judge a value the shell will never see.
 */
async function resolveVariable(
	slot: Slot,
	command: string,
	parsed: Extract<TemplateParse, { kind: "simple" }>,
	opts: ResolveOptions,
): Promise<Answer> {
	const name = slot.name ?? ""
	if (name.length === 0 || !VAR_NAME.test(name)) return { ok: false, reason: `\`${name || "?"}\` is not a name this resolver looks up` }

	// A here-document is data that happens to sit in the same string as code, and it can spell an
	// assignment as easily as anything else. The scan below reads source text, so it stays out of any
	// input that carries one rather than trying to tell the two apart by eye (`X=/tmp` inside a quoted
	// body is not an assignment, and a resolver that believed it would judge a command nobody wrote).
	if (parsed.commands.some((c) => c.heredocs.length > 0)) {
		return { ok: false, reason: "command carries a here-document, so its text is not all code" }
	}

	const before = command.slice(0, slot.span[0])
	const assigned = assignedSource(before, name)
	// Bash keeps an assignment as the shell's own value only when it is a statement of its own after `;` or a
	// newline. `X=a cmd` sets X for cmd alone, `X=a | …` and `X=a &` run in a subshell, `… && X=a` may not run,
	// and `export` / `read` / `for` / `declare` set it by other means. Any mention of the name before the slot
	// that is not the one clean assignment found (or a `$X` read) makes the value unknown: judging the
	// environment's value, or the scanned one, would judge a command the shell will not run.
	if (mentionsNameOtherwise(before, name, assigned?.at)) {
		return { ok: false, reason: `$${name} is set before this point in a way the resolver cannot follow` }
	}
	if (assigned !== null) {
		const rhs = parseAssignmentValue(assigned.word)
		if (rhs === null) return { ok: false, reason: `$${name} is assigned a value only the shell can work out` }
		if (rhs.kind === "literal") return { ok: true, value: rhs.value }
		// The assignment's own substitution has no slot of its own (see the doc comment on
		// `assignedSource`), so it is judged here exactly like a slot's would be — including the
		// check that the parse really did see this command as code and not as text inside a body.
		const seen = parsed.commands.some((c) => c.text.trim() === rhs.inner)
		if (!seen) return { ok: false, reason: `$${name} is assigned a command substitution the parse did not analyse` }
		return await runReadOnly(rhs.inner, opts)
	}

	const fromEnv = opts.env[name]
	if (fromEnv === undefined) return { ok: false, reason: `$${name} is not set in the environment the shell will get` }
	return { ok: true, value: fromEnv }
}

/**
 * The right-hand side of the last `name=` assignment written at the start of a statement before
 * `before`, as source text, or `null`.
 *
 * Why the source text and not the parse: the walker emits the commands inside a substitution
 * *before* the command that holds it (§6.2), and a statement-level assignment emits nothing at all
 * (§5.2) — so `X=$(git rev-parse HEAD); git show "$X"` arrives as [the inner command, `git show`
 * with a slot named `X`], with nothing tying the slot to the assignment. The `Slot`/`TemplateCommand`
 * types cannot express that link without a new field, so the link is recovered here from the
 * statement text, and every conclusion drawn from it is checked against the parse (the inner text
 * must be a command the parse emitted, and layer 0 must rate it allow).
 *
 * Deliberately narrow: only a statement start (`start`, or just after `;`, `&`, `|`, a newline, with
 * whitespace allowed after it) is a candidate, quotes and substitutions are skipped over rather than
 * scanned into, and a comment runs to the end of its line. `(` and `{` are *not* statement starts —
 * an assignment inside a subshell is not visible outside it. And the caller refuses to scan at all
 * when the input carries a here-document, because a body is data sitting in the same string as code.
 */
function assignedSource(before: string, name: string): { word: string; at: number } | null {
	let found: { word: string; at: number } | null = null
	let i = 0
	let atStart = true
	let cleanStart = true
	while (i < before.length) {
		const ch = before[i] as string
		if (ch === "\\") {
			i += 2
			atStart = false
			continue
		}
		if (ch === "'" || ch === '"') {
			i = skipQuoted(before, i, ch)
			atStart = false
			continue
		}
		if (ch === "`") {
			i = skipBacktick(before, i)
			atStart = false
			continue
		}
		if (ch === "$" && before[i + 1] === "(") {
			i = skipParens(before, i + 1)
			atStart = false
			continue
		}
		if (ch === "#" && atStart) {
			const nl = before.indexOf("\n", i)
			i = nl < 0 ? before.length : nl
			atStart = true
			continue
		}
		if (SEPARATOR.includes(ch)) {
			// `;` and a newline start a statement whose assignment the shell keeps; after `&`, `|`, `&&` or `||`
			// the next word starts a command too, but an assignment there is conditional or in a subshell.
			cleanStart = ch === ";" || ch === "\n"
			i += 1
			atStart = true
			continue
		}
		if (atStart && /\s/.test(ch)) {
			i += 1
			continue
		}
		if (atStart) {
			atStart = false
			if (before.startsWith(`${name}=`, i) && cleanStart) {
				const word = readWord(before, i + name.length + 1)
				let j = i + name.length + 1 + word.length
				while (j < before.length && (before[j] === " " || before[j] === "\t")) j += 1
				const rest = before.slice(j)
				// Only a statement that is the assignment alone: followed by the end, `;`, a newline, `&&` or `||`.
				// Another word makes it an env prefix; a single `|` or `&` runs it in a subshell.
				if (rest === "" || rest[0] === ";" || rest[0] === "\n" || rest.startsWith("&&") || rest.startsWith("||")) {
					found = { word, at: i }
				}
				i += name.length + 1
				continue
			}
		}
		i += 1
	}
	return found
}

const SEPARATOR = ";&|\n"

/**
 * Does `name` appear before the slot as anything other than a `$name` / `${name…}` read or the one clean
 * assignment at `cleanAt`? Deliberately crude in the strict direction: a mention inside a quoted string
 * (`echo 'X'`) also counts, which costs a prompt and never resolves a value the shell would not use.
 */
function mentionsNameOtherwise(before: string, name: string, cleanAt: number | undefined): boolean {
	const re = new RegExp(`(^|[^A-Za-z0-9_])${name}(?![A-Za-z0-9_])`, "g")
	for (const m of before.matchAll(re)) {
		const at = (m.index ?? 0) + m[1]!.length
		const prev = before[at - 1]
		if (prev === "$") continue
		if (prev === "{" && before[at - 2] === "$") continue
		if (at === cleanAt) continue
		return true
	}
	return false
}

/** One shell word starting at `start`, with quoting and substitutions kept whole. */
function readWord(s: string, start: number): string {
	let i = start
	while (i < s.length) {
		const ch = s[i] as string
		if (ch === "\\") {
			i += 2
			continue
		}
		if (ch === "'" || ch === '"') {
			i = skipQuoted(s, i, ch)
			continue
		}
		if (ch === "`") {
			i = skipBacktick(s, i)
			continue
		}
		if (ch === "$" && s[i + 1] === "(") {
			i = skipParens(s, i + 1)
			continue
		}
		if (/\s/.test(ch) || SEPARATOR.includes(ch) || "()<>".includes(ch)) break
		i += 1
	}
	return s.slice(start, i)
}

type AssignmentValue = { kind: "literal"; value: string } | { kind: "cmdsub"; inner: string }

/** A word a variable may hold, or `null` when only the shell could work it out. */
function parseAssignmentValue(word: string): AssignmentValue | null {
	const bare = unwrapQuotes(word)
	if (bare === null || bare === "") return null
	const sub = wholeSubstitution(bare)
	if (sub !== null) return { kind: "cmdsub", inner: sub.trim() }
	// A literal this resolver may stand in for: no expansion, no quote, no space, no glob, no tilde
	// (bash expands a tilde in an assignment, and this module does not re-implement that).
	return /^[A-Za-z0-9_@%+=:,./-]+$/.test(bare) ? { kind: "literal", value: bare } : null
}

/** `'x'` / `"x"` when the quotes span the whole word, else the word itself; `null` when mixed. */
function unwrapQuotes(word: string): string | null {
	const first = word[0]
	if (first !== "'" && first !== '"') return word
	const end = skipQuoted(word, 0, first)
	return end === word.length ? word.slice(1, -1) : null
}

/** `$(…)` or `` `…` `` covering the whole value, with its inside text. */
function wholeSubstitution(value: string): string | null {
	if (value.startsWith("$(")) {
		const end = skipParens(value, 1)
		return end === value.length ? value.slice(2, -1) : null
	}
	if (value.startsWith("`")) {
		const end = skipBacktick(value, 0)
		return end === value.length ? value.slice(1, -1) : null
	}
	return null
}

// --------------------------------------------------------------------------- substitutions

/**
 * The guarded execution path: a substitution is run only when its own command is one plain read-only
 * command that layer 0 rates allow here and now. Everything else — two commands, a redirect, a
 * here-document, an env prefix, a nested slot — is "not resolved" without running anything, and so is
 * an empty substitution. Nothing else in this module runs a command.
 */
async function runReadOnly(script: string, opts: ResolveOptions): Promise<Answer> {
	if (!script) return { ok: false, reason: "substitution has no command of its own" }
	const shape = onlyReadOnlyCommand(script, opts)
	if (!shape.ok) return shape
	let out: { ok: boolean; stdout: string }
	try {
		out = await opts.run(script, { cwd: opts.space.cwd, timeoutMs: RESOLVE_TIMEOUT_MS, maxBytes: RESOLVE_MAX_BYTES })
	} catch (err) {
		return { ok: false, reason: `\`${script}\` could not run (${errText(err)})` }
	}
	if (!out.ok) return { ok: false, reason: `\`${script}\` failed` }
	if (typeof out.stdout !== "string") return { ok: false, reason: `\`${script}\` produced no readable output` }
	if (Buffer.byteLength(out.stdout) > RESOLVE_MAX_BYTES) return { ok: false, reason: `\`${script}\` produced more than ${RESOLVE_MAX_BYTES} bytes` }
	// bash drops every trailing newline of a substitution's output; matching that is what makes the
	// value the one the shell would hand the command.
	return { ok: true, value: out.stdout.replace(/\n+$/, "") }
}

/** Structure and verb gate: one simple command, no redirect, no slots, a read-only verb, allow tier. */
function onlyReadOnlyCommand(script: string, opts: ResolveOptions): Answer {
	const parse = opts.parse ?? parseBashTemplate
	let parsed: TemplateParse
	try {
		parsed = parse(script)
	} catch (err) {
		return { ok: false, reason: `\`${script}\` cannot be parsed (${errText(err)})` }
	}
	if (parsed.kind !== "simple" || parsed.commands.length !== 1) {
		return { ok: false, reason: `\`${script}\` is not one simple command` }
	}
	const one = parsed.commands[0] as TemplateCommand
	if (one.slots.length > 0) return { ok: false, reason: `\`${script}\` holds a run-time value of its own` }
	if (one.envVars.length > 0) return { ok: false, reason: `\`${script}\` sets an environment variable` }
	if (one.redirects.length > 0) return { ok: false, reason: `\`${script}\` redirects` }
	if (one.heredocs.length > 0) return { ok: false, reason: `\`${script}\` reads a here-document` }
	if (one.argv.length === 0) return { ok: false, reason: `\`${script}\` runs nothing` }
	if (!readOnlyVerb(one.argv)) return { ok: false, reason: `\`${one.argv[0]}\` is not a verb this resolver runs` }
	const decision = evaluateBash(script, policyFor(opts.space, opts.env))
	if (decision.unparseable || decision.tier !== "allow") {
		return { ok: false, reason: `\`${script}\` is not allow-tier here (${decision.category})` }
	}
	return { ok: true, value: "" }
}

/** The explicit list: the verb (and, for `git`, the sub-verb) decides. Operands are layer 0's job. */
function readOnlyVerb(argv: readonly string[]): boolean {
	const verb = argv[0] ?? ""
	if (verb === "git") {
		const sub = argv[1] ?? ""
		if (sub.startsWith("-")) return false
		const test = GIT_VERBS[sub]
		return test ? test(argv.slice(2)) : false
	}
	return READ_ONLY_VERBS.has(verb)
}

// --------------------------------------------------------------------------- values and text

/** Variable names that carry credentials by convention; matched on the name, before any value is read. */
const SECRET_NAME = /(TOKEN|SECRET|PASSW|PASSPHRASE|CREDENTIAL|API_?KEY|PRIVATE|AUTH|COOKIE|SESSION|_KEY$|^KEY$)/i

/** What the shell would do with this value instead of the one this module judged. */
function checkValue(slot: Slot, value: string): Answer {
	if (value === "") return { ok: false, reason: "value is empty" }
	// A resolved value travels further than the shell: into the prompt, the denial the agent reads and the
	// safety model's request. A variable named like a credential, or a value the redaction rules would mask
	// (a token in a remote URL, a key-shaped string), stays unresolved instead of being copied into any of them.
	if (slot.source === "var" && SECRET_NAME.test(slot.name ?? "")) return { ok: false, reason: `$${slot.name} is named like a credential` }
	if (redactForClassifier(value) !== value) return { ok: false, reason: "value looks like a credential" }
	if (/[\r\n]/.test(value)) return { ok: false, reason: "value contains a line break" }
	if (!slot.quoted) {
		if (/\s/.test(value)) return { ok: false, reason: "unquoted value would be split into several words" }
		if (/[*?[]/.test(value)) return { ok: false, reason: "unquoted value would be glob-expanded" }
	}
	return { ok: true, value }
}

/** Replace each span with its single-quoted value, leaving everything between spans alone. */
function splice(command: string, edits: Array<{ start: number; end: number; value: string }>): string {
	let out = ""
	let cursor = 0
	for (const edit of edits.slice().sort((a, b) => a.start - b.start)) {
		if (edit.start < cursor) continue
		out += command.slice(cursor, edit.start) + edit.value
		cursor = edit.end
	}
	return out + command.slice(cursor)
}

/** One literal word bash reads as exactly this text: `'it'\''s'`. */
function singleQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`
}

function skipQuoted(s: string, start: number, quote: string): number {
	let i = start + 1
	while (i < s.length) {
		const ch = s[i] as string
		if (ch === "\\" && quote === '"') {
			i += 2
			continue
		}
		if (ch === quote) return i + 1
		i += 1
	}
	return s.length
}

function skipBacktick(s: string, start: number): number {
	let i = start + 1
	while (i < s.length) {
		const ch = s[i] as string
		if (ch === "\\") {
			i += 2
			continue
		}
		if (ch === "`") return i + 1
		i += 1
	}
	return s.length
}

/** `start` is the index of `(`; returns the index just past its match. */
function skipParens(s: string, start: number): number {
	let depth = 0
	let i = start
	while (i < s.length) {
		const ch = s[i] as string
		if (ch === "\\") {
			i += 2
			continue
		}
		if (ch === "'" || ch === '"') {
			i = skipQuoted(s, i, ch)
			continue
		}
		if (ch === "`") {
			i = skipBacktick(s, i)
			continue
		}
		if (ch === "(") depth += 1
		if (ch === ")") {
			depth -= 1
			if (depth === 0) return i + 1
		}
		i += 1
	}
	return s.length
}

function errText(err: unknown): string {
	return (err instanceof Error ? err.message : String(err)).slice(0, 120)
}
