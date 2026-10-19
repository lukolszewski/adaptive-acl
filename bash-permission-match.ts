/**
 * Bash permission rule matching: does a configured `Bash(...)` rule cover this command?
 * Handles whole-command, `cmd:*` prefix and glob rule bodies, and decides separately for
 * deny/ask (every segment of a compound command must be covered) and allow (single commands only).
 *
 * The matcher half of this file works from the command TEXT, which is why it carries its own scanners for
 * segments, wrappers, redirections and leading assignments. For an ALLOW rule that is the wrong
 * foundation — a compound can only be scored leg by leg, and the legs are already known properly to
 * layer 0. `bash-rule-argv.ts` is the replacement on that path: it takes the walker's argv and asks
 * whether the words a rule names sit at the front of it. Deny and ask stay here on purpose: a denial
 * has to fire even when the walker refuses to vouch for the construct, so it cannot depend on argv.
 *
 * The producer half at the bottom (`suggestBashAllowRule*`) is the other side of that same contract, and it
 * reads layer 0 for the same reason: a specifier written from a re-split of the text can name words the call
 * never passed, and a rule that can never match is an "Always allow" that silently does nothing. Both
 * producers only describe the approval — whether it can be honoured is decided in `permissions.ts`, which
 * runs the written rules back through the matcher that will have to accept them.
 */

import { homedir } from "node:os"
import { splitShellSegments } from "./utils.ts"
import {
	matchShellRule,
	parsePermissionRule,
	type ShellPermissionRule,
} from "./shell-rule-matching.ts"
import { parseBashCommand, type AstCommand, type AstParse, type AstRedirect } from "./bash-ast.ts"
import { initBashParser, isBashParserReady } from "./bash-parser.ts"
import { categoryHasStrictOperands, envChangesExecution, fileRedirects } from "./bash-audit.ts"
import { implicitDescriptor } from "./bash-rule-argv.ts"
import { evaluateBash } from "./risk-policy.ts"
import { permissionRuleValueToString } from "./permission-rule-parser.ts"

const SAFE_WRAPPER_PREFIXES = [
	/^timeout(?:\s+\d+[smhd]?)?\s+/i,
	/^time\s+-p\s+/i,
	/^nice\s+-n\s+\d+\s+/i,
	/^nohup\s+/i,
]

const SAFE_ENV_VARS = new Set([
	"NODE_ENV",
	"RUST_BACKTRACE",
	"RUST_LOG",
	"PYTHONUNBUFFERED",
	"LANG",
	"LC_ALL",
	"TERM",
	"NO_COLOR",
	"FORCE_COLOR",
	"TZ",
])

// ── Leading `NAME=value` assignments ────────────────────────────────────────
// Recognised by scanning characters, one rule per branch, so that the behaviour
// pinned in bash-permission-match.test.ts reads as code instead of living inside
// one alternation. The accepted form is:
//
//   NAME    an identifier, optionally with an `[index]`, optionally with `+`
//           before the `=`
//   `=`
//   VALUE   any run of plain characters, `'…'` runs (no line break inside),
//           `"…"` runs (escapes allowed, but no `$`, backtick or line break
//           inside) and `\c` escapes, in any order — so `a"b c"d` is one value
//   BLANK   at least one space or tab, because with no command behind it the
//           text IS the command and must not be stripped
//
// Whatever the value cannot contain simply ends it, and that is the whole reason
// `FOO=a;b cmd`, `FOO=a<b cmd` and `FOO=$(x) cmd` are left alone: the value stops
// on a shell separator or a run-time value, so no blank follows and there is no
// *leading* assignment here — even though a shell would split those the same way.

/** What ends an unquoted value: whitespace plus every character that would start
 *  something else in the shell (expansion, separator, redirect, group). */
const VALUE_TERMINATORS = " \t\n\r$`;|&()<>\\'\""

function isLowerLetter(ch: string): boolean {
	return ch >= "a" && ch <= "z"
}

function isDigit(ch: string): boolean {
	return ch >= "0" && ch <= "9"
}

function isNameStart(ch: string): boolean {
	return isLowerLetter(ch) || (ch >= "A" && ch <= "Z") || ch === "_"
}

function isBlank(ch: string): boolean {
	return ch === " " || ch === "\t"
}

/** An escape never swallows a line break — an assignment cannot span lines. */
function isLineBreak(ch: string): boolean {
	return ch === "\n" || ch === "\r" || ch === "\u2028" || ch === "\u2029"
}

/** `ch` may sit in a value unquoted. `""` is end of text, which is a stop. */
function isPlainValueChar(ch: string): boolean {
	return ch !== "" && !VALUE_TERMINATORS.includes(ch)
}

/** Read `NAME` starting at `from`; `at` lands just past it. Shared by the whole
 *  token test below and the leading-assignment scanner. */
function readVarName(text: string, from: number): { name: string; at: number } | null {
	if (!isNameStart(text[from] ?? "")) return null
	let at = from + 1
	while (isNameStart(text[at] ?? "") || isDigit(text[at] ?? "")) at++
	return { name: text.slice(from, at), at }
}

/** Step over one quoted or escaped run of a value; -1 when none starts at `from`. */
function readValueRun(text: string, from: number): number {
	const open = text[from] ?? ""
	if (open === "'") {
		let at = from + 1
		while (at < text.length && text[at] !== "'" && !isLineBreak(text[at]!)) at++
		return text[at] === "'" ? at + 1 : -1
	}
	if (open === '"') {
		let at = from + 1
		for (;;) {
			const ch = text[at] ?? ""
			if (ch === '"') return at + 1
			if (ch === "\\") {
				const escaped = text[at + 1] ?? ""
				if (escaped === "" || isLineBreak(escaped)) return -1
				at += 2
				continue
			}
			if (ch === "" || ch === "$" || ch === "`" || isLineBreak(ch)) return -1
			at++
		}
	}
	if (open === "\\") {
		const escaped = text[from + 1] ?? ""
		return escaped === "" || isLineBreak(escaped) ? -1 : from + 2
	}
	return isPlainValueChar(open) ? from + 1 : -1
}

/**
 * The assignment that opens `text`, if there is one: its bare variable name (an
 * `[index]` is not part of the name) and the offset just past the whitespace that
 * has to follow it. Null otherwise — including for a complete assignment with no
 * command behind it, which is the command itself.
 */
function readLeadingAssignment(text: string): { name: string; next: number } | null {
	const head = readVarName(text, 0)
	if (!head) return null
	let at = head.at
	if (text[at] === "[") {
		const close = text.indexOf("]", at)
		if (close < 0) return null
		at = close + 1
	}
	if (text[at] === "+") at++
	if (text[at] !== "=") return null

	at++
	for (;;) {
		const after = readValueRun(text, at)
		if (after < 0) break
		at = after
	}

	let end = at
	while (isBlank(text[end] ?? "")) end++
	if (end === at) return null
	return { name: head.name, next: end }
}

/** Length of the leading `NAME=value` assignment together with the whitespace
 *  after it, or 0 when `command` does not open with one. `command` must start at
 *  the assignment itself — the callers trim first, as they always have. */
export function leadingAssignmentLength(command: string): number {
	return readLeadingAssignment(command)?.next ?? 0
}

/** The variable name of the leading assignment (`ARR[2]=x cmd` → `ARR`), or `""`
 *  when the text does not open with an assignment. */
export function leadingAssignmentName(command: string): string {
	return readLeadingAssignment(command)?.name ?? ""
}

/** Name of a whole `NAME=` token, else null. Stricter than the scanner above:
 *  the `=` must follow the identifier directly, so neither `ARR[2]=x` nor
 *  `FOO+=x` counts here. That is exactly what the suggestion engine skipped. */
function assignmentName(token: string): string | null {
	const head = readVarName(token, 0)
	return head && token[head.at] === "=" ? head.name : null
}

export function stripOutputRedirections(command: string): string {
	return command.replace(/\s*(?:>>?|[0-9]+>>?)\s*[^\s;&|]+/g, "").trim()
}

export function stripSafeWrappers(command: string): string {
	let stripped = command.trim()
	let prev = ""
	while (stripped !== prev) {
		prev = stripped
		for (const re of SAFE_WRAPPER_PREFIXES) {
			const next = stripped.replace(re, "")
			if (next !== stripped) {
				stripped = next.trim()
				break
			}
		}
	}
	return stripped
}

export function stripAllLeadingEnvVars(command: string): string {
	let stripped = command.trim()
	let prev = ""
	while (stripped !== prev) {
		prev = stripped
		const at = leadingAssignmentLength(stripped)
		if (at === 0) break
		stripped = stripped.slice(at).trim()
	}
	return stripped
}

export function stripSafeLeadingEnvVars(command: string): string {
	let stripped = command.trim()
	let prev = ""
	while (stripped !== prev) {
		prev = stripped
		const assignment = readLeadingAssignment(stripped)
		if (!assignment || !SAFE_ENV_VARS.has(assignment.name)) break
		stripped = stripped.slice(assignment.next).trim()
	}
	return stripped
}

function buildCommandCandidates(
	command: string,
	stripAllEnv: boolean,
): string[] {
	const base = stripOutputRedirections(command)
	const seen = new Set<string>()
	const out: string[] = []

	const push = (s: string) => {
		const t = s.trim()
		if (t && !seen.has(t)) {
			seen.add(t)
			out.push(t)
		}
	}

	push(base)
	push(stripSafeWrappers(base))

	if (stripAllEnv) {
		let start = 0
		while (start < out.length) {
			const end = out.length
			for (let i = start; i < end; i++) {
				push(stripAllLeadingEnvVars(out[i]!))
				push(stripSafeWrappers(out[i]!))
			}
			start = end
		}
	} else {
		for (const cmd of [...out]) {
			push(stripSafeLeadingEnvVars(cmd))
		}
	}

	return out
}

function parseRuleContent(content: string | undefined): ShellPermissionRule | null {
	if (content === undefined) return null
	return parsePermissionRule(content)
}

function commandMatchesRule(
	command: string,
	rule: ShellPermissionRule,
	behavior: "allow" | "deny" | "ask",
): boolean {
	const stripAllEnv = behavior !== "allow"
	const candidates = buildCommandCandidates(command, stripAllEnv)
	const matchMode = behavior === "allow" ? "prefix" : "prefix"
	const allowCompound = behavior !== "allow"

	for (const cmd of candidates) {
		const segments = splitShellSegments(cmd)
		const segmentsToCheck =
			behavior === "allow"
				? segments.length === 1
					? segments
					: []
				: segments.length > 0
					? segments
					: [cmd]

		for (const seg of segmentsToCheck) {
			const segTrim = seg.trim()
			if (!segTrim) continue
			const isCompound = splitShellSegments(segTrim).length > 1
			if (
				matchShellRule(
					rule,
					segTrim,
					matchMode,
					behavior === "allow" ? !isCompound : true,
				)
			) {
				return true
			}
			if (rule.type === "exact" && rule.command === segTrim) {
				return true
			}
		}

		// Tool-wide Bash rule (no content) matches any command
		if (rule.type === "exact" && rule.command === "*") {
			return true
		}
	}

	return false
}

export function bashCommandMatchesRuleContent(
	command: string,
	ruleContent: string | undefined,
	behavior: "allow" | "deny" | "ask",
): boolean {
	if (ruleContent === undefined) {
		// Bare Bash — matches all commands
		return true
	}
	const rule = parseRuleContent(ruleContent)
	if (!rule) return false
	return commandMatchesRule(command, rule, behavior)
}

/** A value decided at run time. Textual rules cannot vouch for what these expand
 *  to, and configured rules are evaluated BEFORE the AST analyzer, so covering
 *  such a segment would pre-empt the only thing that can see what the substituted
 *  command does.
 *
 *  Text path only: it is what the fallback producer (and the deny/ask matcher) reads, because a
 *  command the walker refuses arrives here as characters and nothing else. When the walker does
 *  vouch for a command its own `opaque` flag replaces this guess — the flag is per argument and
 *  says which value is the run-time one, while this regex can only say "something in this text
 *  looks dynamic" and therefore refuses work it could have described.
 */
export const CONTAINS_RUNTIME_VALUE = /\$\(|`|<\(/

/** Shell control flow: a segment starting with one of these is not a command a
 *  rule can usefully describe, so persistence refuses rather than writing noise. */
const CONTROL_WORD_RE = /^(for|while|until|if|case|select|do|done|then|fi|esac|function|time|coproc)\b/

/** Verbs whose prefix rule would be a broad grant over destruction. A rule for
 *  `rm` is not "the thing I just approved", it is "any deletion, forever" — so
 *  these persist as the EXACT command the user saw. They will prompt again on
 *  the next different argument, deliberately: silencing that means writing an
 *  authority broader than the approval, which is the failure this whole path
 *  exists to avoid. */
const EXACT_ONLY_VERBS = new Set([
	"rm", "rmdir", "unlink", "shred", "trash", "trash-put", "dd", "mkfs", "truncate",
	"chmod", "chown", "chgrp", "setfacl", "mv", "rsync", "find", "xargs",
])

export type BashRuleSet = {
	/** Rules to persist, one per segment. Empty unless persistable is true. */
	rules: string[]
	/** False when nothing should be written — the approval becomes allow-once. */
	persistable: boolean
	/** Why persistence was refused, for the user rather than for the log. */
	reason?: string
}

/**
 * The text producer: one rule per `;`/`&&`/`|`-separated segment of the command STRING.
 *
 * This is the fallback, not the normal path. It runs when layer 0 has no answer — the grammar has not
 * loaded yet, or the walker refuses the construct (§12) so there is no argv to describe — and its output
 * is still checked by the round trip in `permissions.ts`, which is what keeps a rule this scanner mis-reads
 * out of the permissions file. It is kept because a refusal to suggest is a UX loss, and the old scanner
 * still gets single-command cases right without a parse.
 *
 * A compound approval used to write ONE rule taken from the head of the command, so `git status && echo
 * done` stored a rule for `git status` only — and since a compound is covered only when EVERY segment is
 * authorised, the same command kept prompting and the extra rule sat there doing nothing useful. Hence one
 * rule per segment.
 *
 * Refuses to persist anything when the command carries a run-time value or shell control flow: better to
 * ask again than to store a rule that claims more than it can honour.
 */
function rulesFromText(command: string): BashRuleSet {
	const trimmed = command.trim()
	if (!trimmed) return { rules: [], persistable: false, reason: "empty command" }

	const segments = splitShellSegments(trimmed)
	if (segments.length === 0) {
		return { rules: [], persistable: false, reason: "no command could be attributed in this text" }
	}

	const rules: string[] = []
	for (const segment of segments) {
		const seg = segment.trim()
		if (!seg) continue
		if (CONTAINS_RUNTIME_VALUE.test(seg)) {
			return { rules: [], persistable: false, reason: "contains a run-time value; approving once only" }
		}
		if (CONTROL_WORD_RE.test(seg)) {
			return { rules: [], persistable: false, reason: "contains shell control flow; no rule written" }
		}
		const verb = seg.split(/\s+/)[0] ?? ""
		if (EXACT_ONLY_VERBS.has(verb.replace(/^.*\//, ""))) {
			const exact = exactBashRule(seg)
			if (!rules.includes(exact)) rules.push(exact)
			continue
		}
		const suggested = ruleFromText(seg)
		// A bare `Bash` is tool-wide: it would allow everything, so refuse the
		// whole set rather than write a wildcard grant under a friendly label.
		if (suggested === "Bash") {
			return { rules: [], persistable: false, reason: "suggested rule would be tool-wide; nothing written" }
		}
		if (!rules.includes(suggested)) rules.push(suggested)
	}

	if (rules.length === 0) {
		return { rules: [], persistable: false, reason: "no rule could be derived" }
	}
	return { rules, persistable: true }
}

/**
 * The second token must look like a subcommand (`commit`, `pr`, `run-all`) —
 * not a flag, filename, path, URL or number. Without this gate a suggestion
 * like `Bash(cat /etc/passwd:*)` gets persisted, which can never match a
 * future invocation again: the user is asked every time and the rule is dead
 * weight. Only a real subcommand is worth generalising over.
 */
function looksLikeSubcommand(token: string): boolean {
	if (!isLowerLetter(token[0] ?? "")) return false
	let afterHyphen = false
	for (let i = 1; i < token.length; i++) {
		const ch = token[i]!
		if (ch === "-") {
			if (afterHyphen) return false
			afterHyphen = true
		} else if (!isLowerLetter(ch) && !isDigit(ch)) {
			return false
		} else {
			afterHyphen = false
		}
	}
	return !afterHyphen
}

/**
 * Programs that actually HAVE a subcommand grammar, so `tool verb:*` is a rule
 * that generalises over real future invocations.
 *
 * Shape alone cannot tell `git commit` from `echo done` — both are `verb noun` —
 * and measuring it found exactly that: `echo done` produced `Bash(echo done:*)`,
 * a rule that can never match `echo` with any other argument. Worse, generic
 * verbs reaching the prefix form is an over-grant, not just a dead one: a rule
 * like `echo:*` or `printf:*` matches `echo … > ~/.ssh/authorized_keys`, because
 * output redirection is stripped before rule matching. So generalisation is
 * limited to tools where the second token really is a subcommand, and every
 * other command gets an exact rule.
 */
const SUBCOMMAND_GRAMMAR_TOOLS = new Set([
	"git", "gh", "glab", "npm", "pnpm", "yarn", "bun", "npx", "npmx",
	"cargo", "rustc", "go", "mix", "mvn", "gradle", "sbt", "dotnet", "composer",
	"docker", "podman", "kubectl", "helm", "terraform", "vault",
	"aws", "gcloud", "az", "brew", "port", "apt", "apt-get", "dnf", "yum", "pacman",
	"pip", "pip3", "pipx", "uv", "poetry", "conda", "gem", "cabal", "stack",
	"systemctl", "service", "launchctl", "journalctl", "make", "cmake", "just",
	"task", "direnv", "asdf", "mise", "devcontainer", "vercel", "netlify", "fly",
	"supabase", "prisma", "turbo", "nx", "lerna", "changesets", "playwright", "cypress",
])

/** True when `tool sub` is a generalisable subcommand rather than `verb noun`. */
function isSubcommandPair(tool: string, sub: string): boolean {
	const name = tool.replace(/^.*\//, "")
	return SUBCOMMAND_GRAMMAR_TOOLS.has(name) && looksLikeSubcommand(sub)
}

/**
 * Binaries whose NAME is never a safe generalisation, because they execute
 * their arguments (or another binary) instead of performing one operation:
 * a rule keyed on them is effectively `Bash(*)`.
 *
 * Why these names are on the list:
 * `Bash(bash:*)` is arbitrary code via `-c`; `Bash(sudo:*)` is privilege
 * escalation for any future sudo; and a wrapper like `nice`/`env` is stripped
 * by analyzers that then inspect the wrapped command, so `Bash(nice:*)`
 * becomes `Bash(*)` for anything that re-parses. Our own gate evaluates
 * configured rules BEFORE the AST analyzer (index.ts applyConfiguredPermissionRules
 * short-circuits the gate), so an over-broad prefix rule here bypasses
 * analysis entirely — this list is load-bearing, not cosmetic.
 *
 * For these we suggest an EXACT rule only.
 */
const NEVER_GENERALISE = new Set([
	// shells
	"sh", "bash", "zsh", "fish", "csh", "tcsh", "ksh", "dash", "cmd", "powershell", "pwsh",
	// shell builtins / executors
	"exec", "eval", "source", ".",
	// wrappers that exec their arguments
	"env", "xargs",
	// wrappers an analyzer strips before looking through
	"nice", "stdbuf", "nohup", "timeout", "time",
	// privilege escalation
	"sudo", "doas", "pkexec",
	// interpreters: their second argument is usually the CODE. The shape gate
	// already rejects `-c` and paths with dots/extensions, but an extension-less
	// script (`python3 cli`, `node bin/app`) would otherwise generalise into a
	// grant over "run whatever file is named here next time".
	"python", "python2", "python3", "pypy", "node", "nodejs", "perl", "ruby", "php", "lua",
])

/** True when every quote in `s` is closed. Uneven quotes mean we are looking at
 *  a fragment and must not build a rule string out of it. */
function hasBalancedQuotes(s: string): boolean {
	let dq = 0
	let sq = 0
	let prev = ""
	for (const ch of s) {
		if (ch === '"' && prev !== "\\") dq++
		if (ch === "'" && prev !== "\\") sq++
		prev = ch
	}
	return dq % 2 === 0 && sq % 2 === 0
}

function exactBashRule(command: string): string {
	// A rule string containing a newline (or `:*` in the middle) fails validation
	// and corrupts the permissions file; never emit one.
	const oneLine = command.split("\n")[0]!.trim()
	return `Bash(${escapeBashRuleContent(oneLine)})`
}

function ruleFromText(command: string): string {
	const trimmed = command.trim()
	if (!trimmed) return "Bash"

	// Heredoc bodies change every invocation, so an exact rule would never match
	// again. Take the stable command text before `<<` — but only when it is
	// genuinely a heredoc (multiline, preceded by whitespace, balanced quotes),
	// otherwise `grep "<<" file` would be truncated into a nonsense rule.
	let head = trimmed
	const idx = trimmed.indexOf("<<")
	if (idx > 0 && trimmed.includes("\n") && hasBalancedQuotes(trimmed)) {
		const before = trimmed.slice(0, idx).trim()
		if (before && hasBalancedQuotes(before)) head = before
	}

	// Multiline commands without heredoc also make poor exact rules: use line 1.
	const firstLine = head.includes("\n") ? head.split("\n")[0]!.trim() : head
	if (!firstLine) return exactBashRule(trimmed)

	const tokens = firstLine.split(/\s+/).filter(Boolean)
	// Skip leading env var assignments
	let i = 0
	while (i < tokens.length && assignmentName(tokens[i]!) !== null) {
		i++
	}

	const baseCmd = tokens[i]
	if (!baseCmd) return exactBashRule(firstLine)

	// Shells, wrappers and privilege escalators never get a generalised rule:
	// `Bash(python3 -c …)` must not become `Bash(python3:*)`, and `Bash(sudo …)`
	// must not become `Bash(sudo rm:*)`.
	const basename = baseCmd.replace(/^.*\//, "")
	if (NEVER_GENERALISE.has(basename)) return exactBashRule(firstLine)

	const subCmd = tokens[i + 1]
	if (subCmd && isSubcommandPair(baseCmd, subCmd)) {
		return `Bash(${baseCmd} ${subCmd}:*)`
	}

	// No subcommand-shaped token: a prefix rule here would be dead weight
	// (`Bash(find .:*)` matches nothing), so stay exact.
	return exactBashRule(firstLine)
}

function escapeBashRuleContent(content: string): string {
	return content
		.replace(/\\/g, "\\\\")
		.replace(/\(/g, "\\(")
		.replace(/\)/g, "\\)")
}

// ── The producer
//
// What an "Allow always" writes. Two producers, one question — *which rule, if it were stored, would let
// this exact command through next time?* — and they differ only in what they are allowed to read:
//
//   - `rulesFromArgv` (the normal path) asks layer 0 for the legs of the command and spells each leg's
//     argv: quoting resolved, one word per argument, assignments and redirections already separated from
//     it. Those are the very words `bash-rule-argv.ts` compares a specifier against, so a specifier spelled
//     out of them matches by construction — a redirect, a here-document, a quoted `&&` or a line break
//     costs a correct specifier instead of costing the offer.
//   - `rulesFromText` is the fallback for the only two cases in which there are no words to spell: the
//     grammar has not loaded yet, and the walker refuses the construct (§12). It is the old scanner, and
//     its guesses are still checked by the same round trip.
//
// Neither producer decides whether the rule would be honoured. `permissions.ts` feeds every set back
// through the matcher that will have to honour it and withholds the offer if it would not be — so a
// producer that cannot describe a leg says so instead of quietly guessing, because a wrong description
// costs one prompt while a guessed one writes authority.

/**
 * The categories whose verdict is set by the targets the command names — deleting *this* path, overwriting
 * *this* file, discarding *this* worktree. Where the risk lives in the target, rule coverage requires argv
 * equality: no extension, options included (work.log 2026-10-14, the decision W8 implements). A suggestion
 * for such a leg therefore has to name every word it ran, or it offers a rule the matcher will refuse to
 * honour — which is the same dead offer W3 removed.
 *
 * **Asks the matcher, because a second list here went wrong.** W9 carried its own `TARGET_BEARING_CATEGORIES`
 * with `file_overwrite`, `permission_change` and `ssh_key_write` — names taken from a task brief, not from this
 * repository's tier tables, which emit `write_sensitive`/`write_outside`, `perm_change` and `persistent_access`.
 * The failure was fail-safe but silent: `chmod`/`sudo`/secret-read verdicts were treated as non-target-bearing,
 * so the producer generalised a specifier the strict matcher then refused, and the user simply lost the
 * "Always" offer for exactly the destructive verbs worth offering. One source of truth, so the producer cannot
 * disagree with the matcher that has to honour its output.
 */
function isTargetBearing(category: string): boolean {
	return categoryHasStrictOperands(category)
}

/**
 * Does layer 0 rate this leg by what it names rather than by what it is? Asked the way `hitsNeverFloor`
 * asks it — same options, same project root — so the two cannot disagree about the command in front of them.
 */
function legNamesItsTargets(text: string, cwd: string): boolean {
	try {
		const decision = evaluateBash(text, { cwd, project: cwd, home: homedir() })
		if (isTargetBearing(decision.category)) return true
		return decision.segments.some((s) => isTargetBearing(s.category))
	} catch {
		// No category, no generalisation: an exact rule always describes the command that was run.
		return true
	}
}

/** Every refusal of the "nothing I could write would be honoured" shape starts with this, which is also how
 *  the round-trip refusal in `permissions.ts` reads, so one explanation does not turn into three. */
const NOT_HONOURABLE = "no rule would cover this command again"

/** `<<<` supplies stdin from text in the command line. The walker keeps it out of both argv and
 *  `redirects`, so it is found the slow way — and a leg carrying it is one whose input no rule names. */
const HERE_STRING = "<<<"

/** A rule is one line: the permissions loader compares rules line by line, so a specifier spanning lines
 *  is not a rule at all. An argument containing a line break therefore cannot be named. */
const LINE_BREAK_CHARS = "\n\r\u2028\u2029"

/**
 * Characters that may never sit unescaped in a specifier: the separators and expansions `bash-rule-argv.ts`
 * reads as shell structure rather than as an argument, the quote and backslash characters that would change
 * how the rest of the word is read, the blank that ends a word, and the star — which would turn the whole
 * specifier into a glob and widen it silently.
 *
 * Escaping them with a backslash is enough for every one of them: `splitArguments` takes a backslashed
 * character as data, `hasWildcards` treats `\*` as a literal star, and `escapeRuleContent` doubles the
 * backslash on the way into the file and `unescapeRuleContent` puts it back on the way out.
 */
const NEVER_UNESCAPED = " \t*&;|<>()$`'\\\""

/**
 * One argument as it must be written inside a specifier, or null when it cannot be written at all.
 *
 * Only a line break cannot: the quoting that would carry it (`'…'`) is the one spelling this module does
 * not emit, because a specifier is written into a file that is read line by line. Everything else — spaces,
 * quotes, `$`, backticks, semicolons — is data with a backslash in front of it, which is what makes an
 * argument like `a && b` spellable instead of fatal.
 */
function spellArgument(word: string): string | null {
	if (word === "") return "''"
	let spelled = ""
	for (const ch of word) {
		if (LINE_BREAK_CHARS.includes(ch)) return null
		spelled += NEVER_UNESCAPED.includes(ch) ? "\\" + ch : ch
	}
	return spelled
}

/** Either the rule, or why nothing could be written for these words. */
type Spelling = { rule: string } | { refusal: string }

/** A rule the approval dialog quotes in one line. Past this the offer is noise, so nothing is offered. */
const MAX_SPECIFIER_CHARS = 600

/**
 * The rule for exactly these words: an exact one naming all of them, or a prefix rule over the two given
 * when `generalise` says the family is worth generalising over.
 *
 * The two refusals are kept apart because the user is shown one of them and they mean different things: a
 * line break in an argument is a rule the permissions file cannot hold, while a very long argument is a rule
 * nobody could read in a dialog. Both say "no offer"; only the first says "no rule could ever exist".
 */
function ruleForWords(words: string[], redirects: readonly AstRedirect[], generalise: boolean): Spelling {
	const parts: string[] = []
	for (const word of words) {
		const spelled = spellArgument(word)
		if (spelled === null) {
			return { refusal: `${NOT_HONOURABLE}: one step has an argument that spans lines, and a rule is one line` }
		}
		parts.push(spelled)
	}
	if (parts.length === 0) return { refusal: `${NOT_HONOURABLE}: the step has no words to name` }
	for (const redirect of redirects) {
		const spelled = spellTarget(redirect)
		// The same refusal, because it is the same fact: a redirect target is an argument to the shell, and
		// one that spans lines cannot be named by a rule that occupies one.
		if (spelled === null) {
			return { refusal: `${NOT_HONOURABLE}: one step has an argument that spans lines, and a rule is one line` }
		}
		parts.push(spelled)
	}
	const specifier = parts.join(" ") + (generalise ? ":*" : "")
	// `Bash` with no specifier and `Bash(*)` are the tool-wide grant, and a bare `*` in the text would be
	// read as a glob. A spelled `*` is always `\*`, so this can only happen for the degenerate cases.
	if (specifier === "" || specifier === "*") {
		return { refusal: "the only rule that would match every command there is; nothing written" }
	}
	if (specifier.length > MAX_SPECIFIER_CHARS) {
		return { refusal: `${NOT_HONOURABLE}: the command is longer (${specifier.length} characters) than a rule anyone could read (${MAX_SPECIFIER_CHARS})` }
	}
	return { rule: permissionRuleValueToString({ toolName: "Bash", ruleContent: specifier }) }
}

/**
 * Why this leg cannot be described by a rule at all — as opposed to being described by a shorter one.
 *
 * Each of these is something argv cannot carry, so any rule naming the leg's words would be broader than
 * what the user approved:
 *
 *   - **no words at all** (`> /tmp/x`): a write with no command, which no `Bash(...)` rule speaks for;
 *   - **a here-document or here-string**: the body is data on the step, never an argument;
 *   - **a run-time value** (`opaque`, §5.10): a rule could only name the placeholder — including a
 *     redirect target that is one, which is why `echo x > $(printf /etc/x)` is refused here and stays
 *     uncovered however the operator is spelled;
 *   - **an environment that changes execution**: the walker keeps `NAME=value` out of argv, which is right
 *     for classification and blind here, so `Bash(git status:*)` would carry
 *     `LD_PRELOAD=/tmp/e.so git status` — the same refusal `legSpellings` makes.
 *
 * A file redirect is NOT in this list, and that is the whole of W10. It used to be: coverage compared
 * argv, so the only rule that would cover `echo hi > /tmp/out.txt` was `Bash(echo hi)`, which covers
 * `echo hi > anywhere`. A specifier can name the target now (`{@link spellTarget}`), so the write is
 * described instead of dropped — and `ruleForLeg` writes it as an exact rule, because a rule that names
 * a file has already written down the whole invocation.
 */
function refusalForLeg(leg: AstCommand): string | null {
	if (leg.argv.length === 0) {
		return "this step runs no command, so there is nothing for a rule to authorise"
	}
	if (leg.heredocs.length > 0 || leg.text.includes(HERE_STRING)) {
		return `${NOT_HONOURABLE}: the step reads a here-document body or here-string, which is data on the step and never part of a rule`
	}
	if (leg.opaque) {
		return "one of its arguments is only known at run time; a rule could name the placeholder, never the value"
	}
	if (leg.envVars.some((e) => envChangesExecution(e.name))) {
		return "its environment decides what runs (PATH, LD_PRELOAD, …), and argv carries none of that"
	}
	return null
}

/**
 * One redirect as it must be written inside a specifier: `> /tmp/out.txt`, `2> err.log`, `>> notes.md`.
 *
 * The descriptor is spelled only when it carries information — `2>` keeps its `2`, `1>` does not, because
 * `1>` is what `>` already means and the matcher resolves the two to one canonical target. Writing the
 * redundant digit would split one invocation into two rule strings that the file's de-duplication cannot
 * join, so the canonical spelling is the only thing an offer produces.
 *
 * The target itself is spelled exactly like an argument — same escaping, same refusal for a line break —
 * because to the shell it is one, and the only reason it never reaches argv is that the walker separates it.
 */
function spellTarget(redirect: AstRedirect): string | null {
	const target = spellArgument(redirect.target)
	if (target === null) return null
	const descriptor = redirect.fd === implicitDescriptor(redirect.op) ? "" : (redirect.fd ?? "")
	return `${descriptor}${redirect.op} ${target}`
}

/**
 * One leg's rule: the tool and its subcommand when the family is safe to generalise over, otherwise every
 * word the call passed, followed by every file the call redirects into or out of.
 *
 * Generalising is a decision about the WORDS THAT WOULD BE DROPPED, because a rule naming fewer words than
 * the call covers everything after them. `SUBCOMMAND_GRAMMAR_TOOLS` says when the dropped words are only
 * options; the verb tables say when a name is never safe as a prefix; a target-bearing category may drop
 * nothing at all (see `isTargetBearing`); and a leg that redirects drops nothing either — the clause names
 * one file, so a prefix in front of it would generalise over the words that decide *what gets written to
 * that file*, which is the other half of the harm.
 */
function ruleForLeg(leg: AstCommand, cwd: string): Spelling {
	const head = leg.argv[0] ?? ""
	const verb = head.slice(head.lastIndexOf("/") + 1)
	const redirects = fileRedirects(leg.redirects)
	const generalise =
		redirects.length === 0 &&
		leg.argv.length >= 2 &&
		!EXACT_ONLY_VERBS.has(verb) &&
		!NEVER_GENERALISE.has(verb) &&
		isSubcommandPair(head, leg.argv[1]!) &&
		!legNamesItsTargets(leg.text, cwd)
	return ruleForWords(generalise ? leg.argv.slice(0, 2) : leg.argv, redirects, generalise)
}

/**
 * One rule per command leg, from the walker's argv — or null when layer 0 has no answer and the caller
 * should ask the text producer instead.
 *
 * `null` is not a refusal. A command the walker will not vouch for has no argv for a rule to have been
 * written from, and the text producer's guess (still checked by the round trip) is worth more than
 * silence. A refusal, by contrast, is a leg layer 0 DID read and that no rule can describe: the whole set
 * goes, because coverage is AND across legs and half a set would sit in the file doing nothing.
 */
function rulesFromArgv(command: string, cwd: string): BashRuleSet | null {
	if (!isBashParserReady()) {
		// Kick the one-time grammar load exactly as `auditBashCommand` does: index.ts does it at session
		// start but fire-and-forget, and a suggestion made inside that window must not decide for the rest
		// of the process that the grammar is unavailable.
		void initBashParser().catch(() => {})
		return null
	}
	let parsed: AstParse
	try {
		parsed = parseBashCommand(command)
	} catch {
		return null
	}
	if (parsed.kind !== "simple" || parsed.commands.length === 0) return null

	const rules: string[] = []
	for (const leg of parsed.commands) {
		const refusal = refusalForLeg(leg)
		if (refusal !== null) return { rules: [], persistable: false, reason: refusal }
		const made = ruleForLeg(leg, cwd)
		if ("refusal" in made) return { rules: [], persistable: false, reason: made.refusal }
		if (!rules.includes(made.rule)) rules.push(made.rule)
	}
	return { rules, persistable: true }
}

/**
 * EVERY rule an "always allow" on this command would write, one per command leg.
 *
 * `cwd` is the project root the command is judged in — the same value the gate and `hitsNeverFloor` use,
 * because it decides which paths are inside the project and therefore what the command's category is, and
 * the category decides whether the rule may be a prefix. Callers that have one must pass it; the default is
 * the process's own directory, which is right for a harness and wrong for a session opened elsewhere.
 *
 * What comes back is a *description* of the approval. Whether it can be honoured is decided by
 * `permissions.ts`, which runs these rules back through `bashRuleCoversArgv`; nothing here may be trusted
 * to have already done that.
 */
export function suggestBashAllowRuleSet(command: string, cwd: string = process.cwd()): BashRuleSet {
	const trimmed = command.trim()
	if (!trimmed) return { rules: [], persistable: false, reason: "empty command" }
	return rulesFromArgv(trimmed, cwd) ?? rulesFromText(trimmed)
}

/**
 * The single rule for this command — the head of the set, for a caller with room for one line only. Prefer
 * `suggestBashAllowRuleSet`: a compound is covered only when every leg has its own rule, so one rule for a
 * two-step command is an offer that will not stick.
 *
 * A leg the producer refuses falls through to the text producer rather than returning `Bash`: an empty rule
 * means "this tool, whatever it does", and no refusal means that.
 */
export function suggestBashAllowRule(command: string, cwd: string = process.cwd()): string {
	const trimmed = command.trim()
	if (!trimmed) return "Bash"
	const set = rulesFromArgv(trimmed, cwd)
	if (set !== null && set.persistable && set.rules.length > 0) return set.rules[0]!
	return ruleFromText(trimmed)
}
