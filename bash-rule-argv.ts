/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * `Bash(...)` allow rules, matched against argv instead of against a re-split of the command text.
 *
 * A rule specifier and a shell command are two spellings of one thing — a command word plus its
 * arguments — but the text matcher (`bash-permission-match.ts`) can only compare the spellings, so
 * it has to undo one of them: it splits the command into segments with its own character scanners,
 * strips wrappers, strips redirections, strips leading `NAME=value`, and only then compares strings.
 * Every one of those steps is a second, weaker opinion about a command that layer 0 (`bash-ast.ts` →
 * the tree-sitter walker) has already worked out properly. This module takes the walker's answer as
 * given — `argv`, quoting resolved, one entry per argument — and asks a question that needs no
 * re-parsing at all: *do the words the rule names sit, unchanged, at the front of these words?*
 *
 * That one change is what makes a chain of permitted legs permitted — `permissions.ts` scores every bash
 * allow rule through this matcher — so a compound never reaches here as one string, `&&` can no longer
 * defeat an allow rule, and `Bash(bash x.sh)` stops failing to match `bash x.sh arg` over a glob detail
 * a user was told to work around.
 *
 * ## What a specifier means here
 *
 * | rule | argv it covers | argv it covers when `strictOperands` is set |
 * | --- | --- | --- |
 * | `Bash` / `Bash()` / `Bash(*)` | every non-empty argv | the same |
 * | `Bash(git status)` | `["git","status"]` and any argv that *starts* with those two words | `["git","status"]` only |
 * | `Bash(git status:*)` | the same: `git status`, plus whatever follows it | the same (it says so itself) |
 * | `Bash(git * main)` | the glob, over the argv joined with single spaces (see below) | the same |
 * | `Bash(echo hi > /tmp/out.txt)` | `["echo","hi"]` writing exactly `/tmp/out.txt` — and nothing else | the same (it is already equality) |
 *
 * Naming fewer words than the call is a deliberate loosening, and the only one: `Bash(bash x.sh)`
 * covers `bash x.sh arg`. A rule that names a word the call does not have still covers nothing, so the
 * loosening runs one way — never towards authority the user did not type.
 *
 * ## Redirects: a target is part of the invocation
 *
 * A leg that writes through a redirect passes the same argv as the same command without one, so argv
 * alone cannot tell `echo hi > /tmp/out.txt` from `echo hi > ~/.ssh/authorized_keys`. The caller hands
 * over the leg's file targets (`coverage.targets`, produced by `bash-audit.ts` from the walker's
 * `redirects`) and the truth table below decides. It is written to narrow coverage, never to widen it:
 *
 * | specifier | what the leg must be |
 * | --- | --- |
 * | exact, no clause | no file target, and its words start with the words named |
 * | exact, with a clause (`a b > f`) | **equal** words **and** exactly the targets named |
 * | `:*` prefix | no file target (a prefix cannot carry a clause; `:*` says "any words", not "any file") |
 * | glob | no file target (a `*` spans characters in the words; nothing in a glob can name one file) |
 * | tool-wide `Bash` | anything — it is not a reading of one approval (see below) |
 *
 * So a rule that names no target covers no command that redirects to one, and a rule that names a
 * target covers nothing but that invocation: the clause already wrote down the whole command, so there
 * is no "and whatever follows it" left to extend over. The tool-wide rule is the one exception because
 * it never was a reading of one approval — it is the user's own "every bash command", `dangerous-
 * permissions.ts` strips it before auto mode, and a rule with no specifier has no place to write a
 * target, so refusing here would only make `Bash` stop meaning what the user typed.
 *
 * ## Strict operands (`{ strictOperands: true }`)
 *
 * The loosening above is wrong for a command whose risk *is* the targets it names. `Bash(rm -rf /tmp/x)`
 * read as a prefix means "and anything else you care to delete", so one approval on a scratch path
 * becomes permission to delete a second path the user never saw — and "Allow always" persists that
 * reading as a durable rule. Where the caller says the argv is target-bearing (it has layer 0's verdict:
 * `delete_recursive`, `perm_change`, … — the table lives in `bash-audit.ts`), an **exact** specifier has
 * to name every word the call passes, options included: `rm -rf /tmp/x --verbose` is not covered by
 * `Bash(rm -rf /tmp/x)` and the user is asked once more.
 *
 * Only an exact specifier gets that treatment, and that is a boundary rather than an oversight:
 * `Bash(rm:*)` and `Bash(rm *)` are breadth the user typed themselves — "every rm", "any rm argument" —
 * so honouring them past their words is not extending an approval, it is reading the rule. What the
 * strict mode forbids is a specifier that stops mid-invocation and still authorises the rest of it.
 * An "Allow always" click never writes a glob (see `suggestBashAllowRuleSet`, which writes an exact rule
 * for destructive verbs), so the residual breadth of `:*` rules is the user's, not the click's.
 *
 * ## What this module deliberately does NOT do
 *
 * - **No stripping.** No wrapper (`nohup`, `timeout 5`), no redirection, no `NAME=value` prefix is
 *   removed here, because stripping is what produced the duplicate analyzers this replaces. The walker
 *   already separates assignments (`AstCommand.envVars`) and redirects (`AstCommand.redirects`) from
 *   argv, so an argument prefix is invisible for free and a redirect arrives as `coverage.targets`
 *   instead of being shaved off the command; a wrapper word *is* argv[0], and a caller that
 *   wants to see through one has to say so where argv is produced, not here.
 * - **No `xargs` allowance.** The text matcher lets `git status:*` cover `xargs git status …`; this
 *   does not. Those trailing arguments arrive from a pipe at run time, and `xargs` is on the
 *   broad-rule list (`dangerous-permissions.ts`) for exactly that reason. Narrowing on the allow path.
 * - **No judgement about argv.** A token the walker could only give as a placeholder
 *   (`__CMDSUB_OUTPUT__`, `__TRACKED_VAR__`) is matched like any other word. Whether a rule may wave
 *   through a value decided at run time is the caller's decision — it has `AstCommand.opaque` — and
 *   today's answer (yes, for a single segment) is pinned in `compound-allow-and.test.ts`.
 * - **No deny/ask.** Those stay textual in `permissions.ts`, on purpose: a deny has to fire even when
 *   the walker refuses to vouch for the construct, which is the one case where argv does not exist.
 */

import { matchWildcardPattern, parsePermissionRule } from "./shell-rule-matching.ts"
import type { PermissionRule } from "./permissions.ts"

/** The tool name these rules are written under — `permissions.ts` maps pi's `bash` onto it. */
const BASH_TOOL = "Bash"

/**
 * Outside quotes these characters mean "shell structure", not "an argument" — a separator, a subshell
 * or an expansion. A specifier built out of them does not describe one argument list, so there is no
 * argv to compare against and the rule simply never covers anything.
 *
 * `<` and `>` are deliberately NOT in this list: they are the two constructs a specifier *can* name, in
 * the one form that is not a shell decision (`{@link takeRedirectOperator}`), because a command that
 * writes a file has to be describable by the rule that authorises it. Everything else that would make
 * the text mean more than one argument list still ends the read.
 */
const STRUCTURE_CHARS = ";|&()$`"

/** Line breaks: inside quotes they are ordinary data, outside them they end the command. */
function isLineBreak(ch: string): boolean {
	return ch === "\n" || ch === "\r" || ch === "\u2028" || ch === "\u2029"
}

function isWordGap(ch: string): boolean {
	return ch === " " || ch === "\t"
}

/** `'…'` — every character up to the matching quote, literally. Null when the quote is never closed. */
function takeSingleQuoted(text: string, from: number): { word: string; next: number } | null {
	const close = text.indexOf("'", from + 1)
	if (close < 0) return null
	return { word: text.slice(from + 1, close), next: close + 1 }
}

/**
 * `"…"` — backslash escapes count, everything else is data, including line breaks. Null when the run
 * is unterminated (a fragment, so no rule can be read from it) or when it still holds something the
 * shell would expand: the value behind `$` or a backtick is a run-time fact, and this module never
 * pretends to know it.
 */
function takeDoubleQuoted(text: string, from: number): { word: string; next: number } | null {
	let word = ""
	let at = from + 1
	for (;;) {
		const ch = text[at] ?? ""
		if (ch === '"') return { word, next: at + 1 }
		if (ch === "") return null
		if (ch === "\\") {
			const escaped = text[at + 1] ?? ""
			if (escaped === "" || isLineBreak(escaped)) return null
			word += escaped
			at += 2
			continue
		}
		if (ch === "$" || ch === "`") return null
		word += ch
		at++
	}
}

/**
 * Read one argument of a specifier, starting mid-token: up to the next unquoted blank. Backslash
 * makes the next character part of this word — which is how `fix\ wip` is one argument, and why a
 * backslash in front of a line break is refused rather than silently joining two commands into one.
 *
 * An unquoted `<` or `>` ends the word without being part of it: that character is a redirect
 * operator, and the caller reads it as one. A quoted or backslashed one never reaches this test —
 * `echo "a>b"` and `echo a\>b` are one argument whose text happens to be `a>b`, which is the whole
 * difference between a rule that names a file and a rule that names a word shaped like a redirect.
 */
function takeWordRun(text: string, from: number): { word: string; next: number } | null {
	let word = ""
	let at = from
	for (;;) {
		const ch = text[at] ?? ""
		if (ch === "" || isWordGap(ch)) return { word, next: at }
		if (ch === "<" || ch === ">") return { word, next: at }
		if (isLineBreak(ch) || STRUCTURE_CHARS.includes(ch)) return null
		if (ch === "'") {
			const run = takeSingleQuoted(text, at)
			if (!run) return null
			word += run.word
			at = run.next
			continue
		}
		if (ch === '"') {
			const run = takeDoubleQuoted(text, at)
			if (!run) return null
			word += run.word
			at = run.next
			continue
		}
		if (ch === "\\") {
			const escaped = text[at + 1] ?? ""
			if (escaped === "" || isLineBreak(escaped)) return null
			word += escaped
			at += 2
			continue
		}
		word += ch
		at++
	}
}

// ------------------------------------------------------------------ redirect clauses (§7 of the walker)

/**
 * The redirect operators a specifier may name, longest spelling first so `&>>` is never read as `&>`
 * plus junk. These are the operators `bash-walker.ts` reports for a `file_redirect`; the ones it
 * refuses (`<>`) and the ones that carry a body instead of a target (`<<`, `<<<`) are absent on
 * purpose — a rule cannot name a here-document body, so a specifier that looks like one names nothing.
 */
const REDIRECT_OPERATORS: readonly string[] = ["&>>", "&>", ">>", ">&", ">|", "<&", ">", "<"]

/**
 * The descriptor an operator means when the command does not write one. `> f` and `1> f` are the same
 * invocation, `0< f` and `< f` are the same invocation, and `&>` moves both streams so it belongs to
 * neither descriptor. Naming the descriptor in a rule therefore means naming *that* stream: a rule for
 * `> f` never covers `2> f`, whose file receives stderr instead of stdout.
 */
const IMPLICIT_DESCRIPTOR: Record<string, number | undefined> = {
	">": 1,
	">>": 1,
	">|": 1,
	">&": 1,
	"<": 0,
	"<&": 0,
}

/** The descriptor an operator means on its own, or undefined when the operator is not stream-scoped. */
export function implicitDescriptor(op: string): number | undefined {
	return IMPLICIT_DESCRIPTOR[op]
}

/**
 * One file a command writes or reads, in the form both sides of a comparison share.
 *
 * This is a fact about the *invocation*, so it is produced two ways and must agree: from the walker's
 * `AstRedirect`s (through `bash-audit.ts`, for the call) and from the words a rule specifier names (for
 * the authority). Canonical means the descriptor is resolved (`>` → stdout), so the two spellings of one
 * command compare equal and no rule can be read as covering a stream it did not name.
 */
export type RedirectTarget = {
	/** The operator without its descriptor: `>`, `>>`, `<`, `>|`, `>&`, `<&`, `&>`, `&>>`. */
	op: string
	/** The descriptor moved, resolved by {@link IMPLICIT_DESCRIPTOR}; undefined when the op is not stream-scoped. */
	fd?: number
	/** The file, quoting resolved — an argument in every sense except that it never reaches argv. */
	target: string
}

/** Resolve one written redirect (rule side or walker side) into the form the comparison uses. */
export function canonicalRedirectTarget(written: { op: string; fd?: number; target: string }): RedirectTarget {
	return { op: written.op, fd: written.fd ?? IMPLICIT_DESCRIPTOR[written.op], target: written.target }
}

/** A redirect as one identity, so two targets can be compared without comparing an object graph. */
function targetIdentity(target: RedirectTarget): string {
	return `${target.fd ?? ""}${target.op}\u0000${target.target}`
}

/**
 * Do a rule's targets and the call's targets name the same writes?
 *
 * Order-insensitive and counted: `> a 2> b` and `2> b > a` are one command to bash, and a leg that opens
 * `a` twice is not covered by a rule that names it once. Comparing sorted identities is how both hold
 * without inventing a source order neither side can guarantee.
 */
function sameTargets(named: readonly RedirectTarget[], called: readonly RedirectTarget[]): boolean {
	if (named.length !== called.length) return false
	const mine = named.map(targetIdentity).sort()
	const theirs = called.map(targetIdentity).sort()
	return mine.every((key, at) => key === theirs[at])
}

/** A token read out of a specifier: an argument word, or a bare redirect operator in front of its target. */
type SpecToken = { word: string } | { operator: string }

/**
 * The redirect operator starting at `at`, descriptor and all (`2>`), or null when the text there is not
 * one. Only ever called at the start of a token, which is what keeps `2>` a descriptor and
 * `echo 2 > f` three words plus an operator: digits glue to an operator exactly as they do in bash.
 */
function takeRedirectOperator(text: string, at: number): { operator: string; next: number } | null {
	let head = at
	while ((text[head] ?? "") >= "0" && (text[head] ?? "") <= "9") head++
	for (const op of REDIRECT_OPERATORS) {
		if (text.startsWith(op, head)) return { operator: text.slice(at, head + op.length), next: head + op.length }
	}
	return null
}

/** Split an operator token back into its operator and its glued descriptor. */
function splitOperatorToken(token: string): { op: string; fd?: number } | null {
	const descriptor = /^\d*/.exec(token)![0]!
	const op = token.slice(descriptor.length)
	if (!REDIRECT_OPERATORS.includes(op)) return null
	return descriptor === "" ? { op } : { op, fd: Number(descriptor) }
}

/**
 * Split a specifier into its tokens: argument words and bare redirect operators, in source order.
 * `null` means "this specifier is not an argument list": unbalanced quoting, a line break outside
 * quotes, or shell structure that has no reading as one command (`&&`, a pipe, `$`, a subshell).
 */
function splitTokens(specifier: string): SpecToken[] | null {
	const tokens: SpecToken[] = []
	let at = 0
	for (;;) {
		while (isWordGap(specifier[at] ?? "")) at++
		if (at >= specifier.length) return tokens
		const operator = takeRedirectOperator(specifier, at)
		if (operator) {
			tokens.push({ operator: operator.operator })
			at = operator.next
			continue
		}
		const run = takeWordRun(specifier, at)
		if (!run) return null
		// A word exists once a quote or an escape has been seen, even when it holds nothing:
		// `-m ""` passes an empty argument, and dropping it here would authorise `-m` alone.
		tokens.push({ word: run.word })
		at = run.next
	}
}

/** What a specifier names: the words it runs, and the files it redirects into or out of. */
export type RuleSpecifier = { words: string[]; targets: RedirectTarget[] }

/**
 * Read a specifier as words plus redirect clauses.
 *
 * This is the normal form the whole contract is stated in: the rule `git commit -m "fix wip"` and the
 * call `git commit -m 'fix wip'` both arrive as `["git","commit","-m","fix wip"]`, because to the shell —
 * and therefore to whatever the rule is actually authorising — they are the same invocation. `""` produced
 * by quotes survives as an empty argument, which is what the walker emits for `cmd ""` too, and a
 * specifier of only whitespace names zero words, which covers nothing rather than everything.
 *
 * A clause is one operator token and the word behind it, and it may sit anywhere in the specifier —
 * `echo > f hi` and `echo hi > f` are the same command to bash, and a rule that could only be written
 * in one spelling would be a rule the user had to learn. An operator with no word behind it (or with
 * another operator behind it) names no file, which is a specifier this module will not read at all.
 */
function readSpecifier(specifier: string): RuleSpecifier | null {
	const tokens = splitTokens(specifier)
	if (tokens === null) return null
	const words: string[] = []
	const targets: RedirectTarget[] = []
	for (let at = 0; at < tokens.length; at++) {
		const token = tokens[at]!
		if ("word" in token) {
			words.push(token.word)
			continue
		}
		const named = tokens[at + 1]
		if (named === undefined || !("word" in named)) return null
		const operator = splitOperatorToken(token.operator)
		if (operator === null) return null
		targets.push(canonicalRedirectTarget({ ...operator, target: named.word }))
		at++
	}
	return { words, targets }
}

/**
 * The specifier text a `Bash` rule carries, or `null` when it carries none (`Bash`, `Bash()`).
 * Whether the rule is about bash at all is decided by the callers, before this is consulted.
 */
function specifierOf(rule: PermissionRule): string | null {
	const written = rule.ruleValue.ruleContent
	if (written === undefined || written === "") return null
	return written
}

/** The words a rule names authorise a call only if they are its first words, in order and unchanged. */
function namedWordsCover(named: string[], argv: string[]): boolean {
	if (named.length === 0 || argv.length < named.length) return false
	for (let i = 0; i < named.length; i++) {
		if (argv[i] !== named[i]) return false
	}
	return true
}

/**
 * Strict coverage: the rule names every word of the call, and the call passes no word the rule did
 * not name. Same positional walk as {@link namedWordsCover} — only "and nothing more" is added, which is
 * the whole difference between "this target" and "this target and whatever follows it".
 */
function namedWordsAreAll(named: string[], argv: string[]): boolean {
	return named.length === argv.length && namedWordsCover(named, argv)
}

/** How far a rule may be read past the words it names. {@link bashRuleCoversArgv} for the contract. */
export type ArgvCoverage = {
	/**
	 * True when the argv comes from a command whose risk is set by the targets it names, so a rule has
	 * to name every word. Set by the caller, which is holding layer 0's verdict (`bash-audit.ts` decides
	 * which categories mean that); omitted = the ordinary prefix contract.
	 */
	strictOperands?: boolean
	/**
	 * The files this command redirects, as layer 0 saw them (`BashLeg.targets`, already canonical and
	 * already without descriptor dups). Omitted means "this command redirects no file", which is what a
	 * caller without a parse has to say — and it is the fail-closed reading, because a rule that names a
	 * target then covers nothing here rather than covering a write nobody authorised.
	 */
	targets?: readonly RedirectTarget[]
}

/**
 * Does this rule authorise this already-parsed argv array?
 *
 * argv is the walker's output: command word first, one entry per argument, quoting already resolved.
 * Nothing here re-tokenises a command string — that is the bug being removed.
 *
 * A call with no words is never covered, not even by the tool-wide rule: argv is empty exactly when
 * there is no command to authorise (`> f` writes a file without running anything), and a rule cannot
 * be what cleared it.
 *
 * `coverage.strictOperands` narrows an exact specifier to argv equality (see the section above); every
 * other specifier form — the tool-wide rule, a `:*` prefix, a glob — means what it says in both modes.
 * Omitting the argument keeps the prefix contract exactly (`namedWordsCover`), which is what a caller with
 * no verdict — or a command whose risk is not set by its targets — wants.
 *
 * `coverage.targets` is the narrower of the two and is not opt-in: when the command writes or reads a
 * file through a redirect, only an exact specifier that names that file — same operator, same
 * descriptor — covers it. A rule that names no target stops covering the command, which is the point:
 * `Bash(echo hi)` covering `echo hi > ~/.ssh/authorized_keys` is the over-grant this repository
 * already refuses to *write*, and refusing it here too is what makes the two halves agree.
 */
export function bashRuleCoversArgv(
	rule: PermissionRule,
	argv: string[],
	coverage: ArgvCoverage = {},
): boolean {
	if (rule.ruleValue.toolName !== BASH_TOOL) return false
	if (argv.length === 0) return false

	// A rule with no specifier — `Bash`, `Bash()`, and `Bash(*)` via the parser's tool-wide spelling — is
	// a blanket bash allow. That is not a hole opened here: entering auto mode strips exactly these rules
	// first (dangerous-permissions.ts strips `Bash` / `Bash(*)` / `git:*`-style blind tails), so this
	// branch is reachable only where the user has already accepted an unconditioned allow. It is also the
	// one form that cannot name a target at all, so narrowing it would make `Bash` stop meaning what the
	// user typed without ever refusing a target-naming rule.
	const specifier = specifierOf(rule)
	if (specifier === null) return true

	const shape = parsePermissionRule(specifier)
	const targets = (coverage.targets ?? []).map(canonicalRedirectTarget)

	// A glob is character-level text, and the existing engine is the only place its rules (escaped
	// `\*`, the trailing ` *` that also covers the bare text, stars spanning line breaks) are defined.
	// Renders the argv back to text so that engine can score it: joining the resolved words with
	// single spaces is not re-tokenising anything — every word is still exactly one argument in the
	// string it lands in, and a star in the rule spans characters inside a word just as it always did.
	// A star spans characters in the WORDS only: nothing in a glob names one file without also naming
	// every file, so a glob never speaks for a command that redirects to one.
	if (shape.type === "wildcard") {
		return targets.length === 0 && matchWildcardPattern(shape.pattern, argv.join(" "))
	}

	const named = readSpecifier(shape.type === "prefix" ? shape.prefix : shape.command)
	if (named === null) return false

	// A specifier that names a target describes a whole invocation — it already wrote down the file — so
	// both halves are compared by equality and no prefix reading is left to extend. A `:*` specifier
	// cannot carry a clause (`:*` is read off the end of the text before any of this), which is the
	// documented answer to "what does `Bash(echo:*)` mean for a redirect": nothing.
	if (named.targets.length > 0) {
		if (shape.type === "prefix") return false
		return namedWordsAreAll(named.words, argv) && sameTargets(named.targets, targets)
	}
	if (targets.length > 0) return false

	if (coverage.strictOperands && shape.type !== "prefix") return namedWordsAreAll(named.words, argv)
	return namedWordsCover(named.words, argv)
}

/**
 * What this rule names, in normal form — quoting resolved, one entry per word, plus the files it
 * redirects — or null when it describes no single invocation: a rule for another tool, a tool-wide
 * rule, a glob (which describes a *set* of argvs, not one), or text this module will not read as words.
 *
 * This is the question the suggestion engine has to ask before it writes a rule: "would the thing I am
 * about to store say the same thing the click said?" — and the answer includes the target, because a
 * specifier whose words match while its file does not is not the same invocation.
 */
export function ruleSpecifier(rule: PermissionRule): RuleSpecifier | null {
	if (rule.ruleValue.toolName !== BASH_TOOL) return null
	const specifier = specifierOf(rule)
	if (specifier === null) return null
	const shape = parsePermissionRule(specifier)
	if (shape.type === "wildcard") return null
	return readSpecifier(shape.type === "prefix" ? shape.prefix : shape.command)
}

/**
 * The WORDS a rule's specifier names, without its redirect clause — null when it names no argument list
 * at all. Kept for callers that compare words (`argv-suggestion.test.ts` checks that a written rule
 * dropped none of them); it is not a coverage question and must not be treated as one, because for
 * `Bash(echo hi > /tmp/out.txt)` the answer here is `["echo","hi"]` and the file is the rest of it.
 * Use {@link ruleSpecifier} when the whole specifier matters.
 */
export function ruleArgv(rule: PermissionRule): string[] | null {
	return ruleSpecifier(rule)?.words ?? null
}
