/**
 * Shell permission rule matching, shared by every configured-rule check.
 *
 * A rule body is one of three shapes:
 *
 *   `git status`    whole command, compared verbatim
 *   `git:*`         legacy prefix — the command must be that program, or it plus arguments
 *   `git * main`    glob, where `*` stands for any run of characters (newlines included)
 *
 * Globs are matched by compiling the rule into its fixed text pieces and then walking
 * the command once against that piece list. No regular expression is involved: a rule
 * is data typed by a human into a settings file, and treating it as a regex would let
 * `rm -rf .*`-style text, or an unbalanced `(`, decide how the match behaves.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

const STAR = "*"
const BACKSLASH = "\\"
/** `tool:*` is prefix syntax, so its trailing star is never read as a wildcard. */
const PREFIX_SUFFIX = ":*"
/** `xargs git commit` is covered by `git:*` — the arguments arrive one run later. */
const XARGS = "xargs "

export type ExactShellRule = { type: "exact"; command: string }
export type PrefixShellRule = { type: "prefix"; prefix: string }
export type WildcardShellRule = { type: "wildcard"; pattern: string }

export type ShellPermissionRule = ExactShellRule | PrefixShellRule | WildcardShellRule

/** Text before `:*` in a prefix rule, or null when the rule is not prefix syntax. */
export function permissionRuleExtractPrefix(permissionRule: string): string | null {
	if (!permissionRule.endsWith(PREFIX_SUFFIX)) return null
	// The prefix has to be real text on a single line: ":*" on its own is not a rule.
	const head = permissionRule.slice(0, -PREFIX_SUFFIX.length)
	return head.length === 0 || head.includes("\n") ? null : head
}

/** How many backslashes sit immediately before position `at`. */
function backslashRun(text: string, at: number): number {
	let count = 0
	while (at - count - 1 >= 0 && text[at - count - 1] === BACKSLASH) count++
	return count
}

/** True when the rule contains a star the author did not escape with a backslash. */
export function hasWildcards(pattern: string): boolean {
	if (pattern.endsWith(PREFIX_SUFFIX)) return false
	for (let at = pattern.indexOf(STAR); at !== -1; at = pattern.indexOf(STAR, at + 1)) {
		if (backslashRun(pattern, at) % 2 === 0) return true
	}
	return false
}

/**
 * A glob cut into fixed text pieces. Piece `i` must appear in the command before
 * piece `i+1`; the gap between two pieces is one star, so it absorbs anything.
 *
 * `bareText` captures the one lenient reading we keep for usability: when the only
 * star in the rule is a trailing ` *`, the rule also covers the command with nothing
 * after that space. `npm run *` therefore covers `npm run` and `npm run build`, but
 * `npm * run *` (two stars) covers neither `npm x run` nor a bare `npm x run `.
 */
type Glob = { pieces: string[]; bareText: string | null }

function compileGlob(pattern: string): Glob {
	const pieces: string[] = [""]
	let stars = 0
	for (let at = 0; at < pattern.length; at++) {
		const char = pattern[at]!
		const following = at + 1 < pattern.length ? pattern[at + 1] : undefined
		// `\*` is a star in the text, `\\` a backslash in the text. A backslash in
		// front of anything else is not an escape at all and stays as it was typed,
		// so `\d` matches the two characters `\d` rather than a digit class.
		if (char === BACKSLASH && (following === STAR || following === BACKSLASH)) {
			pieces[pieces.length - 1]! += following
			at++
			continue
		}
		if (char === STAR) {
			stars++
			pieces.push("")
			continue
		}
		pieces[pieces.length - 1]! += char
	}
	const last = pieces[pieces.length - 1]!
	const head = pieces[0]!
	const trailingWordStar = stars === 1 && last === "" && head.endsWith(" ")
	return { pieces, bareText: trailingWordStar ? head.slice(0, -1) : null }
}

/** Does the fixed text occur at exactly this offset? */
function occursAt(text: string, offset: number, needle: string, foldCase: boolean): boolean {
	if (offset + needle.length > text.length) return false
	const window = text.slice(offset, offset + needle.length)
	if (window === needle) return true
	return foldCase && window.toLowerCase() === needle.toLowerCase()
}

function equalsText(text: string, expected: string, foldCase: boolean): boolean {
	if (text === expected) return true
	return foldCase && text.length === expected.length && text.toLowerCase() === expected.toLowerCase()
}

/** First offset at or after `from` where the fixed text occurs, or -1. */
function findText(text: string, needle: string, from: number, foldCase: boolean): number {
	if (needle === "") return from
	for (let at = from; at + needle.length <= text.length; at++) {
		if (occursAt(text, at, needle, foldCase)) return at
	}
	return -1
}

/**
 * One left-to-right pass over the command. Taking each middle piece at its earliest
 * possible spot is safe — the pieces are fixed text and the last piece is pinned to
 * the end, so an earlier match always leaves at least as much room as a later one.
 */
function coveredBy(pieces: string[], command: string, foldCase: boolean): boolean {
	const head = pieces[0]!
	if (!occursAt(command, 0, head, foldCase)) return false
	if (pieces.length === 1) return command.length === head.length

	let cursor = head.length
	for (let piece = 1; piece < pieces.length - 1; piece++) {
		const found = findText(command, pieces[piece]!, cursor, foldCase)
		if (found === -1) return false
		cursor = found + pieces[piece]!.length
	}

	const tail = pieces[pieces.length - 1]!
	const tailOffset = command.length - tail.length
	return tailOffset >= cursor && occursAt(command, tailOffset, tail, foldCase)
}

/**
 * Match a glob rule against a command. The rule is trimmed; the command is taken as
 * given. Stars span any characters including newlines, and every other character —
 * dots, brackets, dollars, pipes — is the literal character the author typed.
 */
export function matchWildcardPattern(pattern: string, command: string, caseInsensitive = false): boolean {
	const glob = compileGlob(pattern.trim())
	if (glob.bareText !== null && equalsText(command, glob.bareText, caseInsensitive)) return true
	return coveredBy(glob.pieces, command, caseInsensitive)
}

/** Sort a rule body into prefix syntax, glob, or plain whole-command text. */
export function parsePermissionRule(permissionRule: string): ShellPermissionRule {
	const prefix = permissionRuleExtractPrefix(permissionRule)
	if (prefix !== null) return { type: "prefix", prefix }
	if (hasWildcards(permissionRule)) return { type: "wildcard", pattern: permissionRule }
	return { type: "exact", command: permissionRule }
}

/** Is `command` the program `head` itself, or that program followed by arguments? */
function isInvocationOf(command: string, head: string): boolean {
	return command === head || command.startsWith(head + " ")
}

/**
 * Apply one parsed rule to one command segment.
 *
 * `matchMode` "exact" is the strict reading used where a rule may only cover the very
 * command it names: a prefix rule then needs an equal string and a glob never matches.
 * In "prefix" mode a prefix rule also covers arguments, plus the same invocation behind
 * `xargs`. The caller decides compound handling — it splits the command line into
 * segments and passes `allowCompound` false when the allow path must not vouch for a
 * chain — so this function scores exactly one segment either way.
 */
export function matchShellRule(rule: ShellPermissionRule, command: string, matchMode: "exact" | "prefix", allowCompound: boolean): boolean {
	const segment = command.trim()
	if (segment === "") return false

	if (rule.type === "exact") return rule.command === segment

	if (rule.type === "prefix") {
		if (matchMode === "exact") return rule.prefix === segment
		return isInvocationOf(segment, rule.prefix) || isInvocationOf(segment, XARGS + rule.prefix)
	}

	// A glob is a written pattern, not a command stem: it only ever scores the whole
	// segment, so the strict reading rejects it outright.
	if (matchMode === "exact") return false
	return matchWildcardPattern(rule.pattern, segment)
}
