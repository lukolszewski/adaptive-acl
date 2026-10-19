/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * bash-walker-heredoc.ts — here-documents (docs/LAYER0-WALKER-SPEC.md §8) for the layer-0 walker.
 *
 * Two jobs live here, and both of them are about the one construct whose text is *below* the line
 * the parser is looking at:
 *
 * - {@link takeHeredoc} — the tree side (§2 step 10). `bash-walker.ts` hands over every
 *   `heredoc_redirect` node together with the command it emitted last; the body is quoted-delimiter
 *   only, is handed to the caller exactly as it was written, and never touches the owner's span.
 * - {@link maskedCopy} — the text side (§8.6–§8.8). The step-5 brace scan reads characters, and an
 *   inert body full of JSON looks exactly like brace obfuscation to it, so the scan may be handed a
 *   copy of the input with quoted bodies blanked. That copy is proof-carrying (§8.7) and it is never
 *   what any reported value comes from (§8.8).
 *
 * The helpers {@link readHeredocOperator} and {@link findHeredocTerminator} are the text grammar of
 * the construct — operator, delimiter, terminator line — so the step-3 delimiter scan in
 * bash-walker-scan.ts can recognise a heredoc without re-deriving these rules.
 */

import type { AstCommand } from "./bash-ast.ts"
import type { Node } from "web-tree-sitter"
import { MAX_COMMAND_CHARS, parseBash } from "./bash-parser.ts"
import { refuse, type Refusal } from "./bash-walker.ts"

/** A stretch of source that is a heredoc body, terminator excluded (§8.6). */
export type BodySlice = { start: number; end: number }

/** The delimiter word written after `<<`, as the shell would read it. */
export type Delimiter = {
	/** The delimiter with its quoting removed — what the terminator line has to equal. */
	delimiter: string
	/** True when any part of the word was quoted, so the body is inert data (§8.1). */
	quoted: boolean
	/** Just past the delimiter word. */
	end: number
	/** A quote opened in the delimiter and never closed (§8.9). */
	quoteUnopened: boolean
	/** False when no delimiter word is there at all (`<<` followed by a metacharacter). */
	present: boolean
}

/** Where a heredoc's body ends and its terminator line is. */
export type Terminator = {
	/** Just past the last line of the body — the start of the terminator line. */
	bodyEnd: number
	/** Start of the terminator line's text, or -1 when there is none. */
	terminatorStart: number
	/** Just past the terminator; where a text scan resumes. */
	resumeAt: number
	/** True when `resumeAt` is the first character of the following line. */
	atLineStart: boolean
	/** False when the terminator line never appears (§8.9 `unterminated-heredoc`). */
	terminated: boolean
}

/** Characters that end the delimiter word. */
const DELIMITER_END = /[\s;&|<>()]/

/**
 * Read the delimiter word of a heredoc. `from` is the index just past `<<` or `<<-`.
 *
 * Quoting anywhere in the word makes the body inert — `<<'E'`, `<<"E"`, `<<\E` and the mixed
 * spellings all mean the same thing to bash — and the terminator has to match the word with its
 * quotes removed, which is what {@link Delimiter.delimiter} carries.
 */
export function readHeredocDelimiter(text: string, from: number): Delimiter {
	const found: Delimiter = { delimiter: "", quoted: false, end: from, quoteUnopened: false, present: false }
	let i = from
	while (text[i] === " " || text[i] === "\t") i += 1 // `<< 'E'` is a heredoc with a quoted delimiter

	for (;;) {
		const ch = text[i]
		if (ch === undefined || ch === "\n" || DELIMITER_END.test(ch)) break
		if (ch === "'" || ch === '"') {
			const close = text.indexOf(ch, i + 1)
			if (close < 0) {
				found.quoteUnopened = true // §8.9: the delimiter's quote never closes
				return found
			}
			found.delimiter += text.slice(i + 1, close)
			found.quoted = true
			i = close + 1
			continue
		}
		if (ch === "\\") {
			found.quoted = true // an escaped first character quotes the word exactly like 'E' does
			found.delimiter += text[i + 1] ?? ""
			i += text[i + 1] === undefined ? 1 : 2
			continue
		}
		found.delimiter += ch
		i += 1
	}
	found.end = i
	found.present = found.delimiter.length > 0
	return found
}

/**
 * Find the line that ends a heredoc body. `from` is the first character of the first body line.
 *
 * A `<<-` body is matched with its leading tabs ignored (§8.2 — the tabs are stripped for the
 * comparison only; the body itself is handed over with them). `allowClosingTail` says the heredoc
 * was opened inside a substitution, where the text that closes the substitution may share the
 * terminator line; without it a terminator line is the delimiter and nothing else.
 */
export function findHeredocTerminator(text: string, from: number, delimiter: string, stripTabs: boolean, allowClosingTail: boolean): Terminator {
	let line = from
	for (;;) {
		const lineEnd = text.indexOf("\n", line)
		const stop = lineEnd < 0 ? text.length : lineEnd
		let body = text.slice(line, stop)
		if (stripTabs) body = body.replace(/^\t+/, "")
		if (body === delimiter) {
			return { bodyEnd: line, terminatorStart: line, resumeAt: lineEnd < 0 ? text.length : lineEnd + 1, atLineStart: true, terminated: true }
		}
		if (allowClosingTail && body.startsWith(delimiter)) {
			// `$(cat <<'E' … E)` — the grammar closes the substitution on the terminator line, so the
			// scan resumes after the delimiter rather than after the newline.
			return { bodyEnd: line, terminatorStart: line, resumeAt: line + delimiter.length, atLineStart: false, terminated: true }
		}
		if (lineEnd < 0) return { bodyEnd: text.length, terminatorStart: -1, resumeAt: text.length, atLineStart: false, terminated: false }
		line = lineEnd + 1
	}
}

/**
 * §8.6 — a copy of `input` in which every listed body is blanks of the same length, newlines kept,
 * or `null` when no such copy can be proved.
 *
 * §8.7 is why this returns `null` more often than "there were no bodies": every body has to be
 * quoted-delimiter and terminated, every `heredoc_redirect` in the tree has to be one the walker can
 * account for, and the masked input has to parse to the same constructs at the same positions in the
 * same numbers as the input. One missing proof and the caller keeps the refusal it already had.
 */
export function maskedCopy(input: string, bodies: readonly BodySlice[]): string | null {
	if (bodies.length === 0) return null // nothing to mask
	for (const body of bodies) {
		if (body.start < 0 || body.end < body.start || body.end > input.length) return null
		if (input.slice(body.start, body.end).includes("<<")) return null // a body within a body: not ours to prove
	}
	if (input.length > MAX_COMMAND_CHARS) return null

	const blanked = blank(input, bodies)
	const before = parseBash(input)
	if ("error" in before) return null
	const after = parseBash(blanked)
	try {
		if ("error" in after) return null
		// §8.7: the same constructs, at the same positions, the same count, and no construct the
		// walker could not account for before the mask or after it.
		if (!sameConstructs(before.tree.rootNode, after.tree.rootNode)) return null
		if (!redirectsAccountedFor(before.tree.rootNode, bodies.length)) return null
		return blanked
	} finally {
		before.tree.delete()
		if (!("error" in after)) after.tree.delete()
	}
}

/** The input with each body replaced by an equal-length run of blanks, newlines preserved. */
function blank(input: string, bodies: readonly BodySlice[]): string {
	const chars = input.split("")
	for (const body of bodies) {
		for (let i = body.start; i < body.end; i++) {
			if (chars[i] !== "\n") chars[i] = " "
		}
	}
	return chars.join("")
}

/**
 * Same tree, node for node: type, extent, named-ness and the flags that say a node is broken. The
 * mask cannot move or change anything, so this is an exact comparison rather than a similarity one.
 */
function sameConstructs(a: Node, b: Node): boolean {
	if (a.type !== b.type || a.isNamed !== b.isNamed || a.isMissing !== b.isMissing || a.hasError !== b.hasError) return false
	// The one node the mask was told to rewrite: a `heredoc_body` whose text has become blanks is
	// reported at wherever the blanks stop, inside the range that was blanked. Every other node sits
	// in text the mask left byte for byte the same, so an extent that moves anywhere else means the
	// mask changed the command rather than its body.
	if (a.type === "heredoc_body") return b.startIndex >= a.startIndex && b.endIndex <= a.endIndex
	if (a.startIndex !== b.startIndex || a.endIndex !== b.endIndex) return false
	const left = a.children
	const right = b.children
	if (left.length !== right.length) return false
	for (let i = 0; i < left.length; i++) {
		if (!sameConstructs(left[i], right[i])) return false
	}
	return true
}

/** The node types a `heredoc_redirect` is allowed to hold; anything else is an owner we cannot name. */
const HEREDOC_INNARDS = new Set(["file_descriptor", "<<", "<<-", "heredoc_start", "heredoc_body", "heredoc_end"])

/**
 * Redirects that can sit in front of a heredoc operator inside one statement and still belong to the
 * command the operator belongs to (§7.4). Their own span is part of that command's span (§13.3), so a
 * word written behind one is still that command's word.
 */
const OWNED_REDIRECTS = new Set(["file_redirect", "herestring_redirect"])

/** Every `heredoc_redirect` in the tree, and whether each one is plain enough to attribute (§8.7). */
function redirectsAccountedFor(root: Node, expected: number): boolean {
	let seen = 0
	const stack: Node[] = [root]
	while (stack.length > 0) {
		const node = stack.pop() as Node
		if (node.type === "heredoc_redirect") {
			seen += 1
			if (seen > expected) return false
			if (!node.children.every((child) => HEREDOC_INNARDS.has(child.type))) return false
		}
		for (const child of node.children) stack.push(child)
	}
	return seen === expected
}

// --------------------------------------------------------------------------- §2 step 10, tree side

/**
 * §8.1–§8.5, §8.9: attach one `heredoc_redirect` to the command that owns it.
 *
 * The owner's `argv`, `text`, `end` are corrected here when the grammar swallowed an argument in
 * front of the operator (§8.4); nothing else about the owner is touched, and the body is the source
 * that was written (§8.8).
 */
export function takeHeredoc(redirect: Node, owner: AstCommand): Refusal | null {
	const operator = redirect.children.find((child) => child.type === "<<" || child.type === "<<-")
	const start = redirect.children.find((child) => child.type === "heredoc_start")
	const body = redirect.children.find((child) => child.type === "heredoc_body")
	const terminator = redirect.children.find((child) => child.type === "heredoc_end")

	// §8.9: a body the walker cannot give an owner. Anything sitting in the redirect besides the
	// descriptor, the operator, the delimiter, the body and the terminator — a pipeline written on
	// the delimiter line, a redirect the walker would otherwise never see — means the walker cannot
	// say who owns this body, and it is not free to guess.
	for (const child of redirect.children) {
		if (!HEREDOC_INNARDS.has(child.type)) return refuse("heredoc-unattributed", child.type)
	}
	if (!operator || !start || !body || !terminator) return refuse("heredoc-unattributed", redirect.type)

	// §8.1: only a quoted delimiter makes a body inert. The walker does not look inside an unquoted
	// one to rescue it — the parser does not report every expansion that runs there.
	const delimiter = readHeredocDelimiter(redirect.text, operator.endIndex - redirect.startIndex)
	if (!delimiter.quoted) return refuse("heredoc-unquoted-delimiter", start.type)
	if (terminator.endIndex < body.startIndex) return refuse("unterminated-heredoc", redirect.type)

	// §8.4: a word the grammar left in front of the operator goes back into argv, and the span grows
	// to cover it. The span is recomputed from the source rather than appended to (§13.2), so the
	// only way it can be wrong is by covering text that is not part of this command — which is
	// exactly the case `frontOf` refuses.
	const source = redirect.tree.rootNode.text
	const front = frontOf(redirect, owner)
	if (front === "unreadable") return refuse("heredoc-unattributed", redirect.type)
	if (front.words.length > 0) {
		owner.argv.push(...front.words)
		owner.end = front.end
		owner.text = source.slice(owner.start, front.end)
	}

	// §8.2 verbatim, §8.3 order: the body as written — leading tabs and all — minus the single
	// newline the shell does not pass on. `owner.text` never covers it (§13.3), so the span is left
	// alone here.
	owner.heredocs.push(withoutFinalNewline(source, body, operator.type === "<<-"))
	return null
}

/**
 * The body the caller sees: everything that was written, less the newline that ended the last line.
 *
 * For `<<-` the grammar reports the body from the first character the shell would keep, which drops
 * the tabs that were written in front of it. Stripping those is the shell's job at run time, not the
 * walker's (§8.2), so the tabs on the line the body starts on are taken back. A zero-length body is
 * a terminator line, and its tabs were never body text.
 */
function withoutFinalNewline(source: string, body: Node, tabStripped: boolean): string {
	let from = body.startIndex
	if (tabStripped && body.startIndex < body.endIndex) {
		while (source[from - 1] === "\t") from -= 1
		if (source[from - 1] !== "\n") from = body.startIndex // not the start of a line after all
	}
	const text = source.slice(from, body.endIndex)
	return text.endsWith("\n") ? text.slice(0, -1) : text
}

/** What sat in front of the operator: the words to hand back and where the command stops, or nothing. */
type Front = { words: string[]; end: number }

/**
 * §8.4, §8.5 — the words the grammar left in front of the heredoc operator.
 *
 * Three spellings lose an argument to the parser and all three are the same fact about the command:
 * a lone `-` between the last argument and the operator is dropped outright; a `-` written tight
 * against it (`cat -<<'E'`) is fused into the operator token; a `-3` is filed as a
 * `file_descriptor`, which bash does not accept as one (a descriptor is digits only). Every word here
 * goes back in `argv` in source order and the span is grown to cover it — dropping one would report
 * `python3` for a command bash runs as `python3 -`, which is the whole reason §8.4 exists.
 *
 * A digits-only descriptor is not a word and is not reported (§8.5). The gap may start at the end of a
 * redirect this command owns — §13.3 puts a command's own redirects inside its span, so the word behind
 * `cat > out.txt - <<'E'` is its word — but a gap that starts anywhere else, one that crosses a newline,
 * or one holding a word that is not a dash run is not something this module may turn into an argument.
 * `"unreadable"` says so; the caller refuses rather than writing a `text` that is not the substring it
 * names (§13.2).
 */
function frontOf(redirect: Node, owner: AstCommand): Front | "unreadable" {
	const source = redirect.tree.rootNode.text
	const operator = redirect.children.find((child) => child.type === "<<" || child.type === "<<-") as Node
	const descriptor = redirect.children.find((child) => child.type === "file_descriptor")
	const previous = redirect.previousSibling
	// The gap the grammar walked past: from the end of whatever preceded the operator — the owner's
	// last word, or a redirect written in front of it — to the operator itself.
	const from = previous ? Math.max(previous.endIndex, owner.end) : owner.end
	const front: Front = { words: [], end: owner.end }

	const gap = source.slice(from, redirect.startIndex)
	if (gap.trim() !== "") {
		// The gap has to start at this command's span, or at the end of a redirect this command owns:
		// bash runs `cat > out.txt - <<'E'` as `cat -`, and the dash the grammar dropped sits behind the
		// file redirect rather than behind the last word. A newline in the gap is a statement boundary, so
		// whatever sits after it is not a word of this command.
		if (from !== owner.end && !(previous && OWNED_REDIRECTS.has(previous.type))) return "unreadable"
		if (gap.includes("\n")) return "unreadable"
		for (const token of gap.trim().split(/\s+/)) {
			if (!token.startsWith("-")) return "unreadable"
			front.words.push(token)
		}
		front.end = from + gap.trimEnd().length
	}

	if (descriptor) {
		if (/^\d+$/.test(descriptor.text)) {
			// §8.5: a descriptor, not a word. With a dash fused onto the operator too (`cat 3-<<'E'`)
			// bash saw one word (`3-`) and this module has no business re-splitting it.
			if (dashRun(operator.text) !== "") return "unreadable"
		} else if (descriptor.text.startsWith("-")) {
			front.words.push(descriptor.text)
			front.end = descriptor.endIndex
		} else {
			return "unreadable"
		}
	}

	const fused = dashRun(operator.text)
	if (fused !== "") {
		if (descriptor) return "unreadable"
		front.words.push(fused)
		front.end = operator.startIndex + fused.length
	}
	return front
}

/** The `-` characters fused onto the front of a token. A `<<-` operator's own dash is at the end. */
function dashRun(token: string): string {
	const rest = token.replace(/^-+/, "")
	return token.slice(0, token.length - rest.length)
}
