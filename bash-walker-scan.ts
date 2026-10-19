/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * bash-walker-scan.ts — the text scans of §2 steps 2–5 (docs/LAYER0-WALKER-SPEC.md §10), the checks
 * that run on the input as written because they exist for the place where a reviewer, a shell and a
 * parser disagree about where a word begins or ends.
 *
 * One pass over the input reads it the way bash reads it — quotes, escapes, the forms `$` opens,
 * comments, and every here-document operator with its delimiter and its terminator — and collects:
 *
 * - the first delimiter that never closes (§2 step 3), named by which delimiter it is;
 * - the two things a word-boundary scan can see that a shell cannot be argued with: a control
 *   character and a space-like character that is an ordinary word character (§2 step 4, raw text —
 *   "anywhere in the input" is what §10 says, a heredoc body included);
 * - where the meaning of the text differs between shells (§2 step 5): escaped whitespace, `~[`, a
 *   word beginning `=`, and a brace group that a quote sits inside.
 *
 * Each scan names its own class (§10.6). The order of §2 is observable, so the pass keeps its
 * findings apart rather than keeping only the first character that upset it.
 *
 * The one place the input as written is not the whole story is the brace scan: §8.6 lets it be
 * re-run against a copy of the input with inert here-doc bodies blanked, and only with §8.7's proof,
 * which {@link maskedCopy} in bash-walker-heredoc.ts is the only thing here that supplies. Nothing
 * else — not the character scan, not the delimiter scan, not any reported value — ever sees it.
 */

import { MAX_COMMAND_CHARS } from "./bash-parser.ts"
import { refuse, type Refusal } from "./bash-walker.ts"
import { findHeredocTerminator, maskedCopy, readHeredocDelimiter, type BodySlice } from "./bash-walker-heredoc.ts"

/** One `<<` / `<<-` read off the text, with what the scan could establish about its body. */
export type TextHeredoc = {
	/** Where the operator starts. */
	operator: number
	/** The delimiter the terminator line has to equal. */
	delimiter: string
	/** True for `<<'E'`, `<<"E"`, `<<\E` — the body is inert data (§8.1). */
	quoted: boolean
	/** `<<-`, so the terminator is matched with leading tabs ignored (§8.2). */
	dash: boolean
	/** Body extent, terminator excluded; `bodyEnd` is where the terminator line begins. */
	bodyStart: number
	bodyEnd: number
	/** False when no terminator line appears (§8.9). */
	terminated: boolean
}

/** How the reader is sitting at one character. */
type Frame = {
	/** `code` is shell text; the others are quoted runs, whose braces cannot open a group. */
	kind: "code" | "single" | "double" | "ansi"
	/** What opened this frame: nothing, `$(`, `${`, a backtick. Only a code frame has one. */
	opener: "" | "$(" | "${" | "`"
	/** The character that closes a code frame opened by something other than a paren pair. */
	closer: string
	/** Open parens inside a `$(` frame, so the right one closes it. */
	parens: number
}

/** What one pass over the input established. */
type Reading = {
	/** §2 step 3 — the first delimiter that never closed. */
	refusal: Refusal | null
	/** Every here-document operator, in the order the text wrote them. */
	heredocs: TextHeredoc[]
	/** The input with every brace that cannot open a brace group blanked out (§10.5). */
	braceView: string
	/** A backslash before a blank, or joining one word to the next (§10.3). */
	escapedWhitespace: boolean
	/** A word that begins with `=` and a name character (§10.4). */
	leadingEquals: boolean
}

/** Characters that end a word. */
const WORD_BREAK = /[\s|&;()<>]/
/** What may follow a leading `=` for it to be another shell's path lookup (§10.4). */
const NAME_START = /[A-Za-z0-9_]/

/** §10.2 — characters that render as a space, or as nothing, and are ordinary word characters to bash. */
const UNICODE_WHITESPACE = /[\u00a0\u1680\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]/

/**
 * §2 steps 2–5, in that order, first refusal wins (§12.1). The input is never partially analysed: a
 * refusal here abandons the whole string.
 */
export function scanInput(input: string): Refusal | null {
	// §2 step 2 (§10.9) — the walker checks the cap too; both read the same constant.
	if (input.length > MAX_COMMAND_CHARS) return refuse("input-too-large")

	// §2 step 3 — every delimiter that opens has to close, heredoc delimiters and terminators
	// included, because a heredoc body decides what text the rest of the scans are even reading.
	const text = readText(input)
	if (text.refusal) return text.refusal

	// §2 step 4 — accepted characters, looked for in the input as written.
	const character = rejectedCharacter(input)
	if (character) return character

	// §2 step 5 — constructs whose meaning belongs to a different shell.
	return crossShell(input, text)
}

/** §10.1–§10.2, over the whole input: the first character this walker does not accept. */
function rejectedCharacter(input: string): Refusal | null {
	for (let i = 0; i < input.length; i++) {
		const code = input.charCodeAt(i)
		if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) return refuse("control-character")
		if (UNICODE_WHITESPACE.test(input[i])) return refuse("unicode-whitespace")
	}
	return null
}

/**
 * §10.3–§10.5, in the order §2 lists them, each naming its own class (§10.6). The brace class is
 * last because it is the only one that may consult a masked copy of the input (§2.2).
 */
function crossShell(input: string, text: Reading): Refusal | null {
	if (text.escapedWhitespace) return refuse("backslash-whitespace")
	if (input.includes("~[")) return refuse("zsh-tilde-bracket")
	if (text.leadingEquals) return refuse("zsh-equals-expansion")
	if (text.braceView.indexOf("{") < 0) return null
	if (!hidesAQuote(text.braceView)) return null

	// The class fired on the text as written. §8.7: it falls away only for a copy that is proved to
	// change nothing but inert body text; without that proof the refusal the input earned stands.
	const inert = inertBodies(text.heredocs)
	const masked = inert === null ? null : maskedCopy(input, inert)
	if (masked === null) return refuse("brace-with-quote")
	const again = readText(masked)
	if (again.refusal !== null) return refuse("brace-with-quote")
	if (hidesAQuote(again.braceView)) return refuse("brace-with-quote")
	return null
}

/**
 * §10.5 — a brace group a quote sits inside is the shape that hides what the group expands to.
 * Decided on the brace view, in which every brace that sits inside quotes, inside `${…}`, or inside a
 * comment has been blanked: none of those can open a group. One pass carries a flag per open brace —
 * has a quote appeared inside it yet — and any group that closes with its flag set is this class. A
 * brace that never closes belongs to no group and cannot expand, so an unclosed one is not.
 */
function hidesAQuote(view: string): boolean {
	const open: boolean[] = []
	for (const ch of view) {
		if (ch === "{") open.push(false)
		else if (ch === "}") {
			if (open.length === 0) continue
			if (open.pop() === true) return true
		} else if (ch === "'" || ch === '"' || ch === "`") {
			if (open.length > 0) open[open.length - 1] = true
		}
	}
	return false
}

/**
 * §8.7 — the bodies the mask may cover, or nothing at all. Every heredoc in the input has to be
 * quoted-delimiter and terminated for the mask to happen: one unquoted body and the whole mask is
 * abandoned, because the input that gets reported is the input as written and a scan that disagreed
 * with it is not a proof.
 */
function inertBodies(heredocs: readonly TextHeredoc[]): BodySlice[] | null {
	if (heredocs.length === 0) return null
	const bodies: BodySlice[] = []
	for (const one of heredocs) {
		if (!one.quoted || !one.terminated || one.bodyEnd < one.bodyStart) return null
		bodies.push({ start: one.bodyStart, end: one.bodyEnd })
	}
	return bodies
}

// --------------------------------------------------------------------------- one pass over the text

/**
 * Read the input the way bash reads it and collect what §2 steps 3 and 5 need. The reader keeps no
 * opinion about what any of it means; it answers where each construct starts and ends.
 */
function readText(input: string): Reading {
	const view: string[] = []
	const heredocs: TextHeredoc[] = []
	const waiting: TextHeredoc[] = []
	const stack: Frame[] = [{ kind: "code", opener: "", closer: "", parens: 0 }]
	const reading: Reading = { refusal: null, heredocs, braceView: "", escapedWhitespace: false, leadingEquals: false }

	const frame = (): Frame => stack[stack.length - 1]
	/** A brace counts towards a group only in shell text that is not a `${…}` run. */
	const braceChar = (ch: string): string => (frame().kind !== "code" || frame().opener === "${" ? (ch === "{" || ch === "}" ? " " : ch) : ch)
	const broken = (refusal: Refusal): void => {
		if (reading.refusal === null) reading.refusal = refusal
	}

	let atLineStart = true
	let wordOpen = false
	let i = 0
	while (i < input.length) {
		// A line that a command ended, with a here-document still waiting for its body: this line is
		// the body, and nothing else is read until its terminator.
		if (atLineStart && waiting.length > 0 && frame().kind === "code" && frame().opener !== "${") {
			const heredoc = waiting.shift() as TextHeredoc
			const hit = findHeredocTerminator(input, i, heredoc.delimiter, heredoc.dash, stack.length > 1)
			heredoc.bodyStart = i
			heredoc.bodyEnd = hit.bodyEnd
			heredoc.terminated = hit.terminated
			if (!hit.terminated) {
				broken(refuse("unterminated-heredoc", "heredoc_redirect"))
				return finish()
			}
			view.push(input.slice(i, hit.resumeAt))
			i = hit.resumeAt
			atLineStart = hit.atLineStart
			wordOpen = false
			continue
		}

		const ch = input[i]
		const here = frame()

		if (here.kind !== "code") {
			if (ch === "\\") {
				// §4: inside single quotes a backslash escapes nothing, so the character after it is read
				// on its own and `echo 'a\'` closes at its second `'`. In the other quoted runs a backslash
				// takes the next character with it. Either way it opens nothing, and §10.5 sees both
				// characters.
				const escapes = here.kind !== "single"
				view.push(braceChar(ch), escapes ? braceChar(input[i + 1] ?? "") : "")
				i += escapes ? 2 : 1
				wordOpen = true
				continue
			}
			if (ch === "\n") {
				view.push(ch)
				i += 1
				continue
			}
			if (ch === here.closer) {
				stack.pop()
				view.push(ch)
				i += 1
				wordOpen = true
				continue
			}
			if (ch === "$" && here.kind !== "single") {
				// A `$` inside a double-quoted run still opens a substitution, and that text is shell text.
				const dollar = dollarForm(input, i, here.kind)
				if (dollar !== null) {
					stack.push(dollar.frame)
					view.push(dollar.text)
					i += dollar.text.length
					continue
				}
			}
			view.push(braceChar(ch))
			i += 1
			wordOpen = true
			continue
		}

		if (ch === "\n") {
			view.push(ch)
			i += 1
			atLineStart = true
			wordOpen = false
			continue
		}
		atLineStart = false

		// A comment contributes nothing to any command, so its braces cannot open a group either.
		if (ch === "#" && !wordOpen && here.opener !== "${") {
			const stop = input.indexOf("\n", i)
			const end = stop < 0 ? input.length : stop
			view.push(run(input.slice(i, end)))
			i = end
			continue
		}

		if (ch === "\\") {
			const next = input[i + 1]
			if (next === " " || next === "\t") reading.escapedWhitespace = true
			else if (next === "\n" && joinsWord(input, i)) reading.escapedWhitespace = true // §10.1
			view.push(ch, next === undefined ? "" : next)
			i += next === undefined ? 1 : 2
			wordOpen = true
			continue
		}

		if (ch === "$") {
			const dollar = dollarForm(input, i, here.kind)
			if (dollar !== null) {
				stack.push(dollar.frame)
				view.push(dollar.text)
				i += dollar.text.length
				wordOpen = true
				continue
			}
			view.push(ch)
			i += 1
			wordOpen = true
			continue
		}

		// A here-string is not a here-document, and its third `<` must not be read as the start of
		// one. Consume the whole operator.
		if (ch === "<" && input[i + 1] === "<" && input[i + 2] === "<") {
			view.push("<<<")
			i += 3
			wordOpen = false
			continue
		}
		// A here-document operator. The descriptor in front of it is part of the operator as far as
		// this pass is concerned (§8.5).
		if (ch === "<" && input[i + 1] === "<") {
			const dash = input[i + 2] === "-"
			const delimiter = readHeredocDelimiter(input, i + 2 + (dash ? 1 : 0))
			if (delimiter.quoteUnopened) broken(refuse("unterminated-heredoc-delimiter", "heredoc_start"))
			else if (!delimiter.present) broken(refuse("unterminated-heredoc-delimiter", "heredoc_start"))
			if (reading.refusal !== null) return finish()
			const heredoc: TextHeredoc = {
				operator: i,
				delimiter: delimiter.delimiter,
				quoted: delimiter.quoted,
				dash,
				bodyStart: delimiter.end,
				bodyEnd: delimiter.end,
				terminated: false,
			}
			heredocs.push(heredoc)
			view.push(input.slice(i, delimiter.end))
			if (!delimiter.quoted && /[$`]/.test(delimiter.delimiter)) {
				// The terminator is a value the shell computes, so nothing below this point can be read
				// as text: the scan says nothing about the rest of the input. It is not malformed — the
				// command is refused by §8.1 for the unquoted delimiter, and an unquoted delimiter can
				// never take part in a mask (§8.7), so nothing passes on the strength of this.
				return finish()
			}
			waiting.push(heredoc)
			i = delimiter.end
			wordOpen = true
			continue
		}

		if (here.opener === "$(" && here.parens === 0 && ch === ")") {
			stack.pop()
			view.push(ch)
			i += 1
			wordOpen = false
			continue
		}
		if (here.opener === "${" && ch === "}") {
			stack.pop()
			view.push(" ")
			i += 1
			wordOpen = false
			continue
		}
		if (here.opener === "`" && ch === "`") {
			stack.pop()
			view.push(ch)
			i += 1
			wordOpen = false
			continue
		}
		if (here.opener === "$(" && ch === "(") here.parens += 1
		else if (here.opener === "$(" && ch === ")") here.parens -= 1

		if (ch === "`") {
			// A backtick substitution is shell text with an unusual closer: braces inside it can open a
			// group, and the next backtick is what ends it.
			stack.push({ kind: "code", opener: "`", closer: "`", parens: 0 })
		} else if (ch === "'" || ch === '"') {
			stack.push(ch === "'" ? { kind: "single", opener: "", closer: "'", parens: 0 } : { kind: "double", opener: "", closer: '"', parens: 0 })
		}

		// §10.4 — another shell looks the word up as a command; `VAR=1` and `--flag=x` have the `=`
		// mid-word and are not this class.
		if (ch === "=" && !wordOpen && NAME_START.test(input[i + 1] ?? "")) reading.leadingEquals = true

		view.push(braceChar(ch))
		i += 1
		wordOpen = !WORD_BREAK.test(ch)
	}

	// Something that opened and never closed. The outermost one is what the reader hits first.
	if (stack.length > 1) {
		const open = stack[1]
		broken(refuse(open.kind === "single" || open.kind === "double" || open.kind === "ansi" ? "unterminated-quote" : open.opener === "`" ? "unterminated-backtick" : "unterminated-substitution", open.opener === "`" ? "backtick_reference" : "string"))
	} else if (waiting.length > 0) {
		// An operator with no line after it at all: there is no body, and no terminator to find.
		broken(refuse("unterminated-heredoc", "heredoc_redirect"))
	}
	return finish()

	function finish(): Reading {
		reading.braceView = view.join("")
		return reading
	}
}

/**
 * The forms a `$` opens by itself, as a frame to push and the source it consumed. `null` when the
 * `$` is just a dollar sign. A backtick is shell text, so it opens a code frame; the quote forms are
 * quoted runs, so the braces inside them cannot open a group.
 *
 * `run` is where the `$` sits. A quote form opens a string only where a bare quote would open one:
 * inside a double-quoted run a `"` closes the run the `$` sits in and a `'` is one of its characters,
 * and an ANSI-C string interpolates nothing at all. This is also what stops the second half of `$$`
 * (§5.11) from opening a string — the first `$` is read, the second is reached as an ordinary
 * character, and the quote after it belongs to whatever it belongs to in bash.
 */
function dollarForm(input: string, at: number, run: Frame["kind"]): { frame: Frame; text: string } | null {
	const next = input[at + 1]
	if (next === undefined || run === "ansi") return null
	if (next === "(") return { frame: { kind: "code", opener: "$(", closer: ")", parens: 0 }, text: input.slice(at, at + 2) }
	if (next === "{") return { frame: { kind: "code", opener: "${", closer: "}", parens: 0 }, text: input.slice(at, at + 2) }
	if (run !== "code") return null
	if (next === "'") return { frame: { kind: "ansi", opener: "", closer: "'", parens: 0 }, text: input.slice(at, at + 2) }
	if (next === '"') return { frame: { kind: "double", opener: "", closer: '"', parens: 0 }, text: input.slice(at, at + 2) }
	return null
}

/**
 * §10.1 — a backslash-newline that joins one word to the next. When it only separates commands,
 * every reader agrees where the next command starts and it is not this class.
 */
function joinsWord(input: string, at: number): boolean {
	const before = input[at - 1]
	const after = input[at + 2]
	if (before === undefined || after === undefined) return false
	return !WORD_BREAK.test(before) && !WORD_BREAK.test(after)
}

/** A comment, with its braces blanked: nothing in it runs, whatever it looks like. */
function run(text: string): string {
	let out = ""
	for (const ch of text) out += ch === "{" || ch === "}" ? " " : ch
	return out
}
