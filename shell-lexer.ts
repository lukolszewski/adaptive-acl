/**
 * Best-effort POSIX/bash lexer for the auto-mode risk policy.
 *
 * Turns a command string into a flat list of simple commands with:
 *   - argv words (quotes removed, but each word remembers whether it was quoted
 *     and whether it still contains an unexpanded `$var` / `$(...)` / backtick)
 *   - redirections (operator + target word)
 *   - heredoc bodies (`<<EOF` … `EOF`, `<<'EOF'`, `<<-EOF`)
 *   - the operator that connects it to the previous command (`;`, `&&`, `||`,
 *     `|`, `&`, newline)
 *   - inline substitutions (`$(...)`, `` `...` ``, `<(...)`, `>(...)`) extracted
 *     as separate command strings so they can be classified recursively.
 *
 * Reserved words (`if then else fi for do done while until case esac in {} !
 * function select`) are dropped so that the commands inside control structures
 * are still seen. This is not a shell parser; it errs toward *reporting* more
 * commands rather than fewer, which is the safe direction for a gate.
 */

export type Word = {
	/** Value with quotes removed; `$var`/`$(...)` left as-is (unexpanded). */
	value: string
	/** Original source text of the word. */
	raw: string
	/** Entire word was single- or double-quoted. */
	quoted: boolean
	/** Contains an unexpanded parameter or command substitution. */
	hasExpansion: boolean
}

export type Redirect = {
	/** `>`, `>>`, `<`, `&>`, `&>>`, `>|`, `<>`; fd prefix is stripped. */
	op: string
	fd?: number
	target: Word
}

export type SimpleCommand = {
	argv: Word[]
	/** Leading `NAME=value` assignments (values unquoted). */
	assignments: Array<{ name: string; value: string; hasExpansion: boolean }>
	redirects: Redirect[]
	/** Heredoc bodies attached to this command (in order). */
	heredocs: string[]
	/** Operator that precedes this command: "", ";", "&&", "||", "|", "|&", "&", "\n". */
	connector: string
	/** Commands found inside `$(...)`, backticks, `<(...)`, `>(...)` of this command's words. */
	substitutions: string[]
	/** Raw source slice for display. */
	raw: string
}

const RESERVED = new Set([
	"if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done",
	"case", "esac", "in", "function", "select", "!", "{", "}", "time", "coproc",
])

const REDIRECT_RE = /^(\d*)(&>>|&>|>>|>\||>|<>|<<<|<<-|<<|<)/

function isWordChar(ch: string): boolean {
	return !/[\s;&|()<>]/.test(ch)
}

type Token =
	| { kind: "word"; word: Word; raw: string }
	| { kind: "op"; op: string }
	| { kind: "redirect"; op: string; fd?: number; target?: Word; heredoc?: { delimiter: string; quoted: boolean; stripTabs: boolean } }
	| { kind: "newline" }

/** Extract the balanced body starting after `$(` / `<(` / `>(` at index i (which points at "("). */
/** Accumulates the first "ran off the end of the input mid-construct" problem.
 *  Used only by lexShellChecked; classification callers pass nothing and are
 *  unaffected. */
export type LexDiagnostics = { ok: boolean; reason?: string }

function fail(diag: LexDiagnostics | undefined, reason: string): void {
	if (diag && diag.ok) { diag.ok = false; diag.reason = reason }
}

function readBalanced(src: string, i: number, open: string, close: string, diag?: LexDiagnostics): { body: string; end: number } {
	let depth = 0
	let quote: "'" | '"' | null = null
	let j = i
	for (; j < src.length; j++) {
		const ch = src[j]!
		if (quote) {
			if (ch === "\\" && quote === '"') { j++; continue }
			if (ch === quote) quote = null
			continue
		}
		if (ch === "\\") { j++; continue }
		if (ch === "'" || ch === '"') { quote = ch; continue }
		if (ch === open) depth++
		else if (ch === close) {
			depth--
			if (depth === 0) return { body: src.slice(i + 1, j), end: j }
		}
	}
	fail(diag, `unbalanced ${open}${close} substitution`)
	return { body: src.slice(i + 1), end: src.length - 1 }
}

/**
 * Tokenise one word starting at `i`. Returns the word and the index just after it.
 * Collects substitutions found inside into `subs`.
 */
function readWord(src: string, i: number, subs: string[], diag?: LexDiagnostics): { word: Word; end: number } {
	let value = ""
	let raw = ""
	let quoted = false
	let sawUnquoted = false
	let hasExpansion = false
	let j = i
	while (j < src.length) {
		const ch = src[j]!
		if (ch === "'") {
			const endQ = src.indexOf("'", j + 1)
			if (endQ === -1) fail(diag, "unterminated single quote")
			const inner = endQ === -1 ? src.slice(j + 1) : src.slice(j + 1, endQ)
			value += inner
			raw += src.slice(j, endQ === -1 ? src.length : endQ + 1)
			quoted = true
			j = endQ === -1 ? src.length : endQ + 1
			continue
		}
		if (ch === '"') {
			quoted = true
			let k = j + 1
			raw += '"'
			while (k < src.length && src[k] !== '"') {
				const c = src[k]!
				if (c === "\\" && k + 1 < src.length && /["\\$`\n]/.test(src[k + 1]!)) {
					value += src[k + 1]
					raw += src.slice(k, k + 2)
					k += 2
					continue
				}
				if (c === "$" && src[k + 1] === "(") {
					const { body, end } = readBalanced(src, k + 1, "(", ")", diag)
					subs.push(body)
					hasExpansion = true
					value += src.slice(k, end + 1)
					raw += src.slice(k, end + 1)
					k = end + 1
					continue
				}
				if (c === "`") {
					const endB = src.indexOf("`", k + 1)
					if (endB === -1) fail(diag, "unterminated backtick substitution")
					const body = endB === -1 ? src.slice(k + 1) : src.slice(k + 1, endB)
					subs.push(body)
					hasExpansion = true
					value += src.slice(k, endB === -1 ? src.length : endB + 1)
					raw += src.slice(k, endB === -1 ? src.length : endB + 1)
					k = endB === -1 ? src.length : endB + 1
					continue
				}
				if (c === "$") hasExpansion = true
				value += c
				raw += c
				k++
			}
			if (k >= src.length && src[k] !== '"') fail(diag, "unterminated double quote")
			raw += '"'
			j = k + 1
			continue
		}
		if (ch === "\\") {
			if (j + 1 < src.length) {
				if (src[j + 1] === "\n") { j += 2; continue } // line continuation
				value += src[j + 1]
				raw += src.slice(j, j + 2)
				j += 2
				continue
			}
			j++
			continue
		}
		if (ch === "$" && src[j + 1] === "(") {
			const { body, end } = readBalanced(src, j + 1, "(", ")", diag)
			subs.push(body)
			hasExpansion = true
			value += src.slice(j, end + 1)
			raw += src.slice(j, end + 1)
			j = end + 1
			sawUnquoted = true
			continue
		}
		if (ch === "`") {
			const endB = src.indexOf("`", j + 1)
			if (endB === -1) fail(diag, "unterminated backtick substitution")
			const body = endB === -1 ? src.slice(j + 1) : src.slice(j + 1, endB)
			subs.push(body)
			hasExpansion = true
			const piece = src.slice(j, endB === -1 ? src.length : endB + 1)
			value += piece
			raw += piece
			j = endB === -1 ? src.length : endB + 1
			sawUnquoted = true
			continue
		}
		if ((ch === "<" || ch === ">") && src[j + 1] === "(" ) {
			const { body, end } = readBalanced(src, j + 1, "(", ")", diag)
			subs.push(body)
			hasExpansion = true
			const piece = src.slice(j, end + 1)
			value += piece
			raw += piece
			j = end + 1
			sawUnquoted = true
			continue
		}
		if (!isWordChar(ch)) break
		if (ch === "$") hasExpansion = true
		value += ch
		raw += ch
		j++
		sawUnquoted = true
	}
	return { word: { value, raw, quoted: quoted && !sawUnquoted, hasExpansion }, end: j }
}

function tokenize(src: string, diag?: LexDiagnostics): Token[] {
	const tokens: Token[] = []
	const subs: string[] = []
	let i = 0
	const pendingHeredocs: Array<{ delimiter: string; quoted: boolean; stripTabs: boolean; token: Extract<Token, { kind: "redirect" }> }> = []
	let atCommandStart = true

	const drainHeredocs = () => {
		// Called at a newline: consume heredoc bodies in order. The inner loop can
		// only exit without `found` by running out of input, so `!found` means the
		// delimiter never appeared — an unterminated heredoc.
		while (pendingHeredocs.length) {
			const h = pendingHeredocs.shift()!
			const lines: string[] = []
			let found = false
			while (i < src.length) {
				let nl = src.indexOf("\n", i)
				if (nl === -1) nl = src.length
				let line = src.slice(i, nl)
				i = nl + 1
				const cmp = h.stripTabs ? line.replace(/^\t+/, "") : line
				if (cmp === h.delimiter) { found = true; break }
				lines.push(line)
			}
			if (!found) fail(diag, `unterminated heredoc (<<${h.delimiter})`)
			h.token.heredoc = { delimiter: h.delimiter, quoted: h.quoted, stripTabs: h.stripTabs }
			;(h.token as { body?: string }).body = lines.join("\n")
		}
	}

	while (i < src.length) {
		const ch = src[i]!
		if (ch === "\n") {
			i++
			tokens.push({ kind: "newline" })
			drainHeredocs()
			atCommandStart = true
			continue
		}
		if (ch === " " || ch === "\t" || ch === "\r") { i++; continue }
		if (ch === "#" && (atCommandStart || /\s/.test(src[i - 1] ?? " "))) {
			// comment to end of line
			let nl = src.indexOf("\n", i)
			if (nl === -1) nl = src.length
			i = nl
			continue
		}
		if (src.startsWith("&&", i) || src.startsWith("||", i) || src.startsWith(";;", i) || src.startsWith("|&", i)) {
			tokens.push({ kind: "op", op: src.slice(i, i + 2) })
			i += 2
			atCommandStart = true
			continue
		}
		if (ch === ";" || ch === "|" || ch === "&" || ch === "(" || ch === ")") {
			// `&` used in `2>&1` style is handled by REDIRECT parsing below (fd dup)
			tokens.push({ kind: "op", op: ch })
			i++
			atCommandStart = ch !== ")"
			continue
		}
		const rm = REDIRECT_RE.exec(src.slice(i, i + 4))
		if (rm) {
			const fd = rm[1] ? Number(rm[1]) : undefined
			const op = rm[2]!
			i += rm[0].length
			if (op === "<<" || op === "<<-") {
				// heredoc delimiter
				while (src[i] === " " || src[i] === "\t") i++
				let quoted = false
				let delimiter = ""
				if (src[i] === "'" || src[i] === '"') {
					const q = src[i]!
					const endQ = src.indexOf(q, i + 1)
					if (endQ === -1) fail(diag, "unterminated quote in heredoc delimiter")
					delimiter = src.slice(i + 1, endQ === -1 ? src.length : endQ)
					quoted = true
					i = endQ === -1 ? src.length : endQ + 1
				} else {
					let j = i
					while (j < src.length && isWordChar(src[j]!)) {
						if (src[j] === "\\") { j += 2; continue }
						j++
					}
					delimiter = src.slice(i, j).replace(/\\/g, "")
					quoted = src.slice(i, j).includes("\\")
					i = j
				}
				const tok: Extract<Token, { kind: "redirect" }> = { kind: "redirect", op, fd }
				tokens.push(tok)
				pendingHeredocs.push({ delimiter, quoted, stripTabs: op === "<<-", token: tok })
				continue
			}
			// fd duplication: >&1, 2>&1, <&0 — no file target
			if (src[i] === "&" && /\d|-/.test(src[i + 1] ?? "")) {
				let j = i + 1
				while (j < src.length && /[\d-]/.test(src[j]!)) j++
				i = j
				continue
			}
			while (src[i] === " " || src[i] === "\t") i++
			const { word, end } = readWord(src, i, subs, diag)
			i = end
			tokens.push({ kind: "redirect", op, fd, target: word })
			continue
		}
		const { word, end } = readWord(src, i, subs, diag)
		if (end === i) { i++; continue }
		i = end
		tokens.push({ kind: "word", word, raw: word.raw })
		atCommandStart = false
	}
	drainHeredocs()
	// Attach the collected substitutions to the token stream via a sentinel.
	;(tokens as unknown as { subs?: string[] }).subs = subs
	return tokens
}

/** Parse a command string into simple commands. */
export function lexShell(command: string): SimpleCommand[] {
	return lexShellChecked(command).commands
}

/** Like lexShell, but also reports whether the input tokenised cleanly. `ok` is
 *  false when the lexer ran off the end of the input mid-construct (unterminated
 *  quote / heredoc / substitution) — i.e. the command is malformed and the
 *  segment list is unreliable. Callers should refuse-and-ask-to-fix rather than
 *  trust the fabricated segments. */
export function lexShellChecked(command: string): { commands: SimpleCommand[]; ok: boolean; reason?: string } {
	const diag: LexDiagnostics = { ok: true }
	const tokens = tokenize(command, diag)
	const allSubs = ((tokens as unknown as { subs?: string[] }).subs ?? []).slice()
	const commands: SimpleCommand[] = []
	let cur: SimpleCommand | null = null
	let connector = ""
	let forListSkip = false
	let caseSkip = false

	const flush = () => {
		if (cur && (cur.argv.length || cur.assignments.length || cur.redirects.length)) {
			commands.push(cur)
		}
		cur = null
	}
	const ensure = (): SimpleCommand => {
		if (!cur) {
			cur = { argv: [], assignments: [], redirects: [], heredocs: [], connector, substitutions: [], raw: "" }
			connector = ""
		}
		return cur
	}

	for (const tok of tokens) {
		if (tok.kind === "newline") {
			flush()
			connector = "\n"
			forListSkip = false
			continue
		}
		if (tok.kind === "op") {
			if (tok.op === "(" || tok.op === ")") {
				flush()
				if (tok.op === ")") caseSkip = false
				continue
			}
			flush()
			connector = tok.op === ";;" ? ";" : tok.op
			forListSkip = false
			continue
		}
		if (tok.kind === "redirect") {
			const c = ensure()
			const body = (tok as { body?: string }).body
			if (tok.heredoc) {
				c.heredocs.push(body ?? "")
				c.raw += ` ${tok.op}${tok.heredoc.delimiter}`
				continue
			}
			if (tok.target) {
				c.redirects.push({ op: tok.op, fd: tok.fd, target: tok.target })
				c.raw += ` ${tok.fd ?? ""}${tok.op}${tok.target.raw}`
			}
			continue
		}
		// word
		const w = tok.word
		if (forListSkip) continue
		if (caseSkip) {
			// inside `case x in` — pattern list up to `)` handled by op ")"
			if (w.value.endsWith(")")) caseSkip = false
			continue
		}
		// `cur` is reassigned inside the `ensure()`/`flush()` closures, so control-flow analysis believes it is
		// still `null` here and calls the right-hand side dead code (TS2339 on `never`). It is not dead: widening
		// explicitly states the real state rather than silencing the complaint with `!`.
		const active = cur as SimpleCommand | null
		if (!active || active.argv.length === 0) {
			if (!w.quoted && RESERVED.has(w.value)) {
				if (w.value === "for" || w.value === "select") {
					// `for NAME in list;` — skip until the next `;`/newline/`do`
					forListSkip = true
				}
				if (w.value === "case") caseSkip = true
				if (w.value === "in") caseSkip = true
				continue
			}
			// leading assignments
			const am = /^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$/s.exec(w.value)
			if (am && !w.quoted && (!active || active.argv.length === 0)) {
				const c = ensure()
				c.assignments.push({ name: am[1]!, value: am[3] ?? "", hasExpansion: w.hasExpansion })
				c.raw += (c.raw ? " " : "") + w.raw
				continue
			}
		}
		const c = ensure()
		c.argv.push(w)
		c.raw += (c.raw ? " " : "") + w.raw
	}
	flush()

	// Distribute substitutions: a word carrying `$(`/backtick belongs to a command;
	// simplest robust approach — attach every substitution found to the command
	// whose raw text contains it.
	for (const sub of allSubs) {
		const owner = commands.find((c) => c.raw.includes(sub))
		;(owner ?? commands[0])?.substitutions.push(sub)
	}
	return { commands, ok: diag.ok, reason: diag.reason }
}

/** Render argv back to a readable string (values, not raw). */
export function argvToString(cmd: SimpleCommand): string {
	return cmd.argv.map((w) => w.value).join(" ")
}
