/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * bash-walker-values.ts — part 2 of the layer-0 walker: assignments, remembered values and
 * run-time values (docs/LAYER0-WALKER-SPEC.md §4.2/§4.3, §5, §6, and the §3.1 builtins that
 * assign).
 *
 * `bash-walker.ts` produces the shape of a command — which words, which spans, which redirects —
 * and asks this module about every value it cannot produce from quoting alone:
 *
 *   - {@link resolveValue} — one expansion inside an argument, a redirect target or a test operand.
 *     A remembered literal is substituted (§5.3/§5.4), an inert or shell-controlled name becomes
 *     `__TRACKED_VAR__` inside quotes (§5.10, §5.11, §5.5), an accepted substitution becomes
 *     `__CMDSUB_OUTPUT__` (§6.1) with its own commands emitted first (§6.2), and a `cat` fed by a
 *     quoted-delimiter here-document is the one substitution with a known answer (§6.6).
 *   - {@link envAssignment} — a `NAME=value` prefix, visible to that command only (§5.1).
 *   - {@link rememberAssignment} — a statement-level assignment: nothing is emitted, the value is
 *     kept for later references (§5.2, §5.3).
 *   - {@link resolveDeclaration} — the guards over `export`/`declare`/`typeset`/`local`/`readonly`
 *     and `unset` (§3.1, §5.9). The walker emits the builtin as `argv[0]`.
 *
 * ## What is decided here and nowhere else
 *
 * Values only. Word resolution (quoting, escapes, adjacency — §4) stays in `bash-walker.ts`: the
 * two assignment entry points are handed a resolver rather than being given a second copy of §4.
 * `opaque` is not reported here at all — `settle()` derives it from the values that were reported,
 * so a resolver that also flagged it could only disagree (§6.3). The store holds what the input
 * said and nothing else: no clock, no filesystem, no environment (§14.4).
 *
 * ## Fail-closed rule
 *
 * Every path that does not end in a literal, a documented placeholder or an accepted substitution
 * ends in a refusal naming the §12 class. In particular a value is never guessed: a name with no
 * remembered value, a `${…}` spelling, a substitution the walker may not stand in for, and any
 * assignment that changes how the shell reads later text (§5.7) all refuse.
 */

import type { AstCommand } from "./bash-ast.ts"
import type { Node } from "web-tree-sitter"
import { CMDSUB_PLACEHOLDER, refuse, TRACKED_VAR_PLACEHOLDER, type Reason, type Refusal } from "./bash-walker.ts"

// --------------------------------------------------------------------------- contract

/** Where a value is being produced — the answer differs per position (§5, §6.5). */
export type ValuePosition = "argument" | "redirect-target" | "test-operand" | "env-prefix"

/** One request for the value of one node. */
export type ValueSite = {
	/** The expansion node, or a node the walker does not model at all. */
	node: Node
	/** What the value is being used for. */
	position: ValuePosition
	/** The enclosing word, resolved up to this expansion (`""` when it leads). */
	prefix: string
	/** The expansion is the entire word — §6.5 forbids a placeholder here. */
	whole: boolean
	/** The expansion sits inside double quotes, so its value cannot be re-split. */
	quoted: boolean
}

/** A resolved value, or the reason the walker may not have one. */
export type ResolvedValue = { ok: true; text: string } | { ok: false; refusal: Refusal }

/** A `NAME=value` prefix of a command, resolved. */
export type ResolvedAssignment = { ok: true; name: string; value: string } | { ok: false; refusal: Refusal }

/**
 * Walk the statements inside a substitution and append their commands to the result, so that
 * nothing hides inside an argument (§6.2). Refuses when the inside is not analysable.
 */
export type WalkInto = (node: Node) => Refusal | null

/**
 * Resolve a run of sibling nodes as one word, exactly as the walker resolves an argument (§4).
 * The walker supplies it: this module decides *whether* a value may be known, never how `"$a"b'c'`
 * resolves, because a second implementation of §4 would be a second place to get wrong.
 */
export type ResolveWord = (nodes: readonly Node[], position: ValuePosition) => ResolvedValue

/** What one name holds: a literal the caller can see, or the fact that nothing literal does. */
export type Remembered = { literal: string } | { unknown: true }

/**
 * Per-walk value store, created once per `walkBash` call and threaded through every entry point.
 * §14.4: it holds only what the input itself said — never the environment.
 */
export type ValueScope = {
	/** Statement-level assignments seen so far (§5.2, §5.5). */
	variables: Map<string, Remembered>
	/** §5.2 says emit nothing for an assignment; §14.1 says say *something* — see {@link reportRemembered}. */
	assignments: Array<{ name: string; value: string; node: Node }>
}

/** Fresh scope for one walk. */
export function newValueScope(): ValueScope {
	return { variables: new Map(), assignments: [] }
}

// --------------------------------------------------------------------------- §5.10 / §5.11 names

/**
 * §5.10 — names the shell sets, that always exist, and whose value the walker may only stand in
 * for inside double quotes. `IFS` is here because *reading* it in a string is harmless; writing it
 * is §5.7. A `${NAME}` spelling of any of them is refused regardless: the braces may carry a
 * transformation the walker does not model.
 */
const INERT_NAMES = new Set([
	"HOME", "PWD", "OLDPWD", "USER", "LOGNAME", "SHELL", "PATH", "HOSTNAME", "UID", "EUID",
	"PPID", "RANDOM", "SECONDS", "LINENO", "TMPDIR", "BASH_VERSION", "BASHPID", "SHLVL",
	"HISTFILE", "IFS",
])

/** §5.11 — special names with a placeholder and no more. */
const SPECIAL_NAMES = new Set(["?", "$", "!", "#", "0", "-"])

/** §5.11 — `@`, `*` and the positional parameters expand to caller-supplied text, or to nothing. */
function isPositional(name: string): boolean {
	return name === "@" || name === "*" || /^[1-9][0-9]*$/.test(name)
}

/**
 * §5.8 — the shape of a name bash accepts: a letter or an underscore, then letters, digits and
 * underscores. `1VAR=value` is therefore a word, not an assignment. Checked character by character
 * rather than by one pattern, because the pattern is also what a subscript or a `+=` hides behind.
 */
function isAssignmentName(name: string): boolean {
	if (name.length === 0 || !NAME_HEAD.test(name[0])) return false
	for (let i = 1; i < name.length; i++) {
		if (!NAME_TAIL.test(name[i])) return false
	}
	return true
}

const NAME_HEAD = /[A-Za-z_]/
const NAME_TAIL = /[A-Za-z0-9_]/

// --------------------------------------------------------------------------- §4.2 word-position refusals

/** Node types that end one word: nothing above them belongs to the argument being resolved. */
const WORD_BOUNDARIES = new Set([
	"program", "command", "test_command", "redirected_statement", "file_redirect",
	"herestring_redirect", "heredoc_redirect", "variable_assignment", "declaration_command",
	"unset_command", "for_statement", "c_style_for_statement", "while_statement", "list",
	"pipeline", "subshell", "negated_command", "comment", "ERROR", "MISSING",
])

/**
 * Is this expansion the entire content of its word, the quotes aside? §6.5 refuses a value that is
 * the whole argument, and the walker's own `whole` flag stops at the quotes of `"$HOME"` — the
 * enclosing `string` is a node of its own, so `"$X"` reaches this module as "not the whole piece".
 * A quote token between the expansion and the word boundary is quoting, not content; anything else
 * (`a"$X"`, `-n "$X"`) means the value is embedded and one argument out of it is honest.
 */
function contentWhole(node: Node): boolean {
	let current = { startIndex: node.startIndex, endIndex: node.endIndex }
	for (let parent = node.parent; parent; parent = parent.parent) {
		if (WORD_BOUNDARIES.has(parent.type)) return true
		for (const sibling of parent.children) {
			const same = sibling.startIndex === current.startIndex && sibling.endIndex === current.endIndex
			if (same || sibling.type === '"' || sibling.type === "'") continue
			return false
		}
		current = { startIndex: parent.startIndex, endIndex: parent.endIndex }
	}
	return true
}

/** §5.4 — a literal may be substituted bare only when nothing can re-split or re-match it. */
function splittable(value: string): boolean {
	return value === "" || /[ \t\n*?[]/.test(value)
}

/** A placeholder inside a value means the value itself is not a literal (§5.5). */
function runtime(value: string): boolean {
	return value.includes(CMDSUB_PLACEHOLDER) || value.includes(TRACKED_VAR_PLACEHOLDER)
}

// --------------------------------------------------------------------------- entry point: one expansion

/** The value of one expansion inside an argument, a redirect target or a test operand. */
export function resolveValue(scope: ValueScope, site: ValueSite, walkInto: WalkInto): ResolvedValue {
	switch (site.node.type) {
		case "simple_expansion":
			return reference(scope, site, nameOf(site.node))
		case "expansion":
			// §4.2 — every `${…}` spelling, with or without a transformation, a length or an indirect.
			return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
		case "command_substitution":
			return substitution(site, walkInto)
		case "process_substitution":
			// §3.2 — the file name does not exist until something has run.
			return { ok: false, refusal: refuse("process-substitution", site.node.type) }
		case "arithmetic_expansion":
			return arithmetic(site.node)
		default:
			// §3.2: a construct with no rule here is refused, never passed in silence.
			return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
	}
}

/** The name a `$` reference carries, or `""` when the tree gave none. */
function nameOf(node: Node): string {
	const named = node.children.find((child) => child.type === "variable_name" || child.type === "special_variable_name")
	return named?.text ?? ""
}

/**
 * `$NAME`, `$?`, `$$` … — a literal when one was remembered and the position cannot re-split it
 * (§5.3/§5.4), a placeholder when the value is the shell's own (§5.10, §5.11, §5.5), a refusal when
 * the walker would have to invent it (§4.2).
 */
function reference(scope: ValueScope, site: ValueSite, name: string): ResolvedValue {
	if (!name || isPositional(name)) return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
	const remembered = scope.variables.get(name)
	if (remembered && "literal" in remembered) {
		// §5.3: the caller sees the real path — but never where the shell could split it (§5.4).
		if (site.quoted || site.position === "env-prefix" || !splittable(remembered.literal)) return { ok: true, text: remembered.literal }
		return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
	}
	if (remembered || INERT_NAMES.has(name) || SPECIAL_NAMES.has(name)) return tracked(site)
	// §4.2: any name the walker has no value for.
	return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
}

/**
 * A value the shell controls (§6.1). Inside double quotes it is one argument and the placeholder is
 * honest; as a bare word the value *is* the argument, so §5.10 refuses; and when the quotes hold
 * nothing but this value, §6.5 refuses before a value-shaped hole reaches the caller. An assignment
 * value is never re-split, so it keeps the placeholder in any spelling.
 */
function tracked(site: ValueSite): ResolvedValue {
	if (site.position === "env-prefix") return { ok: true, text: TRACKED_VAR_PLACEHOLDER }
	if (!site.quoted) return { ok: false, refusal: refuse("variable-expansion", site.node.type) }
	if (site.whole || contentWhole(site.node)) return { ok: false, refusal: refuse("runtime-only-argument", site.node.type) }
	return { ok: true, text: TRACKED_VAR_PLACEHOLDER }
}

// --------------------------------------------------------------------------- §6 substitutions

/**
 * `$(…)`, and the same for backticks (§6.7): one accepted substitution contributes
 * `__CMDSUB_OUTPUT__` and its own commands, emitted before the command that contains it (§6.2).
 * Two positions may not have one at all — a bare substitution, which the shell splits into arguments
 * of its own (§4.4), and a substitution that is the whole argument (§6.5).
 */
function substitution(site: ValueSite, walkInto: WalkInto): ResolvedValue {
	// §4.2 — `10#$(…)`: the grammar puts the substitution inside a numeric literal, and what is
	// wrong here is the arithmetic base, not the substitution that fell into it.
	if (site.node.parent?.type === "number") return { ok: false, refusal: refuse("arithmetic-non-literal", "number") }

	const known = catHeredoc(site.node)
	if (known) {
		if ("refusal" in known) return { ok: false, refusal: known.refusal }
		// The body is literal data, so the only question left is whether this position can hold it.
		if (!site.quoted && site.position !== "env-prefix" && splittable(known.literal)) return { ok: false, refusal: refuse("command-substitution", site.node.type) }
		return { ok: true, text: known.literal }
	}

	if (site.position !== "env-prefix") {
		if (!site.quoted) return { ok: false, refusal: refuse("command-substitution", site.node.type) }
		if (site.whole || contentWhole(site.node)) return { ok: false, refusal: refuse("command-substitution", site.node.type) }
	}
	const inside = walkInto(site.node)
	if (inside) return { ok: false, refusal: inside }
	return { ok: true, text: CMDSUB_PLACEHOLDER }
}

/** §6.6 — the one substitution with a known, fixed answer, or `null` when it is an ordinary one. */
function catHeredoc(node: Node): { literal: string } | { refusal: Refusal } | null {
	const statements = node.children.filter((child) => child.isNamed)
	if (statements.length !== 1 || statements[0].type !== "redirected_statement") return null
	const parts = statements[0].children.filter((child) => child.isNamed)
	if (parts.length !== 2 || parts[0].type !== "command" || parts[1].type !== "heredoc_redirect") return null
	const words = parts[0].namedChildren
	// Any deviation — another verb, another argument to `cat`, another redirect — is an ordinary
	// substitution, and the ordinary rules refuse it.
	if (words.length !== 1 || words[0].type !== "command_name" || words[0].text !== "cat") return null

	const redirect = parts[1]
	const delimiter = redirect.children.find((child) => child.type === "heredoc_start")
	if (!delimiter) return null
	// §8.1 — an unquoted delimiter is expanded by the shell, so there is no literal to report.
	if (!quotedDelimiter(delimiter.text)) return { refusal: refuse("heredoc-unquoted-delimiter", redirect.type) }
	const body = redirect.children.find((child) => child.type === "heredoc_body")?.text ?? ""
	return { literal: bodyLiteral(body, redirect.text.startsWith("<<-")) }
}

/** §8.1 — `<<'E'`, `<<"E"` and `<<\E` are inert; anything else is expanded. */
function quotedDelimiter(written: string): boolean {
	const wrapped = (quote: string) => written.length > 1 && written.startsWith(quote) && written.endsWith(quote)
	return wrapped("'") || wrapped('"') || written.startsWith("\\")
}

/**
 * §6.6 — the body is the argument's value exactly as `cat` would print it: every line, joined by
 * newlines, without the final one. A multi-line body is reported whole, the way the same program
 * would be if it had been written as a quoted argument — `bash -c "$(cat <<'X' … X)"` must show the
 * caller the script it runs, never an empty value that reads as an interactive shell. Tab stripping
 * is bash's, and only bash's, but the value this reports is what `cat` would print, so `<<-` strips
 * leading tabs here exactly as the shell does (§8.2).
 */
function bodyLiteral(body: string, dash: boolean): string {
	// With `<<-` the grammar keeps the tabs written before the terminator as a last, tab-only line.
	const lines = (dash ? body.replace(/\n\t*$/, "\n") : body).split("\n")
	const printed = (dash ? lines.map((line) => line.replace(/^\t+/, "")) : lines).join("\n")
	// `$(…)` drops every trailing newline of what the command printed.
	return printed.replace(/\n+$/, "")
}

// --------------------------------------------------------------------------- §4.3 arithmetic

/**
 * `$(( … ))` built only from numeric literals and operators, reported as the text that was written
 * (§4.3 — bash computes the value; the walker must not pretend to). Anything that names a value,
 * or runs a substitution, is `arithmetic-non-literal`.
 */
function arithmetic(node: Node): ResolvedValue {
	for (const leaf of leaves(node)) {
		// The grammar reads a hexadecimal literal as a name — `0x1f` arrives in a `variable_name` node,
		// not a `number` one. A name that starts with a digit cannot be a reference in bash, so a leaf
		// of that shape is a literal in some base and nothing else.
		if (leaf.type === "number" || leaf.type === "variable_name") {
			if (NUMERIC_LITERAL.test(leaf.text)) continue
			return { ok: false, refusal: refuse("arithmetic-non-literal", node.type) }
		}
		if (!leaf.isNamed) continue // operators, parens, the `$((` and `))` themselves
		return { ok: false, refusal: refuse("arithmetic-non-literal", leaf.type) }
	}
	return { ok: true, text: node.text }
}

/** Decimal, hex, octal and `base#digits`, as written. */
const NUMERIC_LITERAL = /^(?:[0-9]+#[0-9A-Za-z]+|0[xX][0-9A-Fa-f]+|[0-9]+)$/

function leaves(node: Node, out: Node[] = []): Node[] {
	if (node.namedChildCount === 0 && node.children.length === 0) out.push(node)
	for (const child of node.children) leaves(child, out)
	return out
}

// --------------------------------------------------------------------------- §5 assignments

/** The parts of a `variable_assignment` node, or `null` when the name is not a name (§5.8). */
type ParsedAssignment = { name: string; append: boolean; value: Node[] }

function parseAssignment(node: Node): ParsedAssignment | null {
	const name = node.children.find((child) => child.type === "variable_name")
	if (!name || !isAssignmentName(name.text)) return null
	const operator = node.children.find((child) => !child.isNamed && (child.type === "=" || child.type === "+="))
	if (!operator) return null
	return { name: name.text, append: operator.type === "+=", value: node.children.filter((child) => child.startIndex > operator.startIndex) }
}

/**
 * §5.8 — a `variable_assignment` node whose name bash would not accept is not an assignment at all:
 * `1VAR=value` is one command word. The walker needs to be told, because it routes the node here on
 * the assumption that it is an assignment.
 */
export function assignmentIsCommandWord(node: Node): boolean {
	const name = node.children.find((child) => child.type === "variable_name")
	return name === undefined || !isAssignmentName(name.text)
}

/**
 * A `NAME=value` prefix of a command (§5.1): one entry in `envVars`, in source order, visible to
 * that command only — it is deliberately *not* remembered, so a later `echo "$A"` cannot borrow a
 * value bash would have given it empty. `+=` keeps one entry per assignment as written (§5.6).
 */
export function envAssignment(_scope: ValueScope, node: Node, resolve: ResolveWord): ResolvedAssignment {
	const parsed = parseAssignment(node)
	if (!parsed) return { ok: false, refusal: refuse("assignment-name-invalid", node.type) }
	const resolved = assignmentValue(parsed, resolve)
	if (!resolved.ok) return resolved
	const guard = assignmentRefusal(parsed.name, resolved.value, parsed.append)
	if (guard) return { ok: false, refusal: guard }
	return { ok: true, name: parsed.name, value: resolved.value }
}

/** A value word, or the empty string for `NAME=`. Assignment values are name-shaped, never paths. */
function assignmentValue(parsed: ParsedAssignment, resolve: ResolveWord): { ok: true; value: string } | { ok: false; refusal: Refusal } {
	if (parsed.value.length === 0) return { ok: true, value: "" }
	const shape = parsed.value.find((child) => !ASSIGNMENT_VALUE_NODES.has(child.type))
	if (shape) return { ok: false, refusal: refuse("variable-expansion", shape.type) } // e.g. `(1 2)`: an array, not a value
	const answer = resolve(parsed.value, "env-prefix")
	if (!answer.ok) return answer
	return { ok: true, value: answer.text }
}

/** The node types an assignment value may be built from; anything else the walker cannot read. */
const ASSIGNMENT_VALUE_NODES = new Set([
	"word", "string", "raw_string", "concatenation", "number", "simple_expansion", "expansion",
	"command_substitution", "arithmetic_expansion", "process_substitution",
])

/**
 * A statement-level `NAME=value` / `NAME+=v` (§5.2, §5.6): remembered, and worth no command of its
 * own. A value that is not a literal — a substitution, or built on a value that was itself unknown
 * — is remembered as unknown, so a later bare reference refuses and a quoted one reports
 * `__TRACKED_VAR__` (§5.5).
 */
export function rememberAssignment(scope: ValueScope, node: Node, resolve: ResolveWord): Refusal | null {
	const parsed = parseAssignment(node)
	if (!parsed) return refuse("assignment-name-invalid", node.type)
	const resolved = assignmentValue(parsed, resolve)
	if (!resolved.ok) return resolved.refusal
	const guard = assignmentRefusal(parsed.name, resolved.value, parsed.append)
	if (guard) return guard

	const before = scope.variables.get(parsed.name)
	if (!runtime(resolved.value)) {
		// §5.6: both sides literal — remember the concatenation; anything else is not a literal.
		if (parsed.append && before && !("literal" in before)) scope.variables.set(parsed.name, { unknown: true })
		else scope.variables.set(parsed.name, { literal: (parsed.append && before && "literal" in before ? before.literal : "") + resolved.value })
	} else {
		scope.variables.set(parsed.name, { unknown: true })
	}
	scope.assignments.push({ name: parsed.name, value: resolved.value, node })
	return null
}

/**
 * §13.6 + §14.1 — a non-blank input that emitted no command at all must still say what it holds.
 * A statement-level assignment emits nothing (§5.2), so when nothing else in the input produced a
 * command, the assignments the walk consumed become the answer: no argv, the value in `envVars`,
 * the span of the assignment itself. When the input *did* emit commands, the assignment stays
 * invisible and only its value survives, in the scope, for the references that follow (§5.3).
 */
export function reportRemembered(scope: ValueScope, commands: AstCommand[]): void {
	if (commands.length > 0 || scope.assignments.length === 0) return
	for (const one of scope.assignments) {
		commands.push({
			argv: [],
			envVars: [{ name: one.name, value: one.value }],
			redirects: [],
			heredocs: [],
			text: one.node.text,
			start: one.node.startIndex,
			end: one.node.endIndex,
			connector: connectorBefore(one.node),
			// §6.3: `opaque` is derived from the reported values by the walker, never set here.
			opaque: false,
		})
	}
}

/** The operator written in front of a statement (§13.4), read off the tree it sits in. */
function connectorBefore(node: Node): string {
	const previous = node.previousNamedSibling
	if (!previous) return ""
	for (let cursor = previous.nextSibling; cursor && cursor !== node; cursor = cursor.nextSibling) {
		if (!cursor.isNamed && SEPARATOR_TOKENS.has(cursor.type)) return cursor.type
	}
	return node.tree.rootNode.text.slice(previous.endIndex, node.startIndex).includes("\n") ? "\n" : ""
}

const SEPARATOR_TOKENS = new Set([";", "&", "&&", "||", "|", "|&"])

/**
 * §5.7 — the assignments that change how the shell reads later text.
 * `IFS` decides where words split, so no assignment to it is a fact the walker can keep. `PS4` is
 * executed as part of the trace prompt: a plain one made of prompt-punctuation is allowed, anything
 * else — and every append — is not. A tilde may be expanded at assignment time, quoted or not.
 */
function assignmentRefusal(name: string, value: string, append: boolean): Refusal | null {
	if (name === "IFS") return refuse("ifs-assignment")
	if (name === "PS4" && (append || !tracePromptLiteral(value))) return refuse("prompt-variable-assignment")
	if (value.includes("~")) return refuse("tilde-in-assignment")
	return null
}

/**
 * The trace prompt is only safe while it is text: letters, digits, space and prompt punctuation,
 * with a plain `${NAME}` reference allowed (§5.7). Everything else in it — `$(…)`, a bare `(`, a
 * default or a transformation in the braces — is refused, because a shell that re-executes the
 * prompt runs whatever it holds.
 */
function tracePromptLiteral(value: string): boolean {
	let punctuation = ""
	for (let i = 0; i < value.length; ) {
		if (value[i] !== "$" || !value.startsWith("${", i)) {
			punctuation += value[i]
			i += 1
			continue
		}
		const close = value.indexOf("}", i)
		if (close < 0 || !isAssignmentName(value.slice(i + 2, close))) return false
		i = close + 1
	}
	return PROMPT_PUNCTUATION.test(punctuation)
}

/** Letters, digits, space and the punctuation a prompt is made of. */
const PROMPT_PUNCTUATION = /^[\w +_:./=[\]-]*$/

// --------------------------------------------------------------------------- §3.1 / §5.6 / §5.9 builtins

/** The builtins whose flags can change what an assignment *means* (§5.9). */
const DECLARING_BUILTINS = new Set(["declare", "typeset", "local"])

/**
 * `declare`/`typeset`/`local`/`readonly`/`export` and `unset` (§3.1, §5.6). The walker emits the
 * builtin as `argv[0]` followed by its flags, names and `NAME=value` items as arguments; this says
 * only when the statement cannot be reported that way (§5.9) or re-reads the text in a way the
 * walker cannot follow (§5.7).
 *
 * A declared value is deliberately not remembered: it is already visible to the caller inside
 * `argv`, and a name the shell sets itself (`PATH`, `HOME`) then keeps the inert-name rule for the
 * references that follow instead of silently becoming a literal the walker inferred.
 */
export function resolveDeclaration(_scope: ValueScope, node: Node): Refusal | null {
	const builtin = node.children[0]?.text ?? ""
	const declaring = DECLARING_BUILTINS.has(builtin)
	for (const item of node.children.slice(1)) {
		const written = unquote(item.text)
		if (written.startsWith("-") || written.startsWith("+")) {
			if (declaring && written.includes("n")) return refuse("nameref-assignment", item.type)
			if (declaring && (written.includes("i") || written.includes("a"))) return refuse("subscript-evaluation", item.type)
			continue
		}
		if (declaring && subscriptedName(written)) return refuse("subscript-evaluation", item.type)
		// §5.7 again, this time over an item the walker is about to resolve as an argument.
		const assigned = declaredAssignment(written)
		if (assigned) {
			const guard = assignmentRefusal(assigned.name, assigned.rest, assigned.append)
			if (guard) return guard
		}
	}
	return null
}

/** `NAME=` or `NAME+=` at the head of an item, split without a pattern that could hide a subscript. */
function declaredAssignment(written: string): { name: string; append: boolean; rest: string } | null {
	const equals = written.indexOf("=")
	if (equals <= 0) return null
	const head = written.slice(0, equals)
	const append = head.endsWith("+")
	const name = append ? head.slice(0, -1) : head
	if (!isAssignmentName(name)) return null
	return { name, append, rest: written.slice(equals + 1) }
}

/**
 * The quotes around an item are part of how it was written, not part of its name; `declare
 * 'x[$(id)]=v'` has to be seen for what it is, and §11.3 says a check that reads only the raw
 * spelling is the one that gets hidden.
 */
function unquote(written: string): string {
	return written.replace(/^[$'"\\]+/, "")
}

/**
 * `name[…]` — the shell computes the subscript, and anything hidden inside it runs (§5.9). Read by
 * splitting at the bracket rather than matching a pattern, so a quoted `x[$(id)]` is still seen as
 * the subscripted name it is.
 */
function subscriptedName(written: string): boolean {
	const bracket = written.indexOf("[")
	return bracket > 0 && isAssignmentName(written.slice(0, bracket))
}
