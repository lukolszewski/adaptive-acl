/**
 * bash-walker.ts — layer 0: read a bash command string and say whether a trustworthy argument list
 * exists for every simple command in it (docs/LAYER0-WALKER-SPEC.md).
 *
 * Accepted -> `commands`, in the order the spec's rules emit them, each with its own span,
 * connector and `opaque` flag. Refused -> one id from §12 plus the `malformed` flag that belongs to
 * it. No verdict about safety, permission or intent (§14.5); no partial answer (§1.1); no guesses
 * (§1.3).
 *
 * The work runs as the §2 pipeline, in that order, and the first refusal wins (§12.1): blank input
 * is accepted; over the size cap (§10.9) is `input-too-large`; the text scans of §10 live in
 * bash-walker-scan.ts; a missing tree is `parse-error` / `parse-aborted` / `parser-unavailable`;
 * §3–§9 are walked here; §13.6 is `inventory-mismatch`; the meaning checks of §11 live in
 * bash-walker-meaning.ts and the here-documents of §8 in bash-walker-heredoc.ts. Values the walker
 * cannot produce from quoting alone — expansions, assignments, declarations — are answered by
 * bash-walker-values.ts. The walker proper holds no policy and no value rules of its own.
 *
 * Once nothing is refused, one reporting pass ({@link reportFlagWrites}) adds the write targets a flag
 * names (`sort -o FILE`) to the command's redirect list, so a write is reported the same way however it
 * was spelled. It reports; it never refuses.
 *
 * Deterministic (§14.4): the input string is the only input, and every tree-sitter object created
 * here is released before the call returns.
 */

import type { Node } from "web-tree-sitter"
import type { AstCommand, AstParse, AstRedirect } from "./bash-ast.ts"
import { MAX_COMMAND_CHARS, parseBash } from "./bash-parser.ts"
import {
	assignmentIsCommandWord,
	envAssignment,
	newValueScope,
	rememberAssignment,
	reportRemembered,
	resolveDeclaration,
	resolveValue,
	type ResolveWord,
	type ValuePosition,
	type ValueScope,
} from "./bash-walker-values.ts"
import { scanInput } from "./bash-walker-scan.ts"
import { takeHeredoc } from "./bash-walker-heredoc.ts"
import { checkMeaning, outputFlagWrites } from "./bash-walker-meaning.ts"

/** A value that exists only when the command runs, wearing the shape of a literal (§6.1). */
export const CMDSUB_PLACEHOLDER = "__CMDSUB_OUTPUT__"
export const TRACKED_VAR_PLACEHOLDER = "__TRACKED_VAR__"

/** The complete §12 vocabulary — no other id may appear in a result. Malformed classes first. */
export type Reason =
	| "unterminated-quote" | "unterminated-backtick" | "unterminated-substitution"
	| "unterminated-heredoc" | "unterminated-heredoc-delimiter" | "control-character"
	| "unicode-whitespace" | "parse-error" | "parse-aborted" | "input-too-large"
	| "parser-unavailable" | "backslash-whitespace" | "zsh-tilde-bracket"
	| "zsh-equals-expansion" | "brace-with-quote" | "brace-expansion" | "ansi-c-string"
	| "translated-string" | "arithmetic-non-literal" | "command-substitution"
	| "process-substitution" | "variable-expansion" | "runtime-only-argument"
	| "loop-body" | "conditional-body" | "case-statement" | "function-definition"
	| "brace-group" | "arithmetic-command" | "subshell-argument" | "inventory-mismatch"
	| "heredoc-unattributed" | "heredoc-unquoted-delimiter" | "redirect-unsupported"
	| "ifs-assignment" | "prompt-variable-assignment" | "tilde-in-assignment"
	| "assignment-name-invalid" | "nameref-assignment" | "subscript-evaluation"
	| "evaluates-arguments-as-code" | "zsh-module-builtin" | "wrapper-not-analysable"
	| "proc-environ-read" | "jq-system-call" | "jq-file-flag" | "empty-command-name"
	| "command-name-not-a-literal" | "incomplete-command-fragment"
	| "keyword-as-command-name" | "hidden-comment-in-argument"

export type Refusal = Extract<AstParse, { kind: "unproven" }>

/** §12 — the classes where the input itself is broken, so the fix is a simpler command (§1.2). */
const MALFORMED_CLASSES = new Set<Reason>([
	"unterminated-quote",
	"unterminated-backtick",
	"unterminated-substitution",
	"unterminated-heredoc",
	"unterminated-heredoc-delimiter",
	"control-character",
	"unicode-whitespace",
	"parse-error",
	"parse-aborted",
	"input-too-large",
])

/** One refusal, worded later by the caller. `nodeType` is a diagnostic nobody may branch on. */
export function refuse(reason: Reason, nodeType?: string): Refusal {
	const refusal: Refusal = { kind: "unproven", reason, malformed: MALFORMED_CLASSES.has(reason) }
	if (nodeType !== undefined) refusal.nodeType = nodeType
	return refusal
}

// --------------------------------------------------------------------------- walk state

/** One walk of one input: the source, the commands emitted so far, the value scope. */
type Walk = { input: string; commands: AstCommand[]; scope: ValueScope }

/** A stretch of source that resolves to exactly one argument (§4: adjacency joins, never splits). */
type Piece = { start: number; end: number; nodes: Node[] }

/** A command under construction. */
type Draft = {
	command: AstCommand
	/** Source of every word the command reports — argv and environment values — for §13.6. */
	sources: Piece[]
	/** Descriptor glued to a redirect by `0< file`; not an argument (§7.1). */
	fdShift?: number
}

type Answer<T> = { ok: true; value: T } | { ok: false; refusal: Refusal }

/** A resolved redirect and the words written after its target, which are arguments (§7). */
type RedirectAnswer = { ok: true; redirect: AstRedirect; trailing: Piece[] } | { ok: false; refusal: Refusal }

/**
 * Walk one bash command string. The caller has awaited `initBashParser()`; if it has not, the
 * result is `parser-unavailable` (§12).
 */
export function walkBash(command: string): AstParse {
	// §2 step 1: nothing to do is not a refusal.
	if (command.trim() === "") return { kind: "simple", commands: [] }
	// §2 step 2 (§10.9): over the cap the input is never partially analysed.
	if (command.length > MAX_COMMAND_CHARS) return refuse("input-too-large")
	const scan = scanInput(command) // §2 steps 3–5
	if (scan) return scan

	const parsed = parseBash(command) // §2 step 6
	if ("error" in parsed) return parseOutcome(parsed.error)
	const tree = parsed.tree
	try {
		const walk: Walk = { input: command, commands: [], scope: newValueScope() }
		const walked = walkSequence(walk, tree.rootNode) // §2 step 7
		if (walked) return walked
		// §10.7: a tree the parser could not complete is not a command, whatever the walk made of it.
		if (tree.rootNode.hasError) return refuse("parse-error", "ERROR")
		// §13.6 + §14.1: a non-blank input that emitted no command still has to report what it holds —
		// the statement-level assignments the walk consumed (§5.2) are its entire content.
		reportRemembered(walk.scope, walk.commands)
		const settled = settle(walk) // §2 step 8 (§13.6) and §6.3
		if (settled) return settled
		const meaning = checkMeaning(walk.commands) // §2 step 9
		if (meaning) return meaning
		reportFlagWrites(walk.commands) // reporting: a write named by a flag, not by a redirect
		return { kind: "simple", commands: walk.commands }
	} finally {
		tree.delete()
	}
}

/**
 * Report the files the emitted commands write through a **flag** (`sort -o FILE`, `git diff
 * --output=FILE`) on the channel every reader of "which files does this command open" already uses:
 * the command's own `redirects`. A flag operand is an ordinary word to the grammar, so without this a
 * command that truncates `/etc/x` is reported as read-only and the ladder runs it unasked; reporting it
 * here means the tier tables, the secret and device rules, the strict-operand matching and the redirect
 * target coverage all see the write without learning that flags exist. The operator records how the file
 * is opened — truncating, or appending where the table says the tool appends.
 *
 * Runs after steps 8–10, over values those steps already vouched for, and adds nothing to argv: argv is
 * what the program was passed (§13.2), so this is a fact added to a command, never a word removed from
 * it. A target that turns out to be a runtime placeholder needs no special case either — such a command
 * is already `opaque` (§6.3), and the policy refuses to read an opaque command's arguments as literals.
 */
function reportFlagWrites(commands: AstCommand[]): void {
	for (const command of commands) {
		for (const write of outputFlagWrites(command.argv)) {
			command.redirects.push({ op: write.append ? ">>" : ">", target: write.target, fdDup: false })
		}
	}
}

/** Parser outcome -> §12 id. Offsets are JS string indices already (§13.1); nothing is converted. */
function parseOutcome(error: "not-initialised" | "too-large" | "aborted" | "parse-failed"): Refusal {
	if (error === "not-initialised") return refuse("parser-unavailable")
	if (error === "too-large") return refuse("input-too-large")
	if (error === "aborted") return refuse("parse-aborted")
	return refuse("parse-error")
}

// --------------------------------------------------------------------------- §3 structures

/** Operators that separate statements; anonymous tokens in the tree (§13.4). */
const SEPARATORS = new Set([";", "&", "&&", "||", "|", "|&"])

/** Redirect node types (§7). A heredoc is part 3's and leaves this file at once. */
const REDIRECT_NODES = new Set(["file_redirect", "herestring_redirect", "heredoc_redirect"])

/**
 * Walk a container's statements in source order — `program`, `list`, `pipeline`, `subshell`,
 * `negated_command`. A separator token between two statements is the connector of the one behind
 * it; a gap with no token but a newline is a bare newline; anything else is no operator (§13.4).
 * The first statement inherits the connector written in front of the group it opens.
 */
function walkSequence(walk: Walk, container: Node, inherited = ""): Refusal | null {
	let pending = inherited
	let prevEnd = -1
	for (const child of container.children) {
		if (!child.isNamed) {
			if (SEPARATORS.has(child.type)) pending = child.type
			continue
		}
		const newline = prevEnd >= 0 && walk.input.slice(prevEnd, child.startIndex).includes("\n")
		const refusal = walkStatement(walk, child, pending || (newline ? "\n" : ""))
		if (refusal) return refusal
		pending = ""
		prevEnd = child.endIndex
	}
	return null
}

function walkStatement(walk: Walk, node: Node, connector: string): Refusal | null {
	switch (node.type) {
		case "comment":
			return null // §3.1: a comment contributes nothing
		case "list":
		case "pipeline":
		case "subshell":
		case "negated_command":
			// §3.1: lists, pipelines and a subshell in statement position contribute the commands
			// inside them; `!` and the parentheses contribute nothing.
			return walkSequence(walk, node, connector)
		case "redirected_statement":
			return walkRedirected(walk, node, connector)
		case "command":
			return walkCommand(walk, node, connector, [], undefined)
		case "test_command":
			return walkTest(walk, node, connector, [])
		case "variable_assignment": {
			// §3.1 + §5.2: inert on its own — the value is remembered, no command is emitted. §5.8: a
			// name bash would not accept is not an assignment, so the text is one ordinary command word.
			if (assignmentIsCommandWord(node)) {
				const word = resolvePiece(walk, { start: node.startIndex, end: node.endIndex, nodes: expansionNodes(node) }, "argument")
				if (!word.ok) return word.refusal
				const draft = newDraft(node, connector)
				draft.command.argv.push(word.value)
				draft.sources.push({ start: node.startIndex, end: node.endIndex, nodes: [] })
				return emit(walk, draft)
			}
			return rememberAssignment(walk.scope, node, wordResolver(walk))
		}
		case "declaration_command":
		case "unset_command": {
			// §3.1 + §5.6: the builtin is the first argument, followed by its flags, its names and its
			// NAME=value items, each resolved like any other word. §5.9 refusals come first.
			const refusal = resolveDeclaration(walk.scope, node)
			if (refusal) return refusal
			const draft = newDraft(node, connector)
			for (const item of node.children) {
				const position: ValuePosition = item.type === "variable_assignment" ? "env-prefix" : "argument"
				const resolved = resolvePiece(walk, { start: item.startIndex, end: item.endIndex, nodes: expansionNodes(item) }, position)
				if (!resolved.ok) return resolved.refusal
				draft.command.argv.push(resolved.value)
				draft.sources.push({ start: item.startIndex, end: item.endIndex, nodes: [] })
			}
			if (node.type === "unset_command") forgetUnsetNames(walk.scope, draft.command.argv)
			return emit(walk, draft)
		}
		case "for_statement":
		case "while_statement":
		case "c_style_for_statement":
			// §3.3: how often a body runs, and what the loop variable holds, are run-time facts.
			return refuse("loop-body", node.type)
		case "if_statement":
			return refuse("conditional-body", node.type)
		case "case_statement":
			return refuse("case-statement", node.type)
		case "function_definition":
			return refuse("function-definition", node.type)
		case "compound_statement":
			// `{ …; }` and `(( … ))` arrive as the same node type; what was written tells them apart.
			return refuse(node.text.startsWith("((") ? "arithmetic-command" : "brace-group", node.type)
		case "ERROR":
		case "MISSING":
			return brokenNode(node)
		default:
			// §3.2: something the walker has no rule for. The closest §12 id for a construct that was
			// not analysed is the grouped-compound-command one; `nodeType` says what it actually was.
			return refuse("brace-group", node.type)
	}
}

/**
 * `unset NAME` ends §5.3's memory of `NAME`. A remembered literal is substituted into later
 * references *because* bash would expand them to that value; once the name is unset bash expands them
 * to the empty string, so keeping the memory would name a path bash never writes to —
 * `S=/tmp/build && unset S && cmd > $S/out` truncates `/out`, not a file in temp. Dropping the entry
 * makes the later reference an ordinary unknown name, which §4.2 already refuses.
 *
 * `unset -f` drops a function and leaves the variable of the same name alone, so a name is only
 * forgotten when the command could have unset the variable: no flag at all (bash's default), or any
 * flag bundle that is not `f`-only — an unrecognised bundle is treated as unsetting the variable,
 * because forgetting costs one prompt and remembering could cost a write the gate waved through.
 * Items that are not a plain bash name are skipped: `unset a[1]` never reaches here (§5.9 refuses a
 * subscripted name given to `unset`), and guessing at anything else would invent a revocation.
 */
function forgetUnsetNames(scope: ValueScope, argv: readonly string[]): void {
	if (argv[0] !== "unset") return
	const flags = argv.slice(1).filter((one) => one.startsWith("-") || one.startsWith("+"))
	const functionsOnly = flags.length > 0 && flags.every((one) => one.includes("f") && !one.includes("v"))
	if (functionsOnly) return
	for (const name of argv.slice(1)) {
		if (!isPlainVariableName(name)) continue
		scope.variables.delete(name)
	}
}

/** The shape bash accepts as a variable name (§5.8): a letter or underscore, then word characters. */
function isPlainVariableName(name: string): boolean {
	if (!/^[A-Za-z_]/.test(name)) return false
	return /^[A-Za-z0-9_]*$/.test(name.slice(1))
}

/**
 * An incomplete node. A brace group the parser could not finish is still the class the caller has
 * to be told about (§3.2 refuses a construct as a whole and names it); anything else is only "no
 * tree" (§10.7).
 */
function brokenNode(node: Node): Refusal {
	const text = node.text.replace(/^[\s;&|]+/, "") // where the parser gave up is not where it starts
	if (text.startsWith("{")) return refuse("brace-group", node.type)
	if (text.startsWith("((")) return refuse("arithmetic-command", node.type)
	return refuse("parse-error", node.type)
}

/**
 * §7.4: redirects attach to the command whose streams they redirect, and to the **last** command of
 * a pipeline or list written inside the same redirect scope. A redirect with no command at all is
 * still emitted (§3.1) — truncating a file is a consequence even when nothing prints.
 */
function walkRedirected(walk: Walk, node: Node, connector: string): Refusal | null {
	const body = node.children.find((child) => child.isNamed && !REDIRECT_NODES.has(child.type))
	const redirects: AstRedirect[] = []
	// §7: the words a file_redirect holds after its target. They belong to the command the redirect
	// belongs to, so they travel with the redirects to whichever command ends up owning them.
	const trailing: Piece[] = []
	// A redirect written around a list or a pipeline is resolved after that body, because the target
	// may reference a value the body assigns (§5.3) and the redirect belongs to its last command
	// (§7.4). Everywhere else the targets come first, so a command inside an accepted substitution is
	// emitted before the command that contains it (§6.2, §13.5).
	// §2 step 8: a newline between the parts of this statement is bash ending a statement, so a redirect
	// written on the line below belongs to a command of its own. Asked once the body has been walked,
	// because a construct the walker cannot analyse is the earlier refusal (§12.1).
	const joinedLines = (): Refusal | null => linesJoined(walk, node.children.filter((child) => child.isNamed).map((child) => ({ start: child.startIndex, end: child.endIndex })), node.type)
	const afterBody = !!body && (body.type === "list" || body.type === "pipeline")
	if (!afterBody) {
		const collected = collectRedirects(walk, node, redirects, trailing)
		if (collected) return collected
	}

	if (!body) {
		const draft = newDraft(node, connector)
		draft.command.redirects.push(...redirects)
		const appended = appendWords(walk, draft.command, trailing)
		return appended ?? joinedLines() ?? emit(walk, draft)
	}
	if (body.type === "command") {
		// Where the first redirect begins: a numeric argument glued to it is its descriptor (§7.1).
		const anchor = node.children.find((child) => REDIRECT_NODES.has(child.type))?.startIndex
		const built = walkCommand(walk, body, connector, redirects, anchor, trailing)
		return built ?? joinedLines() ?? attachHeredocs(node, walk)
	}
	if (body.type === "test_command") {
		const built = walkTest(walk, body, connector, redirects, trailing)
		return built ?? joinedLines() ?? attachHeredocs(node, walk)
	}

	// A compound body: walk it, then hand the redirects to its last command.
	const before = walk.commands.length
	const walked = walkStatement(walk, body, connector)
	if (walked) return walked
	const owner = walk.commands.length > before ? walk.commands[walk.commands.length - 1] : undefined
	const collected = collectRedirects(walk, node, redirects, trailing) // §5.3: the body may assign what a target names
	if (collected) return collected
	if (!owner) {
		const empty = newDraft(node, connector)
		empty.command.redirects.push(...redirects)
		const appended = appendWords(walk, empty.command, trailing)
		return appended ?? joinedLines() ?? emit(walk, empty)
	}
	owner.redirects.push(...redirects)
	const appended = appendWords(walk, owner, trailing)
	return appended ?? joinedLines() ?? attachHeredocs(node, walk)
}

/** Every redirect of one statement, in source order, with its target resolved (§7.3). */
function collectRedirects(walk: Walk, node: Node, redirects: AstRedirect[], trailing: Piece[]): Refusal | null {
	for (const child of node.children) {
		if (child.type === "file_redirect") {
			const resolved = fileRedirect(walk, child)
			if (!resolved.ok) return resolved.refusal
			redirects.push(resolved.redirect)
			trailing.push(...resolved.trailing)
		} else if (child.type === "herestring_redirect") {
			const checked = hereString(walk, child)
			if (checked) return checked
		}
	}
	return null
}

/** §2 step 10: hand every heredoc redirect of this statement to the heredoc module. */
function attachHeredocs(statement: Node, walk: Walk): Refusal | null {
	for (const child of statement.children) {
		if (child.type !== "heredoc_redirect") continue
		const owner = walk.commands[walk.commands.length - 1]
		if (!owner) return refuse("heredoc-unattributed", child.type)
		const refusal = takeHeredoc(child, owner)
		if (refusal) return refusal
	}
	return null
}

// --------------------------------------------------------------------------- §4 words, §7 redirects

/** Node types whose value belongs to the values module (§4.2, §5, §6). */
const EXPANSION_NODES = new Set(["command_substitution", "simple_expansion", "expansion", "arithmetic_expansion", "process_substitution"])

/** Word node types the walker resolves from quoting alone (§4). */
const WORD_NODES = new Set(["word", "string", "raw_string", "concatenation", "number", "regex", "test_operator", "ansi_c_string", "extglob_pattern"])

/**
 * §4 word resolution handed to the values module: a run of sibling nodes is one argument, resolved
 * here and nowhere else. The values module decides whether a value may be known at all; it never
 * gets a second copy of the quoting rules to get wrong.
 */
function wordResolver(walk: Walk): ResolveWord {
	return (nodes, position) => {
		const resolved = resolvePiece(walk, { start: nodes[0].startIndex, end: nodes[nodes.length - 1].endIndex, nodes: nodes.flatMap((one) => expansionNodes(one)) }, position)
		return resolved.ok ? { ok: true, text: resolved.value } : resolved
	}
}

/** A command with an empty report, ready to be filled in from the node it was walked from. */
function newDraft(node: Node, connector: string): Draft {
	return {
		command: { argv: [], envVars: [], redirects: [], heredocs: [], text: "", start: node.startIndex, end: node.endIndex, connector, opaque: false },
		sources: [],
	}
}

function walkCommand(walk: Walk, node: Node, connector: string, extra: AstRedirect[], fdAnchor: number | undefined, trailing: Piece[] = []): Refusal | null {
	const draft = newDraft(node, connector)
	draft.command.redirects.push(...extra)
	let pieces: Piece[] = []
	const redirectSpans: Piece[] = []
	let named = false

	/** One argument, from the source gathered since the last one: adjacent segments join (§4). */
	const flush = (): Refusal | null => {
		for (const piece of pieces) {
			const resolved = resolvePiece(walk, piece, "argument")
			if (!resolved.ok) return resolved.refusal
			draft.command.argv.push(resolved.value)
			draft.sources.push(piece)
		}
		pieces = []
		return null
	}
	const push = (child: Node): void => {
		const last = pieces[pieces.length - 1]
		if (last && child.startIndex === last.end) {
			last.end = child.endIndex
			last.nodes.push(...expansionNodes(child))
			return
		}
		pieces.push({ start: child.startIndex, end: child.endIndex, nodes: expansionNodes(child) })
	}

	for (const child of node.children) {
		if (child.type === "command_name") {
			named = true
			push(child) // its own word: bash needs whitespace between a name and its first argument
			continue
		}
		if (child.type === "variable_assignment" && !named) {
			const stopped = flush()
			if (stopped) return stopped
			const assigned = envAssignment(walk.scope, child, wordResolver(walk))
			if (!assigned.ok) return assigned.refusal
			draft.command.envVars.push({ name: assigned.name, value: assigned.value })
			draft.sources.push({ start: child.startIndex, end: child.endIndex, nodes: [] })
			continue
		}
		if (child.type === "file_redirect" || child.type === "herestring_redirect") {
			const stopped = flush()
			if (stopped) return stopped
			if (child.type === "file_redirect") {
				const resolved = fileRedirect(walk, child)
				if (!resolved.ok) return resolved.refusal
				draft.command.redirects.push(resolved.redirect)
				redirectSpans.push({ start: child.startIndex, end: child.endIndex, nodes: [] })
				// Words the grammar filed inside the redirect keep their own source position, so they go
				// back into the argument stream here rather than at the end (§7, §4).
				pieces.push(...resolved.trailing)
			} else {
				// §7: a here-string is data, not a path — never reported, validated like an argument.
				const checked = hereString(walk, child)
				if (checked) return checked
			}
			continue
		}
		if (child.type === "heredoc_redirect") continue // §8: owned by the statement, see attachHeredocs
		if (child.type === "subshell" || child.type === "pipeline") {
			return refuse("subshell-argument", child.type) // §3.2
		}
		push(child) // includes anonymous tokens at word position, e.g. the `$` of `$"locale"`
	}
	const stopped = flush()
	if (stopped) return stopped
	// §2 step 8 (§13.6): the words and redirects of one command are written on one line, so they are
	// tied to one span.
	const joined = linesJoined(walk, [...draft.sources, ...redirectSpans, ...trailing], node.type)
	if (joined) return joined

	// `0< in.txt`: the grammar hands the descriptor to us as a trailing numeric argument. It is not
	// an argument — it is the `fd` of the redirect it is glued to (§7.1), and the span ends with the
	// last word that really is an argument (§13.3).
	const lastSource = draft.sources[draft.sources.length - 1]
	const argv = draft.command.argv
	if (fdAnchor !== undefined && lastSource && argv.length > 0 && lastSource.end === fdAnchor && /^\d+$/.test(argv[argv.length - 1])) {
		draft.fdShift = Number(argv.pop())
		draft.sources.pop()
		draft.command.end = commandEnd(draft)
	}
	// §7: the statement's redirects are resolved before this command is walked, so the words they hold
	// after their targets arrive here and join the argument list last — which is their source order.
	const appended = appendWords(walk, draft.command, trailing)
	if (appended) return appended
	return emit(walk, draft)
}

/**
 * §7 — put the words a `file_redirect` holds after its target back where bash reads them: as arguments
 * of the command the redirect belongs to, in source order. tree-sitter files **every** word after the
 * operator under `destination`; bash takes only the first as the target, so a dropped `-rf /tmp/x`
 * would be a classified `rm` with no visible target. The span grows over them (§13.3 covers a
 * command's own arguments), which is what keeps `text === input.slice(start, end)` (§13.2).
 */
function appendWords(walk: Walk, command: AstCommand, words: Piece[]): Refusal | null {
	if (words.length === 0) return null
	for (const word of words) {
		const resolved = resolvePiece(walk, word, "argument")
		if (!resolved.ok) return resolved.refusal
		command.argv.push(resolved.value)
	}
	command.end = words[words.length - 1].end
	command.text = walk.input.slice(command.start, command.end)
	return null
}

/**
 * §2 step 8 (§13.6): are these contributions to one command written on one line? bash ends a statement
 * at an unescaped newline, so a newline in the gap between two words — or between a word and a
 * redirect — means the parser has joined lines that bash reads as separate commands, and the walker
 * cannot tie what it emitted back to the input. A backslash-newline is a continuation and leaves the
 * two sides one command (§10.1).
 */
function linesJoined(walk: Walk, spans: readonly { start: number; end: number }[], blame: string): Refusal | null {
	const ordered = [...spans].sort((a, b) => a.start - b.start)
	for (let i = 1; i < ordered.length; i++) {
		const gap = walk.input.slice(ordered[i - 1].end, ordered[i].start)
		for (let at = gap.indexOf("\n"); at >= 0; at = gap.indexOf("\n", at + 1)) {
			if (gap[at - 1] !== "\\") return refuse("inventory-mismatch", blame)
		}
	}
	return null
}

/** End of a command's span: just past the last word it reports, or where it started. */
function commandEnd(draft: Draft): number {
	const last = draft.sources[draft.sources.length - 1]
	return last ? last.end : draft.command.start
}

/** The expansions inside a node, in source order. */
function expansionNodes(node: Node, out: Node[] = []): Node[] {
	if (EXPANSION_NODES.has(node.type)) {
		out.push(node)
		return out
	}
	for (const child of node.children) expansionNodes(child, out)
	return out
}

/**
 * One file redirect: operator, descriptor, and a target resolved like an argument (§7.3), plus the
 * words the grammar filed in the same node after the target. `destination` is a repeated field and the
 * walker may not lose them — they come back for the owning command's argv (§7, §14.1).
 */
function fileRedirect(walk: Walk, node: Node): RedirectAnswer {
	const op = redirectOperator(node.text)
	// §7: `<>` is both a read and a write, and closing a descriptor has no target to report.
	if (!op || op === "<>" || op === ">&-" || op === "<&-") return { ok: false, refusal: refuse("redirect-unsupported", node.type) }
	const [destination, ...trailing] = node.childrenForFieldName("destination")
	if (!destination) return { ok: false, refusal: refuse("redirect-unsupported", node.type) }
	const target = resolvePiece(walk, { start: destination.startIndex, end: destination.endIndex, nodes: expansionNodes(destination) }, "redirect-target")
	if (!target.ok) return { ok: false, refusal: target.refusal }
	const descriptor = node.childForFieldName("descriptor")
	// §7.2: `2>&1` duplicates a descriptor; `>& file` is a write. Digits alone decide.
	const redirect: AstRedirect = { op, target: target.value, fdDup: (op === ">&" || op === "<&") && /^\d+$/.test(target.value) }
	if (descriptor) redirect.fd = Number(descriptor.text)
	return { ok: true, redirect, trailing: trailing.map((word) => ({ start: word.startIndex, end: word.endIndex, nodes: expansionNodes(word) })) }
}

/** The operator a redirect was written with, longest spelling first, past any descriptor (§7.1). */
function redirectOperator(text: string): string | null {
	const written = text.slice(/^\d+/.exec(text)?.[0].length ?? 0)
	for (const op of ["&>>", "<<-", "<<<", ">&", "<&", ">>", "<<", "<>", ">|", "&>", ">", "<"]) {
		if (written.startsWith(op)) return op
	}
	return null
}

/** A here-string is not reported (§7); its content still has to be a resolvable argument. */
function hereString(walk: Walk, node: Node): Refusal | null {
	for (const child of node.children) {
		if (!child.isNamed) continue
		const resolved = resolvePiece(walk, { start: child.startIndex, end: child.endIndex, nodes: expansionNodes(child) }, "argument")
		if (!resolved.ok) return resolved.refusal
	}
	return null
}

// --------------------------------------------------------------------------- §4 word resolution

/** The forms a `$` opens by itself, before any question of value (§4.2). */
const DOLLAR_FORMS: Record<string, Reason> = { "'": "ansi-c-string", '"': "translated-string" }

/**
 * Resolve one argument from the source it was written in: quoting removed, escapes resolved,
 * adjacent segments joined, globs and tildes kept exactly as written (§4). Nothing inside single
 * quotes is interpreted at all; inside double quotes a backslash escapes only `$`, backtick, `"`
 * and `\`. Anything the walker has no literal value for goes to the values module and comes back a
 * refusal (§14.1) — the scan never resolves an expansion itself.
 */
function resolvePiece(walk: Walk, piece: Piece, position: ValuePosition): Answer<string> {
	const src = walk.input.slice(piece.start, piece.end)
	if (hasBraceGroup(src)) return { ok: false, refusal: refuse("brace-expansion") }
	const at = new Map<number, Node>()
	for (const node of piece.nodes) at.set(node.startIndex - piece.start, node)

	let out = ""
	let quote = ""
	let i = 0
	while (i < src.length) {
		const ch = src[i]
		if (quote === "'") {
			if (ch === "'") quote = ""
			else out += ch
			i += 1
			continue
		}
		if (ch === "\\") {
			const next = src[i + 1]
			// A backslash-newline that joins one word: the two characters become nothing (§10.1).
			if (next === "\n" || next === undefined) {
				i += next === "\n" ? 2 : 1
				continue
			}
			// Inside double quotes a backslash escapes only four characters; elsewhere it is itself.
			if (quote === '"' && !'$`"\\'.includes(next)) {
				out += "\\"
				i += 1
				continue
			}
			out += next
			i += 2
			continue
		}
		if (ch === quote) {
			quote = ""
			i += 1
			continue
		}
		if (quote === "" && (ch === "'" || ch === '"')) {
			quote = ch
			i += 1
			continue
		}
		const expansion = at.get(i)
		if (expansion) {
			const whole = expansion.startIndex === piece.start && expansion.endIndex === piece.end
			const value = askValue(walk, expansion, position, out, whole, quote === '"')
			if (!value.ok) return value
			out += value.value
			i += expansion.endIndex - expansion.startIndex
			continue
		}
		if (ch === "$") {
			const next = src[i + 1] ?? ""
			const form = quote === "" ? DOLLAR_FORMS[next] : undefined
			if (form) return { ok: false, refusal: refuse(form) }
			// §4: a `$` with nothing expandable after it is the character `$`.
			if (next === "" || !/[*@#$?!0-9A-Za-z_(]/.test(next)) {
				out += "$"
				i += 1
				continue
			}
			// Expandable, and the tree gave no node for it: no literal, so no argument (§1.3).
			return { ok: false, refusal: refuse("variable-expansion") }
		}
		out += ch
		i += 1
	}
	// A quote that never closed is malformed; the parser could not have handed us the piece unless
	// the scan of §2 step 3 had already refused it, so this is a backstop, not the normal path.
	if (quote !== "") return { ok: false, refusal: refuse("unterminated-quote", quote === "'" ? "raw_string" : "string") }
	return { ok: true, value: out }
}

/** Route one expansion to the values module (§5, §6). It answers with a value or a refusal. */
function askValue(walk: Walk, node: Node, position: ValuePosition, prefix: string, whole: boolean, quoted: boolean): Answer<string> {
	const answer = resolveValue(
		walk.scope,
		{ node, position, prefix, whole, quoted },
		// §6.2: the commands inside an accepted substitution are emitted before the one containing it.
		(inner) => walkSequence(walk, inner),
	)
	if (!answer.ok) return { ok: false, refusal: answer.refusal }
	return { ok: true, value: answer.text }
}

/**
 * §4.2: `{a,b}` and `{1..5}` turn one written word into several arguments, in any position, and an
 * escaped brace group is refused too (§10.5). A brace inside quotes cannot open a group, so quoted
 * runs are skipped, and `{}` — the `find -exec` placeholder — holds no separator and stays literal.
 */
function hasBraceGroup(src: string): boolean {
	let depth = 0
	let joins = false
	for (let i = 0; i < src.length; i++) {
		const ch = src[i]
		if (ch === "'" || ch === '"') {
			const close = src.indexOf(ch, i + 1)
			if (close < 0) return false
			i = close
			continue
		}
		if (ch === "{") depth += 1
		else if (ch === "}") {
			if (depth === 1 && joins) return true
			depth = Math.max(0, depth - 1)
			joins = false
		} else if (depth >= 1 && (ch === "," || (ch === "." && src[i + 1] === "."))) joins = true
	}
	return false
}

// --------------------------------------------------------------------------- §9 test commands

/** Nodes that hold a test expression rather than being one of its words. */
const TEST_EXPRESSIONS = new Set(["binary_expression", "unary_expression", "parenthesized_expression", "ternary_expression", "postfix_expression"])

/** §9.1: both spellings report `[[` first and drop the closing bracket. */
function walkTest(walk: Walk, node: Node, connector: string, extra: AstRedirect[], trailing: Piece[] = []): Refusal | null {
	const draft = newDraft(node, connector)
	draft.command.redirects.push(...extra)
	draft.command.argv.push("[[")
	const flattened = flattenTest(walk, node, draft)
	if (flattened) return flattened
	const appended = appendWords(walk, draft.command, trailing)
	if (appended) return appended
	return emit(walk, draft)
}

/** §9.2: operators and operands flattened into argv in source order, each as written. */
function flattenTest(walk: Walk, node: Node, draft: Draft): Refusal | null {
	for (const child of node.children) {
		if (child.type === "[" || child.type === "[[" || child.type === "]" || child.type === "]]") continue
		if (!child.isNamed) {
			draft.command.argv.push(child.type)
			continue
		}
		if (TEST_EXPRESSIONS.has(child.type) && child.namedChildCount > 0) {
			const deeper = flattenTest(walk, child, draft)
			if (deeper) return deeper
			continue
		}
		const piece: Piece = { start: child.startIndex, end: child.endIndex, nodes: expansionNodes(child) }
		if (!WORD_NODES.has(child.type) && piece.nodes.length === 0) {
			// An operand the walker has no rule for: the values module names it (§3.2).
			const answer = resolveValue(walk.scope, { node: child, position: "test-operand", prefix: "", whole: true, quoted: false }, (inner) => walkSequence(walk, inner))
			if (!answer.ok) return answer.refusal
			draft.command.argv.push(answer.text)
			draft.sources.push(piece)
			continue
		}
		const resolved = resolvePiece(walk, piece, "test-operand")
		if (!resolved.ok) return resolved.refusal
		draft.command.argv.push(resolved.value)
		draft.sources.push(piece)
	}
	return null
}

// --------------------------------------------------------------------------- §6.3, §13 spans

/** Record a command at the moment it is complete: its span is the source it was walked from. */
function emit(walk: Walk, draft: Draft): Refusal | null {
	const command = draft.command
	if (draft.fdShift !== undefined) {
		const target = command.redirects.find((redirect) => redirect.fd === undefined)
		if (target) target.fd = draft.fdShift
	}
	command.text = walk.input.slice(command.start, command.end)
	// §13.6: every word a command reports must come from inside the span it reports. A redirect
	// target is the one thing outside it — §13.3 and the corpus put a command's span at its last
	// argument — so only argv and environment words are checked here.
	for (const source of draft.sources) {
		if (source.start < command.start || source.end > command.end) return refuse("inventory-mismatch", "command")
	}
	walk.commands.push(command)
	return null
}

/**
 * §6.3: `opaque` is a property of what the command reports — any argument, any environment value,
 * or any redirect target that is not a descriptor duplicate carrying a placeholder, whole or as a
 * substring. Derived from the reported values so flag and values can never disagree.
 */
function settle(walk: Walk): Refusal | null {
	const sees = (value: string) => value.includes(CMDSUB_PLACEHOLDER) || value.includes(TRACKED_VAR_PLACEHOLDER)
	for (const command of walk.commands) {
		if (command.text !== walk.input.slice(command.start, command.end)) return refuse("inventory-mismatch", "command")
		command.opaque =
			command.argv.some(sees) ||
			command.envVars.some((entry) => sees(entry.value)) ||
			command.redirects.some((redirect) => !redirect.fdDup && sees(redirect.target))
	}
	return null
}
