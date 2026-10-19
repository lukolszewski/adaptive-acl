/**
 * bash-walker-meaning.ts — docs/LAYER0-WALKER-SPEC.md §11, run as §2 step 9 over the finished
 * command list.
 *
 * Everything here reads **resolved values** — `argv`, `envVars`, redirect targets — and never
 * `text` (§11.3): an escaped spelling (`\environ`), a quoted name and a fused flag (`-vNAME`) each
 * hide the same meaning from a reader that works on the source. The input reached this module
 * parsed and well-formed, so none of these refusals is malformed (§11.4, §1.2): the walker is
 * declining to reason about valid bash, and the caller sends it to the effect model.
 *
 * Per command the questions are asked in this order, and the first refusal wins (§12.1):
 *
 * 1. **Is the thing in command position a command?** An empty word, a run-time value, a word that
 *    starts with `-`, `|` or `&`, or a shell reserved word (§11). A command with no command word at
 *    all — a bare redirect (§3.1) — has nothing to ask here.
 * 2. **Can we see the command it actually runs?** A wrapper whose form is known is skipped for
 *    these checks only; the reported `argv` still says what was written (§11.2). A wrapper whose
 *    options the tables below do not cover cannot be skipped, and is refused rather than judged as
 *    itself (`wrapper-not-analysable`).
 * 3. **Do the reported values say all they say?** A newline-and-`#` inside a value hides its tail
 *    from anything that re-reads the line; a path under `/proc/…/environ` is another process's
 *    environment (§11).
 * 4. **What does the resolved command word mean?** Verbs that run their arguments as code, names
 *    that belong to another shell, name operands the shell computes, and a `jq` filter that runs
 *    code or loads one from disk (§11, §5.9, §9.5).
 *
 * `sudo` and the other privilege wrappers are not this module's business, nor is `xargs`: their
 * argument command is the caller's to judge (§11.1), so they are never peeled and never mentioned.
 *
 * The module has one other job, and it is the mirror image of these checks: {@link outputFlagWrites}
 * reads a resolved argv and reports the file the command **opens for writing** through a flag
 * (`sort -o FILE`). It asks the same question — what does this command word mean — and its answer is
 * data for the walker rather than a refusal, so it lives beside the tables rather than in a second
 * reader that could disagree with these.
 *
 * The tables are the whole of the module's knowledge, in one place each: {@link CODE_VERBS},
 * {@link REPORT_ONLY_OPTIONS}, {@link CODE_OPTIONS}, {@link ZSH_MODULE_BUILTINS},
 * {@link NAME_VERBS}, {@link ARITHMETIC_COMPARISONS}, {@link WRAPPERS}, {@link JQ_FILE_OPTIONS},
 * {@link OUTPUT_FLAG_WRITES}.
 * Deterministic like the rest of the walker: no clock, no filesystem, no environment — the
 * `/proc` rule is a string comparison on the resolved path, never a `stat` (§14.4).
 */

import type { AstCommand } from "./bash-ast.ts"
import { CMDSUB_PLACEHOLDER, TRACKED_VAR_PLACEHOLDER, refuse, type Refusal } from "./bash-walker.ts"

/** §11 over the emitted commands, in emit order; the first refusal is the parse's refusal. */
export function checkMeaning(commands: readonly AstCommand[]): Refusal | null {
	for (const command of commands) {
		const refusal = oneCommand(command)
		if (refusal) return refusal
	}
	return null
}

/** One command: its name, the command behind its wrappers, its values, then its verb. */
function oneCommand(command: AstCommand): Refusal | null {
	const name = commandWordIsAProgram(command.argv)
	if (name) return name

	const wrapped = peel(command.argv)
	if (wrapped === null) return refuse("wrapper-not-analysable")

	const hidden = valuesSayWhatTheySay(command)
	if (hidden) return hidden

	return verbIsTrustworthy(wrapped)
}

// --------------------------------------------------------------------------- 1. the command word

/**
 * §11 — a shell reserved word in command position. Only a mis-parse puts one there (`! for i in a;
 * do :; done` reaches us as three commands), and a keyword can never name a program. `[[` is
 * deliberately absent: it is the canonical first argument of a test command (§9.1) and the corpus
 * requires it to stay accepted.
 */
const RESERVED_WORDS = new Set(["if", "then", "else", "elif", "fi", "for", "select", "while", "until", "do", "done", "case", "esac", "function", "in", "!", "{", "}", "]]"])

/** §11 — the first argument must be one whole, literal, program-shaped word. */
function commandWordIsAProgram(argv: readonly string[]): Refusal | null {
	// A bare redirect has no command word at all (§3.1): nothing here to judge.
	if (argv.length === 0) return null
	const word = argv[0]
	// The shell drops an empty expansion at command position and shifts the rest up.
	if (word === "") return refuse("empty-command-name")
	// Which program runs is a run-time fact; §6.5 should have refused the value already.
	if (wornAsLiteral(word)) return refuse("command-name-not-a-literal")
	// What was emitted is a piece of a command: a stray flag, or an operator with no word.
	if (/^[-|&]/.test(word)) return refuse("incomplete-command-fragment")
	if (RESERVED_WORDS.has(word)) return refuse("keyword-as-command-name")
	return null
}

// --------------------------------------------------------------------------- 2. wrappers (§11.2)

/** How the arguments of one wrapper are read to find the command it runs. */
type Wrapper = {
	/** Options with no value of their own; the command may start after them. */
	bareOptions?: readonly string[]
	/** Options that take the next argument, or one fused to them (`-uFOO`), as their value. */
	valueOptions?: readonly string[]
	/** Long options accepted only written `--name=value`; the separated spelling hides the command. */
	setOptions?: readonly string[]
	/** Short options accepted only fused to their value (`-o0`); the separated spelling does the same. */
	fusedOptions?: string
	/** `NAME=value` arguments belong to the wrapper, not to the command (`env FOO=1 ls`). */
	assignments?: boolean
	/** A positional the wrapper eats before the command — a duration, an adjustment. */
	leading?: { pattern: RegExp; required: boolean }
	/** An expansion in the first argument means the wrapper's own argument is the command's shape. */
	opaqueFirstArgument?: boolean
}

/**
 * §11 — the wrappers this walker can read past. `timeout`, `env`, `stdbuf` and `nice` are the four
 * the spec names; `time` and `nohup` exec their remaining arguments unchanged (§3.2 calls `time` a
 * wrapper), so judging the wrapper instead of the wrapped command would be judging nothing.
 *
 * `timeout` knows **no** options of its own: every one of them sits in front of the duration and
 * some of them take a value, so an option we do not model is a duration we cannot find and a
 * command we cannot locate (`sem-timeout-fragment`: even `--kill-after` refuses). `--` is not an
 * option, it is the end of them, and is accepted everywhere.
 */
const WRAPPERS: Record<string, Wrapper> = {
	env: { bareOptions: ["--", "-i", "-0", "--ignore-environment", "--null"], valueOptions: ["-u", "--unset"], assignments: true },
	nice: { bareOptions: ["--"], valueOptions: ["-n", "--adjustment"], leading: { pattern: /^[+-]?\d+$/, required: false }, opaqueFirstArgument: true },
	stdbuf: { bareOptions: ["--"], setOptions: ["--output", "--error", "--input"], fusedOptions: "oei" },
	timeout: { bareOptions: ["--"], leading: { pattern: /^\d+(\.\d+)?[smhd]?$/, required: true } },
	nohup: { bareOptions: ["--"] },
	time: { bareOptions: ["--", "-p", "-v"], valueOptions: ["-f", "-o"] },
}

/** A shell name, as bash accepts one. */
const SHELL_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/

/** `NAME=value` — an argument that belongs to the wrapper rather than to the command. */
function isAssignment(word: string): boolean {
	const equals = word.indexOf("=")
	return equals > 0 && SHELL_NAME.test(word.slice(0, equals))
}

/** §11.2 — step over every wrapper that can be read, as many times as they stack. */
function peel(argv: readonly string[]): readonly string[] | null {
	let rest = argv
	for (;;) {
		const wrapper = rest.length > 0 ? table(WRAPPERS, rest[0]) : undefined
		if (!wrapper) return rest
		const inner = peelOnce(rest.slice(1), wrapper)
		if (inner === null) return null
		rest = inner
	}
}

/** The arguments of the wrapped command, or null when this wrapper's form is not the known one. */
function peelOnce(args: readonly string[], wrapper: Wrapper): readonly string[] | null {
	// §11 — `nice $((0-5)) cmd`: the adjustment is an expansion, so what is a flag and what is the
	// command is not decidable from the text.
	if (wrapper.opaqueFirstArgument && args.length > 0 && expandsAtRuntime(args[0])) return null

	let i = 0
	let optionsWritten = false
	let leadingLeft = wrapper.leading !== undefined
	while (i < args.length) {
		const arg = args[i]
		if (!optionsWritten && arg === "--") {
			optionsWritten = true
			i += 1
			continue
		}
		if (leadingLeft && wrapper.leading?.pattern.test(arg)) {
			leadingLeft = false
			i += 1
			continue
		}
		if (wrapper.assignments && isAssignment(arg)) {
			i += 1
			continue
		}
		if (optionsWritten || !isOption(arg)) break

		const [name, inline] = splitOption(arg)
		if (name.startsWith("--")) {
			// A long option that needs a value only counts when the value was written with it.
			if (wrapper.setOptions?.includes(name)) {
				if (inline === undefined) return null
				i += 1
				continue
			}
			if (wrapper.valueOptions?.includes(name)) i = skip(args, i, inline)
			else if (wrapper.bareOptions?.includes(name)) i += 1
			else return null
			continue
		}
		const letter = name.slice(1)
		if (wrapper.fusedOptions?.includes(letter) && inline !== undefined) i += 1
		else if (wrapper.valueOptions?.includes(name)) i = skip(args, i, inline)
		else if (wrapper.bareOptions?.includes(name) && inline === undefined) i += 1
		else return null
	}
	// A required positional (a duration) that never appeared, or an option where the command should
	// be, means the wrapped command cannot be located.
	if (leadingLeft && wrapper.leading?.required) return null
	return args.slice(i)
}

/** Past one option and its value: fused when it was written with the flag, otherwise the next word. */
function skip(args: readonly string[], index: number, inline: string | undefined): number {
	return inline === undefined ? index + 2 : index + 1
}

/** An option word, as opposed to `-` (stdin) or the empty string. */
function isOption(arg: string): boolean {
	return arg.length > 1 && arg.startsWith("-")
}

/** Split an option into its name and any value written with it: `-o0`, `--output=0`. */
function splitOption(arg: string): [string, string | undefined] {
	if (arg.startsWith("--")) {
		const at = arg.indexOf("=")
		return at < 0 ? [arg, undefined] : [arg.slice(0, at), arg.slice(at + 1)]
	}
	return [arg.slice(0, 2), arg.length > 2 ? arg.slice(2) : undefined]
}

// --------------------------------------------------------------------------- 3. the reported values

/** §11 — a newline, optional blanks and `#`: everything after it is invisible to a line reader. */
const HIDDEN_COMMENT = /\n[ \t]*#/

/** §11 — every value the command reports that could name a file or hide text. */
function valuesSayWhatTheySay(command: AstCommand): Refusal | null {
	const values = [...command.argv, ...command.envVars.map((one) => one.value)]
	for (const redirect of command.redirects) {
		// A descriptor dup has no path in it (§7.6); everything else is a target.
		if (!redirect.fdDup) values.push(redirect.target)
	}
	for (const value of values) {
		if (namesProcEnviron(value)) return refuse("proc-environ-read")
		if (HIDDEN_COMMENT.test(value)) return refuse("hidden-comment-in-argument")
	}
	return null
}

/**
 * §11 — another process's environment file. The kernel resolves path segments, so the answer is
 * decided on the resolved path with its `.` and `..` collapsed and its repeated slashes removed:
 * `/proc/self/../self/environ` is `/proc/self/environ`, and the escaped spelling arrives resolved
 * (§11.3). A relative `proc/self/environ` is a file in the working directory, not this one.
 */
function namesProcEnviron(value: string): boolean {
	// Relative means relative: `proc/self/environ` is a file under the working directory.
	if (!value.startsWith("/")) return false
	const stack: string[] = []
	for (const segment of value.split("/")) {
		// `//` and `.` say nothing; `..` at the root stays at the root, exactly as the kernel resolves it.
		if (segment === "" || segment === ".") continue
		if (segment === "..") {
			if (stack.length > 0) stack.pop()
			continue
		}
		stack.push(segment)
	}
	// `/proc/<pid-or-self>/environ` and nothing below it.
	return stack.length === 3 && stack[0] === "proc" && stack[2] === "environ"
}

// --------------------------------------------------------------------------- 4. what the verb means

/** §11 — verbs whose arguments the shell runs as shell code, whatever their options. */
const CODE_VERBS = new Set(["eval", "source", ".", "exec", "builtin", "trap", "enable", "hash", "bind", "complete", "alias", "let", "coproc", "noglob", "nocorrect"])

/**
 * §11 — verbs that only report when run with one of these options. Anything else they are given —
 * including no option at all, which is the edit/re-execute default — runs code.
 */
const REPORT_ONLY_OPTIONS: Record<string, readonly string[]> = {
	command: ["-v", "-V"],
	fc: ["-l", "-n", "-r", "-t"],
}

/** §11 — verbs that run code only when given one of these options: a callback, a command, a function. */
const CODE_OPTIONS: Record<string, readonly string[]> = {
	mapfile: ["-C"],
	readarray: ["-C"],
	compgen: ["-C", "-F"],
}

/** §11 — names that are not programs on disk but internals of another shell, reached through a loader. */
const ZSH_MODULE_BUILTINS = new Set(["zmodload", "emulate", "sysopen", "sysread", "syswrite", "sysseek", "zpty", "ztcp", "zsocket"])

/** §11 — the `zf_` file-operations family, by prefix. */
const isZshFileOperation = (verb: string): boolean => verb.startsWith("zf_")

function verbIsTrustworthy(argv: readonly string[]): Refusal | null {
	if (argv.length === 0) return null
	const [verb, ...args] = argv

	if (ZSH_MODULE_BUILTINS.has(verb) || isZshFileOperation(verb)) return refuse("zsh-module-builtin")
	if (runsItsArguments(verb, args)) return refuse("evaluates-arguments-as-code")

	const rule = table(NAME_VERBS, verb)
	if (rule) {
		const names = nameOperandsArePlain(rule, args)
		if (names) return names
	}
	if (rule?.arithmeticContext || verb === "[[" || verb === "[" || verb === "test") {
		const numeric = arithmeticOperandsArePlain(args)
		if (numeric) return numeric
	}
	if (verb === "jq") return jqFilterIsPlain(args)
	return null
}

/** §11 — does this verb hand its arguments to the shell? */
function runsItsArguments(verb: string, args: readonly string[]): boolean {
	if (CODE_VERBS.has(verb)) return true

	const reportOnly = table(REPORT_ONLY_OPTIONS, verb)
	if (reportOnly) {
		let reporting = false
		for (const arg of args) {
			if (!isOption(arg)) continue
			if (!everyOptionIn(arg, reportOnly)) return true
			reporting = true
		}
		// No report-only option means the default, and the default runs the arguments.
		return !reporting
	}

	const dangerous = table(CODE_OPTIONS, verb)
	if (dangerous) return args.some((arg) => isOption(arg) && someOptionIn(arg, dangerous))
	return false
}

/** An option word whose every letter is one of the reporting options (`-ln` yes, `-lnx` no). */
function everyOptionIn(arg: string, options: readonly string[]): boolean {
	if (arg.startsWith("--")) return options.includes(arg.split("=")[0])
	return [...arg.slice(1)].every((letter) => options.some((one) => !one.startsWith("--") && one[1] === letter))
}

/** An option word that carries one of the given options, fused or in a cluster (`-Ccb`, `--from-file`). */
function someOptionIn(arg: string, options: readonly string[]): boolean {
	if (arg.startsWith("--")) return options.includes(arg.split("=")[0])
	return [...arg.slice(1)].some((letter) => options.some((one) => !one.startsWith("--") && one[1] === letter))
}

// --------------------------------------------------------------------------- name operands (§5.9, §9.5)

/** How one verb reads its name operands. */
type NameRule = {
	/** Flags whose operand is a name the shell computes; a fused operand counts (`-vNAME`). */
	nameFlags?: readonly string[]
	/** Flags whose operand is data — a prompt, a timeout, a delimiter — and must not be read as a name. */
	dataFlags?: readonly string[]
	/** Non-option arguments after the flags are names too. */
	positionalNames?: boolean
	/** Declaration syntax: `NAME=value` items, and flags that change what an assignment means. */
	declaration?: boolean
	/** Operands are evaluated arithmetically even without a comparison operator. */
	arithmeticContext?: boolean
}

/**
 * §11 — verbs that re-read a name operand, so a subscript hidden inside single quotes is computed
 * and whatever hides in it runs. A data-taking operand is not a name: `read -p '[dir] ' v` is fine.
 */
const NAME_VERBS: Record<string, NameRule> = {
	"[": { nameFlags: ["-v", "-R"] },
	"[[": { nameFlags: ["-v", "-R"] },
	test: { nameFlags: ["-v", "-R"] },
	printf: { nameFlags: ["-v"] },
	read: { nameFlags: ["-a", "-A"], dataFlags: ["-p", "-t", "-u", "-n", "-N", "-d"], positionalNames: true },
	unset: { nameFlags: ["-v"], positionalNames: true },
	wait: { nameFlags: ["-p"] },
	declare: { declaration: true },
	typeset: { declaration: true },
	local: { declaration: true },
}

/**
 * §5.9 — a declaring flag that changes what an assignment means, by letter, so a cluster (`-xn`) is
 * read letter by letter the way the builtin reads it. `declare -A` is absent on purpose: an
 * associative key is a string, not an arithmetic subscript, and the spec names only `-n`, `-i`, `-a`.
 */
const DECLARATION_FLAGS: Record<string, "nameref-assignment" | "subscript-evaluation"> = { n: "nameref-assignment", i: "subscript-evaluation", a: "subscript-evaluation" }

/** §9.5 — inside a bracketed test these make both neighbours numeric contexts. */
const ARITHMETIC_COMPARISONS = new Set(["-eq", "-ne", "-lt", "-le", "-gt", "-ge"])

/**
 * A name the shell computes: `name[…]`, so the bracket is part of the name rather than data — that
 * is where a substitution hides. A word that merely starts with a bracket (`[dir] `) is data, not a
 * subscripted name.
 */
function subscripted(word: string): boolean {
	const bracket = word.indexOf("[")
	return bracket > 0 && SHELL_NAME.test(word.slice(0, bracket))
}

/** What a flag does to the word after it: a name to read, data to skip, or neither. */
function operandRole(rule: NameRule, flag: string): "name" | "data" | null {
	if (rule.nameFlags?.includes(flag)) return "name"
	if (rule.dataFlags?.includes(flag)) return "data"
	return null
}

/** Every word this verb reads as a name — a flag operand or a positional, never a data operand. */
function nameOperands(rule: NameRule, args: readonly string[]): string[] {
	const names: string[] = []
	let waiting: "name" | "data" | null = null
	let optionsWritten = false
	for (const word of args) {
		// The word after a flag that takes one is its operand, whatever it looks like: a data operand
		// is never read as a name, which is why `read -p '[dir] ' v` is fine.
		if (waiting !== null) {
			if (waiting === "name") names.push(word)
			waiting = null
			continue
		}
		if (!optionsWritten && word === "--") {
			optionsWritten = true
			continue
		}
		if (optionsWritten || !isOption(word)) {
			if (rule.positionalNames) names.push(word)
			continue
		}
		const [flag, fused] = splitOption(word)
		const role = operandRole(rule, flag)
		if (role === null) continue
		if (fused === undefined) waiting = role
		else if (role === "name") names.push(fused)
	}
	return names
}

/** §11, §5.9 — every name this verb reads must be a plain name, with no subscript in it. */
function nameOperandsArePlain(rule: NameRule, args: readonly string[]): Refusal | null {
	if (rule.declaration) return declarationOperands(args)
	return nameOperands(rule, args).some(subscripted) ? refuse("subscript-evaluation") : null
}

/** §5.9 — `declare`/`typeset`/`local`: the flag decides, and a subscripted item is computed too. */
function declarationOperands(args: readonly string[]): Refusal | null {
	let optionsWritten = false
	for (const arg of args) {
		if (!optionsWritten && arg === "--") {
			optionsWritten = true
			continue
		}
		if (optionsWritten || !isOption(arg)) {
			// The name half of `NAME=value` — a subscript there is computed before anything is stored.
			if (subscripted(arg.split("=")[0])) return refuse("subscript-evaluation")
			continue
		}
		// No long option of the declaring builtins changes what an assignment means. None of the
		// short ones takes a value either, so every letter of a cluster is a flag (`-xn` names).
		if (arg.startsWith("--")) continue
		for (const letter of arg.slice(1)) {
			const reason = table(DECLARATION_FLAGS, letter)
			if (reason) return refuse(reason)
		}
	}
	return null
}

/** §9.5 — an arithmetic comparison computes both of its operands, subscript included. */
function arithmeticOperandsArePlain(args: readonly string[]): Refusal | null {
	for (let i = 1; i < args.length - 1; i++) {
		if (!ARITHMETIC_COMPARISONS.has(args[i])) continue
		if (subscripted(args[i - 1]) || subscripted(args[i + 1])) return refuse("subscript-evaluation")
	}
	return null
}

// --------------------------------------------------------------------------- jq

/**
 * §11 — the `jq` options that load a program, a raw file, a slurped file or a library path. `-f`
 * and `-L` are the only `jq` options that start with those letters, so a cluster (`-rf`, `-eLf`)
 * counts: the file flag is in it whatever else is written beside it.
 */
const JQ_FILE_OPTIONS = ["-f", "-L", "--from-file", "--rawfile", "--slurpfile", "--library-path"]

/** §11 — the code-executing builtin of the jq language. */
const JQ_SYSTEM = /\bsystem\s*\(/

/** §11 — a filter that runs commands, or one loaded from somewhere the walker cannot read. */
function jqFilterIsPlain(args: readonly string[]): Refusal | null {
	for (const arg of args) {
		if (!isOption(arg)) {
			// The program text, and the file names beside it; a file name is not `system(`.
			if (JQ_SYSTEM.test(arg)) return refuse("jq-system-call")
			continue
		}
		if (someOptionIn(arg, JQ_FILE_OPTIONS)) return refuse("jq-file-flag")
	}
	return null
}

// --------------------------------------------------------------------------- 5. writes through a flag

/** How one tool names the file it writes, when it writes one through a flag instead of a redirect. */
type OutputFlagWrite = {
	/** Short flags whose operand is the file, alone (`-o FILE`), fused (`-oFILE`) or in a cluster (`-bo FILE`). */
	short?: readonly string[]
	/** Long flags whose operand is the file, fused (`--output=FILE`) or separate (`--output FILE`). */
	long?: readonly string[]
	/** Restricts the rule to tools run with one of these subcommands. */
	subcommands?: readonly string[]
	/** The file is opened for appending (`>>`) rather than truncated (`>`). */
	append?: boolean
}

/**
 * The tools whose output flag this walker reads as a write target. Deliberately short: an entry is a
 * claim about one tool's option grammar, and `-o` means something else in most of the tools it could
 * be given to (`ssh -o BatchMode=yes`, `grep -o`, `git -O <orderfile>`), so an unlisted tool reports no
 * target and keeps exactly the verdict it had before this rule existed — never a wrong one.
 *
 * `git --output` belongs to its diff family: `git-diff(1)` documents it in the shared diff options, so
 * `diff`, `show` and `log` all take it and nothing else does.
 */
const OUTPUT_FLAG_WRITES: Record<string, OutputFlagWrite> = {
	sort: { short: ["-o"] },
	uniq: { long: ["--output"] },
	patch: { short: ["-o"] },
	tee: { short: ["-o"], long: ["--output"] },
	git: { long: ["--output"], subcommands: ["diff", "show", "log"] },
}

/** One file a command opens for writing through a flag, and how it opens it. */
export type FlagWrite = { target: string; append: boolean }

/**
 * The files one command's argv writes through an output flag, in the order they were named.
 *
 * `sort -o /etc/x in.txt` opens `/etc/x` for writing exactly as `sort > /etc/x` does, but nothing in
 * the tree says so: the flag is an ordinary word and its operand an ordinary argument, so a reader
 * that only knows `file_redirect` nodes calls the command read-only and the ladder auto-runs it. This
 * answers with the operand, and the walker reports it on the **same channel a redirect target
 * travels on** — an `AstRedirect` on the command — so the tier tables, the secret/device rules, the
 * strict-operand matching and the target coverage all see it without learning anything new.
 *
 * Read off the peeled argv (§11.2), because `env LC_ALL=C sort -o /etc/x f` writes `/etc/x`; a wrapper
 * the peel cannot read reports nothing, which is the verdict the command came with. A name written by
 * `basename`, so `/usr/bin/sort` is the tool it looks like. Every name is reported, including a second
 * `-o` on the same command and a value that is a runtime placeholder — the first is what the tool may
 * well open, and the second is answered by the command's own `opaque` flag, not by dropping it here.
 */
export function outputFlagWrites(argv: readonly string[]): FlagWrite[] {
	const inner = peel(argv)
	if (inner === null || inner.length === 0) return []
	const rule = table(OUTPUT_FLAG_WRITES, programName(inner[0]))
	if (!rule) return []
	const args = inner.slice(1)
	// A subcommand-scoped rule applies when the tool was run with one of its subcommands anywhere among
	// the words in front of the flags — `git -c core.pager=cat diff --output=f` is still `git diff`.
	const subcommands = rule.subcommands
	if (subcommands && !args.some((word) => !isOption(word) && subcommands.includes(word))) return []

	const writes: FlagWrite[] = []
	for (let i = 0; i < args.length; i++) {
		if (args[i] === "--") break // the end of options: a `--output` after it is a filename
		const named = flagOperand(args[i], args[i + 1], rule)
		if (!named) continue
		writes.push({ target: named.value, append: rule.append === true })
		i += named.consumed
	}
	return writes
}

/** The last path segment of a command word: what the tables are keyed by, as everywhere in layer 0. */
function programName(word: string): string {
	return word.slice(word.lastIndexOf("/") + 1)
}

/**
 * The file this option word names, and how many following words its value used up — null when the word
 * names none. One long flag (`--output=…` / `--output …`) or one short flag letter, read in a cluster
 * the way getopt reads it, so a letter that is not last takes the rest of the cluster as its operand and
 * a letter that is last takes the next word.
 */
function flagOperand(word: string | undefined, next: string | undefined, rule: OutputFlagWrite): { value: string; consumed: number } | null {
	if (word === undefined || !isOption(word)) return null
	const operand = (written: string | undefined): { value: string; consumed: number } | null => {
		const value = written ?? next
		// An operand that looks like another option (`sort -o -k1 f`) or is the stream the tool already
		// has (`-`) names nothing: guessing which of a tool's flags is a file is not how a target gets
		// reported, and the tool would reject such a command anyway.
		if (value === undefined || isOption(value) || value === "-") return null
		return { value, consumed: written === undefined ? 1 : 0 }
	}
	if (word.startsWith("--")) {
		const [name, fused] = splitOption(word)
		return rule.long?.includes(name) ? operand(fused) : null
	}
	const letters = word.slice(1)
	for (let at = 0; at < letters.length; at++) {
		if (!rule.short?.includes(`-${letters[at]}`)) continue
		return operand(letters.slice(at + 1) || undefined)
	}
	return null
}

// --------------------------------------------------------------------------- shared bits

/** A value that exists only when the command runs (§6.1), whole or inside a longer string. */
function wornAsLiteral(value: string): boolean {
	return value.includes(CMDSUB_PLACEHOLDER) || value.includes(TRACKED_VAR_PLACEHOLDER)
}

/** Worn as a literal, or still carrying the expansion that the shell — not the walker — resolves. */
function expandsAtRuntime(value: string): boolean {
	return wornAsLiteral(value) || /[$`]/.test(value)
}

/** Table lookup that cannot pick up `Object.prototype`: `constructor` is a perfectly good command. */
function table<T>(rows: Record<string, T>, name: string): T | undefined {
	return Object.hasOwn(rows, name) ? rows[name] : undefined
}
