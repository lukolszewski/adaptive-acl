/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { beforeAll, describe, expect, it } from "vitest"
import type { Node } from "web-tree-sitter"
import { initBashParser, parseBash } from "./bash-parser.ts"
import { refuse, walkBash } from "./bash-walker.ts"
import { compareCase, loadGolden, selectById, type GoldenCase } from "./bash-walker-golden.ts"
import { newValueScope, rememberAssignment, resolveValue, type ValuePosition, type ValueScope } from "./bash-walker-values.ts"

/**
 * Tests for the values layer of the walker (docs/LAYER0-WALKER-SPEC.md §4.2/§4.3, §5, §6, and the
 * §3.1 builtins that assign) over its subset of `bash-walker.golden.jsonl`, plus the cases part 1
 * deferred here and unit cases for the value store itself.
 */

/** The id prefixes this part owns. */
const SUBSET = ["assign-", "cs-", "decl-", "exp-", "unset-"]

/** The five cases part 1 handed to part 2 (`bash-walker.test.ts` lists them as `T10b`). */
const INHERITED = ["word-arith-literal", "word-arith-base", "word-number-base-subst", "test-home-operand", "span-substitution"]

/**
 * Cases in the subset this part cannot pass, and the part that owns the fix. Empty since the
 * supervisor corrected the three corpus lines whose `end` was one index past the input
 * (`test-home-operand`, `cs-cat-heredoc-multi`, `assign-tracked-redirect`; the last also had the
 * span include its redirect, which `red-out` and part 1's span rule exclude).
 */
export const DEFERRED: Record<string, "T10c" | "T10d" | "T11"> = {}

const ALL = loadGolden()
const CASES: GoldenCase[] = [
	...selectById(ALL, SUBSET),
	...INHERITED.map((id) => ALL.find((one) => one.id === id)).filter((one): one is GoldenCase => one !== undefined),
]
const OWNED = CASES.filter((one) => !(one.id in DEFERRED))

beforeAll(async () => {
	await initBashParser()
})

describe("golden subset", () => {
	for (const one of OWNED) {
		it(one.id, () => {
			const mismatch = compareCase(one, walkBash(one.command))
			expect(mismatch, mismatch ? `${mismatch.id}: ${mismatch.message}` : undefined).toBeNull()
		})
	}
	for (const [id, part] of Object.entries(DEFERRED)) {
		if (!CASES.some((one) => one.id === id)) continue
		it.todo(`${id} — needs ${part}`)
	}
})

describe("the subset and the deferral list", () => {
	it("every deferred id is a case in the subset", () => {
		const ids = new Set(CASES.map((one) => one.id))
		expect(Object.keys(DEFERRED).filter((id) => !ids.has(id))).toEqual([])
	})

	it("the subset is the size the task describes", () => {
		expect(CASES.length).toBe(72)
	})
})

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const refused = (command: string): Extract<ReturnType<typeof walkBash>, { kind: "unproven" }> => {
	const parsed = walkBash(command)
	expect(parsed.kind, `${command} -> ${JSON.stringify(parsed)}`).toBe("unproven")
	return parsed as Extract<typeof parsed, { kind: "unproven" }>
}

/** §12 id or "simple" — `string` because `AstParse.reason` is declared `string` (bash-ast.ts), not as the `Reason` union. */
const reasonOf = (command: string): string => {
	const parsed = walkBash(command)
	return parsed.kind === "simple" ? "simple" : parsed.reason
}

const commandsOf = (command: string) => {
	const parsed = walkBash(command)
	if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
	return parsed.commands
}

const argvs = (command: string): string[][] => commandsOf(command).map((one) => one.argv)

// --------------------------------------------------------------------------- §5.3 / §5.4 remembered literals

describe("remembered literals (§5.3, §5.4)", () => {
	it("substitutes a literal into a later reference, in either spelling", () => {
		expect(argvs("D=/tmp/build && rm -rf $D")).toEqual([["rm", "-rf", "/tmp/build"]])
		expect(argvs('D=/tmp/build && rm -rf "$D"')).toEqual([["rm", "-rf", "/tmp/build"]])
		expect(argvs('D=/tmp && cp x "$D/y"')).toEqual([["cp", "x", "/tmp/y"]])
	})

	it("substitutes into a redirect target and a here-string as well", () => {
		expect(commandsOf('D=/tmp && cp a "$D/b" > "$D/log"')[0].redirects).toEqual([{ op: ">", target: "/tmp/log", fdDup: false }])
		expect(argvs("D=hello && grep world <<< $D")).toEqual([["grep", "world"]])
	})

	it("refuses a bare reference whose value could be re-split or re-matched", () => {
		for (const command of ['D="-rf /" && rm $D', "D=/etc/* && cat $D", "V=&& echo $V", 'V="a\tb" && echo $V', 'V="a\nb" && echo $V', "V=a?b && echo $V", "V=a[b && echo $V"]) {
			expect(reasonOf(command), command).toBe("variable-expansion")
		}
	})

	it("substitutes the same unsafe value inside double quotes, where nothing splits", () => {
		expect(argvs('D="-rf /" && rm "$D"')).toEqual([["rm", "-rf /"]])
		expect(argvs("D=/etc/* && cat \"$D\"")).toEqual([["cat", "/etc/*"]])
		expect(argvs('V="a b" && echo "$V"')).toEqual([["echo", "a b"]])
	})

	it("treats an empty value as unsafe bare and harmless quoted", () => {
		expect(reasonOf('V="" && $V eval x')).toBe("variable-expansion")
		expect(argvs('V="" && echo "$V"')).toEqual([["echo", ""]])
	})

	it("substitutes a literal whatever the position, and keeps the command non-opaque", () => {
		const command = commandsOf('D=/etc/hosts && cat "$D"')[0]
		expect(command.opaque).toBe(false)
	})
})

// --------------------------------------------------------------------------- §5.1 command-local prefixes

describe("command-local assignment prefixes (§5.1)", () => {
	it("reports the prefix in source order and resolves its value", () => {
		const command = commandsOf("NODE_ENV=test npm run build")[0]
		expect(command.argv).toEqual(["npm", "run", "build"])
		expect(command.envVars).toEqual([{ name: "NODE_ENV", value: "test" }])
		expect(commandsOf("A=1 B=2 cmd")[0].envVars).toEqual([{ name: "A", value: "1" }, { name: "B", value: "2" }])
	})

	it("keeps the prefix invisible to every later command", () => {
		// bash gives the second command an empty A, so the walker has no value to substitute.
		expect(reasonOf('A=x true && echo "$A"')).toBe("variable-expansion")
		expect(reasonOf('FOO=bar echo hi; echo "$FOO"')).toBe("variable-expansion")
	})

	it("does not report the prefix on the command after it", () => {
		expect(commandsOf("A=x true && false")[1].envVars).toEqual([])
	})
})

// --------------------------------------------------------------------------- §5.5, §6.1 unknown values

describe("unknown values and placeholders (§5.5, §6.1)", () => {
	it("remembers a value built at run time as unknown and reports it quoted-only", () => {
		const parsed = commandsOf('A=$(id) && echo "$A/x"')
		expect(parsed.map((one) => one.argv)).toEqual([["id"], ["echo", "__TRACKED_VAR__/x"]])
		expect(parsed[1].opaque).toBe(true)
		expect(parsed[0].opaque).toBe(false)
	})

	it("refuses that same unknown value bare", () => {
		expect(reasonOf("A=$(echo /tmp) && cat $D".replace("$D", "$A"))).toBe("variable-expansion")
	})

	it("propagates unknownness through an append", () => {
		const parsed = commandsOf('A=$HOME\nA+=2 && echo "$A/x"')
		expect(parsed.map((one) => one.argv)).toEqual([["echo", "__TRACKED_VAR__/x"]])
		expect(parsed[0].opaque).toBe(true)
	})
})

// --------------------------------------------------------------------------- §5.6 append

describe("append (§5.6)", () => {
	it("concatenates two literals and never reports `+=` as an argument", () => {
		expect(argvs('A=1\nA+=2 && echo "$A"')).toEqual([["echo", "12"]])
	})

	it("keeps one environment entry per assignment as written", () => {
		expect(commandsOf("LOG=/var/log/app LOG+=.bak cmd")[0].envVars).toEqual([{ name: "LOG", value: "/var/log/app" }, { name: "LOG", value: ".bak" }])
	})

	it("forgets the concatenation when either side is not a literal", () => {
		// Both statements are remembered; the reference that follows can only be a placeholder.
		const parsed = commandsOf("A=$HOME\nA+=x")
		expect(parsed.map((one) => [one.envVars, one.opaque])).toEqual([
			[[{ name: "A", value: "__TRACKED_VAR__" }], true],
			[[{ name: "A", value: "x" }], false],
		])
		expect(argvs('A=$HOME\nA+=2 && echo "v $A"')).toEqual([["echo", "v __TRACKED_VAR__"]])
	})
})

// --------------------------------------------------------------------------- §5.7 assignments that change the shell

describe("assignments that change how the shell reads (§5.7)", () => {
	it("refuses any assignment to IFS, prefix or statement", () => {
		expect(reasonOf("IFS=: && rm a:b")).toBe("ifs-assignment")
		expect(reasonOf("IFS=x cmd")).toBe("ifs-assignment")
		expect(reasonOf("export IFS=:")).toBe("ifs-assignment")
	})

	it("allows a plain trace prompt and refuses one that is not punctuation", () => {
		expect(commandsOf("PS4='+x: ' set -x")[0].envVars).toEqual([{ name: "PS4", value: "+x: " }])
		expect(reasonOf("PS4='$(id)' && set -x")).toBe("prompt-variable-assignment")
		expect(reasonOf("PS4=+ PS4='(id)' set -x")).toBe("prompt-variable-assignment")
		expect(reasonOf("PS4=+x PS4+='y' cmd")).toBe("prompt-variable-assignment")
	})

	it("allows a ${NAME} reference inside the trace prompt", () => {
		expect(commandsOf("PS4='+${LINENO}: ' cmd")[0].envVars).toEqual([{ name: "PS4", value: "+${LINENO}: " }])
	})

	it("refuses a tilde in an assignment value, quoted or not", () => {
		expect(reasonOf("X=~/dir ls")).toBe("tilde-in-assignment")
		expect(reasonOf("X='~/dir' ls")).toBe("tilde-in-assignment")
		expect(reasonOf("X=a~b cmd")).toBe("tilde-in-assignment")
		// … and keeps one that is not an assignment at all (§4).
		expect(argvs("echo ~/x")).toEqual([["echo", "~/x"]])
	})
})

// --------------------------------------------------------------------------- §5.8 names

describe("an invalid name is not an assignment (§5.8)", () => {
	it("reports `1VAR=value` as the command word bash runs", () => {
		const command = commandsOf("1VAR=value")[0]
		expect(command.argv).toEqual(["1VAR=value"])
		expect(command.envVars).toEqual([])
		expect(command.text).toBe("1VAR=value")
	})

	it("treats it as a command in a list too", () => {
		expect(argvs("1VAR=value && true")).toEqual([["1VAR=value"], ["true"]])
	})
})

// --------------------------------------------------------------------------- §5.9 declaring flags

describe("declaring flags and subscripts (§5.9)", () => {
	it("refuses a nameref", () => {
		expect(reasonOf("declare -n X=Y")).toBe("nameref-assignment")
		expect(reasonOf("local -n x=y")).toBe("nameref-assignment")
		expect(reasonOf("typeset -nr q")).toBe("nameref-assignment")
	})

	it("refuses -i and -a, whose right-hand side the shell computes", () => {
		expect(reasonOf("declare -i N=1")).toBe("subscript-evaluation")
		expect(reasonOf("typeset -a A")).toBe("subscript-evaluation")
		expect(reasonOf("local -i n")).toBe("subscript-evaluation")
	})

	it("refuses a subscripted name, however it is quoted", () => {
		expect(reasonOf("declare x[1]=v")).toBe("subscript-evaluation")
		expect(reasonOf('declare \'x[$(id)]=v\'')).toBe("subscript-evaluation")
	})

	it("keeps the flags that do not change what an assignment means", () => {
		expect(argvs("declare -r X=1")).toEqual([["declare", "-r", "X=1"]])
		expect(argvs("declare -A map")).toEqual([["declare", "-A", "map"]])
		expect(argvs("readonly -a A")).toEqual([["readonly", "-a", "A"]])
	})
})

// --------------------------------------------------------------------------- §5.10 inert names

describe("inert names (§5.10)", () => {
	it("reports one inside double quotes as a placeholder and marks the command opaque", () => {
		expect(argvs('cat "$HOME/x"')).toEqual([["cat", "__TRACKED_VAR__/x"]])
		expect(commandsOf('cat "$HOME/x"')[0].opaque).toBe(true)
		expect(argvs('echo "sep $IFS"')).toEqual([["echo", "sep __TRACKED_VAR__"]])
		for (const name of ["HOME", "PWD", "USER", "PATH", "TMPDIR", "IFS", "SHLVL", "HISTFILE"]) {
			expect(argvs(`echo "v $${name}"`), name).toEqual([["echo", "v __TRACKED_VAR__"]])
		}
	})

	it("refuses the same name bare, whole or embedded", () => {
		expect(reasonOf("cd $HOME && ls")).toBe("variable-expansion")
		expect(reasonOf("echo $HOME/x")).toBe("variable-expansion")
	})

	it("refuses every brace spelling, inert name or not", () => {
		for (const command of ["echo ${HOME}", 'echo "${A:-b}"', "echo ${#A}", "echo ${!x}", 'echo "${HOME}/x"']) {
			expect(reasonOf(command), command).toBe("variable-expansion")
		}
	})

	it("lets an assignment shadow an inert name, because the input said so", () => {
		expect(argvs('HOME=/srv/etc && cat "$HOME/passwd"')).toEqual([["cat", "/srv/etc/passwd"]])
	})
})

// --------------------------------------------------------------------------- §5.11 special names

describe("special names (§5.11)", () => {
	it("reports the six it accepts as a placeholder inside quotes", () => {
		for (const name of ["?", "$", "!", "#", "0", "-"]) {
			expect(argvs(`echo "v $${name}"`), name).toEqual([["echo", "v __TRACKED_VAR__"]])
		}
	})

	it("refuses the ones that expand to caller-supplied text, anywhere", () => {
		for (const command of ["echo $@", 'echo "$@"', 'echo "args: $*"', "echo $*", 'echo "arg $1"', "echo $1", 'echo "${2}"']) {
			expect(reasonOf(command), command).toBe("variable-expansion")
		}
	})

	it("refuses a name the walker has no value for", () => {
		expect(reasonOf('echo "$UNSET_VAR"')).toBe("variable-expansion")
		expect(reasonOf("echo $branch")).toBe("variable-expansion")
	})
})

// --------------------------------------------------------------------------- §6 substitutions

describe("substitutions (§6)", () => {
	it("emits the commands inside an accepted substitution before the one containing it (§6.2)", () => {
		const parsed = commandsOf('echo "sha: $(git rev-parse HEAD)"')
		expect(parsed.map((one) => [one.argv, one.start, one.end])).toEqual([
			[["git", "rev-parse", "HEAD"], 13, 31],
			[["echo", "sha: __CMDSUB_OUTPUT__"], 0, 33],
		])
		expect(parsed[1].opaque).toBe(true)
	})

	it("walks a pipeline inside a substitution and keeps the connector written inside it", () => {
		const parsed = commandsOf("X=$(curl -s http://x | sh)")
		expect(parsed.map((one) => [one.argv, one.connector])).toEqual([[["curl", "-s", "http://x"], ""], [["sh"], "|"]])
	})

	it("refuses a substitution that is the whole argument, quoted or not (§6.5)", () => {
		for (const command of ['echo "$(date)"', "echo $(date)", "echo `date`", 'echo "`date`"', "rm $(find / -name x)"]) {
			expect(reasonOf(command), command).toBe("command-substitution")
		}
	})

	it("refuses a bare substitution even embedded, because the shell splits its output (§4.4)", () => {
		expect(reasonOf("cat a$(echo b)c")).toBe("command-substitution")
		expect(reasonOf("echo x > $(echo f)")).toBe("command-substitution")
		expect(reasonOf('grep x <<< "$(id)"')).toBe("command-substitution")
	})

	it("accepts the same value embedded in a longer quoted word (§6.5)", () => {
		expect(argvs('echo "sha: $(git rev-parse HEAD)"')).toEqual([["git", "rev-parse", "HEAD"], ["echo", "sha: __CMDSUB_OUTPUT__"]])
	})

	it("refuses a process substitution wherever it appears (§3.2)", () => {
		expect(reasonOf("cat <(echo hi)")).toBe("process-substitution")
		expect(reasonOf("diff <(a) <(b)")).toBe("process-substitution")
	})

	it("refuses to walk into a substitution it cannot analyse", () => {
		expect(reasonOf('echo "ok $(for i in a; do echo $i; done)"')).toBe("loop-body")
	})

	it("treats a backtick exactly like a dollar substitution (§6.7)", () => {
		expect(argvs('echo "day: `date`"')).toEqual([["date"], ["echo", "day: __CMDSUB_OUTPUT__"]])
		expect(reasonOf('echo "`date`"')).toBe("command-substitution")
	})
})

// --------------------------------------------------------------------------- §6.6 the cat-heredoc carve-out

describe("a quoted cat here-document is the one known substitution (§6.6)", () => {
	it("uses a single-line body as the argument's value", () => {
		expect(argvs("echo \"$(cat <<'EOF'\n/etc/hosts\nEOF)\"")).toEqual([["echo", "/etc/hosts"]])
		expect(commandsOf("echo \"$(cat <<'EOF'\n/etc/hosts\nEOF)\"")[0].opaque).toBe(false)
	})

	it("reports a multi-line body whole, as cat would print it", () => {
		expect(argvs("echo \"$(cat <<'EOF'\nfirst\nsecond\nEOF)\"")).toEqual([["echo", "first\nsecond"]])
		expect(argvs("bash -c \"$(cat <<'X'\nrm -rf /\necho done\nX\n)\"")).toEqual([["bash", "-c", "rm -rf /\necho done"]])
		expect(argvs("cat \"$(cat <<-'E'\n\t\tone\n\ttwo\n\tE\n)\"")).toEqual([["cat", "one\ntwo"]])
		expect(commandsOf("echo \"$(cat <<'EOF'\nfirst\nsecond\nEOF)\"")[0].opaque).toBe(false)
	})

	it("refuses an unquoted delimiter, which the shell expands", () => {
		expect(reasonOf("echo \"$(cat <<EOF\n{x}\nEOF)\"")).toBe("heredoc-unquoted-delimiter")
	})

	it("refuses any deviation from a bare cat", () => {
		expect(reasonOf("echo \"$(cat -n <<'EOF'\nx\nEOF)\"")).toBe("command-substitution")
		expect(reasonOf("echo \"$(head <<'EOF'\nx\nEOF)\"")).toBe("command-substitution")
	})

	it("still resolves the value in an assignment prefix", () => {
		expect(commandsOf("F=$(cat <<'EOF'\n/etc/hosts\nEOF) cmd")[0].envVars).toEqual([{ name: "F", value: "/etc/hosts" }])
	})
})

// --------------------------------------------------------------------------- §4.3 arithmetic

describe("arithmetic (§4.3)", () => {
	it("reports a literal expression exactly as it was written", () => {
		expect(argvs("echo $((60 * 5))")).toEqual([["echo", "$((60 * 5))"]])
		expect(argvs("echo $((16#ff))")).toEqual([["echo", "$((16#ff))"]])
		expect(argvs("echo $((0x1f + 1))")).toEqual([["echo", "$((0x1f + 1))"]])
		expect(argvs("echo $(( 1 + 2 * 3 ))")).toEqual([["echo", "$(( 1 + 2 * 3 ))"]])
	})

	it("refuses anything that names a value or runs something", () => {
		expect(reasonOf("echo $((n + 1))")).toBe("arithmetic-non-literal")
		expect(reasonOf("echo $((1 + $x))")).toBe("arithmetic-non-literal")
		expect(reasonOf("echo $(( $(id) ))")).toBe("arithmetic-non-literal")
		expect(reasonOf("echo 10#$(id)")).toBe("arithmetic-non-literal")
	})

	it("does not mark a literal arithmetic argument opaque", () => {
		expect(commandsOf("echo $((60 * 5))")[0].opaque).toBe(false)
	})
})

// --------------------------------------------------------------------------- §3.1 / §5.6 builtins

describe("declaration and unset statements (§3.1, §5.6)", () => {
	it("reports the builtin as argv[0] with its items after it", () => {
		expect(argvs("export FOO=bar")).toEqual([["export", "FOO=bar"]])
		expect(argvs('export "FOO=bar"')).toEqual([["export", "FOO=bar"]])
		expect(argvs("export PATH")).toEqual([["export", "PATH"]])
		expect(argvs("readonly Y=2")).toEqual([["readonly", "Y=2"]])
		expect(argvs("local x=1")).toEqual([["local", "x=1"]])
		expect(argvs("unset FOO BAR")).toEqual([["unset", "FOO", "BAR"]])
		expect(argvs("unset -f ls")).toEqual([["unset", "-f", "ls"]])
	})

	it("keeps the span and the text of the statement it emits", () => {
		const command = commandsOf('export "FOO=bar"')[0]
		expect(command.text).toBe('export "FOO=bar"')
		expect([command.start, command.end]).toEqual([0, 16])
		expect(command.connector).toBe("")
	})

	it("reports a value built by a substitution in a declaration as a placeholder", () => {
		const parsed = commandsOf("export FOO=$(echo hi)")
		expect(parsed.map((one) => one.argv)).toEqual([["echo", "hi"], ["export", "FOO=__CMDSUB_OUTPUT__"]])
		expect(parsed[1].opaque).toBe(true)
	})
})

// --------------------------------------------------------------------------- §5.2 / §14.1 what a statement assignment emits

describe("a statement-level assignment (§5.2, §14.1)", () => {
	it("emits no command when the input contains another one", () => {
		expect(commandsOf("D=/tmp/build && rm -rf /tmp/build").map((one) => one.argv)).toEqual([["rm", "-rf", "/tmp/build"]])
	})

	it("is the whole answer when nothing else in the input emits a command", () => {
		const parsed = commandsOf("D=/tmp/build")
		expect(parsed).toHaveLength(1)
		expect(parsed[0].argv).toEqual([])
		expect(parsed[0].envVars).toEqual([{ name: "D", value: "/tmp/build" }])
		expect(parsed[0].text).toBe("D=/tmp/build")
	})

	it("reports each assignment when the input is nothing but assignments, with its connector", () => {
		const parsed = commandsOf("A=1\nB=2")
		expect(parsed.map((one) => [one.envVars, one.connector])).toEqual([[ [{ name: "A", value: "1" }], ""], [[{ name: "B", value: "2" }], "\n"]])
	})

	it("still reports nothing for a comment", () => {
		expect(commandsOf("# nothing here")).toEqual([])
	})
})

// --------------------------------------------------------------------------- the store itself

/** The first node of `type` in a fresh parse of `source`. */
function findNode(source: string, type: string): Node {
	const parsed = parseBash(source)
	if ("error" in parsed) throw new Error(`${source} did not parse: ${parsed.error}`)
	const stack: Node[] = [parsed.tree.rootNode]
	while (stack.length > 0) {
		const node = stack.shift()!
		if (node.type === type) return node
		stack.push(...node.children)
	}
	throw new Error(`no ${type} in ${source}`)
}

/** A resolver that stands in for §4: the source of the run of nodes, with the position recorded. */
function literalResolver(seen: ValuePosition[]) {
	return (nodes: readonly Node[], position: ValuePosition) => {
		seen.push(position)
		return { ok: true as const, text: nodes.map((one) => one.text).join("") }
	}
}

describe("the value store", () => {
	it("starts empty and holds only what the input said (§14.4)", () => {
		const scope = newValueScope()
		expect(scope.variables.size).toBe(0)
		expect(scope.assignments).toEqual([])
	})

	it("remembers a literal, then the concatenation of an append", () => {
		const scope = newValueScope()
		const seen: ValuePosition[] = []
		expect(rememberAssignment(scope, findNode("A=1", "variable_assignment"), literalResolver(seen))).toBeNull()
		expect(scope.variables.get("A")).toEqual({ literal: "1" })
		expect(rememberAssignment(scope, findNode("A+=two", "variable_assignment"), literalResolver(seen))).toBeNull()
		expect(scope.variables.get("A")).toEqual({ literal: "1two" })
		expect(scope.assignments.map((one) => [one.name, one.value])).toEqual([["A", "1"], ["A", "two"]])
	})

	it("remembers a value it cannot resolve as unknown", () => {
		const scope = newValueScope()
		const seen: ValuePosition[] = []
		const unknown = (nodes: readonly Node[], position: ValuePosition) => {
			seen.push(position)
			return { ok: true as const, text: "__TRACKED_VAR__" }
		}
		expect(rememberAssignment(scope, findNode("A=$HOME", "variable_assignment"), unknown)).toBeNull()
		expect(scope.variables.get("A")).toEqual({ unknown: true })
		// An append onto an unknown base stays unknown (§5.6).
		expect(rememberAssignment(scope, findNode("A+=x", "variable_assignment"), literalResolver(seen))).toBeNull()
		expect(scope.variables.get("A")).toEqual({ unknown: true })
		expect(seen.length).toBe(2)
	})

	it("refuses an assignment whose name bash would not accept (§5.8)", () => {
		const scope = newValueScope()
		const answer = rememberAssignment(scope, findNode("1VAR=x", "variable_assignment"), literalResolver([]))
		expect(answer).toEqual(refuse("assignment-name-invalid", "variable_assignment"))
	})

	it("answers an unknown name with a refusal, never with a guess", () => {
		const scope = newValueScope()
		const answer = resolveValue(scope, { node: findNode('echo "$MAYBE"', "simple_expansion"), position: "argument", prefix: "", whole: true, quoted: true }, () => null)
		expect(answer).toEqual({ ok: false, refusal: refuse("variable-expansion", "simple_expansion") })
	})
})
