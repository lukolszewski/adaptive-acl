/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { beforeAll, describe, expect, it } from "vitest"
import type { AstCommand, AstRedirect } from "./bash-ast.ts"
import { initBashParser } from "./bash-parser.ts"
import { compareCase, loadGolden, selectById } from "./bash-walker-golden.ts"
import { walkBash, type Reason } from "./bash-walker.ts"
import { checkMeaning, outputFlagWrites } from "./bash-walker-meaning.ts"
import { TRACKED_VAR_PLACEHOLDER } from "./bash-walker.ts"

/**
 * Tests for §11 of docs/LAYER0-WALKER-SPEC.md — the refusals decided from the resolved arguments.
 *
 * Two layers, and the second is the real proof of the table: the golden cases prove the walker
 * reaches these checks with the right argv, and the hand-built commands prove each rule fires on
 * the value the spec describes without waiting for parts 2 and 3 to resolve an input.
 */

/** `sem-` is this part's subset; the rest were deferred here by part 1 (labelled `T10c`). */
const SUBSET = ["sem-", "test-verbose-subscript", "test-arith-cmp-subscript", "red-proc-environ", "red-in-proc-environ", "red-escaped-proc", "rej-keyword-name"]

/**
 * Corpus cases this part cannot run yet. Empty since the values module landed: `nice $((0-5)) eval x`
 * (§4.3 keeps the arithmetic as written) now reaches step 9 with an argv for the wrapper rule to read.
 */
export const DEFERRED: Record<string, "T11"> = {}

const CASES = selectById(loadGolden(), SUBSET)
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

describe("the subset", () => {
	it("is the size the task describes", () => {
		expect(CASES.length).toBe(53)
		expect(CASES.filter((one) => one.id.startsWith("sem-")).length).toBe(47)
	})
})

// ---------------------------------------------------------------------------
// the table itself: hand-built commands, so no earlier step can stand in the way
// ---------------------------------------------------------------------------

const REDIRECT = (op: string, target: string, fdDup = false): AstRedirect => ({ op, target, fdDup })

/** A finished command, as `bash-walker.ts` would hand it over after §13 and §6.3. */
const cmd = (argv: string[], extra: Partial<AstCommand> = {}): AstCommand => ({
	argv,
	envVars: [],
	redirects: [],
	heredocs: [],
	text: argv.join(" "),
	start: 0,
	end: argv.join(" ").length,
	connector: "",
	opaque: false,
	...extra,
})

/** The §11 verdict for a hand-built command list: a §12 id, or null when nothing is refused. `string` because `Refusal.reason` is declared `string` in bash-ast.ts, not as the `Reason` union. */
const meaning = (...commands: AstCommand[]): string | null => checkMeaning(commands)?.reason ?? null
const clean = (...commands: AstCommand[]): void => expect(meaning(...commands)).toBeNull()
const refusedWith = (reason: Reason, ...commands: AstCommand[]): void => expect(meaning(...commands)).toBe(reason)

/**
 * The golden cases the walker accepts, as (id, resolved commands) pairs.
 *
 * `GoldenCase["expect"]` is the whole `AstParse` union, so a `filter(c => c.expect.kind === "simple")`
 * does not carry the `commands` member into a later callback. Narrowing inside one expression does,
 * which is why the corpus is flattened here instead of at each call site.
 */
const acceptedGoldenCases = (): Array<{ id: string; commands: AstCommand[] }> =>
	loadGolden().flatMap((one) => (one.expect.kind === "simple" ? [{ id: one.id, commands: one.expect.commands }] : []))

describe("evaluates-arguments-as-code", () => {
	it("refuses every verb whose arguments the shell runs (§11)", () => {
		for (const verb of ["eval", "source", ".", "exec", "builtin", "trap", "enable", "hash", "bind", "complete", "alias", "let", "coproc", "noglob", "nocorrect"]) {
			expect(meaning(cmd([verb, "anything"])), verb).toBe("evaluates-arguments-as-code")
			// The name alone runs too: `fc`-style defaults are the other table's business.
			expect(meaning(cmd([verb])), verb).toBe("evaluates-arguments-as-code")
		}
	})

	it("accepts `command` and `fc` only in their reporting spellings (§11)", () => {
		// Every letter of a cluster has to be a reporting option: `-vV` reports, `-v x` does not.
		clean(cmd(["command", "-v", "ls"]), cmd(["command", "-V", "ls"]), cmd(["command", "-vV", "ls"]), cmd(["command", "-v"]), cmd(["fc", "-l"]), cmd(["fc", "-ln"]), cmd(["fc", "-rl"]))
		refusedWith("evaluates-arguments-as-code", cmd(["command", "ls"]))
		refusedWith("evaluates-arguments-as-code", cmd(["command"]))
		refusedWith("evaluates-arguments-as-code", cmd(["command", "-p", "ls"]))
		refusedWith("evaluates-arguments-as-code", cmd(["command", "-qx", "ls"]))
		refusedWith("evaluates-arguments-as-code", cmd(["fc", "-e", "vi"]))
		refusedWith("evaluates-arguments-as-code", cmd(["fc", "-s"]))
		refusedWith("evaluates-arguments-as-code", cmd(["fc"]))
		refusedWith("evaluates-arguments-as-code", cmd(["fc", "-l", "-10"]))
	})

	it("refuses the callback and generator options, and nothing else (§11)", () => {
		clean(cmd(["mapfile", "arr"]), cmd(["mapfile", "-t", "arr"]), cmd(["readarray", "-c", "1", "arr"]), cmd(["compgen", "-c"]), cmd(["compgen", "-a", "builtin"]))
		refusedWith("evaluates-arguments-as-code", cmd(["mapfile", "-C", "cb", "-c", "1", "arr"]))
		refusedWith("evaluates-arguments-as-code", cmd(["mapfile", "-Ccb", "arr"]))
		refusedWith("evaluates-arguments-as-code", cmd(["readarray", "-C", "cb"]))
		refusedWith("evaluates-arguments-as-code", cmd(["compgen", "-C", "id"]))
		refusedWith("evaluates-arguments-as-code", cmd(["compgen", "-F", "gen"]))
	})

	it("leaves a program that merely shares a letter with a verb alone", () => {
		clean(cmd(["sort", "-k", "2"]), cmd(["git", "commit", "-m", "eval this"]), cmd(["grep", "-rn", "eval", "src"]), cmd(["echo", "."]), cmd(["ls", "."]))
	})
})

describe("zsh-module-builtin", () => {
	it("refuses the module internals and the zf_ family (§11)", () => {
		for (const verb of ["zmodload", "emulate", "sysopen", "sysread", "syswrite", "sysseek", "zpty", "ztcp", "zsocket"]) {
			expect(meaning(cmd([verb, "zsh/system"])), verb).toBe("zsh-module-builtin")
		}
		refusedWith("zsh-module-builtin", cmd(["zf_rm", "/tmp/x"]))
		refusedWith("zsh-module-builtin", cmd(["zf_ln", "-s", "a", "b"]))
	})

	it("does not treat a program merely named like one", () => {
		clean(cmd(["zf", "x"]), cmd(["zmodload-not", "x"]), cmd(["sysreads", "x"]), cmd(["emulators", "x"]))
	})
})

describe("wrapper-not-analysable and peeling", () => {
	it("peels a wrapper whose form is known so the wrapped command is judged (§11.2)", () => {
		clean(cmd(["timeout", "5", "ls"]), cmd(["env", "FOO=1", "ls"]), cmd(["env", "-i", "ls"]), cmd(["env", "-u", "FOO", "ls"]), cmd(["env", "-uFOO", "ls"]), cmd(["nice", "-n", "5", "ls"]), cmd(["nice", "-5", "ls"]), cmd(["nice", "ls"]), cmd(["stdbuf", "-o0", "ls"]), cmd(["stdbuf", "--output=0", "ls"]), cmd(["nohup", "ls"]), cmd(["time", "-p", "ls"]))
		refusedWith("evaluates-arguments-as-code", cmd(["nohup", "eval", "rm -rf /tmp/z"]))
		refusedWith("evaluates-arguments-as-code", cmd(["time", "eval", "x"]))
		refusedWith("evaluates-arguments-as-code", cmd(["env", "FOO=1", "nice", "-n", "5", "timeout", "5", "exec", "sh"]))
	})

	it("refuses a wrapper it cannot read past, instead of judging the wrapper", () => {
		refusedWith("wrapper-not-analysable", cmd(["timeout", "-X", "5", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["timeout", "-k", "5", "10", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["timeout", "5s", "-k", "5", "eval", "x"]))
		refusedWith("wrapper-not-analysable", cmd(["timeout", ".5", "eval", "id"]))
		refusedWith("wrapper-not-analysable", cmd(["timeout", "eval", "x"]))
		refusedWith("wrapper-not-analysable", cmd(["env", "-S", "rm -rf x"]))
		refusedWith("wrapper-not-analysable", cmd(["env", "-C", "/tmp", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["env", "-P", "/bin", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["env", "--split-string", "rm x"]))
		refusedWith("wrapper-not-analysable", cmd(["stdbuf", "--output", "0", "eval", "x"]))
		refusedWith("wrapper-not-analysable", cmd(["stdbuf", "-o", "0", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["stdbuf", "--redirect", "0", "ls"]))
		refusedWith("wrapper-not-analysable", cmd(["nice", "$((0-5))", "eval", "x"]))
		refusedWith("wrapper-not-analysable", cmd(["nice", "__TRACKED_VAR__", "eval", "x"]))
		refusedWith("wrapper-not-analysable", cmd(["nohup", "-x", "ls"]))
	})

	it("reads `--` as the end of the wrapper's own options", () => {
		clean(cmd(["timeout", "--", "5", "ls"]), cmd(["env", "--", "ls"]), cmd(["nice", "--", "ls"]))
		refusedWith("evaluates-arguments-as-code", cmd(["nohup", "--", "eval", "x"]))
		refusedWith("evaluates-arguments-as-code", cmd(["timeout", "--", "5", "eval", "x"]))
	})

	it("has no wrapped command to judge when the wrapper stands alone", () => {
		clean(cmd(["env"]), cmd(["nice"]), cmd(["nohup"]), cmd(["timeout", "5"]))
	})

	it("leaves privilege wrappers and xargs for the caller (§11.1)", () => {
		clean(cmd(["sudo", "systemctl", "restart", "nginx"]), cmd(["sudo", "eval", "ls"]), cmd(["doas", "eval", "ls"]), cmd(["xargs", "rm"]), cmd(["xargs", "-I{}", "eval", "{}"]))
	})

	it("never peels in the reported arguments (§11.2)", () => {
		// The peel is a view for these checks only: a wrapper's own arguments stay in argv, so a
		// value-level rule still sees them.
		refusedWith("hidden-comment-in-argument", cmd(["env", "FOO=1\n#x", "ls"]))
		refusedWith("proc-environ-read", cmd(["nohup", "cat", "/proc/self/environ"]))
	})
})

describe("subscript-evaluation", () => {
	it("refuses a subscripted name given to a builtin that computes it (§11)", () => {
		refusedWith("subscript-evaluation", cmd(["[[", "-v", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["test", "-v", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["[[", "-R", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["printf", "-v", "a[$(id)]", "x"]))
		refusedWith("subscript-evaluation", cmd(["printf", "-va[$(id)]", "x"]))
		refusedWith("subscript-evaluation", cmd(["read", "-a", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["read", "-A", "a[`id`]"]))
		refusedWith("subscript-evaluation", cmd(["read", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["unset", "-v", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["unset", "a[$(id)]"]))
		refusedWith("subscript-evaluation", cmd(["wait", "-p", "a[$(id)]", "%1"]))
	})

	it("accepts a plain name, and an operand that is data rather than a name (§11)", () => {
		clean(cmd(["[[", "-v", "ready"]), cmd(["test", "-v", "ready"]), cmd(["printf", "-v", "out", "%s", "x"]), cmd(["read", "-p", "[dir] ", "v"]), cmd(["read", "-r", "a", "b"]), cmd(["read", "-a", "arr"]), cmd(["unset", "-v", "FOO"]), cmd(["unset", "FOO"]), cmd(["wait", "%1"]), cmd(["read", "--", "v"]))
	})

	it("refuses an operand of a bracketed arithmetic comparison (§9.5)", () => {
		refusedWith("subscript-evaluation", cmd(["[[", "cfg[$(whoami)]", "-eq", "1"]))
		refusedWith("subscript-evaluation", cmd(["[[", "1", "-eq", "cfg[$(whoami)]"]))
		refusedWith("subscript-evaluation", cmd(["test", "a[i]", "-lt", "2"]))
		refusedWith("subscript-evaluation", cmd(["[[", "1", "-gt", "a[i]"]))
	})

	it("leaves a plain comparison and a pattern operand alone (§9.3)", () => {
		clean(cmd(["[[", "1", "-eq", "1"]), cmd(["[[", "count", "-ne", "0"]), cmd(["[[", "name", "==", "a[0]*"]), cmd(["[[", "-f", "src/a.ts"]))
	})

	it("refuses a subscripted name in a declaration item (§5.9)", () => {
		refusedWith("subscript-evaluation", cmd(["declare", "a[$(id)]=1"]))
		refusedWith("subscript-evaluation", cmd(["local", "-r", "a[i]=1"]))
		// An associative key is still a subscript the shell computes before anything is stored.
		refusedWith("subscript-evaluation", cmd(["declare", "-A", "map[key]=1"]))
	})
})

describe("nameref-assignment", () => {
	it("refuses the declaring flags that change what an assignment means (§5.9)", () => {
		for (const verb of ["declare", "typeset", "local"]) {
			expect(meaning(cmd([verb, "-n", "ref=target"])), verb).toBe("nameref-assignment")
			expect(meaning(cmd([verb, "-i", "n=1"])), verb).toBe("subscript-evaluation")
			expect(meaning(cmd([verb, "-a", "arr"])), verb).toBe("subscript-evaluation")
			expect(meaning(cmd([verb, "-xn", "ref=y"])), verb).toBe("nameref-assignment")
		}
	})

	it("accepts a declaration whose flags do not change the value", () => {
		clean(cmd(["declare", "FOO=1"]), cmd(["declare", "-r", "FOO=1"]), cmd(["declare", "-x", "PATH=/bin"]), cmd(["local", "--", "FOO=1"]), cmd(["typeset", "-x", "FOO"]), cmd(["declare", "-A", "map"]))
	})

	it("leaves `export -n`, which removes an attribute rather than naming a reference", () => {
		clean(cmd(["export", "-n", "FOO"]), cmd(["readonly", "-a", "x"]), cmd(["export", "FOO=1"]))
	})
})

describe("proc-environ-read", () => {
	it("refuses an argument that names another process's environment (§11)", () => {
		refusedWith("proc-environ-read", cmd(["cat", "/proc/self/environ"]))
		refusedWith("proc-environ-read", cmd(["cat", "/proc/1/environ"]))
		refusedWith("proc-environ-read", cmd(["cp", "/proc/1234/environ", "/tmp/x"]))
	})

	it("resolves path segments the way the kernel will (§11)", () => {
		refusedWith("proc-environ-read", cmd(["cat", "/proc/self/./environ"]))
		refusedWith("proc-environ-read", cmd(["cat", "//proc//self//environ"]))
		refusedWith("proc-environ-read", cmd(["cat", "/proc/self/x/../environ"]))
		refusedWith("proc-environ-read", cmd(["cat", "/proc/1/foo/../../self/environ"]))
		refusedWith("proc-environ-read", cmd(["cat", "/proc/self/environ/"]))
	})

	it("refuses a redirect target too, in either direction (§11)", () => {
		refusedWith("proc-environ-read", cmd(["echo", "x"], { redirects: [REDIRECT(">", "/proc/self/environ")] }))
		refusedWith("proc-environ-read", cmd(["cat"], { redirects: [REDIRECT("<", "/proc/1/environ")] }))
		refusedWith("proc-environ-read", cmd(["cat"], { redirects: [REDIRECT("&>>", "/proc/1/environ")] }))
	})

	it("does not see an environment file in every path that mentions proc", () => {
		clean(
			cmd(["cat", "proc/self/environ"]),
			cmd(["cat", "/proc/environ"]),
			cmd(["cat", "/proc/self/status"]),
			cmd(["cat", "/proc/self/environ/1"]),
			cmd(["cat", "/var/proc/1/environ"]),
			cmd(["cat", "/tmp/myproc/environ"]),
			cmd(["grep", "environ", "/proc/self/status"]),
			cmd(["echo", "/proc"]),
		)
		clean(cmd(["echo", "x"], { redirects: [REDIRECT(">&", "1", true), REDIRECT(">", "/tmp/out.txt")] }))
	})
})

describe("jq-system-call and jq-file-flag", () => {
	it("refuses a filter that runs commands (§11)", () => {
		refusedWith("jq-system-call", cmd(["jq", 'system("id")', "f.json"]))
		refusedWith("jq-system-call", cmd(["jq", "map(system( . ))"]))
		refusedWith("jq-system-call", cmd(["jq", "-n", '"x" | system("id")']))
	})

	it("refuses a filter loaded from disk (§11)", () => {
		for (const flag of ["-f", "-L", "-rf", "-eLf"]) {
			expect(meaning(cmd(["jq", flag, "prog.jq", "f.json"])), flag).toBe("jq-file-flag")
		}
		for (const flag of ["--from-file", "--rawfile", "--slurpfile", "--library-path"]) {
			expect(meaning(cmd(["jq", flag, "x", "f.json"])), flag).toBe("jq-file-flag")
		}
		refusedWith("jq-file-flag", cmd(["jq", "--from-file=prog.jq", "f.json"]))
	})

	it("accepts a filter that only reads its input", () => {
		clean(cmd(["jq", ".stargazers", "f.json"]), cmd(["jq", "-r", ".system", "f.json"]), cmd(["jq", "-e", ".a | .b"]), cmd(["jq", "--arg", "k", "v", ".[$k]"]), cmd(["jq", "--args", ".[0]"]), cmd(["jq", "-c", "-s", ".[]"]), cmd(["jq", "."]))
	})
})

describe("the command word", () => {
	it("refuses an empty first argument (§11)", () => {
		refusedWith("empty-command-name", cmd(["", "ls"]))
		refusedWith("empty-command-name", cmd([""]))
	})

	it("refuses a command name that is only known at run time (§11)", () => {
		refusedWith("command-name-not-a-literal", cmd(["git-__CMDSUB_OUTPUT__", "log"]))
		refusedWith("command-name-not-a-literal", cmd(["__TRACKED_VAR__", "-l"]))
	})

	it("refuses a first argument that is a fragment of a command (§11)", () => {
		refusedWith("incomplete-command-fragment", cmd(["-la"]))
		refusedWith("incomplete-command-fragment", cmd(["|grep", "x"]))
		refusedWith("incomplete-command-fragment", cmd(["&", "bg"]))
		refusedWith("incomplete-command-fragment", cmd(["--flag", "x"]))
	})

	it("refuses a shell reserved word in command position (§11)", () => {
		for (const word of ["for", "do", "done", "if", "then", "else", "elif", "fi", "while", "until", "case", "esac", "select", "function", "in", "!", "{", "}", "]]"]) {
			expect(meaning(cmd([word, "x"])), word).toBe("keyword-as-command-name")
		}
	})

	it("keeps `[[` as the canonical test command (§9.1) and every object method as a program", () => {
		clean(cmd(["[[", "-f", "src/a.ts"]), cmd(["constructor", "x"]), cmd(["toString"]), cmd(["__proto__", "-x"]), cmd(["hasOwnProperty", "y"]))
	})

	it("has nothing to judge for a command with no command word (§3.1)", () => {
		clean(cmd([], { redirects: [REDIRECT(">", "empty.txt")] }))
	})
})

describe("hidden-comment-in-argument", () => {
	it("refuses a newline-and-# inside an argument, an environment value or a target (§11)", () => {
		refusedWith("hidden-comment-in-argument", cmd(["echo", "first\n# second"]))
		refusedWith("hidden-comment-in-argument", cmd(["echo", "first\n   # second"]))
		refusedWith("hidden-comment-in-argument", cmd(["echo", "a\n\t#b"]))
		refusedWith("hidden-comment-in-argument", cmd(["FOO=1"], { envVars: [{ name: "FOO", value: "x\n#y" }] }))
		refusedWith("hidden-comment-in-argument", cmd(["echo", "x"], { redirects: [REDIRECT(">", "f\n# tail")] }))
		refusedWith("hidden-comment-in-argument", cmd(["echo", "x"], { redirects: [REDIRECT("<", "in\n#keep")] }))
	})

	it("accepts a hash that cannot hide anything", () => {
		clean(cmd(["echo", "a # b"]), cmd(["echo", "#!/bin/sh"]), cmd(["echo", "first\nsecond"]), cmd(["grep", "-n", "#", "f"]), cmd(["echo", "\n"]), cmd(["git", "commit", "-m", "fix #12"]))
	})

	it("does not read a here-doc body as a value (§8.3: it is program text, and # is its own language)", () => {
		clean(cmd(["python3", "-"], { heredocs: ["import os\n# a comment\nprint(1)\n"] }))
	})
})

describe("the whole of step 9", () => {
	it("reports the first refusal in command order", () => {
		expect(checkMeaning([cmd(["ls"]), cmd(["eval", "x"]), cmd(["-la"])])).toMatchObject({ reason: "evaluates-arguments-as-code" })
		expect(checkMeaning([cmd(["ls"]), cmd(["cat", "/proc/self/environ"]), cmd(["eval", "x"])])).toMatchObject({ reason: "proc-environ-read" })
	})

	it("never marks a refusal malformed (§11.4)", () => {
		const every = [
			cmd(["eval", "x"]),
			cmd(["zmodload", "zsh/system"]),
			cmd(["timeout", "-X", "5", "ls"]),
			cmd(["printf", "-v", "a[$(id)]", "x"]),
			cmd(["declare", "-n", "r=t"]),
			cmd(["cat", "/proc/self/environ"]),
			cmd(["jq", 'system("id")']),
			cmd(["jq", "-f", "p.jq"]),
			cmd([""]),
			cmd(["git-__CMDSUB_OUTPUT__"]),
			cmd(["-la"]),
			cmd(["for", "i"]),
			cmd(["echo", "a\n#b"]),
		]
		for (const one of every) {
			const refusal = checkMeaning([one])
			expect(refusal, one.argv.join(" ")).not.toBeNull()
			expect(refusal?.malformed, one.argv.join(" ")).toBe(false)
			expect(refusal?.kind).toBe("unproven")
		}
	})

	it("accepts an empty command list (§1.4)", () => {
		expect(checkMeaning([])).toBeNull()
	})

	it("is deterministic and reads nothing but its argument (§14.4)", () => {
		const commands = [cmd(["env", "FOO=1", "timeout", "5", "jq", "-f", "p.jq", "x"]), cmd(["cat", "/proc/self/environ"])]
		expect(checkMeaning(commands)).toEqual(checkMeaning(commands))
	})

	it("trips on no accepted case anywhere in the corpus", () => {
		// Parts 2 and 3 have not merged, so this feeds the corpus's own resolved commands in
		// directly: the false-positive gate for every value those parts will one day produce.
		const tripping = acceptedGoldenCases()
			.map((one) => ({ id: one.id, refusal: checkMeaning(one.commands) }))
			.filter((one) => one.refusal !== null)
		expect(tripping).toEqual([])
	})
})

// ---------------------------------------------------------------------------
// writes named by a flag rather than by a redirect (§2 reporting, `outputFlagWrites`)
// ---------------------------------------------------------------------------

describe("reads a write target out of an output flag", () => {
	const writes = (argv: string[]): string[] => outputFlagWrites(argv).map((one) => one.target)

	it("reports the operand of every flag in the table", () => {
		expect(writes(["sort", "-o", "/etc/x", "in.txt"])).toEqual(["/etc/x"])
		expect(writes(["uniq", "--output=/etc/passwd", "in.txt"])).toEqual(["/etc/passwd"])
		expect(writes(["uniq", "--output", "out.txt", "in.txt"])).toEqual(["out.txt"])
		expect(writes(["patch", "-o", "merged.txt", "in.patch"])).toEqual(["merged.txt"])
		expect(writes(["tee", "-o", "log.txt", "in.txt"])).toEqual(["log.txt"])
		expect(writes(["tee", "--output=log.txt", "in.txt"])).toEqual(["log.txt"])
	})

	it("reads the operand in every spelling the tool accepts", () => {
		expect(writes(["sort", "-oFILE", "in.txt"])).toEqual(["FILE"])
		expect(writes(["sort", "-bo", "out.txt", "in.txt"])).toEqual(["out.txt"]) // a cluster: -b -o
		expect(writes(["sort", "-o", "out.txt", "in.txt"])).toEqual(["out.txt"])
		expect(writes(["git", "diff", "--output=out.diff"])).toEqual(["out.diff"])
		expect(writes(["git", "--no-pager", "diff", "--output", "out.diff"])).toEqual(["out.diff"])
	})

	it("reports every flag the command names, because each is a file the tool may open", () => {
		expect(writes(["sort", "-o", "a.txt", "-o", "b.txt", "in.txt"])).toEqual(["a.txt", "b.txt"])
	})

	it("knows the tool by the last path segment, like every other table in layer 0", () => {
		expect(writes(["/usr/bin/sort", "-o", "out.txt", "in.txt"])).toEqual(["out.txt"])
	})

	it("steps over a wrapper whose form it can read, because the wrapped tool is the one writing", () => {
		expect(writes(["env", "LC_ALL=C", "sort", "-o", "/etc/hosts", "in.txt"])).toEqual(["/etc/hosts"])
		// `sudo` is deliberately not a wrapper this module peels (§11.1), so it reports nothing here.
		expect(writes(["sudo", "sort", "-o", "/etc/hosts", "in.txt"])).toEqual([])
	})

	it("keeps a git rule inside the subcommands that take the flag", () => {
		expect(writes(["git", "diff", "--output=out.diff", "HEAD~1"])).toEqual(["out.diff"])
		expect(writes(["git", "log", "--output=/tmp/log.txt", "-3"])).toEqual(["/tmp/log.txt"])
		expect(writes(["git", "-c", "core.pager=cat", "diff", "--output=out.diff"])).toEqual(["out.diff"])
		expect(writes(["git", "checkout", "--output=out.diff"])).toEqual([])
		expect(writes(["git", "status"])).toEqual([])
	})

	it("names nothing for a tool the table does not claim, however the flag is spelled", () => {
		// `-o` means something else in almost every tool it could be given to.
		expect(writes(["ssh", "-o", "BatchMode=yes", "host"])).toEqual([])
		expect(writes(["grep", "-o", "a", "f"])).toEqual([])
		expect(writes(["sort", "--output", "out.txt"])).toEqual([]) // sort has no long form
		expect(writes(["git", "diff", "--output-directory=out"])).toEqual([]) // a different option
		expect(writes(["cat", "f", "-o", "g"])).toEqual([])
		expect(writes(["echo", "hello"])).toEqual([])
		expect(writes([])).toEqual([])
	})

	it("declines to guess when the operand is not a file name", () => {
		expect(writes(["sort", "-o"])).toEqual([]) // nothing after the flag
		expect(writes(["sort", "-o", "-k1", "f"])).toEqual([]) // what follows is another option
		expect(writes(["sort", "-o", "-", "f"])).toEqual([]) // `-` is the stream it already has
		expect(writes(["sort", "-o", "--", "f"])).toEqual([]) // `--` ends the options
		expect(writes(["sort", "--", "-o", "f"])).toEqual([]) // and a flag after it is a file name
	})

	it("passes a runtime-determined operand through, because `opaque` is what answers it (§6.3)", () => {
		expect(writes(["sort", "-o", `${TRACKED_VAR_PLACEHOLDER}/x`, "f"])).toEqual([`${TRACKED_VAR_PLACEHOLDER}/x`])
	})

	it("changes the meaning of no command in the corpus", () => {
		// The rule is new, so every accepted golden command must report what it reported before it
		// existed. A golden case that writes through a flag is a new case: add its id and target to the
		// list below, and pin the emitted redirect in the walker test.
		const flagWriteCases: Array<{ id: string; target: string }> = []
		const naming = acceptedGoldenCases()
			.flatMap((one) => one.commands.map((c) => ({ id: one.id, target: outputFlagWrites(c.argv)[0]?.target })))
			.filter((one) => one.target !== undefined)
		expect(naming).toEqual(flagWriteCases)
	})
})
