import { beforeAll, describe, expect, it, vi } from "vitest"
import { initBashParser } from "./bash-parser.ts"
import { refuse, walkBash, type Reason, type Refusal } from "./bash-walker.ts"
import { compareCase, loadGolden, selectById, type GoldenCase } from "./bash-walker-golden.ts"

/**
 * Tests for the walker core (docs/LAYER0-WALKER-SPEC.md §2–§4, §7, §9, §13) over its subset of
 * `bash-walker.golden.jsonl`, plus the routing that hands values, heredocs, the text scans and the
 * meaning checks to the part-2 / part-3 modules.
 */

/** The id prefixes this part owns. */
const SUBSET = ["sep-", "sub-", "rej-", "span-", "test-", "word-", "red-"]

/**
 * Cases in the subset another part had to land first. Empty since T10c2 merged (scans §10, heredocs §8,
 * values §5/§6 and the meaning checks §11 are all in); the list stays so a future part can defer again
 * with the count visible.
 */
export const DEFERRED: Record<string, "T10b" | "T10c"> = {}

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

describe("the subset and the deferral list", () => {
	it("every deferred id is a case in the subset", () => {
		const ids = new Set(CASES.map((one) => one.id))
		expect(Object.keys(DEFERRED).filter((id) => !ids.has(id))).toEqual([])
	})

	it("the subset is the size the task describes", () => {
		expect(CASES.length).toBe(98)
	})
})

// ---------------------------------------------------------------------------
// the plug-in points: every stub is reached, and its answer is the walker's answer
// ---------------------------------------------------------------------------

describe("routes values to bash-walker-values.ts", () => {
	const refused = (command: string): Refusal => {
		const parsed = walkBash(command)
		expect(parsed.kind).toBe("unproven")
		return parsed as Refusal
	}

	it("an expansion in an argument", () => {
		expect(refused("echo $HOME")).toMatchObject({ reason: "variable-expansion", nodeType: "simple_expansion" })
	})
	it("a command substitution in an argument", () => {
		expect(refused("echo $(id)")).toMatchObject({ reason: "command-substitution", malformed: false })
	})
	it("a process substitution", () => {
		expect(refused("diff <(a) <(b)")).toMatchObject({ reason: "process-substitution" })
	})
	// Part 1 pinned the values stub here; these are the merged module's answers (§4.3, §5, §5.9).
	const simple = (command: string) => {
		const parsed = walkBash(command)
		if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
		return parsed.commands
	}
	it("arithmetic expansion of literals reports the expression text (§4.3)", () => {
		expect(simple("echo $((1 + 1))")).toMatchObject([{ argv: ["echo", "$((1 + 1))"], opaque: false }])
	})
	it("a command-local assignment prefix becomes an envVar (§5.1)", () => {
		expect(simple("FOO=bar cmd")).toMatchObject([{ argv: ["cmd"], envVars: [{ name: "FOO", value: "bar" }] }])
	})
	it("a statement-level assignment is remembered and reported with an empty argv (§13.6, §14.1)", () => {
		expect(simple("D=/tmp/build")).toMatchObject([{ argv: [], envVars: [{ name: "D", value: "/tmp/build" }] }])
	})
	it("a declaring builtin is a command whose items are argv (§5.9)", () => {
		expect(simple("export FOO=1")).toMatchObject([{ argv: ["export", "FOO=1"], envVars: [] }])
	})
	it("unset is a command whose names are argv (§5.9)", () => {
		expect(simple("unset FOO")).toMatchObject([{ argv: ["unset", "FOO"], envVars: [] }])
	})
	it("an expansion in a redirect target", () => {
		expect(refused("echo x > $OUT")).toMatchObject({ reason: "variable-expansion" })
	})
	it("an expansion in a test operand", () => {
		expect(refused('[[ "$branch" == main ]]')).toMatchObject({ reason: "variable-expansion" })
	})
	it("an expansion inside a test operand", () => {
		expect(walkBash("[[ ${a} == b ]]")).toMatchObject({ kind: "unproven", reason: "variable-expansion" })
	})
})

describe("routes heredocs to bash-walker-heredoc.ts", () => {
	// These pinned the stub's refusal until T10c landed; now the module attaches the body (§8).
	it("a quoted-delimiter body", () => {
		expect(walkBash("cat <<'EOF'\nbody\nEOF")).toMatchObject({ kind: "simple", commands: [{ argv: ["cat"], heredocs: ["body"], text: "cat", end: 3 }] })
	})
	it("a heredoc next to a file redirect", () => {
		expect(walkBash("cat > cfg.json <<'EOF'\n{}\nEOF")).toMatchObject({
			kind: "simple",
			commands: [{ argv: ["cat"], redirects: [{ op: ">", target: "cfg.json" }], heredocs: ["{}"] }],
		})
	})
	it("a heredoc behind an explicit descriptor", () => {
		expect(walkBash("cat 3<<'E'\nx\nE")).toMatchObject({ kind: "simple", commands: [{ argv: ["cat"], heredocs: ["x"] }] })
	})
})

describe("asks bash-walker-scan.ts before parsing", () => {
	it("returns the scan's refusal verbatim, before the parser is consulted", async () => {
		const fromScan = refuse("control-character", "scanned")
		vi.doMock("./bash-walker-scan.ts", () => ({ scanInput: () => fromScan }))
		vi.resetModules()
		try {
			const walker = await import("./bash-walker.ts")
			// The parser was initialised in the module this file imported first; the re-imported
			// copy has its own state, so a scan refusal is the only thing this can return.
			expect(walker.walkBash("ls -la")).toEqual(fromScan)
		} finally {
			vi.doUnmock("./bash-walker-scan.ts")
			vi.resetModules()
		}
	})

	it("does not do the text scans itself — the §10 ids come from the scan module", () => {
		// §10.3 classes belong to the scan module (§2 steps 3–5): the walker never invents a refusal of
		// its own for these, and whitespace that is not escaped is still just a separator.
		expect(walkBash("echo a\\ b")).toMatchObject({ kind: "unproven", reason: "backslash-whitespace", malformed: false })
		expect(walkBash("cat ~[proj]/x")).toMatchObject({ kind: "unproven", reason: "zsh-tilde-bracket", malformed: false })
		expect(walkBash("echo =bad")).toMatchObject({ kind: "unproven", reason: "zsh-equals-expansion", malformed: false })
		expect(walkBash("echo a\tb").kind).toBe("simple")
	})
})

describe("asks bash-walker-meaning.ts about the finished commands", () => {
	it("returns the meaning check's refusal for an accepted command list", async () => {
		const fromMeaning = refuse("jq-system-call", "command")
		vi.doMock("./bash-walker-meaning.ts", () => ({ checkMeaning: (commands: unknown[]) => (commands.length > 0 ? fromMeaning : null) }))
		vi.resetModules()
		try {
			const parser = await import("./bash-parser.ts")
			await parser.initBashParser()
			const walker = await import("./bash-walker.ts")
			expect(walker.walkBash("ls | wc -l")).toEqual(fromMeaning)
		} finally {
			vi.doUnmock("./bash-walker-meaning.ts")
			vi.resetModules()
		}
	})
})

// ---------------------------------------------------------------------------
// §3 structures, §4 words, §7 redirects, §9 tests, §13 spans — beyond the corpus
// ---------------------------------------------------------------------------

const argvs = (command: string): string[][] => {
	const parsed = walkBash(command)
	if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
	return parsed.commands.map((one) => one.argv)
}

/** §12 id or "simple". `string`, not `Reason`: a refusal's `reason` field is declared `string` in bash-ast.ts, so no narrowing to the union exists to claim here. */
const reasonOf = (command: string): string => {
	const parsed = walkBash(command)
	return parsed.kind === "simple" ? "simple" : parsed.reason
}

describe("structures", () => {
	it("emits nothing for a blank input (§1.4)", () => {
		for (const blank of ["", "   ", "\n", " \t\n "]) expect(walkBash(blank)).toEqual({ kind: "simple", commands: [] })
	})

	it("keeps the operator written in front of each command (§13.4)", () => {
		const parsed = walkBash("a; b && c || d | e |& f & g\nh")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands.map((one) => one.connector)).toEqual(["", ";", "&&", "||", "|", "|&", "&", "\n"])
	})

	it("gives the first command inside a group the operator in front of the group", () => {
		const parsed = walkBash("a && ( b ; c )")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands.map((one) => [one.argv.join(" "), one.connector])).toEqual([
			["a", ""],
			["b", "&&"],
			["c", ";"],
		])
	})

	it("drops the negation and the parentheses from the span (§13.3)", () => {
		const parsed = walkBash("! ( ls )")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands[0]).toMatchObject({ start: 4, end: 6, text: "ls", connector: "" })
	})

	it("refuses a construct as a whole, never its parts (§3.4)", () => {
		expect(reasonOf("for i in 1 2; do rm -rf /tmp/x; done")).toBe("loop-body")
		expect(reasonOf("for ((i = 0; i < 3; i++)); do :; done")).toBe("loop-body")
		expect(reasonOf("if a; then b; fi")).toBe("conditional-body")
		expect(reasonOf("case x in y) z;; esac")).toBe("case-statement")
		expect(reasonOf("f() { echo hi; }")).toBe("function-definition")
		expect(reasonOf("{ echo hi; }")).toBe("brace-group")
		expect(reasonOf("(( i = 1 ))")).toBe("arithmetic-command")
		expect(reasonOf("time (ls)")).toBe("subshell-argument")
	})

	it("names an unfinished brace group as a brace group", () => {
		expect(reasonOf("true && { echo hi }")).toBe("brace-group")
		expect(reasonOf("true && (( i = 1 ))")).toBe("arithmetic-command")
	})

	it("refuses a tree the parser could not complete (§10.7)", () => {
		expect(reasonOf("ls |")).toMatchObject("parse-error")
		expect(walkBash("ls |")).toMatchObject({ malformed: true })
	})

	it("refuses anything over the size cap without parsing it (§10.9)", () => {
		expect(reasonOf(`echo ${"a".repeat(10_000)}`)).toBe("input-too-large")
	})
})

describe("words", () => {
	it("joins adjacent quote segments into one argument (§4)", () => {
		expect(argvs(`echo a"b"c'd'e`)).toEqual([["echo", "abcde"]])
	})

	it("keeps operators inside quotes inert (§4)", () => {
		expect(argvs(`echo "a; b && c | d"`)).toEqual([["echo", "a; b && c | d"]])
	})

	it("performs no file-name matching and no tilde expansion (§4)", () => {
		expect(argvs("ls *.ts [ab]? ~ ~/x ~root")).toEqual([["ls", "*.ts", "[ab]?", "~", "~/x", "~root"]])
	})

	it("resolves backslash escapes outside quotes (§4)", () => {
		expect(argvs(String.raw`echo a\\b \; \$X`)).toEqual([["echo", "a\\b", ";", "$X"]])
		expect(argvs(String.raw`find . -name tmp -exec rm {} \;`)).toEqual([["find", ".", "-name", "tmp", "-exec", "rm", "{}", ";"]])
	})

	it("a backslash before whitespace is refused, not resolved (§4, §10.3)", () => {
		expect(walkBash(String.raw`echo a\ b`)).toMatchObject({ kind: "unproven", reason: "backslash-whitespace", malformed: false })
		expect(walkBash("echo a\\\tb")).toMatchObject({ kind: "unproven", reason: "backslash-whitespace", malformed: false })
	})

	it("escapes only the four characters inside double quotes (§4)", () => {
		expect(argvs(`echo "fix \\"bug\\"" `)).toEqual([["echo", 'fix "bug"']])
		expect(argvs(`echo "a\\nb"`)).toEqual([["echo", "a\\nb"]])
	})

	it("treats a `$` with nothing expandable after it as the character (§4)", () => {
		expect(argvs("echo 5$ cost: $ !")).toEqual([["echo", "5$", "cost:", "$", "!"]])
	})

	it("refuses the string forms it does not interpret (§4.2)", () => {
		expect(reasonOf(`printf $'a\\tb'`)).toBe("ansi-c-string")
		expect(reasonOf(`echo $"greeting"`)).toBe("translated-string")
	})

	it("refuses brace expansion, including escaped, in any position (§4.2)", () => {
		expect(reasonOf("echo {a,b}")).toBe("brace-expansion")
		expect(reasonOf("echo {1..5}")).toBe("brace-expansion")
		expect(reasonOf("echo \\{a,b}")).toBe("brace-expansion")
		expect(reasonOf("echo x > {a,b}")).toBe("brace-expansion")
		// `{}` is the find placeholder, not a group; a quoted brace cannot open one.
		expect(reasonOf(`find . -exec rm {} \\;`)).toBe("simple")
		expect(reasonOf(`awk 'BEGIN{printf "%s\n", "hi"}' f`)).toBe("simple")
		expect(reasonOf(`echo -d '{"k":"v","k2":"v2"}'`)).toBe("simple")
	})

	it("refuses an expansion the tree did not hand over as a node (§1.3)", () => {
		expect(reasonOf("echo a$ b")).toBe("simple") // the `$` here is followed by a space: literal
		expect(reasonOf("echo ${A:-x}")).toBe("variable-expansion")
	})
})

describe("redirects", () => {
	const redirectsOf = (command: string) => {
		const parsed = walkBash(command)
		if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind}`)
		return parsed.commands[0].redirects
	}

	it("reports the operator, the target and an explicit descriptor (§7.1)", () => {
		expect(redirectsOf("echo x 2> err.txt")).toEqual([{ op: ">", target: "err.txt", fdDup: false, fd: 2 }])
		expect(redirectsOf("echo x &>> all.log")).toEqual([{ op: "&>>", target: "all.log", fdDup: false }])
		expect(redirectsOf("sort 0< in.txt")).toEqual([{ op: "<", target: "in.txt", fdDup: false, fd: 0 }])
	})

	it("tells a descriptor duplicate from a write (§7.2)", () => {
		expect(redirectsOf("echo x 2>&1")).toEqual([{ op: ">&", target: "1", fdDup: true, fd: 2 }])
		expect(redirectsOf("echo x >& /dev/null")).toEqual([{ op: ">&", target: "/dev/null", fdDup: false }])
		expect(redirectsOf("echo x <& 0")).toEqual([{ op: "<&", target: "0", fdDup: true }])
	})

	it("keeps redirects in source order and off the span (§13.3)", () => {
		const parsed = walkBash("echo hi > out.txt 2>&1")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands[0].text).toBe("echo hi")
		expect(parsed.commands[0].redirects.map((one) => one.op)).toEqual([">", ">&"])
	})

	it("attaches a redirect scope to the last command of a pipeline (§7.4)", () => {
		const parsed = walkBash("ls | grep x > out.txt")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands[0].redirects).toEqual([])
		expect(parsed.commands[1].redirects.map((one) => one.target)).toEqual(["out.txt"])
	})

	it("emits a redirect with no command as a write with empty argv (§3.1)", () => {
		const parsed = walkBash("> empty.txt")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands).toEqual([
			{ argv: [], envVars: [], redirects: [{ op: ">", target: "empty.txt", fdDup: false }], heredocs: [], text: "> empty.txt", start: 0, end: 11, connector: "", opaque: false },
		])
	})

	it("does not report a here-string but does validate it (§7)", () => {
		expect(redirectsOf("grep x <<< 'a b'")).toEqual([])
		expect(reasonOf('grep x <<< "$(id)"')).toBe("command-substitution")
		expect(reasonOf("grep x <<< $HOME")).toBe("variable-expansion")
	})

	it("refuses the one form whose effect the contract cannot express (§7)", () => {
		expect(reasonOf("echo x <> f")).toBe("redirect-unsupported")
	})

	it("resolves a target exactly like an argument (§7.3)", () => {
		expect(redirectsOf(`echo x > "out dir/a.txt"`)).toEqual([{ op: ">", target: "out dir/a.txt", fdDup: false }])
		expect(redirectsOf(`echo x > out"a".txt`)).toEqual([{ op: ">", target: "outa.txt", fdDup: false }])
		expect(redirectsOf("echo x > 'f*?[.'")).toEqual([{ op: ">", target: "f*?[.", fdDup: false }])
	})

	it("never marks a descriptor duplicate opaque (§7.6)", () => {
		const parsed = walkBash("make 2>&1")
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands[0].opaque).toBe(false)
	})
})

describe("test commands", () => {
	it("canonicalises the first argument and drops the closer (§9.1)", () => {
		expect(argvs("[ -f a ]")).toEqual([["[[", "-f", "a"]])
		expect(argvs("[[ -f a ]]")).toEqual([["[[", "-f", "a"]])
		expect(argvs("test -f a")).toEqual([["test", "-f", "a"]])
	})

	it("flattens operators and operands in source order (§9.2)", () => {
		expect(argvs("[[ -f a && ! -d b || -e ( c ) ]]")).toEqual([["[[", "-f", "a", "&&", "!", "-d", "b", "||", "-e", "(", "c", ")"]])
	})

	it("keeps a pattern operand as written (§9.3)", () => {
		expect(argvs("[[ v1.2 =~ ^[0-9]+ ]]")).toEqual([["[[", "v1.2", "=~", "^[0-9]+"]])
		expect(argvs("[[ a == b*c ]]")).toEqual([["[[", "a", "==", "b*c"]])
		expect(argvs("[[ a == @(x|y) ]]")).toEqual([["[[", "a", "==", "@(x|y)"]])
	})
})

describe("spans and text", () => {
	it("uses JS string indices, so a surrogate pair counts twice (§13.1)", () => {
		const parsed = walkBash(`echo "👋" && pwd`)
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands.map((one) => [one.start, one.end])).toEqual([
			[0, 9],
			[13, 16],
		])
	})

	it("never rebuilds text from argv (§13.2)", () => {
		const parsed = walkBash(`echo   'a  b'   # keep`)
		if (parsed.kind !== "simple") throw new Error("expected simple")
		expect(parsed.commands[0].text).toBe(`echo   'a  b'`)
		expect(parsed.commands[0].argv).toEqual(["echo", "a  b"])
	})

	it("reports every command's span as a substring of the input", () => {
		for (const command of ["a && b", "ls | wc -l", "! grep -q x f", "( cd /tmp ; ls )", "> f", "[ -f x ] && echo y", "echo x 2>&1 | tee log"]) {
			const parsed = walkBash(command)
			if (parsed.kind !== "simple") continue
			for (const one of parsed.commands) {
				expect(one.text, `${command} / ${one.text}`).toBe(command.slice(one.start, one.end))
			}
		}
	})
})

describe("result hygiene", () => {
	it("reports `opaque` only from the values a command reports (§6.3)", () => {
		// While the values stub refuses every placeholder, nothing in this subset can be opaque.
		for (const one of OWNED) {
			const parsed = walkBash(one.command)
			if (parsed.kind !== "simple") continue
			for (const command of parsed.commands) {
				const sees = (v: string) => v.includes("__CMDSUB_OUTPUT__") || v.includes("__TRACKED_VAR__")
				const derived = command.argv.some(sees) || command.envVars.some((e) => sees(e.value)) || command.redirects.some((r) => !r.fdDup && sees(r.target))
				expect(command.opaque, `${one.id} ${command.argv.join(" ")}`).toBe(derived)
			}
		}
	})

	it("is deterministic (§14.4)", () => {
		for (const command of ["git add -A && git commit -m wip", "echo x > f 2>&1", "[[ -f a && -d b ]]", "for i in a; do :; done"]) {
			expect(walkBash(command)).toEqual(walkBash(command))
		}
	})

	it("returns the same result for the whole corpus without throwing", () => {
		const counts = new Map<string, number>()
		for (const one of loadGolden() as GoldenCase[]) {
			const parsed = walkBash(one.command)
			const key = parsed.kind === "simple" ? "simple" : parsed.reason
			counts.set(key, (counts.get(key) ?? 0) + 1)
		}
		// Every bucket is a §12 id or `simple`: no other shape may come out of the walker.
		for (const key of counts.keys()) {
			if (key === "simple") continue
			expect(["unproven"].length).toBe(1)
			expect(refuse(key as Reason).reason).toBe(key)
		}
		expect(counts.get("simple") ?? 0).toBeGreaterThan(0)
	})
})

// --------------------------------------------------------------------------- §7 destination words the grammar swallows

describe("a file redirect with more than one destination word", () => {
	/** What one command reports: its arguments, its redirect targets, and the span it points at. */
	const one = (command: string) => {
		const parsed = walkBash(command)
		if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
		expect(parsed.commands.length, command).toBe(1)
		const [command0] = parsed.commands
		return { argv: command0.argv, targets: command0.redirects.map((one0) => one0.target), fds: command0.redirects.map((one0) => one0.fd ?? null), text: command0.text, span: command.slice(command0.start, command0.end) }
	}

	it("keeps every word after the target as an argument of the command (§7)", () => {
		// tree-sitter files every word after the operator under `destination`; bash takes only the first
		// as the target. A dropped `-rf /tmp/x` would be a classified `rm` with no visible target.
		expect(one("ls 2>/dev/null -la")).toEqual({ argv: ["ls", "-la"], targets: ["/dev/null"], fds: [2], text: "ls 2>/dev/null -la", span: "ls 2>/dev/null -la" })
		expect(one("rm > /dev/null -rf /tmp/x")).toEqual({ argv: ["rm", "-rf", "/tmp/x"], targets: ["/dev/null"], fds: [null], text: "rm > /dev/null -rf /tmp/x", span: "rm > /dev/null -rf /tmp/x" })
		expect(one("echo hi > f g")).toEqual({ argv: ["echo", "hi", "g"], targets: ["f"], fds: [null], text: "echo hi > f g", span: "echo hi > f g" })
		expect(one("cat > out.txt -x <<'E'\nbody\nE")).toEqual({ argv: ["cat", "-x"], targets: ["out.txt"], fds: [null], text: "cat > out.txt -x", span: "cat > out.txt -x" })
	})

	it("keeps the words of several redirects in source order, resolved like any argument (§4, §7.3)", () => {
		expect(one("echo hi > a b > c d")).toMatchObject({ argv: ["echo", "hi", "b", "d"], targets: ["a", "c"] })
		expect(one("echo hi >f 2>&1 -y")).toMatchObject({ argv: ["echo", "hi", "-y"], targets: ["f", "1"] })
		expect(one("echo hi > f \"a b\"")).toMatchObject({ argv: ["echo", "hi", "a b"] })
		// A descriptor glued to the operator is still a descriptor, not an argument (§7.1).
		expect(one("sort 0< in.txt -x")).toMatchObject({ argv: ["sort", "-x"], targets: ["in.txt"], fds: [0] })
		// The words go to the stage the redirect belongs to, which is the last one (§7.4).
		const piped = walkBash("ls | grep a > f -x")
		if (piped.kind !== "simple") throw new Error("expected simple")
		expect(piped.commands.map((one0) => one0.argv)).toEqual([["ls"], ["grep", "a", "-x"]])
	})

	it("still refuses a target the walker cannot resolve, with the extra words beside it (§4.2, §7.3)", () => {
		expect(reasonOf("echo hi > {a,b} -x")).toBe("brace-expansion")
		expect(reasonOf("echo hi > f $(id) -x")).toBe("command-substitution")
		expect(reasonOf("echo hi > \"$f\" -x")).toBe("variable-expansion")
		expect(reasonOf("echo hi <> f -x")).toBe("redirect-unsupported")
	})

	it("does not report the dash twice when both recoveries reach the same command (§8.4)", () => {
		// `-x` is a destination word the grammar kept; the lone `-` is one it dropped. Both are the
		// command's own arguments, and each must arrive exactly once, with the body attached.
		const kept = walkBash("cat > out.txt -x <<'E'\nbody\nE")
		if (kept.kind !== "simple") throw new Error("expected simple")
		expect(kept.commands[0]).toMatchObject({ argv: ["cat", "-x"], text: "cat > out.txt -x", end: 16, heredocs: ["body"] })
		const dropped = walkBash("cat > out.txt - <<'E'\nbody\nE")
		if (dropped.kind !== "simple") throw new Error("expected simple")
		expect(dropped.commands[0]).toMatchObject({ argv: ["cat", "-"], text: "cat > out.txt -", end: 15, heredocs: ["body"] })
		// Neither recovery invents a word for a command that had none.
		expect(argvs("cat > out.txt <<'E'\nbody\nE")).toEqual([["cat"]])
		expect(argvs("python3 - x <<'PY'\nprint(1)\nPY")).toEqual([["python3", "-", "x"]])
	})

	it("keeps every reported span a substring of the input (§13.2)", () => {
		for (const command of ["ls 2>/dev/null -la", "rm > /dev/null -rf /tmp/x", "echo hi > f g", "cat > out.txt -x <<'E'\nbody\nE", "cat > out.txt - <<'E'\nbody\nE", "sort 0< in.txt -x", "echo hi > a b > c d", "ls | grep a > f -x", "[[ -f a ]] > f -x"]) {
			const parsed = walkBash(command)
			if (parsed.kind !== "simple") continue
			for (const one0 of parsed.commands) expect(one0.text, `${command} / ${one0.text}`).toBe(command.slice(one0.start, one0.end))
		}
	})
})

// --------------------------------------------------------------------------- §2 step 8: lines the parser joined

describe("a command whose words arrived from the lines below", () => {
	/**
	 * tree-sitter-bash 0.25.1 parses a pipeline of three or more stages followed by newline-separated
	 * commands, the last ending in a redirect, as ONE pipeline whose last stage swallows the following
	 * lines as words — and reports no error. bash runs them as separate commands, so an emitted command
	 * with an unescaped newline between two of its own words is a command that cannot be tied back to
	 * the input (§13.6), and a verb on a swallowed line would never reach the caller at all.
	 */
	const joined = "ls | grep a | cut -c1\necho\nls -la 2>&1"

	it("refuses the joined parse instead of reporting a command that spans lines (§2 step 8)", () => {
		expect(reasonOf(joined)).toBe("inventory-mismatch")
		// The same shape with the other three ways of ending the last line.
		expect(reasonOf("ls | grep a | cut -c1\necho\nls -la > f")).toBe("inventory-mismatch")
		expect(reasonOf("ls | grep a | cut -c1\necho\nls -la < f")).toBe("inventory-mismatch")
		// The valid input is valid bash, so this is not a fix-and-retry answer (§1.2).
		expect(walkBash(joined)).toMatchObject({ malformed: false })
		// The destructive shape this exists for: `rm` never appears in the output of a walker that
		// reports the three lines as arguments of `cut`.
		expect(reasonOf("ls | grep a | cut -c1\necho\nrm -rf /tmp/x 2>&1")).toBe("inventory-mismatch")
	})

	it("refuses it when only a redirect sits on the line below the pipeline", () => {
		// Here no word is swallowed, but `>f` is a statement of its own to bash and a write the walker
		// would otherwise hand to the last stage of the pipeline (§7.4).
		expect(reasonOf("ls | grep a | cut -c1\n>f")).toBe("inventory-mismatch")
	})

	it("leaves the spellings the parser gets right alone", () => {
		// Two stages instead of three, a `;`, an `&&`, and a blank line where none of them triggers the
		// defect: same commands bash runs, same count.
		const counts: [string, number][] = [
			["ls | grep a\necho\nls -la 2>&1", 4],
			["ls | grep a | cut -c1;\necho\nls -la 2>&1", 5],
			["ls | grep a | cut -c1 && echo\nls -la 2>&1", 5],
			["ls | grep a | cut -c1\n\necho\nls -la", 5],
			["ls | grep a | cut -c1;\necho\n\nls -la 2>&1", 5],
			["ls | grep a | cut -c1 && echo\n\nls -la 2>&1", 5],
		]
		for (const [command, count] of counts) {
			const parsed = walkBash(command)
			if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
			expect(parsed.commands.length, command).toBe(count)
		}
		// A blank line alone does not break the join in this version of the grammar: the lines are still
		// swallowed, so the input is still refused rather than reported wrong.
		expect(reasonOf("ls | grep a | cut -c1\n\necho\nls -la 2>&1")).toBe("inventory-mismatch")
	})

	it("is about the gaps between words, not the characters inside them (§4, §10.1)", () => {
		// A newline inside one quoted argument is argument text.
		expect(argvs(`echo "a\nb"`)).toEqual([["echo", "a\nb"]])
		// A backslash-newline joins one word, and separates two commands: neither is a joined line.
		expect(argvs("echo a \\\n b")).toEqual([["echo", "a", "b"]])
		expect(argvs("echo hi \\\n > f")).toEqual([["echo", "hi"]])
		expect(argvs("ls \\\n | grep a \\\n | cut -c1")).toEqual([["ls"], ["grep", "a"], ["cut", "-c1"]])
		expect(argvs("cd /tmp\nls")).toEqual([["cd", "/tmp"], ["ls"]])
		// A backslash-newline inside a word is still the scan's class, not this one (§10.3).
		expect(reasonOf("tr\\\naceroute")).toBe("backslash-whitespace")
	})

	it("keeps a construct it cannot analyse the earlier refusal (§12.1)", () => {
		expect(reasonOf("for i in a; do :; done\n>f")).toBe("loop-body")
		// A test command may legitimately span lines, and its operands are not one command's argv words.
		expect(argvs("[[ -f a &&\n -d b ]]")).toEqual([["[[", "-f", "a", "&&", "-d", "b"]])
		// A here-document body lives on the lines below by definition (§8).
		expect(argvs("cat <<'E'\nbody\nE\necho done")).toEqual([["cat"], ["echo", "done"]])
	})
})

// ---------------------------------------------------------------------------
// reporting pass: a file written through a flag is reported as a write target
// ---------------------------------------------------------------------------

describe("reports a write named by a flag, not by a redirect", () => {
	/** One command's argv and reported targets, for the command the walker accepted. */
	const written = (command: string) => {
		const parsed = walkBash(command)
		if (parsed.kind !== "simple") throw new Error(`${command} -> ${parsed.kind} ${parsed.reason}`)
		return parsed.commands.map((c) => ({ argv: c.argv, text: c.text, opaque: c.opaque, targets: c.redirects.map((r) => `${r.op}${r.fd === undefined ? "" : r.fd} ${r.target}`) }))
	}

	it("adds the flag operand to the command's redirect list", () => {
		expect(written("sort -o out.txt in.txt")).toEqual([
			{ argv: ["sort", "-o", "out.txt", "in.txt"], text: "sort -o out.txt in.txt", opaque: false, targets: ["> out.txt"] },
		])
		expect(written("git diff --output=out.diff HEAD~1")[0]!.targets).toEqual(["> out.diff"])
		expect(written("uniq --output out.txt in.txt")[0]!.targets).toEqual(["> out.txt"])
		expect(written("patch -o merged.txt in.patch")[0]!.targets).toEqual(["> merged.txt"])
	})

	it("leaves argv, span and every other field exactly as the walk wrote them", () => {
		// The words are what the program was passed (§13.2); the target is a fact added on top.
		const one = written("sort -i /tmp/a -o /etc/x")[0]!
		expect(one.argv).toEqual(["sort", "-i", "/tmp/a", "-o", "/etc/x"])
		expect(one.text).toBe("sort -i /tmp/a -o /etc/x")
	})

	it("reports a flag target beside a real redirect, each on its own line of the report", () => {
		// The tree's own redirect is walked first, so it comes first; both are writes.
		expect(written("sort -o /tmp/out.txt > /tmp/in.txt")[0]!.targets).toEqual(["> /tmp/in.txt", "> /tmp/out.txt"])
	})

	it("reports nothing for a command that writes nothing", () => {
		expect(written("sort -c check.txt")[0]!.targets).toEqual([])
		expect(written("sort < sorted.txt")[0]!.targets).toEqual(["< sorted.txt"])
		expect(written("ssh -o BatchMode=yes host")[0]!.targets).toEqual([])
		expect(written("grep -o a f")[0]!.targets).toEqual([])
	})

	it("keeps a pipeline's legs separate, flag target and all", () => {
		expect(written("sort in.txt -o /tmp/x | uniq --output=/tmp/y")).toEqual([
			{ argv: ["sort", "in.txt", "-o", "/tmp/x"], text: "sort in.txt -o /tmp/x", opaque: false, targets: ["> /tmp/x"] },
			{ argv: ["uniq", "--output=/tmp/y"], text: "uniq --output=/tmp/y", opaque: false, targets: ["> /tmp/y"] },
		])
	})

	it("marks the command opaque when the flag operand is only known at run time (§6.3)", () => {
		const parsed = walkBash('sort -o "$(pwd)/out.txt" in.txt')
		if (parsed.kind !== "simple") throw new Error(`unproven: ${parsed.reason}`)
		// The substitution is emitted as its own command first (§6.2); the one wearing the placeholder is
		// the command that writes.
		const [substituted, writing] = parsed.commands
		expect(substituted!.argv).toEqual(["pwd"])
		expect(writing!.opaque).toBe(true)
		expect(writing!.argv).toEqual(["sort", "-o", "__CMDSUB_OUTPUT__/out.txt", "in.txt"])
		expect(writing!.redirects.map((r) => r.target)).toEqual(["__CMDSUB_OUTPUT__/out.txt"])
	})

	it("refuses before reporting: a command the steps 7–10 reject still comes back unproven", () => {
		const parsed = walkBash("sort -o $(ls) in.txt")
		expect(parsed.kind).toBe("unproven")
	})
})
