import type { Node } from "web-tree-sitter"
import { beforeAll, describe, expect, it } from "vitest"
import type { AstCommand } from "./bash-ast.ts"
import { initBashParser, parseBash } from "./bash-parser.ts"
import { walkBash, type Reason } from "./bash-walker.ts"
import { compareCase, loadGolden, selectById, type GoldenCase } from "./bash-walker-golden.ts"
import { scanInput } from "./bash-walker-scan.ts"
import { findHeredocTerminator, maskedCopy, readHeredocDelimiter, takeHeredoc, type BodySlice } from "./bash-walker-heredoc.ts"

/**
 * Tests for part 3: the text scans of §2 steps 2–5 (§10) and the here-documents of §8, over this
 * part's subset of `bash-walker.golden.jsonl` and beyond it.
 */

/** The id prefixes this part owns. */
const SUBSET = ["hd-", "mal-", "pre-"]

/** Cases part 1 handed to this part by name rather than by prefix. */
const NAMED = ["span-heredoc-scope", "word-escape-space"]

/**
 * Cases in the subset this part cannot settle on its own: the ones that need part 2 (`T10b`: values,
 * §5/§6), part 4 (`T10d`: the meaning checks, §11) or the caller (`T11`). Empty — every case in the
 * subset is decided by §8, §10 and the spans of §13.
 */
export const DEFERRED: Record<string, "T10b" | "T10d" | "T11"> = {}

const GOLDEN = loadGolden()
const CASES: GoldenCase[] = [...selectById(GOLDEN, SUBSET), ...GOLDEN.filter((one) => NAMED.includes(one.id))]
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

	it("the subset is what the task describes", () => {
		expect(CASES.map((one) => one.id).sort()).toEqual(
			[...selectById(GOLDEN, SUBSET).map((one) => one.id), ...NAMED].sort(),
		)
		expect(CASES.length).toBe(44)
		expect(selectById(GOLDEN, ["hd-"]).length).toBe(20)
		expect(selectById(GOLDEN, ["mal-"]).length).toBe(21)
		expect(selectById(GOLDEN, ["pre-"]).length).toBe(1)
	})
})

// --------------------------------------------------------------------------- §8 here-documents

const commandsOf = (command: string): AstCommand[] => {
	const parsed = walkBash(command)
	if (parsed.kind !== "simple") throw new Error(`${JSON.stringify(command)} -> ${parsed.kind} ${(parsed as { reason: Reason }).reason}`)
	return parsed.commands
}

const bodiesOf = (command: string): string[][] => commandsOf(command).map((one) => one.heredocs)

describe("§8.1 a quoted delimiter is what makes a body inert", () => {
	it("accepts the three quoted spellings", () => {
		expect(bodiesOf("cat <<'E'\nbody\nE")).toEqual([["body"]])
		expect(bodiesOf('cat <<"E"\nbody\nE')).toEqual([["body"]])
		expect(bodiesOf("cat <<\\E\nbody\nE")).toEqual([["body"]])
		expect(bodiesOf("cat << 'E'\nbody\nE")).toEqual([["body"]]) // blanks between operator and delimiter
	})

	it("refuses the whole command for an unquoted delimiter, whatever is in the body", () => {
		// `cat <<-E` with an expandable line in the body: an unquoted delimiter the parser is happy
		// with. (`cat <<$NAME` is not — the grammar turns that one into an ERROR node, so step 6 answers
		// it before §8.1 is ever reached.)
		for (const command of ["cat <<E\nbody\nE", "cat <<-E\n\tbody\nE", "cat <<E\n$(id)\nE", "cat <<-E\n$NAME\nbody\nE"]) {
			expect(walkBash(command), JSON.stringify(command)).toMatchObject({ kind: "unproven", reason: "heredoc-unquoted-delimiter", malformed: false })
		}
	})

	it("does not look inside an unquoted body for something to rescue", () => {
		// An unquoted body with nothing expandable in it is still a body the shell expands.
		expect(walkBash("cat <<E\nnothing here at all\nE")).toMatchObject({ reason: "heredoc-unquoted-delimiter" })
	})
})

describe("§8.2–§8.5 what the owner is handed", () => {
	it("hands a tab-stripping body over verbatim", () => {
		expect(bodiesOf("cat <<-'E'\n\t\tindented\nE")).toEqual([["\t\tindented"]])
		expect(bodiesOf("cat <<-'E'\n\ta\n\tb\nE")).toEqual([["\ta\n\tb"]])
		// A body that is only the terminator line has no tabs in it, written or otherwise: `\tE` is the
		// terminator (`<<-` ignores leading tabs when matching it), so there is no body line at all.
		expect(bodiesOf("cat <<-'E'\n\tE")).toEqual([[""]])
	})

	it("attaches several bodies of one command in source order", () => {
		expect(bodiesOf("cat <<'A'\none\nA\ncat <<'B'\ntwo\nB")).toEqual([["one"], ["two"]])
	})

	it("accepts a descriptor in front of the operator and reports no redirect for it", () => {
		const [command] = commandsOf("cat 3<<'E'\nbody\nE")
		expect(command.argv).toEqual(["cat"])
		expect(command.redirects).toEqual([])
		expect(command.heredocs).toEqual(["body"])
	})

	it("recovers the lone dash the grammar drops in front of the operator (§8.4)", () => {
		const [dash] = commandsOf("python3 - <<'PY'\nprint(1)\nPY")
		expect(dash.argv).toEqual(["python3", "-"])
		expect(dash.text).toBe("python3 -")
		expect(dash.end).toBe(9)
		expect(dash.heredocs).toEqual(["print(1)"])

		const [bash] = commandsOf("bash - <<'S'\necho hi\nS")
		expect(bash.argv).toEqual(["bash", "-"])

		// An argument after the dash keeps both, in order, and nothing is invented.
		expect(commandsOf("python3 - x <<'PY'\nprint(1)\nPY")[0].argv).toEqual(["python3", "-", "x"])
		expect(commandsOf("cat <<'E'\nbody\nE")[0].argv).toEqual(["cat"])
	})

	it("recovers a dash the grammar fuses into the operator or files as a descriptor", () => {
		const fused = commandsOf("cat -<<'E'\nbody\nE")[0]
		expect(fused.argv).toEqual(["cat", "-"])
		expect(fused.text).toBe("cat -")
		expect(fused.end).toBe(5)
		expect(fused.heredocs).toEqual(["body"])

		// `-3` is not a descriptor — bash reads it as an argument — even though the grammar files it as
		// one, and a word the walker drops is a command reported wrong (§8.4).
		expect(commandsOf("cat -3<<'E'\nbody\nE")[0].argv).toEqual(["cat", "-3"])
		expect(commandsOf("cat 3-<<'E'\nbody\nE")[0].argv).toEqual(["cat", "3-"])

		// A digits-only descriptor is a descriptor: accepted, and not reported as anything (§8.5).
		expect(commandsOf("cat 3<<'E'\nbody\nE")[0].argv).toEqual(["cat"])
	})

	it("recovers a word the grammar drops behind a redirect the command owns (§8.4, §13.3)", () => {
		// bash runs `cat > out.txt - <<'E'` as `cat -` with stdout in out.txt. A command's own redirects
		// are inside its span (§13.3), so the span grows over the redirect to reach the dash the grammar
		// dropped — reporting `cat` here would hide that stdin is read.
		const [dash] = commandsOf("cat > out.txt - <<'E'\nbody\nE")
		expect(dash.argv).toEqual(["cat", "-"])
		expect(dash.text).toBe("cat > out.txt -")
		expect(dash.heredocs).toEqual(["body"])
		expect(commandsOf("cat 2>&1 - <<'E'\nbody\nE")[0].argv).toEqual(["cat", "-"])
		// The same file redirect with nothing lost in front of the operator is an ordinary command.
		const [plain] = commandsOf("cat > out.txt <<'E'\nbody\nE")
		expect(plain.text).toBe("cat")
		expect(plain.heredocs).toEqual(["body"])
	})

	it("refuses a gap it cannot tie to the command in front of the operator (§13.2)", () => {
		// An owner whose span stops short of the word before the operator, and that word is not a
		// redirect this command owns: what sits in between is not this module's to turn into an argument,
		// and a span covering it would not be the substring it names.
		const parsed = parseBash("python3 - <<'PY'\nprint(1)\nPY")
		if ("error" in parsed) throw new Error("the parser could not read the fixture")
		const redirect = parsed.tree.rootNode.children
			.find((child) => child.type === "redirected_statement")!
			.children.find((child) => child.type === "heredoc_redirect")!
		const short: AstCommand = { argv: ["python3"], envVars: [], redirects: [], heredocs: [], text: "python3", start: 0, end: 5, connector: "", opaque: false }
		expect(takeHeredoc(redirect, short)).toMatchObject({ kind: "unproven", reason: "heredoc-unattributed", malformed: false })
		parsed.tree.delete()
	})

	it("keeps a body out of argv and out of the span (§13.3)", () => {
		const [command] = commandsOf("cat <<'E'\nbody\nE")
		expect(command.text).toBe("cat")
		expect(command.argv).not.toContain("body")
		expect(command.text).not.toContain("body")
	})
})

describe("§8.3 several bodies on one command", () => {
	/** Every `heredoc_redirect` in a parse, in source order. */
	function redirectsOf(command: string): { nodes: Node[]; delete: () => void } {
		const parsed = parseBash(command)
		if ("error" in parsed) throw new Error(`the parser could not read ${JSON.stringify(command)}`)
		const found: Node[] = []
		const visit = (node: Node): void => {
			if (node.type === "heredoc_redirect") found.push(node)
			for (const child of node.children) visit(child)
		}
		visit(parsed.tree.rootNode)
		return { nodes: found, delete: () => parsed.tree.delete() }
	}

	it("hands the bodies over in the order the redirects were handed to it", () => {
		// Two operators on one command (`cat <<'A' <<'B'`) is what §8.3 is about, but the grammar
		// returns an ERROR node for it, so the ordering rule is pinned on takeHeredoc directly: one
		// owner, two redirects, and the body list follows the calls rather than sorting itself.
		const { nodes, delete: release } = redirectsOf("cat <<'A'\none\nA\ncat <<'B'\ntwo\nB")
		const delimiter = (one: Node): string => (one.children.find((child) => child.type === "heredoc_start")?.text ?? "") as string
		expect(nodes.map(delimiter)).toEqual(["'A'", "'B'"])
		const owner: AstCommand = { argv: ["cat"], envVars: [], redirects: [], heredocs: [], text: "cat", start: 0, end: 3, connector: "", opaque: false }
		expect(takeHeredoc(nodes[1], owner)).toBeNull()
		expect(takeHeredoc(nodes[0], owner)).toBeNull()
		expect(owner.heredocs).toEqual(["two", "one"])
		expect(owner.argv).toEqual(["cat"])
		release()
	})
})

describe("§8.9 a body the walker cannot attribute", () => {
	it("calls a missing terminator line malformed", () => {
		expect(walkBash("cat <<'E'\nbody")).toMatchObject({ reason: "unterminated-heredoc", malformed: true })
		expect(walkBash("cat <<'A'\nbody\nB")).toMatchObject({ reason: "unterminated-heredoc", malformed: true })
		expect(walkBash("cat <<'E'\nbody\nE trailing")).toMatchObject({ reason: "unterminated-heredoc", malformed: true })
		expect(walkBash("cat <<'E'")).toMatchObject({ reason: "unterminated-heredoc", malformed: true })
	})

	it("calls an unclosed quote in the delimiter malformed", () => {
		expect(walkBash("cat <<'EOF")).toMatchObject({ reason: "unterminated-heredoc-delimiter", malformed: true })
		expect(walkBash('cat <<"EOF')).toMatchObject({ reason: "unterminated-heredoc-delimiter", malformed: true })
	})

	it("calls a pipeline on the delimiter line unattributed, which is not malformed", () => {
		expect(walkBash("cat <<'E' | wc -l\nx\nE")).toMatchObject({ kind: "unproven", reason: "heredoc-unattributed", malformed: false })
	})
})

// --------------------------------------------------------------------------- §8.6–§8.8 the mask

/** The body extent of the one heredoc in a fixture, the way the brace scan needs it. */
function bodyOf(input: string): BodySlice {
	const operator = input.indexOf("<<")
	const delimiter = readHeredocDelimiter(input, operator + 2)
	const hit = findHeredocTerminator(input, delimiter.end + 1, delimiter.delimiter, false, false)
	return { start: delimiter.end + 1, end: hit.bodyEnd }
}

describe("§8.6–§8.8 the mask the brace scan may be handed", () => {
	const JSON_BODY = "cat <<'E'\n{ \"key\": \"value\" }\nE"

	it("blanks a quoted body and nothing else, newlines kept", () => {
		const masked = maskedCopy(JSON_BODY, [bodyOf(JSON_BODY)])
		expect(masked).not.toBeNull()
		expect(masked?.length).toBe(JSON_BODY.length)
		expect(masked).toBe("cat <<'E'\n                  \nE")
	})

	it("refuses to mask when there is no body to mask", () => {
		expect(maskedCopy(JSON_BODY, [])).toBeNull()
	})

	it("throws away a mask that changes the constructs (§8.7)", () => {
		// Blank the command word instead of the body: the copy no longer parses to the same thing.
		expect(maskedCopy(JSON_BODY, [{ start: 0, end: 3 }])).toBeNull()
		// A range that runs past the terminator eats the line the body ends on.
		expect(maskedCopy(JSON_BODY, [{ start: 10, end: JSON_BODY.length }])).toBeNull()
		// A range that is not a body at all.
		expect(maskedCopy("echo hi", [{ start: 0, end: 4 }])).toBeNull()
	})

	it("lets the brace scan pass on a body of JSON while reporting the body as written", () => {
		const [command] = commandsOf(JSON_BODY)
		expect(command.heredocs).toEqual(['{ "key": "value" }']) // §8.8: never the blank
		expect(command.text).toBe("cat")
	})

	it("abandons masking altogether when any delimiter in the input is unquoted (§8.7)", () => {
		// The second heredoc is quoted and its braces would pass; the first one is not quoted, so the
		// mask never happens and the brace class the input earned stands.
		expect(walkBash("cat <<'E'\n{ \"a\": 1 }\nE\ncat <<F\n{ \"b\": 2 }\nF")).toMatchObject({ reason: "brace-with-quote" })
		expect(walkBash("cat <<F\n{ \"b\": 2 }\nF\ncat <<'E'\n{ \"a\": 1 }\nE")).toMatchObject({ reason: "brace-with-quote" })
	})

	it("abandons masking for a body whose terminator never appears (§8.7)", () => {
		expect(scanInput("cat <<'E'\n{ \"a\": 1 }")).toMatchObject({ reason: "unterminated-heredoc" })
	})

	it("abandons masking for a redirect it cannot account for (§8.7)", () => {
		// A pipeline written on the delimiter line: the body is quoted and inert, but the walker cannot
		// name its owner, so nothing is masked and the class the input as written earned stands — step 5
		// answers before §8.9 ever gets to say `heredoc-unattributed`.
		expect(scanInput("cat <<'E' | wc -l\n{ \"a\": 1 }\nE")).toMatchObject({ reason: "brace-with-quote" })
		expect(walkBash("cat <<'E' | wc -l\n{ \"a\": 1 }\nE")).toMatchObject({ reason: "brace-with-quote", malformed: false })
	})

	it("masks a tab-stripping body and still hands the tabs over (§8.2, §8.8)", () => {
		const [command] = commandsOf("cat <<-'E'\n\t{ \"a\": 1 }\n\tE")
		expect(command.heredocs).toEqual(['\t{ "a": 1 }\n\t'])
	})

	it("is invisible to every other scan (§8.6)", () => {
		// A control character inside an inert body is still refused: only the brace scan may be re-run.
		expect(walkBash("cat <<'E'\nx\u0001y\nE")).toMatchObject({ reason: "control-character", malformed: true })
		expect(walkBash("cat <<'E'\n\u00a0x\nE")).toMatchObject({ reason: "unicode-whitespace" })
		expect(walkBash("cat <<'E'\n~[x]\nE")).toMatchObject({ reason: "zsh-tilde-bracket" })
	})
})

// --------------------------------------------------------------------------- §2 steps 2–5, §10

/** §12 id from the scan module, or null when every scan passes. `string`, not `Reason`: `AstParse.reason` is declared `string` in bash-ast.ts. */
const scanned = (command: string): string | null => {
	const refusal = scanInput(command)
	return refusal === null ? null : refusal.reason
}

describe("§2 order: the first step that fires supplies the reason (§12.1)", () => {
	it("the cap comes before everything (§10.9)", () => {
		expect(scanned(`${"a".repeat(10_001)}`)).toBe("input-too-large")
		expect(scanned(`${"a".repeat(10_001)}'`)).toBe("input-too-large")
		expect(scanned("a".repeat(10_000))).toBeNull()
	})

	it("delimiter balance comes before accepted characters", () => {
		expect(scanned("echo 'oops\u0001")).toBe("unterminated-quote")
		expect(scanned("echo `oops\u0001")).toBe("unterminated-backtick")
	})

	it("accepted characters come before the cross-shell classes", () => {
		expect(scanned("echo {\"a\"} \u0007")).toBe("control-character")
		expect(scanned("cat ~[x] =bad")).toBe("zsh-tilde-bracket")
	})

	it("balance comes before the brace class, and the brace class before §8", () => {
		expect(scanned(`echo {"a" 'oops`)).toBe("unterminated-quote")
		// Balanced and inert-looking, but the delimiter is unquoted so there is no mask (§8.7): step 5
		// fires with what the input as written says, before §8.1 ever gets to refuse the delimiter.
		expect(scanned("cat <<E\n{ \"k\": 1 }\nE")).toBe("brace-with-quote")
		expect(walkBash("cat <<E\n{ \"k\": 1 }\nE")).toMatchObject({ reason: "brace-with-quote" })
		expect(walkBash("cat <<E\nnothing in the body\nE")).toMatchObject({ reason: "heredoc-unquoted-delimiter" })
	})
})

describe("§2 step 3 delimiter balance, each naming its own class (§10.6)", () => {
	it("quotes, backticks and the forms a `$` opens", () => {
		for (const command of [`echo "oops`, "echo 'oops", 'echo "a', `echo don't`]) {
			expect(scanned(command), command).toBe("unterminated-quote")
		}
		expect(scanned("echo `")).toBe("unterminated-backtick")
		expect(scanned("echo `ls")).toBe("unterminated-backtick")
		expect(scanned("echo $(oops")).toBe("unterminated-substitution")
		expect(scanned("echo ${oops")).toBe("unterminated-substitution")
		expect(scanned('echo "$(id')).toBe("unterminated-quote")
	})

	it("says nothing about delimiters that do close, however nested", () => {
		for (const command of [`echo "$(echo "hi")"`, "echo ${A:-${B:-x}}", `echo $( (ls) )`, "echo 'a\"b'", `echo "a'b"`, "echo a#b", "echo 'don''t'", `echo $'a\\'b'`, `echo $"greetings"`]) {
			expect(scanned(command), command).toBeNull()
		}
	})

	it("reads a `$` in front of a closing double quote as the character itself (§4)", () => {
		// A `$` with nothing expandable after it is a dollar sign, so the quote that follows is the one
		// that closes the string and nothing is unterminated.
		expect(scanned(`echo "$"`)).toBeNull()
		expect(walkBash(`echo "$"`)).toMatchObject({ kind: "simple", commands: [{ argv: ["echo", "$"] }] })
	})

	it("does not let the second half of `$$` open a string (§5.11)", () => {
		// `$$` is the shell's own id; the `"` after it closes the run the reference sits in. The other
		// special names of §5.11 sit in a string the same way, and `$'` inside double quotes opens
		// nothing because a bare `'` there does not open a string either.
		expect(scanned(`echo "v $$"`)).toBeNull()
		expect(walkBash(`echo "v $$"`)).toMatchObject({ kind: "simple", commands: [{ argv: ["echo", "v __TRACKED_VAR__"], opaque: true }] })
		for (const special of ["?", "!", "#", "-", "0", "$", "@", "*"]) {
			expect(scanned(`echo "x$${special}"`), special).toBeNull()
		}
		expect(scanned(`echo "$'"`)).toBeNull()
		expect(scanned(String.raw`echo "$\""`)).toBeNull()
		expect(scanned(`echo "$$HOME"`)).toBeNull()
		expect(walkBash(`echo "$$HOME"`)).toMatchObject({ kind: "simple", commands: [{ argv: ["echo", "__TRACKED_VAR__HOME"] }] })
	})

	it("takes a backslash inside single quotes as text, so the quote still closes (§4, §10.2)", () => {
		// Nothing is interpreted inside single quotes, not even a backslash: the second `'` ends the run.
		expect(scanned(`echo 'a\\'`)).toBeNull()
		expect(walkBash(`echo 'a\\'`)).toMatchObject({ kind: "simple", commands: [{ argv: ["echo", "a\\"] }] })
		expect(scanned(`echo a'b\\'c`)).toBeNull()
		expect(walkBash(`echo a'b\\'c`)).toMatchObject({ kind: "simple", commands: [{ argv: ["echo", "ab\\c"] }] })
		// An escaped quote inside an ANSI-C string is still an escape, and the run still has to close.
		expect(scanned(`printf $'a\\'b'`)).toBeNull()
		expect(scanned(`printf $'a\\'b`)).toBe("unterminated-quote")
	})

	it("still refuses a translated string written where a quote does open (§4.2)", () => {
		// `$"…"` is a real form in code position: the scan stays out of its way and the walker names it.
		expect(scanned(`echo $"x"`)).toBeNull()
		expect(walkBash(`echo $"x"`).kind).toBe("unproven")
		expect(walkBash(`echo $"x"`)).toMatchObject({ reason: "translated-string", malformed: false })
		expect(scanned(`echo $"oops`)).toBe("unterminated-quote")
	})

	it("reads a here-document body as data, not as quoting", () => {
		// An apostrophe inside an inert body is not an unclosed quote.
		expect(scanned("cat <<'E'\ndon't\nE")).toBeNull()
		expect(scanned("cat <<'E'\n\"unbalanced\nE")).toBeNull()
	})

	it("knows a here-string is not a here-document", () => {
		expect(scanned("grep x <<< \"a b\"")).toBeNull()
		expect(scanned("grep x <<< \"a")).toBe("unterminated-quote")
	})

	it("treats a comment as the end of the line", () => {
		expect(scanned("echo hi # don't worry")).toBeNull()
		expect(scanned("echo hi # (")).toBeNull()
	})
})

describe("§10.1–§10.2 accepted characters", () => {
	it("refuses control characters anywhere, carriage return included", () => {
		for (const bad of ["\u0000", "\u0001", "\u0008", "\u000b", "\u001f", "\u007f", "\r"]) {
			expect(scanned(`echo a${bad}b`), JSON.stringify(bad)).toBe("control-character")
		}
	})

	it("accepts the two control characters bash uses to separate words", () => {
		expect(scanned("echo a\tb")).toBeNull()
		expect(scanned("echo a\nb")).toBeNull()
	})

	it("refuses characters that read as a space and are word characters to bash", () => {
		for (const bad of ["\u00a0", "\u1680", "\u2002", "\u200b", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", "\ufeff"]) {
			expect(scanned(`echo ${bad}hi`), JSON.stringify(bad)).toBe("unicode-whitespace")
		}
	})
})

describe("§10.3–§10.5 constructs another shell would read differently", () => {
	it("refuses a backslash before a blank", () => {
		expect(scanned("echo one\\ two")).toBe("backslash-whitespace")
		expect(scanned("echo a\\\tb")).toBe("backslash-whitespace")
		expect(scanned("tr\\\naceroute")).toBe("backslash-whitespace")
	})

	it("accepts a backslash-newline that only separates commands (§10.1)", () => {
		expect(scanned("true && \\\n  false")).toBeNull()
		expect(scanned("true &&\\\nfalse")).toBeNull()
	})

	it("does not see escaped whitespace where nothing is escaped", () => {
		expect(scanned("echo 'a\\ b'")).toBeNull() // nothing is escaped inside single quotes
		expect(scanned("echo a\\\\b")).toBeNull() // the second backslash is the one that is escaped
		expect(scanned("find . -exec rm {} \\;")).toBeNull()
	})

	it("refuses another shell's directory syntax, anywhere in the input", () => {
		expect(scanned("cat ~[proj]/secrets")).toBe("zsh-tilde-bracket")
		expect(scanned("echo a ~[b] c ~[d]")).toBe("zsh-tilde-bracket")
	})

	it("refuses a word that begins with `=` and a name character", () => {
		expect(scanned("=curl http://x")).toBe("zsh-equals-expansion")
		expect(scanned("true && echo =bad")).toBe("zsh-equals-expansion")
		expect(scanned("ls ; =x")).toBe("zsh-equals-expansion")
	})

	it("does not see a leading `=` where the `=` is mid-word (§10.4)", () => {
		for (const command of ["VAR=1 cmd", "echo --flag=x", "echo a=b", "(( i = 1 ))", "[[ a == b ]]", "echo ${X:-y}", "echo =$HOME"]) {
			expect(scanned(command), command).toBeNull()
		}
	})

	it("refuses a brace group a quote sits inside", () => {
		expect(scanned('echo {"a"}')).toBe("brace-with-quote")
		expect(scanned("echo {a'}',b}")).toBe("brace-with-quote")
		expect(scanned('echo {a,"b"}')).toBe("brace-with-quote")
	})

	it("is not this class when the brace cannot open a group", () => {
		for (const command of [`echo -d '{"k":"v"}'`, `awk 'BEGIN{printf "%s\n", "hi"}' f`, "find . -exec rm {} \\;", "echo ${X-\"a\"}", `echo $'{a,b}'`, "echo hi # {a,\"b\"}"]) {
			expect(scanned(command), command).toBeNull()
		}
	})

	it("is not this class however many braces never close", () => {
		// A brace with no closing partner opens no group and expands nothing, and counting them one at
		// a time against every later character is not how this is decided.
		expect(scanned(`echo ${"{".repeat(4000)}`)).toBeNull()
		expect(scanned(`echo ${"{".repeat(4000)}${"}".repeat(4000)}`)).toBeNull()
		expect(scanned(`echo ${"{".repeat(4000)}"a"${"}".repeat(4000)}`)).toBe("brace-with-quote")
	})

	it("is not this class when no quote is involved, or no group can close", () => {
		expect(scanned("echo {a,b}")).toBeNull()
		expect(scanned("echo {a, b}")).toBeNull()
		expect(scanned(`echo {a"b"`)).toBeNull() // nothing closes the group, so nothing expands
		expect(scanned(`echo "a{b"`)).toBeNull()
	})
})

describe("the scans are only about the classes §10 names", () => {
	it("names malformed for the broken input and not for the cross-shell classes", () => {
		const malformed = ["unterminated-quote", "unterminated-backtick", "unterminated-substitution", "unterminated-heredoc", "unterminated-heredoc-delimiter", "control-character", "unicode-whitespace", "input-too-large"]
		for (const reason of malformed) {
			const command = {
				"unterminated-quote": "echo 'x",
				"unterminated-backtick": "echo `x",
				"unterminated-substitution": "echo $(x",
				"unterminated-heredoc": "cat <<'E'\nbody",
				"unterminated-heredoc-delimiter": "cat <<'E",
				"control-character": "echo a\u0001b",
				"unicode-whitespace": "echo\u00a0a",
				"input-too-large": "a".repeat(10_001),
			}[reason] as string
			const refusal = scanInput(command)
			expect(refusal, command).not.toBeNull()
			expect(refusal?.reason, command).toBe(reason)
			expect(refusal?.malformed, command).toBe(true)
		}
		for (const command of ["echo a\\ b", "cat ~[x]", "echo =x", 'echo {"x"}']) {
			expect(scanInput(command)?.malformed, command).toBe(false)
		}
	})

	it("reads a here-document inside a substitution as one (§8.6 shape)", () => {
		// The terminator line carries the `)` that closes the substitution: the body ends, nothing is
		// unbalanced, and what the command means is for the values module to say (§6).
		expect(scanned(`echo "$(cat <<'E'\n/etc/hosts\nE)"`)).toBeNull()
		// §6.6: a substitution whose whole content is `cat` with a quoted-delimiter heredoc has a known
		// value — the single-line body is the argument, so the path stays visible to the caller.
		expect(walkBash(`echo "$(cat <<'E'\n/etc/hosts\nE)"`)).toMatchObject({
			kind: "simple",
			commands: [{ argv: ["echo", "/etc/hosts"], opaque: false }],
		})
	})

	it("does not need the parser to decide anything it can read (§2.1)", () => {
		// Same refusal with and without a tree behind it: these are characters, not structure.
		for (const command of ["echo a\\ b", "cat ~[x]", 'echo {"a"}', "echo 'x"]) {
			expect(scanned(command)).toBe(walkBash(command).kind === "unproven" ? (walkBash(command) as { reason: Reason }).reason : null)
		}
	})
})
