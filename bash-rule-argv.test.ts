import { describe, expect, it } from "vitest"
import { bashRuleCoversArgv, ruleArgv, ruleSpecifier } from "./bash-rule-argv.ts"
import { permissionRuleValueFromString } from "./permission-rule-parser.ts"
import type { PermissionBehavior, PermissionRule } from "./permissions.ts"

/**
 * The matcher W3 builds `permissions.ts` onto: one already-parsed argv, one rule, yes or no.
 *
 * argv here is written the way the walker emits it — command word first, one entry per argument,
 * quoting already resolved — so every expectation below is about *arguments*, never about how the
 * command happened to be typed. Rules go through the real parser
 * (`permissionRuleValueFromString`) rather than being hand-built, because half of what is being
 * pinned is what a specifier written into a permissions.json turns into.
 */

function ruleFor(spec: string, behavior: PermissionBehavior = "allow"): PermissionRule {
	return { source: "project", behavior, ruleValue: permissionRuleValueFromString(spec) }
}

/** `Bash(<spec>)` covering argv? */
const covers = (spec: string, argv: string[]): boolean => bashRuleCoversArgv(ruleFor(`Bash(${spec})`), argv)

describe("exact specifier: its own words, positionally, from the command word", () => {
	it("covers exactly the argv it names", () => {
		expect(covers("git status", ["git", "status"])).toBe(true)
	})

	it("refuses an argv shorter than the words it names", () => {
		expect(covers("git status", ["git"])).toBe(false)
		expect(covers("git commit -m msg", ["git", "commit", "-m"])).toBe(false)
	})

	it("refuses a different word in any position", () => {
		expect(covers("git status", ["git", "log"])).toBe(false)
		expect(covers("git status", ["git", "statusx"])).toBe(false)
		// A rule is compared word by word, never as a string prefix of the joined arguments:
		// "git status extra" begins with the text "git status " but its second word is not "status".
		expect(covers("git status", ["git", "status extra"])).toBe(false)
	})

	it("is anchored at the command word — the rule's words may not start mid-argv", () => {
		expect(covers("git status", ["sudo", "git", "status"])).toBe(false)
		expect(covers("git status", ["echo", "git", "&&", "git", "status"])).toBe(false)
	})

	it("resolves the quoting of the rule, so quoting style stops mattering", () => {
		const argv = ["git", "commit", "-m", "fix wip"]
		expect(covers('git commit -m "fix wip"', argv)).toBe(true)
		expect(covers("git commit -m 'fix wip'", argv)).toBe(true)
		expect(covers("git commit -m fix\\ wip", argv)).toBe(true)
		// …but two arguments stay two arguments: the rule names one word, the call passes two.
		expect(covers('git commit -m "fix wip"', ["git", "commit", "-m", "fix", "wip"])).toBe(false)
	})

	it("compares case-sensitively, as the text matcher always did", () => {
		expect(covers("Git status", ["git", "status"])).toBe(false)
		expect(covers("Git status", ["Git", "status"])).toBe(true)
	})
})

describe("prefix rules (`:*`) keep today's meaning, with no silent widening", () => {
	it("cover the program alone and the program with arguments", () => {
		expect(covers("git:*", ["git"])).toBe(true)
		expect(covers("git:*", ["git", "status"])).toBe(true)
		expect(covers("git status:*", ["git", "status"])).toBe(true)
		expect(covers("git status:*", ["git", "status", "-uno"])).toBe(true)
	})

	it("do not reach past the word they end on", () => {
		expect(covers("git:*", ["gitk", "log"])).toBe(false)
		expect(covers("git status:*", ["git", "statusx"])).toBe(false)
		expect(covers("npm run:*", ["npm", "runner"])).toBe(false)
		expect(covers("git status:*", ["git"])).toBe(false)
	})

	it("do not cover the same invocation behind xargs — a deliberate narrowing", () => {
		// The text matcher lets `git status:*` cover `xargs git status …`, because it matched strings
		// and had an explicit allowance for the `xargs ` prefix. Here the argv would have to start with
		// the rule's words, and it starts with `xargs` — whose trailing arguments arrive from a pipe at
		// run time, which is why xargs is on the broad-rule list dangerous-permissions.ts strips.
		expect(covers("git status:*", ["xargs", "git", "status"])).toBe(false)
	})
})

describe("a rule that names fewer words than the call still covers it (the deliberate loosening)", () => {
	it("covers a call with arguments the rule never named", () => {
		// The footgun this fixes: `Bash(bash x.sh)` used to match only the bare two-word call, and the
		// port run wrote that up as syntax a user had to learn. Every word the rule names matches
		// positionally here, so the rule means what it looks like it means.
		expect(covers("bash x.sh", ["bash", "x.sh"])).toBe(true)
		expect(covers("bash x.sh", ["bash", "x.sh", "arg"])).toBe(true)
		expect(covers("pi --help", ["pi", "--help", "--tools", "read"])).toBe(true)
	})

	it("runs one way only: never towards words the rule did not name", () => {
		// Where that loosening lands on a destructive verb, spelled out: approving this exact rm also
		// approves the same rm with extra flags, and still nothing with a different target.
		expect(covers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x", "--one-file-system"])).toBe(true)
		expect(covers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/y"])).toBe(false)
		expect(covers("rm -rf /tmp/x", ["rm", "-rf"])).toBe(false)
	})
})

describe("wildcard specifiers keep shell-rule-matching.ts semantics", () => {
	it("cover the bare text a trailing ` *` was always lenient about", () => {
		expect(covers("git *", ["git"])).toBe(true)
		expect(covers("git *", ["git", "status"])).toBe(true)
		expect(covers("npm run *", ["npm", "run"])).toBe(true)
		expect(covers("npm run *", ["npm", "run", "test"])).toBe(true)
		expect(covers("git *", ["gitk"])).toBe(false)
	})

	it("stay character-level: a star spans characters inside one argument", () => {
		expect(covers("git ch*", ["git", "checkout"])).toBe(true)
		expect(covers("git ch*", ["git", "switch"])).toBe(false)
	})

	it("still order the pieces a glob names", () => {
		expect(covers("git * main", ["git", "checkout", "main"])).toBe(true)
		expect(covers("git * main", ["git", "main", "checkout"])).toBe(false)
	})

	it("keep the two-star rule about which bare calls are covered", () => {
		// From the glob engine's own contract: only a single trailing ` *` also covers the text without
		// it. With two stars, `npm x run` has no room for the space the second piece needs.
		expect(covers("npm * run *", ["npm", "x", "run"])).toBe(false)
		expect(covers("npm * run *", ["npm", "x", "run", "test"])).toBe(true)
		expect(covers("npm * run *", ["npmx", "run", "test"])).toBe(false)
	})

	it("read an escaped star as a star in the data, not as a wildcard", () => {
		expect(covers("echo a\\*b", ["echo", "a*b"])).toBe(true)
		expect(covers("echo a\\*b", ["echo", "axb"])).toBe(false)
	})
})

describe("broad rules, empty specifiers, empty calls", () => {
	it("a tool-wide Bash rule covers any argv with a word in it", () => {
		// Not a hole opened here: entering auto mode strips blanket bash rules first
		// (dangerous-permissions.ts), so this branch only fires where the user already wrote an
		// unconditioned allow — which is what `Bash` has always meant.
		for (const spec of ["Bash", "Bash()", "Bash(*)", "Bash( *)"]) {
			expect(bashRuleCoversArgv(ruleFor(spec), ["make", "coffee"]), spec).toBe(true)
		}
	})

	it("does not rescue a rule the rule parser could not read as a call", () => {
		// Text after the closing paren means this is not `Bash(...)` at all but one odd tool name
		// (permission-rule-parser's documented reading), so it authorises nothing anywhere.
		expect(bashRuleCoversArgv(ruleFor("Bash(*) "), ["make", "coffee"])).toBe(false)
	})

	it("never cover an argv with no words in it", () => {
		for (const spec of ["Bash", "Bash()", "Bash(*)", "Bash(git:*)", "Bash(git *)", "Bash(git status)"]) {
			expect(bashRuleCoversArgv(ruleFor(spec), []), spec).toBe(false)
		}
	})

	it("name nothing when they hold only whitespace, and so cover nothing", () => {
		// `Bash( )` is not the tool-wide rule: it is a specifier that failed to name a command word,
		// and the fail-closed reading of a rule that means nothing is "does not authorise".
		expect(covers(" ", ["git", "status"])).toBe(false)
		expect(covers("   ", ["git"])).toBe(false)
	})
})

describe("specifiers that are not an argument list cover nothing", () => {
	// These are allow rules the matcher refuses to interpret. The command still reaches the gate, so
	// the cost is one prompt. Deny and ask rules of the same shape are untouched: they stay textual in
	// permissions.ts precisely so a deny fires when there is no trustworthy argv.
	const NOT_ARGV = [
		"git status && rm -rf /",
		"git status; rm -rf /",
		"echo $(whoami)",
		"echo $HOME",
		"echo `id`",
		"diff <(a) <(b)",
		"echo 'unterminated",
		'echo "unterminated',
		"echo a\\\nb", // a line break outside quotes ends the command
		"git status\necho done",
		"echo (x)",
	]
	for (const spec of NOT_ARGV) {
		it(`refuses ${JSON.stringify(spec)}`, () => {
			expect(covers(spec, ["git", "status"])).toBe(false)
			expect(ruleArgv(ruleFor(`Bash(${spec})`)), spec).toBeNull()
		})
	}

	it("keeps a line break that sits inside quotes as data", () => {
		const argv = ["git", "commit", "-m", "line one\nline two"]
		expect(covers('git commit -m "line one\nline two"', argv)).toBe(true)
	})

	it("leads with an assignment the walker would have reported separately", () => {
		// `FOO=bar git status` reaches the matcher as argv ["git","status"] plus envVars, so a rule
		// spelled with the assignment in front matches nothing. Left as a narrow rule rather than
		// silently re-adding a scanner for assignments: whoever wires this decides with AstCommand.envVars.
		expect(covers("FOO=bar git status", ["git", "status"])).toBe(false)
		expect(ruleArgv(ruleFor("Bash(FOO=bar git status)"))).toEqual(["FOO=bar", "git", "status"])
	})
})

describe("ruleArgv: the specifier in normal form", () => {
	it("words, quoting resolved, whitespace runs collapsed", () => {
		expect(ruleArgv(ruleFor("Bash(git status)"))).toEqual(["git", "status"])
		expect(ruleArgv(ruleFor("Bash(git   status\t--porcelain)"))).toEqual(["git", "status", "--porcelain"])
		expect(ruleArgv(ruleFor("Bash(git status:*)"))).toEqual(["git", "status"])
		expect(ruleArgv(ruleFor('Bash(git commit -m "fix wip")'))).toEqual(["git", "commit", "-m", "fix wip"])
		expect(ruleArgv(ruleFor("Bash(git commit -m fix\\ wip)"))).toEqual(["git", "commit", "-m", "fix wip"])
		expect(ruleArgv(ruleFor("Bash(git commit -m \"\")"))).toEqual(["git", "commit", "-m", ""])
		expect(ruleArgv(ruleFor("Bash(echo a\\*b)"))).toEqual(["echo", "a*b"])
	})

	it("is null for a specifier that describes no single argv", () => {
		expect(ruleArgv(ruleFor("Bash"))).toBeNull()
		expect(ruleArgv(ruleFor("Bash(git *)"))).toBeNull()
		expect(ruleArgv(ruleFor("Bash(git commit -m *)"))).toBeNull()
	})

	it("is an empty list for a specifier that names no word", () => {
		expect(ruleArgv(ruleFor("Bash( )"))).toEqual([])
	})

	it("is null for a rule that is not about bash", () => {
		expect(ruleArgv(ruleFor("Read(src/a.ts)"))).toBeNull()
		expect(bashRuleCoversArgv(ruleFor("Read(git status)"), ["git", "status"])).toBe(false)
	})
})

describe("strict operands: an exact specifier has to name every word", () => {
	// The caller holds layer 0's verdict; the matcher only holds the flag. `covers` above stays W2's
	// contract, so both directions are pinned here — the narrowing is opt-in per call, not a redefinition
	// of what a specifier means, and a caller with no verdict (or a command whose risk is not set by its
	// targets) keeps exactly the behaviour it has always had.
	const strictCovers = (spec: string, argv: string[]): boolean =>
		bashRuleCoversArgv(ruleFor(`Bash(${spec})`), argv, { strictOperands: true })

	it("refuses a call with a word the rule does not name", () => {
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x", "--verbose"])).toBe(false)
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x", "/tmp/z"])).toBe(false)
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x", "extra"])).toBe(false)
		// the same rule in non-strict mode is the loosening W2 pinned, unchanged
		expect(covers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x", "--verbose"])).toBe(true)
	})

	it("covers the argv it names, word for word", () => {
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x"])).toBe(true)
		expect(strictCovers("rm -rf /tmp/x /tmp/z", ["rm", "-rf", "/tmp/x", "/tmp/z"])).toBe(true)
		expect(strictCovers('git commit -m "fix wip"', ["git", "commit", "-m", "fix wip"])).toBe(true)
	})

	it("still refuses fewer words and different words", () => {
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf"])).toBe(false)
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/y"])).toBe(false)
	})

	it("compares arguments, never the joined text", () => {
		// "rm -rf /tmp/x extra" begins with the text "rm -rf /tmp/x ", and its fourth word is not a target
		// the rule named — equality is positional per argument, as prefix coverage always was.
		expect(strictCovers("rm -rf /tmp/x", ["rm", "-rf", "/tmp/x extra"])).toBe(false)
		expect(strictCovers("rm -rf /tmp/x extra", ["rm", "-rf", "/tmp/x", "extra"])).toBe(true)
	})

	it("leaves a `:*` prefix rule alone, because that breadth is the rule's own wording", () => {
		// `compound-allow-and.test.ts` pins Bash(rm:*) covering `rm -rf /x`: a prefix rule says "and
		// anything after this", which is authority the user typed. Strict operands forbid a specifier that
		// stops mid-invocation and still authorises the rest of it — not one that asks for the rest.
		expect(strictCovers("rm:*", ["rm", "-rf", "/tmp/x"])).toBe(true)
		expect(strictCovers("git reset:*", ["git", "reset", "--hard"])).toBe(true)
		expect(strictCovers("rm:*", ["rmk", "-rf"])).toBe(false)
	})

	it("leaves a glob alone for the same reason", () => {
		expect(strictCovers("rm *", ["rm", "-rf", "/tmp/x", "/tmp/z"])).toBe(true)
		expect(strictCovers("rm -rf /*", ["rm", "-rf", "/tmp/x"])).toBe(true)
		expect(strictCovers("rm -rf /*", ["rm", "-rfx", "/tmp/x"])).toBe(false)
	})

	it("leaves the tool-wide rule alone: it already names everything", () => {
		for (const spec of ["Bash", "Bash()", "Bash(*)", "Bash( *)"]) {
			expect(bashRuleCoversArgv(ruleFor(spec), ["rm", "-rf", "/x", "/y"], { strictOperands: true }), spec).toBe(
				true,
			)
		}
	})

	it("never covers an empty argv, strict or not", () => {
		expect(bashRuleCoversArgv(ruleFor("Bash(rm -rf /tmp/x)"), [], { strictOperands: true })).toBe(false)
		expect(bashRuleCoversArgv(ruleFor("Bash(rm:*)"), [], { strictOperands: true })).toBe(false)
	})

	it("is the same positional walk with one condition added, so quoting rules carry over", () => {
		// resolution happens on both sides exactly as before: the rule's quotes are not compared as characters
		expect(strictCovers("rm -rf '/tmp/a dir'", ["rm", "-rf", "/tmp/a dir"])).toBe(true)
		expect(strictCovers('rm -rf "tmp/a dir"', ["rm", "-rf", "/tmp/a dir"])).toBe(false)
	})
})

describe("what the matcher deliberately does not decide", () => {
	it("matches a walker placeholder like any other word", () => {
		// The walker hands over `__CMDSUB_OUTPUT__` where a value is only known at run time and flags
		// the command `opaque`. Covering it here is the same call the text matcher already makes for a
		// single segment (pinned as a known exposure in compound-allow-and.test.ts); closing it belongs
		// to the caller, which is holding `opaque`, not to a function that sees only argv.
		expect(covers("git log:*", ["git", "log", "__CMDSUB_OUTPUT__"])).toBe(true)
	})

	it("sees through no wrapper, because it strips nothing", () => {
		// `nohup pi --help` is argv ["nohup","pi","--help"]: `nohup` is the command word. A caller that
		// wants `Bash(pi *)` to reach it has to unwrap where argv is produced (layer 0 knows wrappers);
		// re-adding a wrapper table here is the duplicate analyser this module exists to delete.
		expect(covers("pi *", ["nohup", "pi", "--help"])).toBe(false)
		expect(covers("pi *", ["pi", "--help"])).toBe(true)
	})
})

describe("a redirect target is part of the invocation a rule names", () => {
	// `coverage.targets` is the leg's own file targets, in the shape the walker reports them (`>` carries
	// no descriptor until the command writes one). Everything below is the truth table in this module's
	// header, asserted in both directions: what the clause lets a rule cover, and — the part that matters
	// for safety — what it stops it from covering.
	const t = (op: string, target: string, fd?: number) => (fd === undefined ? { op, target } : { op, target, fd })
	const withTarget = (spec: string, argv: string[], ...targets: Array<{ op: string; target: string; fd?: number }>) =>
		bashRuleCoversArgv(ruleFor(`Bash(${spec})`), argv, { targets })

	it("covers the invocation it names, words and file both equal", () => {
		expect(withTarget("echo hi > /tmp/out.txt", ["echo", "hi"], t(">", "/tmp/out.txt"))).toBe(true)
		expect(withTarget("git log > report.txt", ["git", "log"], t(">", "report.txt"))).toBe(true)
		expect(withTarget("cat < /etc/shadow", ["cat"], t("<", "/etc/shadow"))).toBe(true)
	})

	it("refuses a different file, however similar", () => {
		expect(withTarget("echo hi > /tmp/out.txt", ["echo", "hi"], t(">", "/tmp/out.txt2"))).toBe(false)
		expect(withTarget("echo hi > /tmp/out.txt", ["echo", "hi"], t(">", "~/.ssh/authorized_keys"))).toBe(false)
		// …and the whole point of the task: the rule that covers the scratch write does not cover the key write.
		expect(withTarget("echo key >> /tmp/log", ["echo", "key"], t(">>", "~/.ssh/authorized_keys"))).toBe(false)
	})

	it("refuses the same file reached by a different operator — append is not truncate", () => {
		expect(withTarget("cat x >> /tmp/log", ["cat", "x"], t(">", "/tmp/log"))).toBe(false)
		expect(withTarget("cat x > /tmp/log", ["cat", "x"], t(">>", "/tmp/log"))).toBe(false)
		// `>|` forces past noclobber and `&>` takes both streams: neither is the operator that was approved.
		expect(withTarget("echo hi >| /tmp/x", ["echo", "hi"], t(">", "/tmp/x"))).toBe(false)
		expect(withTarget("cmd &> /tmp/x", ["cmd"], t(">", "/tmp/x"))).toBe(false)
		expect(withTarget("echo hi >| /tmp/x", ["echo", "hi"], t(">|", "/tmp/x"))).toBe(true)
	})

	it("refuses the same file on a different descriptor, and equates the two spellings of one descriptor", () => {
		// `> f` means stdout; a rule for it never covers `2> f`, whose file receives stderr.
		expect(withTarget("echo hi > /tmp/x", ["echo", "hi"], t(">", "/tmp/x", 2))).toBe(false)
		// `1>` is what bash means by `>`, so the two spellings of the rule are one rule.
		expect(withTarget("echo hi 1> /tmp/x", ["echo", "hi"], t(">", "/tmp/x"))).toBe(true)
		expect(withTarget("echo hi > /tmp/x", ["echo", "hi"], t(">", "/tmp/x", 1))).toBe(true)
		expect(withTarget("cat 0< /etc/x", ["cat"], t("<", "/etc/x"))).toBe(true)
	})

	it("refuses a call with a target the rule did not name, and one it named but the call lacks", () => {
		expect(withTarget("echo hi > /tmp/a", ["echo", "hi"], t(">", "/tmp/a"), t(">", "/tmp/b"))).toBe(false)
		expect(withTarget("echo hi > /tmp/a > /tmp/b", ["echo", "hi"], t(">", "/tmp/a"))).toBe(false)
		// Both named, in either written order: bash opens both and the order of two independent opens is
		// not a fact a rule should have to guess.
		expect(withTarget("echo hi > /tmp/a > /tmp/b", ["echo", "hi"], t(">", "/tmp/b"), t(">", "/tmp/a"))).toBe(true)
		// …and a target written twice is not covered by a rule that names it once.
		expect(withTarget("echo hi > /tmp/a", ["echo", "hi"], t(">", "/tmp/a"), t(">", "/tmp/a"))).toBe(false)
	})

	it("names the words too: a clause makes the specifier a whole invocation, never a prefix", () => {
		expect(withTarget("echo hi > /tmp/x", ["echo", "hi", "there"], t(">", "/tmp/x"))).toBe(false)
		expect(withTarget("echo hi > /tmp/x", ["echo"], t(">", "/tmp/x"))).toBe(false)
		// `strictOperands` is not what makes this equality — the clause is, so the narrowing holds for a
		// non-target-bearing verdict as well (`echo hi > ./notes.txt` is `write_project`, allow tier).
		expect(withTarget("echo hi > /tmp/x", ["echo", "hi"], t(">", "/tmp/x"))).toBe(true)
	})

	it("stops every target-less specifier from covering a command that redirects", () => {
		// This is the tightening that makes the tightening above safe. `Bash(echo:*)` covering
		// `echo hi > ~/.ssh/authorized_keys` is the over-grant AGENTS.md names for the suggestion engine;
		// here it stops being true of the matcher that has to honour the rule.
		for (const op of [">", ">>", "<"]) {
			const targets = [t(op, "/tmp/out.txt")]
			for (const spec of ["echo hi", "echo hi:*", "echo *", "echo hi *", "git * main"]) {
				expect(bashRuleCoversArgv(ruleFor(`Bash(${spec})`), ["echo", "hi"], { targets }), `${spec} ${op}`).toBe(false)
			}
		}
	})

	it("leaves the tool-wide rule alone, because it is not a reading of one approval", () => {
		// `Bash` / `Bash()` / `Bash(*)` have no specifier to name a target in, mean "every bash command"
		// in the user's own words, and are stripped before auto mode (dangerous-permissions.ts). Refusing
		// them would make the blanket rule mean less than it says without ever refusing a target.
		for (const spec of ["Bash", "Bash()", "Bash(*)"]) {
			expect(bashRuleCoversArgv(ruleFor(spec), ["echo", "hi"], { targets: [t(">", "/tmp/x")] }), spec).toBe(true)
		}
	})

	it("lets a prefix rule carry no clause: `x > f:*` names nothing", () => {
		// `:*` is read off the END of the specifier text before any of this runs, so the clause sits inside
		// the prefix. Honouring it would make "any arguments" also mean "any file", which is the reading the
		// task refuses; reading it as words would silently drop the file. It authorises nothing instead.
		expect(withTarget("echo hi > /tmp/x:*", ["echo", "hi"], t(">", "/tmp/x"))).toBe(false)
		expect(withTarget("echo hi > /tmp/x:*", ["echo", "hi", "extra"], t(">", "/tmp/x"))).toBe(false)
	})

	it("reads a quoted or escaped operator as a word shaped like a redirect, not as a clause", () => {
		// `echo "a>b"` runs one argument whose text is `a>b`. A specifier that read the quoted `>` as an
		// operator would turn a harmless rule into a rule about a file — so quoting decides, exactly as it
		// decides everywhere else in this module.
		expect(covers('echo "a>b"', ["echo", "a>b"])).toBe(true)
		expect(covers("echo a\\>b", ["echo", "a>b"])).toBe(true)
		expect(covers("'echo' '>' b", ["echo", ">", "b"])).toBe(true)
		// …and those rules say nothing about a command that really redirects to `b`.
		expect(withTarget('echo "a>b"', ["echo"], t(">", "b"))).toBe(false)
		expect(withTarget("echo a\\>b", ["echo"], t(">", "b"))).toBe(false)
	})

	it("reads an unquoted operator wherever it sits, including fused to a word", () => {
		// `cat /etc/passwd>/tmp/x` is `cat /etc/passwd` writing `/tmp/x` — what the text says is what the
		// rule means. Position is free for the same reason: `echo > f hi` is `echo hi > f`.
		expect(withTarget("cat /etc/passwd>/tmp/x", ["cat", "/etc/passwd"], t(">", "/tmp/x"))).toBe(true)
		expect(withTarget("echo > /tmp/x hi", ["echo", "hi"], t(">", "/tmp/x"))).toBe(true)
		expect(withTarget("echo hi > /tmp/x", ["echo", "hi"], t(">", "/tmp/x"))).toBe(true)
	})

	it("resolves the target's quoting exactly as it resolves an argument's", () => {
		expect(withTarget('echo hi > "my file.txt"', ["echo", "hi"], t(">", "my file.txt"))).toBe(true)
		expect(withTarget("echo hi > my\\ file.txt", ["echo", "hi"], t(">", "my file.txt"))).toBe(true)
		expect(withTarget("echo hi > 'my file.txt'", ["echo", "hi"], t(">", "my file.txt"))).toBe(true)
		expect(withTarget("echo hi > my file.txt", ["echo", "hi"], t(">", "my file.txt"))).toBe(false)
	})

	it("still refuses a specifier that is not one argument list, redirects included", () => {
		for (const spec of [
			"echo hi > /tmp/x && rm -rf /", // a separator on the far side of the clause
			"echo hi > /tmp/x; rm -rf /",
			"echo hi > $(echo /tmp/x)", // a target decided at run time is not a target the rule named
			"echo hi > $TARGET",
			"echo hi >", // an operator with nothing behind it names no file
			"echo hi > > /tmp/x", // two operators in a row: no word to attach them to
			"echo hi > /tmp/x\nrm -rf /", // a bare line break ends the command
			"echo hi << EOF", // a here-document body is not a target a rule can name
			"echo hi ><> /tmp/x", // `<>` is refused by the walker, so no rule may mean it either
			"cat <(ls) > x", // process substitution: `(` is structure
		]) {
			expect(withTarget(spec, ["echo", "hi"], t(">", "/tmp/x")), JSON.stringify(spec)).toBe(false)
			expect(ruleSpecifier(ruleFor(`Bash(${spec})`)), JSON.stringify(spec)).toBeNull()
		}
	})

	it("keeps the argv-only contract for a leg with no file target", () => {
		// A descriptor dup (`2>&1`) moves no file, so a leg carrying only one is scored on its words alone
		// — the decision W9 pinned, unpicked: `Bash(make:*)` still covers `make 2>&1 | tail -50`.
		expect(covers("make:*", ["make"])).toBe(true)
		expect(withTarget("make:*", ["make"])).toBe(true)
		// and a rule that names a target does not cover a command that writes none
		expect(covers("echo hi > /tmp/x", ["echo", "hi"])).toBe(false)
	})

	it("is told the targets in either form, since the comparison is canonical", () => {
		// bash-audit hands over canonical targets (`>` resolved to fd 1); a caller that passed the walker's
		// raw redirect instead must get the same answer, or the canonicalisation is a trap.
		const raw = { op: ">", target: "/tmp/x" }
		const canonical = { op: ">", target: "/tmp/x", fd: 1 }
		for (const target of [raw, canonical]) {
			expect(withTarget("echo hi > /tmp/x", ["echo", "hi"], target)).toBe(true)
			expect(withTarget("echo hi 1> /tmp/x", ["echo", "hi"], target)).toBe(true)
		}
	})

	it("is unaffected when the caller states no targets at all, which is the fail-closed reading", () => {
		// A caller without a parse says nothing about redirects; that must not be read as "the command
		// redirects nowhere" for a rule that names a file, so a clause-carrying rule covers nothing here.
		expect(covers("echo hi > /tmp/x", ["echo", "hi"])).toBe(false)
		expect(covers("echo hi", ["echo", "hi"])).toBe(true)
	})
})

describe("ruleSpecifier: what a rule names, targets included", () => {
	it("separates the words from the files, both resolved", () => {
		expect(ruleSpecifier(ruleFor("Bash(git status)"))).toEqual({ words: ["git", "status"], targets: [] })
		expect(ruleSpecifier(ruleFor("Bash(echo hi > /tmp/out.txt)"))).toEqual({
			words: ["echo", "hi"],
			targets: [{ op: ">", fd: 1, target: "/tmp/out.txt" }],
		})
		expect(ruleSpecifier(ruleFor("Bash(cat a >> 'b c' 2> err.log)"))).toEqual({
			words: ["cat", "a"],
			targets: [
				{ op: ">>", fd: 1, target: "b c" },
				{ op: ">", fd: 2, target: "err.log" },
			],
		})
	})

	it("is the words alone for ruleArgv, which is why it is not a coverage question", () => {
		// Pinned so nobody reads `ruleArgv` as "everything this rule authorises": for a clause-carrying
		// specifier the file is the half that decides the harm.
		expect(ruleArgv(ruleFor("Bash(echo hi > /tmp/out.txt)"))).toEqual(["echo", "hi"])
		expect(ruleArgv(ruleFor("Bash(echo hi > /tmp/out.txt)"))).not.toContain("/tmp/out.txt")
	})
})
