import { describe, expect, it } from "vitest"
import {
	hasWildcards,
	matchWildcardPattern,
	permissionRuleExtractPrefix,
	parsePermissionRule,
	matchShellRule,
} from "./shell-rule-matching.ts"

describe("shell-rule-matching", () => {
	it("parses legacy prefix syntax", () => {
		expect(parsePermissionRule("npm run:*")).toEqual({
			type: "prefix",
			prefix: "npm run",
		})
	})

	it("parses wildcard syntax", () => {
		expect(parsePermissionRule("npm run *")).toEqual({
			type: "wildcard",
			pattern: "npm run *",
		})
	})

	it("matches wildcard in middle", () => {
		expect(matchWildcardPattern("* install", "npm install")).toBe(true)
		expect(matchWildcardPattern("* install", "yarn install")).toBe(true)
	})

	it("matches prefix with word boundary", () => {
		const rule = parsePermissionRule("git:*")
		expect(matchShellRule(rule, "git status", "prefix", true)).toBe(true)
		expect(matchShellRule(rule, "github", "prefix", true)).toBe(false)
	})
})

describe("permissionRuleExtractPrefix", () => {
	it("takes the text before the :* marker", () => {
		expect(permissionRuleExtractPrefix("npm run:*")).toBe("npm run")
		expect(permissionRuleExtractPrefix("ls:*")).toBe("ls")
	})

	it("returns null when the marker is absent", () => {
		expect(permissionRuleExtractPrefix("git status")).toBeNull()
		expect(permissionRuleExtractPrefix("npm run *")).toBeNull()
		expect(permissionRuleExtractPrefix("")).toBeNull()
	})

	it("requires something in front of the marker", () => {
		expect(permissionRuleExtractPrefix(":*")).toBeNull()
	})

	it("keeps everything up to the last :*", () => {
		expect(permissionRuleExtractPrefix("a:*:*")).toBe("a:*")
		expect(permissionRuleExtractPrefix("git * :*")).toBe("git * ")
	})

	it("stays on one line", () => {
		expect(permissionRuleExtractPrefix("git commit\n-am:*",)).toBeNull()
	})
})

describe("hasWildcards", () => {
	it("finds a bare star", () => {
		expect(hasWildcards("npm run *")).toBe(true)
		expect(hasWildcards("* install")).toBe(true)
		expect(hasWildcards("a*b*c")).toBe(true)
	})

	it("says no for text with no star at all", () => {
		expect(hasWildcards("git status")).toBe(false)
		expect(hasWildcards("")).toBe(false)
	})

	it("does not read the :* prefix marker as a wildcard", () => {
		expect(hasWildcards("git:*")).toBe(false)
		expect(hasWildcards("npm run:*")).toBe(false)
	})

	it("ignores a star the author escaped", () => {
		expect(hasWildcards("echo \\*")).toBe(false)
		expect(hasWildcards("echo \\*\\*")).toBe(false)
	})

	it("treats a star after an escaped backslash as bare", () => {
		expect(hasWildcards("path\\\\*")).toBe(true)
	})
})

describe("matchWildcardPattern — literal characters", () => {
	it("matches an escaped star as a star in the text", () => {
		expect(matchWildcardPattern("echo \\*", "echo *")).toBe(true)
		expect(matchWildcardPattern("echo \\*", "echo hi")).toBe(false)
	})

	it("matches an escaped backslash as one backslash", () => {
		expect(matchWildcardPattern("a\\\\b", "a\\b")).toBe(true)
		expect(matchWildcardPattern("a\\\\b", "ab")).toBe(false)
	})

	it("keeps the star live after an escaped backslash", () => {
		expect(matchWildcardPattern("path\\\\*", "path\\to")).toBe(true)
		expect(matchWildcardPattern("path\\\\*", "path\\")).toBe(true)
		expect(matchWildcardPattern("path\\\\*", "pathtox")).toBe(false)
		expect(matchWildcardPattern("path*", "path/to/file")).toBe(true)
	})

	it("leaves a backslash that escapes nothing as plain text", () => {
		expect(matchWildcardPattern("a\\db", "a\\db")).toBe(true)
		expect(matchWildcardPattern("a\\db", "adb")).toBe(false)
	})

	it("accepts a lone trailing backslash", () => {
		expect(matchWildcardPattern("dir\\", "dir\\")).toBe(true)
		expect(matchWildcardPattern("dir\\", "dir")).toBe(false)
	})

	it("treats every regex metacharacter as itself", () => {
		const literals = [
			"a.b",
			"a+b",
			"a?b",
			"(a)",
			"[ab]",
			"end$",
			"^start",
			"a|b",
			"a{2}",
			"n$d",
			"quote'ship",
			'double"quote',
		]
		for (const pattern of literals) {
			expect(matchWildcardPattern(pattern, pattern)).toBe(true)
		}
		expect(matchWildcardPattern("a.b", "axb")).toBe(false)
		expect(matchWildcardPattern("a+b", "aab")).toBe(false)
		expect(matchWildcardPattern("a?b", "axb")).toBe(false)
		expect(matchWildcardPattern("(a)", "xa")).toBe(false)
		expect(matchWildcardPattern("[ab]", "a")).toBe(false)
		expect(matchWildcardPattern("end$", "endx")).toBe(false)
		expect(matchWildcardPattern("^start", "xstart")).toBe(false)
		expect(matchWildcardPattern("a|b", "ab")).toBe(false)
	})

	it("does not turn .* into a regex class", () => {
		expect(matchWildcardPattern("a.*c", "a.*c")).toBe(true)
		expect(matchWildcardPattern("a.*c", "abc")).toBe(false)
	})
})

describe("matchWildcardPattern — star span", () => {
	it("absorbs newlines inside the span", () => {
		expect(matchWildcardPattern("echo *", "echo one\ntwo")).toBe(true)
		expect(matchWildcardPattern("a * b", "a x\ny b")).toBe(true)
		expect(matchWildcardPattern("* done", "line1\nline2 done")).toBe(true)
	})

	it("anchors both ends", () => {
		expect(matchWildcardPattern("*install", "npm install script")).toBe(false)
		expect(matchWildcardPattern("git * push", "git x push y")).toBe(false)
		expect(matchWildcardPattern("git * push", "rewrite git x push")).toBe(false)
		expect(matchWildcardPattern("git * push", "git checkout and push")).toBe(true)
	})

	it("matches several stars in order", () => {
		expect(matchWildcardPattern("*a*b*", "xxaybz")).toBe(true)
		expect(matchWildcardPattern("*a*b*", "xxbyaz")).toBe(false)
	})

	it("collapses a run of stars", () => {
		expect(matchWildcardPattern("a**b", "ab")).toBe(true)
		expect(matchWildcardPattern("a**b", "axxb")).toBe(true)
		expect(matchWildcardPattern("a**b", "a")).toBe(false)
	})

	it("a pattern of only * covers everything, including nothing", () => {
		expect(matchWildcardPattern("*", "anything at all")).toBe(true)
		expect(matchWildcardPattern("*", "")).toBe(true)
		expect(matchWildcardPattern("*", "multi\nline")).toBe(true)
	})

	it("an empty pattern matches only an empty command", () => {
		expect(matchWildcardPattern("", "")).toBe(true)
		expect(matchWildcardPattern("", "x")).toBe(false)
	})
})

describe("matchWildcardPattern — optional trailing ' *'", () => {
	it("covers the command with nothing after the space", () => {
		expect(matchWildcardPattern("npm run *", "npm run")).toBe(true)
		expect(matchWildcardPattern("npm run *", "npm run ")).toBe(true)
	})

	it("still covers the command with arguments", () => {
		expect(matchWildcardPattern("npm run *", "npm run build")).toBe(true)
		expect(matchWildcardPattern("npm run *", "npm run test -- watch")).toBe(true)
	})

	it("does not stretch across the space boundary", () => {
		expect(matchWildcardPattern("npm run *", "npm runb")).toBe(false)
		expect(matchWildcardPattern("npm run *", "npm")).toBe(false)
		expect(matchWildcardPattern("npm run *", "npm ru")).toBe(false)
	})

	it("stops being optional once a second star exists", () => {
		expect(matchWildcardPattern("npm * run *", "npm x run")).toBe(false)
		expect(matchWildcardPattern("npm * run *", "npm x run y")).toBe(true)
		expect(matchWildcardPattern("* run *", "x run")).toBe(false)
	})

	it("applies to the whole rule, not just the tail word", () => {
		expect(matchWildcardPattern("git * push", "git * push")).toBe(true)
		expect(matchWildcardPattern("git commit *", "git commit")).toBe(true)
		expect(matchWildcardPattern("*commit", "commit")).toBe(true)
		expect(matchWildcardPattern("* commit", "commit")).toBe(false)
	})
})

describe("matchWildcardPattern — trimming and case", () => {
	it("trims the rule but not the command's inner text", () => {
		expect(matchWildcardPattern("  npm run *  ", "npm run")).toBe(true)
		expect(matchWildcardPattern("  echo hi  ", "echo hi")).toBe(true)
		expect(matchWildcardPattern("  echo hi  ", "echo  hi")).toBe(false)
	})

	it("is case-sensitive unless asked", () => {
		expect(matchWildcardPattern("NPM RUN *", "npm run build")).toBe(false)
		expect(matchWildcardPattern("NPM RUN *", "npm run build", true)).toBe(true)
	})

	it("folds case for the optional tail too", () => {
		expect(matchWildcardPattern("npm run *", "NPM RUN")).toBe(false)
		expect(matchWildcardPattern("npm run *", "NPM RUN", true)).toBe(true)
	})
})

describe("parsePermissionRule", () => {
	it("prefers prefix syntax over a star in the text", () => {
		expect(parsePermissionRule("git *:*")).toEqual({ type: "prefix", prefix: "git *" })
	})

	it("sorts a bare star into a wildcard rule", () => {
		expect(parsePermissionRule("git * main")).toEqual({
			type: "wildcard",
			pattern: "git * main",
		})
	})

	it("keeps an escaped star out of the wildcard branch", () => {
		expect(parsePermissionRule("echo \\*")).toEqual({
			type: "exact",
			command: "echo \\*",
		})
	})

	it("keeps the rule text exactly as written", () => {
		expect(parsePermissionRule("  git status  ")).toEqual({
			type: "exact",
			command: "  git status  ",
		})
		expect(parsePermissionRule(" npm * ")).toEqual({
			type: "wildcard",
			pattern: " npm * ",
		})
	})

	it("treats an empty rule as an exact rule over empty text", () => {
		expect(parsePermissionRule("")).toEqual({ type: "exact", command: "" })
	})

	it("does not build a prefix rule across a newline", () => {
		expect(parsePermissionRule("git commit\n-am:*")).toEqual({
			type: "exact",
			command: "git commit\n-am:*",
		})
	})
})

describe("matchShellRule", () => {
	const exact = parsePermissionRule("git status")
	const prefix = parsePermissionRule("git:*")
	const glob = parsePermissionRule("npm run *")

	it("scores an exact rule over the whole command only", () => {
		expect(matchShellRule(exact, "git status", "prefix", true)).toBe(true)
		expect(matchShellRule(exact, "git status --oneline", "prefix", true)).toBe(false)
		expect(matchShellRule(exact, "git status", "exact", false)).toBe(true)
	})

	it("ignores whitespace around the command", () => {
		expect(matchShellRule(exact, "  git status  ", "prefix", true)).toBe(true)
		expect(matchShellRule(prefix, "  git commit  ", "prefix", true)).toBe(true)
	})

	it("refuses an empty command for every rule shape", () => {
		expect(matchShellRule(exact, "", "prefix", true)).toBe(false)
		expect(matchShellRule(prefix, "   ", "prefix", true)).toBe(false)
		expect(matchShellRule(glob, "", "prefix", true)).toBe(false)
	})

	it("needs an equal string for a prefix rule in exact mode", () => {
		expect(matchShellRule(prefix, "git", "exact", false)).toBe(true)
		expect(matchShellRule(prefix, "git status", "exact", false)).toBe(false)
		expect(matchShellRule(prefix, "xargs git", "exact", false)).toBe(false)
	})

	it("draws the prefix boundary at a space, not a tab", () => {
		expect(matchShellRule(prefix, "git\tstatus", "prefix", true)).toBe(false)
		expect(matchShellRule(prefix, "git status", "prefix", true)).toBe(true)
		expect(matchShellRule(prefix, "git", "prefix", true)).toBe(true)
	})

	it("covers the same invocation behind xargs", () => {
		expect(matchShellRule(prefix, "xargs git", "prefix", true)).toBe(true)
		expect(matchShellRule(prefix, "xargs git commit", "prefix", true)).toBe(true)
		expect(matchShellRule(prefix, "xargs gitk", "prefix", true)).toBe(false)
		expect(matchShellRule(prefix, "xargs", "prefix", true)).toBe(false)
	})

	it("never lets a wildcard rule match in exact mode", () => {
		expect(matchShellRule(glob, "npm run build", "exact", true)).toBe(false)
		expect(matchShellRule(glob, "npm run ", "exact", true)).toBe(false)
		expect(matchShellRule(glob, "npm run build", "prefix", true)).toBe(true)
	})

	it("scores one segment at a time, whichever way allowCompound reads", () => {
		expect(matchShellRule(glob, "npm run build", "prefix", false)).toBe(true)
		expect(matchShellRule(prefix, "git commit", "prefix", false)).toBe(true)
		expect(matchShellRule(exact, "git commit", "prefix", false)).toBe(false)
	})

	it("keeps a wildcard rule case-sensitive through the rule path", () => {
		expect(matchShellRule(parsePermissionRule("NPM *"), "npm x", "prefix", true)).toBe(false)
		expect(matchShellRule(parsePermissionRule("NPM *"), "NPM x", "prefix", true)).toBe(true)
	})
})
