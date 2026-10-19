import { describe, expect, it } from "vitest"
import {
	bashCommandMatchesRuleContent,
	leadingAssignmentLength,
	leadingAssignmentName,
	stripAllLeadingEnvVars,
	stripSafeLeadingEnvVars,
	suggestBashAllowRule,
} from "./bash-permission-match.ts"

describe("bash-permission-match", () => {
	it("allow matches single-segment prefix rule", () => {
		expect(
			bashCommandMatchesRuleContent("npm run test", "npm run:*", "allow"),
		).toBe(true)
	})

	it("allow does not match compound commands", () => {
		expect(
			bashCommandMatchesRuleContent(
				"git status && rm -rf /",
				"git:*",
				"allow",
			),
		).toBe(false)
	})

	it("deny matches any compound segment", () => {
		expect(
			bashCommandMatchesRuleContent(
				"git status && rm -rf /",
				"rm:*",
				"deny",
			),
		).toBe(true)
	})

	it("suggests prefix rule for bash", () => {
		// Tightened from the old tool-wide `Bash(npm:*)` suggestion: that allowed
		// every future npm command including `npm publish` and arbitrary lifecycle
		// scripts. A subcommand prefix still covers the family you were approving.
		// Tool-wide rules remain available — write `Bash(npm:*)` via /permissions.
		expect(suggestBashAllowRule("npm run test")).toBe("Bash(npm run:*)")
	})
})

// ── The gap the argv matcher exists to close ─────────────────────────────────
// Recorded here so the text path's limits are visible next to the tests that
// depend on them. These are DEFECT PINS, not endorsements: nothing may read them
// as "the user should have written `bash x.sh *`". The behaviour is fixed where a
// rule is compared against arguments instead of against typed text —
// bash-rule-argv.ts, where `Bash(bash x.sh)` covers ["bash","x.sh","arg"].

describe("text matching needs the exact spelling it was written with", () => {
	it("an exact allow body does not cover the same command with one more argument", () => {
		expect(bashCommandMatchesRuleContent("bash x.sh arg", "bash x.sh", "allow")).toBe(false)
		// …which is why the trailing-star form became the documented workaround.
		expect(bashCommandMatchesRuleContent("bash x.sh arg", "bash x.sh *", "allow")).toBe(true)
	})

	it("and an exact deny body is just as literal — which is the safe half", () => {
		// A deny that under-fires costs a prompt somewhere else, never a bypass, so leaving this
		// unchanged on the deny path is deliberate: it stays text and stays narrow.
		expect(bashCommandMatchesRuleContent("rm -rf /tmp/x extra", "rm -rf /tmp/x", "deny")).toBe(false)
	})
})

// ── Leading `NAME=value` recognition ─────────────────────────────────────────
// What `stripAllLeadingEnvVars` / `stripSafeLeadingEnvVars` accept as a leading
// assignment. Every expectation in these tables was RECORDED from the running
// implementation before its borrowed `ENV_VAR_PATTERN` regex was replaced by a
// hand-written scanner (T15) — they are the contract the scanner must reproduce,
// quirks included. Do not "fix" a row here: a row that looks wrong is a row the
// gate already depends on.
//
// Shape of the accepted form, as observed:
//   NAME (identifier, optional `[index]`, optional `+`) `=` value  then ≥1 space/tab
// - a bare `FOO=bar` with nothing after it is NOT stripped: without trailing
//   whitespace the text is the command itself, not a prefix of one.
// - value = unquoted runs, single-quoted runs (no newline inside), double-quoted
//   runs (escapes allowed, but no `$`, backtick or newline inside), `\`-escapes,
//   in any order, so `a"b c"d` works.
// - a value holding a run-time value (`$(…)`, `$X`, backtick) is rejected, and so
//   is anything that ends the value on a shell separator (`;` `|` `&` `(` `)` `<` `>`).

/** `[command, expected]` — the assignment is removed and the rest returned. */
const ASSIGNMENTS_STRIPPED: Array<[string, string]> = [
	["FOO=bar cmd", "cmd"],
	["FOO=bar  cmd", "cmd"],
	["FOO=bar\tcmd", "cmd"],
	["_X1=2 cmd", "cmd"],
	["FOO+=bar cmd", "cmd"],
	["ARR[2]=x cmd", "cmd"],
	["ARR[a b]=x cmd", "cmd"],
	["ARR[]=x cmd", "cmd"],
	["FOO='a b' cmd", "cmd"],
	['FOO="a b" cmd', "cmd"],
	['FOO="a\\"b" cmd', "cmd"],
	["FOO=a\\ b cmd", "cmd"],
	["FOO=a'b'c cmd", "cmd"],
	["FOO= cmd", "cmd"],
	['FOO=a"b c"d cmd', "cmd"],
	['FOO="ab cmd x" done', "done"],
	["FOO=a* cmd", "cmd"],
	["FOO=a{b} cmd", "cmd"],
	["FOO=a=b cmd", "cmd"],
	["FOO== cmd", "cmd"],
	["FOO=bar > out cmd", "> out cmd"],
	["  FOO=bar  cmd  ", "cmd"],
]

/** More than one assignment in front of the command: the walk removes them all,
 *  one scanner span at a time. */
const ASSIGNMENT_CHAINS: Array<[string, string]> = [
	["A=1 B=2 cmd", "cmd"],
	["A=1 B=2 C=3 cmd", "cmd"],
	["NODE_ENV=x FOO=y cmd", "cmd"],
]

/** `[command]` — nothing is recognised, the text comes back as it went in. */
const ASSIGNMENTS_REJECTED: string[] = [
	// a run-time value in the value position
	"FOO=$(x) cmd",
	"FOO=$X cmd",
	// quoted-but-still-expanded: double quotes do not rescue a `$`
	'FOO="$X" cmd',
	"FOO=`x` cmd",
	// the value stops at a shell separator, and then there is no whitespace
	"FOO=a;b cmd",
	"FOO=a|b cmd",
	"FOO=a&b cmd",
	"FOO=(a) cmd",
	"FOO=a<b cmd",
	"FOO=a>b cmd",
	// unbalanced quoting
	"FOO='unterminated cmd",
	'FOO="unterminated cmd',
	"FOO=x\"y 'z' w",
	// no command after the assignment
	"FOO=bar",
	// not a valid name
	"1FOO=bar cmd",
	"+FOO=bar cmd",
	"FOO = bar cmd",
	"=bar cmd",
	"A+[1]=x cmd",
	"ARR[1]x=2 cmd",
	// a line break is never the whitespace that ends a leading assignment
	"FOO=bar\ncmd",
	"FOO='a\nb' cmd",
	'FOO="a\nb" cmd',
	"FOO=a\\\nb cmd",
]

describe("stripAllLeadingEnvVars: leading assignment recognition", () => {
	for (const [command, expected] of ASSIGNMENTS_STRIPPED) {
		it(`strips the assignment in ${JSON.stringify(command)}`, () => {
			expect(stripAllLeadingEnvVars(command)).toBe(expected)
		})
	}

	for (const command of ASSIGNMENTS_REJECTED) {
		it(`leaves ${JSON.stringify(command)} untouched`, () => {
			expect(stripAllLeadingEnvVars(command)).toBe(command)
		})
	}

	for (const [command, expected] of ASSIGNMENT_CHAINS) {
		it(`walks every assignment in ${JSON.stringify(command)}`, () => {
			expect(stripAllLeadingEnvVars(command)).toBe(expected)
		})
	}
})

describe("leadingAssignmentLength: the same contract, measured", () => {
	// Cut at the reported length and trim, and every row recorded above has to come
	// out the same — so the scanner is checked against the recorded behaviour of
	// the regex it replaced, not against a second opinion of mine.
	for (const [command, expected] of ASSIGNMENTS_STRIPPED) {
		it(`spans the assignment in ${JSON.stringify(command)}`, () => {
			const text = command.trimStart()
			expect(text.slice(leadingAssignmentLength(text)).trim()).toBe(expected)
		})
	}

	for (const command of ASSIGNMENTS_REJECTED) {
		it(`reports nothing for ${JSON.stringify(command)}`, () => {
			expect(leadingAssignmentLength(command)).toBe(0)
			expect(leadingAssignmentName(command)).toBe("")
		})
	}

	for (const [command, expected] of ASSIGNMENT_CHAINS) {
		it(`spans only the first assignment of ${JSON.stringify(command)}`, () => {
			const rest = command.slice(leadingAssignmentLength(command)).trim()
			// one span, so the next assignment is still there…
			expect(rest).not.toBe(expected)
			// …and walking the spans from there lands on the command
			expect(stripAllLeadingEnvVars(rest)).toBe(expected)
		})
	}

	// The length includes the whitespace that ends the assignment, which is why
	// `FOO=bar` alone scores 0 while `FOO=bar cmd` scores 8.
	it("counts the trailing whitespace into the span", () => {
		expect(leadingAssignmentLength("FOO=bar cmd")).toBe(8)
		expect(leadingAssignmentLength("FOO=bar  cmd")).toBe(9)
		expect(leadingAssignmentLength("FOO=bar\tcmd")).toBe(8)
		expect(leadingAssignmentLength("FOO= cmd")).toBe(5)
		expect(leadingAssignmentLength("FOO=bar")).toBe(0)
		// a chain: only the FIRST assignment is one span
		expect(leadingAssignmentLength("A=1 B=2 cmd")).toBe(4)
	})

	it("names the variable without its array index", () => {
		expect(leadingAssignmentName("FOO=bar cmd")).toBe("FOO")
		expect(leadingAssignmentName("_X1=2 cmd")).toBe("_X1")
		expect(leadingAssignmentName("FOO+=bar cmd")).toBe("FOO")
		expect(leadingAssignmentName("ARR[2]=x cmd")).toBe("ARR")
		expect(leadingAssignmentName("ARR[a b]=x cmd")).toBe("ARR")
		expect(leadingAssignmentName("NODE_ENV[0]=x cmd")).toBe("NODE_ENV")
		expect(leadingAssignmentLength("NODE_ENV[0]=x cmd")).toBe(14)
	})

	it("spans a value built from several quoting runs", () => {
		expect(leadingAssignmentLength("FOO='a b' cmd")).toBe(10)
		expect(leadingAssignmentLength('FOO="a b" cmd')).toBe(10)
		expect(leadingAssignmentLength('FOO=a"b c"d cmd')).toBe(12)
		// a quoted value may contain the blanks: the span ends at the FIRST blank
		// that is outside quotes
		expect(leadingAssignmentLength('FOO="ab cmd x" done')).toBe(15)
	})
})

describe("stripSafeLeadingEnvVars: only a known-safe name opens the chain", () => {
	const SAFE: Array<[string, string]> = [
		["NODE_ENV=x FOO=y cmd", "FOO=y cmd"],
		["NODE_ENV=x LANG=y cmd", "cmd"],
		["TERM=x NODE_ENV=y FOO=z cmd", "FOO=z cmd"],
		["RUST_LOG=debug FOO=1 cmd", "FOO=1 cmd"],
		["NO_COLOR=1 git status", "git status"],
		["NODE_ENV='a b' cmd", "cmd"],
		["NODE_ENV=x  cmd", "cmd"],
		// the array index is not part of the name, so this still reads as NODE_ENV
		["NODE_ENV[0]=x cmd", "cmd"],
		// a safe name behind an unsafe one stops the walk: nothing is stripped
		["FOO=y NODE_ENV=x cmd", "FOO=y NODE_ENV=x cmd"],
		// the `$` rule applies to safe names too
		['NODE_ENV="$X" cmd', 'NODE_ENV="$X" cmd'],
		["NODE_ENV=x", "NODE_ENV=x"],
	]

	for (const [command, expected] of SAFE) {
		it(`strips only the safe prefix of ${JSON.stringify(command)}`, () => {
			expect(stripSafeLeadingEnvVars(command)).toBe(expected)
		})
	}

	// One row worth naming out loud: an unknown name is never stripped even when
	// the value is obviously inert, and a safe name is stripped even when its
	// value would be meaningless (`NODE_ENV=xNODE_ENV=y` is one value, not two).
	it("never strips an unknown name even if a safe one follows a value", () => {
		expect(stripSafeLeadingEnvVars("NODE_ENV=xNODE_ENV=y cmd")).toBe("cmd")
		expect(stripSafeLeadingEnvVars("LANG=FOO=bar cmd")).toBe("cmd")
	})
})
