import { describe, expect, it } from "vitest"
import {
	escapeRuleContent,
	permissionRuleValueFromString,
	permissionRuleValueToString,
	unescapeRuleContent,
	type PermissionRuleValue,
} from "./permission-rule-parser.ts"

describe("permission-rule-parser", () => {
	it("parses bare tool name", () => {
		expect(permissionRuleValueFromString("Bash")).toEqual({
			toolName: "Bash",
		})
	})

	it("parses tool with content", () => {
		expect(permissionRuleValueFromString("Bash(npm run test)")).toEqual({
			toolName: "Bash",
			ruleContent: "npm run test",
		})
	})

	it("unescapes parentheses in content", () => {
		const raw = "Bash(python -c \"print\\(1\\)\")"
		expect(permissionRuleValueFromString(raw).ruleContent).toBe(
			'python -c "print(1)"',
		)
	})

	it("round-trips through serialize", () => {
		const rule = "Bash(npm run test *)"
		const value = permissionRuleValueFromString(rule)
		expect(permissionRuleValueToString(value)).toBe(rule)
	})

	it("escapes and unescapes content", () => {
		const content = 'echo "test\\nvalue"'
		const escaped = escapeRuleContent(content)
		expect(unescapeRuleContent(escaped)).toBe(content)
	})
})

/**
 * Every expectation below was read off the shipped parser, not decided here: this file is the
 * contract for the format on disk, so a case is only worth having if it says what the rule
 * strings in existing permissions.json files actually mean.
 */

/** A tool-level rule must not carry the key at all — `toEqual` cannot tell that apart. */
const toolLevel = (ruleString: string) => {
	expect(permissionRuleValueFromString(ruleString)).toEqual({
		toolName: expect.any(String),
	})
	expect(
		Object.hasOwn(permissionRuleValueFromString(ruleString), "ruleContent"),
	).toBe(false)
}

describe("permission-rule-parser: trimming", () => {
	it("trims a bare tool name on both sides", () => {
		expect(permissionRuleValueFromString("  Bash  ")).toEqual({
			toolName: "Bash",
		})
	})

	it("tolerates whitespace before the call form", () => {
		expect(permissionRuleValueFromString(" Bash(x)")).toEqual({
			toolName: "Bash",
			ruleContent: "x",
		})
	})

	it("treats whitespace after the closing paren as part of the tool name", () => {
		// Not a specifier with trailing space: the ") is no longer the last character, so the
		// whole string is the (unmatchable) tool name. Preserved deliberately.
		expect(permissionRuleValueFromString("Bash(x) ")).toEqual({
			toolName: "Bash(x)",
		})
		expect(permissionRuleValueFromString("  Bash(x)  ")).toEqual({
			toolName: "Bash(x)",
		})
	})

	it("keeps whitespace inside the specifier verbatim", () => {
		expect(permissionRuleValueFromString("Bash( )")).toEqual({
			toolName: "Bash",
			ruleContent: " ",
		})
		expect(permissionRuleValueFromString("Bash(x )")).toEqual({
			toolName: "Bash",
			ruleContent: "x ",
		})
	})

	it("maps the empty rule to an empty tool name", () => {
		expect(permissionRuleValueFromString("")).toEqual({ toolName: "" })
		expect(permissionRuleValueFromString("   ")).toEqual({ toolName: "" })
	})
})

describe("permission-rule-parser: where the specifier ends", () => {
	it("reads a ) that is not the final character as a bare tool name", () => {
		expect(permissionRuleValueFromString("Bash(a) trailing")).toEqual({
			toolName: "Bash(a) trailing",
		})
	})

	it("uses the LAST unescaped ) , so a specifier may contain unescaped ones", () => {
		expect(permissionRuleValueFromString("Bash(a)(b)")).toEqual({
			toolName: "Bash",
			ruleContent: "a)(b",
		})
		expect(permissionRuleValueFromString("Tool(a)b)")).toEqual({
			toolName: "Tool",
			ruleContent: "a)b",
		})
	})

	it("keeps nested parens in the specifier", () => {
		expect(permissionRuleValueFromString("Bash((a))")).toEqual({
			toolName: "Bash",
			ruleContent: "(a)",
		})
		expect(permissionRuleValueFromString("Bash(print(hi))")).toEqual({
			toolName: "Bash",
			ruleContent: "print(hi)",
		})
		expect(permissionRuleValueFromString("WebFetch(a(b(c)))")).toEqual({
			toolName: "WebFetch",
			ruleContent: "a(b(c))",
		})
	})

	it("needs an unescaped ( too: an escaped one never opens the specifier", () => {
		// The escaped ( at index 4 is data, so the tool name keeps its backslash.
		expect(permissionRuleValueFromString("Bash\\(x)(y)")).toEqual({
			toolName: "Bash\\(x)",
			ruleContent: "y",
		})
		expect(permissionRuleValueFromString("Bash\\)(x)")).toEqual({
			toolName: "Bash\\)",
			ruleContent: "x",
		})
	})

	it("falls back to the whole rule when no unescaped ) survives", () => {
		// trailing single backslash escapes the )
		expect(permissionRuleValueFromString("Bash(a\\)")).toEqual({
			toolName: "Bash(a\\)",
		})
		expect(permissionRuleValueFromString("Bash(x")).toEqual({
			toolName: "Bash(x",
		})
	})

	it("requires a non-empty tool name before the paren", () => {
		expect(permissionRuleValueFromString("(x)")).toEqual({ toolName: "(x)" })
	})

	it("splits a command-looking rule at the first unescaped paren", () => {
		expect(permissionRuleValueFromString("python -c print(1)")).toEqual({
			toolName: "python -c print",
			ruleContent: "1",
		})
	})
})

describe("permission-rule-parser: tool-level specifiers", () => {
	it("treats empty content as a tool-level rule with no ruleContent key", () => {
		toolLevel("Bash()")
		expect(permissionRuleValueFromString("Bash()")).toEqual({
			toolName: "Bash",
		})
	})

	it("treats * as a tool-level rule with no ruleContent key", () => {
		toolLevel("Bash(*)")
		expect(permissionRuleValueFromString("Bash(*)")).toEqual({
			toolName: "Bash",
		})
	})

	it("does not extend the tool-level shortcut to ** or to spaced *", () => {
		expect(permissionRuleValueFromString("Bash(**)")).toEqual({
			toolName: "Bash",
			ruleContent: "**",
		})
		expect(permissionRuleValueFromString("Bash( * )")).toEqual({
			toolName: "Bash",
			ruleContent: " * ",
		})
	})
})

describe("escapeRuleContent / unescapeRuleContent", () => {
	it("escapes exactly backslash, ( and )", () => {
		expect(escapeRuleContent("\\()")).toBe("\\\\\\(\\)")
		expect(escapeRuleContent("\\")).toBe("\\\\")
		expect(escapeRuleContent("(")).toBe("\\(")
		expect(escapeRuleContent(")")).toBe("\\)")
		expect(escapeRuleContent("a\\b")).toBe("a\\\\b")
	})

	it("leaves every other character alone", () => {
		for (const untouched of ["*", "**", "a b", "[]{}", "|&;", "a\nb", "a\tb", "./src/**", "~/.ssh/id_rsa", "\""]) {
			expect(escapeRuleContent(untouched)).toBe(untouched)
		}
	})

	it("retracts its own escapes", () => {
		expect(unescapeRuleContent("\\\\\\(\\)")).toBe("\\()")
		expect(unescapeRuleContent("\\(")).toBe("(")
		expect(unescapeRuleContent("\\)")).toBe(")")
		expect(unescapeRuleContent("a\\\\b")).toBe("a\\b")
	})

	it("leaves escapes it does not know, and a trailing backslash, as literal", () => {
		expect(unescapeRuleContent("\\*")).toBe("\\*")
		expect(unescapeRuleContent("\\n")).toBe("\\n")
		expect(unescapeRuleContent("a\\")).toBe("a\\")
		expect(unescapeRuleContent("\\")).toBe("\\")
	})

	it("does not escape *, so a backslash-star rule stays a backslash-star rule", () => {
		expect(permissionRuleValueFromString("Echo(a\\*b)")).toEqual({
			toolName: "Echo",
			ruleContent: "a\\*b",
		})
		// ...and round-tripping that value re-escapes the backslash: one-way on disk.
		expect(
			permissionRuleValueToString({ toolName: "Echo", ruleContent: "a\\*b" }),
		).toBe("Echo(a\\\\*b)")
	})

	it("documents that escape(unescape(x)) is NOT the identity for x already unescaped", () => {
		// unescape(escape(x)) === x always (see the property test), but the other direction only
		// holds for text that is already in escaped form. "\\n" is a literal backslash + n on
		// disk; normalising it to "\\\\n" would rewrite rules the user typed.
		expect(unescapeRuleContent("\\n")).toBe("\\n")
		expect(escapeRuleContent(unescapeRuleContent("\\n"))).toBe("\\\\n")
		expect(escapeRuleContent(unescapeRuleContent("a\\"))).toBe("a\\\\")
		expect(escapeRuleContent(unescapeRuleContent("\\\\("))).toBe("\\\\\\(")
		expect(escapeRuleContent(unescapeRuleContent("\\\\("))).not.toBe("\\\\(")
	})
})

describe("permissionRuleValueToString", () => {
	it("omits the parens for a missing or empty specifier", () => {
		expect(permissionRuleValueToString({ toolName: "Bash" })).toBe("Bash")
		expect(
			permissionRuleValueToString({ toolName: "Bash", ruleContent: "" }),
		).toBe("Bash")
	})

	it("writes parens for *, which is the one value parse() then drops", () => {
		expect(
			permissionRuleValueToString({ toolName: "Bash", ruleContent: "*" }),
		).toBe("Bash(*)")
		// Bash(*) parses to a tool-level rule, so it serialises back without the specifier.
		expect(
			permissionRuleValueToString(permissionRuleValueFromString("Bash(*)")),
		).toBe("Bash")
	})

	it("re-escapes a specifier that was parsed with the parens left raw", () => {
		expect(
			permissionRuleValueToString(permissionRuleValueFromString("Bash((a))")),
		).toBe("Bash(\\(a\\))")
		expect(
			permissionRuleValueToString(
				permissionRuleValueFromString("Bash(a)(b)"),
			),
		).toBe("Bash(a\\)\\(b)")
	})

	it("is idempotent, so it is safe as a map key", () => {
		for (const rule of [
			"Bash",
			"Bash(*)",
			"Bash(npm run test *)",
			"Edit(./src/**)",
			"Read(~/.ssh/id_rsa)",
			"Bash(git commit -m 'fix (x)')",
			"Bash(a\\)b)",
		]) {
			const once = permissionRuleValueToString(
				permissionRuleValueFromString(rule),
			)
			const twice = permissionRuleValueToString(
				permissionRuleValueFromString(once),
			)
			expect(twice).toBe(once)
		}
	})

	it("survives a newline inside the specifier", () => {
		expect(permissionRuleValueFromString("echo(a\nb)")).toEqual({
			toolName: "echo",
			ruleContent: "a\nb",
		})
	})
})

describe("permission-rule-parser: round-trip", () => {
	const pairs: Array<[string, PermissionRuleValue]> = [
		["Bash", { toolName: "Bash" }],
		["Bash(npm run test)", { toolName: "Bash", ruleContent: "npm run test" }],
		["Bash(npm run test *)", { toolName: "Bash", ruleContent: "npm run test *" }],
		["Bash(a\\)b)", { toolName: "Bash", ruleContent: "a)b" }],
		["Bash(a\\(b)", { toolName: "Bash", ruleContent: "a(b" }],
		["Bash(a\\\\)", { toolName: "Bash", ruleContent: "a\\" }],
		["Bash(\\(a\\))", { toolName: "Bash", ruleContent: "(a)" }],
		["Bash(a\\\\b)", { toolName: "Bash", ruleContent: "a\\b" }],
		["Edit(./src/**)", { toolName: "Edit", ruleContent: "./src/**" }],
		["Read(~/.ssh/id_rsa)", { toolName: "Read", ruleContent: "~/.ssh/id_rsa" }],
	]

	for (const [rule, value] of pairs) {
		it(`parses ${JSON.stringify(rule)}`, () => {
			expect(permissionRuleValueFromString(rule)).toEqual(value)
		})
		it(`serialises ${JSON.stringify(value)} back to ${JSON.stringify(rule)}`, () => {
			expect(permissionRuleValueToString(value)).toBe(rule)
		})
		it(`round-trips ${JSON.stringify(rule)} through a value`, () => {
			expect(
				permissionRuleValueToString(permissionRuleValueFromString(rule)),
			).toBe(rule)
		})
	}

	it("keeps a specifier that ends in a backslash", () => {
		const value = { toolName: "Bash", ruleContent: "git diff HEAD\\" }
		expect(
			permissionRuleValueFromString(permissionRuleValueToString(value)),
		).toEqual(value)
	})

	it("keeps a specifier that is only parens or only backslashes", () => {
		for (const ruleContent of ["(", ")", "\\", "()", "\\\\", "\\(", "(()", "aaa", " "]) {
			expect(
				permissionRuleValueFromString(
					permissionRuleValueToString({ toolName: "Bash", ruleContent }),
				),
			).toEqual({ toolName: "Bash", ruleContent })
		}
	})
})

describe("permission-rule-parser: property test (seeded)", () => {
	/** Deterministic LCG: a failing case has to be reproducible, so no Math.random(). */
	const lcg = (seed: number) => {
		let state = seed
		return (bound: number) => {
			state = (state * 1103515245 + 12345) % 2147483648
			return Math.floor(state / 4096) % bound
		}
	}
	const ALPHABET = ["a", "(", ")", "\\", "*"]

	const draw = (next: (bound: number) => number, maxLen: number): string => {
		let s = ""
		for (let i = next(maxLen + 1); i > 0; i--) s += ALPHABET[next(ALPHABET.length)]
		return s
	}

	it("reproduces the same corpus for the same seed", () => {
		const a = lcg(20261009)
		const b = lcg(20261009)
		expect(Array.from({ length: 50 }, () => draw(a, 10))).toEqual(
			Array.from({ length: 50 }, () => draw(b, 10)),
		)
	})

	it("unescapeRuleContent undoes escapeRuleContent for every sample", () => {
		const next = lcg(20261009)
		const failures: string[] = []
		for (let i = 0; i < 600; i++) {
			const s = draw(next, 14)
			const back = unescapeRuleContent(escapeRuleContent(s))
			if (back !== s) failures.push(`${JSON.stringify(s)} -> ${JSON.stringify(back)}`)
		}
		expect(failures).toEqual([])
	})

	it("round-trips {Bash, specifier} through the stringifier for every sample", () => {
		const next = lcg(4242)
		const failures: string[] = []
		let sampled = 0
		for (let i = 0; i < 600; i++) {
			const ruleContent = draw(next, 14)
			// "" serialises without parens and "*" is the tool-level marker: neither is expected
			// to come back as a specifier.
			if (ruleContent === "" || ruleContent === "*") continue
			sampled++
			const text = permissionRuleValueToString({
				toolName: "Bash",
				ruleContent,
			})
			const back = permissionRuleValueFromString(text)
			if (back.toolName !== "Bash" || back.ruleContent !== ruleContent) {
				failures.push(
					`${JSON.stringify(ruleContent)} -> ${JSON.stringify(text)} -> ${JSON.stringify(back)}`,
				)
			}
		}
		expect(sampled).toBeGreaterThan(400)
		expect(failures).toEqual([])
	})

	it("never finds a specifier where the sample has no unescaped parens", () => {
		const next = lcg(7)
		for (let i = 0; i < 300; i++) {
			const toolName = draw(next, 8).replace(/[()*]/g, "")
			if (toolName === "") continue
			expect(permissionRuleValueFromString(toolName)).toEqual({
				toolName,
			})
		}
	})
})
