import { describe, expect, it } from "vitest"
import {
	buildClassifierSystemPrompt,
	clearClassifierPromptCache,
	getBaseClassifierPrompt,
	getDefaultAutoModeRules,
	getExternalPermissionsTemplate,
} from "./classifier-prompt.ts"

const DEFAULTS = getDefaultAutoModeRules()

/** True when the prompt carries `text` as a bullet line of some rules block. */
function hasBullet(prompt: string, text: string): boolean {
	return prompt
		.split("\n")
		.some((line) => line.trim() === `- ${text}`)
}

function bullet(list: string[] | undefined, index = 0): string {
	const value = list?.[index]
	if (!value) throw new Error("default rules block is empty")
	return value
}

describe("getDefaultAutoModeRules", () => {
	it("reads a populated bullet list out of every rules block", () => {
		expect(DEFAULTS.allow?.length).toBeGreaterThan(5)
		expect(DEFAULTS.soft_deny?.length).toBeGreaterThan(5)
		expect(DEFAULTS.environment?.length).toBeGreaterThan(0)
	})

	it("returns bare bullet text: no marker, no placeholder, no bullet glyph", () => {
		for (const list of [DEFAULTS.allow, DEFAULTS.soft_deny, DEFAULTS.environment]) {
			for (const rule of list ?? []) {
				expect(rule.startsWith("- ")).toBe(false)
				expect(rule).not.toContain("{{")
				expect(rule).not.toContain("}}")
			}
		}
	})

	it("keeps the three blocks disjoint", () => {
		const allow = new Set(DEFAULTS.allow)
		expect(allow.has(bullet(DEFAULTS.soft_deny))).toBe(false)
		expect(allow.has(bullet(DEFAULTS.environment))).toBe(false)
	})
})

describe("buildClassifierSystemPrompt", () => {
	it("splices the rules template into the base prompt", () => {
		const template = getExternalPermissionsTemplate()
		const markerFree = template
			.slice(template.indexOf("## Deny Rules"), template.indexOf("{{rules:deny}}"))
			.trim()
		const prompt = buildClassifierSystemPrompt()
		expect(markerFree.length).toBeGreaterThan(0)
		expect(prompt).toContain(markerFree)
		expect(getBaseClassifierPrompt()).not.toContain(markerFree)
	})

	it("keeps every default block when the caller passes nothing", () => {
		const prompt = buildClassifierSystemPrompt()
		expect(hasBullet(prompt, bullet(DEFAULTS.allow))).toBe(true)
		expect(hasBullet(prompt, bullet(DEFAULTS.soft_deny))).toBe(true)
		expect(hasBullet(prompt, bullet(DEFAULTS.environment))).toBe(true)
	})

	it("replaces the default allow bullets with the caller's", () => {
		const prompt = buildClassifierSystemPrompt({
			allow: ["Only run the project test suite"],
		})
		expect(prompt).toContain("- Only run the project test suite")
		expect(prompt).not.toContain(bullet(DEFAULTS.allow))
		expect(hasBullet(prompt, bullet(DEFAULTS.allow))).toBe(false)
	})

	it("leaves the other blocks alone when only allow is given", () => {
		const prompt = buildClassifierSystemPrompt({ allow: ["Alpha"] })
		expect(hasBullet(prompt, bullet(DEFAULTS.soft_deny))).toBe(true)
		expect(hasBullet(prompt, bullet(DEFAULTS.environment))).toBe(true)
	})

	it("replaces only the deny block when only soft_deny is given", () => {
		const prompt = buildClassifierSystemPrompt({ soft_deny: ["Beta"] })
		expect(prompt).toContain("- Beta")
		expect(prompt).not.toContain(bullet(DEFAULTS.soft_deny))
		expect(hasBullet(prompt, bullet(DEFAULTS.allow))).toBe(true)
		expect(hasBullet(prompt, bullet(DEFAULTS.environment))).toBe(true)
	})

	it("replaces only the environment block when only environment is given", () => {
		const prompt = buildClassifierSystemPrompt({ environment: ["Gamma"] })
		expect(prompt).toContain("- Gamma")
		expect(prompt).not.toContain(bullet(DEFAULTS.environment))
		expect(hasBullet(prompt, bullet(DEFAULTS.allow))).toBe(true)
		expect(hasBullet(prompt, bullet(DEFAULTS.soft_deny))).toBe(true)
	})

	it("treats all three blocks as independent in one call", () => {
		const prompt = buildClassifierSystemPrompt({
			allow: ["One"],
			soft_deny: ["Two"],
			environment: ["Three"],
		})
		for (const text of ["One", "Two", "Three"]) {
			expect(hasBullet(prompt, text)).toBe(true)
		}
		for (const list of [DEFAULTS.allow, DEFAULTS.soft_deny, DEFAULTS.environment]) {
			for (const rule of list ?? []) {
				expect(prompt).not.toContain(rule)
			}
		}
	})

	it("counts an empty array as no rules given, so defaults stay", () => {
		const prompt = buildClassifierSystemPrompt({
			allow: [],
			soft_deny: [],
			environment: [],
		})
		expect(prompt).toBe(buildClassifierSystemPrompt())
		expect(hasBullet(prompt, bullet(DEFAULTS.allow))).toBe(true)
	})

	it("ignores blank entries and renders one bullet per rule", () => {
		const prompt = buildClassifierSystemPrompt({
			allow: ["  ", "First rule", "", "Second rule"],
		})
		expect(hasBullet(prompt, "First rule")).toBe(true)
		expect(hasBullet(prompt, "Second rule")).toBe(true)
		const run = prompt
			.split("\n")
			.filter((line) => line.trim() === "- First rule" || line.trim() === "- Second rule")
		expect(run).toHaveLength(2)
	})

	it("leaves no placeholder marker of any kind in the output", () => {
		const prompt = buildClassifierSystemPrompt({ allow: ["X"] })
		expect(prompt).not.toContain("{{")
		expect(prompt).not.toContain("}}")
		expect(prompt).not.toContain("rules:")
		expect(prompt).not.toContain("include:")
	})

	it("resolves the include markers while the raw files still carry them", () => {
		expect(getBaseClassifierPrompt()).toContain("{{include:")
		expect(buildClassifierSystemPrompt()).not.toContain("{{include:")
	})

	it("swaps the report line for the JSON verdict contract", () => {
		const prompt = buildClassifierSystemPrompt()
		expect(prompt).toContain("shouldBlock")
		expect(prompt).toContain("thinking")
		expect(prompt).toContain("reason")
		expect(prompt).not.toContain("classify_result tool")
	})

	it("renders the verdict contract once, after the rules blocks", () => {
		const prompt = buildClassifierSystemPrompt()
		expect(prompt.match(/## Verdict Format/g)).toHaveLength(1)
		expect(prompt.indexOf("## Verdict Format")).toBeGreaterThan(
			prompt.indexOf("## Allow Rules"),
		)
		expect(prompt.trimEnd().endsWith("one short sentence.")).toBe(true)
	})
})

describe("clearClassifierPromptCache", () => {
	it("does not throw and yields the same prompt on the next call", () => {
		const before = buildClassifierSystemPrompt()
		expect(() => clearClassifierPromptCache()).not.toThrow()
		expect(buildClassifierSystemPrompt()).toBe(before)
		expect(getDefaultAutoModeRules()).toEqual(DEFAULTS)
	})

	it("is idempotent and safe to call before the first read", () => {
		clearClassifierPromptCache()
		clearClassifierPromptCache()
		expect(getBaseClassifierPrompt().length).toBeGreaterThan(0)
		expect(getExternalPermissionsTemplate().length).toBeGreaterThan(0)
	})
})
