/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	getConfigPath,
	setConfigPath,
	updatePermissionModesConfig,
	resolveInjectionWarning,
	resolveInjectionEscalation,
	resolveClassifierConfig,
	resolveCopilotConfig,
	copilotModelKind,
	DEFAULT_COPILOT_CLASSIFIER,
	COPILOT_AUTO_MODEL_REF,
	MAX_CLASSIFIER_OUTPUT_TOKENS,
	loadPermissionModesConfig,
} from "./config.ts"
import { DEFAULT_CONTEXT_TOKENS } from "./context-budget.ts"

function freshConfigPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "pm-cfg-"))
	return join(dir, "nested", "adaptive-acl.json")
}

describe("updatePermissionModesConfig", () => {
	it("creates the parent directory and writes the key", () => {
		const p = freshConfigPath()
		setConfigPath(p)
		expect(existsSync(p)).toBe(false)

		expect(updatePermissionModesConfig((c) => void (c.injectionWarning = false))).toBe(true)
		expect(JSON.parse(readFileSync(p, "utf-8")).injectionWarning).toBe(false)
		expect(loadPermissionModesConfig().injectionWarning).toBe(false)
		rmSync(dirnameOf(p), { recursive: true, force: true })
	})

	it("preserves keys the plugin does not model", () => {
		const p = freshConfigPath()
		setConfigPath(p)
		mkdirSync(dirnameOf(p), { recursive: true })
		writeFileSync(
			p,
			JSON.stringify(
				{ permissions: { allow: ["Bash(git status)"] }, someFutureKey: { a: 1 } },
				null,
				2,
			),
			"utf-8",
		)

		updatePermissionModesConfig((c) => {
			c.grantsAutoImport = { enabled: true, path: "/tmp/g.json" }
		})

		const back = JSON.parse(readFileSync(p, "utf-8"))
		expect(back.someFutureKey).toEqual({ a: 1 })
		expect(back.permissions.allow).toEqual(["Bash(git status)"])
		expect(back.grantsAutoImport.path).toBe("/tmp/g.json")
		rmSync(dirnameOf(p), { recursive: true, force: true })
	})

	it("refuses to overwrite a file it cannot parse, and leaves it byte-identical", () => {
		const p = freshConfigPath()
		setConfigPath(p)
		mkdirSync(dirnameOf(p), { recursive: true })
		const corrupt = '{ "injectionWarning": false, broken'
		writeFileSync(p, corrupt, "utf-8")

		// loadPermissionModesConfig() swallows this and returns {}; the writer must not.
		expect(loadPermissionModesConfig()).toEqual({})
		expect(updatePermissionModesConfig((c) => void (c.injectionWarning = true))).toBe(false)
		expect(readFileSync(p, "utf-8")).toBe(corrupt)
		rmSync(dirnameOf(p), { recursive: true, force: true })
	})

	it("leaves no temp file behind", () => {
		const p = freshConfigPath()
		setConfigPath(p)
		updatePermissionModesConfig((c) => void (c.injectionWarning = false))
		expect(existsSync(`${p}.tmp-${process.pid}`)).toBe(false)
		rmSync(dirnameOf(p), { recursive: true, force: true })
	})
})

describe("injection warning resolvers", () => {
	it("defaults both to true", () => {
		expect(resolveInjectionWarning({})).toBe(true)
		expect(resolveInjectionEscalation({})).toBe(true)
	})

	it("turning off the standing note does not disarm escalation", () => {
		const c = { injectionWarning: false }
		expect(resolveInjectionWarning(c)).toBe(false)
		expect(resolveInjectionEscalation(c)).toBe(true)
	})

	it("escalation is separately switchable", () => {
		expect(resolveInjectionEscalation({ injectionEscalation: false })).toBe(false)
	})
})

describe("classifier context window", () => {
	// The serving model runs a 4 096-token context and that does not change, so the default is a
	// fact about the deployment rather than a tuning knob — and every classifier call is sized to it.
	it("defaults to the served window", () => {
		expect(resolveClassifierConfig({}).contextTokens).toBe(4096)
		expect(resolveClassifierConfig({}).contextTokens).toBe(DEFAULT_CONTEXT_TOKENS)
	})

	it("honours an explicit window", () => {
		expect(resolveClassifierConfig({ classifier: { contextTokens: 2048 } }).contextTokens).toBe(2048)
		expect(resolveClassifierConfig({ classifier: { contextTokens: 32_768 } }).contextTokens).toBe(32_768)
	})

	it("ignores a hand-typed value it cannot size a call with", () => {
		for (const bad of [0, -1, NaN, "x", null, "", "4096"]) {
			expect(
				resolveClassifierConfig({ classifier: { contextTokens: bad as never } }).contextTokens,
			).toBe(4096)
		}
	})

	it("rounds a fractional window down instead of up", () => {
		expect(resolveClassifierConfig({ classifier: { contextTokens: 4096.9 } }).contextTokens).toBe(4096)
	})
})

function dirnameOf(p: string): string {
	return p.slice(0, p.lastIndexOf("/"))
}

// ------------------------------------------------- classifier.maxOutputTokens

/** One rule for both settings: an unusable value is dropped (today's behaviour stays) AND reported in
 *  `problems` — never replaced by a number the user did not type, never silently ignored. These cases pin both
 *  halves, because either one alone is the bug this setting exists to avoid. */
describe("classifier.maxOutputTokens", () => {
	const resolved = (classifier: Record<string, unknown>) =>
		resolveClassifierConfig({ classifier: classifier as never })

	it("is undefined when unset, which is exactly today's behaviour", () => {
		const c = resolved({})
		expect(c.maxOutputTokens).toBeUndefined()
		expect(c.problems).toEqual([])
	})

	it("honours a whole number that leaves room for the prompt", () => {
		const c = resolved({ maxOutputTokens: 1024 })
		expect(c.maxOutputTokens).toBe(1024)
		expect(c.problems).toEqual([])
		// The window's own default is the boundary: one token less than 4096 still leaves a prompt.
		expect(resolved({ maxOutputTokens: 4095 }).maxOutputTokens).toBe(4095)
	})

	it("honours the ceiling itself, not just values under it", () => {
		const c = resolved({ maxOutputTokens: MAX_CLASSIFIER_OUTPUT_TOKENS, contextTokens: 65_536 })
		expect(c.maxOutputTokens).toBe(MAX_CLASSIFIER_OUTPUT_TOKENS)
		expect(c.problems).toEqual([])
	})

	it("refuses a value above the ceiling instead of clamping it", () => {
		const c = resolved({ maxOutputTokens: MAX_CLASSIFIER_OUTPUT_TOKENS + 1, contextTokens: 65_536 })
		expect(c.maxOutputTokens).toBeUndefined()
		expect(c.problems).toHaveLength(1)
		expect(c.problems?.[0]).toContain(String(MAX_CLASSIFIER_OUTPUT_TOKENS))
		expect(c.problems?.[0]).toContain("ignored")
	})

	it("refuses zero, negatives and non-integers rather than flooring them", () => {
		for (const bad of [0, -1, -4096, 300.5, 1.5, NaN, Infinity]) {
			const c = resolved({ maxOutputTokens: bad })
			expect(c.maxOutputTokens, `maxOutputTokens=${bad}`).toBeUndefined()
			expect(c.problems, `maxOutputTokens=${bad}`).toHaveLength(1)
			expect(c.problems?.[0]).toContain("classifier.maxOutputTokens=")
		}
		// A quoted number is a string in a hand-edited file, not a token budget.
		for (const bad of ["1024", null, true, {}]) {
			expect(resolved({ maxOutputTokens: bad }).maxOutputTokens).toBeUndefined()
			expect(resolved({ maxOutputTokens: bad }).problems).toHaveLength(1)
		}
	})

	it("refuses a reserve that leaves no prompt room inside the window", () => {
		const same = resolved({ maxOutputTokens: 4096 }) // == the default contextTokens
		expect(same.maxOutputTokens).toBeUndefined()
		expect(same.problems?.[0]).toContain("contextTokens=4096")

		const over = resolved({ maxOutputTokens: 8000 })
		expect(over.maxOutputTokens).toBeUndefined()
		expect(over.problems).toHaveLength(1)

		// The judgement is made against the window the user configured, not the default one.
		const small = resolved({ maxOutputTokens: 2048, contextTokens: 2048 })
		expect(small.maxOutputTokens).toBeUndefined()
		expect(small.contextTokens).toBe(2048)
		expect(small.problems?.[0]).toContain("contextTokens=2048")

		const fits = resolved({ maxOutputTokens: 2048, contextTokens: 3072 })
		expect(fits.maxOutputTokens).toBe(2048)
		expect(fits.problems).toEqual([])
	})
})

// ---------------------------------------------- classifier.extraRequestFields
describe("classifier.extraRequestFields", () => {
	const resolved = (classifier: Record<string, unknown>) =>
		resolveClassifierConfig({ classifier: classifier as never })

	it("is undefined when unset: nothing extra is sent", () => {
		const c = resolved({})
		expect(c.extraRequestFields).toBeUndefined()
		expect(c.problems).toEqual([])
	})

	it("passes a valid object through untouched, nested objects included", () => {
		const fields = { reasoning_effort: "none", chat_template_kwargs: { enable_thinking: false }, temperature: null }
		const c = resolved({ extraRequestFields: fields })
		expect(c.extraRequestFields).toEqual(fields)
		expect(c.problems).toEqual([])
	})

	it("refuses anything that is not a JSON object", () => {
		for (const bad of [null, [], "{}", 3, true]) {
			const c = resolved({ extraRequestFields: bad })
			expect(c.extraRequestFields, `extraRequestFields=${JSON.stringify(bad)}`).toBeUndefined()
			expect(c.problems?.[0]).toMatch(/JSON object/)
		}
	})

	it("refuses a key the classifier owns, and names it", () => {
		const c = resolved({ extraRequestFields: { max_tokens: 10, seed: 42 } })
		expect(c.extraRequestFields).toBeUndefined()
		expect(c.problems).toHaveLength(1)
		expect(c.problems?.[0]).toContain("max_tokens")
		// The refused key is named, the accepted one is not turned into a second complaint.
		expect(c.problems?.[0]).not.toContain("seed")
	})

	it("reports both settings' problems, in key order, on one resolved config", () => {
		const c = resolved({ maxOutputTokens: -1, extraRequestFields: { model: "x" } })
		expect(c.problems).toHaveLength(2)
		expect(c.problems?.[0]).toContain("maxOutputTokens")
		expect(c.problems?.[1]).toContain("extraRequestFields")
		expect(c.maxOutputTokens).toBeUndefined()
		expect(c.extraRequestFields).toBeUndefined()
	})

	it("keeps the rest of the block intact when one value is refused", () => {
		const c = resolved({ model: "litellm-lab/gate-model", maxOutputTokens: 99_999, timeoutMs: 12_000 })
		expect(c.model).toBe("litellm-lab/gate-model")
		expect(c.timeoutMs).toBe(12_000)
		expect(c.contextTokens).toBe(DEFAULT_CONTEXT_TOKENS)
	})
})

describe("classifier.copilot", () => {
	// Two rules hold this block together. It may not change any behaviour that exists today — so every value is
	// read only on a `github-copilot/…` endpoint, and the defaults are the values the measured transport needs.
	// And a hand-typed value that cannot be used is ignored rather than sent to an endpoint that answers
	// `400 Unsupported parameter`.
	it("defaults to the measured transport's own numbers", () => {
		const c = resolveClassifierConfig({})
		expect(c.copilot).toEqual(DEFAULT_COPILOT_CLASSIFIER)
		expect(c.copilot?.maxOutputTokens).toBe(512)
		expect(c.copilot?.reasoningEffort).toBe("low")
		expect(c.copilot?.sessionEnabled).toBe(true)
		// 0 = no cap. A default cap would spend a free plan's allowance on gating without anyone asking.
		expect(c.copilot?.budgetTokens).toBe(0)
	})

	it("costs nothing to a config that does not use it", () => {
		// Every other resolved field is byte-for-byte what it was before this block existed.
		const c = resolveClassifierConfig({ classifier: { model: "litellm-lab/gate-model", baseUrl: "http://x/v1" } })
		expect(c.model).toBe("litellm-lab/gate-model")
		expect(c.baseUrl).toBe("http://x/v1")
		expect(c.timeoutMs).toBe(15000)
		expect(c.contextTokens).toBe(4096)
	})

	it("honours every knob a user typed", () => {
		const c = resolveClassifierConfig({
			classifier: {
				model: COPILOT_AUTO_MODEL_REF,
				copilot: { maxOutputTokens: 4096, reasoningEffort: "medium", budgetTokens: 200_000, sessionEnabled: false },
			},
		})
		expect(c.model).toBe(COPILOT_AUTO_MODEL_REF)
		expect(c.copilot).toEqual({
			maxOutputTokens: 4096,
			reasoningEffort: "medium",
			budgetTokens: 200_000,
			sessionEnabled: false,
		})
	})

	it("keeps a deliberate 0 as 'no cap' instead of reading it as a typo", () => {
		expect(resolveCopilotConfig({ budgetTokens: 0 }).budgetTokens).toBe(0)
		expect(resolveCopilotConfig({ budgetTokens: -5 }).budgetTokens).toBe(0)
	})

	it("ignores values it cannot build a request with", () => {
		for (const bad of [0, -1, NaN, "512", null, 1.5e9, 1e6]) {
			expect(resolveCopilotConfig({ maxOutputTokens: bad as never }).maxOutputTokens).toBe(512)
		}
		// The ceiling is a ceiling, not a suspicious number: a reserve inside it is honoured exactly.
		expect(resolveCopilotConfig({ maxOutputTokens: 32_768 }).maxOutputTokens).toBe(32_768)
		for (const bad of ["ultrathink", "", "LOW", 3, null, undefined]) {
			expect(resolveCopilotConfig({ reasoningEffort: bad as never }).reasoningEffort).toBe("low")
		}
		expect(resolveCopilotConfig({ sessionEnabled: "yes" as never }).sessionEnabled).toBe(true)
		expect(resolveCopilotConfig({ budgetTokens: "1000" as never }).budgetTokens).toBe(0)
		// Rounded down, never up: an answer reserve is an allowance, not a target.
		expect(resolveCopilotConfig({ maxOutputTokens: 900.7 }).maxOutputTokens).toBe(900)
	})

	it("accepts the Auto sentinel and an explicit pick, and calls anything else non-Copilot", () => {
		expect(copilotModelKind("github-copilot/auto")).toBe("auto")
		expect(copilotModelKind("github-copilot/gpt-4.1")).toBe("explicit")
		expect(copilotModelKind("github-copilot/mai-code-1.1-flash")).toBe("explicit")
		// The suffixes pi's own ref parser strips must not turn the Auto sentinel into an explicit model id:
		// an explicit pick is sent WITHOUT the session header, and the Auto pick dies without it.
		expect(copilotModelKind("github-copilot/auto@tool")).toBe("auto")
		expect(copilotModelKind("github-copilot/auto:low")).toBe("auto")
		expect(copilotModelKind("github-copilot/gpt-5-mini@fast")).toBe("explicit")
		expect(copilotModelKind("litellm-lab/gate-model")).toBeUndefined()
		expect(copilotModelKind("gate-model")).toBeUndefined()
		expect(copilotModelKind("github-copilot/")).toBeUndefined()
		expect(copilotModelKind("")).toBeUndefined()
	})
})

// getConfigPath is exported for diagnostics; assert it tracks setConfigPath.
it("getConfigPath follows setConfigPath", () => {
	const p = join(tmpdir(), "pm-cfg-visible.json")
	setConfigPath(p)
	expect(getConfigPath()).toBe(p)
})
