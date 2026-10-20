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
		const c = resolveClassifierConfig({ classifier: { model: "litellm-lab/clf-gate", baseUrl: "http://x/v1" } })
		expect(c.model).toBe("litellm-lab/clf-gate")
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
		expect(copilotModelKind("litellm-lab/clf-gate")).toBeUndefined()
		expect(copilotModelKind("clf-gate")).toBeUndefined()
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
