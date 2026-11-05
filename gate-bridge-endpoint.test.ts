/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The answer settings on the wire endpoint: `classifier.maxOutputTokens` and `classifier.extraRequestFields`
 * must reach every endpoint kind — an explicit `classifier.baseUrl`, a pi registry model, and a
 * `github-copilot/…` model (explicit pick and Auto) — and must reach the Copilot endpoint BESIDE its own
 * reserve, never instead of it.
 *
 * Why a test of its own: resolution is the one place that can drop a setting without a symptom. The gate would
 * keep sending each call's built-in reserve and nothing anywhere would say the config line had been ignored
 * (a mechanism that is silently not wired still tests green). Three paths, three chances to forget one.
 *
 * Hermetic: nothing here reaches the network. The two Copilot cases that mint a session stub `fetch`; the
 * explicit-pick and non-Copilot cases never build a request at all.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { resolveClassifierConfig, resolveCopilotConfig } from "./config.ts"
import { resolveGateEndpoint } from "./gate-bridge.ts"
import { resetCopilotSessions, resetCopilotUsage } from "./copilot-session.ts"

const COPILOT_BASE = "https://api.individual.githubcopilot.com"
const KEY = "k".repeat(32)

/** A whole classifier block, so a case only names the value it is about. */
function resolved(overrides: Record<string, unknown> = {}) {
	return resolveClassifierConfig({
		classifier: { enabled: true, timeoutMs: 15_000, ...overrides } as never,
	})
}

/** What a config that uses both settings looks like once resolved. The limit is under the default 4 096 window,
 *  so its only job here is to travel. */
const LIMIT = 3000
const EXTRA = {
	reasoning_effort: "none",
	chat_template_kwargs: { enable_thinking: false },
	temperature: null, // `null` removes our temperature on the merge path
}

type CatalogEntry = { id: string; api: string; reasoning?: boolean }

const CATALOG: CatalogEntry[] = [
	{ id: "gpt-5-mini", api: "openai-responses", reasoning: true },
	{ id: "claude-haiku-4.5", api: "anthropic-messages", reasoning: true },
]

function entry(m: CatalogEntry) {
	return { ...m, name: m.id, baseUrl: COPILOT_BASE, contextWindow: 200_000, maxTokens: 64_000 }
}

/** One registry for both kinds of model: the Copilot catalog and a self-hosted LiteLLM entry. */
function registry() {
	const copilot = CATALOG.map(entry)
	const litellm = { id: "gate-model", name: "gate-model", baseUrl: "http://127.0.0.1:9/v1", api: "openai-completions" }
	return {
		find: (provider: string, modelId: string) => {
			if (provider === "github-copilot") return copilot.find((m) => m.id === modelId) as never
			if (provider === "litellm-lab" && modelId === litellm.id) return litellm as never
			return undefined
		},
		getApiKeyAndHeaders: async () => ({ ok: true, apiKey: KEY } as never),
	}
}

/** The mint body, live-clock expiry: the session cache is per process and rides real time here. */
function sessionBody(selected: string) {
	return {
		session_token: "s".repeat(64),
		selected_model: selected,
		available_models: [selected],
		expires_at: Math.floor(Date.now() / 1000) + 3600,
	}
}

function stubFetch(body: unknown): { calls: Array<{ url: string; init?: { body?: string } }> } {
	const calls: Array<{ url: string; init?: { body?: string } }> = []
	vi.stubGlobal("fetch", async (url: string, init?: { body?: string }) => {
		calls.push({ url, init })
		return {
			ok: true,
			status: 200,
			text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
		} as unknown as Response
	})
	return { calls }
}

beforeEach(() => {
	resetCopilotSessions()
	resetCopilotUsage()
})

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("path A — an explicit classifier.baseUrl", () => {
	it("carries both settings to the endpoint", async () => {
		const config = resolved({
			model: "litellm-lab/gate-model",
			baseUrl: "http://127.0.0.1:9/v1",
			modelId: "gate-model",
			maxOutputTokens: LIMIT,
			extraRequestFields: EXTRA,
		})
		const ep = await resolveGateEndpoint(config, undefined)

		expect(ep).toMatchObject({
			baseUrl: "http://127.0.0.1:9/v1",
			model: "gate-model",
			maxOutputTokens: LIMIT,
			extraRequestFields: EXTRA,
		})
		// An explicit baseUrl means "plain OpenAI-compatible": no Copilot transport rides along.
		expect(ep?.copilot).toBeUndefined()
	})

	it("leaves the endpoint byte-identical when neither setting is configured", async () => {
		const ep = await resolveGateEndpoint(
			resolved({ model: "litellm-lab/gate-model", baseUrl: "http://127.0.0.1:9/v1", modelId: "gate-model" }),
			undefined,
		)
		expect(ep).toEqual({
			baseUrl: "http://127.0.0.1:9/v1",
			model: "gate-model",
			timeoutMs: 15_000,
			contextTokens: 4096,
		})
		// Not "present and undefined": a config that does not use the settings must not change the object at all.
		expect(Object.keys(ep ?? {})).not.toContain("maxOutputTokens")
		expect(Object.keys(ep ?? {})).not.toContain("extraRequestFields")
	})
})

describe("path B — a pi registry model", () => {
	it("carries both settings to the registry endpoint", async () => {
		const ep = await resolveGateEndpoint(
			resolved({
				model: "litellm-lab/gate-model",
				maxOutputTokens: LIMIT,
				extraRequestFields: EXTRA,
			}),
			registry() as never,
		)

		expect(ep).toMatchObject({
			baseUrl: "http://127.0.0.1:9/v1",
			model: "gate-model",
			apiKey: KEY,
			contextTokens: 4096,
			maxOutputTokens: LIMIT,
			extraRequestFields: EXTRA,
		})
	})

	it("leaves the endpoint untouched when neither setting is configured", async () => {
		const ep = await resolveGateEndpoint(resolved({ model: "litellm-lab/gate-model" }), registry() as never)
		expect(ep).toEqual({
			baseUrl: "http://127.0.0.1:9/v1",
			model: "gate-model",
			apiKey: KEY,
			headers: undefined,
			timeoutMs: 15_000,
			contextTokens: 4096,
		})
		expect(Object.keys(ep ?? {})).not.toContain("maxOutputTokens")
		expect(Object.keys(ep ?? {})).not.toContain("extraRequestFields")
	})
})

describe("path C — the Copilot endpoint", () => {
	it("an explicit pick carries both settings BESIDE copilot.maxOutputTokens", async () => {
		const { calls } = stubFetch(sessionBody("gpt-5-mini"))
		const ep = await resolveGateEndpoint(
			resolved({
				model: "github-copilot/gpt-5-mini",
				copilot: { maxOutputTokens: 512 },
				maxOutputTokens: LIMIT,
				extraRequestFields: EXTRA,
			}),
			registry() as never,
		)

		// An explicit pick must never mint, so the stub is a tripwire as much as a fallback.
		expect(calls).toHaveLength(0)
		expect(ep).toMatchObject({
			baseUrl: COPILOT_BASE,
			model: "gpt-5-mini",
			api: "responses",
			maxOutputTokens: LIMIT,
			extraRequestFields: EXTRA,
			copilot: { auto: false, maxOutputTokens: 512 },
		})
		// Two different knobs, two different numbers: the general one is not written over the Copilot one.
		expect(ep?.copilot?.maxOutputTokens).toBe(512)
	})

	it("the Auto path carries both settings too — it shares the same endpoint object", async () => {
		stubFetch(sessionBody("gpt-5-mini"))
		const ep = await resolveGateEndpoint(
			resolved({
				model: "github-copilot/auto",
				copilot: { maxOutputTokens: 1024 },
				maxOutputTokens: LIMIT,
				extraRequestFields: EXTRA,
			}),
			registry() as never,
		)

		expect(ep).toMatchObject({
			model: "gpt-5-mini",
			api: "responses",
			maxOutputTokens: LIMIT,
			extraRequestFields: EXTRA,
			copilot: { auto: true, maxOutputTokens: 1024 },
		})
	})

	it("neither setting configured leaves the Copilot endpoint as it was", async () => {
		const ep = await resolveGateEndpoint(resolved({ model: "github-copilot/gpt-5-mini" }), registry() as never)
		expect(ep?.maxOutputTokens).toBeUndefined()
		expect(ep?.extraRequestFields).toBeUndefined()
		expect(Object.keys(ep ?? {})).not.toContain("maxOutputTokens")
		expect(ep?.copilot).toEqual({
			auto: false,
			supportsReasoning: true,
			maxOutputTokens: resolveCopilotConfig(undefined).maxOutputTokens,
			reasoningEffort: "low",
			budgetTokens: 0,
		})
	})
})

describe("a refused value never reaches the endpoint", () => {
	it("drops an unusable maxOutputTokens and reports it", async () => {
		const config = resolved({ model: "litellm-lab/gate-model", maxOutputTokens: 99_999 })
		expect(config.problems).toHaveLength(1)

		const ep = await resolveGateEndpoint(config, registry() as never)
		// Dropped, not clamped: the client's own reserve is what the calls will ask for.
		expect(ep?.maxOutputTokens).toBeUndefined()
		expect(Object.keys(ep ?? {})).not.toContain("maxOutputTokens")
	})

	it("drops extraRequestFields the classifier refuses to merge", async () => {
		const config = resolved({ model: "litellm-lab/gate-model", extraRequestFields: { response_format: null } })
		expect(config.problems).toHaveLength(1)

		const ep = await resolveGateEndpoint(config, registry() as never)
		expect(ep?.extraRequestFields).toBeUndefined()
		expect(Object.keys(ep ?? {})).not.toContain("extraRequestFields")
	})
})
