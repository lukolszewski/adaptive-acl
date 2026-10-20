/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
	DEFAULT_COPILOT_ANSWER_RESERVE,
	ANTHROPIC_API_VERSION,
	anthropicCompatibleSchema,
	answerReserveTokens,
	buildAnthropicMessagesBody,
	buildChatCompletionsBody,
	buildModelRequest,
	buildResponsesBody,
	classifyEffect,
	chatJson,
	extractGrant,
	modelApi,
	modelRequestHeaders,
	readCompletionText,
	readResponsesCompletion,
	type ModelEndpoint,
} from "./model-client.ts"
import { GRANT_SYSTEM_PROMPT } from "./model-client.ts"
import { copilotTokensSpent, resetCopilotUsage, SESSION_TOKEN_HEADER } from "./copilot-session.ts"

/**
 * Every test here stubs `fetch`. No test in this file may reach the network: the Copilot account this was
 * built against is a free plan with a small monthly allowance, and the live path is the probe
 * run by hand outside this file, not the suite.
 *
 * The stubbed bodies are the shapes MEASURED on that account on 2026-10-17 — in particular a `/responses`
 * completion whose `output_text` is `null` and whose verdict sits in `output[1].content[0].text`.
 */

type Sent = { url: string; headers: Record<string, string>; body: Record<string, unknown> }

let sent: Sent[] = []

function stubFetch(handler: (n: number) => { status: number; body: unknown }): void {
	sent = []
	let n = 0
	vi.stubGlobal("fetch", async (url: string, init: Record<string, unknown>) => {
		const body = JSON.parse(String(init.body)) as Record<string, unknown>
		sent.push({ url, headers: init.headers as Record<string, string>, body })
		const { status, body: responseBody } = handler(n++)
		const text = typeof responseBody === "string" ? responseBody : JSON.stringify(responseBody)
		return { ok: status >= 200 && status < 300, status, text: async () => text } as Response
	})
}

const lastBody = (): Record<string, unknown> => sent[sent.length - 1]!.body
const lastHeaders = (): Record<string, string> => sent[sent.length - 1]!.headers

const COPILOT_BASE = "https://api.individual.githubcopilot.com"

/** Case A — today's config: an explicit `baseUrl`, plain OpenAI-compatible, no registry. */
const PLAIN: ModelEndpoint = {
	baseUrl: "http://127.0.0.1:9/v1",
	model: "clf-gate",
	apiKey: "plain-key",
	timeoutMs: 1000,
	contextTokens: 4096,
}

/** Case B — GitHub picks. `api` and `supportsReasoning` are what the catalog said about the pick. */
const AUTO: ModelEndpoint = {
	baseUrl: COPILOT_BASE,
	model: "mai-code-1.1-flash",
	apiKey: "copilot-key",
	api: "responses",
	timeoutMs: 5000,
	contextTokens: 4096,
	copilot: {
		auto: true,
		sessionToken: "session-token-abc",
		supportsReasoning: true,
		maxOutputTokens: 512,
		reasoningEffort: "low",
	},
}

/** Case C — the user picked `gpt-4.1` (a paid-plan case, untestable live from here). */
const EXPLICIT: ModelEndpoint = {
	...AUTO,
	model: "gpt-4.1",
	api: "chat-completions",
	copilot: { auto: false, maxOutputTokens: 512, supportsReasoning: false },
}

const SCHEMA = {
	type: "object",
	properties: { effect: { type: "string" } },
	required: ["effect"],
	additionalProperties: false,
}

/** The measured `/responses` completion: `output_text` null, the reasoning item first, the answer second. */
function responsesJson(text: string | null, extra: Record<string, unknown> = {}) {
	return {
		status: "completed",
		incomplete_details: null,
		output_text: null,
		output: [
			{ type: "reasoning", content: [], id: "r1", summary: [] },
			{
				type: "message",
				role: "assistant",
				id: "m1",
				phase: "final_answer",
				status: "completed",
				content: text === null ? [] : [{ type: "output_text", text, annotations: [], logprobs: [] }],
			},
		],
		usage: {
			input_tokens: 69,
			output_tokens: 269,
			total_tokens: 338,
			output_tokens_details: { reasoning_tokens: 192 },
		},
		...extra,
	}
}

function chatJsonResponse(content: string | null, finish = "stop") {
	return {
		choices: [{ message: { role: "assistant", content }, finish_reason: finish }],
		usage: { prompt_tokens: 40, completion_tokens: 12, total_tokens: 52 },
	}
}

beforeEach(() => {
	resetCopilotUsage()
	sent = []
})

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("the OpenAI-compatible path is byte-identical", () => {
	it("sends exactly the body it has always sent, in the same field order", async () => {
		stubFetch(() => ({ status: 200, body: chatJsonResponse('{"effect":"read_only"}') }))
		const r = await chatJson(PLAIN, "SYS", "USR", "effect", SCHEMA, 200)
		expect(r.ok).toBe(true)
		expect(sent[0]!.url).toBe("http://127.0.0.1:9/v1/chat/completions")
		expect(Object.keys(sent[0]!.body!)).toEqual([
			"model",
			"temperature",
			"max_tokens",
			"stream",
			"messages",
			"response_format",
			"chat_template_kwargs",
		])
		expect(lastBody()).toEqual({
			model: "clf-gate",
			temperature: 0,
			max_tokens: 200,
			stream: false,
			messages: [
				{ role: "system", content: "SYS" },
				{ role: "user", content: "USR" },
			],
			response_format: { type: "json_schema", json_schema: { name: "effect", strict: true, schema: SCHEMA } },
			chat_template_kwargs: { enable_thinking: false },
		})
		expect(lastHeaders()).toEqual({
			"Content-Type": "application/json",
			Authorization: "Bearer plain-key",
		})
	})

	it("adds no Copilot header to a non-Copilot endpoint", async () => {
		stubFetch(() => ({ status: 200, body: chatJsonResponse("{}") }))
		await chatJson({ ...PLAIN, headers: { "X-Trace": "t" } }, "S", "U", "n", SCHEMA, 100)
		expect(lastHeaders()).toEqual({
			"Content-Type": "application/json",
			Authorization: "Bearer plain-key",
			"X-Trace": "t",
		})
		expect(lastHeaders()[SESSION_TOKEN_HEADER]).toBeUndefined()
		expect(lastHeaders()["X-GitHub-Api-Version"]).toBeUndefined()
	})

	it("keeps the honour of `disableThinking: false`", () => {
		const body = buildChatCompletionsBody({ ...PLAIN, disableThinking: false }, "S", "U", "n", SCHEMA, 10)
		expect(body.chat_template_kwargs).toBeUndefined()
		expect(body.temperature).toBe(0)
	})

	it("keeps reporting a plain endpoint's failure with no Copilot commentary", async () => {
		stubFetch(() => ({ status: 404, body: "" }))
		const r = await chatJson(PLAIN, "S", "U", "n", SCHEMA, 10)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toBe("HTTP 404: ")
	})
})

describe("the Auto request (case B)", () => {
	const ok = () => stubFetch(() => ({ status: 200, body: responsesJson('{"effect":"read_only"}') }))

	it("goes to /responses and carries the session header", async () => {
		ok()
		await chatJson(AUTO, "SYS", "USR", "effect", SCHEMA, 200)
		expect(sent[0]!.url).toBe(`${COPILOT_BASE}/responses`)
		const h = lastHeaders()
		expect(h[SESSION_TOKEN_HEADER]).toBe("session-token-abc")
		expect(h["X-GitHub-Api-Version"]).toBe("2026-08-01")
		expect(h.Authorization).toBe("Bearer copilot-key")
		expect(h["Editor-Version"]).toBeTruthy()
	})

	it("sends no temperature and no chat-template knob — both are rejected or meaningless there", async () => {
		ok()
		await chatJson(AUTO, "SYS", "USR", "effect", SCHEMA, 200)
		const body = lastBody()
		expect(body.temperature).toBeUndefined()
		expect(body.chat_template_kwargs).toBeUndefined()
		expect(JSON.stringify(body)).not.toContain("temperature")
		expect(JSON.stringify(body)).not.toContain("chat_template_kwargs")
	})

	it("keeps json_schema on this dialect, which is why this client does not use pi's complete()", async () => {
		ok()
		await chatJson(AUTO, "SYS", "USR", "effect", SCHEMA, 200)
		expect(lastBody().text).toEqual({
			format: { type: "json_schema", name: "effect", strict: true, schema: SCHEMA },
		})
	})

	it("sizes the answer from the configured reserve, not the task's small default", async () => {
		ok()
		await classifyEffect(AUTO, { command: "ls", cwd: "/p", project: "/p" })
		// classifyEffect asks for 200; the reserve wins because 200 is not enough for a thinking model.
		expect(lastBody().max_output_tokens).toBe(512)
		expect(lastBody().max_tokens).toBeUndefined()
	})

	it("honours a bigger configured reserve and never lowers one", () => {
		expect(answerReserveTokens({ ...AUTO, copilot: { auto: true, maxOutputTokens: 4096 } }, 200)).toBe(4096)
		// A caller asking for more than the reserve is never cut back: the reserve is a floor, not a ceiling.
		expect(answerReserveTokens({ ...AUTO, copilot: { auto: true, maxOutputTokens: 100 } }, 400)).toBe(400)
		expect(answerReserveTokens(AUTO, 400)).toBe(512)
		// No Copilot block = the number the task asked for, exactly as before.
		expect(answerReserveTokens(PLAIN, 300)).toBe(300)
		expect(DEFAULT_COPILOT_ANSWER_RESERVE).toBe(512)
	})

	it("asks for the reasoning effort only for a model the catalog says reasons", async () => {
		ok()
		await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(lastBody().reasoning).toEqual({ effort: "low" })

		await chatJson({ ...AUTO, copilot: { auto: true, sessionToken: "t", maxOutputTokens: 512 } }, "S", "U", "n", SCHEMA, 200)
		expect(lastBody().reasoning).toBeUndefined()

		await chatJson(
			{ ...AUTO, copilot: { auto: true, sessionToken: "t", supportsReasoning: true, reasoningEffort: "medium", maxOutputTokens: 512 } },
			"S",
			"U",
			"n",
			SCHEMA,
			200,
		)
		expect(lastBody().reasoning).toEqual({ effort: "medium" })
	})

	it("puts the system prompt where pi puts it, and does not invent an `instructions` field", async () => {
		ok()
		await chatJson(AUTO, "SYS", "USR", "n", SCHEMA, 200)
		expect(lastBody()).not.toHaveProperty("instructions")
		expect(lastBody().input).toEqual([
			{ role: "developer", content: "SYS" },
			{ role: "user", content: [{ type: "input_text", text: "USR" }] },
		])
	})

	it("refuses to send an Auto pick it has no token for, rather than collecting model_not_supported", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson("{}") }))
		const r = await chatJson({ ...AUTO, copilot: { ...AUTO.copilot!, sessionToken: undefined } }, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		expect(sent).toHaveLength(0)
		if (!r.ok) expect(r.error).toMatch(/session token/)
	})
})

describe("an explicit model never carries the session header (fact 5, inverted)", () => {
	// Measured the other way round: `gpt-4.1` answers 200 with the plain token and 400 "Requested model not
	// available for session" WITH one. So a request that pairs an explicit model with a session header is a bug
	// in this encoder, and the encoder is what this test pins — not the caller that built the endpoint.
	it("omits it for an explicit model", async () => {
		stubFetch(() => ({ status: 200, body: chatJsonResponse('{"effect":"read_only"}') }))
		await chatJson(EXPLICIT, "S", "U", "n", SCHEMA, 200)
		expect(sent[0]!.url).toBe(`${COPILOT_BASE}/chat/completions`)
		expect(lastHeaders()[SESSION_TOKEN_HEADER]).toBeUndefined()
		expect(lastHeaders()["X-GitHub-Api-Version"]).toBe("2026-08-01")
		expect(lastBody().temperature).toBeUndefined()
		expect(lastBody().max_tokens).toBe(512)
		expect(lastBody().response_format).toBeTruthy()
	})

	it("strips it even when the caller put one in the transport", () => {
		const h = modelRequestHeaders({
			...EXPLICIT,
			copilot: { auto: false, sessionToken: "should-not-travel", maxOutputTokens: 512 },
		})
		expect(h[SESSION_TOKEN_HEADER]).toBeUndefined()
	})

	it("strips it even when the caller put one in `headers`", () => {
		const h = modelRequestHeaders({
			...EXPLICIT,
			copilot: { auto: false, maxOutputTokens: 512 },
			headers: { [SESSION_TOKEN_HEADER]: "leaked" },
		})
		expect(h[SESSION_TOKEN_HEADER]).toBeUndefined()
		expect(modelRequestHeaders(AUTO)[SESSION_TOKEN_HEADER]).toBe("session-token-abc")
	})

	it("keeps the dialect that the catalog said, without guessing", () => {
		expect(modelApi(EXPLICIT)).toBe("chat-completions")
		expect(modelApi(AUTO)).toBe("responses")
		// An endpoint that predates this field speaks the dialect it always spoke.
		expect(modelApi(PLAIN)).toBe("chat-completions")
		expect(buildModelRequest(PLAIN, "S", "U", "n", SCHEMA, 200).path).toBe("/chat/completions")
		expect(buildModelRequest(AUTO, "S", "U", "n", SCHEMA, 200).path).toBe("/responses")
	})
})

describe("where the verdict text actually is", () => {
	it("reads it off the message item when output_text is null — the measured shape", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('{"shouldBlock":false,"reason":"fine"}') }))
		const r = await chatJson<{ shouldBlock: boolean; reason: string }>(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(true)
		if (r.ok) expect(r.value).toEqual({ shouldBlock: false, reason: "fine" })
	})

	it("reads the same path through the real task prompts", async () => {
		stubFetch(() => ({
			status: 200,
			body: responsesJson('{"authorized":"no","allowed_targets":[],"forbidden_targets":[],"quote":""}'),
		}))
		const r = await extractGrant(AUTO, {
			userMessages: ["rm -rf /tmp/x"],
			description: "delete a directory",
			category: "delete_outside",
			entities: [],
			command: "rm -rf /tmp/x",
		})
		expect(r.ok).toBe(true)
		expect(lastBody().text).toMatchObject({ format: { name: "authorisation", strict: true } })
		expect((lastBody().input as unknown[])[0]).toMatchObject({ role: "developer" })
		expect(lastBody().max_output_tokens).toBe(512)
		expect(GRANT_SYSTEM_PROMPT.length).toBeGreaterThan(0)
	})

	it("joins several text parts and falls back to the aggregate only when the items carry nothing", () => {
		const parts = readResponsesCompletion({
			output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "a" }, { type: "output_text", text: "b" }] }],
		})
		expect(parts.text).toBe("ab")
		const aggregate = readResponsesCompletion({ output_text: '{"a":1}', output: [] })
		expect(aggregate.text).toBe('{"a":1}')
	})

	it("never reads the reasoning item as the answer", () => {
		const r = readResponsesCompletion({
			output: [
				{ type: "reasoning", content: [{ type: "output_text", text: "the user probably means…" }] },
				{ type: "message", role: "assistant", content: [{ type: "output_text", text: '{"a":1}' }] },
			],
		})
		expect(r.text).toBe('{"a":1}')
		// Thinking and no answer: no text at all, so the caller reports an empty completion — not a verdict
		// invented from the model's private reasoning.
		const only = readResponsesCompletion({
			output: [{ type: "reasoning", content: [{ type: "output_text", text: "hmm" }] }],
		})
		expect(only.text).toBe("")
	})

	it("still reads the chat dialect the way it always did", () => {
		expect(readCompletionText("chat-completions", chatJsonResponse('{"a":1}')).text).toBe('{"a":1}')
	})

	it("tolerates a fenced completion the way the old reader did", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('```json\n{"a":1}\n```') }))
		const r = await chatJson<{ a: number }>(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(true)
		if (r.ok) expect(r.value).toEqual({ a: 1 })
	})
})

describe("a truncated answer is a transport failure, never a verdict", () => {
	it("reports incomplete_details as the cap it is", async () => {
		stubFetch(() => ({
			status: 200,
			body: responsesJson('{"shouldBlock": true, "reason": "hal', {
				status: "incomplete",
				incomplete_details: { reason: "max_output_tokens" },
				usage: { input_tokens: 59, output_tokens: 64, total_tokens: 123, output_tokens_details: { reasoning_tokens: 64 } },
			}),
		}))
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) {
			expect(r.error).toMatch(/ran into its token cap/)
			expect(r.error).toMatch(/max_output_tokens=512/)
			expect(r.error).toMatch(/max_output_tokens/) // the reason itself is quoted
			expect(r.error).toMatch(/reasoning=64/)
			// Not a verdict, not a refusal: the wording must survive as "the model did not answer".
			expect(r.error).toMatch(/no verdict to act on/)
		}
	})

	it("refuses even when the partial text parses as a complete object", async () => {
		// A reasoning model can emit the whole JSON object and then keep thinking; the cap still means the
		// answer may have been about to change. Reading the fragment is how a truncation becomes a denial.
		stubFetch(() => ({
			status: 200,
			body: responsesJson('{"shouldBlock": true, "reason": "done"}', { incomplete_details: { reason: "max_output_tokens" } }),
		}))
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
	})

	it("maps the chat dialect's finish_reason the same way", async () => {
		stubFetch(() => ({ status: 200, body: chatJsonResponse("", "length") }))
		const r = await chatJson(EXPLICIT, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toMatch(/ran into its token cap.*max_tokens=512, length/)
	})

	it("reports an empty completed answer as a failure, not an allow", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson("") }))
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toBe("empty completion")
	})
})

describe("every Copilot failure maps to the transport, with its reason", () => {
	const cases: Array<[string, number, unknown, RegExp]> = [
		["404 with an empty body (no version header)", 404, "", /X-GitHub-Api-Version/],
		["model_not_supported (no session)", 400, { error: { code: "model_not_supported" } }, /session token/],
		["Unsupported parameter: temperature", 400, { error: { message: "Unsupported parameter: 'temperature' is not supported with this model" } }, /temperature/],
		["model not available for session", 400, { error: { message: "Requested model not available for session" } }, /must not send it/],
	]

	it.each(cases)("%s", async (_name, status, body, pattern) => {
		stubFetch(() => ({ status, body }))
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) {
			expect(r.error).toMatch(pattern)
			expect(r.error).toMatch(/^HTTP /)
		}
	})

	it("reports a 200 whose body is not JSON without parsing it", async () => {
		stubFetch(() => ({ status: 200, body: "<html>proxy</html>" }))
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toMatch(/not JSON/)
	})

	it("reports a socket error as a failure", async () => {
		vi.stubGlobal("fetch", async () => {
			throw new Error("ECONNREFUSED")
		})
		const r = await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toContain("ECONNREFUSED")
	})
})

describe("the token allowance", () => {
	it("counts what the endpoint reported", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('{"a":1}') }))
		expect(copilotTokensSpent()).toBe(0)
		await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(copilotTokensSpent()).toBe(338) // the measured total_tokens
	})

	it("counts nothing for a non-Copilot endpoint", async () => {
		stubFetch(() => ({ status: 200, body: chatJsonResponse("{}") }))
		await chatJson(PLAIN, "S", "U", "n", SCHEMA, 200)
		expect(copilotTokensSpent()).toBe(0)
	})

	it("stops spending once the budget is gone, without a request", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('{"a":1}') }))
		const budgeted: ModelEndpoint = { ...AUTO, copilot: { ...AUTO.copilot!, budgetTokens: 300 } }
		await chatJson(budgeted, "S", "U", "n", SCHEMA, 200) // spends 338
		expect(copilotTokensSpent()).toBe(338)
		expect(sent).toHaveLength(1)

		const r = await chatJson(budgeted, "S", "U", "n", SCHEMA, 200)
		expect(sent).toHaveLength(1) // no second request
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toMatch(/budget spent \(338\/300 tokens\)/)
	})

	it("no budget configured means no cap", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('{"a":1}') }))
		for (let i = 0; i < 3; i++) await chatJson(AUTO, "S", "U", "n", SCHEMA, 200)
		expect(sent).toHaveLength(3)
	})
})

describe("the builders in isolation", () => {
	it("responses body: measured field set and nothing extra", () => {
		const body = buildResponsesBody(AUTO, "S", "U", "n", SCHEMA, 512)
		expect(Object.keys(body)).toEqual(["model", "input", "max_output_tokens", "stream", "text", "reasoning"])
	})

	it("chat body: the same fields on the Copilot path minus the two it refuses", () => {
		const body = buildChatCompletionsBody(EXPLICIT, "S", "U", "n", SCHEMA, 512)
		expect(Object.keys(body)).toEqual(["model", "max_tokens", "stream", "messages", "response_format"])
		expect(body.response_format).toEqual({
			type: "json_schema",
			json_schema: { name: "n", strict: true, schema: SCHEMA },
		})
	})

	it("a trailing slash in baseUrl does not produce a double slash", () => {
		expect(buildModelRequest({ ...AUTO, baseUrl: `${COPILOT_BASE}/` }, "S", "U", "n", SCHEMA, 1).path).toBe("/responses")
	})

	it("a trailing slash in baseUrl does not produce a double slash", async () => {
		stubFetch(() => ({ status: 200, body: responsesJson('{"a":1}') }))
		await chatJson({ ...AUTO, baseUrl: `${COPILOT_BASE}/` }, "S", "U", "n", SCHEMA, 1)
		expect(sent[0]!.url).toBe(`${COPILOT_BASE}/responses`)
	})
})

// ---------------------------------------------------------------- the anthropic-messages dialect
//
// Shapes measured on a Copilot Business seat (claude-haiku-4.5, /v1/messages): `output_config.format` answers
// 200 with exactly the schema's object; `maxItems` in the schema is a 400; `output_format` is a 400.

/** An explicitly chosen Claude model on Copilot. */
const CLAUDE: ModelEndpoint = {
	...AUTO,
	model: "claude-haiku-4.5",
	api: "anthropic-messages",
	copilot: { auto: false, maxOutputTokens: 512, supportsReasoning: true, reasoningEffort: "low" },
}

function anthropicJson(text: string | null, stop = "end_turn", extra: Record<string, unknown> = {}) {
	return {
		type: "message",
		role: "assistant",
		model: "claude-haiku-4.5",
		content: text === null ? [] : [{ type: "text", text }],
		stop_reason: stop,
		usage: { input_tokens: 159, output_tokens: 8, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
		...extra,
	}
}

describe("the anthropic-messages dialect", () => {
	it("is selected only by ep.api", () => {
		expect(modelApi(CLAUDE)).toBe("anthropic-messages")
		expect(modelApi({ ...CLAUDE, api: undefined })).toBe("chat-completions")
	})

	it("posts /v1/messages with output_config.format and no OpenAI or reasoning fields", async () => {
		stubFetch(() => ({ status: 200, body: anthropicJson('{"effect":"read_only"}') }))
		const r = await chatJson<{ effect: string }>(CLAUDE, "SYS", "USER", "effect", SCHEMA, 200)
		expect(r).toMatchObject({ ok: true, value: { effect: "read_only" } })
		expect(sent[0]!.url).toBe(`${COPILOT_BASE}/v1/messages`)
		expect(lastBody()).toEqual({
			model: "claude-haiku-4.5",
			max_tokens: 512,
			stream: false,
			system: "SYS",
			messages: [{ role: "user", content: "USER" }],
			output_config: { format: { type: "json_schema", schema: SCHEMA } },
		})
		for (const field of ["temperature", "response_format", "text", "reasoning", "thinking", "output_format", "tools"]) {
			expect(lastBody()).not.toHaveProperty(field)
		}
	})

	it("carries anthropic-version plus the Copilot headers, and no session header when explicit", () => {
		const h = modelRequestHeaders(CLAUDE)
		expect(h["anthropic-version"]).toBe(ANTHROPIC_API_VERSION)
		expect(h.Authorization).toBe("Bearer copilot-key")
		expect(h["Copilot-Integration-Id"]).toBe("vscode-chat")
		expect(h["X-GitHub-Api-Version"]).toBeDefined()
		expect(h[SESSION_TOKEN_HEADER]).toBeUndefined()
	})

	it("an Auto pick in this dialect carries the session header", () => {
		const h = modelRequestHeaders({ ...CLAUDE, copilot: { ...CLAUDE.copilot!, auto: true, sessionToken: "tok" } })
		expect(h[SESSION_TOKEN_HEADER]).toBe("tok")
		expect(h["anthropic-version"]).toBe(ANTHROPIC_API_VERSION)
	})

	it("other dialects never get anthropic-version", () => {
		expect(modelRequestHeaders(AUTO)["anthropic-version"]).toBeUndefined()
		expect(modelRequestHeaders(PLAIN)["anthropic-version"]).toBeUndefined()
	})

	it("reads text blocks only, skipping thinking", () => {
		const json = {
			stop_reason: "end_turn",
			content: [
				{ type: "thinking", thinking: '{"effect":"delete_outside"}' },
				{ type: "text", text: '{"effect":' },
				{ type: "text", text: '"read_only"}' },
			],
		}
		expect(readCompletionText("anthropic-messages", json)).toEqual({
			text: '{"effect":"read_only"}',
			truncated: false,
			reason: "end_turn",
		})
	})

	it("stop_reason max_tokens is a truncation, never a verdict", async () => {
		stubFetch(() => ({ status: 200, body: anthropicJson('{"effect":"rea', "max_tokens") }))
		const r = await chatJson(CLAUDE, "S", "U", "effect", SCHEMA, 200)
		expect(r.ok).toBe(false)
		expect(!r.ok && r.error).toMatch(/^truncated: .*max_tokens=512, max_tokens/)
	})

	it("a refusal is not read as an answer", async () => {
		stubFetch(() => ({ status: 200, body: anthropicJson('{"effect":"read_only"}', "refusal") }))
		const r = await chatJson(CLAUDE, "S", "U", "effect", SCHEMA, 200)
		expect(r).toMatchObject({ ok: false, error: "empty completion" })
	})

	it("usage is counted, cached input included", async () => {
		stubFetch(() => ({
			status: 200,
			body: anthropicJson('{"effect":"read_only"}', "end_turn", {
				usage: { input_tokens: 100, output_tokens: 8, cache_read_input_tokens: 50, cache_creation_input_tokens: 10 },
			}),
		}))
		await chatJson(CLAUDE, "S", "U", "effect", SCHEMA, 200)
		expect(copilotTokensSpent()).toBe(168)
	})

	it("names the measured 400s", async () => {
		stubFetch(() => ({
			status: 400,
			body: { type: "error", error: { type: "invalid_request_error", message: "output_config.format.schema: For 'array' type, property 'maxItems' is not supported" } },
		}))
		const r = await chatJson(CLAUDE, "S", "U", "effect", SCHEMA, 200)
		expect(!r.ok && r.error).toContain("refuses some JSON Schema keywords")
	})

	it("the builder in isolation", () => {
		expect(buildAnthropicMessagesBody(CLAUDE, "S", "U", SCHEMA, 300)).toMatchObject({ max_tokens: 300, system: "S" })
		expect(buildModelRequest(CLAUDE, "S", "U", "n", SCHEMA, 1).path).toBe("/v1/messages")
	})
})

describe("anthropicCompatibleSchema", () => {
	it("drops the length and count limits Anthropic refuses, everywhere in the tree", () => {
		const schema = {
			type: "object",
			properties: {
				targets: { type: "array", items: { type: "string", maxLength: 200 }, maxItems: 16 },
				rows: {
					type: "array",
					maxItems: 8,
					minItems: 1,
					items: { type: "object", properties: { quote: { type: "string", maxLength: 400, minLength: 2 } } },
				},
				n: { type: "integer", minimum: 0, maximum: 9 },
			},
			required: ["targets"],
			additionalProperties: false,
		}
		expect(anthropicCompatibleSchema(schema)).toEqual({
			type: "object",
			properties: {
				targets: { type: "array", items: { type: "string" } },
				rows: {
					type: "array",
					minItems: 1,
					items: { type: "object", properties: { quote: { type: "string" } } },
				},
				n: { type: "integer" },
			},
			required: ["targets"],
			additionalProperties: false,
		})
	})

	it("keeps a property that happens to be named like a keyword, and enum values verbatim", () => {
		const schema = {
			type: "object",
			properties: { maxLength: { type: "string", enum: ["maxItems", "x"] } },
			required: ["maxLength"],
		}
		expect(anthropicCompatibleSchema(schema)).toEqual(schema)
	})

	it("drops minItems above 1 and does not mutate its input", () => {
		const schema = { type: "array", minItems: 3, maxItems: 5, items: { type: "string" } }
		const copy = JSON.parse(JSON.stringify(schema))
		expect(anthropicCompatibleSchema(schema)).toEqual({ type: "array", items: { type: "string" } })
		expect(schema).toEqual(copy)
	})
})
