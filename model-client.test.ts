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
	extractMessageGrants,
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
	model: "gate-model",
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
			model: "gate-model",
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

// ---------------------------------------------------------------- which effects the quote authorises

// Appended here rather than merged into the header import block, so nothing above this line changed
// (the same precedent `gate-ledger.test.ts` sets).
import { GRANT_CATEGORY_VALUES } from "./auth-ledger.ts"

/** A pending action with one target, the way the gate hands one over. */
const PENDING = {
	userMessages: ["install ripgrep with apt, you have my ok for sudo here"],
	description: "install a package system-wide",
	category: "package_system",
	entities: [{ kind: "target" as const, value: "ripgrep" }],
	command: "apt-get install -y ripgrep",
}

/** Answer the grant call with this completion text (the chat dialect the served endpoints speak). */
async function grantAnswers(content: string) {
	stubFetch(() => ({ status: 200, body: chatJsonResponse(content) }))
	return extractGrant(PLAIN, PENDING)
}

/** The schema this call sent — read back off the request, because that is what the server sees. */
function sentGrantSchema(): Record<string, any> {
	return (lastBody().response_format as any).json_schema.schema as Record<string, any>
}

describe("the grant call answers which effects the quote authorises", () => {
	it("the wire asks for effects as the category enum, and requires an answer", async () => {
		await grantAnswers('{"authorized":"yes","effects":["package_system","privilege"],"allowed_targets":["ripgrep"],"forbidden_targets":[],"quote":"you have my ok for sudo here"}')
		const schema = sentGrantSchema()
		// Structure, not prose: the items are the SAME closed enum the ledger matches on, so the
		// answer needs no interpretation anywhere downstream.
		expect(schema.properties.effects.items.enum).toEqual([...GRANT_CATEGORY_VALUES])
		// Strict mode asks for every property, so "no effect authorised" has an honest answer ([])
		// instead of a missing field the code would have to guess about.
		expect(schema.required).toContain("effects")
		expect(schema.additionalProperties).toBe(false)
	})

	it("the field travels on every dialect this client speaks", async () => {
		await grantAnswers('{"authorized":"no","effects":[],"allowed_targets":[],"forbidden_targets":[],"quote":""}')
		const schema = sentGrantSchema()
		for (const ep of [PLAIN, { ...PLAIN, api: "responses" as const }, { ...PLAIN, api: "anthropic-messages" as const }]) {
			const body = buildModelRequest(ep, "S", "U", "authorisation", schema, 200).body as Record<string, any>
			const wire = JSON.stringify(body)
			expect(wire).toContain("effects")
			expect(wire).toContain("package_system")
		}
	})

	it("an endpoint that omits the field gets the empty list, and the call still succeeds", async () => {
		// The answer shape before the field existed: strict servers fill it, a server that ignores
		// `required` does not.
		const r = await grantAnswers('{"authorized":"yes","allowed_targets":["ripgrep"],"forbidden_targets":[],"quote":"install ripgrep with apt"}')
		expect(r.ok).toBe(true)
		if (r.ok) expect(r.value.effects).toEqual([])
	})

	it("junk in the list is dropped, never mapped to something wider", async () => {
		// An endpoint that ignores the enum answers with whatever it likes. Dropping what cannot be
		// matched can only shrink what the row claims; nothing here invents a value in its place, and
		// the order and the duplicates are the model's, not ours.
		const r = await grantAnswers('{"authorized":"yes","effects":["package_system","delete_everything","package_system",7,"privilege"],"allowed_targets":[],"forbidden_targets":[],"quote":"install ripgrep with apt"}')
		expect(r.ok).toBe(true)
		if (r.ok) expect(r.value.effects).toEqual(["package_system", "privilege"])
	})

	it("an answer that is not a list is the empty list", async () => {
		// e.g. "effects": "install the package" — free text where structure was asked for. Reading
		// words out of it would be the exact thing this task removes, so it degrades to no effects.
		const r = await grantAnswers('{"authorized":"yes","effects":"install the package","allowed_targets":[],"forbidden_targets":[],"quote":"install ripgrep with apt"}')
		expect(r.ok).toBe(true)
		if (r.ok) expect(r.value.effects).toEqual([])
	})

	it("the other fields still fail closed when the shape is wrong, effects included", async () => {
		const r = await grantAnswers('{"authorized":"maybe","effects":["privilege"],"allowed_targets":[],"forbidden_targets":[],"quote":"x"}')
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toBe("schema violation: authorized")
	})
})

/**
 * Answers recorded from models, one per shape the ladder produced — a hand-written ideal alone would only test
 * the shape we wish for. Each `completion` is what a model returned for a message of that kind; `category` is
 * what layer 0 decided and therefore what the model was answering.
 *
 * What each row pins is the same thing from four directions: code passes the field through. It does not correct an
 * over-wide answer, does not repair a category it disagrees with, and does not let a non-empty list argue with
 * `authorized`. Every one of these answers costs at most one prompt — none of them can allow anything.
 */
describe("recorded gate answers reach code as the model wrote them", () => {
	const RECORDED: Array<{ note: string; category: string; completion: string; effects: string[]; authorized: string }> = [
		// The shape an allow looks like: the quote names the doing, so the effect is named with it.
		{
			note: "a force-push the quote names", category: "vcs_remote", authorized: "yes", effects: ["vcs_remote"],
			completion: '{"authorized":"yes","effects":["vcs_remote"],"allowed_targets":["feature/retry-logic"],"forbidden_targets":[],"quote":"yes, force-push it, I know the branch history is messed up"}',
		},
		// One instruction, two effects: the answer may name MORE than the pending category.
		{
			note: "one instruction, two effects", category: "privilege", authorized: "yes", effects: ["privilege", "process_control"],
			completion: '{"authorized":"yes","effects":["privilege","process_control"],"allowed_targets":["docker"],"forbidden_targets":[],"quote":"we need sudo to restart the docker daemon, go ahead"}',
		},
		// The vocabulary gap: the user's words cover the work, but the model calls an s3 object DATA while
		// layer 0 calls the same target cluster_mutation. Kept verbatim — code does not re-pick it.
		{
			note: "an s3 object called data, against a cluster category", category: "cluster_mutation", authorized: "yes", effects: ["delete_data"],
			completion: '{"authorized":"yes","effects":["delete_data"],"allowed_targets":["dev/","acme-data/"],"forbidden_targets":[],"quote":"clear out the dev/ prefix in the acme-data bucket, nothing else"}',
		},
		// The over-wide answer an effects check has to survive: a complaint that names a package, answered as an
		// install authorisation — two of the three models tried said yes to it, the third said no. Today nothing
		// reads it; under an effects check this row is why METHOD_VERB_REQUIRED cannot be deleted blind.
		{
			note: "an over-wide yes about a complaint that only names a package", category: "package_system", authorized: "yes", effects: ["package_system"],
			completion: '{"authorized":"yes","effects":["package_system"],"allowed_targets":["ripgrep"],"forbidden_targets":[],"quote":"ripgrep is missing from this box, sort that out"}',
		},
		// Effects and `authorized` disagreeing the other way: the field never flips a "no".
		{
			note: "effects disagreeing with a no", category: "remote_exec", authorized: "no", effects: ["remote_exec"],
			completion: '{"authorized":"no","effects":["remote_exec"],"allowed_targets":[],"forbidden_targets":[],"quote":""}',
		},
		// A compound pending action the model refused outright: both segments uncovered, which under an effects
		// check means one prompt, and under today's code means the same prompt it always gave.
		{
			note: "a compound refused outright", category: "delete_recursive+privilege", authorized: "no", effects: [],
			completion: '{"authorized":"no","effects":[],"allowed_targets":[],"forbidden_targets":[],"quote":""}',
		},
	]

	for (const row of RECORDED) {
		it(`${row.note}: the array arrives untouched, whatever it says`, async () => {
			const res = await grantAnswers(row.completion)
			expect(res.ok).toBe(true)
			if (!res.ok) return
			expect(res.value.effects).toEqual(row.effects)
			expect(res.value.authorized).toBe(row.authorized)
		})
	}
})

// ---------------------------------------------------------------- one dictionary, every call

import { buildGrantUserPrompt, EFFECT_ENUM, EFFECT_SYSTEM_PROMPT, extractionChunkChars, EXTRACTION_CHUNK_FLOOR_CHARS, MESSAGE_GRANT_SYSTEM_PROMPT } from "./model-client.ts"
import { EXTRACTION_CHUNK_CHARS } from "./message-chunks.ts"
import { CATEGORY_BOUNDARIES, CATEGORY_GLOSSES, CATEGORY_MEANINGS, categoryMeaningBlock, meaningLinesFor } from "./category-meanings.ts"

/**
 * The vocabulary the models answer in is now defined once (`category-meanings.ts`) and rendered into all three
 * calls. These pins are about the RENDERING — that each call actually receives the definitions, that a
 * definition exists for every value the schema offers, and that the boundaries that kept being crossed are
 * stated where the model that needs them will read them. The words themselves are reviewed in the diff, not
 * asserted here; what a test can hold is that they arrive.
 */
describe("every category is defined, and every call is told", () => {
	const render = categoryMeaningBlock()

	it("the dictionary covers the whole enum the schema offers", () => {
		for (const value of GRANT_CATEGORY_VALUES) {
			expect(CATEGORY_MEANINGS[value], value).toBeTruthy()
			expect(render, value).toContain(`- ${value}: `)
		}
		// Nothing invented: a meaning for a value that does not exist would be a definition no row can use.
		for (const key of Object.keys(CATEGORY_MEANINGS)) {
			expect(GRANT_CATEGORY_VALUES, key).toContain(key)
		}
	})

	it("the extraction call reads a short definition of every value, plus every boundary", () => {
		// This expectation changed when the fixed prompt outgrew its window. It used to require the FULL dictionary,
		// which is 4 262 characters ≈ 1 020 real prompt tokens; with the rest of the prompt that left a 4 096-token
		// endpoint no room for a message piece at all (measured: fixed part 3 601 tokens, a 4 000-character piece
		// refused with ContextWindowExceededError). The call now reads the SHORT view of the same table — one
		// line per value, the dividing words only — plus all eight boundary lines, which is where the confusable
		// pairs are settled. Not one definition less: a line for every value the schema offers is still there.
		expect(MESSAGE_GRANT_SYSTEM_PROMPT).toContain(categoryMeaningBlock(GRANT_CATEGORY_VALUES, true, "short"))
		for (const value of GRANT_CATEGORY_VALUES) {
			expect(MESSAGE_GRANT_SYSTEM_PROMPT, value).toContain(`- ${value}: ${CATEGORY_GLOSSES[value]}`)
		}
		for (const boundary of CATEGORY_BOUNDARIES) {
			expect(MESSAGE_GRANT_SYSTEM_PROMPT, boundary.line).toContain(boundary.line)
		}
		// The full meanings still exist, and the call that can pay for them still reads them.
		expect(EFFECT_SYSTEM_PROMPT).toContain(categoryMeaningBlock(EFFECT_ENUM, true))
	})

	it("the short view is the same table, not a second one that can drift", () => {
		for (const value of GRANT_CATEGORY_VALUES) {
			expect(CATEGORY_GLOSSES[value], value).toBeTruthy()
			expect(CATEGORY_MEANINGS[value], value).toBeTruthy()
			// A gloss that is not shorter than its meaning is not a shorter view of it: the compact rendering
			// would become the bigger of the two and the reason for having both would be gone.
			expect(CATEGORY_GLOSSES[value]!.length, value).toBeLessThan(CATEGORY_MEANINGS[value]!.length)
		}
		for (const key of Object.keys(CATEGORY_GLOSSES)) expect(GRANT_CATEGORY_VALUES, key).toContain(key)
		for (const boundary of CATEGORY_BOUNDARIES) {
			for (const value of boundary.values) expect(GRANT_CATEGORY_VALUES, value).toContain(value)
		}
	})

	it("the extraction prompt stays inside the window it is served into", () => {
		// The regression this pins: a prompt that quietly grows until a whole message piece no longer fits the
		// served window, at which point the width falls to the floor and a 1 500-character message is read in
		// four pieces, each without the sentences around it. The ceiling below is arithmetic on measured tokens:
		// a piece of 3 000 characters — the narrowest width a 4 096 window should still pay for —
		// costs at worst 3 000 / 4.59 = 655 tokens (4.59 chars/token is the densest PROSE measured; real
		// messages are 5.0–5.7). With the 400-token answer reserve the fixed text may therefore cost
		// 4 096 − 400 − 655 = 3 041 tokens = 3 041 × 4.17 = 12 681 characters. 12 600 is the pin, and measured
		// today the fixed part is 12 451 characters = 2 984 tokens, inside it.
		const wrapper = "User message:\n\n\nExtract granted and withdrawn permissions.".length
		expect(MESSAGE_GRANT_SYSTEM_PROMPT.length + wrapper).toBeLessThanOrEqual(12_600)
	})

	it("the effect classifier's list is the same text, for the values it may answer", () => {
		expect(EFFECT_SYSTEM_PROMPT).toContain(categoryMeaningBlock(EFFECT_ENUM, true))
		for (const value of EFFECT_ENUM) expect(GRANT_CATEGORY_VALUES, value).toContain(value)
	})

	it("the boundaries between the confusable pairs are unmistakable", () => {
		// vcs_remote vs vcs_force_protected: the branch decides, not the force, and the protected list is named.
		expect(CATEGORY_MEANINGS.vcs_force_protected).toContain("main")
		expect(CATEGORY_MEANINGS.vcs_force_protected).toContain("release/*")
		expect(CATEGORY_MEANINGS.vcs_remote).toContain("any push")
		// delete_data vs the cluster family: objects INSIDE a store, and a line saying so across the pair.
		expect(CATEGORY_MEANINGS.delete_data).toContain("never the store itself")
		expect(categoryMeaningBlock(EFFECT_ENUM, true)).toContain("cluster_mutation is for cluster RESOURCES")
		// db_mutation vs db_destroy: one table (DROP TABLE included) against a whole database gone.
		expect(CATEGORY_MEANINGS.db_mutation).toContain("DROP TABLE")
		expect(CATEGORY_MEANINGS.db_destroy).toContain("whole database")
		// network_send vs exfiltration vs container_mutation: an image push is a send; a container change is local.
		expect(CATEGORY_MEANINGS.network_send).toContain("pushing an image")
		expect(CATEGORY_MEANINGS.exfiltration).toContain("SECRET")
		expect(CATEGORY_MEANINGS.container_mutation).toContain("THIS machine")
	})

	it("the grant call is told what ITS action type means, and the neighbour it is not", () => {
		const prompt = (category: string) => buildGrantUserPrompt({
			userMessages: ["force-push it, the branch history is a mess"],
			description: "push a branch to the remote",
			category,
			entities: [{ kind: "target", value: "origin/feature/retry" }],
			command: "git push --force origin feature/retry",
		})
		const vcs = prompt("vcs_remote")
		expect(vcs).toContain("What that means: writes to a git remote")
		expect(vcs).toContain("Not to be confused with:")
		// …and the other side of the same pair gets the same treatment, in its own words.
		expect(prompt("vcs_force_protected")).toContain("PROTECTED branch")
		// A compound names each half, because one sentence has to cover both.
		const compound = prompt("delete_recursive+privilege")
		expect(compound).toContain("What delete_recursive means:")
		expect(compound).toContain("What privilege means:")
	})

	it("a gate-internal category is not given a fake meaning", () => {
		// `unproven_structure` says why the analyzer stopped, not what the action does; the slice says nothing.
		expect(meaningLinesFor("unproven_structure")).toEqual([])
		const prompt = buildGrantUserPrompt({
			userMessages: ["do it"], description: "an unverified command", category: "unproven_structure",
			entities: [], command: "some-tool --wizz",
		})
		expect(prompt).toContain("Action type: unproven_structure")
		expect(prompt).not.toContain("What that means:")
		expect(prompt).not.toContain("no meaning recorded")
		// The line the model reads is still exactly one line, with no gap where a definition would have been.
		expect(prompt).toContain("Action type: unproven_structure\nAction targets: (none)")
	})

	it("the extraction prompt no longer teaches that an image push is container work", () => {
		// An image push is a network send, not container work: the old line — and the old example 9 — answered the
		// publish as container work, which is the exact answer that then over-blocked it.
		expect(MESSAGE_GRANT_SYSTEM_PROMPT).not.toContain("publishing an image to a registry is container work")
		// The worked example that once pinned this is gone with a later prompt shortening; the rule now reaches the
		// model only through the meanings dictionary, so that is what is pinned here.
		expect(MESSAGE_GRANT_SYSTEM_PROMPT).toContain("pushing an image or chart sends bytes to a registry — network_send")
	})

	it("the grant system prompt tells the model the meaning decides, not the wording", () => {
		expect(GRANT_SYSTEM_PROMPT).toContain("what that name means")
		expect(GRANT_SYSTEM_PROMPT).toContain("however close the wording of the sentence sounds")
	})

	it("the extraction piece is sized by the server's own token counts, not by the global estimate", () => {
		// These expectations moved with the prompt, not with the code. They first pinned `4096 →
		// EXTRACTION_CHUNK_FLOOR_CHARS (384)`, which was `CHARS_PER_TOKEN = 3.2` (a constant tuned for paths and
		// code) applied to a prose prompt that measures 4.17: the arithmetic put the served window on the floor,
		// so a 1 500-character message became 4 calls, each read without the sentences around it. Re-measured
		// with the server's own `usage.prompt_tokens`: fixed part 2 984 tokens, and a whole 3 230-character
		// filler piece costs 703 tokens, so the call lands at 3 687 of the 4 096 served with the 400-token
		// answer reserve still paid. The bar is any width ≥ 3 000 characters on the default window (correctness
		// of the prompt outranks the width), so this test pins the CONTRACT — a whole paragraph fits, the cap is
		// not reached, a huge window gets the cap — rather than one exact width that would move with every
		// wording fix.
		expect(extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 32768 })).toBe(EXTRACTION_CHUNK_CHARS)
		const w = extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 4096 })
		expect(w).toBeGreaterThanOrEqual(3000)
		// Was toBeLessThan: with the prompt shortened again a 4 096 window pays for the full 4 000-char cap,
		// which is the contract's good case, not a breach.
		expect(w).toBeLessThanOrEqual(EXTRACTION_CHUNK_CHARS)
		// An endpoint that says nothing about its window is treated as the served 4 096, the same default every
		// other classifier call budgets against — and gets the same answer.
		expect(extractionChunkChars({ baseUrl: "http://x/v1", model: "m" })).toBe(w)
		// A window that cannot pay for the prompt at all still gets pieces rather than an empty call: the call
		// then fails, the message stays unseen, and the action costs one prompt — never an allow, never a
		// half-read approval. Between the floor and the cap the width shrinks smoothly.
		expect(extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 2048 })).toBe(EXTRACTION_CHUNK_FLOOR_CHARS)
		// The two points below are where the boundary sits TODAY; they move with the length of the fixed prompt,
		// which is why each is re-measured whenever the prompt gains a field. The prompt grew by one required field
		// plus one example (extraction-fixed 2 476 → 2 644 tokens), and later by the two machine target classes and
		// their one example (2 653 → 2 967 tokens, 11 019 → 12 404 chars), so the smooth-shrink range moved up.
		// NO code changed for either: the width is computed from the window, so a longer prompt buys a narrower
		// piece and the fail-safe (the floor) is what a too-small window gets. 3 400 - 2 967 - 400 leaves 33
		// tokens, which is not a piece — hence the floor at 3 400 — while 3 700 - 2 967 - 400 = 333 tokens ≈ 1.5k
		// chars sits strictly between the floor and the cap. Both windows are asserted, so a prompt that grows
		// into the mid point shows up as a failure rather than as a quietly narrower piece.
		const mid = extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 3700 })
		expect(mid).toBeGreaterThan(EXTRACTION_CHUNK_FLOOR_CHARS)
		expect(mid).toBeLessThan(w)
		expect(extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 3400 })).toBe(EXTRACTION_CHUNK_FLOOR_CHARS)
		expect(extractionChunkChars({ baseUrl: "http://x/v1", model: "m", contextTokens: 3000 })).toBe(EXTRACTION_CHUNK_FLOOR_CHARS)
	})

	it("a piece the server refuses is split in half and re-read, rather than lost", async () => {
		// The width above is calibrated for prose and a piece of pasted code can still beat it. The measured
		// answer from the endpoint is HTTP 400 with `ContextWindowExceededError` in the body, and the old
		// behaviour on that was a failed message — which reads to the session as "no ledger row at all", the same
		// permanent over-block the rejection was meant to avoid. The price of the retry is extra model calls; it
		// can never produce an allow that the whole-message read would not have.
		const long = `${"you may clear the temp folder when the run is done. ".repeat(50)}\n\n${"and keep the release notes file untouched. ".repeat(50)}`
		expect(long.length).toBeGreaterThan(2500)
		const answer = JSON.stringify({
			grants: [{ action: "delete files", category: "delete_recursive", kind: "entity", scope: "named", includesSecrets: false, targets: ["./tmp"], quote: "clear the temp folder" }],
			revocations: [],
		})
		const pieceSizes: number[] = []
		vi.stubGlobal("fetch", async (_url: string, init: Record<string, unknown>) => {
			const body = JSON.parse(String(init.body)) as { messages: Array<{ content: string }> }
			const piece = body.messages[1]!.content
			pieceSizes.push(piece.length)
			if (piece.length > 1200) {
				return { ok: false, status: 400, text: async () => "HTTP 400: ContextWindowExceededError: request (4210 tokens) exceeds the context window" } as Response
			}
			return { ok: true, status: 200, text: async () => JSON.stringify({ choices: [{ message: { content: answer } }] }) } as Response
		})
		const res = await extractMessageGrants({ baseUrl: "http://x/v1", model: "m" }, long)
		expect(res.ok).toBe(true)
		if (!res.ok) throw new Error(res.error)
		// more than one request, every successful one under the size the server refused, and the sentence both
		// halves reported is ONE row (the merge key deduplicates it)
		expect(pieceSizes.length).toBeGreaterThan(1)
		expect(pieceSizes.filter((n) => n <= 1200).length).toBeGreaterThan(0)
		expect(res.value.grants).toHaveLength(1)
		expect(res.value.grants[0]).toMatchObject({ category: "delete_recursive", targets: ["./tmp"] })
	})
})

// ---------------------------------------------------------------- a read stays a read

import { effectToTier, type EffectClassification, type EffectPathSpace } from "./model-client.ts"

/**
 * The path space every case below is decided in. Hermetic (`/home/u`), the same one the gate tests use —
 * the mapping is a pure function of the answer plus this space, so nothing here reads the machine the
 * test happens to run on.
 */
const READ_SPACE: EffectPathSpace = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

/** Shorthand for the tests: the four fields the effect schema answers with, in the order the wire has them. */
function answer(effect: string, targets: unknown, outside_project: boolean, confidence: string): EffectClassification {
	return { effect, targets: targets as string[], outside_project, confidence } as EffectClassification
}

/**
 * Effect answers recorded from a model, one per shape the mapping has to decide — a hand-written ideal alone
 * would only test the shape we wish for. Each row ran `classifyEffect` on the segment text layer 0 handed the
 * model. Paths under the home directory are written the way the code renders them (`~`); the recording said
 * `/home/u/…`, which is the same location.
 *
 * What they pin is one property per row: a read is reported as a read. Before this change every
 * `read_only` + `outside_project: true` answer came back as `write_outside`, so the user was shown "this
 * writes outside the project" about `cat /tmp/cpu_gpu.txt`, and no grant could ever cover it.
 */
describe("recorded effect answers: a read is mapped as a read, never as a write", () => {
	const RECORDED: Array<{ note: string; command: string; completion: string; want: { tier: string; category: string } }> = [
		{
			note: "a temp file the model itself called outside the project — outside is outside, whatever the name looks like",
			command: "cat /tmp/cpu_gpu.txt",
			completion: '{"effect":"read_only","targets":["/tmp/cpu_gpu.txt"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_only" },
		},
		{
			note: "a loop layer 0 would not vouch for; every name it reads is a plain path outside the project",
			command: "for f in /tmp/a /tmp/b; do cat $f; done",
			completion: '{"effect":"read_only","targets":["/tmp/a","/tmp/b"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_only" },
		},
		{
			note: "a read inside an installation outside the project, not secret-bearing",
			command: "ls $PREFIX/dist/bundle/chunks",
			completion: '{"effect":"read_only","targets":["~/.config/pnpm/global/5/node_modules/some-cli/dist/main.js"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_only" },
		},
		{
			note: "`python3 /opt/tools/clean.py` — running code outside the project is a run, not a write",
			command: "python3 /opt/tools/clean.py",
			completion: '{"effect":"run_project_code","targets":["/opt/tools/clean.py"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "run_project_code" },
		},
		{
			note: "the directory the keys live in — layer 0 asks for this read, so the model may not wave it through",
			command: "ls -la ~/.ssh",
			completion: '{"effect":"read_only","targets":["~/.ssh"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_secret" },
		},
		{
			note: "the model named the secret itself: unchanged path, unchanged verdict",
			command: "cat ~/.ssh/id_ed25519",
			completion: '{"effect":"read_secret","targets":["~/.ssh/id_ed25519"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_secret" },
		},
		{
			note: "the $( … ) shape behind a command substitution",
			command: "cat $(echo ~/.ssh/id_rsa)",
			completion: '{"effect":"read_secret","targets":["~/.ssh/id_rsa"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_secret" },
		},
		{
			note: "an AWS credentials file named by a model that called it a read",
			command: "cat $(echo ~/.aws/credentials)",
			completion: '{"effect":"read_secret","targets":["~/.aws/credentials"],"outside_project":true,"confidence":"high"}',
			want: { tier: "ask", category: "read_secret" },
		},
	]

	for (const row of RECORDED) {
		it(`${row.note} → ${row.want.tier} ${row.want.category}`, () => {
			const mapped = effectToTier(JSON.parse(row.completion) as EffectClassification, READ_SPACE)
			expect(mapped).toEqual(row.want)
			// The bug, stated as an invariant: no read answer is ever reported as a write.
			expect(mapped.category).not.toBe("write_outside")
		})
	}
})

/**
 * `cat $(echo ~/.ssh/id_rsa)` is the shape this test exists for, and it reaches the effect model because
 * layer 0 will not vouch for a command substitution (the inner `echo` is what layer 0 sees literally,
 * which is why the gate-level version of this test is in `gate-effect-read.test.ts`). Every answer an
 * endpoint could plausibly give for it is tried, including the wrong ones; none of them may allow.
 * The first entry is a recorded answer, the rest are hand-built wrong answers — the point of a
 * fail-safe is that it holds on input no model has actually sent.
 */
describe("a secret read behind a command substitution cannot reach allow by any answer", () => {
	const SPACE = READ_SPACE
	const answers: Array<[string, EffectClassification]> = [
		["recorded (read_secret, high)", JSON.parse('{"effect":"read_secret","targets":["~/.ssh/id_rsa"],"outside_project":true,"confidence":"high"}')],
		["read_only with the secret as its target", answer("read_only", ["~/.ssh/id_rsa"], true, "high")],
		["read_only with the unexpanded substitution as its target", answer("read_only", ["$(echo ~/.ssh/id_rsa)"], true, "high")],
		["read_only with no target at all", answer("read_only", [], true, "high")],
		["read_only with a target list that is not a list", { effect: "read_only", targets: "the key" as unknown as string[], outside_project: true, confidence: "high" }],
		["read_only with confidence low", answer("read_only", ["~/.ssh/id_rsa"], true, "low")],
		["read_only with confidence missing", { effect: "read_only", targets: ["~/.ssh/id_rsa"], outside_project: true } as EffectClassification],
		["read_only claiming nothing is outside", answer("read_only", ["~/.ssh/id_rsa"], false, "high")],
		["read_only with no path space to check against", answer("read_only", ["~/.ssh/id_rsa"], true, "high")],
	]

	for (const [name, a] of answers) {
		it(`${name}: asks, and never claims a write`, () => {
			const mapped = name.includes("no path space") ? effectToTier(a) : effectToTier(a, SPACE)
			expect(mapped.tier).toBe("ask")
			expect(mapped.category).not.toBe("write_outside")
		})
	}
})

describe("what the read mapping does when the answer is thin", () => {
	const space = READ_SPACE
	it("an outside read with no name to check stays a prompt, under a read category", () => {
		// `read_only` is the honest label and, unlike `write_outside`, one a "you may read that" grant can
		// match — which is the difference between a one-off prompt and a prompt that never ends.
		expect(effectToTier(answer("read_only", [], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["  "], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
	})

	it("an outside read nobody can resolve stays a prompt", () => {
		// An unexpanded `$var` has no basename to test against the secret table: not-known is not allow.
		expect(effectToTier(answer("read_only", ["$BUILD/out.txt"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/home/u/work/$NAME"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		// A location layer 0 calls sensitive where it sits — a read there is not routine outside the project.
		expect(effectToTier(answer("read_only", ["/etc/nginx/nginx.conf"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
	})

	it("an outside read is a prompt whatever its names look like", () => {
		// An outside read used to be allowed when its names all looked ordinary, and an ordinary-looking name is
		// not the user's permission. The category still says READ, which is what makes the prompt answerable at
		// all — a `read_only` grant can cover the next one, a `write_outside` one never could.
		expect(effectToTier(answer("read_only", ["/home/u/notes/todo.md"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/tmp/x.log", "/home/u/.cache/app/out.json"], true, "medium"), space)).toEqual({ tier: "ask", category: "read_only" })
		// …and a read the model says stays inside the project is still allowed: the rule is about OUTSIDE reads.
		expect(effectToTier(answer("read_only", ["./src/app.ts"], false, "high"), space)).toEqual({ tier: "allow", category: "read_only" })
	})

	it("a name that is not a location neither raises nor lowers the read", () => {
		// "uptime" is what the model wrote for `date +%T`; there is no path rule for it and inventing one
		// (resolving it against cwd) would classify a file the command never mentioned. It neither vetoes nor
		// rescues: the read is outside the project, so it asks, under the read category.
		expect(effectToTier(answer("read_only", ["uptime"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		// Inside the project the same answer still allows — the object says nothing, `outside_project` decides.
		expect(effectToTier(answer("read_only", ["uptime"], false, "high"), space)).toEqual({ tier: "allow", category: "read_only" })
	})

	it("a target under another account's home asks, as every outside read now does", () => {
		// A dedicated foreign-home rule once existed because an outside read could otherwise be ALLOWED on the
		// strength of its names. An outside read now asks whatever it looks like, and a path under somebody
		// else's account is never inside this project — so the case is covered by the general rule and the
		// special case is gone. These rows are kept because they are the shapes that found it.
		expect(effectToTier(answer("read_only", ["/home/other/.pi/agent/sessions/2026-01-01.jsonl"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/home/other/notes.md"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/root/.config/app.json"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/home"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
		// Our own home, outside the project: also a prompt, and also for the same single reason.
		expect(effectToTier(answer("read_only", ["/home/u/dev/airun/README.md"], true, "high"), space)).toEqual({ tier: "ask", category: "read_only" })
	})

	it("a pi session transcript read under another home stays a prompt, at either home", () => {
		// The shapes that found this rule: a heredoc'd python reading the agent's own session transcripts. Both
		// recorded answers were `read_only` / `outside_project: true` / `confidence: high` with the session
		// file as the only target. They replay under a `/tmp` cwd, so `~` resolves to a home the command never
		// names — there the home tables are silent and the general outside-read rule is what keeps this a
		// prompt. The paths below are the shape, not a recorded value.
		const scratch = { cwd: "/tmp/scratch-run", project: "/tmp/scratch-run", home: "/home/dev" }
		const sessions = "/home/u/.pi/agent/sessions/session-0001.jsonl"
		expect(effectToTier(answer("read_only", [sessions], true, "high"), scratch)).toEqual({ tier: "ask", category: "read_only" })
		expect(effectToTier(answer("read_only", ["/home/u/.pi/agent/sessions/*/[uuid].jsonl"], true, "high"), scratch)).toEqual({ tier: "ask", category: "read_only" })
		// And at the machine's real home the same path is home-relative sensitive config, which layer 0 asks
		// for on its own. Same verdict either way, which is the property the rule exists to make true.
		const real = { cwd: "/home/u/dev/app", project: "/home/u/dev/app", home: "/home/u" }
		expect(effectToTier(answer("read_only", [sessions], true, "high"), real)).toEqual({ tier: "ask", category: "read_secret" })
	})

	it("without a path space an outside read is not allowed, an inside read is unchanged", () => {
		// The fail-safe direction for a caller that cannot supply the space: ask.
		expect(effectToTier(answer("read_only", ["/home/u/notes/todo.md"], true, "high")).tier).toBe("ask")
		// Inside the project this is the previous behaviour, untouched.
		expect(effectToTier(answer("read_only", [], false, "high"))).toEqual({ tier: "allow", category: "read_only" })
	})

	it("a secret named for a read that stays inside the project still asks", () => {
		// A parsed read of the same file asks today (`read_secret`, risk-policy.ts), so an unparsed one may
		// not do better. This is the one check applied on both halves of `outside_project`.
		expect(effectToTier(answer("read_only", ["./.env"], false, "high"), space)).toEqual({ tier: "ask", category: "read_secret" })
		// …and an ordinary project file is still allowed, so the veto is about the path and not about where
		// the answer came from.
		expect(effectToTier(answer("read_only", ["./src/app.ts"], false, "high"), space)).toEqual({ tier: "allow", category: "read_only" })
	})

	it("low or unusable confidence is the analysis wall, not a read", () => {
		// CLASSIFIER-SPEC §4.1 says `low` → ASK (`interpreter_unknown`); a value outside the enum is the
		// same kind of non-answer, and a server that ignores the schema must not be read as confident.
		expect(effectToTier(answer("read_only", ["/home/u/x"], true, "low"), space)).toEqual({ tier: "ask", category: "interpreter_unknown" })
		expect(effectToTier(answer("read_only", ["/home/u/x"], false, "very-sure"), space)).toEqual({ tier: "ask", category: "interpreter_unknown" })
		expect(effectToTier(answer("write_project", ["./src/a.ts"], false, "surely"), space).tier).toBe("ask")
	})
})

/**
 * The two effects that are safe only inside the project.
 *
 * `write_project` outside is a write outside — unchanged. `run_project_code` outside is a RUN outside:
 * the model's own effect name, with its own targets as the objects, never a relabelled write. The tier
 * (`ask`) is what it always was; only the category the ask is filed under moved.
 */
describe("the two effects that are safe only inside the project still ask outside it", () => {
	const space = READ_SPACE
	it("write_project reaching outside is a write outside", () => {
		expect(effectToTier(answer("write_project", ["/home/u/.config/app/conf"], true, "high"), space)).toEqual({ tier: "ask", category: "write_outside" })
	})

	it("running code outside the project asks as a run, not as a write", () => {
		// This used to stay `write_outside`, on the argument that a `run_project_code` category would let a grant
		// for "run the tests here" cover code reaching outside. The ask must instead name the effect that is
		// being approved and the objects it names, or the user is asked to approve a write that will not happen
		// and the answer cannot be recorded in a form any grant matches.
		expect(effectToTier(answer("run_project_code", ["./scripts/dev.sh"], true, "high"), space)).toEqual({ tier: "ask", category: "run_project_code" })
		expect(effectToTier(answer("run_project_code", ["/opt/tools/clean.py"], true, "high"), space)).toEqual({ tier: "ask", category: "run_project_code" })
		expect(effectToTier(answer("run_project_code", ["./scripts/dev.sh"], false, "high"), space)).toEqual({ tier: "allow", category: "run_project_code" })
	})

	it("a run whose target is a secret-bearing path asks as a secret read", () => {
		// Hand-built wrong answer (no model files a `~/.ssh` script as a run): the secret veto applies to the
		// targets whatever the effect name, and the category is the one that says "credentials are involved".
		expect(effectToTier(answer("run_project_code", ["~/.ssh/id_rsa"], true, "high"), space)).toEqual({ tier: "ask", category: "read_secret" })
		// A declined answer is not an answer about running anything: analysis wall, no grant can match it.
		expect(effectToTier(answer("run_project_code", ["/opt/tools/clean.py"], true, "low"), space)).toEqual({ tier: "ask", category: "interpreter_unknown" })
		expect(effectToTier(answer("run_project_code", ["/opt/tools/clean.py"], true, "very-sure"), space)).toEqual({ tier: "ask", category: "interpreter_unknown" })
		// Without a path space the secret question cannot be asked; the ask stands, under the run category.
		expect(effectToTier(answer("run_project_code", ["~/.ssh/id_rsa"], true, "high"))).toEqual({ tier: "ask", category: "run_project_code" })
	})

	it("an ask-category answer is still the model's own category, untouched", () => {
		for (const effect of ["container_mutation", "network_send", "package_system", "vcs_remote"]) {
			expect(effectToTier(answer(effect, ["docker"], false, "high"), space)).toEqual({ tier: "ask", category: effect })
		}
		expect(effectToTier(answer("disk_destroy", ["/dev/sda"], true, "high"), space)).toEqual({ tier: "never", category: "disk_destroy" })
	})
})
