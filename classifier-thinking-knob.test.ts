/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The classifier no longer forces a chat-template knob, and nothing about the shared model object is edited.
 *
 * This file used to pin the opposite: `classifierStageModel` copied the registry's model with
 * `compat.thinkingFormat = "qwen-chat-template"` and `reasoning: true` so pi-ai would emit
 * `chat_template_kwargs: {enable_thinking: false}` for every text stage. That was one server's dialect
 * shipped as if it were everyone's — endpoints that do not know the field ignore it or reject the request —
 * and the field a given server wants is now the user's `classifier.extraRequestFields`, applied through
 * pi-ai's `onPayload` hook (`request-fields.ts`). Default: nothing extra.
 *
 * What survives is the one knob this transport really has per request: Anthropic's `thinkingEnabled`.
 */
import { describe, expect, it } from "vitest"
import { classifierThinkingOff } from "./classifier-client.ts"

// A model exactly as pi's registry would hand one over for a LiteLLM alias: an OpenAI-compatible
// endpoint, no `reasoning` flag, no `compat.thinkingFormat`.
const undeclaredAlias = {
	id: "gate-model",
	api: "openai-completions",
	provider: "litellm-lab",
	baseUrl: "http://litellm.internal.example:4000/v1",
} as unknown as Parameters<typeof classifierThinkingOff>[0]

describe("no forced chat-template knob", () => {
	it("invents nothing for an OpenAI-compatible transport, declared reasoning or not", () => {
		expect(classifierThinkingOff(undeclaredAlias)).toEqual({ via: "unknown" })
		const declared = { ...undeclaredAlias, reasoning: true } as typeof undeclaredAlias
		expect(classifierThinkingOff(declared)).toEqual({ via: "unknown" })
	})

	it("invents nothing for a transport with no per-request knob at all", () => {
		const responses = {
			id: "r",
			api: "openai-responses",
			provider: "openai",
		} as unknown as Parameters<typeof classifierThinkingOff>[0]
		expect(classifierThinkingOff(responses)).toEqual({ via: "unknown" })
	})

	it("still takes the per-request option on anthropic, where the knob really lives", () => {
		const anthropic = {
			id: "c",
			api: "anthropic-messages",
		} as unknown as Parameters<typeof classifierThinkingOff>[0]
		expect(classifierThinkingOff(anthropic)).toEqual({
			via: "option",
			options: { thinkingEnabled: false },
		})
	})
})
