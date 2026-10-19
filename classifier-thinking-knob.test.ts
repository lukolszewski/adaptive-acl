/**
 * The thinking knob must be sent even when pi does not declare the model as a reasoning model
 * — a behaviour asked of the endpoint, not inferred from the model record.
 *
 * This pin exists because a plausible-sounding risk — "sending a Qwen-shaped field to a server that never
 * advertised one will 400" — went untested for a day and cost five worker runs. The endpoint answers in
 * 758 ms with a verdict when the field is sent, and never answers at all when it is not.
 */
import { describe, expect, it } from "vitest"
import { classifierStageModel, classifierThinkingOff } from "./classifier-client.ts"

// A model exactly as pi's registry would hand one over for a LiteLLM alias: an OpenAI-compatible
// endpoint, no `reasoning` flag, no `compat.thinkingFormat`. This is the shape that used to be skipped.
const undeclaredAlias = {
	id: "clf-gate",
	api: "openai-completions",
	provider: "litellm-lab",
	baseUrl: "http://litellm.internal.example:4000/v1",
} as unknown as Parameters<typeof classifierThinkingOff>[0]

describe("thinking knob on an undeclared model", () => {
	it("sends the chat-template knob even though pi does not know it thinks", () => {
		expect(classifierThinkingOff(undeclaredAlias)).toEqual({ via: "chat-template" })
	})

	it("gives the text stage a model view carrying the format, without mutating the registry's object", () => {
		const stageModel = classifierStageModel(undeclaredAlias, "single")
		expect(stageModel).not.toBe(undeclaredAlias)
		expect((stageModel.compat as { thinkingFormat?: string }).thinkingFormat).toBe("qwen-chat-template")
		// pi-ai only writes the knob when the model also declares reasoning; setting the format alone sends
		// nothing, which is the bug this pin exists to keep dead.
		expect(stageModel.reasoning).toBe(true)
		// The registry object is shared by the whole session: mutating it would switch off the user's
		// reasoning everywhere, which is the old bug with its polarity reversed.
		expect((undeclaredAlias.compat as { thinkingFormat?: string } | undefined)?.thinkingFormat).toBeUndefined()
		expect(undeclaredAlias.reasoning).toBeFalsy()
	})

	it("leaves the tool stage exactly as found — it works today on every transport", () => {
		expect(classifierStageModel(undeclaredAlias, "tool")).toBe(undeclaredAlias)
	})

	it("still takes the per-request option on anthropic, where the knob lives elsewhere", () => {
		const anthropic = { id: "c", api: "anthropic-messages" } as unknown as Parameters<typeof classifierThinkingOff>[0]
		expect(classifierThinkingOff(anthropic)).toEqual({ via: "option", options: { thinkingEnabled: false } })
	})
})
