/**
 * "The classifier is on" must mean two things: the config actually reaches the
 * gate, and a transport that cannot answer never leaves the call unjudged (the silent-uselessness
 * bug: a config that enables a model nobody can reach, presenting itself as a working auto mode).
 *
 * Naming note: the task named `classifier.ts`, which does not exist in this tree. The shipped
 * classifier is `classifier-client.ts` (legacy stages over pi-ai), `model-client.ts` + `gate.ts`
 * (the `gate` engine, the default), and `config.ts` for enablement. Those files are not mine to
 * edit, so this file pins their contract from the outside and says nothing about what those files
 * should change — the assertions here hold either way.
 *
 * Hermetic: the config is re-pointed at a temp dir, and "unreachable transport" means a closed port
 * on 127.0.0.1 — no shared endpoint, no network, no live user config.
 */

import { mkdtempSync, writeFileSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest"
import type { Api, AssistantMessage, Context, Model } from "@earendil-works/pi-ai/compat"
import type { ModelEndpoint } from "./model-client.ts"

import { classifyToolCall, ClassifierStageFailure, isClassifierStageFailure, type ClassifierRegistry } from "./classifier-client.ts"
import { CLASSIFIER_TOOL_NAME } from "./classifier-tool.ts"
import { AUTO_MODE_REJECTION_PREFIX, buildClassifierUnavailableMessage } from "./classifier-messages.ts"
import { attributionLine, classifierUnavailability, gateDenialAttribution, gateDenialMessage, resetClassifierUnavailability, resolveGateEndpoint } from "./gate-bridge.ts"
import { resetCopilotSessions, resetCopilotUsage, recordCopilotUsage, type FetchLike } from "./copilot-session.ts"
import {
	getConfigPath,
	loadPermissionModesConfig,
	resolveClassifierConfig,
	resolveCopilotConfig,
	setConfigPath,
} from "./config.ts"
import { classifierStats, resetClassifierStats, runGate, type GateResult } from "./gate.ts"
import { isClassifierDenial } from "./classifier-messages.ts"

/** A port nothing listens on: "the endpoint exists in config but cannot answer", in ~1 ms. */
const DEAD_BASE_URL = "http://127.0.0.1:9/v1"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

/** Layer 0 cannot classify this verb, so only the model can decide it. */
const UNKNOWN_COMMAND = "someprog --do-thing"

function chatModel(baseUrl: string): Model<Api> {
	return {
		id: "clf-gate",
		name: "clf-gate",
		api: "openai-completions",
		provider: "litellm-lab",
		baseUrl,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		reasoning: false,
		contextWindow: 4096,
		maxTokens: 512,
	} as unknown as Model<Api>
}

function registryFor(
	model: Model<Api>,
	auth: { ok: true; apiKey?: string } | { ok: false; error: string },
): ClassifierRegistry {
	return {
		find: (_provider, modelId) => (modelId === model.id ? model : undefined),
		getApiKeyAndHeaders: async () => auth as never,
	}
}

function session() {
	return {
		cwd: "/home/u/proj",
		mode: "auto",
		branch: [
			{
				type: "message",
				message: { role: "user", content: [{ type: "text", text: "Show me the README." }] },
			},
		] as never,
	}
}

/** `classifier-client.ts` builds its own `AbortController`; a stubbed reply just has to look real. */
function assistantWithToolCall(args: Record<string, unknown>): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: "c1", name: CLASSIFIER_TOOL_NAME, arguments: args }],
		api: "openai-completions",
		provider: "litellm-lab",
		model: "clf-gate",
		stopReason: "toolUse",
		timestamp: Date.now(),
		usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
	} as unknown as AssistantMessage
}

// A seam, not a fake transport: only the tests that need to control the model's answer use it, and
// everything else falls through to the real `completeSimple`.
let answerStub: (() => Promise<AssistantMessage>) | undefined

vi.mock("@earendil-works/pi-ai/compat", async (importActual) => {
	const actual = await importActual<typeof import("@earendil-works/pi-ai/compat")>()
	return {
		...actual,
		completeSimple: (model: never, context: Context, options: never) =>
			answerStub
				? answerStub()
				: actual.completeSimple(model as never, context, options as never),
	}
})

describe("enablement: the config reaches the gate", () => {
	it("re-reads permission-modes.json on every resolve, so flipping it on needs no restart", () => {
		const original = getConfigPath()
		const dir = mkdtempSync(join(tmpdir(), "pm-enable-"))
		const path = join(dir, "permission-modes.json")
		setConfigPath(path)
		try {
			writeFileSync(path, JSON.stringify({ classifier: { enabled: false } }), "utf8")
			expect(resolveClassifierConfig(loadPermissionModesConfig()).enabled).toBe(false)

			// The same resolver, the same path, a file that changed underneath it: the new value wins.
			writeFileSync(
				path,
				JSON.stringify({
					classifier: { enabled: true, model: "litellm-lab/qwen3.8-flash-next", timeoutMs: 8000 },
				}),
				"utf8",
			)
			const cfg = resolveClassifierConfig(loadPermissionModesConfig())
			expect(cfg.enabled).toBe(true)
			expect(cfg.model).toBe("litellm-lab/qwen3.8-flash-next")
			expect(cfg.timeoutMs).toBe(8000)
		} finally {
			setConfigPath(original)
		}
	})

	it("the only memo on that path is index.ts's per-turn snapshot — it is refreshed in before_agent_start", async () => {
		// `classifierConfig` is a module-scope snapshot (index.ts:275) and a stale snapshot is exactly
		// how "I edited the config and nothing happened" turns into a reload superstition. The refresh
		// sites are the proof, so they are pinned here rather than remembered in prose.
		const src = await readFile(new URL("./index.ts", import.meta.url), "utf8")
		const REFRESH = /classifierConfig = resolveClassifierConfig\(loadPermissionModesConfig\(\)\)/g
		const sites = [...src.matchAll(REFRESH)].map((m) => m.index)
		expect(sites.length).toBeGreaterThanOrEqual(3)

		// Span checks, not fixed windows: a refresh belongs to the handler that re-applies it, and the
		// handler's extent is "from its registration to the next one" — no magic character count that a
		// future edit shifts and the test silently stops proving anything.
		const between = (from: number, to: number) => sites.filter((i) => i > from && i < to).length
		const turn = src.indexOf('pi.on("before_agent_start"')
		expect(turn).toBeGreaterThan(-1)
		expect(between(turn, src.indexOf("pi.on(", turn + 1))).toBe(1)

		// The other site is the session handler, so the refresh set is {load, turn, session} — and
		// `/reload` is nowhere in it, which is the answer to "does a config edit need a restart?".
		const onStart = src.indexOf("async function onSessionStart(")
		const registration = src.indexOf('pi.on("session_start", onSessionStart)')
		expect(onStart).toBeGreaterThan(-1)
		expect(between(onStart, registration)).toBe(1)
		expect(src).toContain('pi.on("session_tree", onSessionStart)')
	})

	it("the project-scoped file the brief points at is not on the classifier read path at all", async () => {
		// /home/u/dev/pm/.pi/permission-modes.json is `getProjectConfigPath(cwd)` — the project layer.
		// Nothing imports its loader, so a `classifier` block written there configures nothing, and the
		// "is it hot-reloaded?" question in the brief was being asked about a file nobody reads.
		const src = await readFile(new URL("./index.ts", import.meta.url), "utf8")
		expect(src).not.toContain("loadProjectPermissionModesConfig")
		expect(src).not.toContain("getProjectConfigPath")
	})
})

describe("enablement: an unusable transport never drops the judgement", () => {
	it("with no endpoint resolved, an unclassifiable call goes to a person, not through", async () => {
		resetClassifierStats()
		const r = await runGate("bash", { command: UNKNOWN_COMMAND }, { policy: POLICY })
		expect(r.outcome).toBe("prompt")
		expect(r.outcome).not.toContain("allow")
		expect(r.reason).toContain("no classifier endpoint configured")
		// Visible: the gate counts it, which is the only way `/classifier-status` can tell a config
		// state apart from flakiness. Without the counter this state is indistinguishable from success.
		expect(classifierStats.noEndpoint).toBe(1)
		expect(classifierStats.eligible).toBe(1)
	})

	it("with an endpoint that refuses, the call still prompts and the failure is counted", async () => {
		resetClassifierStats()
		const r = await runGate("bash", { command: UNKNOWN_COMMAND }, {
			policy: POLICY,
			endpoint: { baseUrl: DEAD_BASE_URL, model: "clf-gate", timeoutMs: 2000, contextTokens: 4096 },
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("classifier unavailable")
		expect(classifierStats.failed).toBe(1)
		expect(classifierStats.ok).toBe(0)
	}, 20_000)

	it("endpoint resolution reports every failure as `no endpoint`, never as a half-built one", async () => {
		const model = chatModel(DEAD_BASE_URL)
		const base = { enabled: true, model: "litellm-lab/clf-gate", timeoutMs: 1000, contextTokens: 4096 }

		expect(await resolveGateEndpoint({ ...base, enabled: false } as never, undefined)).toBeUndefined()
		expect(await resolveGateEndpoint(base as never, undefined)).toBeUndefined()
		expect(await resolveGateEndpoint(base as never, registryFor(model, { ok: false, error: "no key" }))).toBeUndefined()
		expect(await resolveGateEndpoint(base as never, {
			find: () => undefined,
			getApiKeyAndHeaders: async () => ({ ok: true }) as never,
		})).toBeUndefined()

		const resolved = await resolveGateEndpoint(base as never, registryFor(model, { ok: true, apiKey: "k" }))
		expect(resolved).toMatchObject({ baseUrl: DEAD_BASE_URL, model: "clf-gate", apiKey: "k" })

		// A key-less registry is still a usable gate endpoint — the gate's client omits the header, so a
		// no-auth server resolves and answers. Contrast `classifier.test.ts > the legacy client rejects`.
		const noKey = await resolveGateEndpoint(base as never, registryFor(model, { ok: true }))
		expect(noKey).toMatchObject({ baseUrl: DEAD_BASE_URL, model: "clf-gate" })
		expect(noKey?.apiKey).toBeUndefined()

		// The `baseUrl` branch (what the live user config uses) does not consult the registry at all.
		expect(await resolveGateEndpoint({ ...base, baseUrl: DEAD_BASE_URL, modelId: "clf-gate" } as never, undefined))
			.toMatchObject({ baseUrl: DEAD_BASE_URL, model: "clf-gate" })
	})

	it("the legacy client rejects instead of answering for the model", async () => {
		const pending = { name: "bash", input: { command: "cat README.md" } }
		const call = (modelRef: string, registry: ClassifierRegistry) =>
			classifyToolCall({
				modelRef,
				session: session(),
				pendingTool: pending,
				registry,
				timeoutMs: 2000,
				stage: "tool",
			})

		await expect(call("clf-gate", registryFor(chatModel(DEAD_BASE_URL), { ok: true }))).rejects
			.toThrow(/Invalid classifier model ref/)
		await expect(call("litellm-lab/other", registryFor(chatModel(DEAD_BASE_URL), { ok: true }))).rejects
			.toThrow(/Classifier model not found/)
		await expect(call("litellm-lab/clf-gate", registryFor(chatModel(DEAD_BASE_URL), { ok: false, error: "no credentials for litellm-lab" })))
			.rejects.toThrow(/no credentials for litellm-lab/)
		// A registry that resolves the model but has no key: pi-ai refuses the request before it reaches
		// the network. `resolveGateEndpoint` tolerates exactly this (the gate's own client sends
		// Authorization only when a key exists, which is how a no-auth LiteLLM endpoint works at all), so
		// a no-auth server that works under engine=gate fails every call under engine=legacy. Pinned here
		// because the symptom a user sees is a prompt, with nothing saying "auth plumbing", which is the
		// silent-uselessness shape this pin exists for.
		await expect(call("litellm-lab/clf-gate", registryFor(chatModel(DEAD_BASE_URL), { ok: true }))).rejects
			.toThrow(/No API key for provider/)
		// With a key, the same registry reaches the socket and the dead port answers.
		await expect(call("litellm-lab/clf-gate", registryFor(chatModel(DEAD_BASE_URL), { ok: true, apiKey: "placeholder" })))
			.rejects.toThrow(/Connection error|ECONNREFUSED|fetch failed/i)
	}, 30_000)

	it("an answer the parser cannot read is an error, never an implicit allow", async () => {
		answerStub = async () => assistantWithToolCall({ thinking: "…", reason: "looks fine" }) // no shouldBlock
		try {
			await expect(
				classifyToolCall({
					modelRef: "litellm-lab/clf-gate",
					session: session(),
					pendingTool: { name: "bash", input: { command: "cat README.md" } },
					registry: registryFor(chatModel(DEAD_BASE_URL), { ok: true }),
					timeoutMs: 2000,
					stage: "tool",
				}),
			).rejects.toThrow(/unparseable tool result/)
		} finally {
			answerStub = undefined
		}
	})

	it("a config that turns the classifier on defaults to fail-closed", () => {
		// `{}` means "enabled, and deny when the transport cannot answer" — the default is the one that
		// cannot silently become useless, and an explicit `failClosed: false` is a user's choice.
		const defaults = resolveClassifierConfig({})
		expect(defaults.enabled).toBe(true)
		expect(defaults.failClosed).toBe(true)
		expect(resolveClassifierConfig({ classifier: { enabled: true } }).failClosed).toBe(true)
	})
})

describe("a stage that could not be read reaches the attribution (D23)", () => {
	// The decider has a name now; this is the half where the named decider is told the truth. A truncated
	// reasoning answer used to arrive as three interchangeable `new Error("unparseable …")` strings, so the
	// only way a caller could tell "the model refused" from "the model never got to answer" was to parse
	// prose out of a message. The legacy client now throws one named shape carrying the bucket, and this
	// pins that the bucket is the one gate-bridge and classifier-messages already speak.
	function assistantWithText(text: string, stopReason: string): AssistantMessage {
		return {
			...assistantWithToolCall({}),
			content: [{ type: "text", text }],
			stopReason: stopReason as never,
		} as unknown as AssistantMessage
	}

	async function singleStageFailure(text: string, stopReason: string): Promise<unknown> {
		answerStub = async () => assistantWithText(text, stopReason)
		try {
			// The stage is expected to throw; returning the rejection is what lets these tests read the
			// failure's fields instead of only its message. A verdict here fails the assertion below.
			return await classifyToolCall({
				modelRef: "litellm-lab/clf-gate",
				session: session(),
				pendingTool: { name: "bash", input: { command: "tokei --stats src" } },
				registry: registryFor(chatModel(DEAD_BASE_URL), { ok: true }),
				timeoutMs: 2000,
				stage: "single",
			})
		} catch (err) {
			return err
		} finally {
			answerStub = undefined
		}
	}

	it("throws one named failure that carries its stage and its token cap", async () => {
		const err = await singleStageFailure("Thinking: this command lists so", "length")
		expect(isClassifierStageFailure(err)).toBe(true)
		const failure = err as ClassifierStageFailure
		expect(failure.kind).toBe("truncated")
		expect(failure.stage).toBe("single")
		expect(failure.maxTokens).toBe(512)
		expect(failure.reply.length).toBeGreaterThan(0)
	})

	it("hands the caller the attribution bucket instead of leaving it to guess", async () => {
		const failure = (await singleStageFailure("I think this is probably fine.", "stop")) as ClassifierStageFailure
		expect(failure.kind).toBe("prose")

		// The value is assignable to `DenialContext.classifierWhy`, which is the whole contract: the
		// caller copies it, it does not infer it from the message text.
		const line = attributionLine({
			ctx: { decidedBy: "classifier", classifierWhy: failure.classifierWhy },
			category: "run_project_code",
			targets: ["bash: tokei"],
		})
		expect(line).toContain("classifier — unavailable")
		expect(line).not.toContain("denied: the safety model judged this")

		const notice = buildClassifierUnavailableMessage("bash", "litellm-lab/clf-gate", {
			classifierWhy: failure.classifierWhy,
		})
		expect(notice).toContain("did not answer")
		expect(notice).toContain("classifier — unavailable")
		// …and the detail the static notice cannot know lives on the failure next to it.
		expect(failure.message).toContain("classifier stage single")
		expect(failure.message).toContain("max_tokens=512")
	})
})

/**
 * Every failure mode says the same thing about the verdict — there is none — and a different thing about the cause.
 *
 * The owner's ruling on posture (control flow unchanged, it is already right): layer 0 decides where it can; where
 * it cannot and the classifier is unreachable, an interactive session asks and an unattended run declines, and the
 * reason names that the classifier was not available. What was wrong was the READER'S sentence: a failed Copilot
 * Auto-session mint and an Auto pick in a dialect this client cannot speak both resolved to "no endpoint", which
 * reads as "you configured nothing" when the truth is "it is there and could not be used". The transport failures
 * (`model_not_supported`, the empty 404 that means the version header went missing, `Unsupported parameter`, a spent
 * token allowance, an answer cut off by its cap) already arrived as transport failures; what was missing was the
 * cause reaching the denial text rather than staying in the debug log.
 *
 * So each case below asserts four things: the gate fabricated no verdict, the denial calls it unavailable, the
 * specific cause is named, and the refusal prefix that means "the model judged this and said no" is nowhere.
 */
describe("every classifier failure reaches the user as unavailable, with its cause", () => {
	const COPILOT_BASE = "https://api.individual.githubcopilot.com"
	const KEY = "t".repeat(393)

	/** One catalog entry per dialect group, the shape pi's Copilot catalog has. */
	const CATALOG = [
		{ id: "gpt-4.1", api: "openai-completions", reasoning: false },
		{ id: "mai-code-1.1-flash", api: "openai-responses", reasoning: true },
		{ id: "claude-haiku-4.5", api: "anthropic-messages", reasoning: true },
	].map((m) => ({ ...m, baseUrl: COPILOT_BASE, name: m.id, contextWindow: 200_000, maxTokens: 64_000 }))

	function copilotRegistry(auth: { ok: boolean; apiKey?: string } = { ok: true, apiKey: KEY }) {
		return {
			find: (provider: string, modelId: string) =>
				provider === "github-copilot" ? (CATALOG.find((m) => m.id === modelId) as never) : undefined,
			getApiKeyAndHeaders: async () =>
				auth.ok ? ({ ok: true, apiKey: auth.apiKey } as never) : ({ ok: false, error: "no key" } as never),
		}
	}

	function copilotConfig(model: string) {
		return {
			enabled: true,
			model,
			timeoutMs: 5_000,
			contextTokens: 4096,
			copilot: resolveCopilotConfig(undefined),
		}
	}

	function respond(status: number, body: unknown): Response {
		return {
			ok: status >= 200 && status < 300,
			status,
			text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
			json: async () => body,
		} as unknown as Response
	}

	/** A Copilot endpoint as the resolver would have handed it over, for the cases whose failure is in the CALL. */
	function copilotEndpoint(over: Partial<ModelEndpoint> = {}): ModelEndpoint {
		return {
			baseUrl: COPILOT_BASE,
			model: "mai-code-1.1-flash",
			apiKey: KEY,
			api: "chat-completions",
			timeoutMs: 2000,
			contextTokens: 4096,
			copilot: {
				auto: true,
				sessionToken: "s".repeat(60),
				supportsReasoning: false,
				maxOutputTokens: 512,
				reasoningEffort: "low",
				budgetTokens: 0,
			},
			...over,
		}
	}

	/** The two lines a human reads first, rendered exactly as index.ts renders them. */
	function denial(r: GateResult, endpointKnown: boolean): string {
		const ctx = gateDenialAttribution({
			result: r,
			policy: POLICY,
			endpoint: endpointKnown,
			userMessages: 1,
		})
		return gateDenialMessage(r, { ...ctx, unattended: true })
	}

	/** Run the gate over a command only the model can judge, with no model to ask. */
	async function gateWithoutEndpoint() {
		resetClassifierStats()
		return runGate("bash", { command: UNKNOWN_COMMAND }, { policy: POLICY, userMessages: ["do the thing"] })
	}

	beforeEach(() => {
		resetClassifierUnavailability()
		resetCopilotSessions()
		resetCopilotUsage()
		resetClassifierStats()
		vi.unstubAllGlobals()
	})

	afterEach(() => {
		// The record is process state; leaving it set would make an unrelated later test read a stale cause.
		resetClassifierUnavailability()
		resetCopilotUsage()
		vi.unstubAllGlobals()
	})

	it("a failed Auto-session mint is unavailable, naming the mint's own error", async () => {
		vi.stubGlobal("fetch", async () => respond(500, "upstream proxy blew up"))
		const ep = await resolveGateEndpoint(copilotConfig("github-copilot/auto") as never, copilotRegistry() as never)
		expect(ep).toBeUndefined()
		expect(classifierUnavailability()?.cause).toBe("auto-session-failed")

		const r = await gateWithoutEndpoint()
		expect(r.outcome).toBe("prompt")
		expect(r.tier).toBe("ask")
		expect(r.reason).toContain("classifier unavailable")
		expect(r.reason).toContain("upstream proxy blew up")
		// A configured classifier that failed is NOT the same state as nothing configured — the counters say so too.
		expect(classifierStats.resolveFailed).toBe(1)
		expect(classifierStats.noEndpoint).toBe(0)
		const out = denial(r, false)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("cause:")
		expect(out).toContain("upstream proxy blew up")
		expect(out).not.toContain("no endpoint configured")
		expect(out).not.toContain(AUTO_MODE_REJECTION_PREFIX)
	})

	it("a 404 with an empty body says which header was missing, instead of blaming the URL", async () => {
		vi.stubGlobal("fetch", async () => respond(404, ""))
		await resolveGateEndpoint(copilotConfig("github-copilot/auto") as never, copilotRegistry() as never)
		const blocked = classifierUnavailability()
		expect(blocked?.cause).toBe("auto-session-failed")
		expect(blocked?.detail).toContain("X-GitHub-Api-Version")

		const out = denial(await gateWithoutEndpoint(), false)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("X-GitHub-Api-Version")
		expect(out).not.toContain("no endpoint configured")
	})

	it("an Auto pick in a dialect we cannot speak names the dialect", async () => {
		vi.stubGlobal("fetch", async () =>
			respond(200, {
				session_token: "s".repeat(60),
				selected_model: "claude-haiku-4.5",
				available_models: ["claude-haiku-4.5"],
				expires_at: Math.floor(Date.now() / 1000) + 3600,
			}),
		)
		const ep = await resolveGateEndpoint(copilotConfig("github-copilot/auto") as never, copilotRegistry() as never)
		expect(ep).toBeUndefined()
		expect(classifierUnavailability()?.cause).toBe("auto-pick-unspeakable")
		expect(classifierUnavailability()?.detail).toContain("anthropic-messages")

		const out = denial(await gateWithoutEndpoint(), false)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("anthropic-messages")
		expect(out).not.toContain("no endpoint configured")
		// A dialect we cannot speak is not a verdict either way: the gate asked a person instead.
		expect(out).not.toContain(AUTO_MODE_REJECTION_PREFIX)
	})

	it("an explicitly configured model in an unspeakable dialect is also an unavailable classifier", async () => {
		const ep = await resolveGateEndpoint(copilotConfig("github-copilot/claude-haiku-4.5") as never, copilotRegistry() as never)
		expect(ep).toBeUndefined()
		expect(classifierUnavailability()?.cause).toBe("model-unspeakable")
		expect(classifierUnavailability()?.detail).toContain("claude-haiku-4.5")
		expect(denial(await gateWithoutEndpoint(), false)).toContain("classifier — unavailable")
	})

	/** Run the gate against a Copilot endpoint whose CALL fails in one specific way. */
	async function failingCall(ep: ModelEndpoint, reply: () => Response) {
		const seen: string[] = []
		vi.stubGlobal("fetch", async (url: string) => {
			seen.push(url)
			return reply()
		})
		resetClassifierStats()
		const r = await runGate("bash", { command: UNKNOWN_COMMAND }, {
			policy: POLICY,
			endpoint: ep,
			userMessages: ["do the thing"],
		})
		return { r, calls: seen.length }
	}

	it("`model_not_supported` names the model GitHub will not serve", async () => {
		const { r } = await failingCall(copilotEndpoint(), () =>
			respond(400, JSON.stringify({ error: { code: "model_not_supported", message: "Requested model not available" } })),
		)
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("classifier unavailable")
		expect(r.reason).toContain("model_not_supported")
		expect(r.reason).toContain("Auto session token")
		const out = denial(r, true)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("model_not_supported")
		expect(out).not.toContain(AUTO_MODE_REJECTION_PREFIX)
	})

	it("a model-call 404 with an empty body names the header, not the path", async () => {
		const { r } = await failingCall(copilotEndpoint(), () => respond(404, ""))
		expect(r.reason).toContain("X-GitHub-Api-Version")
		expect(denial(r, true)).toContain("classifier — unavailable")
	})

	it("`Unsupported parameter` says the request should not have sent it", async () => {
		const { r } = await failingCall(copilotEndpoint(), () =>
			respond(400, "Unsupported parameter: 'temperature' is not supported with this model"),
		)
		expect(r.reason).toContain("Unsupported parameter")
		expect(r.reason).toContain("should not have sent it")
		expect(denial(r, true)).toContain("classifier — unavailable")
	})

	it("a spent token allowance is an unavailable classifier that refuses to send, and says spent/budget", async () => {
		recordCopilotUsage({ inputTokens: 40, outputTokens: 60, reasoningTokens: 0, totalTokens: 100 })
		const { r, calls } = await failingCall(copilotEndpoint({ copilot: { auto: true, sessionToken: "s".repeat(60), supportsReasoning: false, maxOutputTokens: 512, reasoningEffort: "low", budgetTokens: 10 } }), () => respond(200, {}))
		// Refused before the network: a spent allowance must not be paid for again.
		expect(calls).toBe(0)
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("budget spent (100/10 tokens)")
		const out = denial(r, true)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("budget spent (100/10 tokens)")
		expect(out).not.toContain(AUTO_MODE_REJECTION_PREFIX)
	})

	it("an answer cut off by its token cap is a transport failure, never a short verdict", async () => {
		const { r } = await failingCall(copilotEndpoint({ api: "responses" }), () =>
			respond(200, {
				status: "incomplete",
				incomplete_details: { reason: "max_output_tokens" },
				output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "The verdict is" }] }],
				usage: { input_tokens: 900, output_tokens: 512, total_tokens: 1412 },
			}),
		)
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("truncated")
		expect(r.reason).toContain("ran into its token cap")
		const out = denial(r, true)
		expect(out).toContain("classifier — unavailable")
		expect(out).toContain("token cap")
		expect(out).not.toContain(AUTO_MODE_REJECTION_PREFIX)
	})

	it("and when nothing is configured at all, the sentence is still the config answer", async () => {
		// The other half of the rule: a Copilot failure must not crowd out the truthful sentence for the case where
		// the user genuinely never set a classifier up.
		const r = await gateWithoutEndpoint()
		expect(r.reason).toContain("no classifier endpoint configured")
		expect(classifierStats.noEndpoint).toBe(1)
		expect(denial(r, false)).toContain("no endpoint configured")
	})

	it("the long notice to the agent names the cause too, when the caller has one", () => {
		const notice = buildClassifierUnavailableMessage("bash", "github-copilot/auto", {
			classifierWhy: "unavailable",
			classifierCause: "the Copilot Auto session could not be minted: HTTP 500 upstream proxy blew up",
		})
		expect(notice).toContain("upstream proxy blew up")
		expect(notice).toContain("did not answer")
		expect(isClassifierDenial(notice)).toBe(false)
	})
})
