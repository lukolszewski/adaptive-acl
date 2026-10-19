import { beforeEach, describe, expect, it, vi } from "vitest"
import { resolveCopilotConfig } from "./config.ts"
import {
	classifierUnavailability,
	resetClassifierUnavailability,
	resolveGateEndpoint,
} from "./gate-bridge.ts"

import {
	AUTO_SESSION_MODEL_HINTS,
	SESSION_FAILURE_COOLDOWN_MS,
	SESSION_REFRESH_MARGIN_MS,
	SESSION_TOKEN_HEADER,
	acquireAutoSession,
	autoSessionMintBody,
	copilotBudgetSpent,
	copilotBudgetText,
	copilotRequestHeaders,
	copilotTokensSpent,
	FALLBACK_SESSION_LIFETIME_MS,
	parseExpiresAt,
	readCopilotUsage,
	recordCopilotUsage,
	resetCopilotSessions,
	resetCopilotUsage,
	type FetchLike,
} from "./copilot-session.ts"

/**
 * No network here, by rule: the live path is `bun /home/u/dev/pm/.probe/copilot-rt.ts` (and, after W89,
 * `tools/copilot-probe.ts --live`), and this account has a small monthly allowance. Everything below runs
 * against a stubbed `fetch` whose responses are the bodies measured live on 2026-10-17.
 */

const BASE_URL = "https://api.individual.githubcopilot.com"
const KEY = "t".repeat(393)

type Call = { url: string; init: Record<string, unknown> }

function jsonResponse(status: number, body: unknown): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
		json: async () => body,
	} as unknown as Response
}

/** The stubs are object literals, not undici `Response`s, so `instanceof Response` is false for them. Test the
 *  shape the code under test actually calls. */
function isResponse(value: unknown): value is Response {
	return typeof (value as { text?: unknown } | null)?.text === "function"
}

/** A stub `fetch` plus the calls it recorded. `reply` may be a body or a list consumed in order. */
function stubFetch(reply: unknown | unknown[]): { fetch: FetchLike; calls: Call[] } {
	const calls: Call[] = []
	let n = 0
	const fetch: FetchLike = async (url, init) => {
		calls.push({ url, init })
		const item = Array.isArray(reply) ? reply[Math.min(n++, reply.length - 1)] : reply
		if (item instanceof Error) throw item
		// A case may hand its own Response (its own status/body); a plain object is a 200 with that JSON.
		if (isResponse(item)) return item
		return jsonResponse(200, item)
	}
	return { fetch, calls }
}

/** The session body as GitHub actually answered, token shortened to something a test may print. */
function sessionBody(opts: { expiresAt?: unknown; token?: string; selected?: string } = {}) {
	return {
		session_token: opts.token ?? "s".repeat(426),
		selected_model: opts.selected ?? "mai-code-1.1-flash",
		available_models: ["mai-code-1.1-flash", "gpt-5-mini"],
		expires_at: opts.expiresAt ?? Math.floor(Date.now() / 1000) + 3600,
	}
}

/** A clock the tests wind by hand. */
function clock(startMs = 1_792_189_934_000): {
	now: () => number
	set: (ms: number) => void
	advance: (ms: number) => void
} {
	let t = startMs
	return {
		now: () => t,
		set: (ms) => void (t = ms),
		advance: (ms) => void (t += ms),
	}
}

const okBody = sessionBody({ expiresAt: 1_792_193_534 }) // the measured `expires_at`, epoch SECONDS

/**
 * The same body for the `resolveGateEndpoint` block, which cannot inject a clock. `resolveGateEndpoint` builds the
 * session options itself, so `acquireAutoSession` falls back to real `Date.now`; a fixture pinned to the measured
 * epoch therefore goes stale in wall time about an hour after the measurement and every gated call re-mints — a
 * caching test that passes for one hour and fails forever after. Tests that ride the real clock need a fixture
 * that rides it too; the wind-the-clock tests above keep `okBody` and its pinned epoch.
 */
const okBodyLive = sessionBody({ selected: "mai-code-1.1-flash" })

beforeEach(() => {
	resetCopilotSessions()
	resetCopilotUsage()
})

describe("acquireAutoSession — the request", () => {
	it("posts the auto hint to /models/session with the headers GitHub requires", async () => {
		const { fetch, calls } = stubFetch(okBody)
		const r = await acquireAutoSession({ baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch })

		expect(r.ok).toBe(true)
		expect(calls).toHaveLength(1)
		expect(calls[0]!.url).toBe(`${BASE_URL}/models/session`)
		const init = calls[0]!.init as { method: string; headers: Record<string, string>; body: string }
		expect(init.method).toBe("POST")
		expect(JSON.parse(init.body)).toEqual({ auto_mode: { model_hints: ["auto"] } })
		// Measured: without this exact header the POST is 404 with an empty body. Pinned as a header, not as a
		// comment, because a "404 not found" message sends the reader to a URL that is not the problem.
		expect(init.headers["X-GitHub-Api-Version"]).toBe("2026-08-01")
		expect(init.headers.Authorization).toBe(`Bearer ${KEY}`)
		expect(init.headers["Editor-Version"]).toBeTruthy()
		// The session mint itself must not carry a session token.
		expect(init.headers[SESSION_TOKEN_HEADER]).toBeUndefined()
	})

	it("reads the pick, the availability list and the expiry out of the response", async () => {
		const { fetch } = stubFetch(okBody)
		const r = await acquireAutoSession({ baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch })
		expect(r.ok && r.session).toEqual({
			sessionToken: "s".repeat(426),
			selectedModel: "mai-code-1.1-flash",
			availableModels: ["mai-code-1.1-flash", "gpt-5-mini"],
			// 1792193534 s → ms. The unit is a measured fact, not a guess.
			expiresAtMs: 1_792_193_534_000,
			baseUrl: BASE_URL,
		})
	})

	it("never puts the credential or the token in a returned error", async () => {
		const { fetch } = stubFetch(jsonResponseRaw(401, '{"message":"Bad credentials"}'))
		const r = await acquireAutoSession({ baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch })
		expect(r.ok).toBe(false)
		if (!r.ok) {
			expect(r.error).toContain("401")
			expect(r.error).not.toContain(KEY)
		}
	})
})

function jsonResponseRaw(status: number, text: string): Response {
	return { ok: status < 300, status, text: async () => text } as unknown as Response
}

describe("acquireAutoSession — cache, refresh, single-flight", () => {
	it("serves the cached session for the rest of its life — one POST per hour, not per call", async () => {
		const { fetch, calls } = stubFetch(okBody)
		const { now, set } = clock()
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now }

		const first = await acquireAutoSession(opts)
		for (let i = 0; i < 50; i++) await acquireAutoSession(opts)
		expect(calls).toHaveLength(1)

		set(1_792_193_534_000 - SESSION_REFRESH_MARGIN_MS - 1)
		await acquireAutoSession(opts)
		expect(calls).toHaveLength(1)
		expect(first.ok).toBe(true)
	})

	it("refreshes inside the margin instead of waiting for the token to die", async () => {
		const { fetch, calls } = stubFetch([okBody, sessionBody({ token: "n".repeat(400), expiresAt: 1_792_197_134 })])
		const { now, advance } = clock()
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now }

		await acquireAutoSession(opts)
		expect(calls).toHaveLength(1)

		advance(3600_000 - SESSION_REFRESH_MARGIN_MS) // now inside the margin
		const r = await acquireAutoSession(opts)
		expect(calls).toHaveLength(2)
		expect(r.ok && r.session.sessionToken).toBe("n".repeat(400))
	})

	it("two calls in the same turn share one POST", async () => {
		let resolveFetch: ((v: Response) => void) | undefined
		const fetch: FetchLike = () => new Promise<Response>((res) => void (resolveFetch = res))
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now: clock().now }

		const a = acquireAutoSession(opts)
		const b = acquireAutoSession(opts)
		resolveFetch!(jsonResponse(200, okBody))
		const [ra, rb] = await Promise.all([a, b])

		expect(ra.ok && rb.ok).toBe(true)
		const tokenA = ra.ok ? ra.session.sessionToken : undefined
		const tokenB = rb.ok ? rb.session.sessionToken : undefined
		expect(tokenA).toBeTruthy()
		expect(tokenA).toBe(tokenB)
	})

	it("a failed refresh keeps a still-live token rather than losing the classifier", async () => {
		const { fetch, calls } = stubFetch([okBody, new Error("socket hang up")])
		const { now, advance } = clock()
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now }

		await acquireAutoSession(opts)
		advance(3600_000 - SESSION_REFRESH_MARGIN_MS) // past the margin, before the hard expiry
		const r = await acquireAutoSession(opts)

		expect(calls).toHaveLength(2)
		expect(r.ok).toBe(true) // the stale-but-alive token still works
		expect(r.ok && r.session.sessionToken).toBe("s".repeat(426))
	})

	it("reports unavailability instead of throwing once the token is truly gone", async () => {
		const failing = stubFetch(new Error("socket hang up"))
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: failing.fetch, now: clock().now }

		const r = await acquireAutoSession(opts)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toContain("socket hang up")

		// Cooldown: the gate resolves an endpoint on every tool call, so a dead Copilot must not cost one
		// failing request per call.
		const before = failing.calls.length
		const again = await acquireAutoSession(opts)
		expect(failing.calls.length).toBe(before)
		expect(again.ok).toBe(false)
	})

	it("tries again after the cooldown", async () => {
		const { fetch, calls } = stubFetch([new Error("boom"), okBody])
		const { now, advance } = clock()
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now }

		expect((await acquireAutoSession(opts)).ok).toBe(false)
		expect(calls).toHaveLength(1)
		advance(SESSION_FAILURE_COOLDOWN_MS + 1)
		expect((await acquireAutoSession(opts)).ok).toBe(true)
		expect(calls).toHaveLength(2)
	})

	it("keeps accounts apart", async () => {
		const { fetch, calls } = stubFetch(okBody)
		const opts = { baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch }
		await acquireAutoSession(opts)
		await acquireAutoSession({ ...opts, apiKey: "u".repeat(200) })
		expect(calls).toHaveLength(2)
	})
})

describe("acquireAutoSession — every failure is an answer, never an exception", () => {
	const cases: Array<[string, unknown, RegExp]> = [
		// The one that cost the supervisor a wrong conclusion: 404, empty body, and a URL that looks fine.
		["404 with no body", jsonResponseRaw(404, ""), /X-GitHub-Api-Version: 2026-08-01/],
		["400 model not available", jsonResponseRaw(400, '{"error":"Requested model not available for session"}'), /HTTP 400.*not available for session/],
		["a 200 that is not JSON", jsonResponseRaw(200, "<html>proxy said no</html>"), /not JSON/],
		["a 200 with no token", { nothing: true }, /no session_token/],
	]
	it.each(cases)("maps %s to {ok:false}", async (_name, body, pattern) => {
		const fetch: FetchLike = async () => (isResponse(body) ? body : jsonResponse(200, body))
		const r = await acquireAutoSession({ baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch })
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toMatch(pattern)
	})

	it("survives a missing base url and a missing key without reaching the network", async () => {
		const { fetch, calls } = stubFetch(okBody)
		expect((await acquireAutoSession({ baseUrl: "", apiKey: KEY, fetchImpl: fetch })).ok).toBe(false)
		expect((await acquireAutoSession({ baseUrl: BASE_URL, apiKey: "", fetchImpl: fetch })).ok).toBe(false)
		expect(calls).toHaveLength(0)
	})
})

describe("parseExpiresAt", () => {
	it("reads epoch seconds — the unit GitHub sends", () => {
		expect(parseExpiresAt(1_792_193_534, 0)).toBe(1_792_193_534_000)
	})
	it("reads epoch milliseconds when a server ever means that", () => {
		expect(parseExpiresAt(1_792_193_534_000, 0)).toBe(1_792_193_534_000)
		expect(parseExpiresAt("1792193534", 0)).toBe(1_792_193_534_000)
	})
	it("reads an ISO timestamp", () => {
		expect(parseExpiresAt("2026-10-17T00:00:00.000Z", 0)).toBe(Date.parse("2026-10-17T00:00:00.000Z"))
	})
	it("falls back to a shorter-than-measured life when the field is unusable", () => {
		for (const bad of [undefined, null, 0, -1, "later", NaN]) {
			expect(parseExpiresAt(bad, 1_000_000)).toBe(1_000_000 + FALLBACK_SESSION_LIFETIME_MS)
		}
	})
})

describe("headers and the allowance", () => {
	it("attaches the session header only when a token is handed in", () => {
		expect(copilotRequestHeaders(KEY)[SESSION_TOKEN_HEADER]).toBeUndefined()
		expect(copilotRequestHeaders(KEY, "tok")[SESSION_TOKEN_HEADER]).toBe("tok")
		expect(copilotRequestHeaders(KEY, "")[SESSION_TOKEN_HEADER]).toBeUndefined()
		// Every Copilot request carries the version header, session mint included.
		expect(copilotRequestHeaders(KEY)["X-GitHub-Api-Version"]).toBe("2026-08-01")
	})

	it("adds every call's tokens to one counter and reads the usage shapes both dialects send", () => {
		// The measured `usage` object from /responses …
		const responses = readCopilotUsage({
			usage: {
				input_tokens: 69,
				output_tokens: 269,
				total_tokens: 338,
				output_tokens_details: { reasoning_tokens: 192 },
			},
		})
		expect(responses).toEqual({ inputTokens: 69, outputTokens: 269, reasoningTokens: 192, totalTokens: 338 })
		// … and the chat/completions shape.
		const chat = readCopilotUsage({ usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } })
		expect(chat?.totalTokens).toBe(15)
		// No usage at all is not zero spent: the caller must be able to tell "we were not told" from "free".
		expect(readCopilotUsage({})).toBeUndefined()
		expect(readCopilotUsage(null)).toBeUndefined()

		expect(recordCopilotUsage(responses)).toBe(338)
		expect(recordCopilotUsage(undefined)).toBe(338)
		expect(copilotTokensSpent()).toBe(338)
	})

	it("treats a zero budget as no cap, and a spent one as spent", () => {
		expect(copilotBudgetSpent(0)).toBe(false)
		expect(copilotBudgetSpent(undefined)).toBe(false)
		expect(copilotBudgetSpent(-1)).toBe(false)
		recordCopilotUsage({ inputTokens: 90, outputTokens: 10, reasoningTokens: 0, totalTokens: 100 })
		expect(copilotBudgetSpent(100)).toBe(true)
		expect(copilotBudgetSpent(101)).toBe(false)
	})
})

/**
 * The D57 narrowing. What makes it code rather than hope is the measurement behind it
 * (`bun tools/copilot-probe.ts --live --hints`, §2b of `docs/COPILOT-COMPAT-MEASUREMENTS.md`):
 * `model_hints` filters the pool GitHub just offered by MODEL ID — `["gpt-5-mini"]` turned a pool of two into
 * `[gpt-5-mini]` and picked it — while an id GitHub cannot match (a dialect name included) returns a 200 whose
 * pool is empty and whose `selected_model` is `""`. So the narrowing is built from GitHub's own
 * `available_models`, and an empty hint list is never sent.
 *
 * Every case here stubs `fetch`; none of them touches the network or `~/.copilot`.
 */
describe("acquireAutoSession — narrowing the pick by hint (D57)", () => {
	/** A mint body whose pool the case chooses, expiry derived from the case's own clock so the session stays live. */
	function mintBody(opts: { selected: string; pool: string[]; token?: string; now?: () => number }): unknown {
		return {
			session_token: opts.token ?? "s".repeat(100),
			selected_model: opts.selected,
			available_models: opts.pool,
			expires_at: Math.floor((opts.now ? opts.now() : Date.now()) / 1000) + 3600,
		}
	}

	/** The bodies that actually went on the wire, parsed. Pinned shape: a future edit must not widen the mint.
	 * `mintOnce` is the only sender, so these are the bytes the gate sends. */
	function sentBodies(calls: Call[]): Array<{ auto_mode: { model_hints: string[] } }> {
		return calls.map((c) => JSON.parse((c.init as { body: string }).body))
	}

	/** The catalog truth of one case, as the endpoint resolver would hand it over. */
	function encodableOnly(ids: string[]): (id: string) => boolean {
		return (id) => ids.includes(id)
	}

	it("asks the measured control question first, even when a dialect test is supplied", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "gpt-5-mini", pool: ["gpt-5-mini", "claude-haiku-4.5"], now }),
			mintBody({ selected: "gpt-5-mini", pool: ["gpt-5-mini"], token: "n".repeat(80), now }),
		])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["gpt-5-mini"]),
		})
		// A pick we can address means the retry never happens: one POST, the body that has always been sent.
		expect(calls).toHaveLength(1)
		expect(sentBodies(calls)[0]).toEqual({ auto_mode: { model_hints: ["auto"] } })
		expect(r.ok && r.session.selectedModel).toBe("gpt-5-mini")
	})

	it("a pick we cannot speak buys ONE more mint, asking for the offered ids we can speak", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "claude-haiku-4.5", pool: ["zzz-new-1", "claude-haiku-4.5"], token: "s".repeat(100), now }),
			mintBody({ selected: "zzz-new-1", pool: ["zzz-new-1"], token: "n".repeat(80), now }),
		])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["zzz-new-1"]),
		})
		expect(calls).toHaveLength(2)
		expect(sentBodies(calls)[1]).toEqual({ auto_mode: { model_hints: ["zzz-new-1"] } })
		// The retry is the session we keep — its token is the one that can address its own pick.
		expect(r.ok && r.session.sessionToken).toBe("n".repeat(80))
		expect(r.ok && r.session.selectedModel).toBe("zzz-new-1")
	})

	it("hints are GitHub's own ids, filtered — never a name this file knows", async () => {
		const { now } = clock()
		// A pool of ids that exist nowhere in this repository, which is the point: a catalog that churns (row 3)
		// must not need an edit here for the narrowing to work.
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "qqq-claude-x", pool: ["qqq-gpt-y", "qqq-claude-x"], now }),
			mintBody({ selected: "qqq-gpt-y", pool: ["qqq-gpt-y"], token: "n".repeat(60), now }),
		])
		await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["qqq-gpt-y"]),
		})
		const hints = sentBodies(calls)[1]!.auto_mode.model_hints
		expect(hints).toEqual(["qqq-gpt-y"])
		// Every hint was offered by the first mint: the narrowing is a subset of GitHub's answer, not a wish.
		const offered = ["qqq-gpt-y", "qqq-claude-x"]
		expect(hints.every((h) => offered.includes(h))).toBe(true)
	})

	it("when nothing offered is speakable there is ONE mint, and the unspeakable pick is kept for the message", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([mintBody({ selected: "qqq-claude-x", pool: ["qqq-claude-x"], now })])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly([]), // a client that speaks none of what is offered
		})
		// No empty hint list on the wire: an unmatched hint is measured to answer with an empty pool, which would
		// replace "GitHub's pick speaks anthropic-messages" with the vaguer "named no model".
		expect(calls).toHaveLength(1)
		expect(sentBodies(calls)[0]).toEqual({ auto_mode: { model_hints: ["auto"] } })
		expect(r.ok && r.session.selectedModel).toBe("qqq-claude-x")
	})

	it("an empty pool and an empty selected_model (the measured unmatched-hint shape) buys no second mint", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([{ session_token: "s".repeat(60), selected_model: "", available_models: [], expires_at: Math.floor(now() / 1000) + 3600 }])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["anything"]),
		})
		expect(calls).toHaveLength(1)
		expect(r.ok && r.session.selectedModel).toBe("")
		expect(r.ok && r.session.availableModels).toEqual([])
	})

	it("a retry that fails does not replace the session we already had", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "claude-x", pool: ["gpt-y", "claude-x"], token: "s".repeat(100), now }),
			jsonResponseRaw(500, '{"message":"boom"}'),
		])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["gpt-y"]),
		})
		expect(calls).toHaveLength(2)
		// The first answer is still a session, and it still names the pick the reader needs to be told about.
		expect(r.ok).toBe(true)
		expect(r.ok && r.session.sessionToken).toBe("s".repeat(100))
		expect(r.ok && r.session.selectedModel).toBe("claude-x")
	})

	it("a retry that hands back another unspeakable pick is thrown away", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "claude-x", pool: ["gpt-y", "claude-x"], token: "s".repeat(100), now }),
			mintBody({ selected: "claude-z", pool: ["claude-z"], token: "n".repeat(80), now }),
		])
		const r = await acquireAutoSession({
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["gpt-y"]),
		})
		expect(calls).toHaveLength(2)
		expect(r.ok && r.session.sessionToken).toBe("s".repeat(100))
	})

	it("two mints is the ceiling per acquisition, and the cache still holds afterwards", async () => {
		const { now } = clock()
		const { fetch, calls } = stubFetch([
			mintBody({ selected: "claude-x", pool: ["gpt-y", "claude-x"], now }),
			mintBody({ selected: "gpt-y", pool: ["gpt-y"], token: "n".repeat(80), now }),
		])
		const opts = {
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now,
			encodableModel: encodableOnly(["gpt-y"]),
		}
		expect((await acquireAutoSession(opts)).ok).toBe(true)
		for (let i = 0; i < 20; i++) await acquireAutoSession(opts)
		// Two, not twenty: one control mint plus the single narrowing retry, then the cache takes over.
		expect(calls).toHaveLength(2)
	})

	it("two callers in one turn still share one acquisition — narrowing did not break single-flight", async () => {
		let resolveFetch: ((v: Response) => void) | undefined
		const fetch: FetchLike = () => new Promise<Response>((res) => void (resolveFetch = res))
		const opts = {
			baseUrl: BASE_URL, apiKey: KEY, fetchImpl: fetch, now: clock().now,
			encodableModel: encodableOnly(["zzz-new-1"]),
		}
		const a = acquireAutoSession(opts)
		const b = acquireAutoSession(opts)
		resolveFetch!(jsonResponse(200, mintBody({ selected: "zzz-new-1", pool: ["zzz-new-1"], token: "n".repeat(80) })))
		const [ra, rb] = await Promise.all([a, b])
		expect(ra.ok && rb.ok).toBe(true)
		if (ra.ok && rb.ok) expect(ra.session.sessionToken).toBe(rb.session.sessionToken)
	})
})

describe("autoSessionMintBody — the shape of the mint", () => {
	it("defaults to the one hint ever measured, and copies the hints it is given", () => {
		expect(AUTO_SESSION_MODEL_HINTS).toEqual(["auto"])
		expect(autoSessionMintBody()).toEqual({ auto_mode: { model_hints: ["auto"] } })
		expect(autoSessionMintBody(["a", "b"])).toEqual({ auto_mode: { model_hints: ["a", "b"] } })
		// The caller's array is not aliased into the body: a later mutation must not change what we send.
		const hints = ["a"]
		const body = autoSessionMintBody(hints)
		hints.push("mutated")
		expect(body.auto_mode.model_hints).toEqual(["a"])
	})
})

// ---------------------------------------------------------------- the endpoint that consumes the session
//
// `resolveGateEndpoint` lives in gate-bridge.ts, which has no test file of its own and is not editable by any
// other task than W87; the Copilot cases of that decision are the other half of this module's contract, so they
// are pinned here rather than waiting for a file that does not exist. Fake registries only — no network.

const COPILOT_BASE = "https://api.individual.githubcopilot.com"

type CatalogEntry = { id: string; api: string; reasoning?: boolean }

function catalogEntry(m: CatalogEntry) {
	return { ...m, baseUrl: COPILOT_BASE, name: m.id, contextWindow: 200_000, maxTokens: 64_000 }
}

function registryFor(catalog: CatalogEntry[], auth: { ok: boolean; apiKey?: string } = { ok: true, apiKey: KEY }) {
	return {
		find: (provider: string, modelId: string) =>
			provider === "github-copilot" ? (catalog.find((m) => m.id === modelId) as never) : undefined,
		getApiKeyAndHeaders: async () => (auth.ok ? ({ ok: true, apiKey: auth.apiKey } as never) : ({ ok: false, error: "no key" } as never)),
	}
}

/** A registry with one entry per dialect group, the way pi's Copilot catalog looks. */
const CATALOG = [
	{ id: "gpt-4.1", api: "openai-completions", reasoning: false },
	{ id: "gpt-5-mini", api: "openai-responses", reasoning: true },
	{ id: "mai-code-1.1-flash", api: "openai-responses", reasoning: true },
	{ id: "claude-haiku-4.5", api: "anthropic-messages", reasoning: true },
].map(catalogEntry)

function configFor(model: string, copilot?: Record<string, unknown>) {
	return {
		enabled: true,
		model,
		timeoutMs: 15_000,
		contextTokens: 4096,
		copilot: resolveCopilotConfig(copilot as never),
	}
}

describe("resolveGateEndpoint — the Copilot cases", () => {
	/** Stub the Auto-session POST and count how often GitHub was asked. */
	function stubSession(body: unknown): number[] {
		const calls: number[] = []
		vi.stubGlobal("fetch", async (url: string) => {
			calls.push(1)
			return {
				ok: true,
				status: 200,
				text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
			} as unknown as Response
		})
		return calls
	}

	it("github-copilot/auto resolves to the pick, the pick's dialect, and the session token", async () => {
		const calls = stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		expect(calls).toHaveLength(1)
		expect(ep).toMatchObject({
			baseUrl: COPILOT_BASE,
			model: "mai-code-1.1-flash", // GitHub's pick, not anything in the config
			api: "responses",
			apiKey: KEY,
			copilot: {
				auto: true,
				sessionToken: "s".repeat(426),
				supportsReasoning: true,
				maxOutputTokens: 512,
				reasoningEffort: "low",
				budgetTokens: 0,
			},
		})
	})

	it("mints once and reuses: every gated tool call resolves an endpoint, the account pays once an hour", async () => {
		const calls = stubSession(okBodyLive)
		const config = configFor("github-copilot/auto") as never
		const registry = registryFor(CATALOG) as never
		await resolveGateEndpoint(config, registry)
		await resolveGateEndpoint(config, registry)
		await resolveGateEndpoint(config, registry)
		expect(calls).toHaveLength(1)
	})

	it("carries the user's copilot knobs onto the endpoint", async () => {
		stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(
			configFor("github-copilot/auto", { maxOutputTokens: 2048, reasoningEffort: "medium", budgetTokens: 50_000 }) as never,
			registryFor(CATALOG) as never,
		)
		expect(ep?.copilot).toMatchObject({ maxOutputTokens: 2048, reasoningEffort: "medium", budgetTokens: 50_000 })
	})

	it("sessionEnabled: false means no endpoint at all — no guess at a model the user did not choose", async () => {
		const calls = stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto", { sessionEnabled: false }) as never, registryFor(CATALOG) as never)
		expect(ep).toBeUndefined()
		expect(calls).toHaveLength(0)
	})

	it("a failed session means no endpoint, and the gate falls back to asking", async () => {
		vi.stubGlobal("fetch", async () => ({ ok: false, status: 404, text: async () => "" }) as unknown as Response)
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		expect(ep).toBeUndefined()
	})

	it("an Auto pick the client cannot speak (anthropic-messages) is no endpoint, not a wrong request", async () => {
		stubSession(sessionBody({ selected: "claude-haiku-4.5" }))
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		expect(ep).toBeUndefined()
	})

	it("a spent budget, an unusable pick and a missing credential stay three different sentences", async () => {
		// Three levers a reader can pull, so they must never collapse into one string: raise the budget, choose
		// a model Auto will not offer, re-authenticate Copilot. And none of them may read as "no endpoint
		// configured", which sends a reader with a working Copilot login to edit a config that is fine.
		resetCopilotUsage()
		recordCopilotUsage({ inputTokens: 600, outputTokens: 400, reasoningTokens: 0, totalTokens: 1000 })
		const spent = copilotBudgetText(1000, copilotTokensSpent())

		resetCopilotSessions()
		const noKey = await acquireAutoSession({ baseUrl: BASE_URL, apiKey: "", fetchImpl: stubFetch(okBody).fetch })
		expect(noKey.ok).toBe(false)
		const credential = noKey.ok ? "" : noKey.error

		resetClassifierUnavailability()
		stubSession(sessionBody({ selected: "claude-haiku-4.5" }))
		await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		const unspeakable = classifierUnavailability()
		expect(unspeakable?.cause).toBe("auto-pick-unspeakable")

		resetClassifierUnavailability()
		// The session cache is per (baseUrl, key) and lives an hour, so a second resolution in the same test has
		// to be handed a cleared cache or it re-reads the first fixture's pick.
		resetCopilotSessions()
		stubSession({ ...sessionBody(), selected_model: "", available_models: [] }) // the measured unmatched-hint shape
		await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		const unnamed = classifierUnavailability()
		expect(unnamed?.cause).toBe("auto-pick-unnamed")

		const texts = [spent, credential, unspeakable?.detail ?? "", unnamed?.detail ?? ""]
		for (const t of texts) {
			expect(t.length).toBeGreaterThan(0)
			expect(t).not.toContain("no endpoint configured")
		}
		expect(new Set(texts).size).toBe(texts.length)
	})

	it("an Auto pick pi's catalog has never heard of still gets a dialect, and no reasoning field", async () => {
		stubSession(sessionBody({ selected: "mai-new-1", token: "n".repeat(100) }))
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG) as never)
		// Both Auto picks ever observed are openai-responses; a wrong guess is a 400 → transport failure, never a verdict.
		expect(ep).toMatchObject({ model: "mai-new-1", api: "responses", copilot: { auto: true, supportsReasoning: false } })
	})

	it("an explicit model resolves through the catalog and never asks for a session", async () => {
		const calls = stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(configFor("github-copilot/gpt-4.1") as never, registryFor(CATALOG) as never)
		expect(calls).toHaveLength(0) // fact 5: an explicit pick must not mint, and must not carry the header
		expect(ep).toMatchObject({
			baseUrl: COPILOT_BASE,
			model: "gpt-4.1",
			api: "chat-completions",
			copilot: { auto: false, supportsReasoning: false },
		})
		expect(ep?.copilot?.sessionToken).toBeUndefined()
	})

	it("an explicit model is honoured by id even when it reasons", async () => {
		const ep = await resolveGateEndpoint(configFor("github-copilot/gpt-5-mini") as never, registryFor(CATALOG) as never)
		expect(ep).toMatchObject({ model: "gpt-5-mini", api: "responses", copilot: { auto: false, supportsReasoning: true } })
	})

	it("an explicit model that is not in the catalog has no known dialect, so no endpoint", async () => {
		stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(configFor("github-copilot/some-model-pi-has-not-listed") as never, registryFor(CATALOG) as never)
		expect(ep).toBeUndefined()
	})

	it("an explicit anthropic-messages model is not speakable by this client", async () => {
		const ep = await resolveGateEndpoint(configFor("github-copilot/claude-haiku-4.5") as never, registryFor(CATALOG) as never)
		expect(ep).toBeUndefined()
	})

	it("without a credential there is no endpoint, and no session is minted", async () => {
		const calls = stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(configFor("github-copilot/auto") as never, registryFor(CATALOG, { ok: false }) as never)
		expect(ep).toBeUndefined()
		expect(calls).toHaveLength(0)
	})

	it("an explicit classifier.baseUrl still wins over everything Copilot, byte-identically", async () => {
		const calls = stubSession(okBodyLive)
		const ep = await resolveGateEndpoint(
			{ ...configFor("github-copilot/auto"), baseUrl: "http://127.0.0.1:9/v1", modelId: "clf-gate" } as never,
			registryFor(CATALOG) as never,
		)
		expect(calls).toHaveLength(0)
		expect(ep).toEqual({ baseUrl: "http://127.0.0.1:9/v1", model: "clf-gate", timeoutMs: 15_000, contextTokens: 4096 })
		expect(ep?.api).toBeUndefined()
		expect(ep?.copilot).toBeUndefined()
	})

	it("a non-Copilot registry model is untouched by any of this", async () => {
		const registry = {
			find: (provider: string) => (provider === "litellm-lab" ? ({ id: "clf-gate", baseUrl: "http://x/v1", api: "openai-completions" } as never) : undefined),
			getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" } as never),
		}
		const ep = await resolveGateEndpoint({ ...configFor("litellm-lab/clf-gate"), copilot: undefined } as never, registry as never)
		expect(ep).toEqual({ baseUrl: "http://x/v1", model: "clf-gate", apiKey: "k", timeoutMs: 15_000, contextTokens: 4096 })
	})
})

describe("the D57 narrowing is wired to the resolver (gate-bridge → copilot-session)", () => {
	/**
	 * W91 built the retry in `copilot-session.ts` and could not edit `gate-bridge.ts`, so it handed over the one call
	 * site that passes `encodableModel` — and noted, correctly, that a test for that glue belongs to whoever lands the
	 * hunk. Without it the whole feature is dormant and green: `encodableModel` is optional, so forgetting to pass it
	 * byte-for-byte restores the old mint and nothing anywhere goes red. That is the exact failure mode this tree has
	 * been collecting decision records about (D45: a safety mechanism that is silently not wired).
	 */
	it("mints once with the control body, then asks for the offered ids it can encode", async () => {
		const bodies: Array<{ auto_mode: { model_hints: string[] } }> = []
		/** A mint response. The pick is ALWAYS a member of the pool GitHub offered — true in every live row of §2b —
		 *  and that detail is the test: a fixture that puts the pick outside the pool retries for the wrong reason
		 *  (pick-not-in-pool, not dialect) and stays green even with a predicate that calls everything encodable.
		 *  That is how the first version of this test was wrong, caught by mutating the predicate to `() => true`.
		 */
		const mintResponse = (selected: string, pool: string[]) => ({
			session_token: "s".repeat(426),
			selected_model: selected,
			available_models: pool,
			expires_at: Math.floor(Date.now() / 1000) + 3600,
		})
		vi.stubGlobal("fetch", async (_url: string, init?: { body?: string }) => {
			bodies.push(JSON.parse(String(init?.body)))
			const second = bodies.length > 1
			const pool = ["claude-haiku-4.5", "gpt-5-mini"]
			return {
				ok: true,
				status: 200,
				text: async () => JSON.stringify(mintResponse(second ? "gpt-5-mini" : "claude-haiku-4.5", pool)),
			} as unknown as Response
		})

		const ep = await resolveGateEndpoint(
			configFor("github-copilot/auto") as never,
			registryFor(CATALOG) as never,
		)

		expect(bodies).toHaveLength(2)
		expect(bodies[0].auto_mode.model_hints).toEqual(["auto"])
		// Hints are MODEL IDS taken from the pool GitHub just named, filtered to the encodable ones — never a dialect
		// name, which the wire answers with an empty pool at HTTP 200 (§2b), and never an id invented from pi's catalog.
		expect(bodies[1].auto_mode.model_hints).toEqual(["gpt-5-mini"])
		expect(bodies[1].auto_mode.model_hints).not.toContain("claude-haiku-4.5")
		expect((ep as { model?: string }).model).toBe("gpt-5-mini")
	})

	it("does not retry when the pick is already encodable — one mint per acquisition on the happy path", async () => {
		let mints = 0
		vi.stubGlobal("fetch", async () => {
			mints++
			return {
				ok: true,
				status: 200,
				text: async () => JSON.stringify(sessionBody()),
			} as unknown as Response
		})
		const ep = await resolveGateEndpoint(
			configFor("github-copilot/auto") as never,
			registryFor(CATALOG) as never,
		)
		expect(mints).toBe(1)
		expect((ep as { model?: string }).model).toBe("mai-code-1.1-flash")
	})
})
