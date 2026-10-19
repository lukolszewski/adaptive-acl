/**
 * The plugin's own GitHub Copilot **Auto** session.
 *
 * Why this module exists at all, measured 2026-10-16/17 on a free plan: when GitHub picks the model,
 * the pick is not addressable with the plain account
 * token — `POST {baseUrl}/models/session` hands back a `selected_model` plus a `session_token`, and the
 * pick answers 200 only with that token in `Copilot-Session-Token`. The same header restricts you to the
 * Auto picks, so it must never travel with a model the user named. One POST buys a token good for ~60
 * minutes, which is why the result is cached rather than fetched per tool call.
 *
 * What this module owns: the fetch, the cache (refresh 5 minutes before `expires_at`), single-flight on
 * concurrent calls, and the token allowance counter. What it deliberately does not own: the request
 * bodies (model-client.ts) and the decision of which case we are in (gate-bridge.ts).
 *
 * One request-shaping decision IS ours, though: when GitHub hands back a pick whose dialect the caller cannot
 * encode, we ask once more for the ids GitHub itself offered that the caller can (`encodableModel` below).
 * That is measured behaviour of `model_hints`, not a guess — the numbers are quoted in
 * `requestAutoSession` below, from the live run of 2026-10-17.
 *
 * Failure contract: **never throws**. Every failure — 404, a rejected token, a body that is not JSON, an
 * aborted request — comes back as `{ok:false, error}`, and the caller resolves no endpoint, so the gate
 * falls back to asking a person (or declining when nobody is there). A classifier that cannot reach its
 * model is an unavailable classifier, not one that votes "no".
 */

/** `X-GitHub-Api-Version` the session endpoint answers to. Without it GitHub returns **404 with an empty
 *  body** for a POST that is otherwise correct — measured, and the single most confusing failure on this
 *  path, so it is named in the error text rather than left for the next reader to rediscover. */
export const COPILOT_API_VERSION = "2026-08-01"

/** The headers Copilot's own clients send. pi's model catalog attaches the same four to every Copilot
 *  model; `registry.getApiKeyAndHeaders()` returns no headers at all, so an extension that posts on its
 *  own has to supply them. */
export const COPILOT_STATIC_HEADERS: Readonly<Record<string, string>> = Object.freeze({
	"User-Agent": "GitHubCopilotChat/0.35.0",
	"Editor-Version": "vscode/1.107.0",
	"Editor-Plugin-Version": "copilot-chat/0.35.0",
	"Copilot-Integration-Id": "vscode-chat",
})

/** The header that makes an Auto pick reachable. Attaching it to an explicitly chosen model is the reverse
 *  failure — GitHub then answers `400 Requested model not available for session` — so it is named here once
 *  and referenced everywhere else. */
export const SESSION_TOKEN_HEADER = "Copilot-Session-Token"

export const COPILOT_SESSION_PATH = "/models/session"

/** Refresh this far before the token actually dies, so a call that starts near the boundary is not the one
 *  that discovers it. Measured lifetime ≈ 60 min (`expires_at` − now was exactly 3600 s), so this is ~9 % of
 *  a lifetime and roughly one POST per hour. */
export const SESSION_REFRESH_MARGIN_MS = 5 * 60_000

/** Used when the response has no usable `expires_at`. Shorter than the measured hour on purpose: an unknown
 *  expiry is a reason to re-ask sooner, not to hold a possibly-dead token for an hour. */
export const FALLBACK_SESSION_LIFETIME_MS = 50 * 60_000

/** After a failed POST, stop retrying for this long. The gate resolves an endpoint on **every** gated tool
 *  call, so without a cooldown a revoked Copilot login turns into one failing HTTP request per call — a
 *  slow denial instead of a fast one. A cached token that has not expired is still served during cooldown. */
export const SESSION_FAILURE_COOLDOWN_MS = 15_000

/** The session POST is not on the model path and spends no quota; it is still bounded, because the caller is
 *  a tool-call gate and an unreachable endpoint must not stall it. */
export const DEFAULT_SESSION_TIMEOUT_MS = 10_000

export type CopilotSession = {
	/** Value for {@link SESSION_TOKEN_HEADER}. Never logged, never returned to a caller's logs. */
	sessionToken: string
	/** GitHub's pick — the model id the request must name. The caller does not choose it. */
	selectedModel?: string
	availableModels: string[]
	/** Absolute ms timestamp; {@link SESSION_REFRESH_MARGIN_MS} before this we re-fetch. */
	expiresAtMs: number
	baseUrl: string
}

export type CopilotSessionResult =
	| { ok: true; session: CopilotSession }
	| { ok: false; error: string }

/** Injectable for tests — every test in the suite stubs this and none of them touch the network. */
export type FetchLike = (url: string, init: Record<string, unknown>) => Promise<Response>

export type AutoSessionOptions = {
	baseUrl: string
	apiKey: string
	timeoutMs?: number
	fetchImpl?: FetchLike
	/** Injectable clock (ms) so expiry and cooldown are testable without waiting. */
	now?: () => number
	signal?: AbortSignal
	/**
	 * "Can this client actually address model `id`?" — i.e. is its request dialect one we encode, read from pi's
	 * catalog at the moment of the call ({@link encodableModelNote} below). Supplied by the endpoint resolver,
	 * which is the only place holding the catalog.
	 *
	 * Omit it and the mint is the measured control body, one POST, exactly as long as this has worked. Supply it
	 * and a pick we cannot speak triggers ONE more mint asking for the offered ids we CAN speak.
	 */
	encodableModel?: (id: string) => boolean
}

type CacheEntry = {
	/** Last good session. Kept after its refresh point so a failed refresh does not lose a live token. */
	session?: CopilotSession
	/** Why the last POST failed, for the message the gate shows while the cooldown holds. */
	failure?: string
	/** Do not POST again before this instant (ms). 0 = no cooldown. */
	cooldownUntil: number
	/** The in-flight POST, shared by every concurrent caller (one session per process, not one per caller). */
	inflight?: Promise<CopilotSessionResult>
}

const _sessions = new Map<string, CacheEntry>()

/** Drop every cached session and the cooldown state. Called by tests; a real process does not need it, the
 *  cache invalidates itself from `expires_at`. */
export function resetCopilotSessions(): void {
	_sessions.clear()
}

function cacheKey(baseUrl: string, apiKey: string): string {
	// Two accounts in one process would otherwise share a token. The key must not contain the credential,
	// so: the host we are talking to plus the token's length and last four characters.
	const tail = apiKey.slice(-4)
	return `${baseUrl.replace(/\/$/, "")}|${apiKey.length}|${tail}`
}

/** The headers every Copilot request from this extension carries, session token included when there is one.
 *  Kept here so the session POST and the completion POST cannot drift apart. */
export function copilotRequestHeaders(apiKey: string, sessionToken?: string): Record<string, string> {
	return {
		...COPILOT_STATIC_HEADERS,
		"X-GitHub-Api-Version": COPILOT_API_VERSION,
		Accept: "application/json",
		"Content-Type": "application/json",
		Authorization: `Bearer ${apiKey}`,
		...(sessionToken ? { [SESSION_TOKEN_HEADER]: sessionToken } : {}),
	}
}

/**
 * `expires_at` as delivered: epoch **seconds** (measured: `1792193534`, exactly now + 3600). Accept
 * milliseconds and an ISO string too — this is a third-party field, and the cost of guessing its unit wrong
 * is a token we hold past its death (then one confusing 401) or a POST per call. Both readings are
 * distinguishable: nothing in milliseconds is below 1e12 while every second-scale timestamp for the next
 * 30 000 years is above it.
 */
export function parseExpiresAt(raw: unknown, nowMs: number): number {
	if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
		return raw < 1e12 ? Math.round(raw * 1000) : Math.round(raw)
	}
	if (typeof raw === "string") {
		const parsed = Date.parse(raw)
		if (Number.isFinite(parsed)) return parsed
		const numeric = Number(raw)
		if (Number.isFinite(numeric) && numeric > 0) return numeric < 1e12 ? Math.round(numeric * 1000) : Math.round(numeric)
	}
	return nowMs + FALLBACK_SESSION_LIFETIME_MS
}

function describeFailure(status: number, body: string): string {
	const detail = body.replace(/\s+/g, " ").trim().slice(0, 200)
	if (status === 404 && !detail) {
		// The shape a correct request produces when the version header is missing. Saying "404 not found"
		// here sends the reader to the URL; the URL is fine.
		return (
			`copilot auto session: 404 with an empty body — this endpoint answers 404 for every request ` +
			`without the header X-GitHub-Api-Version: ${COPILOT_API_VERSION}`
		)
	}
	if (status === 401 || status === 403) {
		return `copilot auto session: ${status} — the Copilot credential pi handed us was refused${detail ? `: ${detail}` : ""}`
	}
	return `copilot auto session: HTTP ${status}${detail ? `: ${detail}` : ""}`
}

/** The only `model_hints` value ever measured against GitHub (live mint, 2026-10-17).
 *  Everything else the field might accept is a measurement away from
 *  being known, which is why the mint body is built here rather than typed inline at the call site: the probe
 *  and the product must send the same bytes, and a hint we have not observed is not a hint we send. */
export const AUTO_SESSION_MODEL_HINTS: readonly string[] = Object.freeze(["auto"])

/** The mint body, one field deep. Kept as a function of the hints so a live probe can print — and
 *  live-measure — the exact bytes the gate will send, and so an extra hint can only enter through an argument
 *  someone wrote down, never through a string literal in the fetch. */
export function autoSessionMintBody(modelHints: readonly string[] = AUTO_SESSION_MODEL_HINTS): {
	auto_mode: { model_hints: string[] }
} {
	return { auto_mode: { model_hints: [...modelHints] } }
}

/** Never start a retry with less of the timeout budget than this — a mint that begins with 0 ms left aborts
 *  instantly, and an aborted retry is worse than no retry at all. */
const MIN_RETRY_TIMEOUT_MS = 1_000

type MintCall = {
	base: string
	apiKey: string
	hints: readonly string[]
	doFetch: FetchLike
	now: () => number
	timeoutMs: number
	signal?: AbortSignal
}

/** One `POST {baseUrl}/models/session`. Never throws: every failure — 404, a refused credential, a body that is
 *  not JSON, an abort — arrives as `{ok:false, error}`. */
async function mintOnce(call: MintCall): Promise<CopilotSessionResult> {
	const { base, apiKey, doFetch, now } = call
	const controller = new AbortController()
	const timeout = setTimeout(() => controller.abort(), call.timeoutMs)
	const onParentAbort = () => controller.abort()
	call.signal?.addEventListener("abort", onParentAbort, { once: true })
	const t0 = now()
	try {
		const res = await doFetch(`${base}${COPILOT_SESSION_PATH}`, {
			method: "POST",
			headers: copilotRequestHeaders(apiKey),
			body: JSON.stringify(autoSessionMintBody(call.hints)),
			signal: controller.signal,
		})
		const text = await res.text().catch(() => "")
		if (!res.ok) return { ok: false, error: describeFailure(res.status, text) }
		let json: Record<string, unknown>
		try {
			json = JSON.parse(text) as Record<string, unknown>
		} catch {
			return { ok: false, error: "copilot auto session: a 200 whose body is not JSON" }
		}
		const token = json?.session_token
		if (typeof token !== "string" || !token) {
			return { ok: false, error: "copilot auto session: no session_token in the response" }
		}
		const selected = typeof json.selected_model === "string" ? json.selected_model : undefined
		const available = Array.isArray(json.available_models)
			? json.available_models.filter((m): m is string => typeof m === "string")
			: []
		return {
			ok: true,
			session: {
				sessionToken: token,
				selectedModel: selected,
				availableModels: available,
				expiresAtMs: parseExpiresAt(json.expires_at, now()),
				baseUrl: base,
			},
		}
	} catch (err) {
		const ms = now() - t0
		const aborted = controller.signal.aborted
		return {
			ok: false,
			error: aborted
				? `copilot auto session: timeout/abort after ${ms}ms`
				: `copilot auto session: ${String(err)}`,
		}
	} finally {
		clearTimeout(timeout)
		call.signal?.removeEventListener("abort", onParentAbort)
	}
}

/**
 * Mint an Auto session, and — when the caller said which models it can speak — ask a second time for one it
 * can address.
 *
 * The second ask is the whole point, and it rests on two facts measured live on 2026-10-17:
 * `model_hints` is a **model-id filter over the pool GitHub just offered** — `{hints:["gpt-5-mini"]}` turned a
 * pool of two into `[gpt-5-mini]` and picked it — while a hint GitHub cannot match (a dialect name, an id from
 * outside the Auto pool, a made-up word) yields a **200 whose pool is empty and whose `selected_model` is `""`**.
 * Dialect names are therefore not hints, and the narrowing can only be built from ids GitHub itself named:
 * the `available_models` of the mint we just did, filtered by what the caller can encode. Nothing here holds a
 * model name, which is the point — the catalog churns within hours (measurements row 3).
 *
 * What this can never do is damage the path that already works: the retry runs only when the pick is one the
 * caller cannot address, it happens at most once, and a retry that did not produce an encodable pick is thrown
 * away in favour of the first answer — so the message built for an unspeakable pick is still the message the
 * reader gets, never "the session named no model".
 */
async function requestAutoSession(opts: AutoSessionOptions): Promise<CopilotSessionResult> {
	const now = opts.now ?? Date.now
	const doFetch: FetchLike = opts.fetchImpl ?? ((globalThis.fetch as unknown) as FetchLike)
	const base = (opts.baseUrl ?? "").replace(/\/$/, "")
	if (!base) return { ok: false, error: "copilot auto session: no base url (the registry returned no baseUrl)" }
	if (!opts.apiKey) return { ok: false, error: "copilot auto session: no credential (is the user signed in to Copilot?)" }

	const budgetMs = opts.timeoutMs ?? DEFAULT_SESSION_TIMEOUT_MS
	const started = now()
	const mint = (hints: readonly string[], spentMs: number) =>
		mintOnce({
			base,
			apiKey: opts.apiKey,
			hints,
			doFetch,
			now,
			signal: opts.signal,
			// The retry inherits whatever the first mint left of the caller's timeout, so one acquisition stays
			// inside the bound it was given rather than quietly doubling it.
			timeoutMs: Math.max(MIN_RETRY_TIMEOUT_MS, budgetMs - spentMs),
		})

	const first = await mint(AUTO_SESSION_MODEL_HINTS, 0)
	const encodable = opts.encodableModel
	if (!encodable || !first.ok) return first

	const offered = first.session.availableModels
	// The narrowing list is GitHub's own answer, filtered. An id this file invented would be a name in source
	// and, worse, one GitHub may not be offering today.
	const usable = offered.filter((id) => encodable(id))
	if (usable.includes(first.session.selectedModel ?? "")) return first
	// Nothing encodable was offered. `model_hints: []` has never been sent, so it is not sent now: the empty
	// pool we DO have measured would only replace a named, loud failure with a vaguer one.
	if (usable.length === 0) return first

	// Two mints is the ceiling for one acquisition, and the ceiling is structural: there is exactly one retry
	// below, no loop. A loop here would be a request storm on a tool-call path.
	const retry = await mint(usable, now() - started)
	const pick = retry.ok ? retry.session.selectedModel ?? "" : ""
	if (!retry.ok || !pick || !encodable(pick)) return first
	return retry
}

/**
 * Get a live Auto session, from cache when the cache is live.
 *
 * Three behaviours worth naming, because each one exists for a measured reason:
 *  - **cache + margin**: inside the refresh window this costs nothing, so one POST per ~55 minutes however
 *    many tool calls the session makes;
 *  - **single-flight**: the gate can ask twice in one turn (ledger extraction and the effect call), and two
 *    concurrent POSTs would mint two tokens and keep the older one;
 *  - **a failed refresh keeps a live token**: GitHub's expiry is not a guarantee, so we hold the token until
 *    it actually dies rather than losing a working classifier because one POST timed out.
 */
export async function acquireAutoSession(opts: AutoSessionOptions): Promise<CopilotSessionResult> {
	const now = opts.now ?? Date.now
	const entry: CacheEntry = _sessions.get(cacheKey(opts.baseUrl, opts.apiKey)) ?? { cooldownUntil: 0 }
	_sessions.set(cacheKey(opts.baseUrl, opts.apiKey), entry)
	const live = entry.session && now() < entry.session.expiresAtMs

	if (entry.session && now() < entry.session.expiresAtMs - SESSION_REFRESH_MARGIN_MS) {
		return { ok: true, session: entry.session }
	}
	if (entry.inflight) return await entry.inflight
	if (entry.cooldownUntil > now()) {
		if (live) return { ok: true, session: entry.session! }
		return { ok: false, error: entry.failure ?? "copilot auto session: recent failure, retrying shortly" }
	}

	const call = (async (): Promise<CopilotSessionResult> => {
		const result = await requestAutoSession(opts)
		if (result.ok) {
			entry.session = result.session
			entry.failure = undefined
			entry.cooldownUntil = 0
			return result
		}
		entry.failure = result.error
		entry.cooldownUntil = now() + SESSION_FAILURE_COOLDOWN_MS
		// A token we already hold is still a token: losing the classifier to one failed refresh would turn a
		// 400 ms network blip into a session of prompts.
		if (entry.session && now() < entry.session.expiresAtMs) {
			return { ok: true, session: entry.session }
		}
		return result
	})().finally(() => {
		if (entry.inflight === call) entry.inflight = undefined
	})
	entry.inflight = call
	return await call
}

// ---------------------------------------------------------------- the allowance

/**
 * Tokens this process has spent on Copilot, and the cap the user set. A free plan's allowance is shared with
 * the user's own chat, so the gate has to be able to stop spending and say so. The cap is expressed in
 * tokens we can see (`usage.total_tokens`), not in GitHub's premium-request units, which are only visible on
 * a paid plan's accounting — that gap is documented rather than papered over.
 */
export type CopilotUsage = {
	inputTokens: number
	outputTokens: number
	reasoningTokens: number
	totalTokens: number
}

let _tokensSpent = 0

function num(value: unknown): number {
	return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

/** Read `usage` off either dialect's response. Missing or malformed usage is `undefined`, not zero — the
 *  caller should know we could not see it rather than record a free call. Both spellings are read: the
 *  responses dialect counts `input_tokens`/`output_tokens`, the chat dialect `prompt_tokens`/
 *  `completion_tokens`, and a transport that speaks both dialects must not silently record 0 for one of them
 *  (a budget that never grows is worse than no budget). */
export function readCopilotUsage(json: unknown): CopilotUsage | undefined {
	const usage = (json as { usage?: Record<string, unknown> } | null)?.usage
	if (!usage || typeof usage !== "object") return undefined
	const details = usage.output_tokens_details as Record<string, unknown> | undefined
	const input = num(usage.input_tokens) || num(usage.prompt_tokens)
	const output = num(usage.output_tokens) || num(usage.completion_tokens)
	const total = num(usage.total_tokens) || input + output
	if (!total && !input && !output) return undefined
	return {
		inputTokens: input,
		outputTokens: output,
		reasoningTokens: num(details?.reasoning_tokens),
		totalTokens: total,
	}
}

/** Add one call's tokens to the running total. Returns the new total, so a caller can log without a second read. */
export function recordCopilotUsage(usage: CopilotUsage | undefined): number {
	if (usage) _tokensSpent += usage.totalTokens
	return _tokensSpent
}

export function copilotTokensSpent(): number {
	return _tokensSpent
}

export function resetCopilotUsage(): void {
	_tokensSpent = 0
}

/** `budgetTokens <= 0` means no cap — the default, and the behaviour every existing config has. */
export function copilotBudgetSpent(budgetTokens: number | undefined): boolean {
	if (!(budgetTokens && budgetTokens > 0)) return false
	return _tokensSpent >= budgetTokens
}

/** Wording shared by every budget refusal, so the denial always names the cause: a spent allowance is a
 *  transport failure, never a verdict, and a reader must be able to tell the two apart. */
export function copilotBudgetText(budgetTokens: number, spent: number): string {
	return `copilot token budget spent (${spent}/${budgetTokens} tokens) — the classifier is not asking again this session`
}
