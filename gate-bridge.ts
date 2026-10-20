/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Bridge between pi (index.ts) and the v3 gate pipeline (gate.ts).
 * Mostly pure helpers: endpoint resolution, user-message extraction, prompt labels. The one piece of state is
 * {@link classifierUnavailability} — the cause recorded by the most recent endpoint resolution — because the
 * module that renders a denial is not the module that resolved the endpoint, and index.ts is not the place to
 * thread it through. Read {@link resolveGateEndpointWithFailure} before adding to it.
 */

import { redactForClassifier } from "./classifier-redact.ts"
import { parseModelRef, type ClassifierRegistry } from "./classifier-client.ts"
import {
	COPILOT_PROVIDER,
	copilotModelKind,
	resolveCopilotConfig,
	type ClassifierConfig,
} from "./config.ts"
import {
	extractMessageGrants,
	type ModelApi,
	type ModelEndpoint,
} from "./model-client.ts"
import { acquireAutoSession, DEFAULT_SESSION_TIMEOUT_MS } from "./copilot-session.ts"
import type { GateResult } from "./gate.ts"
import {
	applyEvents,
	eventsFromExtraction,
	isSyntheticUserTurn,
	ledgerCovers,
	readOnlyActive,
	readOnlyLiftedByGrant,
	type Ledger,
	type LedgerEntry,
} from "./auth-ledger.ts"
import { DENIAL_LIMITS } from "./denial-tracking.ts"
import { policyProject, type Entity, type PolicyOptions } from "./risk-policy.ts"

/** User messages reach a model call through `limitUserMessages`, which sizes them in tokens against
 *  the endpoint's window, so a character clamp here cannot protect anything — it can only delete whole
 *  messages before the budget sees them. `MESSAGE_REF_MAX_CHARS` is the same safety cap against a
 *  pasted dump, and nothing more. */
export function collectUserMessagesFromBranch(
	branch: Array<{ type?: string; message?: { role?: string; content?: unknown } }>,
): string[] {
	const out: string[] = []
	for (const entry of branch) {
		if (entry?.type !== "message") continue
		const msg = entry.message
		if (msg?.role !== "user") continue
		const content = msg.content
		if (typeof content === "string") {
			if (content.trim()) out.push(redactForClassifier(content.trim(), MESSAGE_REF_MAX_CHARS))
			continue
		}
		if (!Array.isArray(content)) continue
		for (const block of content) {
			if ((block as { type?: string })?.type === "text") {
				const t = String((block as { text?: string }).text ?? "").trim()
				// Skip tool-result-shaped payloads that some flows store as user text.
				if (t && !t.startsWith("<tool_result")) out.push(redactForClassifier(t, MESSAGE_REF_MAX_CHARS))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- ledger sync

export type UserMessageRef = {
	/** Branch entry id, or a synthetic stable "#<index>" when pi gives none. */
	id: string
	/** Branch ordinal — the ledger's `seq` (revocation precedence). */
	seq: number
	text: string
}

/** Safety cap against a pasted dump, applied to both collectors. Sizing what reaches a model call is
 *  the budget's job (`context-budget.ts` + ledger rows); this number only has to stay above anything a
 *  person can paste, because the old 4 000 clamp cut long messages in half before extraction — or the
 *  token budget — ever saw them. The clamp itself (head + tail, `[truncated]` marker) still applies. */
export const MESSAGE_REF_MAX_CHARS = 32_000

/** User messages WITH identity and branch position, for ledger extraction.
 *  Same filtering as collectUserMessagesFromBranch (redaction, tool-result skip). */
export function collectUserMessageRefs(
	branch: Array<{ type?: string; id?: string; message?: { role?: string; content?: unknown } }>,
): UserMessageRef[] {
	const out: UserMessageRef[] = []
	for (let i = 0; i < branch.length; i++) {
		const entry = branch[i]!
		if (entry?.type !== "message" || entry.message?.role !== "user") continue
		const content = entry.message.content
		const parts: string[] = []
		if (typeof content === "string") {
			if (content.trim()) parts.push(content.trim())
		} else if (Array.isArray(content)) {
			for (const block of content) {
				if ((block as { type?: string })?.type === "text") {
					const t = String((block as { text?: string }).text ?? "").trim()
					if (t && !t.startsWith("<tool_result")) parts.push(t)
				}
			}
		}
		if (!parts.length) continue
		out.push({
			id: typeof entry.id === "string" && entry.id ? entry.id : `#${i}`,
			seq: i,
			// A safety cap against a pasted dump, nothing more: the old 4 000 clamp cut a long message in
			// half before extraction ever saw it, so a grant in its second half was never recorded. Sizing
			// what reaches a model call is the budget's job now (context-budget.ts + ledger rows); this
			// number only has to stay above anything a person can paste. The clamp itself (head + tail,
			// `[truncated]` marker) still applies past it.
			text: redactForClassifier(parts.join("\n"), MESSAGE_REF_MAX_CHARS),
		})
	}
	return out
}

export type SyncLedgerResult = {
	/** Extraction calls made this invocation. */
	processed: number
	/** Unseen messages still waiting (drain via background backfill). */
	pending: number
	/** Whether the ledger changed (caller persists a snapshot). */
	changed: boolean
}

/**
 * Fold unseen user messages into the ledger, newest-first
 * (proper-permission-ledger.md §2.2/§2.6). `maxCalls` bounds this invocation
 * (≤2 inline before a tool call; larger for a background drain step). Messages
 * beyond `backfillLimit` (counted from the newest) are marked seen without
 * extraction — they fall back to the targeted call / prompt path. A failed
 * extraction leaves the message unseen so the next invocation retries;
 * worst case is a prompt, never a false allow.
 */
export async function syncLedger(opts: {
	refs: UserMessageRef[]
	ledger: Ledger
	endpoint: ModelEndpoint
	maxCalls: number
	backfillLimit?: number
	signal?: AbortSignal
	debug?: (line: string) => void
}): Promise<SyncLedgerResult> {
	const { refs, ledger, endpoint } = opts
	const dbg = opts.debug ?? (() => {})
	const limit = opts.backfillLimit ?? 400
	let changed = false

	const unseen = refs.filter((r) => !ledger.seen.has(r.id))
	// beyond-cap messages (older than the newest `limit`): skip permanently
	if (unseen.length > limit) {
		const skipped = unseen.slice(0, unseen.length - limit)
		for (const r of skipped) ledger.seen.add(r.id)
		changed = true
		dbg(`[gate] ledger: skipped ${skipped.length} messages beyond backfill limit ${limit}`)
	}
	const queue = unseen.slice(-limit).reverse() // newest first
	let processed = 0
	for (const r of queue) {
		if (processed >= opts.maxCalls) break
		if (opts.signal?.aborted) break
		if (isSyntheticUserTurn(r.text)) {
			// tool-written notice, not the user speaking: nothing to extract, no call spent
			ledger.seen.add(r.id)
			changed = true
			continue
		}
		const res = await extractMessageGrants(endpoint, r.text, opts.signal)
		processed++
		if (!res.ok) {
			dbg(`[gate] ledger: extraction failed for ${r.id}: ${res.error}`)
			continue // stays unseen → retried next invocation
		}
		const events = eventsFromExtraction(res.value, r.id, r.seq, r.text)
		applyEvents(ledger, events)
		ledger.seen.add(r.id)
		changed = true
		if (events.length) {
			dbg(`[gate] ledger: ${r.id} → ${events.map((e) => `${e.type}:${e.category}:${e.value}`).join(", ")}`)
		}
	}
	const pending = refs.filter((r) => !ledger.seen.has(r.id)).length
	return { processed, pending, changed }
}

/**
 * Resolve the HTTP endpoint for the gate's model calls.
 * Priority: explicit classifier.baseUrl override → pi model registry entry.
 *
 * This stays the single decision point: it is the only place that turns `classifier.model` into a wire
 * behaviour — dialect, and whether a Copilot Auto session is needed. Everything downstream (gate.ts, the ledger,
 * index.ts) takes a {@link ModelEndpoint} and knows nothing about providers.
 */
export async function resolveGateEndpoint(
	config: ClassifierConfig & { baseUrl?: string; modelId?: string },
	registry: ClassifierRegistry | undefined,
): Promise<ModelEndpoint | undefined> {
	return (await resolveGateEndpointWithFailure(config, registry)).endpoint
}

/**
 * The same decision, with the reason attached when the answer is "no endpoint".
 *
 * Every call records its outcome — a resolved endpoint or a configured-but-unusable classifier clears any earlier
 * failure — which is what lets the denial text tell "you configured nothing" apart from "the classifier could not
 * be used, and here is why". Callers that render a denial should pass {@link EndpointResolution.failure} to
 * {@link GateDenialAttribution}; the recorded copy is the fallback for call sites that cannot.
 */
export async function resolveGateEndpointWithFailure(
	config: ClassifierConfig & { baseUrl?: string; modelId?: string },
	registry: ClassifierRegistry | undefined,
): Promise<EndpointResolution> {
	const outcome = await classifyEndpointResolution(config, registry)
	lastUnavailability = outcome.failure
	return outcome
}

async function classifyEndpointResolution(
	config: ClassifierConfig & { baseUrl?: string; modelId?: string },
	registry: ClassifierRegistry | undefined,
): Promise<EndpointResolution> {
	if (!config.enabled) return {}
	if (config.baseUrl) {
		// Case A: an explicit endpoint means "plain OpenAI-compatible, bypass the registry" — including for a
		// `github-copilot/...` model string and for the whole `copilot` block. Byte-identical to 2.7.
		return {
			endpoint: {
				baseUrl: config.baseUrl,
				model: config.modelId ?? config.model.split("/").pop() ?? config.model,
				timeoutMs: config.timeoutMs,
				contextTokens: config.contextTokens,
			},
		}
	}
	if (!registry) return {}
	const parsed = parseModelRef(config.model)
	if (!parsed) return {}
	if (parsed.provider === COPILOT_PROVIDER) {
		return resolveCopilotEndpoint(config, registry, parsed.modelId, copilotModelKind(config.model) ?? "explicit")
	}
	const model = registry.find(parsed.provider, parsed.modelId) as
		| { baseUrl?: string; id?: string }
		| undefined
	if (!model?.baseUrl) return {}
	try {
		const auth = await registry.getApiKeyAndHeaders(model as never)
		if (!auth.ok) return {}
		return {
			endpoint: {
				// The credential may name its own host (pi's OAuth `toAuth`); the catalog URL is only the default.
				baseUrl: auth.baseUrl ?? model.baseUrl,
				model: model.id ?? parsed.modelId,
				apiKey: auth.apiKey,
				headers: auth.headers,
				timeoutMs: config.timeoutMs,
				contextTokens: config.contextTokens,
			},
		}
	} catch {
		return {}
	}
}

// -------------------------------------------------------------- the Copilot endpoint

/** Catalog ids that exist in every Copilot catalog we have read (33 models, one per dialect group). On the Auto
 *  path GitHub's pick is unknown until the session answers, and the pick's dialect is what the request must be
 *  shaped for — so one of these is a CARRIER whose only job is to fetch the credential and the host: pi's
 *  `getApiKeyAndHeaders` reads nothing but `model.provider`, the Copilot token is per account, not per model.
 *  The carrier is never the model the classifier is asked about. */
const COPILOT_AUTH_CARRIERS: readonly string[] = ["gpt-4.1", "gpt-5-mini", "claude-haiku-4.5"]

/** Catalog `api` → the dialect this client speaks. A catalog api missing here does not resolve, and the gate
 *  asks a person — the owner's ruling for an unreachable classifier, not a silent loosening. */
const COPILOT_DIALECTS: Record<string, ModelApi> = {
	"openai-completions": "chat-completions",
	"openai-responses": "responses",
	"anthropic-messages": "anthropic-messages",
}

type CatalogModel = { id?: string; api?: string; baseUrl?: string; reasoning?: boolean }

function findCopilotModel(registry: ClassifierRegistry, id: string | undefined): CatalogModel | undefined {
	if (!id) return undefined
	const model = registry.find(COPILOT_PROVIDER, id) as CatalogModel | undefined
	return model?.baseUrl ? model : undefined
}

function copilotCarrier(registry: ClassifierRegistry, namedId: string | undefined): CatalogModel | undefined {
	if (namedId) return findCopilotModel(registry, namedId)
	for (const carrier of COPILOT_AUTH_CARRIERS) {
		const found = findCopilotModel(registry, carrier)
		if (found) return found
	}
	return undefined
}

/**
 * Why a classifier the user DID configure could not be used on the most recent resolution.
 *
 * Until now "no endpoint" was one answer covering two opposite situations. `undefined` from the resolver meant
 * "the user never configured a classifier" to everyone downstream — but a failed Auto-session mint and a pick in
 * a dialect this client cannot encode also produced it, and those mean "the classifier is there and could not be
 * used". The reader pulls a different lever for each (edit the config vs check the Copilot login / wait for the
 * service), so a Copilot failure must reach the text as an *unavailable classifier naming its cause*, never as a
 * missing configuration and never as a refusal.
 *
 * The record is module state read at render time, the same shape as `classifierStats` in gate.ts: index.ts — the
 * only caller — resolves the endpoint immediately before it runs the gate, so the record describes the call being
 * rendered, and any successful or genuinely-unconfigured resolution clears it. That is also its limit: it is "the
 * most recent resolution in this process", not a value tied to an id. A caller that can hand the fact over
 * explicitly should (see {@link GateDenialEvidence.endpointFailure} and {@link resolveGateEndpointWithFailure}).
 */
export type ClassifierUnavailability = {
	/** Stable id, one per branch that returns no endpoint despite a configured classifier. */
	cause: "auto-session-failed" | "auto-pick-unnamed" | "auto-pick-unspeakable" | "model-unspeakable"
	/** The clause a human reads: what failed, and on which model. */
	detail: string
	/** The configured `classifier.model`, so a log line names what the user actually set. */
	model?: string
}

/** What a resolution produced: an endpoint, or the reason there is none despite a configured classifier. */
export type EndpointResolution = { endpoint?: ModelEndpoint; failure?: ClassifierUnavailability }

let lastUnavailability: ClassifierUnavailability | undefined

/** What stopped the most recent endpoint resolution, when a classifier was configured and could not be used. */
export function classifierUnavailability(): ClassifierUnavailability | undefined {
	return lastUnavailability
}

/** Forget the last resolution. A test seam; in a real process every resolution overwrites the record. */
export function resetClassifierUnavailability(): void {
	lastUnavailability = undefined
}

/**
 * Turn a `github-copilot/...` classifier model into an endpoint, or into the reason there is none.
 *
 * "No endpoint" means "no classifier on this call", which the gate already handles: it prompts in a terminal and
 * declines unattended with the reason naming that the classifier was not there. Every branch returning it is that
 * decision, never a swallowed error — Copilot's own failures must never be read as a verdict. A branch that fails
 * for a reason the user did not choose (the mint, GitHub's pick) also returns the cause; a branch that returns
 * nothing but `undefined` is a configuration state (no catalog entry, no credential, the session switched off),
 * where "no endpoint configured" is the honest sentence.
 */
async function resolveCopilotEndpoint(
	config: ClassifierConfig & { baseUrl?: string; modelId?: string },
	registry: ClassifierRegistry,
	modelId: string,
	kind: "auto" | "explicit",
): Promise<EndpointResolution> {
	const copilot = config.copilot ?? resolveCopilotConfig(undefined)
	const carrier = copilotCarrier(registry, kind === "explicit" ? modelId : undefined)
	if (!carrier?.baseUrl) return {}
	let auth
	try {
		auth = await registry.getApiKeyAndHeaders(carrier as never)
	} catch {
		return {}
	}
	if (!auth.ok || !auth.apiKey) return {}
	// Unlike a self-hosted LiteLLM endpoint, Copilot has no no-auth mode: the token IS the credential.
	// The catalog says api.individual.githubcopilot.com for every account, but a Business/Enterprise token routes
	// elsewhere (its `proxy-ep`, e.g. proxy.business.githubcopilot.com → api.business.githubcopilot.com). pi
	// derives that per credential and returns it here; the individual host answers 401 to a business token.
	const baseUrl = auth.baseUrl ?? carrier.baseUrl
	const shared = {
		baseUrl,
		apiKey: auth.apiKey,
		headers: auth.headers,
		timeoutMs: config.timeoutMs,
		contextTokens: config.contextTokens,
	}
	const configuredModel = config.model

	if (kind === "auto") {
		// With the session switched off there is no way to address GitHub's pick, and guessing a model the user
		// did not choose is not a fallback — it is a different classifier. No endpoint instead.
		if (!copilot.sessionEnabled) return {}
		const minted = await acquireAutoSession({
			baseUrl,
			apiKey: auth.apiKey,
			// The mint is not the model call and sits on a tool-call path: cap it, whatever the model timeout is.
			timeoutMs: Math.min(config.timeoutMs ?? DEFAULT_SESSION_TIMEOUT_MS, DEFAULT_SESSION_TIMEOUT_MS),
			// `model_hints` filters GitHub's offered pool by MODEL ID (measured 2026-10-17) — a dialect name is
			// answered with an empty pool and `selected_model: ""` at HTTP 200, so naming dialects here would look like
			// a safeguard and do nothing. A pick this client cannot encode therefore buys exactly one more mint, asking
			// for the offered ids it CAN put on the wire. The dialect comes from pi's catalog on every call because the
			// catalog churns within hours; a model pi has not listed yet counts as encodable, which is the same
			// guess the resolver makes a few lines below.
			encodableModel: (id) => {
				const offered = findCopilotModel(registry, id)
				return !offered?.api || COPILOT_DIALECTS[offered.api] !== undefined
			},
		})
		if (!minted.ok) {
			return {
				failure: {
					cause: "auto-session-failed",
					detail: `the Copilot Auto session could not be minted: ${minted.error}`,
					model: configuredModel,
				},
			}
		}
		const picked = minted.session.selectedModel
		if (!picked) {
			return {
				failure: {
					cause: "auto-pick-unnamed",
					detail: "the Copilot Auto session answered without naming a model, so there is nothing to ask",
					model: configuredModel,
				},
			}
		}
		const pickedModel = findCopilotModel(registry, picked)
		const dialect = pickedModel?.api ? COPILOT_DIALECTS[pickedModel.api] : undefined
		// A catalog entry that speaks a dialect we cannot speak is a known mismatch: no endpoint. It is not a
		// missing configuration — GitHub chose a model this client cannot address, and that is what the reader
		// has to be told.
		if (pickedModel?.api && !dialect) {
			return {
				failure: {
					cause: "auto-pick-unspeakable",
					detail: `GitHub's Auto pick "${picked}" speaks ${pickedModel.api}, a request dialect this classifier cannot encode`,
					model: configuredModel,
				},
			}
		}
		// No catalog entry at all (GitHub added a model pi has not listed yet) is an unknown, and the two
		// candidates GitHub has ever returned on this account are both openai-responses. A wrong guess costs one
		// 400 → transport failure → a prompt; it cannot produce a wrong verdict.
		return {
			endpoint: {
				...shared,
				model: picked,
				api: dialect ?? "responses",
				copilot: {
					auto: true,
					sessionToken: minted.session.sessionToken,
					supportsReasoning: pickedModel?.reasoning === true,
					maxOutputTokens: copilot.maxOutputTokens,
					reasoningEffort: copilot.reasoningEffort,
					budgetTokens: copilot.budgetTokens,
				},
			},
		}
	}

	// Case C: the user named the model, so it must NEVER carry a session token (measured: with one, GitHub
	// restricts the request to the Auto picks and `gpt-4.1` answers 400). `auto: false` is what makes the encoder
	// strip the header, and the encoder strips it even if one were handed to it.
	const dialect = COPILOT_DIALECTS[carrier.api ?? ""]
	if (!dialect) {
		return {
			failure: {
				cause: "model-unspeakable",
				detail: `the configured Copilot model "${carrier.id ?? modelId}" speaks ${carrier.api || "a transport"} this classifier cannot encode`,
				model: configuredModel,
			},
		}
	}
	return {
		endpoint: {
			...shared,
			model: carrier.id ?? modelId,
			api: dialect,
			copilot: {
				auto: false,
				supportsReasoning: carrier.reasoning === true,
				maxOutputTokens: copilot.maxOutputTokens,
				reasoningEffort: copilot.reasoningEffort,
				budgetTokens: copilot.budgetTokens,
			},
		},
	}
}

/** One-line label for the approval prompt. */
export function gatePromptLabel(r: GateResult): string {
	const ents = r.entities
		.filter((e) => e.kind === "target")
		.map((e) => e.value)
		.slice(0, 4)
	const entStr = ents.length ? ` [${ents.join(", ")}]` : ""
	if (r.tier === "never") {
		return `⛔ HIGH RISK — ${r.description}${entStr}. This action is never auto-approved.`
	}
	return `${r.description}${entStr} — ${r.reason}`
}

/**
 * Whether a retry could EVER succeed. Without this an agent cannot tell
 * "blocked by policy" from "blocked until you change the command" from "only a
 * human can clear this", and burns turns re-issuing the same call — measured in
 * this very session, where two denials said only "not authorised by the user".
 */
export type DenialFutility = "never" | "only-after-rewrite" | "only-with-user-approval"

const RETRY_TEXT: Record<DenialFutility, string> = {
	never: "never by rewriting — only a human can clear this. Do not retry it and do not try a variant: ask the user, or park it and report at the end.",
	"only-after-rewrite": "only after you change the command. Repeating it unchanged will be denied again.",
	"only-with-user-approval": "only with the user's explicit approval. Ask them, naming the exact target.",
}

export function futilityFor(opts: {
	tier: "allow" | "ask" | "never"
	unparseable?: boolean
	unattended?: boolean
	/** A person is watching, so `unattended` is a flag, not the absence of a human. */
	humanPresent?: boolean
}): DenialFutility {
	if (opts.tier === "never") return "never"
	// A command that does not parse stays a rewrite whoever is watching: approving a broken command
	// does not make it parse.
	if (opts.unparseable) return "only-after-rewrite"
	// With no UI, asking is not a path — rewriting is. With a person present it is the FLAG that
	// swallowed the dialog, so a rewrite is the wrong advice (see `HUMAN_PRESENT_SOFT_DENY`).
	if (opts.unattended) return opts.humanPresent ? "only-with-user-approval" : "only-after-rewrite"
	return "only-with-user-approval"
}

// ---------------------------------------------------------------- attribution

/**
 * Who refused. Named on the caller's side, never guessed by the message builder: a guess here sends the
 * reader to the wrong lever (a rule file for a layer-0 verdict, a rewrite for a person's "no"). Where a
 * call site knows the facts but not the layer, {@link gateDenialAttribution} turns those facts into one
 * of these names and leaves the field out when the facts do not settle it.
 */
export type DenialDecider =
	| "layer0"
	| "rule"
	| "grant"
	| "ledger"
	| "classifier"
	| "budget"
	| "escalation"
	| "user"

/**
 * What the caller knows about a refusal it is about to render. Every field is optional and every
 * default reproduces the pre-attribution text, so a call site that has not been wired yet still
 * compiles and still gets a truthful message — with `undetermined` where the decider is unknown,
 * which is the whole point: a confidently wrong attribution is worse than no attribution.
 */
export type DenialContext = {
	/** Who decided. The caller knows; the message builder must not guess. */
	decidedBy?: DenialDecider
	/** Which half of the rules channel spoke, when `decidedBy === "rule"`. */
	ruleKind?: "deny" | "ask"
	/** The rule as the user wrote it, when `decidedBy === "rule"`. */
	ruleText?: string
	/** The user's own words that forbid this, when `decidedBy === "ledger"`. */
	ledgerQuote?: string
	/** The category on the forbid row that refused, when that row could be identified. Together with
	 *  `ledgerValue` this is what makes the row findable in `/grants` — a quote alone cannot be revoked. */
	ledgerCategory?: string
	/** The value on that row (`*` for a blanket "stop doing this kind of thing"), i.e. the string a
	 *  revocation has to name. Never truncated: a cut-down value names nothing. */
	ledgerValue?: string
	/** Why the model layer has no usable verdict, when `decidedBy === "classifier"`. */
	classifierWhy?: "denied" | "unavailable" | "no-endpoint" | "window-too-small"
	/** The specific thing that went wrong, when the caller or the transport named one — the transport's own error
	 *  text, or the reason the endpoint could not be resolved. Printed inside the decider clause because
	 *  "classifier unavailable" alone still leaves the reader choosing between a Copilot login, a model GitHub
	 *  will not serve, and a spent token allowance. Never trusted as data: clamped and rendered inside a code span. */
	classifierCause?: string
	/** Whether the store held a revocation or nothing at all, when `decidedBy === "grant"`. */
	grantState?: "revoked" | "absent"
	/** A human is looking at this session, so a prompt WOULD have been shown. */
	humanPresent?: boolean
	/** For callers that hand-build a denial and have no GateResult to read these off. */
	category?: string
	targets?: string[]
}

const NOT_REPORTED = "not reported"
const UNDETERMINED = "undetermined (the caller did not say who refused)"

/** The decider clause alone, for call sites that assemble their own sentence. */
export function describeDecider(ctx?: DenialContext): string {
	return `decided by: ${deciderPhrase(ctx)}`
}

function deciderPhrase(ctx?: DenialContext): string {
	switch (ctx?.decidedBy) {
		case "layer0":
			return "layer0-policy — the deterministic parse + effect model refused"
		case "rule":
			return rulePhrase(ctx)
		case "grant":
			return grantPhrase(ctx)
		case "ledger":
			return ledgerPhrase(ctx)
		case "classifier":
			return classifierPhrase(ctx)
		case "budget":
			return `budget — classifier denials spent (${DENIAL_LIMITS.maxConsecutive} in a row or ${DENIAL_LIMITS.maxTotal} in the run), so the gate stopped asking the model and refuses instead`
		case "escalation":
			return "unattended-escalation — the denial ladder refused, not a policy decision"
		case "user":
			return "user — a person answered the prompt and blocked this; their answer is the verdict, not a rule and not a tier"
		default:
			return UNDETERMINED
	}
}

function rulePhrase(ctx: DenialContext): string {
	const kind = ctx.ruleKind ? `rule:${ctx.ruleKind}` : `rule (deny-or-ask: ${NOT_REPORTED})`
	const text = ctx.ruleText ? ` \`${ctx.ruleText}\`` : ` (rule text ${NOT_REPORTED})`
	return `${kind}${text} — a permission rule the user wrote`
}

function grantPhrase(ctx: DenialContext): string {
	if (ctx.grantState === "revoked") return "grant-store — a revocation outranks the grant (/grants lists what is stored)"
	if (ctx.grantState === "absent") return "grant-store — no stored grant covers this category + target; answering a prompt stores one"
	return `grant-store — revoked or never granted: ${NOT_REPORTED}`
}

function ledgerPhrase(ctx: DenialContext): string {
	// Every ledger refusal is the same two-part sentence: WHOSE words, then WHICH of them, then the row
	// they were filed under. The frame is a constant and comes first — it is never assembled out of the
	// quote, so no quote can move it or read as anything but data the user once said. A denial that reads
	// like an instruction is exactly what that shape guards against.
	const frame = "ledger — the user's own earlier words forbid this: "
	const quote = displayQuote(ctx.ledgerQuote)
	const said = quote ? `"${quote}"` : `(forbidding quote ${NOT_REPORTED})`
	return `${frame}${said}${rowClause(ctx)}`
}

/**
 * The row, in the ledger's own vocabulary: the category it was filed under and the value it names.
 * Shown because the quote is not revocable — `/grants` lists rows by category + value, so those two are
 * what a person needs in front of them to clear the thing that is blocking the call. Printed only when
 * the row was identified; when it was not, the absence is silent here and visible in the quote clause.
 */
function rowClause(ctx: DenialContext): string {
	const parts = [ctx.ledgerCategory, ctx.ledgerValue ? `value=${ctx.ledgerValue}` : undefined].filter(
		(p): p is string => Boolean(p),
	)
	return parts.length ? ` (row: ${parts.join(" ")})` : ""
}

/**
 * The user's sentence, presented as data.
 *
 * Three edits, all of them about keeping the quote inside its quotation marks: whitespace is flattened,
 * because a multi-line sentence would otherwise print extra lines INSIDE the denial and read as more of
 * the gate's own instructions (the quote is the least trustworthy text in this message — it is copied
 * out of a transcript, and it is shown to the user, so it must not be able to forge
 * a line); a `"` inside it becomes `'` so the delimiters still bound it; and it is cut to
 * `QUOTE_MAX_CHARS` with a visible marker. Only a quote is ever cut — a truncated command line is worse
 * than no command line, which is why the lever line is never shortened here or anywhere else.
 */
function displayQuote(raw?: string): string | undefined {
	const flat = (raw ?? "").replace(/"/g, "'").replace(/\s+/g, " ").trim()
	if (!flat) return undefined
	return flat.length > QUOTE_MAX_CHARS ? `${flat.slice(0, QUOTE_MAX_CHARS)}...` : flat
}

/**
 * The one line that tells a person which lever moves, in words they can paste.
 *
 * What the tree actually offers for a ledger FORBID row: a newer sentence saying the opposite (a grant
 * for the same value outranks it — `applyEvent`'s exact-key flip), `/grants` to see the row, and
 * `/grants clear` to drop the ledger. `/grants revoke <value>` is NOT one of them: it revokes GRANTS and
 * leaves forbids alone (`revokeLedgerGrants`, `dropRevokedGrantRows` both say so), so printing it as the
 * remedy would send the reader to a command that answers "No session grant matches". An offer that
 * cannot be honoured is worse than no offer — which is why this line names `/grants revoke` only now that
 * the command behind it exists: it lifts forbid rows as well as grants, so the row's own value is
 * offered as a command the code will actually carry out.
 */
export function ledgerLever(ctx?: DenialContext): string | undefined {
	if (ctx?.decidedBy !== "ledger" || !ctx.ledgerValue) return undefined
	// A blanket row names no target, so telling someone to "allow `*`" is not a thing they can say. Where
	// the row has a concrete value, that value is in the sentence, because it is also the key a newer grant
	// has to share to outrank it.
	const blanket = ctx.ledgerValue === "*"
	const what = blanket ? "this kind of action" : ctx.ledgerValue
	const how = blanket
		? `say you allow ${what} again in your own words — the sentence that set this is the one a newer sentence outranks`
		: `say you allow ${what} again in your own words — a newer grant for that value outranks the forbid`
	return `clear it: ${how} · /grants lists every row · /grants revoke ${blanket ? '"*"' : ctx.ledgerValue} lifts this forbid too — the revocation survives re-reading the sentence · /grants clear drops everything`
}

function classifierPhrase(ctx: DenialContext): string {
	switch (ctx.classifierWhy) {
		case "denied":
			return "classifier — denied: the safety model judged this and said no (its own verdict, not a rule and not layer 0)"
		case "unavailable":
			// The cause is the actionable half of this sentence: "unavailable" says nothing was judged, the cause says
			// what to fix. Absent is admitted as absent rather than papered over with a generic guess.
			return `classifier — unavailable: the model did not answer, so there is no verdict to act on and the gate fails closed${causeClause(ctx)}`
		case "no-endpoint":
			return "classifier — no endpoint configured (classifier.enabled off, or no baseUrl/auth resolved)"
		case "window-too-small":
			return "classifier — no user message fits the grant window, so the authorisation call was skipped"
		default:
			return `classifier — which kind of failure: ${NOT_REPORTED}${causeClause(ctx)}`
	}
}

/** How long a transport's error text may be inside an attribution line. Bodies are already capped by the
 *  transport (300 chars); this keeps one denial readable when the cause is a whole HTTP response. */
const CAUSE_MAX_CHARS = 220

function causeClause(ctx: DenialContext): string {
	const flat = (ctx.classifierCause ?? "").replace(/\s+/g, " ").replace(/`/g, "'").trim()
	if (!flat) return ""
	const shown = flat.length > CAUSE_MAX_CHARS ? `${flat.slice(0, CAUSE_MAX_CHARS)}…` : flat
	return ` — cause: \`${shown}\``
}

/**
 * One line, fixed order — decider, then category, then the target as layer 0 rendered it — because
 * those three answer the three different questions a denial used to leave open: which lever moves,
 * what kind of action this is, and which object it is about.
 */
export function attributionLine(opts: { ctx?: DenialContext; category?: string; targets?: string[] }): string {
	const ctx = opts.ctx
	const category = firstText(opts.category, ctx?.category) ?? NOT_REPORTED
	const targets = (opts.targets?.length ? opts.targets : ctx?.targets) ?? []
	const shown = targets.slice(0, 3).join(", ")
	const targetText = targets.length ? `${shown}${targets.length > 3 ? ` (+${targets.length - 3} more)` : ""}` : NOT_REPORTED
	return `${describeDecider(ctx)} | category: ${category} | target: ${targetText}`
}

function firstText(...values: Array<string | undefined>): string | undefined {
	for (const v of values) if (v && v.trim()) return v
	return undefined
}

const LITERAL_ARGS =
	"Split this into separate calls, each with literal arguments (no substitution, no chaining), keeping targets inside the project."

/**
 * category -> why + rewrite, keyed on the categories risk-policy actually emits
 * and ordered by how often they block real calls. `{target}` is replaced with
 * the offending path. Guidance may only point at LESS powerful actions — this
 * text is read by an agent trying to satisfy the gate, so it must never sketch a
 * way around it.
 */
const DENIAL_GUIDANCE: Record<string, { mechanism: string; fix: string }> = {
	unproven_value: {
		mechanism: "an argument value comes from a command substitution, so its effect cannot be determined statically",
		fix: "run the substitution as its own read-only call first, then pass its literal output as a plain argument.",
	},
	unproven_structure: {
		mechanism: "the command uses shell structure the analyzer will not vouch for (brace grouping, complex quoting)",
		fix: "rewrite as plain sequential commands without brace groups or nested quoting.",
	},
	unparseable_command: {
		mechanism: "the command could not be parsed (unbalanced quote, heredoc or control character)",
		fix: "fix the quoting, or write the script to a file with the write tool and run it by path.",
	},
	unknown_command: {
		mechanism: "this program is not in the read-only tables, so what it does is unknown",
		fix: "use a command with a known effect for the same job, or ask for this exact command to be approved.",
	},
	interpreter_unknown: {
		mechanism: "an interpreter is running code the analyzer cannot classify (-c, heredoc or inline script)",
		fix: "write the script to a file with the write tool, then run that file by path.",
	},
	read_secret: {
		mechanism: "this reads a secret-bearing path ({target})",
		fix: "Never print the contents. If one value is needed, have the user supply that value, or move it somewhere not secret-bearing. For durable access the user can add a rule naming the exact path, e.g. Read({target}) - a folder glob will not reach a secret, by design.",
	},
	write_outside: {
		mechanism: "this writes outside the project ({target})",
		fix: "write inside the project, or name the exact path so the user can approve that scope.",
	},
	delete_outside: {
		mechanism: "this deletes outside the project ({target})",
		fix: "delete inside the project, or name the exact path. Prefer an exact rule over a wildcard.",
	},
	delete_recursive: {
		mechanism: "this deletes recursively ({target})",
		fix: "name the specific paths to remove instead of recursing.",
	},
	delete_data: {
		mechanism: "this destroys data ({target})",
		fix: "confirm the exact targets with the user and remove them explicitly, one path at a time.",
	},
	perm_change: {
		mechanism: "this changes permissions on {target}",
		fix: "narrow to the single path that needs it and say why.",
	},
	privilege: {
		mechanism: "this escalates privileges",
		fix: "do the same work without privilege escalation, or ask the user to run that step.",
	},
	cluster_mutation: { mechanism: "this mutates cluster state", fix: "run the read-only equivalent (get/describe) first, then ask before mutating." },
	container_mutation: { mechanism: "this mutates containers or images", fix: "inspect with read-only commands first, then ask before creating or removing." },
	db_mutation: { mechanism: "this mutates stored data", fix: "run the read query first, then ask before writing." },
	vcs_remote: { mechanism: "this publishes to a remote", fix: "keep the change local (commit only) and ask before pushing." },
	vcs_discard: { mechanism: "this discards local work", fix: "commit or stash first so the change is recoverable, then ask." },
	network_send: { mechanism: "this sends data off this machine", fix: "check the payload holds no credentials, then ask before sending." },
	network_listen: { mechanism: "this binds a port or opens a tunnel", fix: "stay on a project-local port and ask before exposing anything." },
	process_control: { mechanism: "this stops or signals running processes", fix: "target one named process rather than a pattern." },
	process_massacre: { mechanism: "this looks like a self-replicating function (fork bomb)", fix: "do not attempt variants." },
	package_system: { mechanism: "this installs system packages", fix: "prefer a project-local install, and ask before touching the system." },
	remote_exec: { mechanism: "this downloads and runs remote code", fix: "download first, read it, then run the local file." },
	disk_destroy: { mechanism: "this targets disk or partition state", fix: "do not attempt variants; ask the user to run it." },
	system_power: { mechanism: "this changes machine power state", fix: "ask the user to run it." },
	device_write: { mechanism: "this writes to a device node", fix: "write to a regular file inside the project instead." },
	wipe_protected: { mechanism: "this would destroy a protected location ({target})", fix: "do not attempt variants; ask the user." },
	history_wipe: { mechanism: "this deletes shell history", fix: "do not attempt variants; ask the user." },
	unknown_tool: { mechanism: "the effect of this call cannot be classified", fix: LITERAL_ARGS },
}

const FALLBACK_GUIDANCE = {
	mechanism: "the gate could not establish that this is safe",
	fix: LITERAL_ARGS,
}

/**
 * The construct the analyzer reported, in words that say what to rewrite.
 *
 * `unproven_structure` used to carry ONE sentence — "brace grouping, complex quoting" — however the walker had
 * refused, so a command whose only structure was `${PI_SESSION_ID:-unset}` was told to delete a brace group it did
 * not have, and to give up on a step a literal rewrite cleared in one second. The analyzer already names the
 * construct (a §12 id) in the segment description; this table is that id in the reader's terms.
 *
 * Two rules an entry has to keep: it names ONLY its own construct (a fix line mentioning brace groups for a
 * parameter expansion re-creates the defect), and it points at a LESS powerful action, never at a way around the
 * gate — the same constraint as {@link DENIAL_GUIDANCE}.
 */
const CONSTRUCT_GUIDANCE: Record<string, { mechanism: string; fix: string }> = {
	"variable-expansion": {
		mechanism: "the command contains a parameter expansion (`$X` or `${X:-y}`), so the value it acts on is not knowable from the text",
		fix: "run it with the value written out literally where the parameter expansion stands, or read the value in its own read-only call and pass what it printed as a plain argument.",
	},
	"command-substitution": {
		mechanism: "one argument is the output of another command (`$(…)` or backticks), so its value does not exist until the command runs",
		fix: "run the inner command on its own first, then pass what it printed as a plain argument.",
	},
	"process-substitution": {
		mechanism: "an argument is a live stream (`<(…)` / `>(…)`), which stands for a file that only exists while the command runs",
		fix: "write the input to a project file first, then pass that path.",
	},
	"brace-group": {
		mechanism: "the commands are wrapped in a brace group (`{ …; }`), which the analyzer does not flatten into separate commands",
		fix: "write the commands inside it out one after another with plain `&&` or `;` between them.",
	},
	"brace-expansion": {
		mechanism: "an argument is generated by brace expansion (`{1..5}`, `{a,b}`), so the command's real argument list is decided when it runs",
		fix: "name the values you want explicitly, one command per value.",
	},
	"brace-with-quote": {
		mechanism: "a brace sits in the same word as a quote — or inside a here-document whose delimiter is unquoted — so the analyzer cannot tell what the argument will be",
		fix: "quote the here-document delimiter (`<<'EOF'`) so the body is data, and keep braces out of a word that is quoted.",
	},
	"loop-body": {
		mechanism: "the command is a loop (`for` / `while` / `until`), so its body runs an unknown number of times over values the text does not list",
		fix: "write out the iterations you need as their own plain commands.",
	},
	"conditional-body": {
		mechanism: "which command runs depends on an `if`/`then` test the analyzer cannot evaluate",
		fix: "run the test on its own, then issue only the command you actually need.",
	},
	"case-statement": {
		mechanism: "which command runs depends on a `case` match against a value the text does not fix",
		fix: "pick the branch you need and run that command directly.",
	},
	"function-definition": {
		mechanism: "the command defines a shell function, so what runs later depends on calls the analyzer cannot see",
		fix: "run the body directly, once, as a plain command.",
	},
	"subshell-argument": {
		mechanism: "an argument or group runs in a subshell (`( … )`), so its effect on the shell state is not visible to the analyzer",
		fix: "write the inner commands out at the top level, one after another.",
	},
	"arithmetic-command": {
		mechanism: "the command's exit status comes from an arithmetic evaluation (`(( … ))`), which is not a program the analyzer knows",
		fix: "compute the value with a plain command and use the result literally.",
	},
	"arithmetic-non-literal": {
		mechanism: "an arithmetic expression contains a value that only exists at run time, so the number it yields is unknown",
		fix: "substitute the literal number, or compute it in its own read-only call and use what it printed.",
	},
	"runtime-only-argument": {
		mechanism: "an argument's value is decided while the command runs, so nothing about the target is established by the text",
		fix: "pass the literal argument, or determine it in a separate read-only call first.",
	},
	"heredoc-unquoted-delimiter": {
		mechanism: "a here-document is written with an unquoted delimiter, so `$VAR` and `$(…)` inside its body expand while it is read",
		fix: "quote the delimiter (`<<'EOF'`) so the body is data, or write the file with the write tool and run it by path.",
	},
	"heredoc-unattributed": {
		mechanism: "a here-document could not be tied to one command, so the analyzer cannot say which program receives that body",
		fix: "write the content to a file with the write tool, then name the file as an argument.",
	},
	"redirect-unsupported": {
		mechanism: "the command uses a redirection form the analyzer does not model, so where its output goes is unknown",
		fix: "use a plain `>` to a project path, or let the tool that already writes files do it.",
	},
	"evaluates-arguments-as-code": {
		mechanism: "this program runs the text of its own arguments as code, so the analyzer cannot separate the data from the program",
		fix: "put the code in a file with the write tool and run that file by path.",
	},
	"wrapper-not-analysable": {
		mechanism: "a wrapper (`env`, `timeout`, `sudo`, `nice`, …) sits in front of the real command in a shape the analyzer cannot see through",
		fix: "run the inner command on its own, without the wrapper.",
	},
	"jq-system-call": {
		mechanism: "a `jq` program contains `system(…)`, which runs a shell command from inside the filter",
		fix: "do the shell part yourself as its own command and keep the filter to data only.",
	},
	"jq-file-flag": {
		mechanism: "a `jq` flag reads the program from a file the analyzer has not read, so the filter's effect is unknown",
		fix: "pass a short filter inline, or show the filter file's contents first.",
	},
	"proc-environ-read": {
		mechanism: "the command reads another process's environment out of `/proc`, which can contain credentials",
		fix: "ask the user for the value they need, rather than reading it out of a process.",
	},
	"ifs-assignment": {
		mechanism: "the command changes `IFS`, which changes how every later word in the same command is split",
		fix: "drop the assignment and quote the arguments you mean literally.",
	},
	"prompt-variable-assignment": {
		mechanism: "the command assigns a variable that the shell reads back (`PS1`, `PROMPT_COMMAND`, …), so it changes the shell itself",
		fix: "do the work in a plain command instead of changing the prompt or its hooks.",
	},
	"tilde-in-assignment": {
		mechanism: "a `~` inside an assignment expands to a home-relative path the analyzer cannot resolve here",
		fix: "write the path out in full, or let a tool that resolves paths take it.",
	},
	"nameref-assignment": {
		mechanism: "the command creates a name reference (`declare -n`), so one assignment writes through a name chosen at run time",
		fix: "assign the target variable directly by name.",
	},
	"subscript-evaluation": {
		mechanism: "an array subscript is evaluated as an expression, so which element is touched is decided at run time",
		fix: "use the literal index you mean.",
	},
	"assignment-name-invalid": {
		mechanism: "the analyzer cannot read the name being assigned, so it cannot bound what changes",
		fix: "write the assignment with a plain identifier on the left of `=`.",
	},
	"ansi-c-string": {
		mechanism: "the command uses an ANSI-C quoted string (`$'…'`), whose escapes expand into bytes the text does not show",
		fix: "use a plainly quoted string, or write the content with the write tool.",
	},
	"translated-string": {
		mechanism: "the command uses a locale-translated string (a `$` before a quoted string), whose text depends on the machine's locale",
		fix: "use the literal text you mean, plainly quoted.",
	},
	"backslash-whitespace": {
		mechanism: "a backslash escapes whitespace, so word boundaries — and therefore the argument list — are not what they look like",
		fix: "quote the whole value instead of escaping its spaces.",
	},
	"hidden-comment-in-argument": {
		mechanism: "a `#` sits where the analyzer cannot tell whether it starts a comment or is part of an argument",
		fix: "put the `#` inside quotes if it is data, or on its own if it is a comment.",
	},
	"inventory-mismatch": {
		mechanism: "the parse and the analyzer's count of the commands disagree, so this command is not being read reliably at all",
		fix: "split it into separate, plainly quoted commands.",
	},
	"incomplete-command-fragment": {
		mechanism: "the text is a fragment of a command rather than a whole command",
		fix: "send the complete command.",
	},
	"command-name-not-a-literal": {
		mechanism: "the name of the program to run comes from a value the analyzer cannot see, so which program this is stays unknown",
		fix: "name the program literally at the start of the command.",
	},
	"keyword-as-command-name": {
		mechanism: "the command starts with a shell keyword, so what runs depends on the surrounding shell structure",
		fix: "run the command the keyword guards, on its own.",
	},
	"parse-aborted": {
		mechanism: "the analyzer gave up on this command (it was too large or too deep), so nothing about its effect was established",
		fix: "make it smaller: one command per call, each plainly quoted.",
	},
	"input-too-large": {
		mechanism: "the command is larger than the analyzer will read, so nothing about its effect was established",
		fix: "put long content in a file with the write tool and run a short command that names it.",
	},
	"parser-unavailable": {
		mechanism: "the shell analyzer was not loaded in this process, so the command was not checked at all",
		fix: "retry the call; if it keeps happening the shell grammar failed to load and the session needs a restart.",
	},
}

/** The rewrite offered when a construct is named but has no entry of its own. Deliberately free of any specific
 *  construct's name: naming one for a command that does not contain it is the defect this table replaces. */
const GENERIC_REWRITE =
	"rewrite it as plain sequential commands — one command per step, every argument written out literally."

/** The §12 ids that can arrive as the reported construct. Every id with prose of its own is here by construction;
 *  the rest are listed so a reported-but-unlisted construct is still NAMED rather than guessed away. */
const REPORTED_CONSTRUCTS = new Set<string>([
	...Object.keys(CONSTRUCT_GUIDANCE),
	"unterminated-quote", "unterminated-backtick", "unterminated-substitution", "unterminated-heredoc",
	"unterminated-heredoc-delimiter", "control-character", "unicode-whitespace", "parse-error", "zsh-tilde-bracket",
	"zsh-equals-expansion", "zsh-module-builtin", "empty-command-name",
])

/**
 * The construct the analyzer actually reported, read out of the text it wrote.
 *
 * It appears there in two shapes — `cannot verify command structure (variable-expansion)` and
 * `echo (read-only) (structure not verified: variable-expansion)` — so this scans the words rather than parsing
 * one format. The FIRST match wins, which is the primary construct: layer 0 puts its own note first.
 */
export function reportedConstruct(text: string | undefined): string | undefined {
	if (!text) return undefined
	for (const word of text.split(/[^A-Za-z0-9_-]+/)) {
		const id = word.toLowerCase()
		if (id && REPORTED_CONSTRUCTS.has(id)) return id
	}
	return undefined
}

/** Why + rewrite for one reported construct. The generic sentence is the fallback for when NOTHING was reported —
 *  never a substitute for a construct that is known. */
export function structureGuidance(construct?: string): { mechanism: string; fix: string } {
	if (!construct) return DENIAL_GUIDANCE.unproven_structure
	const bespoke = CONSTRUCT_GUIDANCE[construct]
	if (bespoke) return bespoke
	return {
		mechanism: `the analyzer refused the construct it reported: \`${construct}\`, so what this command does was not established`,
		fix: GENERIC_REWRITE,
	}
}

export type DenialSegment = { command: string; category: string; targets: string[]; description?: string }

/**
 * Which kind of wall the agent hit. This is what decides the ladder, not a
 * denial count: a count cannot tell "the gate could not see the effect" from
 * "the target itself is not allowed", and those want opposite responses.
 */
export type DenialWall = "analysis" | "authority"

const ANALYSIS_CATEGORIES = new Set([
	"unproven_value",
	"unproven_structure",
	"unparseable_command",
	"interpreter_unknown",
	"unknown_command",
	"unknown_tool",
])

export function wallFor(category: string): DenialWall {
	const key = category.split("+")[0] ?? category
	return ANALYSIS_CATEGORIES.has(key) ? "analysis" : "authority"
}

/**
 * Which wall a whole call hit, from the verdict rather than from one category.
 *
 * `wallFor(r.category)` alone is wrong in exactly the case this guards: layer 0 bailed on the command's shape,
 * the effect model then GUESSED a category for a command nobody could parse (`write_outside`), and that guess —
 * the last thing asked, not the thing that decided — moved the call to the authority wall, whose advice is "the
 * target itself is not allowed, park it". A command that was never understood has no established target, so no
 * authority verdict about it can be true. One bailed segment is therefore enough to make the wall analysis.
 */
export function denialWall(r: GateResult): DenialWall {
	if (wallFor(r.category) === "analysis") return "analysis"
	const bailed = (r.policy?.segments ?? []).some(
		(s) => s.tier !== "allow" && wallFor(s.category) === "analysis",
	)
	return bailed ? "analysis" : "authority"
}

/**
 * Escalation bucket for one goal. Deliberately not the exact command: keying on
 * argv means every rewrite resets the count, so the ladder would measure
 * stubbornness instead of progress, and a model that keeps varying the command
 * would never escalate at all. Analysis denials bucket per tool (the target is
 * usually irrelevant to them); authority denials bucket by target directory, so
 * retries at the same place escalate while unrelated work does not.
 */
export function denialFamily(opts: { tool: string; category: string; targets: string[] }): string {
	if (wallFor(opts.category) === "analysis") return `${opts.tool}|analysis`
	// Two leading path segments: coarse enough that poking at sibling directories
	// counts as one escalating goal, narrow enough that unrelated trees stay
	// separate. Stripping only the filename would split siblings, so ten attempts
	// at ten sibling paths would never escalate.
	const parts = (opts.targets[0] ?? "").split("/").filter(Boolean)
	const scope = parts.length > 1 ? `${parts[0]}/${parts[1]}` : parts[0] ?? ""
	return `${opts.tool}|authority|${scope || "none"}`
}

/**
 * The one sentence said on the caller's behalf when a prompt was suppressed while a person watched.
 * It exists because the flag, not the policy, was the author of the refusal, and nothing in the old
 * text said so: the session ran for hours self-denying with "do not ask the user" at the keyboard.
 * Deliberately contains no instruction not to ask — with a human present, asking IS the fix.
 */
export const HUMAN_PRESENT_SOFT_DENY =
	" A PROMPT WOULD HAVE BEEN SHOWN here — a human is watching this session — but unattended mode is ON, so the gate soft-denied the call instead of asking you. The lever is /unattended off (then make the same call again), or say to the user what you wanted and let them answer."

/** Guidance for a soft-deny with a person present: the flag is the author, so no rung of the
 *  rewrite-first ladder applies. Attempt/wall/tier only choose what to do AFTER that is said. */
function humanPresentGuidance(opts: { wall: DenialWall; attempt: number; tier: "allow" | "ask" | "never" }): string {
	if (opts.tier === "never") {
		return `${HUMAN_PRESENT_SOFT_DENY} Note: this call is high-risk — even attended it is never auto-approved, so only a person's answer clears it. Say what you needed and park it.`
	}
	if (opts.attempt >= 3) {
		return `${HUMAN_PRESENT_SOFT_DENY} You have been soft-denied ${opts.attempt} times without a dialog ever appearing, so retrying is not the missing step: say so once and continue with the work that does not need it.`
	}
	if (opts.wall === "authority") {
		return `${HUMAN_PRESENT_SOFT_DENY} Rewriting will not clear this one either — the target itself is what is not allowed, so it needs the flag off and a person's answer, naming the exact target.`
	}
	return `${HUMAN_PRESENT_SOFT_DENY} The FIX above may still be worth one rewrite; if the shape is already plain, this is not an analysis gap and another variant will not help.`
}

/**
 * What a rung that stops the rewrite loop has to hand the person who reads the report at the end: the
 * three things that turn "I got blocked" into one reply which unblocks the run.
 */
const REPORT_ESSENTIALS =
	"what you were trying to achieve, the exact target, and the narrowest rule that would allow it"

/**
 * The unattended ladder. The failure it is designed against: an agent stopping
 * a run that was one rewrite away, because the message offered parking as a
 * comfortable exit. So attempt one offers NEITHER parking NOR an exit, and the
 * escalation appears only once a rewrite has actually failed — earlier for an
 * authority wall, where rewriting cannot possibly help.
 *
 * Every rung says only what this session can actually do, and what it can do right now does not include
 * asking. A gated tool call has no route to a person: `promptGateApproval` produces this text and
 * returns the denial when the session is unattended or has no UI, so nothing is pending and nothing
 * times out later, and the subagent→parent forwarding path is not reachable from that call site at all.
 * The only escalation left is the end-of-run report a person reads when they come back, which is why a
 * rung that stops the loop names the report and its essentials instead of an ask.
 *
 * The rungs used to read `Ask the user with request_user_permission (the request waits up to 10 minutes
 * and fails closed)`. That tool is registered nowhere, so the agent spent a turn calling a name that
 * does not exist, and the wait it was promised had no author. If a tool like it is ever registered, it
 * has to reach a person through the same path a clicked approval takes — never a rule file or a grant
 * row written from inside the tool — and only then does the ask rung come back here. Until then
 * `deny-messages.test.ts` fails on any rung that names a tool `index.ts` does not register.
 */
export function unattendedEscalation(opts: {
	wall: DenialWall
	attempt: number
	tier: "allow" | "ask" | "never"
	/** True when a dialog WOULD have been rendered (`ctx.hasUI`). Absent = today's ladder. */
	humanPresent?: boolean
}): string {
	if (opts.humanPresent) return humanPresentGuidance(opts)
	if (opts.tier === "never") {
		return ` Unattended: no rewrite makes this acceptable — only a human can clear it, and no prompt can be shown to one from this session. Park it, finish the work that does not depend on it, and list it in your end-of-run report (${REPORT_ESSENTIALS}). Asking now only ends the run with a question nobody is there to answer.`
	}
	if (opts.attempt >= 3) {
		return ` Unattended: denied ${opts.attempt} times. Park it now, continue with everything that does not depend on it, and list it in your end-of-run report with what you tried.`
	}
	if (opts.attempt === 2) {
		return opts.wall === "authority"
			? ` Unattended: rewriting will not clear this — the target itself is what is not allowed. Nobody is watching this session and nothing is waiting for an answer, so park the step and put it in your end-of-run report (${REPORT_ESSENTIALS}) — that is the whole decision a person needs to unblock it in one reply.`
			: ` Unattended: that rewrite did not clear it. Try once more with a genuinely different shape (see FIX above), not a re-wording of the same command. If that also fails, park it and list it in your end-of-run report with what you tried: an ask cannot be answered in this run.`
	}
	return " Unattended: keep working — do NOT park this step and do not ask the user yet. You have not tried rewriting it, and most denials of this kind clear on the first rewrite. There is nobody at this session to answer a question, so rewriting is the only route."
}

/**
 * A denial that came from a human (or a parent session), not from an analysis gap.
 * Deliberately outside the ladder: rewriting after a person said no is arguing,
 * and asking again is nagging.
 */
export const UNATTENDED_PARK_AFTER_HUMAN_DENIAL =
	" Unattended: a person denied this, so do not rewrite it and do not ask again. Park the step, continue with other work, and list it in your end-of-run report."

/**
 * Denial text for the agent: one DENIED + FIX pair per OFFENDING segment, then a
 * single RETRY line. Naming only the blocked segment matters — the previous
 * message listed every target in the chain, so harmless commands sitting next to
 * the real problem were implicated, which sends the agent off fixing the wrong thing.
 */
export function buildPreciseDenial(opts: {
	head: string
	segments: DenialSegment[]
	futility: DenialFutility
	/** `attributionLine(...)` — who decided, what category, what target. */
	attribution?: string
	/** How a human clears this, when the decider is something they can change. Its own line, because it
	 *  is the one line written for a person rather than for the agent, and it is never truncated. */
	lever?: string
	/** One line between the segments and the retry hint, for a fact the reader needs before deciding what to do
	 *  — today that is the effect model's category being called what it is when the analyzer never finished. */
	note?: string
}): string {
	const lines: string[] = [opts.head]
	if (opts.attribution) lines.push(opts.attribution)
	if (opts.lever) lines.push(opts.lever)
	const shown = opts.segments.slice(0, 3)
	for (const s of shown) {
		const key = s.category.split("+")[0] ?? s.category
		// An unproven structure says WHY it was unproven, and the analyzer's own segment description says which.
		// Keying guidance on the category alone printed "brace grouping, complex quoting" for a parameter
		// expansion, which sent the agent to rewrite a command that had no brace in it.
		const construct = key === "unproven_structure" ? reportedConstruct(s.description ?? s.command) : undefined
		const g = construct ? structureGuidance(construct) : DENIAL_GUIDANCE[key] ?? FALLBACK_GUIDANCE
		const target = s.targets[0] ?? "the named path"
		lines.push(`DENIED: ${s.command} — ${g.mechanism.replace(/\{target\}/g, target)} [${key}]`)
		lines.push(`FIX: ${g.fix.replace(/\{target\}/g, target)}`)
	}
	if (opts.segments.length > shown.length) {
		lines.push(`(+${opts.segments.length - shown.length} more blocked segments)`)
	}
	if (opts.note) lines.push(opts.note)
	lines.push(`RETRY: ${RETRY_TEXT[opts.futility]}`)
	return lines.join("\n")
}

/** What the caller knows on top of the gate result. */
export type GateDenialContext = DenialContext & { unattended?: boolean }

/** Denial message sent back to the agent when there is no UI or the user blocks. */
export function gateDenialMessage(
	r: GateResult,
	ctx?: GateDenialContext,
): string {
	const blocked = r.policy.segments.filter((s) => s.tier !== "allow")
	const segments: DenialSegment[] = blocked.length > 0
		? blocked.map((s) => ({
			command: s.command.trim() || s.description,
			category: s.category,
			// The analyzer's own words — the layer-0 ones, not the model's — are what identify the construct, so
			// they travel with the segment instead of being lost when the wall is rendered.
			description: s.description,
			targets: s.entities.filter((e) => e.kind === "target").map((e) => e.value),
		}))
		: [
				{
					command: r.description,
					category: r.category,
					targets: r.entities.filter((e) => e.kind === "target").map((e) => e.value),
				},
			]
	const head =
		r.tier === "never"
			? `Blocked (high-risk, never auto-approved): ${r.description}`
			: `Not auto-approved: ${r.description}`
	// Wall type is part of the head so the agent sees the shape of the problem, not just the local complaint.
	const wall = denialWall(r)
	const headWithWall = `${head} (${wall} wall)`
	// When the wall is analysis but the call's category came from the model, that category is a guess about a
	// command nobody parsed. Say so, before the retry hint: left unsaid, the reader reads `write_outside` as a
	// verdict about the target and goes looking for a rule to add.
	const guessedCategory = wall === "analysis" && wallFor(r.category) === "authority" ? r.category : undefined
	// The whole-call category and targets come straight off the gate result — they have always been
	// there, they were just never printed, which is why every denial read as one undifferentiated
	// "not auto-approved".
	const attribution = attributionLine({
		ctx,
		category: r.category,
		targets: r.entities.filter((e) => e.kind === "target").map((e) => e.value),
	})
	return buildPreciseDenial({
		head: headWithWall,
		attribution,
		lever: ledgerLever(ctx),
		note: guessedCategory
			? `GUESS: \`${guessedCategory}\` is what the safety model called a command the analyzer could not verify — a guess about intent, not a verdict about the target. The blocker is the command's shape, so the FIX above is the step that clears it.`
			: undefined,
		segments,
		futility: futilityFor({
			tier: r.tier,
			unparseable: r.unparseable,
			unattended: ctx?.unattended,
			humanPresent: ctx?.humanPresent,
		}),
	})
}

// ------------------------------------------------- what a call site can actually name

/**
 * Everything a caller can see about a denial it is about to render, without being asked to guess.
 * Each field is a FACT the caller has, not a hint: `endpoint` is whether this call resolved a model
 * endpoint, `userMessages` is what it handed the gate, `ledger` is the ledger the gate was given (so
 * a gate that ran without one cannot be attributed to the ledger), `blockedByHuman` is a click that
 * happened. Anything the caller does not have is left out, and the result is `undetermined`.
 */
export type GateDenialEvidence = {
	/** The verdict being rendered — the source for tier, category, entities and the model-call record. */
	result: GateResult
	/** The exact policy options the gate ran with, so entities resolve against the same root layer 0 used. */
	policy: PolicyOptions
	/** Did this call resolve a classifier endpoint? Absent = the caller does not say. */
	endpoint?: boolean
	/** Why the endpoint was missing, when the caller resolved one and it failed. Absent falls back to the
	 *  resolver's own record of the most recent resolution. */
	endpointFailure?: ClassifierUnavailability
	/** How many user messages the gate was given — the gate skips the authorisation call for a reason. */
	userMessages?: number
	/** The ledger the gate consulted; omit it when the gate ran without one. */
	ledger?: Ledger
	/** A person answered the dialog and chose Block. */
	blockedByHuman?: boolean
}

/** What the caller passes in; `gateDenialAttribution` adds the verdict itself. */
export type GateDenialKnowledge = Omit<GateDenialEvidence, "result" | "blockedByHuman">

/** The gate renders these quotes at 100 characters; the attribution shows no more than the head line would.
 *  Applied by `displayQuote`, i.e. on the way OUT, so a hand-built context is truncated just the same. Exported
 *  so the length pin in the tests reads as the same number the renderer uses. */
export const QUOTE_MAX_CHARS = 100

/**
 * Name the decider of a gate denial from evidence, never from a guess.
 *
 * The rule the whole function follows: name the LAST AUTHORITY THAT COULD HAVE SAID YES AND DID NOT,
 * because that is the lever the reader has to pull. The layer that merely turned the call into a
 * question in the first place is already visible in the head line and in `category:`; crediting it
 * with the refusal would send the reader to a rewrite when the missing thing was a grant.
 *
 * Order follows the gate's own pipeline, and each step needs positive evidence:
 *   1. a person's click — nothing below it can outrank an answered prompt;
 *   2. `never` — the gate stops at layer 0 before any authority is consulted, so nothing else may be
 *      named here (a forbid covering the entities would be a lie: that code never ran);
 *   3. a ledger forbid — re-checked with the gate's own predicate, on the gate's own inputs;
 *   4. the read-only posture — see `readOnlyPostureAuthor` for why this one needs two witnesses;
 *   5. the model layer, read off the call record (`modelCalls`) and the caller's endpoint fact.
 *
 * Anything left over stays `undetermined`. A wall of `undetermined` is a visible gap someone can fix;
 * a confident wrong name sends a person to edit the wrong file, which is the failure this whole
 * module was built to avoid.
 */
export function gateDenialAttribution(e: GateDenialEvidence): GateDenialContext {
	const r = e.result
	if (e.blockedByHuman) return { decidedBy: "user" }
	if (r.tier === "never") return neverDenialAuthor(r)
	const space = { home: e.policy.home, project: policyProject(e.policy) }
	return (
		ledgerForbidAuthor(e, space) ??
		readOnlyPostureAuthor(e, space) ??
		authorityChannelAuthor(r, e)
	)
}

type PathSpace = { home?: string; project?: string }

/** The worst tier the deterministic tables produced by themselves. `unknown` segments are skipped on
 *  purpose: layer 0 did not answer those, the effect model did, and crediting layer 0 for a verdict it
 *  handed over would attribute the refusal to the wrong layer. */
function layer0Tier(r: GateResult): "allow" | "ask" | "never" {
	const weight = { allow: 0, ask: 1, never: 2 } as const
	let worst: "allow" | "ask" | "never" = "allow"
	for (const seg of r.policy?.segments ?? []) {
		if (seg.tier === "unknown") continue
		if (weight[seg.tier] > weight[worst]) worst = seg.tier
	}
	return worst
}

function neverDenialAuthor(r: GateResult): GateDenialContext {
	if (layer0Tier(r) === "never") return { decidedBy: "layer0" }
	// Nothing but a model verdict can raise a call the tables did not rank `never`, and only a call that
	// ANSWERED can have done it. With neither, the honest answer is that nobody reported who decided.
	if (answeredCall(r, "effect")) return { decidedBy: "classifier", classifierWhy: "denied" }
	return {}
}

function callsOf(r: GateResult, task: "grant" | "effect"): GateResult["modelCalls"] {
	return (r.modelCalls ?? []).filter((c) => c.task === task)
}

function answeredCall(r: GateResult, task: "grant" | "effect"): boolean {
	return callsOf(r, task).some((c) => c.ok)
}

/** The last authority consulted for an ask-tier call: the model layer, if it was reached at all. */
function authorityChannelAuthor(r: GateResult, e: GateDenialEvidence): GateDenialContext {
	const calls = r.modelCalls ?? []
	// A call that failed is a transport fact, recorded whether the task was grant or effect: there is no
	// verdict, and the gate failed closed. This is the rung a user most needs to see — and it carries the
	// transport's own error text, which is the only place the specific failure (a model GitHub will not
	// serve, a parameter it rejects, a spent allowance) is written down.
	const failed = calls.find((c) => !c.ok)
	if (failed) return { decidedBy: "classifier", classifierWhy: "unavailable", classifierCause: failed.error }
	// The authorisation model answered and the call still denied: it looked for the user's approval in
	// the transcript and did not find it. `denied` here means "the model was the last authority asked
	// and its answer was no", which is the same lever either way — a grant or a rule from the user.
	if (answeredCall(r, "grant")) return { decidedBy: "classifier", classifierWhy: "denied" }
	// No authorisation call, but the effect model may still be the author: only its verdict can raise a
	// call above what the tables said, and only a call that answered can have raised it.
	if (layer0Tier(r) !== r.tier && answeredCall(r, "effect")) return { decidedBy: "classifier", classifierWhy: "denied" }
	// Nothing was asked. `endpoint` is the caller's own fact, so this is the enablement answer the head
	// line cannot give: eligible for the model, and the model was not there.
	if (e.endpoint === false) {
		// Two different states share "no endpoint", and the reader's next move depends on which:
		// nothing was configured (a config edit), or the classifier exists and could not be used (a Copilot
		// login, a service failure, a model this client cannot address). Only the first is a configuration
		// answer, so a recorded resolution failure is reported as an unavailable classifier naming its cause.
		const blocked = e.endpointFailure ?? lastUnavailability
		if (blocked) return { decidedBy: "classifier", classifierWhy: "unavailable", classifierCause: blocked.detail }
		return { decidedBy: "classifier", classifierWhy: "no-endpoint" }
	}
	// An endpoint and messages, yet no call: the gate said so itself — not one message fit the grant
	// window, so the authorisation call was skipped.
	if (e.endpoint === true && (e.userMessages ?? 0) > 0) return { decidedBy: "classifier", classifierWhy: "window-too-small" }
	return {}
}

/**
 * A named forbid in the ledger. `ledgerCovers` is the gate's own predicate, run here on the gate's own
 * inputs (the result's category and entities, the policy options the gate ran with), so the claim can
 * only be true when the gate would have stopped at the same row. Re-running a pure function to explain
 * a verdict is not a second authority; inventing one out of prose would be.
 */
function ledgerForbidAuthor(e: GateDenialEvidence, space: PathSpace): GateDenialContext | undefined {
	const ledger = e.ledger
	if (!ledger) return undefined
	const r = e.result
	if (!ledgerCovers(ledger, r.category, r.entities, space.home, space.project).forbidden) return undefined
	// The row itself, so the quote, the category and the value can all be shown. Getting it from
	// `namedForbidCovers` — the other exported forbid lookup — was the defect: that function answers a
	// DIFFERENT question (it skips blanket `*` rows on purpose and ignores categories), so the row that
	// actually refused a call never had its quote rendered and the denial said `(forbidding quote not
	// reported)` while holding a row with a quote in it.
	const row = forbiddingRow(ledger, r.category, r.entities, space)
	return {
		decidedBy: "ledger",
		ledgerQuote: row?.quote,
		ledgerCategory: row?.category,
		ledgerValue: row?.value,
	}
}

/** The same rows on copies. `ledgerCovers` stamps `lastMatchedAt` on every grant it matches, and a probe
 *  that only EXPLAINS a denial must not write that mark onto the caller's ledger — it would make a grant
 *  the gate never accepted look freshly matched, and that field feeds persistence. */
function detached(ledger: Ledger): Ledger {
	return { ...ledger, grants: ledger.grants.map((g) => ({ ...g })) }
}

/**
 * Which forbid row refused this call — found by asking the gate's predicate, never by re-deriving its
 * rules.
 *
 * `ledgerCovers` reports `forbidden` and nothing else: its `by` list carries grants, and the forbid branch
 * returns `by: []`, so the caller is left with a verdict and no row. The category-compatibility and
 * value-coverage rules that chose that row are private to `auth-ledger.ts` (and being changed there
 * now); copying them into the presentation layer would make this file a second authority on what a forbid
 * covers, and the copy would drift the day the table moves. So instead the predicate is asked again,
 * one candidate at a time: rebuild the verdict against a ledger whose ONLY forbid is the candidate — with
 * the grants emptied, so the answer is that row's own coverage and nothing else's — and the row whose
 * presence alone reproduces the refusal is the row that refused.
 *
 * Newest first, because the gate's scan credits the highest-seq compatible forbid for the target it
 * stopped at, and the first candidate tried is usually the answer. The scan is bounded by the ledger's own
 * cap on forbid rows (100 today), one cheap probe each — 1 target against 1 row — on a path that renders
 * a denial rather than decides one.
 */
function forbiddingRow(
	ledger: Ledger,
	category: string,
	entities: Entity[],
	space: PathSpace,
): LedgerEntry | undefined {
	// The target the gate's own scan stopped at: it returns at the FIRST target no grant covers, so that is
	// the first target that reports a forbid on its own. Naming a row for a later target would quote a
	// sentence that had nothing to do with this refusal.
	const probe = detached(ledger)
	const failed = entities
		.filter((e) => e.kind === "target")
		.find((t) => ledgerCovers(probe, category, [t], space.home, space.project).forbidden)
	if (!failed) return undefined
	const oneRow = { ...ledger, grants: [] as LedgerEntry[] }
	for (const f of [...ledger.forbids].sort((a, b) => b.seq - a.seq)) {
		if (ledgerCovers({ ...oneRow, forbids: [f] }, category, [failed], space.home, space.project).forbidden) {
			return f
		}
	}
	return undefined
}

/** The sentence gate.ts puts on a posture block, matched as a CONFIRMATION only — see the comment. */
const POSTURE_REASON_PREFIX = "read-only — you asked me not to change anything"

/**
 * The read-only posture ("don't change anything") is a ledger row like any other, but the gate skips it
 * for read-only categories and the set it skips (`READ_ONLY_EXEMPT`) is private to gate.ts. Naming the
 * ledger on the predicates alone would be a guess for exactly those categories — a `read_secret` deny
 * with the posture live and no endpoint is refused by layer 0, not by the posture.
 *
 * So this claim needs two witnesses, one that can only be false-positive and one that can only be
 * false-negative: the ledger predicates say a posture is live and no later grant lifted it, AND the
 * gate's own reason says the posture is what blocked. Either half alone could name the wrong author;
 * together, neither can. If either wording or those predicates change, the result is `undetermined` —
 * which costs a name and never invents one.
 */
function readOnlyPostureAuthor(e: GateDenialEvidence, space: PathSpace): GateDenialContext | undefined {
	const ledger = e.ledger
	if (!ledger) return undefined
	if (!e.result.reason.startsWith(POSTURE_REASON_PREFIX)) return undefined
	const ro = readOnlyActive(ledger)
	if (!ro) return undefined
	if (readOnlyLiftedByGrant(ledger, e.result.category, e.result.entities, ro.seq, space.home, space.project)) {
		return undefined
	}
	return { decidedBy: "ledger", ledgerQuote: ro.quote }
}
