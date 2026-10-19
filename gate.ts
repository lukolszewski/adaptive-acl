/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The auto-mode gate pipeline (docs/CLASSIFIER-SPEC.md §1–§4):
 *
 *   layer 0  evaluateToolCall (deterministic policy)
 *   layer 1a session grants (prompt-once memory)
 *   layer 1b transcript authorisation (model extract + code verify)   [ASK only]
 *   layer 1c effect classification (model)                            [UNKNOWN only]
 *
 * Returns a GateResult; the caller (index.ts) renders prompts/denials.
 * No UI, no pi imports — testable end to end against a live endpoint.
 */

import { evaluateToolCall, policyProject, type Entity, type PolicyDecision, type PolicyOptions } from "./risk-policy.ts"
import { verifyGrant, type GrantExtraction } from "./grant-verify.ts"
import {
	classifyEffect,
	effectToTier,
	extractGrant,
	type EffectClassification,
	type ModelCallResult,
	type ModelEndpoint,
} from "./model-client.ts"
import { addGrant, grantsCover, type GrantStore } from "./session-grants.ts"
import { compoundAll, ledgerCovers, namedForbidCovers, readOnlyActive, readOnlyLiftedByGrant, type Ledger } from "./auth-ledger.ts"
import { callBudget, estimateTokens, fitNewestFirst } from "./context-budget.ts"
import { fitLedgerRows, LEDGER_SHARE, ledgerRows } from "./ledger-render.ts"
import { GRANT_CALL_RESERVE_TOKENS, GRANT_NUMBERING_OVERHEAD_CHARS, grantCallFixedChars } from "./model-client.ts"
// `classifierUnavailability` is a value import from gate-bridge, which imports this module by TYPE only — so the
// edge has no cycle. It is how the gate can say WHY it had no endpoint: the resolver records the cause, and a
// denial that just said "no endpoint configured" would send a user with a broken Copilot session to their config.
import { classifierUnavailability } from "./gate-bridge.ts"
import { classifierUnavailableReason } from "./classifier-messages.ts"

/** Categories that are reads, not "changes" — exempt from the read-only posture
 *  (which is about writes/mutations). Everything else ask/unknown is treated as a
 *  change under read-only (fail-safe on ambiguous/unknown commands). */
const READ_ONLY_EXEMPT = new Set(["read_secret", "read_only"])

export type GateOutcome =
	| "allow"            // run it, no user involvement
	| "allow-granted"    // run it, authorised by transcript or session grant
	| "prompt"           // needs the user (ASK, not authorised)
	| "prompt-never"     // needs the user, loud warning, not pre-authorisable
export type GateResult = {
	outcome: GateOutcome
	tier: "allow" | "ask" | "never"
	category: string
	entities: Entity[]
	description: string
	/** Why (for the prompt / denial message / log). */
	reason: string
	/** Grant source when outcome is allow-granted. */
	grantedBy?: "session-grant" | "ledger" | "transcript"
	/** The command could not be parsed; the caller should ask the model to
	 *  fix/simplify and retry rather than prompt the user. */
	unparseable?: boolean
	policy: PolicyDecision
	modelCalls: Array<{ task: "grant" | "effect"; ms: number; ok: boolean; error?: string; raw?: string }>
}

export type GateOptions = {
	policy: PolicyOptions
	endpoint?: ModelEndpoint
	grants?: GrantStore
	/** Authorisation ledger (kept in sync by the caller via syncLedger). */
	ledger?: Ledger
	/** Recent user messages, oldest first (already redacted/limited by caller). */
	userMessages?: string[]
	signal?: AbortSignal
	debug?: (line: string) => void
}

// Recent-window fallback only — long-range authorisation lives in the ledger,
// so the window no longer has to carry the whole session (it can't anyway).
// The character caps that used to sit here (15 000 total, 2 000 per message) are gone. They were
// sized in a unit the server does not use — 15 000 characters measured 5 662 tokens and the request
// was rejected outright — and clipping a message mid-sentence fabricates evidence, because a
// truncated "...and never touch prod" reads like the approval it was cutting off. The window is now
// sized in tokens against the model's own context (context-budget.ts) and a message goes whole or
// not at all.
const MAX_USER_MSGS = 60

/** Budget for a caller that has no measured fixed part to subtract (tests, diagnostics). */
const BARE_CALL_BUDGET = callBudget(undefined, 0, GRANT_CALL_RESERVE_TOKENS)

/**
 * The recent-window the grant call gets: the newest `MAX_USER_MSGS`, then as much of those as fits
 * in `budgetTokens` — filled newest-first, stopping at the first message that does not fit, so what
 * reaches the model is a contiguous suffix and every string in it is one of the strings passed in.
 * An empty result means even the newest message is too large for the window; the caller then sends
 * no raw messages at all rather than a fragment of one.
 */
export function limitUserMessages(
	msgs: string[],
	budgetTokens: number = BARE_CALL_BUDGET,
): string[] {
	return fitNewestFirst(
		msgs.slice(-MAX_USER_MSGS),
		(m) => estimateTokens(m.length + GRANT_NUMBERING_OVERHEAD_CHARS),
		budgetTokens,
	)
}

/**
 * Classifier health for this process, surfaced by `/classifier-status`.
 *
 * The eval harness cannot see any of this: only the gate knows when a verdict was
 * eligible for the model and the model was unusable. Those are three different
 * states - disabled, no endpoint resolved, endpoint present but failing - and all
 * three look identical to the user: a prompt. Only the last is even partly helped
 * by rewriting, which is exactly the question `/classifier-status` answers.
 */
export const classifierStats = {
	/** verdicts where the model was the only way to decide */
	eligible: 0,
	/** effect-model calls attempted */
	calls: 0,
	ok: 0,
	failed: 0,
	/** eligible verdicts with no endpoint at all: a config state, not flakiness */
	noEndpoint: 0,
	/** eligible verdicts whose endpoint could not be resolved even though a classifier IS configured — a Copilot
	 *  Auto session that would not mint, a pick in a dialect we cannot encode. Not the same state as `noEndpoint`
	 *  and not fixed by editing the config, so the two counters must not share a number. */
	resolveFailed: 0,
	/** grant-extraction call failures: these cost a prompt, not a wrong verdict */
	grantFailed: 0,
}

export function resetClassifierStats(): void {
	classifierStats.eligible = 0
	classifierStats.calls = 0
	classifierStats.ok = 0
	classifierStats.failed = 0
	classifierStats.noEndpoint = 0
	classifierStats.resolveFailed = 0
	classifierStats.grantFailed = 0
}

export async function runGate(tool: string, input: Record<string, unknown>, opts: GateOptions): Promise<GateResult> {
	const modelCalls: GateResult["modelCalls"] = []
	const dbg = opts.debug ?? (() => {})
	let policy = evaluateToolCall(tool, input, opts.policy)
	// The project root layer 0 actually used. Every grant match below resolves `./x` entities against it,
	// so using anything else (a discovered git root, the shell cwd) silently mis-resolves them and every
	// in-project grant misses — see `canonicalPath`.
	const project = policyProject(opts.policy)
	const space = { home: opts.policy.home, project }
	dbg(`[gate] layer0: ${policy.tier} ${policy.category} — ${policy.description}`)

	// ---- unparseable: refuse and ask the model to fix/simplify (no model call).
	// The command is malformed (unterminated quote/heredoc/substitution), so the
	// segment list is unreliable; do not send fabricated fragments to the effect
	// model and do not prompt the user about a broken command.
	if (policy.unparseable) {
		dbg(`[gate] unparseable: ${policy.reason}`)
		const r = finish("prompt", "ask", policy, policy.reason, modelCalls)
		r.unparseable = true
		return r
	}

	// ---- resolve UNKNOWN segments via effect classification
	if (policy.tier === "unknown") {
		classifierStats.eligible++
		if (!opts.endpoint) {
			// Two states, two sentences. "Nothing is configured" is the config answer the user has always needed;
			// "the classifier is configured and could not be used" is a service/credential answer, and must never
			// read as if the user had not set anything up.
			const blocked = classifierUnavailability()
			if (blocked) classifierStats.resolveFailed++
			else classifierStats.noEndpoint++
			return finish(
				"prompt",
				"ask",
				policy,
				blocked
					? `${classifierUnavailableReason(blocked.detail)}; confirmation required`
					: `cannot classify locally and no classifier endpoint configured`,
				modelCalls,
			)
		}
		// classify each unknown segment; the worst result wins
		let worst: { tier: "allow" | "ask" | "never"; category: string } = { tier: "allow", category: "read_only" }
		const targets: Entity[] = [...policy.entities]
		for (const u of policy.unknown) {
			const res: ModelCallResult<EffectClassification> = await classifyEffect(
				opts.endpoint,
				{ command: u.command, inlineCode: u.inlineCode, cwd: opts.policy.cwd, project: opts.policy.project ?? opts.policy.cwd },
				opts.signal,
			)
			modelCalls.push({ task: "effect", ms: res.ms, ok: res.ok, error: res.ok ? undefined : res.error, raw: res.ok ? res.raw : res.raw })
			classifierStats.calls++
			if (res.ok) classifierStats.ok++
			else classifierStats.failed++
			if (!res.ok) {
				dbg(`[gate] effect call failed: ${res.error}`)
				// The transport's own error text IS the diagnosis (`model_not_supported`, a 404 for a request that lost
				// its version header, `Unsupported parameter`, a spent allowance, a cut-off answer), so it travels into
				// the reason. Framing matters more than the wording: this is a classifier that could not be asked,
				// never a classifier that voted no.
				return finish("prompt", "ask", policy, `${classifierUnavailableReason(res.error)}; confirmation required`, modelCalls)
			}
			const mapped = effectToTier(res.value)
			dbg(`[gate] effect: ${u.command.slice(0, 60)} → ${res.value.effect}/${res.value.confidence} → ${mapped.tier}`)
			for (const t of res.value.targets) targets.push({ kind: "target", value: t })
			if (rank(mapped.tier) > rank(worst.tier)) worst = mapped
		}
		// merge with the non-unknown part of the policy decision
		const residualTier = policy.segments.filter((s) => s.tier !== "unknown").reduce<"allow" | "ask" | "never">((acc, s) => (rank(s.tier as never) > rank(acc) ? (s.tier as never) : acc), "allow")
		const finalTier = rank(worst.tier) > rank(residualTier) ? worst.tier : residualTier
		policy = {
			...policy,
			tier: finalTier,
			category: finalTier === worst.tier ? worst.category : policy.category,
			entities: dedupe(targets),
		}
		if (finalTier === "allow" && !namedForbidCovers(opts.ledger ?? null, policy.entities, opts.policy.home, project)) {
			return finish("allow", "allow", policy, "classified as project-scoped/read-only", modelCalls)
		}
	}

	if (policy.tier === "allow") {
		// "do not delete X" must bind even where the tables say allow: a named
		// user forbid downgrades the decision to ASK so the normal pipeline
		// (session grants → ledger seq precedence → prompt) decides. The touched
		// path is promoted to a target so the prompt can offer session options
		// and a plain Allow lifts it for the rest of the session.
		const fb = opts.ledger ? namedForbidCovers(opts.ledger, policy.entities, opts.policy.home, project) : null
		if (!fb) return finish("allow", "allow", policy, policy.reason, modelCalls)
		dbg(`[gate] user forbid overrides allow: "${fb.entity}" — "${fb.entry.quote.slice(0, 60)}"`)
		policy = {
			...policy,
			tier: "ask",
			description: `${policy.description} — user said: "${fb.entry.quote.slice(0, 100)}"`,
			entities: policy.entities.map((e) =>
				e.kind === "path" && e.value === fb.entity ? { kind: "target" as const, value: e.value } : e,
			),
		}
	}
	if (policy.tier === "never") {
		return finish("prompt-never", "never", policy, policy.description, modelCalls)
	}

	// ---- ASK: session grants first (a prompt approval is the user's most explicit
	// authority and wins even over a read-only posture)
	if (opts.grants) {
		const cover = grantsCover(opts.grants, policy.category, policy.entities, opts.policy.home, project)
		if (cover.covered) {
			dbg(`[gate] session grant covers: ${cover.by.join(", ")}`)
			return finish("allow-granted", "ask", policy, `covered by earlier approval (${cover.by.join(", ")})`, modelCalls, "session-grant")
		}
	}

	// ---- ASK: authorisation ledger (whole-session memory, pure code) — evaluated
	// BEFORE the read-only posture, so a later explicit "you can write to /x" is
	// never outranked by an earlier "don't change anything": the posture is a
	// default, not a veto, and newest-user-statement-wins is the whole point of the
	// seq-ordered ledger. A revocation still wins over an older grant (lv.forbidden).
	let roBlock: { quote: string; seq: number } | null = null
	if (opts.ledger) {
		const lv = ledgerCovers(opts.ledger, policy.category, policy.entities, opts.policy.home, project)
		if (lv.covered) {
			dbg(`[gate] ledger covers: ${lv.reason}`)
			// promote to a session grant so repeats skip even the ledger scan
			if (opts.grants) {
				for (const m of lv.by) addGrant(opts.grants, policy.category, m.entity, "entity")
			}
			return finish("allow-granted", "ask", policy, lv.reason, modelCalls, "ledger")
		}
		if (lv.forbidden) {
			// an explicit revocation outrules the recent-window fallback: a stale
			// grant still inside the window must not overrule "stop doing X"
			dbg(`[gate] ledger forbids: ${lv.reason}`)
			return finish("prompt", "ask", policy, lv.reason, modelCalls)
		}
		// Nothing authorised this mutation → defer to the posture check below.
		const ro = readOnlyActive(opts.ledger)
		// Exempt from the read-only posture only when EVERY category in a compound is
		// exempt: `read_secret+write_outside` contains a mutation, so it must not
		// inherit the read exemption just because a read segment was listed first.
		if (ro && !compoundAll(policy.category, READ_ONLY_EXEMPT)) roBlock = ro
	}

	// ---- ASK: read-only posture ("you are not allowed to change anything").
	// Refuse mutations (everything ask/unknown that is not a plain read); allow-tier
	// project/temp work already returned above, so the project folder is excluded by
	// default. A later per-target grant (seq > posture) lifts that target; a blanket
	// "you can make changes now" clears the posture entirely.
	if (roBlock && !readOnlyLiftedByGrant(opts.ledger!, policy.category, policy.entities, roBlock.seq, opts.policy.home, project)) {
		dbg(`[gate] read-only posture blocks ${policy.category}: "${roBlock.quote.slice(0, 60)}"`)
		return finish("prompt", "ask", policy, `read-only — you asked me not to change anything ("${roBlock.quote.slice(0, 100)}")`, modelCalls)
	}

	// ---- ASK: transcript authorisation. Sized to the model's window: subtract what the fixed part
	// of this call costs from the endpoint's context, and let the messages fill what is left —
	// whole, newest-first, or not at all.
	if (opts.endpoint) {
		const command = policy.segments.map((s) => s.command).filter(Boolean)[0] ?? ""
		const fixed = { description: policy.description, category: policy.category, entities: policy.entities, command }
		// The ledger rows are the summary of the turns that no longer fit the window. They are fitted
		// against a share of a budget measured WITHOUT them, then the fixed part is re-measured WITH them
		// so the raw messages get exactly what is left. Measuring by rendering the real prompt
		// (`grantCallFixedChars`) counts the section header, the blank line and every newline as sent,
		// and any row budget the ledger could not spend returns to the raw fill by construction —
		// no block size is hard-coded here.
		const bareBudget = callBudget(opts.endpoint.contextTokens, grantCallFixedChars(fixed), GRANT_CALL_RESERVE_TOKENS)
		const rows = opts.ledger ? fitLedgerRows(ledgerRows(opts.ledger), Math.floor(bareBudget * LEDGER_SHARE)) : []
		const rowTexts = rows.map((r) => r.text)
		const budget = callBudget(
			opts.endpoint.contextTokens,
			grantCallFixedChars({ ...fixed, ledgerRows: rowTexts }),
			GRANT_CALL_RESERVE_TOKENS,
		)
		const userMessages = limitUserMessages(opts.userMessages ?? [], budget)
		if (rows.length > 0) dbg(`[gate] grant window: ${rows.length} ledger row(s) + ${userMessages.length} message(s) in ${budget} tokens`)
		if (userMessages.length === 0 && rows.length === 0 && (opts.userMessages?.length ?? 0) > 0) {
			// Not even the newest message fits, so nothing older can either, and no ledger row stands in
			// for them. An empty list would ask the model to authorise an action from no evidence at all.
			dbg(`[gate] no user message fits the ${budget}-token grant window — call skipped`)
			return finish("prompt", "ask", policy, `needs confirmation (no user message fits the classifier window)`, modelCalls)
		}
		// Rows alone are enough to ask: a grant can live only in a row (the message that carried it is
		// long gone from the window), and skipping the call then would lose an authorisation the ledger
		// demonstrably holds.
		if (userMessages.length > 0 || rows.length > 0) {
			const res: ModelCallResult<GrantExtraction> = await extractGrant(
				opts.endpoint,
				{ ...fixed, userMessages, ledgerRows: rowTexts },
				opts.signal,
			)
			modelCalls.push({ task: "grant", ms: res.ms, ok: res.ok, error: res.ok ? undefined : res.error, raw: res.ok ? res.raw : res.raw })
			if (!res.ok) {
				classifierStats.grantFailed++
				dbg(`[gate] grant call failed: ${res.error}`)
				return finish("prompt", "ask", policy, `needs confirmation: ${classifierUnavailableReason(res.error)}`, modelCalls)
			}
			const verdict = verifyGrant({
				extraction: res.value,
				category: policy.category,
				entities: policy.entities,
				userMessages,
				ledgerQuotes: rows.map((r) => r.quote),
				space,
			})
			dbg(`[gate] grant: model=${res.value.authorized} verified=${verdict.granted} — ${verdict.reason}`)
			if (verdict.granted) {
				// persist so the identical action does not re-pay the model call
				if (opts.grants) {
					for (const m of verdict.matches) addGrant(opts.grants, policy.category, m.entity, "entity")
				}
				// `ledger` labels a verdict grounded in a row rather than in a message still in the window,
				// so the log/eval output can tell the two kinds of evidence apart.
				return finish("allow-granted", "ask", policy, verdict.reason, modelCalls, verdict.source === "ledger" ? "ledger" : "transcript")
			}
			return finish("prompt", "ask", policy, verdict.reason, modelCalls)
		}
	}

	return finish("prompt", "ask", policy, policy.description, modelCalls)
}

function rank(t: "allow" | "ask" | "never" | "unknown"): number {
	return t === "allow" ? 0 : t === "unknown" ? 1 : t === "ask" ? 2 : 3
}

function dedupe(list: Entity[]): Entity[] {
	const seen = new Set<string>()
	return list.filter((e) => {
		const k = `${e.kind}:${e.value}`
		if (seen.has(k) || !e.value) return false
		seen.add(k)
		return true
	})
}

function finish(
	outcome: GateOutcome,
	tier: "allow" | "ask" | "never",
	policy: PolicyDecision,
	reason: string,
	modelCalls: GateResult["modelCalls"],
	grantedBy?: "session-grant" | "transcript" | "ledger",
): GateResult {
	return {
		outcome,
		tier,
		category: policy.category,
		entities: policy.entities,
		description: policy.description,
		reason,
		grantedBy,
		policy,
		modelCalls,
	}
}
