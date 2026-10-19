/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Making a confirmed orphan rule live in the session that confirmed it.
 *
 * `/grants adopt confirm <id>` writes an orphan's allow rule into this project's rules file. Writing it is
 * not the same as honouring it: the session runs on a policy snapshot, and nothing on the confirm path
 * re-reads it, so the next `npm publish` in that same turn still reached the gate and was blocked while the
 * command had just said "adopted". The honest response available at the time was a wording fix — "written
 * to the rules file, effective next session" — which records the gap instead of closing it, so the other half
 * stayed open: make it live, or keep saying it is not. (Even that wording understates today's behaviour: the snapshot is re-read at every turn start by a
 * private call in the extension closure, so the rule was always coming in one message rather than one
 * session. The assertion in `index.test.ts` passes because it calls the gate handler without a turn between.)
 *
 * This module takes the other half through the reload door (`reload-policy.ts`): after a confirmation that
 * actually wrote something, re-read the rules files and hand back the snapshot to install. The rule becomes
 * live because the file that now contains it is re-read — not because anything in this session decided to
 * grant the invocation.
 *
 * --------------------------------------------- why there is no session grant here, and never will be
 * The obvious pairing was the interactive one: a click on the prompt writes a rule AND records a live grant,
 * the rule being for later and the grant for now. It does not fit an adopted *rule*. A session grant is
 * `{category, value, kind}` where `value` is an entity — a path, a remote — and `grantsCover()` refuses a
 * row with no target to match, which is why a path-less command is given no durable row at all rather than a
 * broad one. `Bash(npm publish)` names no entity, so the only grant that could cover it is a wildcard or a
 * category-level row: wider than the rule the human actually confirmed, which is the one thing this module's
 * brief forbids. Re-reading a file the human's confirmation just wrote is the narrower move, not the larger
 * one — and it leaves one store of what is allowed, the file, instead of a shadow grant that can drift from
 * it. So this module mints nothing: it re-reads, and it reports.
 *
 * ------------------------------------------------------- the sentence this module exists to make true
 * `detail` is derived from the re-read, never from the write's return value. A rule is called live only when
 * the policy being handed back carries it as an allow; otherwise the caller gets the honest "effective next
 * session" wording back, with the reason. That is deliberate: the failure this path started from was a message
 * written before the effect it described had been checked, and a command line is a safety claim.
 *
 * ------------------------------------------------------------------------ what the caller still owns
 * Auto mode's strip of classifier-bypassing bash allows stays with the caller: pass the BASE snapshot (what
 * `loadMergedPermissionRules()` returned, before `stripDangerousPermissionRules`) and re-apply the strip and
 * the classifier-verdict-cache invalidation to whatever comes back, exactly as the activation path does.
 */

import {
	type PolicyReload,
	policyCarries,
	reloadPermissionPolicy,
	ruleLabel,
	summariseReload,
} from "./reload-policy.ts"
import type { PermissionRule } from "./permissions.ts"

/** The honest fallback: nothing is called live until a re-read of the file proves it, never by default. */
const NOT_LIVE = "written to the rules file, effective next session"

/** What one confirmed rule turned into, as the command will report it. */
export type AdoptedRuleEffect = {
	/** The rule text `confirmAdoption()` reported writing, verbatim. */
	rule: string
	/** True only when the re-read put this rule into the policy this call returns. */
	live: boolean
	/** One phrase for the command line, always true of the outcome it describes. */
	detail: string
}

export type AdoptLiveResult = {
	/** Install this as the session's base policy. The array handed in, untouched, when nothing was written. */
	rules: PermissionRule[]
	/** One entry per written rule, in the order the confirmation reported them. */
	effects: AdoptedRuleEffect[]
	/** The reload behind those answers — absent when no reload was needed, because nothing was written. */
	reload?: PolicyReload
	/** Rules that became live which this confirmation did not name — the files are the source of truth, so
	 *  an edit made during the session comes in with the adopt. Reported so a caller cannot understate it. */
	unrequested: string[]
	/** One line of facts about the reload, for whoever is reading the command output. */
	summary: string
}

export type MakeLiveOptions = {
	/** The checkout whose rules files were just written. Same cwd the confirmation used. */
	cwd: string
	/** `ConfirmationReport.rules` — the rules a human named by id AND `confirmAdoption()` wrote. Grant rows
	 *  are not expressible here on purpose: they are already live, and this module adds no authority. */
	written: readonly string[]
	/** The session's current base policy, before any auto-mode strip. Pass what the session is ACTUALLY
	 *  running on, not a fresh `loadMergedPermissionRules()` — the latter has already seen the file the
	 *  confirmation wrote, which would make every answer trivially "live" and the report meaningless. */
	live: readonly PermissionRule[]
	/** Test seam for the user-level config path, forwarded to the reload. */
	globalFile?: string
}

/**
 * Re-read the policy after an adoption, and say per rule whether it is live now.
 *
 * Nothing here widens anything by itself: the only new authority that can arrive is what the rules files
 * already contain, and the only thing that put them there was a human naming an id (`confirmAdoptChoices`)
 * or an ordinary approval. When `written` is empty no reload is attempted at all — a confirm that wrote no
 * rule has nothing to make live, and touching the policy on that path would make the command's side effects
 * depend on input it was not given.
 */
export function makeAdoptedRulesLive(opts: MakeLiveOptions): AdoptLiveResult {
	if (opts.written.length === 0) {
		return {
			rules: [...opts.live],
			effects: [],
			unrequested: [],
			summary: "nothing was written, so nothing was re-read",
		}
	}

	const reload: PolicyReload = reloadPermissionPolicy({
		cwd: opts.cwd,
		live: opts.live,
		...(opts.globalFile !== undefined ? { globalFile: opts.globalFile } : {}),
	})

	// One lookup per confirmed rule, reused for both the sentence and the bookkeeping below, so the thing the
	// line claims and the thing `unrequested` subtracts can never drift apart.
	const matched = opts.written.map((rule) => ({ rule, carried: policyCarries(reload.rules, rule) }))

	const effects = matched.map(({ rule, carried }): AdoptedRuleEffect => {
		if (carried) return { rule, live: true, detail: `live now — re-read from the ${carried.source} rules file` }
		return {
			rule,
			live: false,
			detail: reload.unreadable.length > 0
				? `${NOT_LIVE} — the policy could not be re-read (${reload.unreadable.join("; ")})`
				: `${NOT_LIVE} — the re-read did not find it in the rules files`,
		}
	})

	const confirmed = new Set(matched.map((m) => (m.carried ? ruleLabel(m.carried) : m.rule)))
	return {
		rules: reload.rules,
		effects,
		reload,
		unrequested: reload.added.filter((label) => !confirmed.has(label)),
		summary: summariseReload(reload),
	}
}
