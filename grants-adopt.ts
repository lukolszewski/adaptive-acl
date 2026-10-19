/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * `/grants adopt` — the action half of the orphan scan.
 *
 * `<cwd>/.pi/projects/` can hold state for ids the current session does not use. After a directory
 * move the old id's directory sits there with every rule it ever had, and nothing reads it.
 * `listProjectStateDirs()` (utils.ts) names those directories; this module decides what to do with
 * what is inside them.
 *
 * ------------------------------------------------------------ the line this module does not cross
 * An orphan's **tightening** rules — `deny` and `ask` — may be taken without asking. Rules evaluate
 * deny → ask → allow → passthrough, so adding a deny or an ask can only turn an allowance into a
 * refusal or a prompt; there is no rule shape that makes an existing refusal looser by adding another
 * entry above it in that order. And the failure this feature exists to prevent is silent: a lost deny
 * does not error, the next session simply stops refusing. So a quiet copy is the smaller risk.
 *
 * An orphan's **widening** rules — every `allow`, and every grant row in its journal — are never
 * applied here. They are authority the human did not grant in this session, and the premise of the
 * whole product is that authority comes from an explicit human act: a prompt answered, an "always"
 * clicked, a sentence the user said. A file cannot assert that about itself — which is why
 * `importLedger()` treats imported rows as background authority instead of decided ones — and here
 * there is not even a surviving session that once said it. So `adoptOrphans()` returns them as
 * `pending` and writes nothing for them, and `confirmAdoption()` — called by the UI after a human
 * picked a row — is the only thing that can make one real.
 *
 * Why allows are not simply written with a flag on them: a stored allowance nobody authorised is the
 * one bug class this subsystem was built to make impossible, and an adopt runs from a command,
 * unattended. Withholding costs one click; guessing costs a permission forever. The asymmetry decides it:
 * wait whenever waiting is bounded and being wrong is not.
 *
 * ------------------------------------------------------------------ other rules this module keeps
 *  - **Adopt copies, it never moves.** An orphan's own files are read and left alone, so a
 *    half-finished adopt loses nothing and the old id can be adopted again or deleted by hand.
 *  - **Nothing is removed from the live project either.** The tightening half goes through
 *    `addPermissionRule()`, which appends to one behaviour list and leaves the rest of the document
 *    as it was; this module never opens the live project's allow list.
 *  - **A revocation outranks an adoption.** Rows are added through `addGrant()` — the choke point
 *    every derivation shares — and are screened against the store's tombstones first. An adoption is
 *    not a human re-grant, so it cannot lift a ban; only a prompt can.
 *  - **Path values are routed through the one canonicaliser** (`canonicalPath`, grant-verify.ts) with
 *    the caller's own project root, so a row written before the move lands on the path that exists now.
 *  - **A file it cannot read is reported, not judged.** Following utils.ts: an unparsable deny list
 *    means "no rule I could read here", never "this directory is clean".
 *  - **One id source.** The id in use comes from `getProjectId(cwd)` and every path from
 *    `getProjectPermissionsPath()`, so an adopted rule lands in the same directory the gate reads.
 */

import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import { isDangerousBashPermission } from "./dangerous-permissions.ts"
import { mergeIntoGrantsFile, pruneRows, readGrantsFile } from "./grants-file.ts"
import { canonicalPath, type PathSpace } from "./grant-verify.ts"
import {
	addPermissionRule,
	getProjectPermissionsPath,
	type PermissionRuleDestination,
} from "./permissions-loader.ts"
import {
	permissionRuleValueFromString,
	permissionRuleValueToString,
} from "./permission-rule-parser.ts"
import type { PermissionBehavior } from "./permissions.ts"
import {
	addGrant,
	rowIdentity,
	type GrantStore,
} from "./session-grants.ts"
import { getProjectId, listProjectStateDirs } from "./utils.ts"

/** Where one orphan's state came from, so every reported item can name its source. */
export type OrphanOrigin = { id: string; file: string }

/** One rule read out of an orphan's rule file. */
export type RuleCandidate = {
	kind: "rule"
	/** The rule in the spelling the matcher stores: `Tool`, or `Tool(specifier)`. */
	rule: string
	behavior: PermissionBehavior
	tool: string
	specifier?: string
	origin: OrphanOrigin
	/** Which live file it belongs in. An orphan's `permissions.local.json` stays local: a personal
	 *  rule must not be promoted into the shared project file just because it was adopted. */
	into: PermissionRuleDestination
}

/** One grant row read out of an orphan's journal. Widening by nature — a grant is an allowance. */
export type GrantCandidate = {
	kind: "grant"
	category: string
	/** The value exactly as the orphan spelled it. */
	value: string
	/** That value resolved into THIS project's path space — what a confirmed row stores. Equal to
	 *  `value` for anything not path-shaped (`canonicalPath` leaves a bare word alone). */
	target: string
	scope: "entity" | "scope"
	/** The orphan recorded an "always", so a confirmed row may be durable too. */
	durable: boolean
	origin: OrphanOrigin
}

export type Candidate = RuleCandidate | GrantCandidate

/** Something the scan found and will not act on, with the reason it will not. */
export type SkippedItem = { origin: OrphanOrigin; what: string; reason: string }

/** Everything one scan decided, before anything was written. Reads only. */
export type AdoptionPlan = {
	cwd: string
	projectId: string
	/** The orphan ids that were read — never the live one. */
	orphans: string[]
	/** Tightening: deny / ask. Safe to take now. */
	apply: RuleCandidate[]
	/** Widening: allow rules and grant rows. Nothing was written for any of these. */
	pending: Candidate[]
	skipped: SkippedItem[]
}

export type AdoptionOutcome = {
	/** The tightening rules this call actually wrote. */
	apply: RuleCandidate[]
	/** The widening items it refused to write without a human. */
	pending: Candidate[]
	plan: AdoptionPlan
	failed: { rule: string; into: PermissionRuleDestination; error: string }[]
}

export type ConfirmationReport = {
	/** Allow rules a human confirmed, now written. */
	rules: string[]
	/** Grant rows a human confirmed, now in the store. */
	grants: { category: string; value: string; kind: "entity" | "scope" }[]
	refused: { what: string; reason: string }[]
	/** Only when the caller asked for a journal: the merge that carried the rows into it. */
	journal?: { path: string; ok: boolean; added: number; error?: string }
}

export type AdoptionOptions = {
	/** The checkout whose `.pi/projects/` holds the orphans. */
	cwd: string
	/** Project root the path space resolves against. Must be the root the gate itself used —
	 *  re-deriving one here (a git root, `process.cwd()`) mis-resolves every in-project value.
	 *  Defaults to `cwd`. */
	project?: string
	home?: string
}

/** The two rule files, and where each one's rules belong in the live project. */
const RULE_SOURCES: readonly { file: string; into: PermissionRuleDestination }[] = [
	{ file: "permissions.json", into: "project" },
	{ file: "permissions.local.json", into: "local" },
]

const BEHAVIORS: readonly PermissionBehavior[] = ["deny", "ask", "allow"]

/** deny beats ask beats allow, so a stricter entry above makes a looser one dead weight. */
const STRICTNESS: Record<PermissionBehavior, number> = { allow: 0, ask: 1, deny: 2 }

function describeError(err: unknown): string {
	const name = (err as { name?: unknown } | null)?.name
	return typeof name === "string" ? name : "read failed"
}

/** Read one rules document into its three lists, tolerating every shape the file has had. */
function readRuleLists(file: string): { lists: Partial<Record<PermissionBehavior, unknown[]>> } | { error: string } {
	let raw: string
	try {
		raw = readFileSync(file, "utf-8")
	} catch (err) {
		return { error: `could not be read (${describeError(err)})` }
	}
	// A blank file is not a malformed one: it says nothing, which is not an error.
	if (!raw.trim()) return { lists: {} }
	let doc: unknown
	try {
		doc = JSON.parse(raw)
	} catch {
		return { error: "not valid JSON — an unreadable deny list is not a clean one" }
	}
	if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { error: "not an object" }
	const root = doc as Record<string, unknown>
	const nested = root.permissions
	const bag =
		nested && typeof nested === "object" && !Array.isArray(nested)
			? (nested as Record<string, unknown>)
			: root
	const lists: Partial<Record<PermissionBehavior, unknown[]>> = {}
	for (const behavior of BEHAVIORS) {
		const list = bag[behavior]
		if (Array.isArray(list)) lists[behavior] = list
	}
	return { lists }
}

type ParsedRule = { text: string; tool: string; specifier?: string }

/** One entry of a rule list, in the spelling the destination file will store — or nothing. */
function parseRule(raw: unknown): ParsedRule | undefined {
	if (typeof raw !== "string" || !raw.trim()) return undefined
	const value = permissionRuleValueFromString(raw)
	const tool = value.toolName.trim()
	if (!tool) return undefined
	const text = permissionRuleValueToString({ ...value, toolName: tool })
	return value.ruleContent === undefined
		? { text, tool }
		: { text, tool, specifier: value.ruleContent }
}

/**
 * Per rule text, the strictest behaviour the live destination file already carries.
 *
 * Only that file is consulted, on purpose: the check exists so a re-run neither rewrites a file for no
 * reason nor reports a rule as new when the user already has it. Reading the global config for it would
 * put whatever is on the machine in the middle of the decision.
 */
function strictnessOnDisk(
	cwd: string,
	into: PermissionRuleDestination,
): Map<string, number> {
	const out = new Map<string, number>()
	const file = getProjectPermissionsPath(cwd, into === "local")
	if (!existsSync(file)) return out
	const read = readRuleLists(file)
	if (!("lists" in read)) return out
	for (const behavior of BEHAVIORS) {
		for (const rawEntry of read.lists[behavior] ?? []) {
			const parsed = parseRule(rawEntry)
			if (!parsed) continue
			const level = STRICTNESS[behavior]
			if ((out.get(parsed.text) ?? -1) > level) continue
			out.set(parsed.text, level)
		}
	}
	return out
}

/** How many rows a journal's ledger half carries, for the notice that says they were left alone. */
function ledgerHalfCounts(snapshot: unknown): { grants: number; forbids: number } | undefined {
	if (!snapshot || typeof snapshot !== "object") return undefined
	const half = snapshot as { grants?: unknown; forbids?: unknown }
	if (!Array.isArray(half.grants) || !Array.isArray(half.forbids)) return undefined
	return { grants: half.grants.length, forbids: half.forbids.length }
}

/**
 * Read every orphan directory and sort its contents into what may be taken now and what must wait.
 *
 * Reads only: creates nothing, writes nothing, and touches the live project's files solely for the
 * idempotence check in `strictnessOnDisk`.
 */
export function planAdoption(opts: AdoptionOptions): AdoptionPlan {
	const cwd = opts.cwd
	const space: PathSpace = { home: opts.home ?? homedir(), project: opts.project ?? cwd }
	const projectId = getProjectId(cwd)
	const plan: AdoptionPlan = { cwd, projectId, orphans: [], apply: [], pending: [], skipped: [] }

	// Rule text -> the strictest tightening candidate seen for it. Flattened into `plan.apply` at the
	// end, so deduping one entry never renumbers another.
	const tightening = new Map<string, RuleCandidate>()
	/** Everything widening already on its way to `pending`, keyed so one row is never offered twice. */
	const widening = new Map<string, Candidate>()
	const diskCache = new Map<PermissionRuleDestination, Map<string, number>>()
	const onDisk = (into: PermissionRuleDestination) => {
		let held = diskCache.get(into)
		if (!held) {
			held = strictnessOnDisk(cwd, into)
			diskCache.set(into, held)
		}
		return held
	}

	for (const orphan of listProjectStateDirs(cwd, projectId)) {
		plan.orphans.push(orphan.id)

		for (const source of RULE_SOURCES) {
			const origin: OrphanOrigin = { id: orphan.id, file: source.file }
			const file = join(orphan.path, source.file)
			if (!existsSync(file)) continue
			const read = readRuleLists(file)
			if ("error" in read) {
				plan.skipped.push({ origin, what: source.file, reason: read.error })
				continue
			}

			for (const behavior of BEHAVIORS) {
				for (const rawEntry of read.lists[behavior] ?? []) {
					const rule = parseRule(rawEntry)
					if (!rule) {
						plan.skipped.push({
							origin,
							what: String(rawEntry),
							reason: "not a usable rule string",
						})
						continue
					}

					if (behavior === "allow") {
						// Widening — and a broad Bash allow is not even offered: it hands the shell to the
						// model past the classifier, and entering auto mode strips it again, so offering it
						// would be offering something that cannot be honoured.
						if (isDangerousBashPermission(rule.tool, rule.specifier)) {
							plan.skipped.push({
								origin,
								what: rule.text,
								reason:
									"a Bash allow this broad bypasses the classifier and is stripped on auto entry, so it is not offered",
							})
							continue
						}
						const key = `rule:${rule.text}`
						if (widening.has(key)) continue
						widening.set(key, {
							kind: "rule",
							rule: rule.text,
							behavior,
							tool: rule.tool,
							specifier: rule.specifier,
							origin,
							into: source.into,
						})
						continue
					}

					// Tightening: one entry per rule text — the strictest one seen.
					const held = tightening.get(rule.text)
					if (held && STRICTNESS[held.behavior] >= STRICTNESS[behavior]) continue
					tightening.set(rule.text, {
						kind: "rule",
						rule: rule.text,
						behavior,
						tool: rule.tool,
						specifier: rule.specifier,
						origin,
						into: source.into,
					})
				}
			}
		}

		if (!orphan.grants) continue
		const origin: OrphanOrigin = { id: orphan.id, file: "grants.json" }
		const journal = readGrantsFile(join(orphan.path, "grants.json"))
		if (!journal.ok) {
			plan.skipped.push({ origin, what: "grants.json", reason: journal.error })
			continue
		}
		// `readGrantsFile` vetoed the rows this file's own revocations took away before handing it over,
		// so a row revoked in that session is not here and cannot be offered from here.
		const rows = pruneRows(journal.file.grants)
		for (const dead of rows.dropped) {
			plan.skipped.push({
				origin,
				what: String(dead.value),
				reason: "a value that can never match a target",
			})
		}
		for (const row of rows.kept) {
			const key = `grant:${rowIdentity(row)}`
			if (widening.has(key)) continue
			widening.set(key, {
				kind: "grant",
				category: row.category,
				value: row.value,
				target: canonicalPath(row.value, space),
				scope: row.kind,
				durable: row.durable === true,
				origin,
			})
		}
		// The ledger half is one session's derived state. Unioning it in would move another session's
		// extracted grants into this project's authority — the laundering `selectDurableGrants()`
		// refuses to do with imported rows — so it is counted and left where it is.
		const half = ledgerHalfCounts(journal.file.ledger)
		if (half && (half.grants || half.forbids)) {
			plan.skipped.push({
				origin,
				what: "grants.json (ledger half)",
				reason: `${half.grants} ledger grants and ${half.forbids} forbids belong to that session's transcript — /grants import takes the whole file if you meant to`,
			})
		}
	}

	for (const candidate of tightening.values()) {
		const alreadyThere = onDisk(candidate.into).get(candidate.rule)
		if (alreadyThere !== undefined && alreadyThere >= STRICTNESS[candidate.behavior]) {
			plan.skipped.push({
				origin: candidate.origin,
				what: candidate.rule,
				reason: `this project already has it as ${candidate.behavior} (or stricter)`,
			})
			continue
		}
		plan.apply.push(candidate)
	}
	plan.pending = [...widening.values()]
	return plan
}

/**
 * Plan, then take the tightening half. Nothing else is written: every widening item comes back in
 * `pending` with nothing changed on its behalf, and an empty plan writes nothing at all — not even an
 * empty rules document, which would be a file the user never asked for and a diff that means nothing.
 */
export function adoptOrphans(opts: AdoptionOptions): AdoptionOutcome {
	const plan = planAdoption(opts)
	const outcome: AdoptionOutcome = { apply: [], pending: plan.pending, plan, failed: [] }
	for (const item of plan.apply) {
		const ok = addPermissionRule({
			rule: item.rule,
			behavior: item.behavior,
			destination: item.into,
			cwd: opts.cwd,
		})
		if (ok) outcome.apply.push(item)
		else outcome.failed.push({
			rule: item.rule,
			into: item.into,
			error: `could not write the ${item.into} rules file`,
		})
	}
	return outcome
}

/**
 * Does the live store already carry this exact row?
 *
 * Compared in the canonical path space, because a session's rows arrive in the spelling `displayPath`
 * chose (`./x`, `~/x`, absolute) and an orphan's arrive in whatever spelling that checkout had. Asking
 * "is it already there" in one space is the only way to answer it honestly — and the answer is worth
 * having, because "nothing to do" and "refused" are different reports to a human.
 */
function holdsRow(
	store: GrantStore,
	category: string,
	target: string,
	kind: "entity" | "scope",
	space: PathSpace,
): boolean {
	const want = target.toLowerCase()
	return store.grants.some(
		(row) =>
			row.category === category &&
			row.kind === kind &&
			canonicalPath(row.value, space).toLowerCase() === want,
	)
}

/**
 * Has this target been taken back in this store?
 *
 * One screen, deliberately stronger than the store's own exact-key rule (`revocationVetoes`). Three
 * differences, each on the decline side, so the worst this can do is cost a prompt:
 *  - it compares canonical paths, not raw strings. Without it the exact failure this feature is about
 *    survives: the orphan row says `./src/x`, the user revoked `/moved/project/src/x`, and an adoption
 *    that resolves those two to one file would walk the row straight back in;
 *  - it ignores the clock. A revocation with no timestamp (0) would otherwise be outranked by any row
 *    that remembers when it was earned, which is precisely how a revoked grant comes back;
 *  - it does not distinguish a local revocation from an imported one. That distinction exists to stop a
 *    stale journal blocking legitimate work forever — but an adoption is not legitimate work, it is a
 *    copy of an old file, and declining it blocks nothing: answering the prompt at the gate still grants
 *    the target, with the fresh timestamp a re-grant is supposed to carry.
 *
 * Same `kind` is required, so revoking a folder never declines an entity row — the narrowness
 * `revocationVetoes` keeps on purpose. And nothing here ever deletes a row: an adoption can only decline
 * to add, never remove authority somebody else is relying on.
 */
function revokedInStore(
	store: GrantStore,
	target: string,
	category: string,
	kind: "entity" | "scope",
	space: PathSpace,
): boolean {
	const want = target.toLowerCase()
	return (store.revoked ?? []).some(
		(revocation) =>
			revocation.category === category &&
			revocation.kind === kind &&
			canonicalPath(revocation.value, space).toLowerCase() === want,
	)
}

/**
 * Hand confirmed items to the store and the rule files after a human picked them.
 *
 * The only place in this module that widens anything, and every path through it is the path an
 * ordinary approval already takes: `addGrant()` for rows — so the compound-category split, the store's
 * caps and its dedup apply to an adopted row exactly as to a prompt-earned one — and
 * `addPermissionRule()` for rules. A row whose target this session has revoked is declined, not added
 * (`revokedInStore`), and values are stored canonicalised, so a row written before the move lands on
 * the path that exists now.
 *
 * Grant rows land in the caller's live store; pass `journal` to also mirror the store into the
 * workspace journal (merged, never replaced — it may hold rows another session wrote).
 */
export function confirmAdoption(opts: {
	cwd: string
	items: readonly Candidate[]
	store: GrantStore
	project?: string
	home?: string
	journal?: string
	/** Default true: adopting is restoring authority meant to outlive the session. Pass false to try
	 *  an adopted row for this session only. */
	durable?: boolean
}): ConfirmationReport {
	const report: ConfirmationReport = { rules: [], grants: [], refused: [] }
	const space: PathSpace = { home: opts.home ?? homedir(), project: opts.project ?? opts.cwd }
	let touchedRows = 0

	for (const item of opts.items) {
		if (item.kind === "rule") {
			// Guarded here as well as at plan time: a caller can hand back a candidate it did not get
			// from `planAdoption`, and a classifier-bypassing allow must never be written.
			if (isDangerousBashPermission(item.tool, item.specifier)) {
				report.refused.push({
					what: item.rule,
					reason: "a Bash allow this broad bypasses the classifier and is not confirmable",
				})
				continue
			}
			const ok = addPermissionRule({
				rule: item.rule,
				behavior: "allow",
				destination: item.into,
				cwd: opts.cwd,
			})
			if (ok) report.rules.push(item.rule)
			else report.refused.push({ what: item.rule, reason: `could not write the ${item.into} rules file` })
			continue
		}

		const target = canonicalPath(item.value, space)
		if (holdsRow(opts.store, item.category, target, item.scope, space)) {
			// Nothing to do — reported as such rather than as a confirmation, so a UI cannot count it.
			report.refused.push({
				what: `${item.category} ${item.value}`,
				reason: "this session already holds a row for that target",
			})
			continue
		}
		if (revokedInStore(opts.store, target, item.category, item.scope, space)) {
			report.refused.push({
				what: `${item.category} ${item.value}`,
				reason: `revoked in this session as ${target} — an adoption is not a re-grant; answer the prompt to grant it again`,
			})
			continue
		}
		const before = new Set(opts.store.grants.map((row) => rowIdentity(row)))
		addGrant(opts.store, item.category, target, item.scope, opts.durable ?? true)
		const added = opts.store.grants.filter((row) => !before.has(rowIdentity(row)))
		if (!added.length) {
			// The store already held every segment of this row, or its cap refused it. Reported, never
			// silently counted as a confirmation.
			report.refused.push({
				what: `${item.category} ${item.value}`,
				reason: "the session already holds this row",
			})
			continue
		}
		for (const row of added) {
			report.grants.push({ category: row.category, value: row.value, kind: row.kind })
			touchedRows++
		}
	}

	if (touchedRows > 0 && opts.journal) {
		const merged = mergeIntoGrantsFile(opts.journal, undefined, opts.store, { sourceCwd: opts.cwd })
		report.journal = {
			path: opts.journal,
			ok: merged.ok,
			added: merged.added,
			...(merged.error ? { error: merged.error } : {}),
		}
	}
	return report
}
