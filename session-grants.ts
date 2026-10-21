/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Prompt-once session grants (docs/CLASSIFIER-SPEC.md §3.2).
 * A grant is {category, entity} or {category, scope-prefix}; grants never widen
 * automatically. Pure in-memory store with (de)serialisation for session persist.
 *
 * This module also owns the vocabulary of REVOCATIONS ("tombstones") — the reason
 * `grants-file.ts` can merge at all. See `GrantRevocation` below.
 */

import type { Entity } from "./risk-policy.ts"
import { canonicalPath, entityMatchesTarget, expandHome } from "./grant-verify.ts"
import { coversByGrammar } from "./target-grammar.ts"

export type SessionGrant = {
	category: string
	/** Exact entity value, or a prefix ending in "/" for scope grants. */
	value: string
	kind: "entity" | "scope"
	at: number
	/** Row came from a grants file rather than a decision made in this session. */
	origin?: "imported"
	/**
	 * The user answered a prompt with "always", so this row is meant to outlive
	 * the session: `selectDurableGrants()` hands it to the journal
	 * (`grants-file.mergeIntoGrantsFile`) and it is re-imported at the next
	 * session start. Absent/false means "this session only".
	 *
	 * Orthogonal to `origin`, and the two must not be collapsed: `origin` says
	 * where a row came from (imported rows are background authority that anything
	 * said in this session outranks — see `auth-ledger.importLedger`), `durable`
	 * says whether it belongs in the journal. An imported row can be durable (it
	 * was an "always" somewhere else) and a durable row is not background
	 * authority just because it round-tripped through a file. Durability never
	 * changes precedence and never widens what a grant matches.
	 */
	durable?: boolean
}

/**
 * A revocation kept as data instead of as an absence.
 *
 * An absence cannot be merged. A journal that unions two sessions' rows has no way
 * to tell "nobody here ever granted /x" from "/x was granted here and then taken
 * back", so a union without revocations has only two answers and both are wrong:
 * either rows can never leave the journal (authority nobody can revoke) or a session
 * that no longer holds a row deletes it for everybody (a revocation that travels by
 * accident, dropping additions nobody meant to drop). Recording the revocation as a
 * row of its own is what makes keeping-and-vetoing expressible in one write.
 *
 * Matching is exact on {category, value, kind} — the narrowest statement that can
 * be made about a row. A revocation is never widened: no wildcards, no prefix, no
 * path space, no `canonicalPath`. Revoking `/x/y` must not also erase a folder grant
 * over `/x`; silently erasing authority the user never revoked is the same failure
 * as resurrecting authority they did revoke, and only a prompt may widen anything.
 */
export type GrantRevocation = {
	category: string
	value: string
	kind: "entity" | "scope"
	/** Wall-clock ms of the revocation. The only clock two sessions share — `seq`
	 *  orders messages inside ONE transcript and means nothing across sessions. */
	at: number
	/** Who said it. Absent = said IN this session, by the user, at `/grants revoke`;
	 *  `"imported"` = read out of a file. The two are not equally strong, and the
	 *  difference is only expressible as data: a revocation made here needs no clock
	 *  and stops this session's own derivations from re-earning the key
	 *  (`auth-ledger.applyEvent`), while a revocation that arrived from a journal is
	 *  background authority — it vetoes the rows that travel with it, but it must not
	 *  block legitimate work here forever, or one stale file would leave `/grants clear`
	 *  as the only remedy. Same asymmetry an imported forbid already has.
	 *  Optional, so a journal written before this field existed keeps reading. */
	origin?: "imported"
	/** Why, for the human reading the journal: the user's words, or the command that
	 *  revoked it. Diagnostic only — matching never looks at it. */
	quote?: string
}

/** Revocations are bounded like everything else here: the ones a journal has not
 *  needed for the longest are the cheapest to forget (forgetting one costs at most a
 *  prompt for a re-grant, never a permission). */
export const MAX_REVOCATIONS = 100

/** The shape a revocation can be pointed at. `at` is optional because rows written
 *  before revocations existed carry no wall clock, and an undated row is the oldest
 *  thing in the file — the fail-closed reading of a row we cannot date. */
export type RevocableRow = { category: string; value: string; kind: string; at?: number }

export type GrantStore = {
	grants: SessionGrant[]
	/** Revocations recorded here, plus any the journal handed us. A row one of them
	 *  vetoes never comes back — but a revocation never vetoes a row this session
	 *  earned on its own either, because a prompt outranks a file: see `revokeRows`. */
	revoked?: GrantRevocation[]
}

/** Exact identity of a row: the three fields a revocation is aimed at. NUL-joined
 *  because a category or a path may contain any other character. */
export function rowIdentity(row: { category: string; value: string; kind: string }): string {
	return `${row.category}\u0000${row.value}\u0000${row.kind}`
}

/**
 * Does this revocation take that row away?
 *
 * Exact key first, then `at`: a revocation older than the row it names is history,
 * not a veto — the user revoked and later answered "always" again, and a revocation
 * that could never be lifted except by editing files would be a ban, not a
 * revocation. Equal timestamps go to the revocation: when the clock cannot order the
 * two, the tie breaks toward the decision that REMOVED authority, and re-granting
 * still works because a fresh approval carries a fresh `at`.
 */
export function revocationVetoes(row: RevocableRow, revocation: GrantRevocation): boolean {
	if (rowIdentity(row) !== rowIdentity(revocation)) return false
	return (typeof row.at === "number" ? row.at : 0) <= revocation.at
}

/** Split rows into what survives and what a revocation still vetoes. */
export function partitionRevoked<T extends RevocableRow>(
	rows: readonly T[] | undefined | null,
	revocations: readonly GrantRevocation[] | undefined | null,
): { kept: T[]; vetoed: T[] } {
	const folded = foldRevocations(undefined, revocations)
	const kept: T[] = []
	const vetoed: T[] = []
	const byKey = new Map<string, GrantRevocation>()
	for (const revocation of folded) byKey.set(rowIdentity(revocation), revocation)
	for (const row of Array.isArray(rows) ? rows : []) {
		const hit = byKey.get(rowIdentity(row))
		if (hit && revocationVetoes(row, hit)) vetoed.push(row)
		else kept.push(row)
	}
	return { kept, vetoed }
}

/**
 * Read one revocation back from a journal or a session blob, repairing what it can
 * the way `asGrantRow` does. A row with a target but no timestamp is kept and read
 * as "revoked before anything in this file" — nothing can then be proven to be after
 * it, which is the fail-closed direction. A row that cannot name its category or its
 * target is inert and goes.
 *
 * Values are NOT screened by `isUnmatchableValue`: a revocation is only ever compared
 * for equality, so an odd value can never widen anything — it simply never matches.
 */
export function asRevocation(raw: unknown): GrantRevocation | undefined {
	const r = raw as Partial<GrantRevocation> | null | undefined
	if (!r || typeof r !== "object") return undefined
	if (typeof r.category !== "string" || !r.category) return undefined
	if (typeof r.value !== "string" || !r.value) return undefined
	const out: GrantRevocation = {
		category: r.category,
		value: r.value,
		kind: r.kind === "scope" ? "scope" : "entity",
		at: typeof r.at === "number" && Number.isFinite(r.at) ? r.at : 0,
	}
	if (r.origin === "imported") out.origin = "imported"
	if (typeof r.quote === "string" && r.quote.trim()) out.quote = r.quote.slice(0, 300)
	return out
}

/** Whose word a revocation is: a statement made in this session outranks the same
 *  statement read out of a file, whatever timestamp the file puts on it. Without this
 *  ordering an import could DEMOTE a revocation the user made here — the file claims a
 *  later `at`, wins the fold, arrives tagged `imported`, and the local guard in
 *  `applyEvent` would then stop applying, so the revoked grant walks straight back in on
 *  the next re-extraction. A file may replace a file; it may not silence a person. */
function provenance(row: GrantRevocation): number {
	return row.origin === "imported" ? 0 : 1
}

/**
 * Fold two sightings of the revocation list into one. Per exact key a local revocation
 * beats an imported one, and within one provenance the newest wins (a revocation IS a
 * timestamp; the later one describes today). The result stays bounded, dropping the
 * oldest first.
 */
export function foldRevocations(
	held: readonly GrantRevocation[] | undefined | null,
	incoming: readonly GrantRevocation[] | undefined | null,
): GrantRevocation[] {
	const byKey = new Map<string, GrantRevocation>()
	for (const list of [held, incoming]) {
		for (const raw of Array.isArray(list) ? list : []) {
			const clean = asRevocation(raw)
			if (!clean) continue
			const key = rowIdentity(clean)
			const before = byKey.get(key)
			if (!before) {
				byKey.set(key, clean)
				continue
			}
			const mine = provenance(clean)
			const ours = provenance(before)
			if (mine > ours || (mine === ours && clean.at >= before.at)) byKey.set(key, clean)
		}
	}
	const rows = [...byKey.values()]
	if (rows.length <= MAX_REVOCATIONS) return rows
	return rows.sort((a, b) => b.at - a.at).slice(0, MAX_REVOCATIONS)
}

/**
 * The keys this session revoked for itself, as exact `{category,value,kind}` identities.
 *
 * This is the question `applyEvent` has to ask before it lets any derivation re-earn a
 * row: "did somebody HERE take this back?" Imported revocations are excluded on purpose —
 * they are background authority, and letting one veto a sentence the user says in this
 * session would give a stale journal the power to block legitimate work permanently.
 * Keys rather than rows, because the asker holds an event and wants one Set lookup.
 */
export function localRevocationKeys(
	revocations: readonly GrantRevocation[] | undefined | null,
): Set<string> {
	const keys = new Set<string>()
	for (const raw of Array.isArray(revocations) ? revocations : []) {
		const clean = asRevocation(raw)
		if (!clean || clean.origin === "imported") continue
		keys.add(rowIdentity(clean))
	}
	return keys
}

/**
 * Read a revocation list in from a file, tagged as background authority.
 *
 * A file cannot assert this about itself, so the reader asserts it: everything arriving
 * from disk is a file, including one written by a session that made the revocation
 * locally. Folding here as well means callers get one bounded, deduped list back.
 */
export function asBackgroundRevocations(
	revocations: readonly GrantRevocation[] | undefined | null,
): GrantRevocation[] {
	const rows: GrantRevocation[] = []
	for (const raw of Array.isArray(revocations) ? revocations : []) {
		const clean = asRevocation(raw)
		if (!clean) continue
		rows.push({ ...clean, origin: "imported" })
	}
	return foldRevocations(undefined, rows)
}

/**
 * Take back every stored row the predicate matches and write down that we did.
 *
 * The predicate belongs to the caller because *which* rows the user meant is a path
 * question (`~` vs absolute vs project-relative) and this module must not own a
 * second answer to it: `/grants revoke` normalizes both sides its own way and hands
 * us the rows it settled on. Each removed row yields its own revocation, so a revoke
 * of one file can never widen into the folder grant sitting next to it.
 *
 * Returns what it recorded — the caller reports that count, and a revoke that found
 * nothing returns [] and records nothing (an empty revoke must not become a ban).
 */
export function revokeRows(
	store: GrantStore,
	matches: (row: SessionGrant) => boolean,
	opts: { quote?: string; at?: number } = {},
): GrantRevocation[] {
	const at = typeof opts.at === "number" ? opts.at : Date.now()
	const taken: GrantRevocation[] = []
	for (let i = store.grants.length - 1; i >= 0; i--) {
		const row = store.grants[i]!
		if (!matches(row)) continue
		store.grants.splice(i, 1)
		const revocation: GrantRevocation = { category: row.category, value: row.value, kind: row.kind, at }
		if (opts.quote) revocation.quote = opts.quote
		taken.push(revocation)
	}
	if (taken.length) store.revoked = foldRevocations(store.revoked, taken)
	return taken
}

/** Drop rows an earlier revocation still vetoes (a row that came back through an
 *  import, or one re-earned with an `at` that cannot beat it). Returns how many went. */
export function dropRevokedRows(store: GrantStore): number {
	const split = partitionRevoked(store.grants, store.revoked)
	store.grants = split.kept
	return split.vetoed.length
}

/**
 * One row read back from an untrusted source: a resumed session blob or a journal
 * file on disk. Repairs what it can instead of dropping it — losing an "always" to
 * a missing timestamp or a hand-edited `kind` costs the user a prompt for a
 * question they already answered — while a row that cannot name a category or a
 * target is inert and is reported by the caller as dropped.
 *
 * `at` defaults to 0 ("oldest"), so a row with no timestamp never outranks one
 * that remembers when it was earned.
 */
export function asGrantRow(row: unknown): SessionGrant | undefined {
	const g = row as Partial<SessionGrant> | null | undefined
	if (!g || typeof g !== "object") return undefined
	if (typeof g.category !== "string" || !g.category) return undefined
	if (typeof g.value !== "string" || !g.value) return undefined
	const out: SessionGrant = {
		category: g.category,
		value: g.value,
		kind: g.kind === "scope" ? "scope" : "entity",
		at: typeof g.at === "number" && Number.isFinite(g.at) ? g.at : 0,
	}
	if (g.origin === "imported") out.origin = "imported"
	if (g.durable === true) out.durable = true
	return out
}

export function createGrantStore(): GrantStore {
	return { grants: [], revoked: [] }
}

/**
 * Split a compound category into the effects it names.
 *
 * One approval of `cp src dst && chmod 644 dst` was shown to the user as ONE decision covering
 * both effects, so both must be remembered - and nothing else. Collapsing to the first segment
 * (the old behaviour) made the compound match itself by accident while a later `chmod` alone found
 * no grant at all and prompted again: the approval did not stick for the effect the user actually
 * agreed to.
 */
function categoryOf(category: string): string[] {
	return [...new Set(category.split("+").map((s) => s.trim()).filter(Boolean))]
}

/**
 * Record an approval. `durable` is optional and defaults to false, so a caller
 * that does not care about surviving a restart passes four arguments exactly as
 * before. A re-approval of a key that is already stored keeps the existing row
 * (and therefore its existing `durable` flag): re-approving the same target must
 * not silently downgrade an "always" the user already gave.
 */
export function addGrant(
	store: GrantStore,
	category: string,
	value: string,
	kind: "entity" | "scope",
	durable = false,
): void {
	if (!value) return
	for (const seg of categoryOf(category)) {
		const held = store.grants.find((g) => g.category === seg && g.value === value && g.kind === kind)
		if (held) {
			if (durable) held.durable = true
			continue
		}
		const row: SessionGrant = { category: seg, value, kind, at: Date.now() }
		if (durable) row.durable = true
		store.grants.push(row)
	}
}

/**
 * Does one stored row cover one pending target?
 *
 * The grammar comes first (docs/CLASSIFIER-SPEC.md §3), and only for a category that has one: `vcs_remote origin/*` is the
 * value the gate itself writes when the user answers "Allow for session (scope)", and to a run of
 * `/`-components it is a component that must equal `*`, so the button covered nothing. A category with
 * no grammar — or a pair the grammar cannot read — is judged by exactly the rules that judged it before,
 * which is why this is a widening of publish targets only and never a change to path matching.
 */
function rowCoversTarget(seg: string, row: SessionGrant, target: string, home?: string, project?: string): boolean {
	const byGrammar = coversByGrammar(seg, row.value, target)
	if (byGrammar !== undefined) return byGrammar
	if (row.kind === "scope") return scopeCovers(seg, row.value, target, home, project)
	return (
		entityMatchesTarget(target, row.value, home, project) ||
		canonicalPath(row.value, { home, project }) === canonicalPath(target, { home, project })
	)
}

function scopeCovers(category: string, scopeValue: string, entity: string, home?: string, project?: string): boolean {
	// A scope of a grammared category is read by that grammar: its own wildcards (`origin/*`, `myrepo/app`)
	// mean something a prefix of characters cannot express.
	const byGrammar = coversByGrammar(category, scopeValue, entity)
	if (byGrammar !== undefined) return byGrammar
	// Canonicalise both sides into one path space. `~` ↔ home was handled here first; the project-
	// relative half (`./x`, emitted by displayPath for every in-project target) needs `project`, or a
	// folder grant can never cover a file inside the project. See `canonicalPath`.
	const space = { home, project }
	const s = canonicalPath(scopeValue, space).toLowerCase()
	const e = canonicalPath(entity, space).toLowerCase()
	if (s.endsWith("/")) return e.startsWith(s) || (e + "/") === s
	return entityMatchesTarget(entity, scopeValue, home, project)
}

/**
 * EVERY effect of the pending action must have its own grant, over every target.
 *
 * Checking only the first segment let a stored `write_outside` stand in for `write_outside+perm_change`,
 * i.e. a content permission silently authorising a privilege change. Requiring all segments is
 * strictly narrower than before, so it can only ever cost an extra prompt - never buy a false allow.
 */
export function grantsCover(
	store: GrantStore,
	category: string,
	entities: Entity[],
	home?: string,
	project?: string,
): { covered: boolean; by: string[] } {
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const segments = categoryOf(category)
	if (targets.length === 0 || segments.length === 0) return { covered: false, by: [] }
	const by: string[] = []
	for (const seg of segments) {
		const relevant = store.grants.filter((g) => g.category === seg)
		if (relevant.length === 0) return { covered: false, by: [] }
		for (const t of targets) {
			const hit = relevant.find((g) => rowCoversTarget(seg, g, t, home, project))
			if (!hit) return { covered: false, by: [] }
			by.push(hit.value)
		}
	}
	return { covered: true, by }
}

/**
 * Why this store does (or does not) cover this action, one line per row the segment holds.
 *
 * `grantsCover` answers a boolean and stops at the first miss, which is right for a gate and useless for
 * the question a user asks after being refused: "I said yes to that, why did it ask again?" This walks the
 * same rows with the same predicate (`rowCoversTarget`) and reports each verdict instead of the first one,
 * so a near miss is visible instead of inferred. Pure — it reads the store and returns strings, and writes
 * nothing anywhere — this function only renders the lines, and the `/grants explain` command in index.ts prints them.
 *
 * Lines, in order:
 *  - `row <category> "<value>" (<kind>): covers <target>[, <target>…]` for a row that covers at least one
 *    pending target;
 *  - `rejected: <category> "<value>" (<kind>) — covers none of: <target>…` for a row that covers none;
 *  - `segment <category> has no rows` for an effect of a compound nothing in this store speaks for.
 */
export function explainGrantsCover(
	store: GrantStore,
	category: string,
	entities: Entity[],
	home?: string,
	project?: string,
): string[] {
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const segments = categoryOf(category)
	if (segments.length === 0) return [`no category to explain`]
	if (targets.length === 0) return [`nothing to match: the action names no target`]
	const lines: string[] = []
	for (const seg of segments) {
		const rows = store.grants.filter((g) => g.category === seg)
		if (rows.length === 0) {
			lines.push(`segment ${seg} has no rows`)
			continue
		}
		for (const row of rows) {
			const covers: string[] = []
			const misses: string[] = []
			for (const t of targets) (rowCoversTarget(seg, row, t, home, project) ? covers : misses).push(t)
			if (covers.length > 0) {
				lines.push(`row ${seg} "${row.value}" (${row.kind}): covers ${covers.join(", ")}`)
			} else {
				lines.push(`rejected: ${seg} "${row.value}" (${row.kind}) — covers none of: ${misses.join(", ")}`)
			}
		}
	}
	return lines
}

/** Session grants are bounded too: an import must not push out live grants. */
const MAX_SESSION_GRANTS = 200

/**
 * Import session grants from a grants file.
 *
 * Revocations are honoured AT THE BOUNDARY, not left to the caller to remember:
 *  - revocations arriving with the file veto the rows arriving with it (compared by
 *    `at`, so a row that was re-granted after the revocation still comes through);
 *  - revocations made IN THIS SESSION veto matching incoming rows on the key alone,
 *    whatever timestamp the file claims. A file may only be as strong as its own
 *    clock; a revocation you made here needs no clock. `importSessionGrants` stamps
 *    every incoming row with *our* clock, so without this rule an import could walk
 *    a grant back in that somebody in this session already revoked.
 *
 * `replace` swaps rows, never revocations: an import may replace what is allowed
 * without ever undoing what was taken back.
 *
 * Deduped on {category, value, kind} and appended, so an import never reorders
 * or displaces what this session already earned — and never evicts a live grant
 * either: rows past MAX_SESSION_GRANTS are reported as dropped, keeping the
 * existing eviction order. Values that can never match a target are skipped by
 * the caller (`pruneRows`), not here — the store stays dumb and the policy
 * visible at the command.
 *
 * A durable row stays durable through the import; `origin: "imported"` is set for
 * every row and means "background authority", which durability does not change.
 */
export function importSessionGrants(
	store: GrantStore,
	rows: SessionGrant[] | undefined | null,
	opts: { replace?: boolean; revoked?: readonly GrantRevocation[] } = {},
): { added: number; dropped: number } {
	if (opts.replace) store.grants = []
	// Two lists, because they are not equally strong: `local` is what THIS session
	// revoked (a statement made here, needs no clock), the incoming list is what the
	// file says (trusted only as far as its own timestamps reach).
	const local = foldRevocations(store.revoked, undefined)
	const background = asBackgroundRevocations(opts.revoked)
	store.revoked = foldRevocations(local, background)
	const localKeys = new Set(local.map((r) => rowIdentity(r)))
	const backgroundByKey = new Map<string, GrantRevocation>()
	for (const revocation of background) backgroundByKey.set(rowIdentity(revocation), revocation)

	const seen = new Set(store.grants.map((g) => rowIdentity(g)))
	let added = 0
	let dropped = 0
	for (const row of Array.isArray(rows) ? rows : []) {
		if (!row || typeof row.category !== "string" || typeof row.value !== "string") {
			dropped++
			continue
		}
		const kind = row.kind === "scope" ? "scope" : "entity"
		const key = rowIdentity({ category: row.category, value: row.value, kind })
		if (seen.has(key)) continue
		// A revocation is honoured here, at the boundary, rather than hoped for
		// downstream. Against the file's own list the row keeps its source timestamp —
		// that comparison is the only way a re-grant recorded after the revocation can
		// still come through. A local revocation needs no such comparison.
		const revoker = backgroundByKey.get(key)
		if (
			localKeys.has(key) ||
			(revoker !== undefined &&
				revocationVetoes({ category: row.category, value: row.value, kind, at: row.at }, revoker))
		) {
			// Counted as dropped: it did not enter the store, which is what the caller
			// reports. Nothing here disappears silently.
			dropped++
			continue
		}
		if (store.grants.length >= MAX_SESSION_GRANTS) {
			dropped++
			continue
		}
		seen.add(key)
		const next: SessionGrant = {
			category: row.category,
			value: row.value,
			kind,
			// Stamped with NOW, not the source row's `at`: the merge order in the
			// journal compares recency within one path, and a foreign clock from an
			// unrelated project must not outrank what this project stored. The cost is
			// that an imported row can never out-argue a revocation made here, which is
			// exactly why the veto above does not trust the source timestamp either.
			at: Date.now(),
			origin: "imported",
		}
		// Durability travels with the row (it stays an "always"), `origin` still
		// says where it came from. The dedup key ignores both.
		if (row.durable === true) next.durable = true
		store.grants.push(next)
		added++
	}
	return { added, dropped }
}

/**
 * The session blob. With nothing to record it stays the bare array every older build
 * already reads; only a session that actually revoked something grows the object form,
 * so a revocation survives a restart instead of being forgotten at the next export.
 */
export function serializeGrants(store: GrantStore): string {
	if (!store.revoked?.length) return JSON.stringify(store.grants)
	return JSON.stringify({ grants: store.grants, revoked: store.revoked })
}

/**
 * Restore rows from a session blob INTO an existing store, passing the payload through.
 *
 * The rule, expressed as a function: a restore copies the row, it does not
 * re-decide it. `at`, `durable` and `origin` come from the stored row and nothing else.
 * Rebuilding the row instead — `addGrant(store, category, value, kind)`, which stamps
 * `at: Date.now()` and forgets `durable` — is a correctness bug even while it appears to
 * work: revocation ordering breaks ties by timestamp (`revocationVetoes`), so a restore
 * that invents `at` makes every revoked row look re-earned and stays safe only while the
 * restore happens to read the newest snapshot, which no longer holds the row. Keep the
 * real `at` and the veto still holds whichever snapshot gets picked, and the user's
 * "always" is still an "always" after a resume.
 *
 * Revocations are honoured on the way in, against the stored `at` — data compared with
 * data — so a blob whose writer left a vetoed row in place is refused on read, which is
 * what `deserializeLedger` already does for the ledger half.
 *
 * Accepts every shape the caller may hand it: the bare array older builds wrote, the
 * `{grants, revoked}` object, either already parsed or as JSON text, and `undefined`.
 * Reports what it refused rather than hiding it: `refused` counts rows a revocation
 * vetoed, `dropped` counts inert rows, duplicates and rows past the cap.
 */
export function restoreGrantRows(
	store: GrantStore,
	blob: unknown,
): { restored: number; refused: number; dropped: number } {
	let parsed: unknown = blob
	if (typeof blob === "string") {
		if (!blob.trim()) return { restored: 0, refused: 0, dropped: 0 }
		try {
			parsed = JSON.parse(blob)
		} catch {
			return { restored: 0, refused: 0, dropped: 0 }
		}
	}
	let rows: unknown[] = []
	if (Array.isArray(parsed)) rows = parsed
	else if (parsed && typeof parsed === "object") {
		const bag = parsed as { grants?: unknown; revoked?: unknown }
		// Revocations first: a row in this same blob is judged against them.
		if (Array.isArray(bag.revoked)) store.revoked = foldRevocations(store.revoked, bag.revoked)
		if (Array.isArray(bag.grants)) rows = bag.grants
	}

	const readable: SessionGrant[] = []
	let dropped = 0
	for (const raw of rows) {
		const row = asGrantRow(raw)
		if (!row) {
			dropped++
			continue
		}
		readable.push(row)
	}
	const split = partitionRevoked(readable, store.revoked)

	const keys = new Set(store.grants.map((g) => rowIdentity(g)))
	let restored = 0
	for (const row of split.kept) {
		const key = rowIdentity(row)
		if (keys.has(key) || store.grants.length >= MAX_SESSION_GRANTS) {
			dropped++
			continue
		}
		keys.add(key)
		store.grants.push(row)
		restored++
	}
	return { restored, refused: split.vetoed.length, dropped }
}

/**
 * Read a session blob into a fresh store. Rows are repaired where possible rather than
 * dropped (`asGrantRow`), so a `durable` answer survives a resume even when the stored
 * shape drifted; a row that cannot name its category or target is inert and goes.
 *
 * Both shapes are read: the bare array older builds wrote (no revocations to restore)
 * and the `{grants, revoked}` object. One door with `restoreGrantRows`, so provenance is
 * passed through and revocations are honoured on the read in both paths.
 */
export function deserializeGrants(json: string | undefined | null): GrantStore {
	if (!json) return createGrantStore()
	const store = createGrantStore()
	restoreGrantRows(store, json)
	return store
}

