/**
 * Grants portability: ONE file holding the whole
 * authorisation state — ledger grants, forbids, read-only posture, session
 * grants, and the revocations that take rows back — so it can move between
 * sessions. Pure fs, no pi dependency.
 *
 * Importing is deliberately NOT the same as declaring. Rules (`permissions.json`)
 * are user-authored and evaluate before the mode gate; imported rows are
 * background authority that anything said in the current session outranks. See
 * `importLedger()` in auth-ledger.ts for the precedence rule.
 *
 * The same file doubles as the durable journal behind a prompt answer
 * ("Allow always" → a `durable` session grant → `mergeIntoGrantsFile()`), which
 * is why it is a merge and not a dump: several sessions write one project
 * journal, and none of them may drop the others' rows.
 *
 * --------------------------------------------------------------- revocations
 * A merge that can only ADD cannot revoke, so revocation is stored as a ROW —
 * `{category, value, kind, at}` in `revoked`, mirrored inside the ledger snapshot —
 * and honoured wherever rows are read. That is what lets `mergeIntoGrantsFile()`
 * union the ledger half instead of replacing it: keeping a concurrent session's
 * addition is only safe once "taken back" is something the file can say. Ordering is
 * the wall clock (`at`), never `seq`: `seq` is an ordinal inside one transcript and
 * means nothing between two sessions. A revocation vetoes a row whose `at` is not
 * NEWER than it — equal timestamps go to the revocation, because when the clock
 * cannot order the two, the tie breaks toward the decision that removed authority.
 * A re-grant is therefore not a ban: answering "always" again stamps a fresh `at` and
 * outranks the tombstone, which is the point — prompts are the authority, files are
 * only the memory of them.
 *
 * --------------------------------------------------- version: 1, optional field
 * `revoked` was added WITHOUT bumping `v`, and that is a considered choice, not
 * an oversight. Two options existed:
 *  - an optional field on a `v: 1` file. Every build alive today still reads the
 *    journal: `readGrantsFile` looks at `v`, `grants` and `ledger`, and JSON hands it
 *    the extra key to ignore. Portability keeps working, in both directions.
 *  - bump `GRANTS_FILE_V`. Every current reader then REFUSES the file outright —
 *    auto-export logs "grant journal NOT updated" on every approval and `/grants
 *    import` fails, so an older build silently stops persisting authority at all.
 *    That is a bigger safety loss than the one it protects: a session that saves
 *    nothing loses every answer its user gave.
 * What the optional field does NOT fix, stated plainly: a build that predates
 * revocations can rewrite the journal from data it never looked at, and erase the
 * `revoked` array along with the unknown key. That is unavoidable for ANY
 * revocation-as-data scheme — code that cannot see a revocation cannot preserve one —
 * and it is bounded: it needs a project whose user revoked durably AND an older build
 * still running in it, and one upgrade ends it. Losing revocations is the same harm
 * as union-without-tombstones, so the window is worth closing after an upgrade, not
 * paid for by disabling the journal for everyone else.
 *
 * Two properties callers must know before wiring this up:
 * - A merge adds rows and honours revocations; it does not DELETE on its own. So
 *   `/grants revoke` must record a tombstone (see `revokeRows` / `revokeLedgerGrants`)
 *   rather than only splicing its own store: dropping a row without recording it just
 *   means the next session's union brings it back.
 * - The `ledger` half is now a UNION, not one session's snapshot: rows another session
 *   earned stay, rows either session revoked leave. Authority that must survive a
 *   restart still belongs in `grants[]` with `durable: true`, because the ledger half
 *   is derived state re-extracted from each session's own transcript.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"

import { MAX_FORBIDS, MAX_GRANTS } from "./auth-ledger.ts"
import {
	asGrantRow,
	foldRevocations,
	partitionRevoked,
	rowIdentity,
	type GrantRevocation,
	type GrantStore,
	type SessionGrant,
} from "./session-grants.ts"

export const GRANTS_FILE_V = 1

export type GrantsFile = {
	v: number
	exportedAt: string
	sourceCwd: string
	/** SerializedLedger verbatim: grants, forbids, seen, readOnlyOn, readOnlyOffSeq,
	 *  and the same `revoked` list this file carries at the top level. */
	ledger: unknown
	grants: SessionGrant[]
	/** Revocations, exact-key. Mirrored inside `ledger.revoked` on purpose: the top-level
	 *  list is what a reader of the FILE applies, the one inside the snapshot is what a
	 *  session restoring the ledger alone applies. Both are written from one folded list,
	 *  so they cannot disagree about whether something was revoked. */
	revoked?: GrantRevocation[]
}

export type ReadGrantsResult =
	| { ok: true; file: GrantsFile; /** rows this file's own revocations took away */ vetoed: number }
	| { ok: false; error: string }

export type MergeGrantsResult = {
	ok: boolean
	/** Session-grant rows in the journal after the merge. */
	written: number
	/** Keys the merge introduced (0 once the journal already has them — idempotent). */
	added: number
	/** Rows not carried into the file: unmatchable values, rows too broken to match,
	 *  and rows pushed out by the store's own caps. */
	dropped: number
	/** Rows of ANY half that a revocation vetoed — reported, never silently absent. */
	vetoed: number
	/** Revocations the journal now holds. */
	revocations: number
	error?: string
}

/**
 * Values that can never match a real target: parser placeholders, unexpanded
 * substitutions, and shell fragments that were blamed as paths. They are inert
 * — but they occupy MAX_GRANTS slots and LRU-evict genuine grants, and exporting
 * them launders them into a file that gets imported forever.
 */
const UNMATCHABLE_MARKERS = [
	"__TRACKED_VAR__",
	"__CMDSUB_OUTPUT__",
	"$(",
	"${",
	"|",
	"===",
	"`",
	"\n",
]

export function isUnmatchableValue(value: unknown): boolean {
	const v = typeof value === "string" ? value.trim() : ""
	if (!v) return true
	// "*" is a real bare-verb/all grant, not junk.
	if (v === "*") return false
	for (const m of UNMATCHABLE_MARKERS) if (v.includes(m)) return true
	// A matchable target is always path-shaped (or "*" handled above). Anything
	// else — `select(.type!=null) | .type`, `their verb tables` — cannot match.
	return !/^[/~.]/.test(v)
}

export function pruneRows<T extends { value: string }>(
	rows: T[] | undefined | null,
): { kept: T[]; dropped: T[] } {
	const kept: T[] = []
	const dropped: T[] = []
	for (const row of Array.isArray(rows) ? rows : []) {
		if (isUnmatchableValue(row?.value)) dropped.push(row)
		else kept.push(row)
	}
	return { kept, dropped }
}

export function buildGrantsFile(opts: {
	ledger: unknown
	grants: SessionGrant[]
	sourceCwd: string
	/** Revocations this session recorded. Folded with any the ledger snapshot carries. */
	revoked?: readonly GrantRevocation[]
}): { file: GrantsFile; dropped: number; vetoed: number } {
	const pruned = pruneRows(opts.grants)
	const revoked = foldRevocations(halfOf(opts.ledger)?.revoked, opts.revoked)
	const keptGrants = partitionRevoked(pruned.kept, revoked).kept
	const keptLedger = keptLedgerGrants(opts.ledger, revoked)
	const file: GrantsFile = {
		v: GRANTS_FILE_V,
		exportedAt: new Date().toISOString(),
		sourceCwd: opts.sourceCwd,
		ledger: keptLedger.snapshot,
		grants: keptGrants,
		revoked,
	}
	return {
		file,
		dropped: pruned.dropped.length,
		vetoed: pruned.kept.length - keptGrants.length + keptLedger.vetoed,
	}
}


export function writeGrantsFile(path: string, file: GrantsFile): boolean {
	try {
		const dir = dirname(path)
		if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true })
		const tmp = `${path}.tmp-${process.pid}`
		writeFileSync(tmp, `${JSON.stringify(file, null, 2)}\n`, "utf-8")
		renameSync(tmp, path)
		return true
	} catch {
		return false
	}
}

export function readGrantsFile(path: string): ReadGrantsResult {
	if (!existsSync(path)) return { ok: false, error: `no such file: ${path}` }
	let parsed: unknown
	try {
		parsed = JSON.parse(readFileSync(path, "utf-8"))
	} catch {
		return { ok: false, error: `not valid JSON: ${path}` }
	}
	const f = parsed as Partial<GrantsFile> | null
	if (!f || typeof f !== "object") {
		return { ok: false, error: `not a grants file (expected an object): ${path}` }
	}
	if (f.v !== GRANTS_FILE_V) {
		return {
			ok: false,
			error: `unsupported grants file version ${String(f.v)} (expected ${GRANTS_FILE_V}): ${path}`,
		}
	}
	if (!Array.isArray(f.grants)) return { ok: false, error: `grants[] missing: ${path}` }
	if (!f.ledger || typeof f.ledger !== "object") {
		return { ok: false, error: `ledger object missing: ${path}` }
	}
	// Apply-on-read. A journal's revocations veto the rows in the SAME file — both
	// halves — before any caller sees them, so the veto cannot be forgotten downstream:
	// `/grants import` hands `file.ledger` straight to `importLedger` and `file.grants`
	// straight to `importSessionGrants`, and neither of them would think to ask.
	const revoked = foldRevocations(halfOf(f.ledger)?.revoked, f.revoked)
	const session = partitionRevoked(f.grants as SessionGrant[], revoked)
	const ledgerHalf = keptLedgerGrants(f.ledger, revoked)
	return {
		ok: true,
		vetoed: session.vetoed.length + ledgerHalf.vetoed,
		file: {
			v: GRANTS_FILE_V,
			exportedAt: String(f.exportedAt ?? ""),
			sourceCwd: String(f.sourceCwd ?? ""),
			ledger: ledgerHalf.snapshot,
			grants: session.kept,
			revoked,
		},
	}
}

export function summarizeGrantsFile(file: GrantsFile): string {
	const half = halfOf(file.ledger)
	const grants = half ? half.grants.length : 0
	const forbids = half ? half.forbids.length : 0
	const revoked = (file.revoked?.length ?? 0) || half?.revoked.length || 0
	const posture = half?.readOnlyOn ? ", read-only posture" : ""
	// The revoked count is in the one-line summary on purpose: a journal whose absences
	// are invisible is the thing nobody audits. The counter order of the first two is
	// pinned by the round-trip test in grants-portability.test.ts.
	return (
		`${grants} ledger grants, ${forbids} forbids, ${file.grants.length} session grants` +
		`${revoked ? `, ${revoked} revoked` : ""}${posture}` +
		` (exported ${file.exportedAt || "?"} from ${file.sourceCwd || "?"})`
	)
}

// ------------------------------------------------- durable journal (auto-export)

/** Standing in for `SerializedLedger` when a journal is created by a caller that
 *  has nothing to say about the ledger. Shaped like auth-ledger's snapshot so
 *  `readGrantsFile()` still accepts the file it wrote. */
const EMPTY_LEDGER = { v: 1, grants: [] as unknown[], forbids: [] as unknown[], seen: [] as string[] }

/** One row inside the ledger half. This module merges those rows; it does not
 *  validate them the way the store does — `deserializeLedger` is the owner of what a
 *  ledger row must satisfy, and a journal that started dropping rows on different
 *  rules would lose authority nobody told it about. */
type LedgerRow = Record<string, unknown>

type LedgerHalf = {
	v: number
	grants: LedgerRow[]
	forbids: LedgerRow[]
	seen: string[]
	readOnlyOn?: unknown
	readOnlyOffSeq?: unknown
	revoked: GrantRevocation[]
	/** Entries in either row list that named no category or no target. They can never
	 *  be matched and never be revoked, so they are left out — but counted, because a
	 *  journal that loses rows quietly is worse than one that loses them loudly. */
	unreadable: number
}

/** A row we can point a revocation at: it has to name a category and a target. */
function isLedgerRow(row: unknown): row is LedgerRow {
	const r = row as { category?: unknown; value?: unknown } | null
	return !!r && typeof r === "object" && typeof r.category === "string" && !!r.category && typeof r.value === "string" && !!r.value
}

/** The key a revocation is aimed at. `kind` is repaired the way `asGrantRow` repairs
 *  it, because a row that lost its kind still means "the entity", and leaving it
 *  unreadable would let a revocation miss it. */
function ledgerKey(row: LedgerRow): string {
	return rowIdentity({
		category: String(row.category),
		value: String(row.value),
		kind: row.kind === "scope" ? "scope" : "entity",
	})
}

/**
 * The row's position on the shared clock. `at` if it has one; otherwise its `seq`,
 * which is an ordinal and not a time — but an ordinal is always tiny next to an epoch
 * millisecond, so the fallback can only ever read as "older", i.e. more easily
 * revoked. That is the fail-closed direction for a row we cannot date.
 */
function stampOf(row: LedgerRow): number {
	if (typeof row.at === "number" && Number.isFinite(row.at)) return row.at
	if (typeof row.seq === "number" && Number.isFinite(row.seq)) return row.seq
	return 0
}

/** Read a ledger half structurally. Returns undefined when the value is not a
 *  snapshot at all, so callers can keep the "the caller had nothing to say" path. */
function halfOf(snapshot: unknown): LedgerHalf | undefined {
	const s = snapshot as {
		v?: unknown
		grants?: unknown
		forbids?: unknown
		seen?: unknown
		readOnlyOn?: unknown
		readOnlyOffSeq?: unknown
		revoked?: unknown
	} | null
	if (!s || typeof s !== "object") return undefined
	const lists = { grants: Array.isArray(s.grants) ? s.grants : [], forbids: Array.isArray(s.forbids) ? s.forbids : [] }
	const rows = (list: unknown[]): LedgerRow[] => list.filter(isLedgerRow)
	const grants = rows(lists.grants)
	const forbids = rows(lists.forbids)
	const half: LedgerHalf = {
		v: typeof s.v === "number" ? s.v : 1,
		grants,
		forbids,
		seen: Array.isArray(s.seen) ? s.seen.filter((x): x is string => typeof x === "string") : [],
		revoked: foldRevocations(undefined, s.revoked as GrantRevocation[] | undefined),
		unreadable: lists.grants.length - grants.length + (lists.forbids.length - forbids.length),
	}
	if (s.readOnlyOn !== undefined) half.readOnlyOn = s.readOnlyOn
	if (typeof s.readOnlyOffSeq === "number") half.readOnlyOffSeq = s.readOnlyOffSeq
	return half
}

/** Write one back, emitting only the keys the half actually has. */
function snapshotOf(half: LedgerHalf): Record<string, unknown> {
	const out: Record<string, unknown> = { v: half.v, grants: half.grants, forbids: half.forbids, seen: half.seen }
	if (half.readOnlyOn !== undefined) out.readOnlyOn = half.readOnlyOn
	if (typeof half.readOnlyOffSeq === "number") out.readOnlyOffSeq = half.readOnlyOffSeq
	if (half.revoked.length) out.revoked = half.revoked
	return out
}

/** Which sighting of one key describes the row now: the one with the later stamp, and
 *  on a tie the one already on disk (a journal that rewrites itself for no reason is
 *  a journal whose diff means nothing). */
function newerRow(held: LedgerRow, next: LedgerRow): LedgerRow {
	return stampOf(next) > stampOf(held) ? next : held
}

/** Union two sightings of one row list on the exact key: rows only one side has are
 *  kept, rows both have are folded to the newer sighting. */
function unionRows(held: LedgerRow[], next: LedgerRow[]): LedgerRow[] {
	const byKey = new Map<string, LedgerRow>()
	for (const row of [...held, ...next]) {
		const key = ledgerKey(row)
		const before = byKey.get(key)
		byKey.set(key, before ? newerRow(before, row) : row)
	}
	return [...byKey.values()]
}

/** Keep the file inside the caps the STORE enforces — a journal holding more rows than
 *  a ledger can hold drops them by insertion order at import, which is a worse choice
 *  made silently. The oldest stamps leave first, and the count goes back to the caller
 *  so nothing disappears without being reported. */
function capRows(rows: LedgerRow[], cap: number): { rows: LedgerRow[]; evicted: number } {
	if (rows.length <= cap) return { rows, evicted: 0 }
	const byAge = [...rows].sort((a, b) => stampOf(a) - stampOf(b))
	const gone = new Set(byAge.slice(0, rows.length - cap))
	return { rows: rows.filter((r) => !gone.has(r)), evicted: gone.size }
}

/** Remove the ledger rows a revocation vetoes, without touching the forbids. */
function vetoLedgerGrants(rows: LedgerRow[], revoked: readonly GrantRevocation[]): { kept: LedgerRow[]; vetoed: number } {
	if (!revoked.length) return { kept: rows, vetoed: 0 }
	const byKey = new Map<string, GrantRevocation>()
	for (const revocation of revoked) byKey.set(rowIdentity(revocation), revocation)
	const kept: LedgerRow[] = []
	let vetoed = 0
	for (const row of rows) {
		const hit = byKey.get(ledgerKey(row))
		if (hit && stampOf(row) <= hit.at) vetoed++
		else kept.push(row)
	}
	return { kept, vetoed }
}

/**
 * Revocations veto ledger grant rows, and nothing else. When nothing was vetoed the
 * snapshot is handed back UNTOUCHED rather than rebuilt: this module does not own the
 * shape of a ledger snapshot and must not quietly normalise fields it does not know.
 */
function keptLedgerGrants(snapshot: unknown, revoked: readonly GrantRevocation[]): { snapshot: unknown; vetoed: number } {
	if (!revoked.length) return { snapshot, vetoed: 0 }
	const half = halfOf(snapshot)
	if (!half || !half.grants.length) return { snapshot, vetoed: 0 }
	const split = vetoLedgerGrants(half.grants, revoked)
	if (!split.vetoed) return { snapshot, vetoed: 0 }
	return { snapshot: snapshotOf({ ...half, grants: split.kept }), vetoed: split.vetoed }
}

/** Same key as the dedup in session-grants / auth-ledger: {category, value, kind}. */
function rowKey(row: { category: string; value: string; kind: string }): string {
	return rowIdentity(row)
}

/**
 * Fold two sightings of one key. The newer row describes the target, except that
 * `durable` is sticky: a session that re-saw the target without knowing it was
 * ever an "always" must not quietly drop the user's answer — that is the whole
 * point of the field.
 */
function foldRow(held: SessionGrant, next: SessionGrant): SessionGrant {
	const newer = next.at >= held.at ? next : held
	if (held.durable === true || next.durable === true) return { ...newer, durable: true }
	return newer
}

/**
 * Union the ledger half. Neither side outranks the other: a snapshot arriving with this
 * call is one session's derived state, and the one on disk is another's, so rows both
 * sides hold are folded and rows only one side holds are KEPT. That is only safe
 * because `revoked` exists — a row the other session took back is vetoed by its
 * revocation on the way out, so union cannot resurrect it.
 *
 * Two things cannot be unioned and are decided instead:
 *  - `seen`: message ids from one transcript, meaningless in another. The writer's ids
 *    win when it stated any, because they describe the session doing the writing.
 *  - the read-only posture: two scalars, one answer. A writer that stated a posture
 *    restates it; a writer that said nothing (`ledger: undefined`) cannot erase the
 *    journal's, which is the behaviour callers rely on.
 */
function unionHalves(
	held: LedgerHalf | undefined,
	next: LedgerHalf | undefined,
): LedgerHalf | undefined {
	if (!held) return next
	if (!next) return held
	const half: LedgerHalf = {
		v: next.v ?? held.v,
		grants: unionRows(held.grants, next.grants),
		forbids: unionRows(held.forbids, next.forbids),
		seen: next.seen.length ? next.seen : held.seen,
		revoked: foldRevocations(held.revoked, next.revoked),
		unreadable: held.unreadable + next.unreadable,
	}
	if (next.readOnlyOn !== undefined) half.readOnlyOn = next.readOnlyOn
	else if (held.readOnlyOn !== undefined) half.readOnlyOn = held.readOnlyOn
	if (typeof next.readOnlyOffSeq === "number") half.readOnlyOffSeq = next.readOnlyOffSeq
	else if (typeof held.readOnlyOffSeq === "number") half.readOnlyOffSeq = held.readOnlyOffSeq
	return half
}

export function mergeIntoGrantsFile(
	path: string,
	ledger: unknown,
	/** A store may be passed instead of the row list, and then the revocations recorded
	 *  in it travel with the rows — one argument at the call site, nothing to forget. */
	grants: SessionGrant[] | GrantStore | undefined | null,
	opts: { sourceCwd?: string; revoked?: readonly GrantRevocation[] } = {},
): MergeGrantsResult {
	const failed = (error: string): MergeGrantsResult => ({
		ok: false, written: 0, added: 0, dropped: 0, vetoed: 0, revocations: 0, error,
	})
	// No default path, no `~` expansion, no project discovery: the caller resolves
	// the path or this writes somewhere authority would never be looked for.
	if (typeof path !== "string" || !path.trim()) return failed("no journal path given — the caller resolves it")
	if (path.startsWith("~")) return failed(`journal path is not resolved (leading ~): ${path}`)

	let current: GrantsFile | undefined
	if (existsSync(path)) {
		const read = readGrantsFile(path)
		// Unparsable, wrong version, or missing halves: refuse and leave the file
		// alone. A journal a human has been reading is not ours to overwrite with a
		// guess — same discipline as `updatePermissionModesConfig()` in config.ts.
		if (!read.ok) return failed(read.error)
		current = read.file
	}

	const rows = Array.isArray(grants) ? grants : grants?.grants
	const storeRevoked = Array.isArray(grants) ? undefined : grants?.revoked

	const currentHalf = current ? halfOf(current.ledger) : undefined
	const incomingHalf = halfOf(ledger)

	// One revocation list, folded from every place one can arrive, applied to every row
	// the file will carry. Order matters: union first, veto second, so a revocation from
	// either side reaches rows the other side brought.
	const revoked = foldRevocations(
		current?.revoked,
		[
			...(currentHalf?.revoked ?? []),
			...(incomingHalf?.revoked ?? []),
			...(storeRevoked ?? []),
			...(opts.revoked ?? []),
		],
	)

	const pruned = pruneRows(rows)
	const incoming: SessionGrant[] = []
	let dropped = pruned.dropped.length
	for (const row of pruned.kept) {
		const clean = asGrantRow(row)
		if (clean) incoming.push(clean)
		else dropped++
	}

	const byKey = new Map<string, SessionGrant>()
	for (const row of current?.grants ?? []) {
		const clean = asGrantRow(row)
		if (clean) byKey.set(rowKey(clean), clean)
		else dropped++
	}
	let added = 0
	for (const row of incoming) {
		const key = rowKey(row)
		const held = byKey.get(key)
		if (held) byKey.set(key, foldRow(held, row))
		else {
			byKey.set(key, row)
			added++
		}
	}
	const sessionRows = partitionRevoked([...byKey.values()], revoked)

	// The ledger half: union, then veto the grants, then fit it to the store's caps.
	// Forbids are unioned and NEVER vetoed — a revocation is not a forbid and must not
	// become a way to delete one.
	const merged = unionHalves(currentHalf, incomingHalf)
	let ledgerHalf = merged
	let ledgerVetoed = 0
	if (ledgerHalf) {
		dropped += ledgerHalf.unreadable
		const grantsSplit = vetoLedgerGrants(ledgerHalf.grants, revoked)
		ledgerVetoed = grantsSplit.vetoed
		const cappedGrants = capRows(grantsSplit.kept, MAX_GRANTS)
		const cappedForbids = capRows(ledgerHalf.forbids, MAX_FORBIDS)
		dropped += cappedGrants.evicted + cappedForbids.evicted
		// `revoked` is written INSIDE the snapshot as well as at the top level: a session
		// restoring the ledger half alone never sees the file's field, and losing a
		// revocation there is how a revoked grant comes back.
		ledgerHalf = { ...ledgerHalf, grants: cappedGrants.rows, forbids: cappedForbids.rows, revoked }
	}

	const file: GrantsFile = {
		v: GRANTS_FILE_V,
		exportedAt: new Date().toISOString(),
		sourceCwd: opts.sourceCwd ?? current?.sourceCwd ?? "",
		ledger: ledgerHalf ? snapshotOf(ledgerHalf) : (current?.ledger ?? EMPTY_LEDGER),
		grants: sessionRows.kept,
		revoked,
	}
	if (!writeGrantsFile(path, file)) return failed(`could not write ${path}`)
	return {
		ok: true,
		written: file.grants.length,
		added,
		dropped,
		vetoed: sessionRows.vetoed.length + ledgerVetoed,
		revocations: revoked.length,
	}
}

/**
 * The rows worth persisting: the user said "always" at a prompt, the value can
 * still match a real target, and we did not get it from this very file.
 *
 * Excluding imported rows is not redundancy, it is laundering: re-exporting what
 * a session imported moves another project's authority into this project's
 * journal, where the next session imports it as if this project's user had said
 * it — and keeps doing so forever, because nothing else ever removes it.
 */
export function selectDurableGrants(store: GrantStore): SessionGrant[] {
	return store.grants.filter(
		(g) => g.durable === true && g.origin !== "imported" && !isUnmatchableValue(g.value),
	)
}
