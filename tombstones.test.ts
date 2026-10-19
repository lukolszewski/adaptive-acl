/**
 * Revocations as data ("tombstones"): the two properties that make a union of the
 * ledger half safe, proved together. Keeping a concurrent session's addition without
 * keeping-and-vetoing is only half the job — a test that shows the union alone proves
 * nothing about the case the design exists for.
 */
import { afterAll, describe, expect, it } from "vitest"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	applyEvent,
	createLedger,
	deserializeLedger,
	importLedger,
	ledgerCovers,
	revokeLedgerGrants,
	serializeLedger,
	type ExtractedEvent,
	type LedgerEntry,
} from "./auth-ledger.ts"
import {
	GRANTS_FILE_V,
	buildGrantsFile,
	mergeIntoGrantsFile,
	readGrantsFile,
	summarizeGrantsFile,
	writeGrantsFile,
	type GrantsFile,
} from "./grants-file.ts"
import {
	addGrant,
	createGrantStore,
	deserializeGrants,
	importSessionGrants,
	partitionRevoked,
	revocationVetoes,
	revokeRows,
	serializeGrants,
	type GrantRevocation,
	type SessionGrant,
} from "./session-grants.ts"
import type { Entity } from "./risk-policy.ts"

const tmp = mkdtempSync(join(tmpdir(), "pm-tomb-"))
const at = (name: string) => join(tmp, name)
const T = (value: string): Entity => ({ kind: "target", value })

/** Two fixed "clock readings": every expectation below is about their ORDER. */
const EARLIER = 1_000
const LATER = 5_000

function sessionRow(value: string, at = EARLIER, extra: Partial<SessionGrant> = {}): SessionGrant {
	return { category: "write_project", value, kind: "entity", at, ...extra }
}

function tombstone(value: string, at = LATER, extra: Partial<GrantRevocation> = {}): GrantRevocation {
	return { category: "write_project", value, kind: "entity", at, ...extra }
}

/** A serialized ledger holding exactly these grant targets, with an optional clock so
 *  a test can say which side of a revocation they fall on. A restored session/blob
 *  looks exactly like this: rows that remember when they were earned. */
function ledgerWith(values: string[], opts: { seq?: number; at?: number } = {}) {
	const ledger = createLedger()
	values.forEach((value, i) => {
		applyEvent(ledger, event("grant", value, (opts.seq ?? 1) + i))
		if (opts.at !== undefined) ledger.grants[i]!.at = opts.at + i
	})
	return serializeLedger(ledger)
}

function event(type: "grant" | "forbid", value: string, seq: number): ExtractedEvent {
	return {
		type,
		category: "write_project",
		value,
		kind: "entity",
		quote: `${type} ${value}`,
		messageId: `m${seq}`,
		seq,
	}
}

function raw(path: string): any {
	return JSON.parse(readFileSync(path, "utf-8"))
}

function read(path: string): GrantsFile {
	const r = readGrantsFile(path)
	if (!r.ok) throw new Error(`journal unreadable: ${r.error}`)
	return r.file
}

function ledgerGrantValues(path: string): string[] {
	return (raw(path).ledger.grants as { value: string }[]).map((g) => g.value)
}

const TOMB_FIELDS = ["category", "value", "kind", "at"]

// ------------------------------------------------------- the schema decision (v: 1)

describe("a v: 1 journal may carry `revoked`", () => {
	it("keeps the version constant: today's readers are not asked to refuse the file", () => {
		expect(GRANTS_FILE_V).toBe(1)
	})

	it("is read by the current validator, tombstones included", () => {
		const p = at("v1-with-revoked.json")
		writeFileSync(
			p,
			JSON.stringify({
				v: 1,
				exportedAt: "2026-10-14T00:00:00.000Z",
				sourceCwd: "/other",
				ledger: { v: 1, grants: [], forbids: [], seen: [] },
				grants: [],
				revoked: [{ category: "write_project", value: "/taken/back", kind: "entity", at: LATER, quote: "/grants revoke /taken/back" }],
			}),
		)
		const file = read(p)
		expect(file.revoked).toHaveLength(1)
		expect(file.revoked?.[0]).toMatchObject({ category: "write_project", value: "/taken/back", kind: "entity", at: LATER })
		expect(file.revoked?.[0]?.quote).toContain("revoke")
	})

	it("survives the write → read round trip with its fields intact", () => {
		const p = at("round-trip.json")
		const { file } = buildGrantsFile({
			ledger: ledgerWith(["/keep"]),
			grants: [sessionRow("/keep", EARLIER, { durable: true })],
			sourceCwd: "/p",
			revoked: [tombstone("/gone", LATER, { quote: "not again" })],
		})
		expect(writeGrantsFile(p, file)).toBe(true)
		expect(Object.keys(file.revoked?.[0] ?? {}).sort()).toEqual([...TOMB_FIELDS, "quote"].sort())
		expect(read(p).revoked).toEqual([{ category: "write_project", value: "/gone", kind: "entity", at: LATER, quote: "not again" }])
	})

	it("treats a missing, empty or malformed `revoked` as 'nothing was taken back'", () => {
		const p = at("junk-revoked.json")
		writeFileSync(
			p,
			JSON.stringify({
				v: 1,
				exportedAt: "x",
				sourceCwd: "/s",
				ledger: { v: 1, grants: [], forbids: [], seen: [] },
				grants: [],
				revoked: [null, 7, { value: "/no/category" }, { category: "c", value: "/ok", at: LATER }, { category: "c", value: "/at/missing" }],
			}),
		)
		// The two that can name a target survive (kind defaults to entity, a missing
		// timestamp reads as "oldest"), and the file still loads.
		expect(read(p).revoked?.map((r) => r.value).sort()).toEqual(["/at/missing", "/ok"])
	})
})

// ------------------------------------------------------ exact keys only, never wider

describe("a revocation reaches exactly the row it names", () => {
	it("vetoes nothing but the same {category, value, kind}", () => {
		const rev = tombstone("/x/y")
		const rows = [
			sessionRow("/x/y"), // the row itself
			{ ...sessionRow("/x/y"), category: "read_secret" }, // another category
			{ ...sessionRow("/x/y"), kind: "scope" as const }, // another kind
			sessionRow("/x/y/"), // a value that merely starts with it
			sessionRow("/x"), // and its parent folder
			sessionRow("/x/"), // a folder grant OVER the parent
		]
		const split = partitionRevoked(rows, [rev])
		expect(split.vetoed).toHaveLength(1)
		expect(split.vetoed[0]).toBe(rows[0])
		expect(split.kept).toEqual(rows.slice(1))
	})

	it("a folder grant over /x outlives a revocation of /x/y", () => {
		const p = at("narrow.json")
		// The user said "always" about the whole folder, then revoked one file in it.
		mergeIntoGrantsFile(p, ledgerWith([]), [
			{ category: "write_project", value: "/x/", kind: "scope", at: EARLIER, durable: true },
			{ category: "write_project", value: "/x/y", kind: "entity", at: EARLIER, durable: true },
		])
		const r = mergeIntoGrantsFile(p, ledgerWith([]), [], { revoked: [tombstone("/x/y")] })
		expect(r.vetoed).toBe(1)
		expect(read(p).grants.map((g) => g.value)).toEqual(["/x/"])
		expect(r.revocations).toBe(1)
	})

	it("orders equal timestamps toward the revocation and a later grant above it", () => {
		expect(revocationVetoes(sessionRow("/a", LATER), tombstone("/a", LATER))).toBe(true)
		expect(revocationVetoes(sessionRow("/a", LATER + 1), tombstone("/a", LATER))).toBe(false)
		// A row that cannot prove when it was earned is the oldest thing on disk.
		expect(revocationVetoes({ category: "write_project", value: "/a", kind: "entity" }, tombstone("/a", 1))).toBe(true)
	})
})

// ------------------------------------------------------------- apply-on-read

describe("revocations are honoured when the journal is read", () => {
	it("vetoes grant rows in the SAME file, in both halves", () => {
		const p = at("same-file.json")
		writeFileSync(
			p,
			JSON.stringify({
				v: 1,
				exportedAt: "x",
				sourceCwd: "/s",
				ledger: {
					v: 1,
					grants: [
						{ category: "write_project", value: "/revoked", kind: "entity", quote: "q", messageId: "", seq: 0, at: EARLIER },
						{ category: "write_project", value: "/re-granted", kind: "entity", quote: "q", messageId: "", seq: 0, at: LATER + 10 },
					],
					forbids: [],
					seen: [],
				},
				grants: [
					sessionRow("/revoked", EARLIER),
					sessionRow("/re-granted", LATER + 10),
				],
				revoked: [tombstone("/revoked", LATER)],
			}),
		)
		const readBack = readGrantsFile(p)
		expect(readBack.ok && readBack.vetoed).toBe(2)
		const file = read(p)
		expect(file.grants.map((g) => g.value)).toEqual(["/re-granted"])
		expect((file.ledger as any).grants.map((g: any) => g.value)).toEqual(["/re-granted"])
		// …and the revocation itself is still there to do it again next time.
		expect(file.revoked?.map((r) => r.value)).toEqual(["/revoked"])
	})

	it("never vetoes a forbid, and a merge never drops one either", () => {
		const p = at("forbids.json")
		const source = createLedger()
		applyEvent(source, event("forbid", "/data/never", 3))
		const { file } = buildGrantsFile({
			ledger: serializeLedger(source),
			grants: [],
			sourceCwd: "/p",
			revoked: [tombstone("/data/never", LATER)],
		})
		expect(writeGrantsFile(p, file)).toBe(true)
		expect((read(p).ledger as any).forbids.map((f: any) => f.value)).toEqual(["/data/never"])

		// A second session whose own snapshot has no idea about the forbid writes.
		const r = mergeIntoGrantsFile(p, ledgerWith(["/unrelated"]), [])
		expect(r.ok).toBe(true)
		expect((read(p).ledger as any).forbids.map((f: any) => f.value)).toEqual(["/data/never"])
		expect(ledgerGrantValues(p)).toContain("/unrelated")
	})

	it("shows up in the one-line summary, so an absence has a reason on screen", () => {
		const { file } = buildGrantsFile({
			ledger: ledgerWith(["/a"]),
			grants: [sessionRow("/a")],
			sourceCwd: "/p",
			revoked: [tombstone("/b"), tombstone("/c")],
		})
		expect(summarizeGrantsFile(file)).toContain("2 revoked")
		expect(summarizeGrantsFile(file)).toContain("1 ledger grants, 0 forbids")
	})

	it("counts what it refused when building an export", () => {
		const built = buildGrantsFile({
			ledger: ledgerWith(["/revoked", "/kept"], { at: EARLIER }),
			grants: [sessionRow("/revoked"), sessionRow("/kept")],
			sourceCwd: "/p",
			revoked: [tombstone("/revoked", LATER)],
		})
		expect(built.vetoed).toBe(2)
		expect(built.file.grants.map((g) => g.value)).toEqual(["/kept"])
		expect((built.file.ledger as any).grants.map((g: any) => g.value)).toEqual(["/kept"])
	})
})

// ----------------------------------------- the point of all this: union + veto

describe("mergeIntoGrantsFile unions the ledger half and still revokes", () => {
	/** The supervisor's scenario, at the journal layer: a row written by ANOTHER
	 *  session, then this session's auto-export over the top of it. */
	function concurrentJournal(name: string) {
		const p = at(name)
		writeFileSync(
			p,
			JSON.stringify({
				v: 1,
				exportedAt: "earlier",
				sourceCwd: "/other",
				ledger: {
					v: 1,
					grants: [
						{ category: "read_only", value: "/from/other/session", kind: "entity", quote: "q", messageId: "m0", seq: 1, at: EARLIER },
					],
					forbids: [],
					seen: ["m0"],
				},
				grants: [],
			}),
		)
		return p
	}

	it("keeps a concurrent session's addition (the gap this task closes)", () => {
		const p = concurrentJournal("union.json")
		const r = mergeIntoGrantsFile(p, ledgerWith(["/mine"]), [sessionRow("/mine", LATER)], { sourceCwd: "/mine" })
		expect(r.ok).toBe(true)
		const values = ledgerGrantValues(p)
		expect(values).toContain("/mine")
		expect(values).toContain("/from/other/session")
		expect(raw(p).sourceCwd).toBe("/mine")
	})

	it("keeps it even when this session revoked something of its own in the same write", () => {
		const p = concurrentJournal("union-and-veto.json")
		mergeIntoGrantsFile(p, ledgerWith(["/mine"], { at: EARLIER }), [], { revoked: [tombstone("/mine")] })
		const values = ledgerGrantValues(p)
		// Both halves of the promise, in one write: the addition nobody else had seen
		// is kept, and what this session took back stays gone.
		expect(values).toContain("/from/other/session")
		expect(values).not.toContain("/mine")
	})

	it("a revocation recorded by EITHER session keeps its target out of the file", () => {
		// (a) revoked in the session that wrote the journal first.
		const p = at("revoked-by-holder.json")
		mergeIntoGrantsFile(p, ledgerWith(["/shared"], { at: EARLIER }), [])
		mergeIntoGrantsFile(p, ledgerWith([]), [], { revoked: [tombstone("/shared", LATER)] })
		expect(ledgerGrantValues(p)).toEqual([])
		// A third session, holding the row in its own ledger, cannot write it back.
		mergeIntoGrantsFile(p, ledgerWith(["/shared"], { at: EARLIER }), [])
		expect(ledgerGrantValues(p)).toEqual([])

		// (b) revoked in the session arriving now: its revocation travels inside its
		// own snapshot and vetoes the row already on disk.
		const q = at("revoked-by-arriver.json")
		mergeIntoGrantsFile(q, ledgerWith(["/shared"], { at: EARLIER }), [])
		const arriving = createLedger()
		const removed = revokeLedgerGrants(arriving, () => true) // nothing to take yet
		expect(removed).toEqual([])
		applyEvent(arriving, event("grant", "/shared", 1))
		arriving.grants[0]!.at = EARLIER
		revokeLedgerGrants(arriving, (g: LedgerEntry) => g.value === "/shared", { quote: "/grants revoke /shared", at: LATER })
		const r = mergeIntoGrantsFile(q, serializeLedger(arriving), [])
		expect(r.vetoed).toBe(1)
		expect(r.revocations).toBe(1)
		expect(ledgerGrantValues(q)).toEqual([])
	})

	it("a grant re-earned after the revocation is kept — the tombstone is not a ban", () => {
		const p = at("re-grant.json")
		mergeIntoGrantsFile(p, ledgerWith(["/shared"], { at: EARLIER }), [sessionRow("/shared", EARLIER)])
		mergeIntoGrantsFile(p, ledgerWith([]), [], { revoked: [tombstone("/shared", LATER)] })
		expect(ledgerGrantValues(p)).toEqual([])
		expect(read(p).grants).toEqual([])

		// Same target, earned later than the revocation, from either half.
		mergeIntoGrantsFile(p, ledgerWith(["/shared"], { at: LATER + 100 }), [sessionRow("/shared", LATER + 100)])
		expect(ledgerGrantValues(p)).toEqual(["/shared"])
		expect(read(p).grants.map((g) => g.value)).toEqual(["/shared"])
	})

	it("keeps the sticky-durable folding it had before", () => {
		const p = at("fold.json")
		mergeIntoGrantsFile(p, ledgerWith([]), [sessionRow("/x", EARLIER, { durable: true })])
		mergeIntoGrantsFile(p, ledgerWith([]), [sessionRow("/x", LATER)])
		const [row] = read(p).grants
		expect(row.at).toBe(LATER)
		expect(row.durable).toBe(true)
	})

	it("still refuses to touch a journal it cannot read, tombstones or no tombstones", () => {
		const p = at("v9-with-tombstones.json")
		const body = JSON.stringify({
			v: 9,
			exportedAt: "x",
			sourceCwd: "/s",
			ledger: { v: 1, grants: [], forbids: [], seen: [] },
			grants: [],
			revoked: [tombstone("/x")],
		})
		writeFileSync(p, body)
		const r = mergeIntoGrantsFile(p, ledgerWith(["/a"]), [])
		expect(r.ok).toBe(false)
		expect(r.error).toContain("version")
		expect(readFileSync(p, "utf-8")).toBe(body)
	})
})

// ------------------------------------------------------------- the store side

describe("revoking from the session store", () => {
	it("records one tombstone per row it removed, and nothing for a revoke that matched nothing", () => {
		const store = createGrantStore()
		addGrant(store, "write_project+perm_change", "/data/x", "entity", true)
		addGrant(store, "write_project", "/data/keep", "entity", true)
		expect(store.grants).toHaveLength(3) // the compound became its two effects

		const taken = revokeRows(store, (g) => g.value === "/data/x", { quote: "/grants revoke /data/x", at: LATER })
		expect(taken.map((r) => [r.category, r.value, r.kind, r.at])).toEqual([
			["perm_change", "/data/x", "entity", LATER],
			["write_project", "/data/x", "entity", LATER],
		])
		expect(store.grants.map((g) => g.value)).toEqual(["/data/keep"])
		expect(store.revoked).toHaveLength(2)
		expect(revokeRows(store, () => false)).toEqual([])
		expect(store.revoked).toHaveLength(2) // an empty revoke records no ban
	})

	it("lets the user answer 'always' again for the same target afterwards", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		revokeRows(store, (g) => g.value === "/data/x", { at: LATER })
		expect(store.grants).toHaveLength(0)

		addGrant(store, "write_project", "/data/x", "entity", true)
		expect(store.grants).toHaveLength(1) // addGrant stamps a fresh `at`
		expect(store.grants[0]!.at).toBeGreaterThan(LATER)
		// …and the fresh row is not vetoed by the revocation it followed.
		expect(partitionRevoked(store.grants, store.revoked).vetoed).toEqual([])
	})

	it("refuses a revoked row on import even when the file claims a later timestamp", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		revokeRows(store, (g) => g.value === "/data/x", { at: LATER })

		const r = importSessionGrants(store, [sessionRow("/data/x", 1, { durable: true })])
		expect(r).toEqual({ added: 0, dropped: 1 })
		expect(store.grants).toHaveLength(0)
	})

	it("honours the revocations that arrive with the file, but a re-grant recorded after them still comes through", () => {
		const store = createGrantStore()
		const r = importSessionGrants(
			store,
			[sessionRow("/revoked", 1), sessionRow("/re-granted", LATER + 10), sessionRow("/clean", 3)],
			{
				revoked: [tombstone("/revoked", LATER), tombstone("/re-granted", EARLIER)],
			},
		)
		expect(store.grants.map((g) => g.value).sort()).toEqual(["/clean", "/re-granted"])
		expect(r.added).toBe(2)
		expect(r.dropped).toBe(1)
	})

	it("keeps local revocations through a --replace import", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		revokeRows(store, (g) => g.value === "/data/x", { at: LATER })
		importSessionGrants(store, [sessionRow("/from/file", 1)], { replace: true })
		expect(store.grants.map((g) => g.value)).toEqual(["/from/file"])
		expect(store.revoked?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("round-trips revocations through the session blob, old and new shapes", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		revokeRows(store, (g) => g.value === "/data/x", { at: LATER })

		const restored = deserializeGrants(serializeGrants(store))
		expect(restored.grants).toEqual([])
		expect(restored.revoked?.map((r) => r.value)).toEqual(["/data/x"])

		// A blob written before revocations existed is a bare array, and has none.
		const legacy = deserializeGrants(JSON.stringify([sessionRow("/old", EARLIER)]))
		expect(legacy.grants.map((g) => g.value)).toEqual(["/old"])
		expect(legacy.revoked).toEqual([])
	})
})

// ----------------------------------------------------------- the ledger side

describe("revoking from the ledger", () => {
	it("stamps the rows it earns so a revocation has something to compare against", () => {
		const ledger = createLedger()
		applyEvent(ledger, event("grant", "/data/x", 3))
		expect(typeof ledger.grants[0]!.at).toBe("number")
		expect(ledger.grants[0]!.at!).toBeGreaterThan(0)
	})

	it("takes the rows back and keeps a tombstone for each", () => {
		const ledger = createLedger()
		applyEvent(ledger, event("grant", "/data/x", 1))
		applyEvent(ledger, event("grant", "/data/keep", 2))
		const taken = revokeLedgerGrants(ledger, (g) => g.value === "/data/x", { quote: "/grants revoke /data/x" })
		expect(taken.map((r) => r.value)).toEqual(["/data/x"])
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])
		expect(ledger.revoked?.[0]).toMatchObject({ value: "/data/x", kind: "entity", quote: "/grants revoke /data/x" })
		expect(ledgerCovers(ledger, "write_project", [T("/data/x")]).covered).toBe(false)
		expect(ledgerCovers(ledger, "write_project", [T("/data/keep")]).covered).toBe(true)
	})

	it("leaves forbids alone: a revocation is not a way to delete a forbid", () => {
		const ledger = createLedger()
		applyEvent(ledger, event("forbid", "/data/never", 4))
		revokeLedgerGrants(ledger, () => true, { quote: "clear everything" })
		expect(ledger.forbids.map((f) => f.value)).toEqual(["/data/never"])
		expect(ledger.revoked ?? []).toEqual([]) // nothing was removed, so nothing was recorded
	})

	it("carries tombstones through serialize → restore, vetoing the rows they cover", () => {
		const ledger = createLedger()
		applyEvent(ledger, event("grant", "/data/x", 1))
		applyEvent(ledger, event("grant", "/data/keep", 2))
		ledger.grants[0]!.at = EARLIER
		revokeLedgerGrants(ledger, (g) => g.value === "/data/x", { at: LATER + 1 })
		const snapshot = serializeLedger(ledger)
		expect((snapshot as any).revoked).toHaveLength(1)

		const restored = deserializeLedger(snapshot)
		expect(restored.grants.map((g) => g.value)).toEqual(["/data/keep"])
		expect(restored.revoked?.map((r) => r.value)).toEqual(["/data/x"])

		// A writer that left its own row in place is still refused on read.
		const sloppier = deserializeLedger({
			v: 1,
			grants: [{ category: "write_project", value: "/sneaky", kind: "entity", quote: "q", messageId: "", seq: 2, at: EARLIER }],
			forbids: [],
			seen: [],
			revoked: [{ category: "write_project", value: "/sneaky", kind: "entity", at: LATER }],
		})
		expect(sloppier.grants).toEqual([])
		expect(sloppier.revoked).toHaveLength(1)
	})

	it("refuses revoked rows at the import door and adds nothing to the count", () => {
		const target = createLedger()
		applyEvent(target, event("grant", "/data/x", 1))
		target.grants[0]!.at = EARLIER
		revokeLedgerGrants(target, (g) => g.value === "/data/x", { at: LATER })

		const source = createLedger()
		applyEvent(source, event("grant", "/data/x", 9))
		applyEvent(source, event("grant", "/data/new", 10))
		source.grants.forEach((g) => (g.at = EARLIER))
		const summary = importLedger(target, serializeLedger(source))
		expect(summary.grantsAdded).toBe(1)
		expect(summary.revokedOnArrival).toBe(1)
		expect(target.grants.map((g) => g.value)).toEqual(["/data/new"])
	})

	it("does not let an imported revocation veto a grant this session earned by itself", () => {
		// Same precedence an imported FORBID gets: a file cannot outrank a person.
		const target = createLedger()
		applyEvent(target, event("grant", "/data/x", 1))
		target.grants[0]!.at = EARLIER
		const source = createLedger()
		applyEvent(source, event("grant", "/data/x", 2))
		source.grants[0]!.at = EARLIER
		revokeLedgerGrants(source, (g) => g.value === "/data/x", { at: LATER })

		const summary = importLedger(target, serializeLedger(source))
		expect(summary.revocationsAdded).toBe(1)
		expect(target.grants.map((g) => g.value)).toEqual(["/data/x"])
		expect(target.revoked?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("never imports a row the source had already revoked", () => {
		const source = createLedger()
		applyEvent(source, event("grant", "/data/x", 1))
		source.grants[0]!.at = EARLIER
		revokeLedgerGrants(source, (g) => g.value === "/data/x", { at: LATER })
		const target = createLedger()
		const summary = importLedger(target, serializeLedger(source))
		expect(summary.grantsAdded).toBe(0)
		expect(target.grants).toEqual([])
		// The revocation still travels, so the next session is refused too.
		expect(target.revoked?.map((r) => r.value)).toEqual(["/data/x"])
	})
})

afterAll(() => rmSync(tmp, { recursive: true, force: true }))
