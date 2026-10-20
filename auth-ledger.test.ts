/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, afterAll, it } from "vitest"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
	applyEvent,
	applyEvents,
	createLedger,
	deserializeLedger,
	eventsFromExtraction,
	extractionStats,
	importLedger,
	isSyntheticUserTurn,
	kindGroup,
	ledgerCovers,
	mapActionToCategory,
	MAX_FORBIDS,
	MAX_GRANTS,
	namedForbidCovers,
	readOnlyActive,
	readOnlyLiftedByGrant,
	revokeLedgerForbids,
	revokeLedgerGrants,
	serializeLedger,
	type ExtractedEvent,
	type Ledger,
} from "./auth-ledger.ts"
import { mergeIntoGrantsFile, readGrantsFile } from "./grants-file.ts"
import type { Entity } from "./risk-policy.ts"

const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

function grant(category: string, value: string, seq: number, quote = `you can do it to ${value}`, kind?: "entity" | "scope"): ExtractedEvent {
	return { type: "grant", category, value, kind: kind ?? (value.endsWith("/") ? "scope" : "entity"), quote, messageId: `m${seq}`, seq }
}
function forbid(value: string, seq: number, quote = `do not touch ${value}`, category = "*"): ExtractedEvent {
	return { type: "forbid", category, value, kind: value.endsWith("/") ? "scope" : "entity", quote, messageId: `m${seq}`, seq }
}

describe("kind groups / action mapping", () => {
	it("keeps the three fs-mutation kinds apart, and unrelated domains apart", () => {
		// Content, destruction and privilege are three harm classes, not one. They shared
		// fs-write until the split; lumping them let a folder write grant authorise chmod.
		expect(kindGroup("write_outside")).toBe("fs-write")
		expect(kindGroup("delete_recursive")).toBe("fs-delete")
		expect(kindGroup("perm_change")).toBe("fs-perm")
		expect(kindGroup("write_outside")).not.toBe(kindGroup("delete_recursive"))
		expect(kindGroup("write_outside")).not.toBe(kindGroup("perm_change"))
		expect(kindGroup("write_outside")).not.toBe(kindGroup("package_system"))
		expect(kindGroup("cluster_mutation")).toBe(kindGroup("container_mutation"))
		expect(kindGroup("vcs_remote")).not.toBe(kindGroup("vcs_discard"))
	})
	it("maps domain nouns before generic verbs", () => {
		expect(mapActionToCategory("delete the pod")).toBe("cluster_mutation")
		expect(mapActionToCategory("drop the sessions table")).toBe("db_mutation")
		expect(mapActionToCategory("delete old logs")).toBe("delete_outside")
		expect(mapActionToCategory("copy files with rsync")).toBe("write_outside")
		expect(mapActionToCategory("install ripgrep")).toBe("package_system")
		expect(mapActionToCategory("interpretive dance")).toBeUndefined()
	})
})

describe("fold: dedup + seq precedence", () => {
	it("dedups same key, keeps highest seq", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 5))
		applyEvent(l, grant("write_outside", "/data/", 9, "again /data/ please"))
		applyEvent(l, grant("write_outside", "/data/", 3, "old /data/"))
		expect(l.grants).toHaveLength(1)
		expect(l.grants[0]!.seq).toBe(9)
		expect(l.grants[0]!.quote).toContain("again")
	})
	it("exact-key flip-flop keeps only the newest side", () => {
		const l = createLedger()
		applyEvents(l, [grant("write_outside", "/data/", 2), forbid("/data/", 5), grant("write_outside", "/data/", 8)])
		// forbid category "*" vs grant category write_outside — different keys, so
		// both survive; precedence is decided at match time by seq.
		const v = ledgerCovers(l, "write_outside", [T("/data/x.txt")])
		expect(v.covered).toBe(true)
	})
	it("revocation between grants blocks, re-grant unblocks", () => {
		const probe = () => ledgerCovers(l, "write_outside", [T("/data/x")])
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 2))
		expect(probe().covered).toBe(true)
		applyEvent(l, forbid("/data/", 5))
		expect(probe().covered).toBe(false)
		expect(probe().forbidden).toBe(true)
		applyEvent(l, grant("write_outside", "/data/", 8))
		expect(probe().covered).toBe(true)
	})
	it("'revoke all' keeps blocking targets a later grant did not re-grant", () => {
		const l = createLedger()
		applyEvents(l, [
			grant("write_outside", "/a/", 2),
			grant("write_outside", "/b/", 3),
			forbid("*", 10, "stop, do not write anywhere"),
			grant("write_outside", "/a/", 15),
		])
		expect(ledgerCovers(l, "write_outside", [T("/a/f")]).covered).toBe(true)
		const b = ledgerCovers(l, "write_outside", [T("/b/f")])
		expect(b.covered).toBe(false)
		expect(b.forbidden).toBe(true)
	})
	it("folded state is independent of processing order", () => {
		const events = [
			grant("write_outside", "/data/", 2),
			forbid("/data/", 5),
			grant("write_outside", "/data/", 8),
			grant("db_mutation", "sessions", 4, "you can drop the sessions table"),
			forbid("*", 6, "actually stop everything"),
			grant("package_system", "ripgrep", 9, "just apt-get install ripgrep"),
			forbid("payments", 7),
		]
		const probes: Array<[string, Entity[]]> = [
			["write_outside", [T("/data/x")]],
			["db_mutation", [T("sessions")]],
			["package_system", [T("ripgrep")]],
			["db_mutation", [T("payments")]],
		]
		const orders = [
			events,
			[...events].reverse(),
			[events[3]!, events[6]!, events[0]!, events[5]!, events[2]!, events[1]!, events[4]!],
			[events[4]!, events[2]!, events[0]!, events[1]!, events[6]!, events[5]!, events[3]!],
		]
		const results = orders.map((order) => {
			const l = createLedger()
			applyEvents(l, order)
			return probes.map(([c, e]) => `${ledgerCovers(l, c, e).covered}/${ledgerCovers(l, c, e).forbidden}`).join(" ")
		})
		expect(new Set(results).size).toBe(1)
		// sanity on the shared verdicts: sessions revoked by "stop everything" (seq 6 > 4),
		// ripgrep re-granted after it (9 > 6), payments forbidden
		expect(results[0]).toBe("true/false false/true true/false false/true")
	})
	it("newest-first partial fold never allows a later-revoked grant", () => {
		// grant at 10, revocation at 40 — processed newest-first
		const l = createLedger()
		applyEvent(l, forbid("/data/", 40))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(false)
		applyEvent(l, grant("write_outside", "/data/", 10)) // older grant arrives later
		const v = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
	})
})

describe("matching", () => {
	it("a write grant reaches mkdir at the location, and never chmod", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "write_outside", [T("/x/x/sub")]).covered).toBe(true)
		// Used to be true, through the shared fs-write group. Copy files here says nothing about
		// who else may read what lands there, and chmod is precisely that decision.
		expect(ledgerCovers(l, "perm_change", [T("/x/x/sub/f")]).covered).toBe(false)
		// The permission is still grantable - it just has to be named by a quote that says it.
		const withPerm = createLedger()
		applyEvent(withPerm, grant("perm_change", "/x/x/", 3, "copy the file and chmod what you copy in /x/x/"))
		expect(ledgerCovers(withPerm, "perm_change", [T("/x/x/sub/f")]).covered).toBe(true)
	})
	it("deletes require a delete verb in the grant quote", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(false)
		applyEvent(l, grant("delete_outside", "/x/x/old", 5, "and delete /x/x/old when done"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(true)
	})
	it("METHOD_VERB_REQUIRED: naming the package is not approving the install", () => {
		const l = createLedger()
		applyEvent(l, grant("package_system", "ripgrep", 3, "ripgrep is missing on this box"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(false)
		applyEvent(l, grant("package_system", "ripgrep", 4, "go ahead and install ripgrep"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(true)
	})
	it("near-names never match across the ledger", () => {
		const l = createLedger()
		applyEvent(l, grant("delete_data", "db-backup", 3, "you can delete db-backup"))
		expect(ledgerCovers(l, "delete_data", [T("db-backup-test")]).covered).toBe(false)
		expect(ledgerCovers(l, "delete_data", [T("db-backup")]).covered).toBe(true)
	})
	it("cross-group grants never match; unmappable actions never match", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 3, "write to /data/ freely"))
		expect(ledgerCovers(l, "package_system", [T("/data/")]).covered).toBe(false)
		applyEvent(l, { type: "grant", category: "*frobnicate the widget*", value: "widget", kind: "entity", quote: "frobnicate the widget", messageId: "m9", seq: 9 })
		expect(ledgerCovers(l, "write_outside", [T("widget")]).covered).toBe(false)
	})
	it("all targets must be covered", () => {
		const l = createLedger()
		applyEvent(l, grant("db_mutation", "sessions", 3, "drop the sessions table"))
		expect(ledgerCovers(l, "db_mutation", [T("sessions"), T("users")]).covered).toBe(false)
	})
	it("bare-verb '*' grant covers unlisted targets of the category", () => {
		const l = createLedger()
		applyEvent(l, grant("vcs_remote", "*", 3, "force-push it", "scope"))
		expect(ledgerCovers(l, "vcs_remote", [T("origin/main")]).covered).toBe(true)
		expect(ledgerCovers(l, "package_system", [T("origin/main")]).covered).toBe(false)
	})
})

describe("caps / eviction", () => {
	it("evicts least-recently-matched grants first, never forbids for grants", () => {
		const l = createLedger()
		for (let i = 0; i < MAX_GRANTS + 10; i++) applyEvent(l, grant("write_outside", `/p${i}/`, i))
		expect(l.grants.length).toBe(MAX_GRANTS)
		// the oldest unmatched ones are gone; matching bumps recency
		expect(ledgerCovers(l, "write_outside", [T(`/p${MAX_GRANTS + 9}/x`)]).covered).toBe(true)
		for (let i = 0; i < MAX_FORBIDS + 5; i++) applyEvent(l, forbid(`/q${i}/`, 1000 + i))
		expect(l.forbids.length).toBe(MAX_FORBIDS)
		expect(l.grants.length).toBe(MAX_GRANTS)
	})
})

describe("eventsFromExtraction verification", () => {
	it("a tool-written interrupt notice yields no events, whatever the extractor says", () => {
		const notice = "[Request interrupted by user for tool use]"
		expect(isSyntheticUserTurn(notice)).toBe(true)
		expect(isSyntheticUserTurn("  [Request interrupted by user]\n")).toBe(true)
		expect(isSyntheticUserTurn("stop, do not change anything")).toBe(false)
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "stop", targets: [], all: true, quote: notice }] },
			"m9", 9, notice,
		)
		expect(ev).toEqual([])
	})
	const msg = "please copy the dataset to /mnt/scratch/exp1/ and then you can delete ./old-dumps, but do not touch ~/backups"
	it("keeps verified grants/revocations, drops unverifiable quotes and targets", () => {
		const ev = eventsFromExtraction(
			{
				grants: [
					{ action: "copy files", targets: ["/mnt/scratch/exp1/"], quote: "copy the dataset to /mnt/scratch/exp1/" },
					{ action: "delete files", targets: ["./old-dumps"], quote: "you can delete ./old-dumps" },
					{ action: "delete files", targets: ["/etc/passwd"], quote: "you can delete ./old-dumps" }, // target not in message
					{ action: "install tools", targets: ["ripgrep"], quote: "install ripgrep now" }, // quote not in message
				],
				revocations: [{ action: "delete files", targets: ["~/backups"], all: false, quote: "do not touch ~/backups" }],
			},
			"mid1", 7, msg,
		)
		expect(ev.map((e) => `${e.type}:${e.value}`)).toEqual([
			"grant:/mnt/scratch/exp1/",
			"grant:./old-dumps",
			"forbid:~/backups",
			// A named revocation records the path AND its subtree: a folder grant reaches the
			// files inside it, so "do not touch ~/backups" has to as well, or the earlier grant
			// keeps authorising them. Found by eval case L-02.
			"forbid:~/backups/",
		])
		expect(ev[0]!.kind).toBe("scope")
		expect(ev[0]!.category).toBe("write_outside")
		expect(ev.every((e) => e.messageId === "mid1" && e.seq === 7)).toBe(true)
	})
	it("bare-verb grant only for bare-verb categories with the verb in the quote", () => {
		const ev = eventsFromExtraction(
			{ grants: [{ action: "push to remote", targets: [], quote: "force-push it" }], revocations: [] },
			"m1", 2, "ok now force-push it",
		)
		expect(ev).toEqual([expect.objectContaining({ type: "grant", category: "vcs_remote", value: "*", kind: "scope" })])
		const none = eventsFromExtraction(
			{ grants: [{ action: "write files", targets: [], quote: "sounds good" }], revocations: [] },
			"m1", 2, "sounds good",
		)
		expect(none).toEqual([])
	})
	it("'all' revocation with unmappable action sets the read-only posture (enforced by the gate, not ledgerCovers)", () => {
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "risky work", targets: [], all: true, quote: "stop, don't run anything risky anymore" }] },
			"m1", 50, "stop, don't run anything risky anymore",
		)
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 10))
		applyEvents(l, ev)
		// posture is set; the older grant (seq 10 < 50) does not lift it
		expect(readOnlyActive(l)?.seq).toBe(50)
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/data/x")], 50)).toBe(false)
		expect(l.forbids).toHaveLength(0)
	})
	it("blanket 'don't change anything' sets the read-only posture, not a wildcard forbid", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "change anything", targets: [], all: true, quote: "you are not allowed to change anything" }] },
			"m0", 0, "you are not allowed to change anything",
		))
		expect(readOnlyActive(l)?.quote).toContain("change anything")
		expect(l.forbids).toHaveLength(0) // no more */* forbid row
	})
	it("read-only: later per-target grant lifts that target, blanket re-enable clears it", () => {
		const l = createLedger()
		applyEvent(l, { type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "do not change anything", messageId: "m0", seq: 0 })
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(false)
		applyEvent(l, grant("write_outside", "/x/", 5, "you can write to /x/"))
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(true) // seq 5 > 0
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/y/f")], 0)).toBe(false) // different target
		expect(readOnlyLiftedByGrant(l, "write_outside", [], 0)).toBe(false) // targetless can't be lifted
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "make changes", targets: [], quote: "ok you can make changes now" }], revocations: [] },
			"m9", 9, "ok you can make changes now",
		))
		expect(readOnlyActive(l)).toBeNull()
	})
	it("read-only posture is order-independent and re-armable (on/off/on by seq)", () => {
		const evs: ExtractedEvent[] = [
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "read only please", messageId: "a", seq: 2 },
			{ type: "readonly-off", category: "*", value: "*", kind: "scope", quote: "changes are fine", messageId: "b", seq: 5 },
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "actually stop changing things", messageId: "c", seq: 8 },
		]
		const results = [evs, [...evs].reverse(), [evs[1]!, evs[2]!, evs[0]!]].map((order) => {
			const l = createLedger(); applyEvents(l, order); return readOnlyActive(l)?.seq ?? null
		})
		expect(new Set(results.map(String)).size).toBe(1)
		expect(results[0]).toBe(8) // newest on (seq 8) wins
	})
	it("generic-kind revocation targets escalate to a category-wide forbid (G9 regression)", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "delete image", targets: ["payments:staging"], quote: "you can delete the payments:staging image" }], revocations: [] },
			"m0", 0, "you can delete the payments:staging image",
		))
		expect(ledgerCovers(l, "container_mutation", [T("payments:staging")]).covered).toBe(true)
		// model emits the generic kind as a "target" — must not be treated as a name
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "delete image", targets: ["images"], all: false, quote: "do not delete any images" }] },
			"m1", 1, "actually never mind, do not delete any images",
		))
		const v = ledgerCovers(l, "container_mutation", [T("payments:staging")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
		// scoped to the kind group: unrelated fs writes are untouched
		applyEvent(l, grant("write_outside", "/data/", 0))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
	})
})

describe("serialize / restore", () => {
	it("round-trips and filters entries from rewound-away messages", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/a/", 2))
		applyEvent(l, grant("write_outside", "/b/", 3))
		applyEvent(l, forbid("/c/", 4))
		l.seen.add("m2"); l.seen.add("m3"); l.seen.add("m4")
		const snap = JSON.parse(JSON.stringify(serializeLedger(l)))
		const full = deserializeLedger(snap)
		expect(full.grants).toHaveLength(2)
		expect(full.forbids).toHaveLength(1)
		expect(full.seen.size).toBe(3)
		const filtered = deserializeLedger(snap, new Set(["m2", "m4"]))
		expect(filtered.grants.map((g) => g.value)).toEqual(["/a/"])
		expect(filtered.forbids).toHaveLength(1)
		expect([...filtered.seen].sort()).toEqual(["m2", "m4"])
	})
	it("unknown version → empty ledger (backfill rebuilds)", () => {
		expect(deserializeLedger({ v: 2, grants: [] }).grants).toEqual([])
		expect(deserializeLedger("garbage").grants).toEqual([])
		expect(deserializeLedger(undefined).grants).toEqual([])
	})
})

// ---------------------------------------------------------------- revocation vs derivation
// A revocation the user made HERE has to
// survive everything this session can do afterwards — a drain re-reading the same
// message, a per-message extraction call, an import of a session that never saw the
// slash command, and a restart. The two tests below are the two halves of that: the
// guard on the door every derivation walks through, and the memory (`seen`) that keeps
// the drain from trying in the first place.

const journalDir = mkdtempSync(join(tmpdir(), "pm-ledger-revoke-"))
afterAll(() => rmSync(journalDir, { recursive: true, force: true }))

/** Two clock readings, fixed. Every expectation below is about their ORDER, never their value. */
const EARLIER = 1_000
const LATER = 5_000

function journalPath(name: string): string {
	return join(journalDir, name)
}

function journalValues(path: string): string[] {
	return (JSON.parse(readFileSync(path, "utf-8")).ledger.grants as { value: string }[]).map((g) => g.value)
}

function journalRevoked(path: string): Array<{ value: string; at: number }> {
	return JSON.parse(readFileSync(path, "utf-8")).ledger.revoked ?? []
}

function writeJournal(path: string, ledger: unknown): void {
	const r = mergeIntoGrantsFile(path, ledger, [], { sourceCwd: "/proj" })
	if (!r.ok) throw new Error(`journal write failed: ${r.error}`)
}

function readJournalLedger(path: string): unknown {
	const r = readGrantsFile(path)
	if (!r.ok) throw new Error(`journal read failed: ${r.error}`)
	return r.file.ledger
}

describe("a revocation is a wall for every derivation path (D4.1)", () => {
	it("keeps a revoked ledger grant absent through re-extraction and a re-import, and keeps its tombstone in the journal", () => {
		const ledger = createLedger()
		applyEvent(ledger, grant("write_project", "/data/x", 3))
		applyEvent(ledger, grant("write_project", "/data/keep", 4))
		expect(ledgerCovers(ledger, "write_project", [T("/data/x")]).covered).toBe(true)

		// A session that never saw the revoke — an export taken before it, or a concurrent
		// branch. This is what makes the re-import below a test rather than a no-op: the
		// file really does still offer `/data/x`.
		const path = journalPath("revoke-then-import.json")
		writeJournal(path, serializeLedger(ledger))
		expect(journalValues(path)).toEqual(["/data/x", "/data/keep"])

		// /grants revoke /data/x — one row removed, one tombstone written. The tombstone is
		// stamped after the row it takes away, because that is what a revocation IS: the user
		// withdrew it later. Every veto below is that comparison, so the clocks have to be
		// real ones and not two made-up numbers on the other side of the row's own `at`.
		const rowAt = ledger.grants.find((g) => g.value === "/data/x")!.at!
		const taken = revokeLedgerGrants(ledger, (g) => g.value === "/data/x", {
			at: rowAt + 1_000,
			quote: "/grants revoke /data/x",
		})
		expect(taken.map((r) => r.value)).toEqual(["/data/x"])
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])

		// Re-extraction. Same event from the same message (the drain re-read it), the same
		// key under a newer message with a higher seq, and the quote reworded: a re-derivation
		// is not one shape, and none of them may cross the tombstone.
		applyEvents(ledger, [
			grant("write_project", "/data/x", 3),
			grant("write_project", "/data/x", 11, "go on, /data/x"),
		])
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])
		expect(ledgerCovers(ledger, "write_project", [T("/data/x")]).covered).toBe(false)

		// Re-import the session the file came from.
		const summary = importLedger(ledger, readJournalLedger(path))
		expect(summary.revokedOnArrival).toBe(1)
		expect(summary.grantsAdded).toBe(0)
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])

		// The tombstone is still there — in the ledger and in the journal, after the ledger
		// has been written back over the file that still carried the row.
		expect(ledger.revoked?.map((r) => r.value)).toEqual(["/data/x"])
		writeJournal(path, serializeLedger(ledger))
		expect(journalRevoked(path).map((r) => r.value)).toContain("/data/x")
		expect(journalValues(path)).not.toContain("/data/x")
	})

	it("refuses only the revoked key: other targets, other categories and forbids keep flowing", () => {
		const ledger = createLedger()
		applyEvent(ledger, grant("write_project", "/data/x", 2))
		revokeLedgerGrants(ledger, (g) => g.value === "/data/x", { at: LATER })

		applyEvents(ledger, [
			grant("write_project", "/data/y", 6), // another target
			grant("write_outside", "/data/x", 7), // another category, same target
			forbid("/data/z", 8), // a deny is never refused
		])
		expect(ledger.grants.map((g) => `${g.category}:${g.value}`).sort()).toEqual([
			"write_outside:/data/x",
			"write_project:/data/y",
		])
		expect(ledger.forbids.map((f) => f.value)).toEqual(["/data/z"])
	})

	it("keeps an imported revocation as background: what the user says HERE still earns the key", () => {
		// The other side of the same rule. If a tombstone read off disk could veto a local
		// derivation, one stale file in the auto-import path would block this project's user
		// from ever re-granting that value, with /grants clear as the only way out.
		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 1))
		source.grants[0]!.at = EARLIER
		revokeLedgerGrants(source, (g) => g.value === "/data/x", { at: LATER })

		const target = createLedger()
		const summary = importLedger(target, serializeLedger(source))
		expect(summary.revocationsAdded).toBe(1)
		expect(target.revoked?.[0]?.origin).toBe("imported")

		applyEvent(target, grant("write_project", "/data/x", 5))
		expect(target.grants.map((g) => g.value)).toEqual(["/data/x"])
	})

	it("will not let an import demote a revocation made here, whatever clock the file claims", () => {
		// If the fold let the file's later timestamp win, the surviving row would arrive
		// tagged `imported`, the local guard would stop firing for that key, and the very
		// next re-extraction would walk the revoked grant back in. Ordering is the guard.
		const target = createLedger()
		applyEvent(target, grant("write_project", "/data/x", 1))
		target.grants[0]!.at = EARLIER
		revokeLedgerGrants(target, (g) => g.value === "/data/x", { at: EARLIER + 10 })

		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 7))
		source.grants[0]!.at = LATER + 1_000 // re-earned over there, after their revoke
		source.revoked = [{ category: "write_project", value: "/data/x", kind: "entity", at: LATER + 1_000 }]

		importLedger(target, serializeLedger(source))
		expect(target.revoked?.[0]?.origin).toBeUndefined() // ours is still ours
		expect(target.grants).toEqual([]) // their row was refused at the door
		applyEvent(target, grant("write_project", "/data/x", 12))
		expect(target.grants).toEqual([]) // and the guard still fires
	})
})

describe("taking a forbid back (W49b: /grants revoke on a deny row)", () => {
	/** One sentence, derived the way the drain derives it. Reused because the property under test
	 *  is "the same message cannot put it back", which only exists at this entry point. */
	const searchQuote = "you will not fucking search in /home/u/dev"
	const searchPayload = { grants: [], revocations: [{ action: "search", targets: ["/home/u/dev"], all: false, quote: searchQuote }] }
	const drainSearch = (l: Ledger) => applyEvents(l, eventsFromExtraction(searchPayload as never, "m1", 1, searchQuote))

	it("removes the rows it matched and hands them back with the sentence behind them", () => {
		const l = createLedger()
		drainSearch(l)
		expect(l.forbids.length).toBeGreaterThan(0)
		const taken = revokeLedgerForbids(l, (f) => f.value === "/home/u/dev/", { quote: "/grants revoke /home/u/dev" })
		expect(taken.map((f) => f.value)).toEqual(["/home/u/dev/"])
		// The row carries the user's own words; the caller prints them, so it needs the row and not
		// just a count. A revoke that reports only a number cannot say WHICH sentence stopped.
		expect(taken[0]!.quote).toBe(searchQuote)
		expect(l.forbids.some((f) => f.value === "/home/u/dev/")).toBe(false)
		expect(l.revokedForbids?.map((r) => r.value)).toEqual(["/home/u/dev/"])
	})

	it("stays gone when the very same message is drained again", () => {
		// The acceptance property, and the whole reason this function exists: before this fix the row
		// was spliced out of ledger.forbids by nothing at all, and even a hand-deleted one came back
		// on the next drain because the tombstone gate looked only at grant keys.
		const l = createLedger()
		drainSearch(l)
		expect(l.forbids.length).toBeGreaterThan(0)
		revokeLedgerForbids(l, () => true, { quote: "/grants revoke /home/u/dev" })
		expect(l.forbids).toEqual([])
		const blockedBefore = extractionStats.forbidRevocationsBlocked
		drainSearch(l)
		drainSearch(l)
		expect(l.forbids).toEqual([])
		// Every re-derivation was stopped at the door. How MANY rows one sentence derives is the
		// derivation tests' business (see the derivation table below); this one only claims none of them got in.
		expect(extractionStats.forbidRevocationsBlocked - blockedBefore).toBeGreaterThanOrEqual(1)
	})

	it("revokes exactly the value pointed at, never the row beside it", () => {
		// Same narrow key the grant side uses. Revoking one file must not fall over the folder grant
		// next to it, and here the mirror image: cancelling one ban must not cancel another.
		const l = createLedger()
		applyEvents(l, [forbid("/data/x", 1), forbid("/data/keep", 2)])
		const taken = revokeLedgerForbids(l, (f) => f.value === "/data/x", { at: LATER })
		expect(taken.map((f) => f.value)).toEqual(["/data/x"])
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/keep"])
		expect(l.revokedForbids?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("records nothing when it matched nothing: a failed revoke must not become a standing ban", () => {
		const l = createLedger()
		applyEvent(l, forbid("/data/keep", 1))
		expect(revokeLedgerForbids(l, (f) => f.value === "/nope", { at: LATER })).toEqual([])
		expect(l.revokedForbids).toEqual([])
		applyEvent(l, forbid("/data/keep", 3)) // nothing is walled off, so the row still lands
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/keep"])
	})

	it("never reaches across to the allow side: a grant of the same key still lands", () => {
		// The reason the tombstones live in two lists. rowIdentity has no type field, so a shared
		// list would make this revoke delete a grant that happened to carry the same
		// {category,value,kind} — cancelling a DENY would silently remove an ALLOW.
		const l = createLedger()
		applyEvent(l, forbid("/data/x", 1, "do not touch /data/x", "write_outside"))
		revokeLedgerForbids(l, () => true, { at: LATER })
		expect(l.revoked?.length ?? 0).toBe(0)
		applyEvent(l, grant("write_outside", "/data/x", 5, "you can write /data/x"))
		expect(l.grants.map((g) => g.value)).toEqual(["/data/x"])
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
		const blockedBefore = extractionStats.revocationBlocked
		// Same key, re-derived: the grant side of the wall is the list `revoked`, and this key is in
		// neither wall, so it lands and the grant counter does not move.
		applyEvent(l, grant("write_outside", "/data/x", 7, "write /data/x again"))
		expect(l.grants.length).toBe(1)
		expect(l.grants[0]!.seq).toBe(7)
		expect(extractionStats.revocationBlocked - blockedBefore).toBe(0)
	})

	it("keeps grant revocation behaving exactly as it did: a revoked grant is still walled, a revoked grant does not wall a forbid", () => {
		const l = createLedger()
		const blockedBefore = extractionStats.revocationBlocked
		const forbidBlockedBefore = extractionStats.forbidRevocationsBlocked
		applyEvent(l, grant("write_outside", "/data/x", 2))
		revokeLedgerGrants(l, (g) => g.value === "/data/x", { at: LATER })
		applyEvent(l, grant("write_outside", "/data/x", 9))
		expect(l.grants).toEqual([])
		expect(extractionStats.revocationBlocked - blockedBefore).toBe(1)
		// The other direction of the same wall being two walls.
		applyEvent(l, forbid("/data/x", 9, "do not touch /data/x", "write_outside"))
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/x"])
		expect(l.revokedForbids).toEqual([])
		expect(extractionStats.forbidRevocationsBlocked - forbidBlockedBefore).toBe(0)
	})

	it("survives the snapshot round trip, so /grants clear is not the only way out after a reload", () => {
		const l = createLedger()
		drainSearch(l)
		revokeLedgerForbids(l, () => true, { quote: "/grants revoke /home/u/dev" })
		const blob = JSON.parse(JSON.stringify(serializeLedger(l)))
		expect(blob.revokedForbids?.length).toBeGreaterThan(0)
		const back = deserializeLedger(blob)
		expect(back.forbids).toEqual([])
		expect(back.revokedForbids?.length).toBeGreaterThan(0)
		expect(back.revokedForbids?.[0]?.origin).toBeUndefined() // said HERE, not read off a file
		drainSearch(back)
		expect(back.forbids).toEqual([])
	})

	it("applies a file's own forbid revocations on read, so a stale blob cannot resurrect the ban", () => {
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		revokeLedgerForbids(source, () => true, { at: LATER })
		// A blob written by a writer that forgot to splice: the row AND its tombstone, same key.
		const blob = serializeLedger(source)
		;(blob as { forbids: unknown[] }).forbids = [{ category: "*", value: "/data/x", kind: "entity", quote: "do not touch /data/x", messageId: "m1", seq: 1, at: EARLIER }]
		const restored = deserializeLedger(blob)
		expect(restored.forbids).toEqual([])
		expect(restored.revokedForbids?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("refuses at the door an imported forbid this session already revoked, and says so", () => {
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		const offered = serializeLedger(source)

		const target = createLedger()
		applyEvent(target, forbid("/data/x", 1))
		revokeLedgerForbids(target, () => true, { at: LATER })
		const summary = importLedger(target, offered)
		expect(summary.forbidsAdded).toBe(0)
		expect(summary.forbidsRefusedHere).toBe(1)
		expect(target.forbids).toEqual([])
	})

	it("keeps a file's revocation as background: the ban it cancelled is not a ban THIS session may not re-derive", () => {
		// The imported-revocation asymmetry, mirrored for forbids. A tombstone that arrived from a
		// journal filters the rows that travel with it, but it must not veto a sentence the user says
		// here, or one stale file would need /grants clear to overcome.
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		source.forbids[0]!.at = EARLIER
		revokeLedgerForbids(source, () => true, { at: LATER })

		const target = createLedger()
		importLedger(target, serializeLedger(source))
		expect(target.revokedForbids).toEqual([]) // not folded in: background authority cannot veto here
		applyEvent(target, forbid("/data/x", 4))
		expect(target.forbids.map((f) => f.value)).toEqual(["/data/x"])
	})

	it("pins 2514c8d and eval case L-02: a revocation stays at least as wide as the grant it revokes", () => {
		// FORBID_FAMILIES folds fs-write / fs-delete / fs-perm into one fs-mutation family, so a
		// revocation recorded against ONE mutation category still dominates every other one. L-02
		// produced a TRUE false allow when a named revocation stored only its own narrow category
		// while the grant it took back was a folder scope, and 2514c8d wrote the rule that a
		// revocation must be at least as wide as the grant it revokes. The fold stays for this
		// reason even though the same fold is what made one permission-files sentence over-block;
		// the fix for an over-general rule is not to delete it. Narrow the fold and this test goes
		// red before the false allow comes back.
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 3, "you can write anything under /data/", "scope"))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
		// The revocation lands on the destruction side of the family; the grant it takes back is on
		// the content side. That crossing is the whole point of the fold.
		applyEvent(l, { type: "forbid", category: "delete_recursive", value: "/data/", kind: "scope", quote: "stop, that is enough with /data/", messageId: "m9", seq: 9 })
		const v = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
		expect(v.reason).toContain("stop, that is enough")
	})
})

describe("seen travels with the ledger (D4.2)", () => {
	it("restores `seen` across an import so the drain skips old messages, and still lands a genuinely new grant", () => {
		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 3))
		// `seen` is written by the drain layer (gate-bridge.syncLedger), not by applyEvent.
		source.seen.add("m3")
		source.seen.add("m4") // extracted, said nothing
		const blob = serializeLedger(source)

		const target = createLedger()
		const summary = importLedger(target, blob)
		expect(summary.grantsAdded).toBe(1)
		expect(summary.seenImported).toBe(2)
		expect([...target.seen].sort()).toEqual(["m3", "m4"])

		// Direction 1 — no re-derivation. This is the exact filter syncLedger() runs
		// (`refs.filter(r => !ledger.seen.has(r.id))`) over the ids of the branch.
		const refs = ["m3", "m4", "m9"]
		expect(refs.filter((id) => !target.seen.has(id))).toEqual(["m9"])

		// Direction 2 — the message the file had not read still earns its grant.
		applyEvent(target, grant("write_project", "/data/new", 9))
		expect(target.grants.map((g) => g.value)).toEqual(["/data/x", "/data/new"])
		expect(ledgerCovers(target, "write_project", [T("/data/new")]).covered).toBe(true)
		expect(ledgerCovers(target, "write_project", [T("/data/x")]).covered).toBe(true)
	})

	it("is idempotent and union, not a replacement: a local `seen` survives an import", () => {
		const target = createLedger()
		applyEvent(target, grant("write_project", "/local", 1))
		target.seen.add("m1")
		const source = createLedger()
		applyEvent(source, grant("write_project", "/from/file", 2))
		source.seen.add("m2")

		expect(importLedger(target, serializeLedger(source)).seenImported).toBe(1)
		expect(importLedger(target, serializeLedger(source)).seenImported).toBe(0)
		expect([...target.seen].sort()).toEqual(["m1", "m2"])
	})
})

/** Derivation is the only place where a sentence becomes authority, so it is tested through
 *  `eventsFromExtraction` — the entry point the drain calls — and not through the helpers below it.
 *  A unit test on `mapActionToCategory` alone could not tell a wrong category from a wrong target,
 *  and the two defects this block exists for are both target defects wearing category clothes. */
describe("derivation: the keyword must not fire on the noun, and a named thing is not a category (W49b A+B)", () => {
	const derive = (sentence: string, rev: { action: string; targets?: string[]; all?: boolean }) =>
		eventsFromExtraction({ grants: [], revocations: [{ action: rev.action, targets: rev.targets ?? [], all: rev.all === true, quote: sentence }] } as never, "m1", 1, sentence)

	// One path space for the whole block: the sentences talk about real paths under this home, and
	// the matchers need the same root layer 0 would hand them.
	const HOME = "/home/u"
	const PROJECT = "/home/u/dev/pm"

	const table = [
		{
			sentence: "I do not want to use ANY permission files",
			rev: { action: "use permission files", targets: [], all: true },
			// The bug: the noun `permission` bought the privilege category, the no-target fallback
			// bought value "*", and the fs-mutation family fold turned that into a ban on every write
			// and recursive delete in the workspace; the matchers below are the reproduction.
			mustNot: (r: { category: string; value: string }[]) =>
				r.some((e) => e.category === "perm_change" && e.value === "*") || r.some((e) => e.category === "*" && e.value === "*"),
			// It derives RULE-FILE-SCOPED rows, not a posture row: the sentence names files, and a
			// class the user's own words named is a target. Two rows because the class has two homes —
			// the global rule file and the project's rule directory — and each appears exactly once.
			must: (r: { type: string; value: string; quote: string }[]) =>
				r.length === 2 &&
				r.every((e) => e.type === "forbid" && e.value !== "*" && e.quote === "I do not want to use ANY permission files") &&
				r.some((e) => e.value.endsWith("adaptive-acl.json")) &&
				r.some((e) => e.value.includes(".pi/projects/")),
		},
		{
			sentence: "you will not fucking search in /home/u/dev",
			rev: { action: "search", targets: ["/home/u/dev"], all: false },
			// category "*" here means the prefix contains the project, so a sentence about reading
			// outside the repo blocked writing a file inside it. Two rows for one sentence on top.
			mustNot: (r: { category: string }[]) => r.length > 1 || r.some((e) => e.category === "*"),
			must: (r: { category: string; value: string; kind: string }[]) =>
				r.length === 1 && r[0]!.category === "read_only" && r[0]!.kind === "scope" && r[0]!.value === "/home/u/dev/",
		},
		{
			sentence: "no writes anywhere, ever",
			rev: { action: "write files", targets: [], all: true },
			// The fix must not neuter a real posture: a sentence that names no target keeps its
			// category-wide scope, exactly as it had it.
			mustNot: () => false,
			must: (r: { category: string; value: string }[]) =>
				r.length === 1 && r[0]!.value === "*" && (r[0]!.category === "write_outside" || r[0]!.category === "write_project"),
		},
		{
			sentence: "chmod is not allowed on any file",
			rev: { action: "chmod", targets: [], all: true },
			// The keyword still works where it belongs: an ACL verb is an ACL sentence.
			mustNot: () => false,
			must: (r: { category: string; value: string }[]) => r.length === 1 && r[0]!.category === "perm_change" && r[0]!.value === "*",
		},
	]

	it.each(table)("$sentence", ({ sentence, rev, mustNot, must }) => {
		const rows = derive(sentence, rev)
		expect(mustNot(rows)).toBe(false)
		expect(must(rows)).toBe(true)
	})

	it("keeps the ACL verb requirement honest in both directions", () => {
		// The noun alone must not select the privilege category, and the verbs must still select it.
		expect(mapActionToCategory("permission files")).toBeUndefined()
		expect(mapActionToCategory("rule files")).toBeUndefined()
		expect(mapActionToCategory("use permission files")).toBeUndefined()
		expect(mapActionToCategory("chmod")).toBe("perm_change")
		expect(mapActionToCategory("chown the folder")).toBe("perm_change")
		expect(mapActionToCategory("setfacl")).toBe("perm_change")
		expect(mapActionToCategory("grant write access")).toBe("perm_change")
		// …and a plain read sentence is still a read sentence, ACL row above it or not.
		expect(mapActionToCategory("read files")).toBe("read_only")
	})

	it("derives a target for a class sentence: no value '*' row comes from a sentence that named a thing", () => {
		const rows = derive("stop writing permissions.json", { action: "permission files", targets: [], all: true })
		expect(rows.length).toBeGreaterThan(0)
		expect(rows.some((e) => e.value === "*")).toBe(false)
		expect(rows.some((e) => e.category === "perm_change")).toBe(false)
	})

	it("never turns a complaint about searching into a session-wide read ban", () => {
		// The counterweight, and the reason search verbs are NOT in the action table: a BLANKET search
		// complaint would then map to a category and take the category-wide fallback, prompting for
		// every read in the session. Same over-block, other side of the same sentence.
		const rows = derive("you will not search half a tb of files in my home to find clues", { action: "search home", targets: [], all: true })
		expect(rows.some((e) => e.category === "read_only" && e.value === "*")).toBe(false)
		expect(rows.every((e) => e.type === "readonly-on" || e.category.startsWith("*"))).toBe(true)
	})

	it("keeps 'do not touch X' wide, because the sentence named no action at all", () => {
		// category "*" survives where it always meant something: a named target with no action class.
		// Narrowing THIS to one category would be a deny-loosening the ticket does not ask for.
		const rows = derive("do not touch ~/backups", { action: "touch", targets: ["~/backups"], all: false })
		expect(rows.every((e) => e.category === "*")).toBe(true)
		expect(rows.map((e) => e.value)).toEqual(["~/backups", "~/backups/"])
	})

	it("keeps a read ban from outranking a write inside the prefix it names", () => {
		// The user-visible defect, pinned at the MATCHER rather than at the row shape: a folder grant
		// for the project, plus the derived read-only forbid whose prefix contains that project.
		// Before the fix the first pair of assertions came back `forbidden`, quoting the search sentence
		// as the reason a file inside the repo could not be written.
		const sentence = "you will not fucking search in /home/u/dev"
		const l = createLedger()
		applyEvent(l, grant("write_project", "/home/u/dev/pm/", 0, "you can write under /home/u/dev/pm/", "scope"))
		applyEvent(l, grant("read_only", "/home/u/dev/pm/", 0, "you can read under /home/u/dev/pm/", "scope"))
		applyEvents(l, derive(sentence, { action: "search", targets: ["/home/u/dev"], all: false }))

		const inside = [T("/home/u/dev/pm/corpus/STATE.md")]
		const write = ledgerCovers(l, "write_project", inside)
		expect(write.forbidden).toBe(false)
		expect(write.covered).toBe(true)

		// …and the read the sentence DID forbid is still blocked at the very same path. The ban is the
		// NEWER statement here (the user permitted the folder first, then refused the search), which is
		// the sequence the complaint was about; a ban older than a grant is lifted by it, by design.
		const read = ledgerCovers(l, "read_only", inside)
		expect(read.covered).toBe(false)
		expect(read.forbidden).toBe(true)
		expect(read.reason).toContain("search")
	})

	it("derives one row per named location for a read sentence, not the entity-plus-subtree pair", () => {
		const rows = derive("do not read anything in /etc", { action: "read files", targets: ["/etc"], all: false })
		expect(rows).toHaveLength(1)
		expect(rows[0]).toEqual(expect.objectContaining({ type: "forbid", category: "read_only", value: "/etc/", kind: "scope" }))

		// The shape comes from the name: an extension means a file, so the row names the file rather
		// than a `<file>/` prefix that could only ever match itself.
		const file = derive("do not read ~/.kube/config.json", { action: "read files", targets: ["~/.kube/config.json"], all: false })
		expect(file).toHaveLength(1)
		expect(file[0]).toEqual(expect.objectContaining({ value: "~/.kube/config.json", kind: "entity" }))

		// What the heuristic cannot know: `credentials` has no extension, so it is spelled as a place.
		// Pinned because it is a CHOICE, not an accident — a prefix row still covers the file itself
		// (`valueCovers` reads `t + "/"` as containing `t`), so the ban is no weaker, only its spelling
		// in `/grants` is. A future "fix" that makes this an entity row must say what it costs.
		const noExtension = derive("do not read ~/.aws/credentials", { action: "read files", targets: ["~/.aws/credentials"], all: false })
		expect(noExtension).toHaveLength(1)
		expect(noExtension[0]).toEqual(expect.objectContaining({ value: "~/.aws/credentials/", kind: "scope" }))
		const l = createLedger()
		applyEvents(l, noExtension)
		expect(ledgerCovers(l, "read_only", [T("/home/u/.aws/credentials")], "/home/u").forbidden).toBe(true)
	})

	it("leaves a mutation sentence's pair exactly as eval case L-02 pinned it", () => {
		const rows = derive("do not delete anything under ~/scratch-data", { action: "delete files", targets: ["~/scratch-data"], all: false })
		expect(rows.map((e) => `${e.category}:${e.value}:${e.kind}`)).toEqual(["*:~/scratch-data:entity", "*:~/scratch-data/:scope"])
	})

	it("lets the allow-tier scan tell a read ban from a mutation ban, and keeps the old default", () => {
		// An in-project write is ALLOW-tier, so it never reaches ledgerCovers' forbid comparison at
		// all — the named-forbid scan is what decides, which is why the row shape alone was never the
		// whole fix. `pendingCategory` is optional: absent, the scan is exactly as blind as it has ever
		// been, and a caller that has not been updated cannot silently loosen anything. That is pinned
		// here rather than assumed, because a half-wired fix looks finished.
		const l = createLedger()
		applyEvents(l, derive("you will not fucking search in /home/u/dev", { action: "search", targets: ["/home/u/dev"], all: false }))
		const inside = [T("/home/u/dev/pm/corpus/STATE.md")]
		expect(namedForbidCovers(l, inside, HOME, PROJECT)).not.toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "write_project")).toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only")).not.toBeNull()
		// A compound that mutates anything keeps every ban: fail-closed is the tie-break, not the
		// exception. `read_secret` is a read, so a read_secret ban binds a read_secret action too.
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only+write_project")).not.toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only+read_secret")).not.toBeNull()
	})

	it("narrows only read-shaped rows: 'do not touch X' still downgrades an allowed write", () => {
		const l = createLedger()
		applyEvents(l, derive("do not touch ~/backups", { action: "touch", targets: ["~/backups"], all: false }))
		expect(namedForbidCovers(l, [T("/home/u/backups/ledger.ts")], HOME, PROJECT, "write_project")).not.toBeNull()
		expect(namedForbidCovers(l, [T("/home/u/backups/ledger.ts")], HOME, PROJECT, "delete_recursive")).not.toBeNull()
	})
})

