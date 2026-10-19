/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Restoring a session blob. The rule this file pins: a restore COPIES
 * a row, it does not re-decide one.
 *
 * The behaviour under test used to be safe by accident. Restore rebuilt each row with
 * `addGrant(...)`, which throws away the stored `at` and stamps "now" — and because the
 * restore path read the NEWEST snapshot, whose rows had already been removed by the
 * revoke, nothing visibly broke. Two properties were still unguarded underneath: a restore
 * that picks an older snapshot re-earns a revoked row with a brand-new timestamp, and a
 * stored "always" comes back as a this-session-only row. Both are ordering bugs, and
 * ordering is exactly what a revocation is decided by — `revocationVetoes` compares the
 * row's `at` against the tombstone's, breaking a tie toward the revocation.
 *
 * So the tests below are written to fail if `at` were invented: each one states which
 * timestamp a row must carry, and the veto test only holds because it does.
 */
import { describe, expect, it } from "vitest"

import {
	createGrantStore,
	deserializeGrants,
	restoreGrantRows,
	revokeRows,
	serializeGrants,
	addGrant,
	type GrantRevocation,
	type SessionGrant,
} from "./session-grants.ts"

/** Two clock readings. Every expectation here is about their ORDER, never their value. */
const EARLIER = 1_000
const LATER = 5_000

function row(value: string, at = EARLIER, extra: Partial<SessionGrant> = {}): SessionGrant {
	return { category: "write_project", value, kind: "entity", at, ...extra }
}

function tombstone(value: string, at = LATER, extra: Partial<GrantRevocation> = {}): GrantRevocation {
	return { category: "write_project", value, kind: "entity", at, ...extra }
}

function plain(value: string, at = EARLIER): Record<string, unknown> {
	return { category: "write_project", value, kind: "entity", at }
}

describe("restoring session grants passes the stored payload through (D5)", () => {
	it("keeps the stored `at` and `durable` instead of stamping a new one", () => {
		const store = createGrantStore()
		const r = restoreGrantRows(store, [
			plain("/data/x", EARLIER),
			{ category: "write_project", value: "/data/y", kind: "scope", at: LATER, durable: true },
		])
		expect(r).toEqual({ restored: 2, refused: 0, dropped: 0 })
		expect(store.grants.map((g) => [g.value, g.at, g.kind, g.durable])).toEqual([
			["/data/x", EARLIER, "entity", undefined],
			["/data/y", LATER, "scope", true],
		])
		// The line that fails if a restore re-derives `at` from the current clock: these rows
		// were earned long before this test ran, and they have to say so afterwards.
		expect(store.grants[0]!.at).toBe(EARLIER)
		expect(store.grants[0]!.at).toBeLessThan(Date.now())
		// …and the line that fails if a restore forgets `durable`: an "always" that resumes
		// as "this session only" silently drops the row from the journal forever.
		expect(store.grants[1]!.durable).toBe(true)
	})

	it("keeps a revoked grant revoked when the snapshot it came from is older than the revoke", () => {
		// THE ordering test. A snapshot taken before the revoke still holds the row, with the
		// `at` it was earned at. Revocation ordering breaks the tie by comparing exactly those
		// two timestamps, so passing the payload through is what makes the veto hold whichever
		// snapshot a restore picks. Fabricate `at: Date.now()` here and the row looks re-earned
		// after the revocation, comes back, and the user's `/grants revoke` has silently undone
		// itself — while every current caller happens to read the newest snapshot.
		const store = createGrantStore()
		store.revoked = [tombstone("/data/x", LATER)]
		const olderSnapshot = JSON.stringify([plain("/data/x", EARLIER)])

		expect(restoreGrantRows(store, olderSnapshot)).toEqual({ restored: 0, refused: 1, dropped: 0 })
		expect(store.grants).toEqual([])
		expect(store.revoked?.map((t) => t.value)).toEqual(["/data/x"])

		// The other side of the ordering: a row the user re-earned AFTER the revocation is
		// newer than the tombstone, so it is history, not a veto — and it is only recognised as
		// newer because its own timestamp survived.
		const reGranted = JSON.stringify([{ ...plain("/data/x", LATER + 10), durable: true }])
		expect(restoreGrantRows(store, reGranted)).toEqual({ restored: 1, refused: 0, dropped: 0 })
		expect(store.grants.map((g) => [g.value, g.at, g.durable])).toEqual([["/data/x", LATER + 10, true]])

		// A row restored this way can be revoked again, and the new tombstone stamps from it.
		expect(revokeRows(store, (g) => g.value === "/data/x", { at: LATER + 20 }).map((t) => t.at)).toEqual([
			LATER + 20,
		])
	})

	it("reads both blob shapes and honours the revocations carried inside the blob", () => {
		// The `{grants, revoked}` object is one unit: a row in this blob is judged against the
		// revocations in this blob, so the order of the two reads inside the function matters.
		const store = createGrantStore()
		const blob = JSON.stringify({
			grants: [plain("/data/x", EARLIER), plain("/keep", EARLIER)],
			revoked: [tombstone("/data/x", LATER)],
		})
		expect(restoreGrantRows(store, blob)).toEqual({ restored: 1, refused: 1, dropped: 0 })
		expect(store.grants.map((g) => g.value)).toEqual(["/keep"])
		expect(store.revoked?.map((t) => t.value)).toEqual(["/data/x"])

		// A bare array — what every build before revocations wrote — has nothing to veto.
		const legacy = createGrantStore()
		expect(restoreGrantRows(legacy, JSON.stringify([plain("/old", EARLIER)]))).toEqual({
			restored: 1,
			refused: 0,
			dropped: 0,
		})
		expect(legacy.grants[0]!.at).toBe(EARLIER)
		expect(legacy.revoked).toEqual([])
	})

	it("reports what it refused, what it dropped and what it could not read", () => {
		const store = createGrantStore()
		store.revoked = [tombstone("/data/x", LATER)]
		addGrant(store, "write_project", "/already/here", "entity")
		const r = restoreGrantRows(store, [
			plain("/data/x", EARLIER), // refused: a revocation still vetoes it
			plain("/already/here", LATER), // dropped: the key is already in the store
			{ category: "write_project", kind: "entity", at: EARLIER }, // dropped: no target
			{ value: "/no/category", kind: "entity", at: EARLIER }, // dropped: no category
			plain("/fresh", EARLIER),
		])
		expect(r).toEqual({ restored: 1, refused: 1, dropped: 3 })
		expect(store.grants.map((g) => g.value).sort()).toEqual(["/already/here", "/fresh"])

		// Garbage is nothing to restore, not a crash.
		const quiet = createGrantStore()
		expect(restoreGrantRows(quiet, "not json")).toEqual({ restored: 0, refused: 0, dropped: 0 })
		expect(restoreGrantRows(quiet, undefined)).toEqual({ restored: 0, refused: 0, dropped: 0 })
		expect(quiet.grants).toEqual([])
	})

	it("applies the vetoes on the read itself, the way the ledger half already does", () => {
		// A writer that left a vetoed row in place — an older snapshot, or a hand-edited file —
		// is refused here rather than hoped about downstream. `deserializeGrants` and
		// `restoreGrantRows` are one door, so both inherit it.
		const blob = JSON.stringify({
			grants: [plain("/vetoed", EARLIER), plain("/kept", EARLIER)],
			revoked: [tombstone("/vetoed", LATER)],
		})
		const store = deserializeGrants(blob)
		expect(store.grants.map((g) => g.value)).toEqual(["/kept"])
		expect(store.revoked?.map((t) => t.value)).toEqual(["/vetoed"])

		// A row re-earned after the revocation still comes back through the same door.
		const reEarned = createGrantStore()
		reEarned.revoked = [tombstone("/vetoed", LATER)]
		expect(restoreGrantRows(reEarned, [plain("/vetoed", LATER + 1)]).restored).toBe(1)
	})

	it("round-trips a store that revoked something, keeping both rows' timestamps", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		addGrant(store, "write_project", "/data/keep", "entity", true)
		const before = store.grants.map((g) => [g.value, g.at, g.durable])
		const restored = deserializeGrants(serializeGrants(store))
		expect(restored.grants.map((g) => [g.value, g.at, g.durable])).toEqual(before)
		expect(restored.grants.map((g) => g.at)).toEqual(before.map(([, at]) => at))
	})
})
