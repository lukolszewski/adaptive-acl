/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { afterAll, describe, expect, it } from "vitest"
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	GRANTS_FILE_V,
	buildGrantsFile,
	mergeIntoGrantsFile,
	readGrantsFile,
	writeGrantsFile,
	type GrantsFile,
} from "./grants-file.ts"
import type { SessionGrant } from "./session-grants.ts"
import { createGrantStore, grantsCover, importSessionGrants } from "./session-grants.ts"
import { NO_OBJECT_TARGET } from "./grant-verify.ts"

const tmp = mkdtempSync(join(tmpdir(), "pm-journal-"))
const at = (name: string) => join(tmp, name)

/** Stand-in for `serializeLedger()` output — the merge never looks inside it. */
const ledgerOf = (values: string[]) => ({
	v: 1,
	grants: values.map((value) => ({ category: "write_project", value, kind: "entity", seq: 1 })),
	forbids: [],
	seen: [],
})

function row(
	value: string,
	atMs = 1_000,
	extra: Partial<SessionGrant> = {},
): SessionGrant {
	return { category: "write_project", value, kind: "entity", at: atMs, ...extra }
}

function load(path: string): GrantsFile {
	const read = readGrantsFile(path)
	if (!read.ok) throw new Error(`journal unreadable: ${read.error}`)
	return read.file
}

const EMPTY_LEDGER = { v: 1, grants: [], forbids: [], seen: [] }

function ledgerRows(file: GrantsFile): string[] {
	const ledger = file.ledger as { grants?: { value: string }[] }
	return (ledger.grants ?? []).map((g) => g.value)
}

describe("mergeIntoGrantsFile — merging", () => {
	it("creates a journal that does not exist yet, parents included", () => {
		const p = at("fresh/deep/journal.json")
		const r = mergeIntoGrantsFile(p, ledgerOf(["/a"]), [row("/a")])
		expect(r).toMatchObject({ ok: true, written: 1, added: 1, dropped: 0 })
		expect(load(p).grants.map((g) => g.value)).toEqual(["/a"])
		expect(load(p).v).toBe(GRANTS_FILE_V)
	})

	it("is idempotent: writing the same answers again adds nothing", () => {
		const p = at("twice.json")
		const first = mergeIntoGrantsFile(p, ledgerOf([]), [row("/a"), row("/b")])
		const second = mergeIntoGrantsFile(p, ledgerOf([]), [row("/a"), row("/b")])
		expect(first.added).toBe(2)
		expect(second.added).toBe(0)
		expect(second.written).toBe(2)
		expect(load(p).grants.map((g) => g.value).sort()).toEqual(["/a", "/b"])
	})

	it("keeps the rows of both journals when two sessions share one file", () => {
		const p = at("two-sessions.json")
		// Session A earned /a, session B earned /b — neither sees the other's store.
		mergeIntoGrantsFile(p, ledgerOf(["/from-A"]), [row("/a")])
		const b = mergeIntoGrantsFile(p, ledgerOf(["/from-B"]), [row("/b", 2_000)])
		expect(b.added).toBe(1)
		expect(load(p).grants.map((g) => g.value).sort()).toEqual(["/a", "/b"])
	})

	it("never deletes: rows the incoming set does not mention are kept", () => {
		const p = at("keep.json")
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/mine"), row("/theirs")])
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [])
		expect(r).toMatchObject({ ok: true, added: 0, written: 2 })
		expect(load(p).grants.map((g) => g.value)).toEqual(["/mine", "/theirs"])
	})

	it("keeps the newest sighting of a key, but never drops an older 'always'", () => {
		const p = at("fold.json")
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/x", 1_000, { durable: true })])
		// A later session re-approved the same target without knowing it was an "always".
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/x", 2_000)])
		const [x] = load(p).grants
		expect(x.at).toBe(2_000)
		expect(x.durable).toBe(true)

		// And the other way round: an older durable row still sticks onto the newer one.
		const q = at("fold-older.json")
		mergeIntoGrantsFile(q, ledgerOf([]), [row("/y", 5_000)])
		mergeIntoGrantsFile(q, ledgerOf([]), [row("/y", 4_000, { durable: true })])
		const [y] = load(q).grants
		expect(y.at).toBe(5_000)
		expect(y.durable).toBe(true)
	})

	it("counts the values that can never match a target and keeps them out", () => {
		const p = at("prune.json")
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [
			row("/real/target"),
			row("select(.type!=null) | .type"),
			row("$(git rev-parse --git-dir)/info/exclude"),
			row(""),
		])
		expect(r.dropped).toBe(3)
		expect(r.written).toBe(1)
		expect(load(p).grants.map((g) => g.value)).toEqual(["/real/target"])
	})

	it("drops rows too broken to match instead of laundering them into the journal", () => {
		const p = at("broken-rows.json")
		writeFileSync(
			p,
			JSON.stringify({ v: GRANTS_FILE_V, exportedAt: "x", sourceCwd: "/c", ledger: {}, grants: [{ category: "write_project" }] }),
			"utf-8",
		)
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [row("/keep")])
		expect(r.ok).toBe(true)
		expect(r.dropped).toBe(1)
		expect(load(p).grants.map((g) => g.value)).toEqual(["/keep"])
	})
})

describe("mergeIntoGrantsFile — refusing to destroy what is there", () => {
	it("leaves an unparsable journal byte-identical and says why", () => {
		const p = at("corrupt.json")
		writeFileSync(p, "{ not json at all", "utf-8")
		const before = readFileSync(p, "utf-8")
		const r = mergeIntoGrantsFile(p, ledgerOf(["/a"]), [row("/a")])
		expect(r.ok).toBe(false)
		expect(r.error).toContain("not valid JSON")
		expect(readFileSync(p, "utf-8")).toBe(before)
		expect(readdirSync(tmp).filter((f) => f.startsWith("corrupt.json.tmp-"))).toEqual([])
	})

	it("refuses a journal written by another version", () => {
		const p = at("v9.json")
		writeFileSync(p, JSON.stringify({ v: 9, grants: [], ledger: {} }), "utf-8")
		const before = readFileSync(p, "utf-8")
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [row("/a")])
		expect(r.ok).toBe(false)
		expect(r.error).toContain("version")
		expect(readFileSync(p, "utf-8")).toBe(before)
	})

	it("refuses a file that parses but is not a journal", () => {
		const p = at("not-a-journal.json")
		writeFileSync(p, JSON.stringify({ v: GRANTS_FILE_V, ledger: {} }), "utf-8")
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [row("/a")])
		expect(r.ok).toBe(false)
		expect(r.error).toContain("grants[]")
		expect(existsSync(p)).toBe(true)
		expect(readFileSync(p, "utf-8")).toContain('"ledger"')
	})

	it("writes nowhere but the exact path it was handed — no defaulting, no `~`", () => {
		const unresolved = "~/journal-should-not-exist.json"
		const r = mergeIntoGrantsFile(unresolved, ledgerOf([]), [row("/a")])
		expect(r.ok).toBe(false)
		expect(r.error).toContain("~")
		expect(existsSync(join(process.cwd(), "~", "journal-should-not-exist.json"))).toBe(false)
		expect(mergeIntoGrantsFile("   ", ledgerOf([]), [row("/a")]).ok).toBe(false)
	})
})

describe("mergeIntoGrantsFile — the rest of the file", () => {
	it("keeps the journal's ledger half when the caller has nothing to say", () => {
		const p = at("ledger-half.json")
		mergeIntoGrantsFile(p, ledgerOf(["/from-ledger"]), [row("/a")])
		mergeIntoGrantsFile(p, undefined, [row("/b")])
		expect(ledgerRows(load(p))).toEqual(["/from-ledger"])

		// This half of the expectation reads as it does because revocation is a ROW: a real snapshot is now
		// UNIONED with the half on disk, because replacing it silently deleted a concurrent session's
		// addition. What makes union safe is `revoked` — a row another session took back is
		// vetoed by its revocation on the way out. See tombstones.test.ts.
		mergeIntoGrantsFile(p, ledgerOf(["/new"]), [])
		expect(ledgerRows(load(p)).sort()).toEqual(["/from-ledger", "/new"])
	})

	it("starts a ledger-less journal with an empty snapshot the reader accepts", () => {
		const p = at("no-ledger.json")
		expect(mergeIntoGrantsFile(p, null, [row("/a")]).ok).toBe(true)
		expect(load(p).ledger).toEqual(EMPTY_LEDGER)
	})

	it("keeps sourceCwd from the journal unless the caller restates it", () => {
		const p = at("cwd.json")
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/a")], { sourceCwd: "/project/a" })
		expect(load(p).sourceCwd).toBe("/project/a")
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/b")])
		expect(load(p).sourceCwd).toBe("/project/a")
	})

	it("survives a manual export landing on top of an auto-written journal", () => {
		const p = at("manual.json")
		mergeIntoGrantsFile(p, EMPTY_LEDGER, [row("/auto")])
		const { file } = buildGrantsFile({
			ledger: EMPTY_LEDGER,
			grants: [row("/exported", 2_000)],
			sourceCwd: "/project/a",
		})
		expect(writeGrantsFile(p, file)).toBe(true)
		const after = mergeIntoGrantsFile(p, file.ledger, [row("/auto", 3_000)])
		expect(after.written).toBe(2)
		expect(load(p).grants.map((g) => g.value).sort()).toEqual(["/auto", "/exported"])
	})

	it("writes atomically: no half-written journal is ever readable", () => {
		const dir = join(tmp, "atomic")
		mkdirSync(dir, { recursive: true })
		const p = join(dir, "grants.json")
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/a")])
		// Every intermediate is a `.tmp-` sibling; the reader only ever sees a complete file.
		mergeIntoGrantsFile(p, ledgerOf([]), [row("/b")])
		expect(readdirSync(dir).filter((f) => f.includes(".tmp-"))).toEqual([])
		expect(load(p).grants).toHaveLength(2)
	})
})

afterAll(() => rmSync(tmp, { recursive: true, force: true }))

/**
 * The shape on disk did not change when a revocation started naming several kinds.
 *
 * A revocation may now name several kinds, or every kind, on one thing, and the ledger writes one row per kind
 * (or one row whose category is `any`). A row is still `{category, value, kind, …}`, so the file format is the
 * same `v: 1` file and a journal written today must load in a build that has never heard of `any` — and a
 * journal written yesterday must still load today. The first test below is the mechanical half of that claim:
 * nothing in a file written with an `any` row is new syntax.
 */
describe("`any` travels in the shape that already existed", () => {
	it("a file written with an `any` forbid row uses no key the base build does not have", () => {
		const path = at("any-shape.json")
		const written = mergeIntoGrantsFile(
			path,
			{
				v: 1,
				grants: [{ category: "write_project", value: "/srv/warehouse", kind: "entity", seq: 1, quote: "you can work in /srv/warehouse", messageId: "m1" }],
				forbids: [
					{ category: "any", value: "/srv/warehouse/", kind: "scope", seq: 4, quote: "leave /srv/warehouse alone", messageId: "m4" },
					{ category: "delete_outside", value: "/srv/warehouse/", kind: "scope", seq: 4, quote: "leave /srv/warehouse alone", messageId: "m4" },
				],
				seen: ["m1", "m4"],
			},
			[row("/srv/warehouse")],
			{ sourceCwd: "/srv/project" },
		)
		expect(written.ok, written.error).toBe(true)
		const parsed = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>
		// The keys of the file, and of every row in it, are the key set the format had before `any`.
		expect(Object.keys(parsed).sort()).toEqual(["exportedAt", "grants", "ledger", "revoked", "sourceCwd", "v"].sort())
		const forbids = (parsed.ledger as { forbids: Record<string, unknown>[] }).forbids
		expect(forbids.length).toBeGreaterThan(0)
		const baseKeys = new Set(["category", "value", "kind", "quote", "messageId", "seq", "at", "origin", "includesSecrets", "sourceSeq", "sourceMessageId", "modelCategory", "lastMatchedAt"])
		for (const f of forbids) {
			for (const key of Object.keys(f)) expect(baseKeys, key).toContain(key)
			// A LIST never appears in a row: the fan-out happened in the ledger, not on the wire to disk.
			expect(Array.isArray(f.category), JSON.stringify(f)).toBe(false)
		}
		expect(forbids.some((f) => f.category === "any")).toBe(true)
	})

	it("a journal written before `any` existed (no `any` anywhere) reads and merges unchanged", () => {
		const path = at("base-shape.json")
		// Byte-for-byte what an earlier build writes: v1, plain rows, no key `any` introduced (there is none) and
		// no category value it introduced on the GRANT side.
		writeFileSync(
			path,
			JSON.stringify({
				v: 1,
				exportedAt: "2026-10-28T00:00:00.000Z",
				sourceCwd: "/srv/project",
				ledger: { v: 1, grants: [{ category: "write_project", value: "./src/a.ts", kind: "entity", seq: 2, quote: "you can edit ./src/a.ts" }], forbids: [], seen: ["m2"] },
				grants: [{ category: "delete_outside", value: "/tmp/scratch/", kind: "scope", at: 1_700_000_000_000 }],
				revoked: [{ category: "write_outside", value: "/etc/things.conf", kind: "entity", at: 1_700_000_000_500 }],
			}),
			"utf-8",
		)
		const read = readGrantsFile(path)
		expect(read.ok, read.ok ? "" : read.error).toBe(true)
		if (!read.ok) return
		expect(read.file.grants).toHaveLength(1)
		expect(read.file.revoked ?? []).toHaveLength(1)
		// Merging into it still works, and adds the new row without touching the old ones.
		const merged = mergeIntoGrantsFile(path, undefined, [row("./src/b.ts")], { sourceCwd: "/srv/project" })
		expect(merged.ok, merged.error).toBe(true)
		expect(merged.added).toBe(1)
		// Both halves survive: the session-grants half keeps its own row and gains the new one; the ledger half
		// keeps the row an earlier build wrote, which is the half a rename of the category vocabulary could break.
		expect(load(path).grants.map((g) => g.value).sort()).toEqual(["./src/b.ts", "/tmp/scratch/"])
		const ledgerHalf = (load(path).ledger ?? {}) as { grants?: Array<{ value: string; category: string }> }
		expect((ledgerHalf.grants ?? []).map((g) => `${g.category} ${g.value}`).sort()).toEqual(["write_project ./src/a.ts"])
	})

	it("a GRANT row that names `any` is refused on the way in, never honoured", () => {
		// The value means "every action on the target"; only a forbid may claim it. Here it arrives in the
		// session-grants half of a file, where `asGrantRow` is the door.
		const path = at("grant-any.json")
		writeFileSync(
			path,
			JSON.stringify({
				v: 1,
				exportedAt: "2026-10-30T00:00:00.000Z",
				sourceCwd: "/srv/project",
				ledger: { v: 1, grants: [], forbids: [], seen: [] },
				grants: [
					{ category: "any", value: "/srv/warehouse/", kind: "scope", at: 1 },
					{ category: "write_outside", value: "/srv/other/", kind: "scope", at: 1 },
				],
				revoked: [],
			}),
			"utf-8",
		)
		const merged = mergeIntoGrantsFile(path, undefined, [], { sourceCwd: "/srv/project" })
		expect(merged.ok, merged.error).toBe(true)
		// Nothing was added from a row this build does not honour, and the file keeps the row it already had
		// untouched — refusing to USE a value is not a licence to rewrite somebody's file.
		expect(merged.added).toBe(0)
		expect(readGrantsFile(path).ok).toBe(true)
	})
})

describe("the values a status read and an agent spawn name survive the journal", () => {
	// Both shapes were thrown away on write by the path-shape screen: `localhost` is not a place, and the
	// screen only knew the categories whose object is a NAME. A durable "always" that is dropped on the way
	// into the journal is the complaint in one line — the user answered, the file forgot, and the prompt came
	// back after a restart or an export.
	const statusRow = (value: string): SessionGrant => ({ category: "read_system_state", value, kind: "entity", at: 1_000, durable: true })

	it("keeps a machine object and a unit-scoped one, and reads them back whole", () => {
		const p = at("system-state.json")
		const r = mergeIntoGrantsFile(p, ledgerOf([]), [statusRow("localhost"), statusRow("localhost/nginx")])
		expect(r.dropped).toBe(0)
		expect(r.written).toBe(2)
		const back = load(p).grants.map((g) => [g.category, g.value, g.durable])
		expect(back).toEqual([
			["read_system_state", "localhost", true],
			["read_system_state", "localhost/nginx", true],
		])
	})

	it("the restored rows answer the read they were granted for, and the service-scoped one stays scoped", () => {
		const p = at("system-state-match.json")
		mergeIntoGrantsFile(p, ledgerOf([]), [statusRow("localhost"), statusRow("localhost/nginx")])
		const store = createGrantStore()
		importSessionGrants(store, load(p).grants)
		const target = (value: string) => ({ kind: "target" as const, value })
		expect(grantsCover(store, "read_system_state", [target("localhost")]).covered).toBe(true)
		expect(grantsCover(store, "read_system_state", [target("localhost/nginx")]).covered).toBe(true)
		// A service-named grant does not reach the whole machine either.
		const scoped = createGrantStore()
		importSessionGrants(scoped, [statusRow("localhost/nginx")])
		expect(grantsCover(scoped, "read_system_state", [target("localhost")]).covered).toBe(false)
	})

	it("keeps an agent-name target and the no-object marker", () => {
		const p = at("agent-name.json")
		const rows: SessionGrant[] = [
			{ category: "agent_spawn", value: "pi", kind: "entity", at: 1_000, durable: true },
			{ category: "privilege", value: NO_OBJECT_TARGET, kind: "entity", at: 1_000, durable: true },
		]
		const r = mergeIntoGrantsFile(p, ledgerOf([]), rows)
		expect(r.dropped).toBe(0)
		expect(load(p).grants.map((g) => [g.category, g.value])).toEqual([
			["agent_spawn", "pi"],
			["privilege", NO_OBJECT_TARGET],
		])
	})
})
