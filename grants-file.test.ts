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

		// W7 tombstones changed this half of the expectation: a real snapshot is now UNIONED
		// with the half on disk, because replacing it silently deleted a concurrent session's
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
