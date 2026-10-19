import { afterAll, describe, expect, it } from "vitest"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	addGrant,
	createGrantStore,
	deserializeGrants,
	grantsCover,
	importSessionGrants,
	serializeGrants,
	type GrantStore,
	type SessionGrant,
} from "./session-grants.ts"
import {
	buildGrantsFile,
	mergeIntoGrantsFile,
	readGrantsFile,
	selectDurableGrants,
	writeGrantsFile,
} from "./grants-file.ts"
import type { Entity } from "./risk-policy.ts"

const tmp = mkdtempSync(join(tmpdir(), "pm-durable-"))
const at = (name: string) => join(tmp, name)
const T = (value: string): Entity => ({ kind: "target", value })
const LEDGER = { v: 1, grants: [], forbids: [], seen: [] }

/** Read the journal back into a store, the way session start does. */
function reimport(path: string, into: GrantStore = createGrantStore()): GrantStore {
	const read = readGrantsFile(path)
	if (!read.ok) throw new Error(read.error)
	importSessionGrants(into, read.file.grants)
	return into
}

function journalRows(path: string): SessionGrant[] {
	const read = readGrantsFile(path)
	if (!read.ok) throw new Error(read.error)
	return read.file.grants
}

/** What `/grants revoke` does to the store. */
function revoke(store: GrantStore, value: string): void {
	store.grants = store.grants.filter((g) => g.value !== value)
}

describe("the durable flag", () => {
	it("defaults off, so a four-argument addGrant behaves exactly as before", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/only/this/session", "entity")
		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.durable).toBeUndefined()

		addGrant(store, "write_project", "/data/x", "entity", true)
		expect(store.grants[1]).toMatchObject({ value: "/data/x", durable: true })
	})

	it("re-approving a target cannot downgrade an existing 'always'", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		addGrant(store, "write_project", "/data/x", "entity")
		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.durable).toBe(true)

		addGrant(store, "write_project", "/only/this/session", "entity", true)
		expect(store.grants.find((g) => g.value === "/only/this/session")?.durable).toBe(true)
	})

	it("marks every effect of a compound approval", () => {
		const store = createGrantStore()
		addGrant(store, "write_project+perm_change", "/data/x", "entity", true)
		expect(store.grants.map((g) => [g.category, g.durable])).toEqual([
			["write_project", true],
			["perm_change", true],
		])
	})

	it("round-trips through the session blob", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/durable", "scope", true)
		addGrant(store, "read_secret", "/tmp/once", "entity")
		const restored = deserializeGrants(serializeGrants(store))
		expect(restored.grants.find((g) => g.value === "/durable")).toMatchObject({
			kind: "scope",
			durable: true,
		})
		expect(restored.grants.find((g) => g.value === "/tmp/once")?.durable).toBeUndefined()
	})

	it("survives the journal round-trip", () => {
		const p = at("roundtrip.json")
		const store = createGrantStore()
		addGrant(store, "write_outside", "/data/x", "entity", true)
		expect(mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(store)).ok).toBe(true)
		expect(journalRows(p)[0]).toMatchObject({ value: "/data/x", durable: true })
		expect(reimport(p).grants[0]).toMatchObject({ value: "/data/x", durable: true, origin: "imported" })
	})

	it("repairs a drifted row instead of losing the 'always'", () => {
		const restored = deserializeGrants(
			JSON.stringify([
				{ category: "write_project", value: "/no/timestamp", durable: true },
				{ category: "write_project", value: "/kind/is/missing", durable: true },
				{ category: "write_project", value: "/durable/is/a/string", durable: "yes" },
				{ value: "/category/missing", durable: true },
			]),
		)
		expect(restored.grants.map((g) => g.value)).toEqual([
			"/no/timestamp",
			"/kind/is/missing",
			"/durable/is/a/string",
		])
		expect(restored.grants[1]!.kind).toBe("entity")
		expect(restored.grants[0]).toMatchObject({ at: 0, durable: true })
		expect(restored.grants[2]!.durable).toBeUndefined()
	})
})

describe("importSessionGrants with durable rows", () => {
	it("keeps durability and origin as two separate facts", () => {
		const store = createGrantStore()
		const r = importSessionGrants(store, [
			{ category: "write_project", value: "/always/elsewhere", kind: "entity", at: 1, durable: true },
			{ category: "write_project", value: "/once/elsewhere", kind: "entity", at: 1 },
		])
		expect(r.added).toBe(2)
		expect(store.grants[0]).toMatchObject({ value: "/always/elsewhere", durable: true, origin: "imported" })
		expect(store.grants[1]).toMatchObject({ value: "/once/elsewhere", origin: "imported" })
		expect(store.grants[1]!.durable).toBeUndefined()
	})

	it("still dedupes on {category, value, kind} alone", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity")
		const r = importSessionGrants(store, [
			{ category: "write_project", value: "/data/x", kind: "entity", at: 1, durable: true },
		])
		expect(r.added).toBe(0)
		expect(store.grants).toHaveLength(1)
		// The local row was not an "always" and the import cannot promote it.
		expect(store.grants[0]!.durable).toBeUndefined()
	})

	it("an import at the cap drops rows instead of evicting live grants", () => {
		const store = createGrantStore()
		for (let i = 0; i < 200; i++) addGrant(store, "read_only", `/live/${i}`, "entity")
		const before = store.grants.map((g) => g.value)
		const r = importSessionGrants(store, [
			{ category: "write_project", value: "/durable/1", kind: "entity", at: 1, durable: true },
			{ category: "write_project", value: "/durable/2", kind: "scope", at: 1, durable: true },
		])
		expect(r).toEqual({ added: 0, dropped: 2 })
		expect(store.grants.map((g) => g.value)).toEqual(before)
	})
})

describe("selectDurableGrants", () => {
	it("keeps only this session's matchable 'always' rows", () => {
		const store = createGrantStore()
		addGrant(store, "write_project", "/keep/me", "entity", true)
		addGrant(store, "write_project", "/data/", "scope", true)
		addGrant(store, "write_project", "/not-marked", "entity")
		addGrant(store, "write_project", "$(git rev-parse --git-dir)/exclude", "entity", true)
		addGrant(store, "write_project", "select(.type!=null) | .type", "entity", true)
		importSessionGrants(store, [
			{ category: "write_project", value: "/imported/always", kind: "entity", at: 1, durable: true },
		])
		expect(selectDurableGrants(store).map((g) => g.value).sort()).toEqual(["/data/", "/keep/me"])
	})

	it("a store that only imported never re-exports", () => {
		const p = at("nothing-to-export.json")
		const earned = createGrantStore()
		addGrant(earned, "write_project", "/from/this/session", "entity", true)
		mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(earned))

		// Fresh session: it has imported the journal and earned nothing of its own.
		const fresh = reimport(p)
		expect(fresh.grants).toHaveLength(1)
		expect(fresh.grants[0]).toMatchObject({ value: "/from/this/session", origin: "imported", durable: true })
		expect(selectDurableGrants(fresh)).toEqual([])
		expect(mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(fresh)).written).toBe(1)
		expect(journalRows(p).map((g) => g.value)).toEqual(["/from/this/session"])
	})
})

describe("a prompt answer that outlives the session", () => {
	it("covers the same action in a fresh store after a restart", () => {
		const p = at("restart.json")
		const earned = createGrantStore()
		addGrant(earned, "write_outside", "/data/proj/src/a.ts", "entity", true)
		addGrant(earned, "write_outside+fs-delete", "/data/proj/", "scope", true)
		expect(mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(earned)).written).toBe(3)

		const after = reimport(p)
		expect(grantsCover(after, "write_outside", [T("/data/proj/src/a.ts")]).covered).toBe(true)
		expect(grantsCover(after, "write_outside", [T("/data/proj/notes/todo.md")]).covered).toBe(true)
		// The compound was answered as two effects, so it still needs both.
		expect(grantsCover(after, "write_outside+fs-delete", [T("/data/proj/notes/todo.md")]).covered).toBe(true)
		expect(grantsCover(after, "perm_change", [T("/data/proj/src/a.ts")]).covered).toBe(false)
		expect(after.grants.every((g) => g.origin === "imported")).toBe(true)
	})

	it("re-earning the same answer rewrites the same journal without duplicating it", () => {
		const p = at("restart-twice.json")
		const first = createGrantStore()
		addGrant(first, "write_project", "/data/x", "entity", true)
		mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(first))

		const second = reimport(p) // next session starts by importing the journal
		addGrant(second, "write_project", "/data/x", "entity", true)
		expect(selectDurableGrants(second)).toEqual([]) // already known, nothing earned here
		const r = mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(second))
		expect(r).toMatchObject({ ok: true, added: 0, written: 1 })
		expect(journalRows(p).filter((g) => g.value === "/data/x")).toHaveLength(1)
		expect(journalRows(p)[0]!.durable).toBe(true)
	})

	it("travels with forbids in the same file without becoming one", () => {
		const p = at("with-forbids.json")
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		const { file, dropped } = buildGrantsFile({
			ledger: { v: 1, grants: [], forbids: [{ category: "write_project", value: "/data/never", kind: "scope", seq: 2 }], seen: [] },
			grants: selectDurableGrants(store),
			sourceCwd: "/project",
		})
		expect(dropped).toBe(0)
		expect(writeGrantsFile(p, file)).toBe(true)
		expect(mergeIntoGrantsFile(p, undefined, []).ok).toBe(true)

		const read = readGrantsFile(p)
		if (!read.ok) throw new Error(read.error)
		const forbids = (read.file.ledger as { forbids: { value: string }[] }).forbids
		expect(forbids.map((f) => f.value)).toEqual(["/data/never"])
		expect(read.file.grants.map((g) => g.value)).toEqual(["/data/x"])
	})
})

describe("revoke still reaches a durable row", () => {
	it("dropping it from the store and rewriting the journal removes it", () => {
		const p = at("revoke.json")
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		addGrant(store, "write_project", "/data/keep", "entity", true)
		mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(store))

		revoke(store, "/data/x")
		const { file } = buildGrantsFile({
			ledger: LEDGER,
			grants: selectDurableGrants(store),
			sourceCwd: "/project",
		})
		expect(writeGrantsFile(p, file)).toBe(true)

		expect(journalRows(p).map((g) => g.value)).toEqual(["/data/keep"])
		const after = reimport(p)
		expect(grantsCover(after, "write_project", [T("/data/x")]).covered).toBe(false)
		expect(grantsCover(after, "write_project", [T("/data/keep")]).covered).toBe(true)
		expect(selectDurableGrants(store).map((g) => g.value)).toEqual(["/data/keep"])
	})

	it("a merge alone cannot undo it — which is why revoke has to rewrite", () => {
		const p = at("revoke-merge-only.json")
		const store = createGrantStore()
		addGrant(store, "write_project", "/data/x", "entity", true)
		mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(store))

		revoke(store, "/data/x")
		const r = mergeIntoGrantsFile(p, LEDGER, selectDurableGrants(store))
		expect(r).toMatchObject({ ok: true, added: 0, written: 1 })
		expect(journalRows(p).map((g) => g.value)).toEqual(["/data/x"])
	})
})

afterAll(() => rmSync(tmp, { recursive: true, force: true }))
