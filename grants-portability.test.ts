/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { afterAll, describe, expect, it } from "vitest"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	applyEvent,
	createLedger,
	importLedger,
	ledgerCovers,
	readOnlyActive,
	serializeLedger,
	deserializeLedger,
	type ExtractedEvent,
} from "./auth-ledger.ts"
import { createGrantStore, importSessionGrants, type SessionGrant } from "./session-grants.ts"
import {
	buildGrantsFile,
	isUnmatchableValue,
	mergeIntoGrantsFile,
	pruneRows,
	readGrantsFile,
	summarizeGrantsFile,
	writeGrantsFile,
} from "./grants-file.ts"
import type { Entity } from "./risk-policy.ts"

const T = (value: string): Entity => ({ kind: "target", value })

function grant(value: string, seq: number, category = "write_outside"): ExtractedEvent {
	return {
		type: "grant",
		category,
		value,
		kind: "entity",
		quote: `you can write ${value}`,
		messageId: `m${seq}`,
		seq,
	}
}

function forbid(value: string, seq: number, category = "write_outside"): ExtractedEvent {
	return {
		type: "forbid",
		category,
		value,
		kind: "entity",
		quote: `stop touching ${value}`,
		messageId: `m${seq}`,
		seq,
	}
}

function sourceLedger(events: ExtractedEvent[]) {
	const l = createLedger()
	for (const ev of events) applyEvent(l, ev)
	return l
}

describe("grants-file value pruning", () => {
	it("drops the junk observed in a live /grants listing", () => {
		for (const junk of [
			"~/.pi/agent/=== jsonl by recency ===",
			"select(.type!=null) | .type",
			"$(git rev-parse --git-dir)/info/exclude",
			"/home/u/x/__TRACKED_VAR__",
			"their verb tables",
			"",
		]) {
			expect(isUnmatchableValue(junk)).toBe(true)
		}
	})

	it("keeps real targets and the bare-verb wildcard", () => {
		for (const ok of [
			"/home/u/dev/x",
			"~/dev/x",
			"./src/a.ts",
			"/home/u/dev/pm-gate-ordering/",
			"*",
		]) {
			expect(isUnmatchableValue(ok)).toBe(false)
		}
	})

	it("pruneRows splits without losing the kept rows", () => {
		const r = pruneRows([{ value: "/a/b" }, { value: "| .type" }, { value: "*" }])
		expect(r.kept.map((k) => k.value)).toEqual(["/a/b", "*"])
		expect(r.dropped.map((d) => d.value)).toEqual(["| .type"])
	})
})

describe("grants-file value pruning with a category", () => {
	// Back-compat: a caller that names no category gets exactly the old rule, so every
	// non-path-shaped value stays unmatchable for it. `origin` is the value this whole
	// change is about, and it must STILL be dropped when nobody said what it targets.
	it("is the old path rule when no category is given", () => {
		for (const value of ["origin", "origin/*", "origin/feature/X", "gh workflow run", "myrepo/app:1.0", "httpx"]) {
			expect(isUnmatchableValue(value)).toBe(true)
		}
		expect(isUnmatchableValue("/data/x", "vcs_remote")).toBe(false)
		expect(isUnmatchableValue("~/x", "write_outside")).toBe(false)
		expect(isUnmatchableValue(undefined, "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("", "vcs_remote")).toBe(true)
	})

	it("accepts a name when every category segment targets something that has no path", () => {
		for (const [category, value] of [
			["vcs_remote", "origin"],
			["vcs_remote", "origin/*"],
			["vcs_remote", "origin/feature/X"],
			["vcs_remote", "gh workflow run"],
			["vcs_discard", "feature/X"],
			["container_mutation+network_send", "myrepo/app"],
			["package_system", "httpx"],
			["cluster_mutation", "prod/us-east"],
			["db_mutation", "orders"],
			["network_send", "api.example.com"],
			["remote_exec", "build-host"],
			["network_listen", "8080"],
			["process_control", "worker"],
			["system_config", "nginx"],
			["privilege", "sudo"],
			["interactive_editor", "vim"],
		] as const) {
			expect(isUnmatchableValue(value, category)).toBe(false)
		}
	})

	it("keeps the path rule for any fs / secret / perm segment, compound included", () => {
		for (const [category, value] of [
			["write_outside", "origin"],
			["delete_recursive", "their verb tables"],
			["read_secret", "prod"],
			["write_sensitive", "origin"],
			["perm_change", "origin"],
			// One fs segment in a compound is enough: the fs half of the effect needs a path.
			["vcs_remote+write_outside", "origin"],
		] as const) {
			expect(isUnmatchableValue(value, category)).toBe(true)
		}
	})

	it("still calls junk junk in a non-path category", () => {
		// Shell fragments, a sentence instead of a name, and an over-long dump.
		expect(isUnmatchableValue("select(.type!=null) | .type", "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("$(git remote get-url origin)", "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("origin ${BRANCH}", "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("please push this branch to the remote now", "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("x".repeat(201), "vcs_remote")).toBe(true)
		expect(isUnmatchableValue("x".repeat(200), "vcs_remote")).toBe(false)
		// "*" is the bare-verb/all grant, whatever the category.
		expect(isUnmatchableValue("*", "vcs_remote")).toBe(false)
		// Unknown category → the path rule, not a free pass.
		expect(isUnmatchableValue("origin", "something_new")).toBe(true)
	})

	it("pruneRows passes each row's own category through", () => {
		const r = pruneRows([
			{ value: "origin", category: "vcs_remote" },
			{ value: "origin", category: "write_outside" },
			{ value: "origin" },
		])
		expect(r.kept.map((k) => [k.value, k.category])).toEqual([["origin", "vcs_remote"]])
		expect(r.dropped.map((d) => d.category)).toEqual(["write_outside", undefined])
	})
})

describe("grants-file IO", () => {
	const tmp = mkdtempSync(join(tmpdir(), "pm-gf-"))

	it("round-trips through disk", () => {
		const src = sourceLedger([grant("/data/x", 3), forbid("/data/y", 4)])
		const { file } = buildGrantsFile({
			ledger: serializeLedger(src),
			grants: [{ category: "read_only", value: "/data/z", kind: "entity", at: 1 }],
			sourceCwd: "/some/cwd",
		})
		const p = join(tmp, "grants.json")
		expect(writeGrantsFile(p, file)).toBe(true)

		const back = readGrantsFile(p)
		expect(back.ok).toBe(true)
		if (!back.ok) return
		expect(back.file.sourceCwd).toBe("/some/cwd")
		expect(back.file.grants).toHaveLength(1)
		expect(summarizeGrantsFile(back.file)).toContain("1 ledger grants, 1 forbids")
	})

	it("creates a missing parent directory", () => {
		const { file } = buildGrantsFile({ ledger: serializeLedger(createLedger()), grants: [], sourceCwd: "/c" })
		const p = join(tmp, "deep", "nested", "g.json")
		expect(writeGrantsFile(p, file)).toBe(true)
		expect(readGrantsFile(p).ok).toBe(true)
	})

	it("reports malformed input instead of importing nothing silently", () => {
		const bad = join(tmp, "bad.json")
		writeFileSync(bad, "{ not json", "utf-8")
		expect(readGrantsFile(bad).ok).toBe(false)

		const wrongVersion = join(tmp, "v9.json")
		writeFileSync(wrongVersion, JSON.stringify({ v: 9, grants: [], ledger: {} }), "utf-8")
		const r = readGrantsFile(wrongVersion)
		expect(r.ok).toBe(false)
		if (!r.ok) expect(r.error).toContain("version")

		const noGrants = join(tmp, "ng.json")
		writeFileSync(noGrants, JSON.stringify({ v: 1, ledger: {} }), "utf-8")
		expect(readGrantsFile(noGrants).ok).toBe(false)

		const missing = join(tmp, "nope.json")
		expect(readGrantsFile(missing).ok).toBe(false)
	})

	it("prunes junk on export, not on import", () => {
		const { file, dropped } = buildGrantsFile({
			ledger: serializeLedger(createLedger()),
			grants: [
				{ category: "read_secret", value: "~/.pi/agent/sessions/400", kind: "entity", at: 1 },
				{ category: "read_only", value: "/real/path", kind: "entity", at: 1 },
			],
			sourceCwd: "/c",
		})
		// sessions/400 is a numeric directory blamed as a path; the real one stays.
		expect(dropped + file.grants.length).toBe(2)
		expect(file.grants.some((g) => g.value === "/real/path")).toBe(true)
	})

	it("keeps every git / forge / container / package grant across export → import", () => {
		// The finding: "Allow always" on a push recorded NOTHING durable, because every
		// non-path-shaped value was called unmatchable and pruned on the way out.
		const rows: SessionGrant[] = [
			{ category: "vcs_remote", value: "origin", kind: "entity", at: 1, durable: true },
			{ category: "vcs_remote", value: "origin/*", kind: "entity", at: 1, durable: true },
			{ category: "vcs_remote", value: "origin/feature/X", kind: "entity", at: 1, durable: true },
			{ category: "vcs_remote", value: "gh workflow run", kind: "entity", at: 1, durable: true },
			{ category: "container_mutation+network_send", value: "myrepo/app", kind: "entity", at: 1, durable: true },
			{ category: "package_system", value: "httpx", kind: "entity", at: 1, durable: true },
			// ...and these are still junk, category or no category.
			{ category: "vcs_remote", value: "select(.type!=null) | .type", kind: "entity", at: 1, durable: true },
			{ category: "write_outside", value: "their verb tables", kind: "entity", at: 1, durable: true },
			{ category: "vcs_remote", value: "please push this branch to the remote now", kind: "entity", at: 1, durable: true },
		]
		const { file, dropped } = buildGrantsFile({
			ledger: serializeLedger(createLedger()),
			grants: rows,
			sourceCwd: "/c",
		})
		expect(dropped).toBe(3)

		const p = join(tmp, "non-path.json")
		expect(writeGrantsFile(p, file)).toBe(true)
		const back = readGrantsFile(p)
		if (!back.ok) throw new Error(back.error)
		const reader = createGrantStore()
		importSessionGrants(reader, back.file.grants)
		expect(reader.grants.map((g) => g.value).sort()).toEqual(
			["gh workflow run", "httpx", "myrepo/app", "origin", "origin/*", "origin/feature/X"].sort(),
		)
		// The durable flag is what makes these rows worth persisting at all.
		expect(back.file.grants.every((g) => g.durable === true)).toBe(true)
	})

	it("keeps them through the merge path too, which prunes on the way in", () => {
		const p = join(tmp, "non-path-merge.json")
		const r = mergeIntoGrantsFile(
			p,
			{ v: 1, grants: [], forbids: [], seen: [] },
			[
				{ category: "vcs_remote", value: "origin/*", kind: "entity", at: 1, durable: true },
				{ category: "vcs_remote", value: "push this branch to the remote before review", kind: "entity", at: 1, durable: true },
			],
			{ sourceCwd: "/c" },
		)
		expect(r.ok).toBe(true)
		expect(r.dropped).toBe(1)
		expect(r.written).toBe(1)
		const back = readGrantsFile(p)
		if (!back.ok) throw new Error(back.error)
		expect(back.file.grants.map((g) => g.value)).toEqual(["origin/*"])
	})

	afterAll(() => rmSync(tmp, { recursive: true, force: true }))
})

describe("importLedger precedence", () => {
	it("imported grants hold authority", () => {
		const file = serializeLedger(sourceLedger([grant("/data/x", 7)]))
		const target = createLedger()
		const s = importLedger(target, file)
		expect(s.grantsAdded).toBe(1)
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(true)
		expect(target.grants[0]!.origin).toBe("imported")
		expect(target.grants[0]!.seq).toBe(0)
		expect(target.grants[0]!.sourceSeq).toBe(7)
	})

	it("a LOCAL revocation dominates an imported grant", () => {
		const target = createLedger()
		importLedger(target, serializeLedger(sourceLedger([grant("/data/x", 9)])))
		applyEvent(target, forbid("/data/x", 1))
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(false)
	})

	it("a local grant outranks an imported forbid (background authority, by design)", () => {
		const target = createLedger()
		importLedger(target, serializeLedger(sourceLedger([forbid("/data/x", 40)])))
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(false)
		applyEvent(target, grant("/data/x", 2))
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(true)
	})

	it("an import never resurrects revoked authority from the source", () => {
		// The honest form of "forbids travel": the source ledger itself no longer
		// grants what it revoked, so there is nothing to resurrect on import.
		const file = serializeLedger(sourceLedger([grant("/data/x", 1), forbid("/data/x", 3)]))
		const target = createLedger()
		importLedger(target, file)
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(false)
	})

	it("an imported revocation is background too - it does NOT veto a local grant", () => {
		// Consequence of the seq-0 rule, stated as a test because it is the cost of
		// the design, not a hole in it: a file cannot outrank a person. An imported
		// forbid (seq 0) loses to a grant the user actually made HERE (seq >= 1).
		// Importing forbids at a high seq would let a stale or poisoned file
		// permanently block legitimate work with only /grants clear as the remedy.
		const target = createLedger()
		applyEvent(target, grant("/data/x", 1))
		const s = importLedger(target, serializeLedger(sourceLedger([forbid("/data/x", 3)])))
		expect(s.forbidsAdded).toBe(1)
		expect(target.forbids[0]!.origin).toBe("imported")
		expect(ledgerCovers(target, "write_outside", [T("/data/x")]).covered).toBe(true)
	})

	it("survives the restore filter that drops rows with foreign messageIds", () => {
		const target = createLedger()
		applyEvent(target, grant("/local/kept", 1))
		importLedger(target, serializeLedger(sourceLedger([grant("/imported/kept", 5)])))

		// A new session's branch contains neither message id.
		const restored = deserializeLedger(serializeLedger(target), new Set(["unrelated"]))
		const values = restored.grants.map((g) => g.value)
		expect(values).toContain("/imported/kept")
		expect(values).not.toContain("/local/kept")
	})

	it("restores `seen`, so backfill does not re-extract a conversation the file already read", () => {
		// ASSERTION FLIPPED deliberately — it used to read
		// "does not restore `seen` (backfill re-extraction is self-healing)" and asserted
		// `target.seen.size === 0`. Keeping it red would hide the flip it was watching, which
		// is the same call made on the ledger-half assertion in `grants-file.test.ts`. Restoring the ids is
		// a correctness matter now that a revocation is a row: re-extracting an imported
		// conversation is both a model call per message and the road a revoked grant could
		// come back along. Both directions are pinned in auth-ledger.test.ts.
		// `seen` is written by the drain layer, not applyEvent(), so seed it directly.
		const src = sourceLedger([grant("/data/x", 1)])
		src.seen.add("m1")
		expect(src.seen.size).toBe(1)
		const target = createLedger()
		const s = importLedger(target, serializeLedger(src))
		expect(target.seen.has("m1")).toBe(true)
		expect(s.seenImported).toBe(1)
	})

	it("dedupes and respects the cap, reporting what fell off", () => {
		const target = createLedger()
		for (let i = 0; i < 195; i++) applyEvent(target, grant(`/a/${i}`, i + 1))
		const src = sourceLedger([grant("/a/0", 1), grant("/b/0", 2), ...Array.from({ length: 29 }, (_, i) => grant(`/b/${i + 1}`, i + 3))])
		const s = importLedger(target, serializeLedger(src))
		expect(target.grants.length).toBe(200)
		expect(s.grantsAdded).toBe(5)
		expect(s.dropped).toBe(25)
	})

	it("replace drops the target's own rows", () => {
		const target = createLedger()
		applyEvent(target, grant("/local/only", 1))
		importLedger(target, serializeLedger(sourceLedger([grant("/from/file", 2)])), {
			replace: true,
		})
		expect(target.grants.map((g) => g.value)).toEqual(["/from/file"])
	})
})

describe("read-only posture travels", () => {
	it("imports an active posture into a fresh ledger", () => {
		const src = createLedger()
		applyEvent(src, {
			type: "readonly-on",
			category: "*",
			value: "*",
			kind: "entity",
			quote: "do not change anything",
			messageId: "m1",
			seq: 6,
		})
		const target = createLedger()
		const s = importLedger(target, serializeLedger(src))
		expect(s.postureImported).toBe(true)
		expect(readOnlyActive(target)).not.toBeNull()
	})

	it("a local 'you can make changes now' outranks the imported posture", () => {
		const src = createLedger()
		applyEvent(src, {
			type: "readonly-on",
			category: "*",
			value: "*",
			kind: "entity",
			quote: "do not change anything",
			messageId: "m1",
			seq: 6,
		})
		const target = createLedger()
		applyEvent(target, {
			type: "readonly-off",
			category: "*",
			value: "*",
			kind: "entity",
			quote: "you can make changes now",
			messageId: "n1",
			seq: 1,
		})
		const s = importLedger(target, serializeLedger(src))
		expect(s.postureImported).toBe(false)
		expect(readOnlyActive(target)).toBeNull()
	})
})

describe("importSessionGrants", () => {
	it("marks, dedupes and caps imports", () => {
		const store = createGrantStore()
		store.grants.push({ category: "read_only", value: "/a", kind: "entity", at: 1 })
		const r = importSessionGrants(store, [
			{ category: "read_only", value: "/a", kind: "entity", at: 0 },
			{ category: "read_only", value: "/b", kind: "scope", at: 0 },
			{ category: "write_outside", value: "/c", kind: "entity", at: 0 },
		])
		expect(r.added).toBe(2)
		expect(store.grants.find((g) => g.value === "/b")?.origin).toBe("imported")
		expect(store.grants.find((g) => g.value === "/a")?.origin).toBeUndefined()
	})

	it("replace swaps the store contents", () => {
		const store = createGrantStore()
		store.grants.push({ category: "read_only", value: "/old", kind: "entity", at: 1 })
		importSessionGrants(store, [{ category: "read_only", value: "/new", kind: "entity", at: 0 }], {
			replace: true,
		})
		expect(store.grants.map((g) => g.value)).toEqual(["/new"])
	})

	it("tolerates garbage rows and counts them as dropped", () => {
		const store = createGrantStore()
		const r = importSessionGrants(store, [
			null as never,
			{ category: "read_only", value: "/ok", kind: "entity", at: 0 },
		])
		expect(r.added).toBe(1)
		expect(r.dropped).toBe(1)
	})
})
