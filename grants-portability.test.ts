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
import { createGrantStore, importSessionGrants } from "./session-grants.ts"
import {
	buildGrantsFile,
	isUnmatchableValue,
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
		// is the same call W7 made on this file's ledger-half assertion. Restoring the ids is
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
