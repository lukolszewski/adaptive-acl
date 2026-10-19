/**
 * The direction matrix: which permission implies which.
 *
 * Rules under test, all one-way:
 *   read        -> read only
 *   write       -> read (within the same covered path), write, and delete ONLY with a
 *                  destructive verb in the user's own quote
 *   delete      -> delete only (never read, never write)
 *   nothing     -> read_secret, which needs its own grant or an explicit inclusion
 *
 * Every "does not" here is load-bearing. A grant that reads the folder is not a grant that
 * empties it, and a grant that edits it is not a grant that publishes its credentials.
 */
import { describe, expect, it } from "vitest"
import { applyEvent, createLedger, ledgerCovers } from "./auth-ledger.ts"
import type { Ledger, LedgerEntry } from "./auth-ledger.ts"

const HOME = "/home/u"

type Row = Partial<LedgerEntry> & { category: string; value: string; quote: string; kind?: "entity" | "scope"; type?: "grant" | "forbid" }

function ledgerWith(rows: Row[]): Ledger {
	const l = createLedger()
	rows.forEach((r, i) =>
		applyEvent(l, {
			// Honour the row's type. A fixture that always pushed "grant" turned a revocation
			// into a wildcard GRANT (category "*", higher seq) — i.e. into permission for
			// everything — and the assertion below it never even ran, because vitest stops at
			// the first failed expect in a test. That is how a green-looking line lied.
			type: r.type ?? "grant",
			category: r.category,
			value: r.value,
			kind: r.kind ?? "entity",
			quote: r.quote,
			messageId: `m${i}`,
			seq: r.seq ?? i + 1,
			...(r.includesSecrets === undefined ? {} : { includesSecrets: r.includesSecrets }),
		}),
	)
	return l
}

function covers(rows: Row[], pending: string, target: string): boolean {
	return ledgerCovers(ledgerWith(rows), pending, [{ kind: "target", value: target }], HOME).covered
}

const READ = [{ category: "read_only", value: "/home/u/w/", kind: "scope" as const, quote: "you can read files in /home/u/w" }]
const WRITE_SCOPE = [{ category: "write_outside", value: "/home/u/w/", kind: "scope" as const, quote: "you can write files in /home/u/w" }]
const DELETE_SCOPE = [{ category: "delete_recursive", value: "/home/u/w/", kind: "scope" as const, quote: "you can delete files in /home/u/w" }]

describe("read grants", () => {
	it("cover reads, exact and under a scope", () => {
		expect(covers(READ, "read_only", "/home/u/w/a.ts")).toBe(true)
		expect(covers([{ ...READ[0]!, value: "/home/u/w/a.ts", kind: "entity" }], "read_only", "/home/u/w/a.ts")).toBe(true)
	})
	it("never cover writes", () => {
		expect(covers(READ, "write_outside", "/home/u/w/a.ts")).toBe(false)
		expect(covers(READ, "write_project", "/home/u/w/a.ts")).toBe(false)
	})
	it("never cover deletes", () => {
		expect(covers(READ, "delete_recursive", "/home/u/w/a.ts")).toBe(false)
		expect(covers(READ, "delete_outside", "/home/u/w/a.ts")).toBe(false)
	})
	it("never reach secret reads, even inside the folder they may read", () => {
		expect(covers(READ, "read_secret", "/home/u/w/.env")).toBe(false)
	})
})

describe("write grants imply read", () => {
	it("within the scope they name", () => {
		expect(covers(WRITE_SCOPE, "read_only", "/home/u/w/a.ts")).toBe(true)
	})
	it("and for an exact file grant, that file only", () => {
		const one = [{ category: "write_outside", value: "/home/u/w/a.ts", kind: "entity" as const, quote: "you can write /home/u/w/a.ts" }]
		expect(covers(one, "read_only", "/home/u/w/a.ts")).toBe(true)
		expect(covers(one, "read_only", "/home/u/w/b.ts")).toBe(false)
	})
	it("but a write grant never reaches secret reads", () => {
		expect(covers(WRITE_SCOPE, "read_secret", "/home/u/w/.env")).toBe(false)
		const sensitive = [{ category: "write_sensitive", value: "/home/u/.ssh/", kind: "scope" as const, quote: "you can edit files in /home/u/.ssh" }]
		expect(covers(sensitive, "read_secret", "/home/u/.ssh/id_rsa")).toBe(false)
	})
	it("and never reaches a path outside the grant", () => {
		expect(covers(WRITE_SCOPE, "read_only", "/home/u/other/a.ts")).toBe(false)
	})
})

describe("write grants do not silently imply delete", () => {
	it("no destructive verb in the user's own quote, no delete", () => {
		expect(covers(WRITE_SCOPE, "delete_recursive", "/home/u/w/a.ts")).toBe(false)
		expect(covers(WRITE_SCOPE, "delete_data", "/home/u/w/a.ts")).toBe(false)
	})
	it("mv/move/rename DOES count as delete evidence — a recorded trade-off, not a hole", () => {
		// A move destroys its source path: `mv /w/a /tmp` means /w/a is gone. Pinned here as
		// well as in gate-move.test.ts and compound-category.test.ts, because it looks like a
		// bug on every read and has been "fixed" once already, breaking four tests.
		const move = [{ category: "write_outside", value: "/home/u/w/", kind: "scope" as const, quote: "you can move files into /home/u/w" }]
		expect(covers(move, "write_outside", "/home/u/w/a.ts")).toBe(true)
		expect(covers(move, "delete_recursive", "/home/u/w/a.ts")).toBe(true)
	})
	it("an explicit delete verb does bridge write to delete, by group and evidence", () => {
		const del = [{ category: "write_outside", value: "/home/u/w/", kind: "scope" as const, quote: "you can delete files in /home/u/w" }]
		expect(covers(del, "delete_recursive", "/home/u/w/a.ts")).toBe(true)
	})
})

describe("delete grants", () => {
	it("cover deletes under their scope", () => {
		expect(covers(DELETE_SCOPE, "delete_recursive", "/home/u/w/a.ts")).toBe(true)
	})
	it("do NOT imply read — deletion is not a read capability in disguise", () => {
		expect(covers(DELETE_SCOPE, "read_only", "/home/u/w/a.ts")).toBe(false)
	})
	it("but it DOES imply write, through the shared fs-write kind group", () => {
		// NOT a claim about what we want: delete_outside/delete_recursive and write_outside all
		// sit in group fs-write, so a folder delete grant currently authorises writes inside it.
		// Pre-existing group design, asserted here so it is visible rather than surprising, and
		// recorded as an open item in DIRECTED-PERMISSIONS-PLAN.md.
		expect(covers(DELETE_SCOPE, "write_outside", "/home/u/w/a.ts")).toBe(true)
	})
})

describe("a revocation still dominates everything above", () => {
	it("the folder read implied by a write grant is dead once the folder is revoked", () => {
		const rows: Row[] = [
			...WRITE_SCOPE,
			// Trailing slash matters: a scope row matches by prefix, and the subtree row that
			// real extraction emits (see the L-02 fix) is `${path}/`. Mirrors that shape.
			{ type: "forbid", category: "*", value: "/home/u/w/", kind: "scope", quote: "stop, do not touch /home/u/w anymore", seq: 9 },
		]
		expect(covers(rows, "read_only", "/home/u/w/a.ts")).toBe(false)
		expect(covers(rows, "write_outside", "/home/u/w/a.ts")).toBe(false)
	})
})
