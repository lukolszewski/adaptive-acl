/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The direction matrix: which permission implies which.
 *
 * Rules under test, all one-way:
 *   read        -> read only
 *   write       -> read (within the same covered path) and write, plus the single-file delete inside its
 *                  scope and a read of a SECRET-CLASS path inside it
 *   delete      -> delete, plus write inside the same scope (one shared kind group, one-way),
 *                  plus read (you cannot remove what you may not look at), and
 *                  through that write half the secret-class read
 *   service     -> container / cluster / db / host / unit grants cover READING that same object
 *   read        -> nothing else: a read grant never buys a change, and never reaches another object
 *
 * Every "does not" here is load-bearing. A grant that reads the folder is not a grant that empties it, and
 * one that reads a machine is not one that may change it.
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

/** The stronger half of the answer: not just "nothing covered it" but "the user forbade it". */
function forbidden(rows: Row[], pending: string, target: string): boolean {
	return ledgerCovers(ledgerWith(rows), pending, [{ kind: "target", value: target }], HOME).forbidden
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
	it("and reaches secret-class paths inside them", () => {
		// These lines used to assert `false` with the reason "a grant that edits it is not a grant that
		// publishes its credentials". The ordinary direction holds instead: within the scope the row names,
		// an edit needs a read first, so the read comes with it — credentials included, because editing a
		// credentials file is not possible without opening it.
		// Two things keep this from being a blanket: the direction is one-way (a read grant still buys no write,
		// pinned above), and it reaches only what the row's own value covers.
		expect(covers(WRITE_SCOPE, "read_secret", "/home/u/w/.env")).toBe(true)
		const sensitive = [{ category: "write_sensitive", value: "/home/u/.ssh/", kind: "scope" as const, quote: "you can edit files in /home/u/.ssh" }]
		expect(covers(sensitive, "read_secret", "/home/u/.ssh/id_rsa")).toBe(true)
		// …and outside it, nothing.
		expect(covers(sensitive, "read_secret", "/home/u/w/.env")).toBe(false)
		expect(covers(WRITE_SCOPE, "read_secret", "/home/u/other/.env")).toBe(false)
	})
	it("and never reaches a path outside the grant", () => {
		expect(covers(WRITE_SCOPE, "read_only", "/home/u/other/a.ts")).toBe(false)
	})
})

describe("write grants imply one file's delete and no more", () => {
	it("a content row answers no RECURSIVE delete and no data delete, whatever its quote says", () => {
		expect(covers(WRITE_SCOPE, "delete_recursive", "/home/u/w/a.ts")).toBe(false)
		expect(covers(WRITE_SCOPE, "delete_data", "/home/u/w/a.ts")).toBe(false)
		// The one shape that is open: removing a single file inside what the row names…
		expect(covers(WRITE_SCOPE, "delete_outside", "/home/u/w/a.ts")).toBe(true)
		// …and never the folder the row was granted over.
		expect(covers(WRITE_SCOPE, "delete_outside", "/home/u/w")).toBe(false)
	})
	it("mv/move/rename in the quote is no longer delete evidence", () => {
		// A move really does destroy its source path (`mv /w/a /tmp` means /w/a is gone), but the code
		// no longer decides that by finding "move" in a sentence: the model files the delete half as its
		// own row (one row PER EFFECT) or the action costs a prompt. Same pins as gate-move.test.ts and
		// compound-category.test.ts, flipped together. The write half is unaffected.
		const move = [{ category: "write_outside", value: "/home/u/w/", kind: "scope" as const, quote: "you can move files into /home/u/w" }]
		expect(covers(move, "write_outside", "/home/u/w/a.ts")).toBe(true)
		expect(covers(move, "delete_recursive", "/home/u/w/a.ts")).toBe(false)
	})
	it("an explicit delete verb in a write row no longer bridges to delete", () => {
		// The bridge is gone: reach is the row's own kind group, so the word "delete" in a
		// write_outside row buys it nothing. A delete-category row over the same scope still works.
		const del = [{ category: "write_outside", value: "/home/u/w/", kind: "scope" as const, quote: "you can delete files in /home/u/w" }]
		expect(covers(del, "delete_recursive", "/home/u/w/a.ts")).toBe(false)
		const delRow = [{ category: "delete_recursive", value: "/home/u/w/", kind: "scope" as const, quote: "you can delete files in /home/u/w" }]
		expect(covers(delRow, "delete_recursive", "/home/u/w/a.ts")).toBe(true)
	})
})

describe("delete grants", () => {
	it("cover deletes under their scope", () => {
		expect(covers(DELETE_SCOPE, "delete_recursive", "/home/u/w/a.ts")).toBe(true)
	})
	it("imply read — you cannot remove what you may not look at", () => {
		// This line used to assert `false` with the reason "deletion is not a read capability in disguise".
		// The ordinary direction holds instead: a user who approved "clean up /w" is not surprised by
		// `cat /w/a`, and one approval per object is the whole point. Nothing else moved — a delete grant still
		// buys no write it did not buy before, and a write grant still buys no delete (the rows above).
		expect(covers(DELETE_SCOPE, "read_only", "/home/u/w/a.ts")).toBe(true)
		// …inside the scope it named, and nowhere else.
		expect(covers(DELETE_SCOPE, "read_only", "/home/u/other/a.ts")).toBe(false)
		// read_secret is reached through the write half (see above).
		expect(covers(DELETE_SCOPE, "read_secret", "/home/u/w/.env")).toBe(true)
		// A category-wide delete row names no object, so it is not evidence about this one.
		expect(covers([{ category: "delete_recursive", value: "*", quote: "you can delete stuff" }], "read_only", "/home/u/w/a.ts")).toBe(false)
	})
	it("but it DOES imply write, by the one named direction (delete grant -> write pending)", () => {
		// One-way and deliberate: destroying every byte under a scope already implies putting bytes
		// there, so writing is not a new class of harm. The reverse (write -> delete) is not implied.
		expect(covers(DELETE_SCOPE, "write_outside", "/home/u/w/a.ts")).toBe(true)
	})
})

describe("service grants cover reading the object they name", () => {
	// Layer 0 names a non-file read's object (the daemon, the cluster, the host, the unit, the database), so
	// one approval per object is only real if the grant the user gave for that object answers the read too.
	const SERVICE_ROWS: Array<{ category: string; object: string; read: string }> = [
		{ category: "container_mutation", object: "docker:default", read: "docker ps" },
		{ category: "cluster_mutation", object: "cluster/prod-cn", read: "kubectl get pods -n cn" },
		{ category: "remote_exec", object: "build-01.internal", read: "ssh build-01 uptime" },
		{ category: "db_mutation", object: "postgres:analytics", read: "psql analytics -c 'select 1'" },
		{ category: "network_send", object: "api.example.com", read: "curl https://api.example.com/health" },
		{ category: "process_control", object: "nginx.service", read: "systemctl status nginx" },
		{ category: "system_config", object: "nginx.service", read: "systemctl show nginx" },
	]
	for (const row of SERVICE_ROWS) {
		it(`${row.category} on ${row.object} covers reading it (${row.read})`, () => {
			const rows = [{ category: row.category, value: row.object, quote: `you may work on ${row.object}` }]
			expect(covers(rows, "read_only", row.object)).toBe(true)
			// …and nothing else of that kind: a grant about one daemon is not a grant about every host.
			expect(covers(rows, "read_only", "some-other-object")).toBe(false)
			// One row's OWN effect is not asserted here: whether it answers its own category also depends on
			// the verb gate, which is pinned in its own tests, not by a fixture quote.
		})
	}
	it("a category-wide service row names no object, so it covers no read", () => {
		expect(covers([{ category: "container_mutation", value: "*", quote: "you can use docker" }], "read_only", "docker:default")).toBe(false)
	})
	it("a service grant never reaches a secret read", () => {
		const rows = [{ category: "cluster_mutation", value: "cluster/prod", quote: "you may work on the cluster" }]
		expect(covers(rows, "read_secret", "cluster/prod")).toBe(false)
	})
	it("and a package grant is not a read of the mirror", () => {
		expect(covers([{ category: "package_system", value: "apt", quote: "install ripgrep" }], "read_only", "apt")).toBe(false)
	})
	it("a compound row counts as its own segments: write+delete answers the read", () => {
		const rows = [{ category: "write_outside+delete_outside", value: "/home/u/w/a.ts", quote: "fix or drop the file" }]
		expect(covers(rows, "read_only", "/home/u/w/a.ts")).toBe(true)
		expect(covers(rows, "read_only", "/home/u/w/b.ts")).toBe(false)
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
	it("a service grant's read coverage dies to a forbid on the same object", () => {
		const rows: Row[] = [
			{ category: "container_mutation", value: "docker:default", quote: "you may work on docker" },
			{ type: "forbid", category: "read_only", value: "docker:default", quote: "stop looking at the containers", seq: 9 },
		]
		// The forbid is newer, so it wins outright — the service read coverage is a coverage rule, not a rank.
		expect(covers(rows, "read_only", "docker:default")).toBe(false)
		expect(forbidden(rows, "read_only", "docker:default")).toBe(true)
		// A later grant for the same object revives it: newest user statement wins, as everywhere else.
		const revived: Row[] = [...rows, { category: "read_only", value: "docker:default", quote: "fine, look at them", seq: 12 }]
		expect(covers(revived, "read_only", "docker:default")).toBe(true)
	})
})
