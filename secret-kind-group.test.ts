/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * A grant to read a secret-bearing path must never authorise writing it.
 *
 * `read_secret` and `write_sensitive` used to share the kind group "secret", and
 * `compatible()` is pure group equality, so they authorised each other. Reading a
 * credential file and mutating it are different permissions; a user who said "you
 * may read this" did not say "you may rewrite this".
 *
 * The write→read direction is the ONE direction the group split does not close, and it must not: you cannot
 * edit a credentials file without opening it first. It stays one-way, so the pin above is what the file exists
 * for and the read side is now asserted alongside it.
 */
import { describe, expect, it } from "vitest"
import { applyEvent, createLedger, ledgerCovers } from "./auth-ledger.ts"
import type { Entity } from "./risk-policy.ts"

const HOME = "/home/u"
const SECRET = "/home/u/.pi/agent/adaptive-acl.json"

function granted(category: string) {
	const l = createLedger()
	applyEvent(l, {
		type: "grant",
		category,
		value: SECRET,
		kind: "entity",
		quote: `you can touch ${SECRET}`,
		messageId: "m1",
		seq: 1,
	})
	return l
}

/** What the gate hands `ledgerCovers` for a single-path tool call. */
const target: Entity[] = [{ kind: "target", value: SECRET }]

describe("secret read and secret write are separate permissions", () => {
	it("a read grant does not authorise writing the same path", () => {
		expect(ledgerCovers(granted("read_secret"), "write_sensitive", target, HOME).covered).toBe(false)
	})

	it("a write grant DOES authorise reading the same path (an edit needs a read first)", () => {
		// The line used to assert `false` on the reasoning that reading and writing a secret are different
		// permissions. The direction that holds is the ordinary one: to edit the file you must open it,
		// and within the row's own value the read comes with the write. What the split still guarantees is the
		// OTHER direction, pinned above: a read grant buys no write.
		expect(ledgerCovers(granted("write_sensitive"), "read_secret", target, HOME).covered).toBe(true)
		// …and only inside the value the row names.
		const elsewhere: Entity[] = [{ kind: "target", value: "/home/u/.ssh/id_rsa" }]
		expect(ledgerCovers(granted("write_sensitive"), "read_secret", elsewhere, HOME).covered).toBe(false)
	})

	it("each still authorises its own kind", () => {
		expect(ledgerCovers(granted("read_secret"), "read_secret", target, HOME).covered).toBe(true)
		expect(ledgerCovers(granted("write_sensitive"), "write_sensitive", target, HOME).covered).toBe(true)
	})

	it("an unrelated category is not covered either", () => {
		expect(ledgerCovers(granted("read_secret"), "delete_outside", target, HOME).covered).toBe(false)
	})
})
