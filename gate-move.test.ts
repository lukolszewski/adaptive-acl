/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * End-to-end proof for the mv symptom, at the GATE level (not just ledgerCovers).
 *
 * A `write_outside` row answers neither half of a move, except for one shape that is about the TARGET rather
 * than a word in a quote: a write grant permits removing a single file inside what it names (`rm file`, and
 * `mv`, which is delete+write). What is still pinned here is that a move over a granted scope is settled
 * WITHOUT a model call when it is covered, that it still prompts outside the scope, that a recursive delete is
 * untouched, and that segment order never changes the answer.
 */
import { describe, expect, it } from "vitest";
import { applyEvent, createLedger } from "./auth-ledger.ts";
import { runGate } from "./gate.ts";

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" };

function ledgerWith(quote: string) {
	const l = createLedger();
	applyEvent(l, {
		type: "grant",
		category: "write_outside",
		value: "/x/x/",
		kind: "scope",
		quote,
		messageId: "m1",
		seq: 1,
	});
	return l;
}

describe("mv against a granted directory", () => {
	it("a content row authorises the single-file move inside its scope", async () => {
		// Both halves of `mv /x/x/a /x/x/b` are inside the granted scope, and a move of ONE file is delete+write
		// under that rule — so the write row answers both and the action runs without paying for a model call.
		const r = await runGate("bash", { command: "mv /x/x/a /x/x/b" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: ["move the file into /x/x/"],
		});
		expect(r.outcome).toBe("allow-granted");
		expect(r.grantedBy).toBe("ledger");
		expect(r.modelCalls).toHaveLength(0); // no endpoint in this test: an allow from the ledger, not from a model
	});

	it("same verdict when an innocent clause comes first", async () => {
		// This is the case that used to be decided by segment order: `echo done` is
		// allow-tier, so the compound's first-listed category changed which
		// category the ledger treated the command as. Order-independence survives either way.
		const r = await runGate("bash", { command: "echo done && mv /x/x/a /x/x/b" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: ["move the file into /x/x/"],
		});
		expect(r.outcome).toBe("allow-granted");
	});

	it("a recursive delete is still not implied by a content row", async () => {
		const r = await runGate("bash", { command: "rm -rf /x/x/old" }, {
			policy: POLICY,
			ledger: ledgerWith("copy the file to /x/x/ with rsync"),
			userMessages: [],
		});
		expect(r.outcome).toBe("prompt");
	});

	it("a move grant does not reach outside its scope", async () => {
		const r = await runGate("bash", { command: "mv /y/y/a /y/y/b" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: ["move the file into /x/x/"],
		});
		expect(r.outcome).toBe("prompt");
	});

	it("and it does not remove the folder the grant was given over", async () => {
		// The one target-shaped refusal: "write inside /x/x/" is not "delete /x/x".
		const r = await runGate("bash", { command: "rm /x/x" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: [],
		});
		expect(r.outcome).toBe("prompt");
	});
});
