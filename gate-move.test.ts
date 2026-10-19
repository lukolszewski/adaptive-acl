/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * End-to-end proof for the mv symptom: approving a move must stop it prompting,
 * at the GATE level (not just ledgerCovers), and the delete-verb gate must still
 * refuse a grant whose words never authorised a delete.
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
	it("a quote naming the move authorises it — no prompt, no model call", async () => {
		const r = await runGate("bash", { command: "mv /x/x/a /x/x/b" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: ["move the file into /x/x/"],
		});
		expect(r.outcome).toBe("allow-granted");
		expect(r.grantedBy).toBe("ledger");
		expect(r.modelCalls).toHaveLength(0);
	});

	it("same verdict when an innocent clause comes first", async () => {
		// This is the case that used to be decided by segment order: `echo done` is
		// allow-tier, so the compound's first-listed category changed which
		// category the ledger treated the command as.
		const r = await runGate("bash", { command: "echo done && mv /x/x/a /x/x/b" }, {
			policy: POLICY,
			ledger: ledgerWith("move the file into /x/x/"),
			userMessages: ["move the file into /x/x/"],
		});
		expect(r.outcome).toBe("allow-granted");
	});

	it("a grant whose words never mentioned deleting still cannot authorise rm", async () => {
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
});
