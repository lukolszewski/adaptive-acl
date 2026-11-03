/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import { compoundAll, compoundHas, createLedger, ledgerCovers, type LedgerEntry } from "./auth-ledger.ts";
import { evaluateBash, type PolicyOptions } from "./risk-policy.ts";

// A compound category joins the effects of several segments in COMPOSITION order,
// not severity order. Every reader that took `split("+")[0]` as "the" category made
// its answer depend on that order — and for the delete-verb gate that skipped a
// security check outright (fail open) instead of applying it.
//
// Fix shape: requirements use a UNION over segments (any delete arms the verb gate),
// exemptions use an INTERSECTION (all must be exempt). Both are monotone, so the
// change cannot loosen anything.
//
// The verb gate this file's middle describe used to exercise is gone — a row reaches only its
// own kind group, so the ORDER property below is now about segment coverage, not about which
// half armed the word check. The order-independence is still the thing being pinned; only the
// expected verdicts changed.

const opts: PolicyOptions = { cwd: "/tmp/proj", fs: false };

function grant(quote: string): LedgerEntry {
	return {
		category: "write_outside",
		value: "/x/x/",
		kind: "scope",
		quote,
		messageId: "m1",
		seq: 1,
	};
}

describe("compoundHas / compoundAll are order-independent", () => {
	const dels = new Set(["delete_outside", "delete_recursive"]);
	const exempt = new Set(["read_only", "read_secret"]);

	it("union finds the marker in either position", () => {
		expect(compoundHas("write_outside+delete_outside", dels)).toBe(true);
		expect(compoundHas("delete_outside+write_outside", dels)).toBe(true);
		expect(compoundHas("write_outside+perm_change", dels)).toBe(false);
	});

	it("intersection requires every part to qualify", () => {
		expect(compoundAll("read_only+read_secret", exempt)).toBe(true);
		expect(compoundAll("read_secret", exempt)).toBe(true);
		expect(compoundAll("read_secret+write_outside", exempt)).toBe(false);
		expect(compoundAll("write_outside+read_secret", exempt)).toBe(false);
	});
});

describe("a delete segment inside a granted scope, in either order", () => {
	// Real entities from the real analyzer, not hand-built fixtures.
	const verdicts = evaluateBash("mv /x/x/a /x/x/b", opts);
	const entities = verdicts.entities;

	it("the command really produces both path entities", () => {
		const vals = entities.filter((e) => e.kind === "target").map((e) => e.value).sort();
		expect(vals).toEqual(["/x/x/a", "/x/x/b"]);
	});

	for (const category of ["write_outside+delete_outside", "delete_outside+write_outside"]) {
		it(`${category}: a write grant answers the single-file delete half`, () => {
			const ledger = createLedger();
			ledger.grants.push(grant("put the files under /x/x"));
			const v = ledgerCovers(ledger, category, entities);
			expect(v.covered, `order ${category}: a single-file delete inside the granted scope`).toBe(true);
		});

		it(`${category}: …and the quote's wording is still not what answers it`, () => {
			// This pair used to be refused outright: "a delete needs a row the model filed under a delete
			// category". Exactly ONE shape of it is now open, as a rule about the category and the target —
			// removing a single file is part of editing it, and `mv` is delete+write — so a `write_outside`
			// row over /x/x/ answers the `delete_outside` half.
			//
			// What is still NOT true, and is the reason this is not a word list in disguise: the sentence buys
			// nothing a category rule did not already give it. A recursive delete under the same row and the
			// same words is refused (asserted here, and once more in the exclusions below).
			const ledger = createLedger();
			ledger.grants.push(grant("rm everything under /x/x"));
			expect(ledgerCovers(ledger, category, entities).covered).toBe(true);
			expect(ledgerCovers(ledger, "delete_recursive", entities).covered).toBe(false);
		});
	}

	it("a quote naming the move is no longer what decides the move's delete half", () => {
		// mv/move/rename used to satisfy the delete-verb gate from the quote text, and that read is gone.
		// The verdict now comes from the category rule whether or not the sentence says "move", and the
		// three excluded cases are refused whatever it says.
		const ledger = createLedger();
		ledger.grants.push(grant("move the config under /x/x"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(true);
		expect(ledgerCovers(ledger, "write_outside+delete_outside", entities).covered).toBe(true);
		expect(ledgerCovers(ledger, "delete_recursive", entities).covered).toBe(false);
		expect(ledgerCovers(ledger, "delete_data", entities).covered).toBe(false);
	});

	it("a quote that names nothing at all gets the same verdict: the quote is not the evidence", () => {
		// The row's category and the target are. A sentence about keeping things where they are would never have
		// earned the row in the first place — the extraction prompt and the verbatim quote check own that end.
		const ledger = createLedger();
		ledger.grants.push(grant("keep the config where it is"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(true);
		expect(ledgerCovers(ledger, "delete_recursive", entities).covered).toBe(false);
	});

	it("delete-flavoured wording buys no RECURSIVE delete, whatever it says", () => {
		// These words used to be the strongest entries in the delete-verb table, and they still buy nothing a
		// category rule does not: the single-file verdict is identical for every one of them, and a recursive
		// delete under a content row stays refused.
		for (const quote of [
			"unlink the socket under /x/x",
			"rmdir the old folder under /x/x",
			"trash the stale file under /x/x",
			"shred the secret under /x/x",
		]) {
			const ledger = createLedger();
			ledger.grants.push(grant(quote));
			expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered, quote).toBe(true);
			expect(ledgerCovers(ledger, "delete_recursive", entities).covered, quote).toBe(false);
		}
	});

	it("the recorded 'move' trade-off is gone: ordinary English decides nothing", () => {
		// Kept as the same pin, with the verdict the category rule gives it: a sentence containing
		// "move" behaves exactly like one that contains no destructive word at all, so a re-added word list
		// shows up here as a differing verdict.
		const ledger = createLedger();
		ledger.grants.push(grant("move on to the next step"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(true);
		expect(ledgerCovers(ledger, "delete_recursive", entities).covered).toBe(false);
	});

	it("the three refusals that remain: recursive, data, and the granted folder itself", () => {
		const ledger = createLedger();
		ledger.grants.push(grant("put the files under /x/x"));
		// A file INSIDE the scope is removable…
		expect(ledgerCovers(ledger, "delete_outside", [{ kind: "target", value: "/x/x/a" }] as never).covered).toBe(true);
		// …the folder the row was granted over is not.
		expect(ledgerCovers(ledger, "delete_outside", [{ kind: "target", value: "/x/x" }] as never).covered).toBe(false);
		// A file grant removes that file, not its sibling.
		const oneFile = createLedger();
		oneFile.grants.push({ ...grant("put the file at /x/x/a"), value: "/x/x/a", kind: "entity" });
		expect(ledgerCovers(oneFile, "delete_outside", [{ kind: "target", value: "/x/x/a" }] as never).covered).toBe(true);
		expect(ledgerCovers(oneFile, "delete_outside", [{ kind: "target", value: "/x/x/b" }] as never).covered).toBe(false);
	});

	it("both orders reach the same verdict", () => {
		const build = () => {
			const l = createLedger();
			l.grants.push(grant("put the files under /x/x"));
			return l;
		};
		const a = ledgerCovers(build(), "write_outside+delete_outside", entities).covered;
		const b = ledgerCovers(build(), "delete_outside+write_outside", entities).covered;
		expect(a).toBe(b);
	});

	it("every segment of a compound is answered by its own row, with no category-wide verb gate", () => {
		// Per-segment matching, and now per-segment AUTHORITY: the delete gate that used to be computed
		// over the whole pending (`compoundHas`) is deleted, so a compound is covered when each half has
		// a row in its own kind group. No row is any longer asked for a destructive word.
		const rows = (rowsIn: Array<{ category: string; quote: string }>) => {
			const ledger = createLedger();
			rowsIn.forEach((r, i) => {
				ledger.grants.push({
					category: r.category,
					value: "/x/x/a",
					kind: "entity",
					quote: r.quote,
					messageId: `m${i + 1}`,
					seq: i + 1,
				} as never);
			});
			return ledger;
		};
		const oneTarget = [{ kind: "target", value: "/x/x/a" }] as never;

		// Two rows, each in its own kind group, answer the two halves — this used to be refused because
		// neither sentence was about the other half's destruction. Coverage still needs BOTH rows: the
		// perm_change row cannot answer the delete half and the delete row cannot answer the chmod half
		// (the next assertion). Direction is pinned, only its polarity moved.
		expect(
			ledgerCovers(
				rows([
					{ category: "perm_change", quote: "chmod the file /x/x/a whenever you like" },
					{ category: "delete_outside", quote: "rm /x/x/a whenever you like" },
				]),
				"perm_change+delete_outside",
				oneTarget,
			).covered,
		).toBe(true);

		// A single destructive row is not enough: the chmod half still needs a row in the privilege
		// group, and no row reaches across kind groups.
		expect(
			ledgerCovers(
				rows([{ category: "delete_outside", quote: "rm /x/x/a whenever you like" }]),
				"perm_change+delete_outside",
				oneTarget,
			).covered,
		).toBe(false);
		// Both halves present, the first row's sentence now including "rm": same verdict as above, and
		// the wording is irrelevant to it.
		expect(
			ledgerCovers(
				rows([
					{ category: "perm_change", quote: "chmod and then rm /x/x/a whenever you like" },
					{ category: "delete_outside", quote: "rm /x/x/a whenever you like" },
				]),
				"perm_change+delete_outside",
				oneTarget,
			).covered,
		).toBe(true);
	});
});

describe("compound commands behave identically regardless of clause order", () => {
	it("`echo done && mv …` and `mv … && echo done` agree on tier and category set", () => {
		const one = evaluateBash("echo done && mv /x/x/a /x/x/b", opts);
		const other = evaluateBash("mv /x/x/a /x/x/b && echo done", opts);
		expect(one.tier).toBe(other.tier);
		expect([...one.category.split("+")].sort()).toEqual([...other.category.split("+")].sort());
	});
});
