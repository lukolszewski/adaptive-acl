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

describe("delete-verb gate no longer depends on segment order", () => {
	// Real entities from the real analyzer, not hand-built fixtures.
	const verdicts = evaluateBash("mv /x/x/a /x/x/b", opts);
	const entities = verdicts.entities;

	it("the command really produces both path entities", () => {
		const vals = entities.filter((e) => e.kind === "target").map((e) => e.value).sort();
		expect(vals).toEqual(["/x/x/a", "/x/x/b"]);
	});

	for (const category of ["write_outside+delete_outside", "delete_outside+write_outside"]) {
		it(`${category}: a write grant alone cannot authorise the delete half`, () => {
			const ledger = createLedger();
			ledger.grants.push(grant("put the files under /x/x"));
			const v = ledgerCovers(ledger, category, entities);
			expect(v.covered, `order ${category} must require the delete verb`).toBe(false);
		});

		it(`${category}: a quote naming the action still authorises it`, () => {
			const ledger = createLedger();
			ledger.grants.push(grant("rm everything under /x/x"));
			expect(ledgerCovers(ledger, category, entities).covered).toBe(true);
		});
	}

	it("a quote naming the move authorises the move-produced delete half", () => {
		// mv/move/rename are what actually produce the delete_outside half of a move,
		// so they have to satisfy the gate that half arms.
		const ledger = createLedger();
		ledger.grants.push(grant("move the config under /x/x"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(true);
		expect(ledgerCovers(ledger, "write_outside+delete_outside", entities).covered).toBe(true);
	});

	it("a quote with no destructive verb still does not", () => {
		const ledger = createLedger();
		ledger.grants.push(grant("keep the config where it is"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(false);
	});

	it("delete-only verbs satisfy the gate", () => {
		// These words can only ever accompany a deletion, so unlike `move` they add no
		// ordinary-English false-positive path. Pinned so a future tidy-up does not drop
		// them and re-create an unsatisfiable gate for rmdir/unlink/trash/shred.
		for (const quote of [
			"unlink the socket under /x/x",
			"rmdir the old folder under /x/x",
			"trash the stale file under /x/x",
			"shred the secret under /x/x",
		]) {
			const ledger = createLedger();
			ledger.grants.push(grant(quote));
			expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered, quote).toBe(true);
		}
	});

	it("accepted trade-off: the word 'move' alone satisfies the verb requirement", () => {
		// Pinned on purpose. "move" is ordinary English, so an unrelated grant quote
		// that happens to target this path can satisfy the delete-verb check. The
		// remaining bound is valueCovers on the grant target, not the wording. If this
		// ever needs tightening, tighten the verb-to-category binding, not the gate.
		const ledger = createLedger();
		ledger.grants.push(grant("move on to the next step"));
		expect(ledgerCovers(ledger, "delete_outside+write_outside", entities).covered).toBe(true);
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
});

describe("compound commands behave identically regardless of clause order", () => {
	it("`echo done && mv …` and `mv … && echo done` agree on tier and category set", () => {
		const one = evaluateBash("echo done && mv /x/x/a /x/x/b", opts);
		const other = evaluateBash("mv /x/x/a /x/x/b && echo done", opts);
		expect(one.tier).toBe(other.tier);
		expect([...one.category.split("+")].sort()).toEqual([...other.category.split("+")].sort());
	});
});
