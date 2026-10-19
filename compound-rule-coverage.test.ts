/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import { bashCommandMatchesRuleContent } from "./bash-permission-match.ts";

/**
 * CURRENT BEHAVIOUR — DEFECT PIN, not an endorsement.
 *
 * For behavior==="allow", bashCommandMatchesRuleContent sets
 * segmentsToCheck = [] whenever the command splits into more than one segment,
 * so the matching loop never runs: NO allow rule can cover a compound command,
 * not even a rule containing the identical text. Deny/ask do inspect segments,
 * which is the asymmetry that shows the original intent: refuse to let a prefix
 * rule cover `a && b` when only `a` is authorised. The safe reading of that
 * intent is "every segment needs its own authority", not "compounds are
 * uncoverable".
 *
 * STATUS: fixed at the CALLER, not here. `evaluateToolPermission` now covers
 * compounds via per-segment AND (see compound-allow-and.test.ts), so a compound
 * command no longer prompts forever. This matcher still behaves as described and
 * these assertions are still TRUE — do NOT invert them. The single-rule matcher
 * structurally cannot express AND-across-segments, which is why the fix lives
 * where the whole rule set is visible.
 *
 * Why the refusal is still here: keeping it means any future caller that forgets
 * the AND semantics fails closed (no match) rather than covering `a && b` on the
 * strength of a rule for `a` alone.
 */
describe("compound commands vs allow rules (defect pin)", () => {
	it("single command is covered by its prefix rule", () => {
		expect(bashCommandMatchesRuleContent("git status", "git status:*", "allow")).toBe(true);
	});

	it("the SAME command with an innocent extra clause is covered by nothing", () => {
		// Pin: currently false. After the fix, requires BOTH segments covered.
		expect(bashCommandMatchesRuleContent("git status && echo done", "git status:*", "allow")).toBe(false);
	});

	it("not even a rule holding the identical compound text covers it", () => {
		// Pin: currently false — the whole-command candidate is never compared
		// because segmentsToCheck is empty for a multi-segment command.
		const cmd = "git status && echo done";
		expect(bashCommandMatchesRuleContent(cmd, `${cmd}:*`, "allow")).toBe(false);
	});

	it("only a tool-wide rule reaches a compound", () => {
		expect(bashCommandMatchesRuleContent("git status && echo done", undefined, "allow")).toBe(true);
	});

	it("deny behaviour does inspect segments (the asymmetry, pinned)", () => {
		// This half is why the code looks intentional — deny must not be evadable
		// by padding a command with an innocent clause.
		expect(bashCommandMatchesRuleContent("git status && rm -rf /x", "rm:*", "deny")).toBe(true);
	});

	it("so an allow rule cannot be widened by padding, but also cannot ever help", () => {
		// Both facts at once: safe against padding, useless for coverage.
		expect(bashCommandMatchesRuleContent("git status && rm -rf /x", "git status:*", "allow")).toBe(false);
		expect(bashCommandMatchesRuleContent("git status", "git status:*", "deny")).toBe(true);
	});
});
