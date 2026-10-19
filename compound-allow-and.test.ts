/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
} from "./permissions.ts";

// (A) per-leg AND for allow rules.
// The invariant that matters: a compound is allowed only when EVERY leg was
// separately authorised. Padding must gain nothing, and nothing may pre-empt the
// layer-0 analysis for values decided at run time. The legs come from the walker
// (bash-audit.ts) and the per-leg match is bash-rule-argv.ts's, so this file is a
// black-box pin on evaluateToolPermission rather than a description of how it works.

const cwd = "/home/user/project";

function rules(cfg: { allow?: string[]; deny?: string[]; ask?: string[] }) {
	return mergePermissionRules(rulesFromPermissionsConfig(cfg, "project"));
}

function verdict(command: string, cfg: { allow?: string[]; deny?: string[]; ask?: string[] }) {
	return evaluateToolPermission("bash", { command }, cwd, rules(cfg));
}

describe("compound allow requires every segment authorised", () => {
	it("one authorised half is not enough", () => {
		expect(verdict("git status && echo done", { allow: ["Bash(git status:*)"] }).behavior).toBe("passthrough");
	});

	it("both halves authorised covers it", () => {
		expect(verdict("git status && echo done", { allow: ["Bash(git status:*)", "Bash(echo:*)"] }).behavior).toBe("allow");
	});

	it("padding an authorised command with a destructive clause gains nothing", () => {
		// THE attack this whole design exists to stop.
		expect(verdict("git status && rm -rf /x", { allow: ["Bash(git status:*)"] }).behavior).toBe("passthrough");
	});

	it("...and it stays blocked even when the first half is broadly allowed", () => {
		expect(verdict("git status && rm -rf /x", { allow: ["Bash(git:*)"] }).behavior).toBe("passthrough");
	});

	it("deliberately authorising both halves does cover the compound", () => {
		expect(
			verdict("git status && rm -rf /x", { allow: ["Bash(git status:*)", "Bash(rm:*)"] }).behavior,
		).toBe("allow");
	});

	it("deny still wins on any segment", () => {
		expect(
			verdict("git status && rm -rf /x", {
				allow: ["Bash(git status:*)", "Bash(rm:*)"],
				deny: ["Bash(rm *)"],
			}).behavior,
		).toBe("deny");
	});

	it("an ask rule still forces a prompt despite full allow coverage", () => {
		expect(
			verdict("git status && echo done", {
				allow: ["Bash(git status:*)", "Bash(echo:*)"],
				ask: ["Bash(git status:*)"],
			}).behavior,
		).toBe("ask");
	});
});

describe("no regression on what already worked", () => {
	it("single command unchanged", () => {
		expect(verdict("git status", { allow: ["Bash(git status:*)"] }).behavior).toBe("allow");
		expect(verdict("npm run test", { allow: ["Bash(npm run:*)"] }).behavior).toBe("allow");
	});

	it("space-star rule form still works, single and compound", () => {
		expect(verdict("git status", { allow: ["Bash(git *)"] }).behavior).toBe("allow");
		expect(verdict("git status && git log", { allow: ["Bash(git *)"] }).behavior).toBe("allow");
	});

	it("a tool-wide Bash rule still reaches a compound", () => {
		// …and still does not reach an unproven one; that refusal is pinned in bash-allow-layer0.test.ts.
		expect(verdict("git status && echo done", { allow: ["Bash"] }).behavior).toBe("allow");
	});

	it("unrelated allow rule does not cover a compound", () => {
		expect(verdict("git status && echo done", { allow: ["Bash(npm:*)"] }).behavior).toBe("passthrough");
	});
});

describe("hand runtime-determined values back to the analyzer", () => {
	it("a substitution inside a covered compound is NOT allowed by rules", () => {
		// Both halves are allowed, yet this must not be waved through: the rule path
		// runs before the AST analyzer, which is what flags unproven argv.
		expect(
			verdict("git status && echo $(rm -rf /tmp/x)", {
				allow: ["Bash(git status:*)", "Bash(echo:*)"],
			}).behavior,
		).toBe("passthrough");
	});

	it("backticks likewise", () => {
		expect(
			verdict("git status && echo `id`", { allow: ["Bash(git status:*)", "Bash(echo:*)"] }).behavior,
		).toBe("passthrough");
	});

	it("CLOSED: a leg the walker cannot prove is covered by nothing, single segment included", () => {
		// This was pinned the other way as a KNOWN PRE-EXISTING EXPOSURE, with a note that closing it
		// should be "a decision made deliberately, not as collateral". It is that decision now, taken on
		// 2026-10-14: rule coverage never applies to a leg the walker could not
		// prove, and an unproven leg goes to the prompt regardless of what rules exist. A rule for `diff`
		// or `git log` says nothing about what `$(whoami)` runs; the prompt is the only channel that can.
		expect(
			verdict("diff <(git show a) <(git show b)", { allow: ["Bash(diff:*)"] }).behavior,
		).toBe("passthrough");
		expect(verdict("git log $(whoami)", { allow: ["Bash(git log:*)"] }).behavior).toBe("passthrough");
		// The same rule over proven argv is still covered: the tightening is scoped to the unproven construct.
		expect(verdict("git log --oneline", { allow: ["Bash(git log:*)"] }).behavior).toBe("allow");
	});
});

describe("loops fail closed rather than being textually covered", () => {
	it("a for loop is not covered by a rule for its first word", () => {
		// The walker refuses the whole construct (`loop-body`), so there is no leg for a rule to cover —
		// the same verdict the old scanner reached by cutting the body out on ';'.
		expect(verdict("for f in a b; do rm -f $f; done", { allow: ["Bash(for:*)"] }).behavior).toBe("passthrough");
	});

	it("pipeline needs both halves", () => {
		expect(verdict("git log | grep x", { allow: ["Bash(git log:*)"] }).behavior).toBe("passthrough");
		expect(verdict("git log | grep x", { allow: ["Bash(git log:*)", "Bash(grep:*)"] }).behavior).toBe("allow");
	});
});
