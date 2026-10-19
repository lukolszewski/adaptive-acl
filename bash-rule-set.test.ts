/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import { suggestBashAllowRule, suggestBashAllowRuleSet } from "./bash-permission-match.ts";
import { bashRuleCoversArgv } from "./bash-rule-argv.ts";
import { permissionRuleValueFromString } from "./permission-rule-parser.ts";
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
} from "./permissions.ts";

// (B) what an "always allow" writes.
// The failure being fixed: a compound approval wrote ONE rule from the head of the
// command, so the rule covered one clause while coverage requires every clause —
// the command prompted again and the extra rule sat there doing nothing.

const cwd = "/home/user/project";

function coveredBy(command: string, rules: string[]) {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig({ allow: rules }, "project")),
	).behavior;
}

describe("one rule per segment", () => {
	it("a two-clause command yields two rules", () => {
		const set = suggestBashAllowRuleSet("git status && echo done");
		expect(set.persistable).toBe(true);
		// git has a subcommand grammar, so `git status:*` generalises. echo does not:
		// `done` is just an argument, so the rule stays exact rather than becoming a
		// dead `echo done:*` or, worse, a blanket `echo:*`.
		expect(set.rules).toEqual(["Bash(git status:*)", "Bash(echo done)"]);
	});

	it("persisting that set stops the command prompting", () => {
		const cmd = "git status && echo done";
		expect(coveredBy(cmd, suggestBashAllowRuleSet(cmd).rules)).toBe("allow");
	});

	it("a single command is unchanged from the single-rule suggestion", () => {
		for (const cmd of ["git commit -m 'x'", "npm run build", "gh pr view 3"]) {
			const set = suggestBashAllowRuleSet(cmd);
			expect(set.rules).toEqual([suggestBashAllowRule(cmd)]);
		}
	});
});

describe("destructive segments never become prefix rules", () => {
	it("the rm clause contributes an exact rule, the git clause a prefix", () => {
		const set = suggestBashAllowRuleSet("git status && rm -rf /tmp/x");
		expect(set.rules).toContain("Bash(git status:*)");
		const rmRules = set.rules.filter((r) => r.includes("rm"));
		expect(rmRules).toEqual(["Bash(rm -rf /tmp/x)"]);
		expect(rmRules[0]).not.toContain(":*");
	});

	it("the approved compound is covered, a different deletion is not", () => {
		const cmd = "git status && rm -rf /tmp/x";
		const rules = suggestBashAllowRuleSet(cmd).rules;
		expect(coveredBy(cmd, rules)).toBe("allow");
		// THE property: an exact grant must not generalise into destruction power.
		expect(coveredBy("rm -rf /tmp/y", rules)).toBe("passthrough");
		expect(coveredBy("git status && rm -rf /tmp/y", rules)).toBe("passthrough");
	});

	it("mv is exact too, since the source path is what gets destroyed", () => {
		const set = suggestBashAllowRuleSet("mv /x/x/a /x/x/b");
		expect(set.rules).toEqual(["Bash(mv /x/x/a /x/x/b)"]);
	});

	it("find is exact — a prefix over find is a search-everything grant", () => {
		expect(suggestBashAllowRuleSet("find . -name x").rules).toEqual(["Bash(find . -name x)"]);
	});
});

describe("refuses to persist what it cannot honour", () => {
	it("run-time values", () => {
		for (const cmd of ["git status && echo $(whoami)", "git status && echo `id`"]) {
			const set = suggestBashAllowRuleSet(cmd);
			expect(set.persistable, cmd).toBe(false);
			expect(set.rules, cmd).toEqual([]);
		}
	});

	it("shell control flow", () => {
		for (const cmd of ["for f in a b; do rm -f $f; done", "if test -f x; then echo y; fi"]) {
			const set = suggestBashAllowRuleSet(cmd);
			expect(set.persistable, cmd).toBe(false);
		}
	});

	it("nothing persisted means the command still goes to the gate", () => {
		const cmd = "git status && echo $(whoami)";
		expect(coveredBy(cmd, suggestBashAllowRuleSet(cmd).rules)).toBe("passthrough");
	});

	it("empty command", () => {
		expect(suggestBashAllowRuleSet("   ").persistable).toBe(false);
	});
});

describe("the rules that get written are rules the argv matcher can read", () => {
	// What an "always allow" is for: the next invocation stops prompting. On the text path that round
	// trip was broken for compounds — one rule was written for the head clause, while coverage needed
	// every clause — so the command asked again forever. The set above writes one rule per leg, and
	// coverage asks `bashRuleCoversArgv` per leg (`permissions.ts`), so this pins the two halves against
	// each other: for every leg of these commands, some rule in the written set covers that leg's argv.
	const LEGS: Record<string, string[][]> = {
		"git status && echo done": [["git", "status"], ["echo", "done"]],
		"git status && rm -rf /tmp/x": [["git", "status"], ["rm", "-rf", "/tmp/x"]],
		"mv /x/x/a /x/x/b": [["mv", "/x/x/a", "/x/x/b"]],
		"find . -name x": [["find", ".", "-name", "x"]],
		"npm run build": [["npm", "run", "build"]],
	};

	function allowRules(ruleStrings: string[]) {
		return ruleStrings.map((r) => ({
			source: "project" as const,
			behavior: "allow" as const,
			ruleValue: permissionRuleValueFromString(r),
		}));
	}

	for (const [command, legs] of Object.entries(LEGS)) {
		it(`every leg of ${JSON.stringify(command)} is covered by its own rule`, () => {
			const rules = allowRules(suggestBashAllowRuleSet(command).rules);
			expect(rules.length, command).toBeGreaterThan(0);
			for (const leg of legs) {
				const label = `${command} — leg ${leg.join(" ")}`;
				expect(rules.some((r) => bashRuleCoversArgv(r, leg)), label).toBe(true);
			}
		});
	}

	it("covering the leg does not cover a different destruction on it", () => {
		const rules = allowRules(suggestBashAllowRuleSet("git status && rm -rf /tmp/x").rules);
		expect(rules.some((r) => bashRuleCoversArgv(r, ["rm", "-rf", "/tmp/y"]))).toBe(false);
		expect(rules.some((r) => bashRuleCoversArgv(r, ["rm", "-rf", "/"]))).toBe(false);
	});
});

describe("non-bash tools keep their single-rule behaviour", () => {
	it("edit yields one rule, unchanged", () => {
		const set = suggestAllowRuleSetForToolCall("edit", { path: "src/a/b.ts" }, cwd);
		expect(set.persistable).toBe(true);
		expect(set.rules).toHaveLength(1);
	});

	it("bash tool call routes through the set function", () => {
		const set = suggestAllowRuleSetForToolCall("bash", { command: "git status && echo done" }, cwd);
		expect(set.rules).toEqual(["Bash(git status:*)", "Bash(echo done)"]);
	});
});

describe("generic verbs can never become wildcard grants", () => {
	// Output redirection is stripped before rule matching, so a prefix rule over a
	// verb that writes via redirection is a write-everywhere grant. `echo:*` would
	// match `echo key > ~/.ssh/authorized_keys`. Shape-based detection cannot
	// prevent this — `echo done` looks exactly like `git commit` — so only tools
	// with a real subcommand grammar generalise.
	it.each([
		"echo done",
		"printf hello",
		"cat notes.txt",
		"tee out.txt",
		"touch newfile",
		"python3 -c 'print(1)'",
	])("%s stays exact", (cmd) => {
		const rule = suggestBashAllowRule(cmd);
		expect(rule, cmd).not.toContain(":*");
		expect(suggestBashAllowRuleSet(cmd).rules[0], cmd).not.toContain(":*");
	});

	it("real subcommands still generalise", () => {
		expect(suggestBashAllowRule("git commit -m x")).toBe("Bash(git commit:*)");
		expect(suggestBashAllowRule("kubectl get pods")).toBe("Bash(kubectl get:*)");
		expect(suggestBashAllowRule("brew install ripgrep")).toBe("Bash(brew install:*)");
		expect(suggestBashAllowRule("terraform plan -out=x")).toBe("Bash(terraform plan:*)");
	});

	it("a redirect on a read-only verb is not covered by that verb alone", () => {
		// Documents the exposure the wildcard rule would have created: exact rules
		// keep the redirect part of the match.
		const rules = suggestBashAllowRuleSet("echo hi").rules;
		expect(rules).toEqual(["Bash(echo hi)"]);
		expect(coveredBy("echo key > ~/.ssh/authorized_keys", rules)).toBe("passthrough");
	});
});
