/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { describe, expect, it } from "vitest"

import {
	formatDangerousRuleDisplay,
	isDangerousBashPermission,
	isDangerousClassifierPermission,
	restoreDangerousPermissionRules,
	stripDangerousPermissionRules,
} from "./dangerous-permissions.ts"
import {
	permissionRuleValueFromString,
	permissionRuleValueToString,
} from "./permission-rule-parser.ts"
import type {
	PermissionBehavior,
	PermissionRule,
	PermissionRuleSource,
} from "./permissions.ts"

function allowRule(
	ruleString: string,
	source: PermissionRule["source"] = "project",
): PermissionRule {
	return {
		source,
		behavior: "allow",
		ruleValue: permissionRuleValueFromString(ruleString),
	}
}

function ruleOf(
	behavior: PermissionBehavior,
	ruleString: string,
	source: PermissionRuleSource = "project",
): PermissionRule {
	return { source, behavior, ruleValue: permissionRuleValueFromString(ruleString) }
}

/** `allow:Bash(python:*)` — a rule list reduced to something worth diffing. */
function labelled(rules: PermissionRule[]): string[] {
	return rules.map(
		(rule) => `${rule.behavior}:${permissionRuleValueToString(rule.ruleValue)}`,
	)
}

describe("dangerous-permissions", () => {
	it("flags Bash(*) and interpreter prefixes as dangerous", () => {
		expect(isDangerousBashPermission("Bash", undefined)).toBe(true)
		expect(isDangerousBashPermission("Bash", "*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "python:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "npm run:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "curl:*")).toBe(true)
	})

	it("does not flag specific safe-ish allow patterns", () => {
		// Narrow script-scoped rules survive; only broad verb/bare forms are stripped.
		expect(isDangerousBashPermission("Bash", "npm run test *")).toBe(false)
		expect(isDangerousBashPermission("Bash", "npm install lodash:*")).toBe(false)
	})

	// Adjudication ② (2026-09-12): package managers with lifecycle-script
	// execution are dangerous as broad rules — adjudicated 2026-09-12.
	it("flags broad package-manager allow rules as dangerous", () => {
		expect(isDangerousBashPermission("Bash", "npm:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "npm install *")).toBe(true)
		expect(isDangerousBashPermission("Bash", "npm install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "npm ci:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "pnpm add:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "pnpm dlx:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "yarn add:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "bun add:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "bunx:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "pip install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "pip3 install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "cargo install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "cargo run:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "uv run:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "poetry install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "gem install:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "composer require:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "go run:*")).toBe(true)
	})

	it("strips dangerous allow rules on auto entry and restores on exit", () => {
		const rules = [
			allowRule("Bash(npm install *)"),
			allowRule("Bash(python:*)"),
			allowRule("Bash(*)"),
		]
		const stripped = stripDangerousPermissionRules(rules)
		expect(stripped.active).toHaveLength(0)
		expect(stripped.stashed).toHaveLength(3)
		expect(formatDangerousRuleDisplay(stripped.stashed[0]!.ruleValue)).toBe(
			"Bash(npm install *)",
		)
		const restored = restoreDangerousPermissionRules(
			stripped.active,
			stripped.stashed,
		)
		expect(restored).toHaveLength(3)
	})
})

describe("the five blanket forms", () => {
	// N, N:*, N*, N * and N -<flag>*, for a one-word and a multi-word name.
	it.each([
		"git",
		"git:*",
		"git*",
		"git *",
		"git -C*",
		"npm run",
		"npm run:*",
		"npm run*",
		"npm run *",
		"npm run --no-audit*",
	])("treats Bash(%s) as a grant over every command", (ruleContent) => {
		expect(isDangerousBashPermission("Bash", ruleContent)).toBe(true)
	})

	it("needs the trailing star on the flag form", () => {
		expect(isDangerousBashPermission("Bash", "git -C*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "git -C")).toBe(false)
		expect(isDangerousBashPermission("Bash", "npm run --no-audit*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "npm run --no-audit")).toBe(false)
		expect(isDangerousBashPermission("Bash", "git -")).toBe(false)
		expect(isDangerousBashPermission("Bash", "python -")).toBe(false)
	})

	// The name has to end where the pattern ends: no partial-word hits.
	it.each([
		"gitfoo",
		"gitt*",
		"gitlab:*",
		"pythonfoo",
		"python3x",
		"nodejs:*",
		"npmrunner",
		"npm runx",
		"npm runny:*",
		"curlopr:*",
	])("does not treat Bash(%s) as a listed program", (ruleContent) => {
		expect(isDangerousBashPermission("Bash", ruleContent)).toBe(false)
	})

	it.each([
		"npm run test",
		"npm run build:*",
		"git status",
		"git commit -m x",
		"python -m pytest",
		"npm install lodash:*",
		"curl https://example.com/sh.sh",
		"cargo build --release",
		"go run ./cmd",
		"ls",
	])("keeps the narrow rule Bash(%s)", (ruleContent) => {
		expect(isDangerousBashPermission("Bash", ruleContent)).toBe(false)
	})

	it("matches names case-insensitively and ignores padding", () => {
		expect(isDangerousBashPermission("Bash", "PYTHON:*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "Git")).toBe(true)
		expect(isDangerousBashPermission("Bash", "  npm run  ")).toBe(true)
		expect(isDangerousBashPermission("Bash", "\tCurl -*\n")).toBe(true)
		expect(isDangerousBashPermission("Bash", "Npm Install *")).toBe(true)
		expect(isDangerousBashPermission("Bash", "Go Run:*")).toBe(true)
	})
})

describe("rules that name no command", () => {
	it("opens everything", () => {
		expect(isDangerousBashPermission("Bash", undefined)).toBe(true)
		expect(isDangerousBashPermission("Bash", "")).toBe(true)
		expect(isDangerousBashPermission("Bash", "*")).toBe(true)
		expect(isDangerousBashPermission("Bash", "  *  ")).toBe(true)
	})

	it("does not read a whitespace-only rule as the empty rule", () => {
		// Pinned deliberately: padding is trimmed, but content that survives trimming to
		// nothing still has to name a command to be dangerous.
		expect(isDangerousBashPermission("Bash", "   ")).toBe(false)
		expect(isDangerousBashPermission("Bash", "\n")).toBe(false)
	})

	// Only the literal tool name "Bash" describes a shell; note the lower-case "bash" —
	// callers map pi's tool names onto the rule-file spelling before asking.
	const notTheShell: Array<[toolName: string, ruleContent: string | undefined]> = [
		["Edit", undefined],
		["Read", "*"],
		["Write", "python:*"],
		["bash", undefined],
		["Bash ", "*"],
	]
	it.each(notTheShell)("never fires for tool %s", (toolName, ruleContent) => {
		expect(isDangerousBashPermission(toolName, ruleContent)).toBe(false)
	})

	it("asks the same question through the classifier entry point", () => {
		const asked = [
			undefined,
			"*",
			"git",
			"python:*",
			"npm run test",
			"git -v",
			"curl -*",
			"ssh",
		]
		for (const ruleContent of asked) {
			expect(isDangerousClassifierPermission("Bash", ruleContent)).toBe(
				isDangerousBashPermission("Bash", ruleContent),
			)
		}
		expect(isDangerousClassifierPermission("Edit", undefined)).toBe(false)
		expect(isDangerousClassifierPermission("Edit", "npm run:*")).toBe(false)
	})
})

describe("stripping and restoring", () => {
	it("leaves deny and ask rules alone however broad they are", () => {
		const rules = [
			ruleOf("deny", "Bash(python:*)"),
			ruleOf("ask", "Bash(*)"),
			ruleOf("deny", "Bash"),
			ruleOf("ask", "Bash(npm install *)"),
		]
		const stripped = stripDangerousPermissionRules(rules)
		expect(labelled(stripped.active)).toEqual([
			"deny:Bash(python:*)",
			"ask:Bash",
			"deny:Bash",
			"ask:Bash(npm install *)",
		])
		expect(stripped.stashed).toEqual([])
	})

	it("keeps input order inside each half of the split", () => {
		const rules = [
			ruleOf("allow", "Bash(git status)"),
			ruleOf("allow", "Bash(python:*)"),
			ruleOf("deny", "Bash(rm:*)"),
			ruleOf("allow", "Read(src/**)"),
			ruleOf("allow", "Bash(npm install *)"),
			ruleOf("allow", "Bash(curl:*)"),
		]
		const { active, stashed } = stripDangerousPermissionRules(rules)
		expect(labelled(active)).toEqual([
			"allow:Bash(git status)",
			"deny:Bash(rm:*)",
			"allow:Read(src/**)",
		])
		expect(labelled(stashed)).toEqual([
			"allow:Bash(python:*)",
			"allow:Bash(npm install *)",
			"allow:Bash(curl:*)",
		])
	})

	it("moves the rule objects themselves, not copies", () => {
		const rules = [ruleOf("allow", "Bash(git:*)"), ruleOf("allow", "Bash(ls)")]
		const { active, stashed } = stripDangerousPermissionRules(rules)
		expect(stashed[0]).toBe(rules[0])
		expect(active[0]).toBe(rules[1])
	})

	it("returns the very same array when there is nothing to put back", () => {
		const active = [ruleOf("allow", "Bash(git status)")]
		expect(restoreDangerousPermissionRules(active, [])).toBe(active)
	})

	it("appends the stash after the active rules, in stash order", () => {
		const active = [ruleOf("allow", "Bash(git status)")]
		const stashed = [
			ruleOf("allow", "Bash(python:*)"),
			ruleOf("allow", "Bash(curl:*)"),
		]
		expect(labelled(restoreDangerousPermissionRules(active, stashed))).toEqual([
			"allow:Bash(git status)",
			"allow:Bash(python:*)",
			"allow:Bash(curl:*)",
		])
	})

	it("skips a rule the user re-added while auto mode ran", () => {
		const active = [
			ruleOf("allow", "Bash(git status)"),
			ruleOf("allow", "Bash(python:*)"),
		]
		const stashed = [ruleOf("allow", "Bash(python:*)")]
		const restored = restoreDangerousPermissionRules(active, stashed)
		expect(labelled(restored)).toEqual([
			"allow:Bash(git status)",
			"allow:Bash(python:*)",
		])
	})

	it("counts behaviour, rule text and source as one identity", () => {
		const active = [ruleOf("allow", "Bash(git:*)", "global")]
		const stashed = [
			ruleOf("allow", "Bash(git:*)", "project"), // same text, different file → kept
			ruleOf("allow", "Bash(git:*)", "global"), // already there → dropped
		]
		const restored = restoreDangerousPermissionRules(active, stashed)
		expect(restored).toHaveLength(2)
		expect(restored.map((rule) => rule.source)).toEqual(["global", "project"])
	})

	it("collapses a stash entry that appears twice", () => {
		const twice = ruleOf("allow", "Bash(npm:*)")
		expect(restoreDangerousPermissionRules([], [twice, twice])).toHaveLength(1)
	})

	it("round-trips a strip back to the rules it started from", () => {
		const rules = [
			allowRule("Bash(npm install *)"),
			allowRule("Bash(git status)"),
			ruleOf("deny", "Bash(rm:*)"),
			allowRule("Bash(python:*)"),
		]
		const { active, stashed } = stripDangerousPermissionRules(rules)
		expect(labelled(restoreDangerousPermissionRules(active, stashed))).toEqual([
			"allow:Bash(git status)",
			"deny:Bash(rm:*)",
			"allow:Bash(npm install *)",
			"allow:Bash(python:*)",
		])
	})
})

describe("formatDangerousRuleDisplay", () => {
	it("prints the rule the way the settings file wrote it", () => {
		expect(
			formatDangerousRuleDisplay({ toolName: "Bash", ruleContent: "npm install *" }),
		).toBe("Bash(npm install *)")
		expect(formatDangerousRuleDisplay({ toolName: "Read", ruleContent: "src/**" })).toBe(
			"Read(src/**)",
		)
	})

	it("shows (*) when the rule carries no content", () => {
		expect(formatDangerousRuleDisplay({ toolName: "Bash" })).toBe("Bash(*)")
		// An explicitly empty string is still content, so it prints empty.
		expect(formatDangerousRuleDisplay({ toolName: "Bash", ruleContent: "" })).toBe(
			"Bash()",
		)
	})
})
