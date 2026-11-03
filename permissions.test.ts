/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { describe, expect, it } from "vitest"
import {
	evaluateToolPermission,
	formatMergedRulesForDisplay,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleForToolCall,
} from "./permissions.ts"

describe("permissions evaluate", () => {
	const cwd = "/home/user/project"

	it("deny beats allow", () => {
		const rules = mergePermissionRules(
			rulesFromPermissionsConfig(
				{ allow: ["Bash(git *)"], deny: ["Bash(rm *)"] },
				"global",
			),
		)
		const verdict = evaluateToolPermission(
			"bash",
			{ command: "rm file" },
			cwd,
			rules,
		)
		expect(verdict.behavior).toBe("deny")
	})

	it("allow skips passthrough for matching bash", () => {
		const rules = rulesFromPermissionsConfig(
			{ allow: ["Bash(npm run:*)"] },
			"project",
		)
		const verdict = evaluateToolPermission(
			"bash",
			{ command: "npm run test" },
			cwd,
			rules,
		)
		expect(verdict.behavior).toBe("allow")
	})

	it("ask rule triggers ask verdict", () => {
		const rules = rulesFromPermissionsConfig(
			{ ask: ["Bash(npm install *)"] },
			"global",
		)
		const verdict = evaluateToolPermission(
			"bash",
			{ command: "npm install foo" },
			cwd,
			rules,
		)
		expect(verdict.behavior).toBe("ask")
	})

	it("suggests allow rule for tool call", () => {
		expect(
			suggestAllowRuleForToolCall(
				"bash",
				{ command: "npm test" },
				cwd,
			),
			// Was `Bash(npm:*)` (tool-wide). Now scoped to the subcommand family.
			).toBe("Bash(npm test:*)")
	})
})

describe("the /permissions listing marks a rule that can never fire", () => {
	// A rule naming a tool this extension does not match (`Grep(…)https://example.com` ported from a Claude
	// Code settings file, a closing paren lost to stray text) reads exactly like an active rule and does
	// nothing. The loader warns once on load; this is the other place the user looks.
	it("annotates the dead rule and leaves live ones alone", () => {
		const rules = mergePermissionRules(
			rulesFromPermissionsConfig({ allow: ["Bash(npm test)", "Grep(TODO)"] }, "project"),
		)
		const text = formatMergedRulesForDisplay(rules)
		expect(text).toContain("[project] Bash(npm test)")
		expect(text).toContain("[project] Grep(TODO)  ← no such tool: this rule never fires")
		expect(text.split("\n").filter((line) => line.includes("no such tool"))).toHaveLength(1)
	})
})
