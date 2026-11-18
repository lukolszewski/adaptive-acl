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

describe("deny and ask stay textual, run-time values included", () => {
	// Allow moved to argv and to slot rules; deny and ask did not, and must not. A denial has to fire on a
	// construct layer 0 refuses — that is the one case where there is no argv to compare — so these two
	// layers keep reading the command as characters. `$…` is a marker only on the allow side.
	const project = "/home/user/project"
	const withRules = (config: { allow?: string[]; deny?: string[]; ask?: string[] }) =>
		mergePermissionRules(rulesFromPermissionsConfig(config, "project"))

	it("a deny glob still stops a command whose value is only known at run time", () => {
		for (const command of ['rm "$X"', "rm $X", 'rm "$(git rev-parse HEAD)"']) {
			expect(
				evaluateToolPermission("bash", { command }, project, withRules({ deny: ["Bash(rm *)"] })).behavior,
				command,
			).toBe("deny")
		}
	})

	it("a deny prefix still stops the leg a slot rule was written for", () => {
		const verdict = evaluateToolPermission(
			"bash",
			{ command: 'grep -n "$P" src/' },
			project,
			withRules({ allow: ["Bash(grep -n $… src/)"], deny: ["Bash(grep -n:*)"] }),
		)
		expect(verdict.behavior).toBe("deny")
	})

	it("an ask rule still asks, even when a slot rule would allow the command", () => {
		const verdict = evaluateToolPermission(
			"bash",
			{ command: 'grep -n "$P" src/' },
			project,
			withRules({ allow: ["Bash(grep -n $… src/)"], ask: ["Bash(grep -n *)"] }),
		)
		expect(verdict.behavior).toBe("ask")
	})

	it("reads `$…` in a deny rule as the literal characters it is", () => {
		// Unchanged on purpose: the text matcher compares spellings, so a marker there matches the text `$…`
		// and nothing else. That direction is the safe one — a deny can only fire less, never allow more —
		// and the allow path never consults it.
		const verdict = evaluateToolPermission(
			"bash",
			{ command: 'rm "$X"' },
			project,
			withRules({ deny: ["Bash(rm $…)"] }),
		)
		expect(verdict.behavior).toBe("passthrough")
	})
})
