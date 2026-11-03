import { describe, expect, it, beforeEach, afterEach, vi } from "vitest"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
	deadPermissionRules,
	loadMergedPermissionRules,
	resetDeadRuleWarnings,
	writeProjectPermissionsFile,
	writeGlobalPermissionsConfig,
} from "./permissions-loader.ts"
import { setConfigPath } from "./config.ts"

describe("permissions-loader", () => {
	let tmpDir: string

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "pm-perm-"))
		setConfigPath(join(tmpDir, "adaptive-acl.json"))
		// The once-per-process warning is the behaviour under test below; each test starts clean.
		resetDeadRuleWarnings()
	})

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true })
	})

	it("merges global and project rules", () => {
		writeGlobalPermissionsConfig({
			allow: ["Bash(npm run:*)"],
		})
		writeProjectPermissionsFile(tmpDir, {
			deny: ["Bash(rm *)"],
		})
		const rules = loadMergedPermissionRules(tmpDir)
		expect(rules.some((r) => r.behavior === "allow")).toBe(true)
		expect(rules.some((r) => r.behavior === "deny")).toBe(true)
	})
})

describe("a rule that can never fire is reported, not silently dead", () => {
	let tmpDir: string

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "pm-dead-"))
		setConfigPath(join(tmpDir, "adaptive-acl.json"))
		resetDeadRuleWarnings()
	})

	afterEach(() => {
		vi.restoreAllMocks()
		rmSync(tmpDir, { recursive: true, force: true })
	})

	it("parses a rule with a trailing space as the rule it reads like", () => {
		// `Bash(npm test) ` used to parse as a tool called `Bash(npm test)`: a rule that looks active and
		// matches nothing. Trimming cannot widen the specifier, which is compared verbatim either way.
		writeProjectPermissionsFile(tmpDir, { allow: ["Bash(npm test) "] })
		const rules = loadMergedPermissionRules(tmpDir)
		expect(rules).toHaveLength(1)
		expect(rules[0]!.ruleValue).toEqual({ toolName: "Bash", ruleContent: "npm test" })
		expect(deadPermissionRules(rules)).toEqual([])
	})

	it("names the rules whose tool this extension cannot match", () => {
		writeProjectPermissionsFile(tmpDir, { allow: ["Grep(TODO)", "Bash(npm test) trailing", "Bash(ls)"] })
		const rules = loadMergedPermissionRules(tmpDir)
		const dead = deadPermissionRules(rules).map((rule) => rule.ruleValue.toolName)
		expect(dead.sort()).toEqual(["Bash(npm test) trailing", "Grep"])
	})

	it("warns once per unknown tool name, on the loader's own channel", () => {
		const warnings = vi.spyOn(console, "warn").mockImplementation(() => {})
		writeProjectPermissionsFile(tmpDir, { deny: ["Grep(a)", "Grep(b)"], allow: ["Bash(ls)"] })
		loadMergedPermissionRules(tmpDir)
		expect(warnings).toHaveBeenCalledTimes(1)
		expect(String(warnings.mock.calls[0]?.[0])).toContain("Grep")
		// the approval path reloads the rules constantly; a repeated warning is noise a user learns to ignore
		loadMergedPermissionRules(tmpDir)
		expect(warnings).toHaveBeenCalledTimes(1)
	})
})
