/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Re-reading the rules files into a live policy.
 *
 * Everything here is one of two questions, because those are the two ways a reload face can be wrong.
 * (1) Does it install what the files say? Pinned against healthy files, and cross-checked against the
 * loader the activation path uses, so this module cannot quietly invent or lose a rule. (2) Can it take down
 * a wall? Every test in the second group asserts the effect at the matcher's face
 * (`evaluateToolPermission`, the same call `index.ts` makes with the snapshot) rather than on this module's
 * return value — a reload that reports a kept deny but installs an empty policy would be worthless.
 *
 * The corruption cases are the point of the file: an unreadable `permissions.json` is the one input that a
 * naive reload reads as "this project has no deny rules", and a lost deny is the failure this codebase
 * treats as the worst there is.
 *
 * Every fixture is a tmp checkout with its own user-level config path, so nothing here reads or writes a
 * real `~/.pi/agent/permission-modes.json` or any real project's `.pi/projects/`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { setConfigPath } from "./config.ts"
import {
	getProjectPermissionsPath,
	loadMergedPermissionRules,
	writeGlobalPermissionsConfig,
	writeProjectPermissionsFile,
} from "./permissions-loader.ts"
import {
	evaluateToolPermission,
	type PermissionRule,
	type PermissionsConfig,
	rulesFromPermissionsConfig,
} from "./permissions.ts"
import {
	policyCarries,
	type PolicyReload,
	reloadPermissionPolicy,
	ruleLabel,
	summariseReload,
} from "./reload-policy.ts"

const roots: string[] = []
let cwd = ""
let globalFile = ""

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "pm-reload-"))
	roots.push(cwd)
	globalFile = join(cwd, "permission-modes.json")
	// The global source is a real path, not the developer's own config. Every read in this file goes
	// through it, so this one line is what keeps the suite from reading the machine it runs on.
	setConfigPath(globalFile)
})

afterEach(() => {
	for (const dir of roots) rmSync(dir, { recursive: true, force: true })
	roots.length = 0
})

/** Write a live rules file the way the plugin writes it, and hand back its path. */
function projectFile(permissions: PermissionsConfig, local = false): string {
	writeProjectPermissionsFile(cwd, permissions, local)
	return getProjectPermissionsPath(cwd, local)
}

/** Replace a rules file with bytes of the caller's choosing — the corrupted-file fixtures. */
function raw(file: string, body: string): string {
	writeFileSync(file, body)
	return file
}

/** What the activation path would have produced for these lists — i.e. a realistic live snapshot. */
function live(...sets: [PermissionsConfig, "global" | "project" | "local"][]): PermissionRule[] {
	return sets.flatMap(([permissions, source]) => rulesFromPermissionsConfig(permissions, source))
}

function labels(rules: readonly PermissionRule[]): string[] {
	return rules.map(ruleLabel).sort()
}

function reload(live: readonly PermissionRule[]): PolicyReload {
	return reloadPermissionPolicy({ cwd, live, globalFile })
}

const bash = (rules: PermissionRule[], command: string, at = cwd) =>
	evaluateToolPermission("bash", { command }, at, rules)

describe("reload installs what the files say", () => {
	it("brings in a rule the project file gained after activation", () => {
		projectFile({ allow: ["Bash(npm publish)"] })
		const out = reload([])
		expect(out.added).toContain("allow Bash(npm publish)")
		expect(out.changed).toBe(true)
		expect(bash(out.rules, "npm publish").behavior).toBe("allow")
	})

	it("agrees with the loader the activation path uses, on a healthy tree", () => {
		projectFile({ deny: ["Bash(rm *)"], ask: ["Read(./.env)"] })
		projectFile({ allow: ["Bash(npm publish)"] }, true)
		writeGlobalPermissionsConfig({ deny: ["Bash(git push --force*)"] })
		const out = reload([])
		// Same rules, same spellings — a reload that quietly read a subset would look like a successful
		// no-change reload on every healthy tree.
		expect(labels(out.rules)).toEqual(labels(loadMergedPermissionRules(cwd)))
	})

	it("drops an allow the file no longer carries, because there the file is the source of truth", () => {
		const was = live([{ allow: ["Bash(npm test)"] }, "project"])
		projectFile({})
		const out = reload(was)
		expect(out.dropped).toEqual(["allow Bash(npm test)"])
		expect(out.rules).toHaveLength(0)
		expect(bash(out.rules, "npm test").behavior).toBe("passthrough")
	})

	it("reads the user-level file too, and labels its rules as global", () => {
		writeGlobalPermissionsConfig({ deny: ["Bash(npm publish)"] })
		const out = reload([])
		expect(policyCarries(out.rules, "Bash(npm publish)", "deny")?.source).toBe("global")
		expect(bash(out.rules, "npm publish").behavior).toBe("deny")
	})

	it("installs nothing that no file carries", () => {
		projectFile({ allow: ["Bash(npm publish)"] })
		const out = reload([])
		expect(labels(out.rules)).toEqual(["allow Bash(npm publish)"])
		expect(policyCarries(out.rules, "Bash(npm *)")).toBeUndefined()
		expect(bash(out.rules, "npm install left-pad").behavior).toBe("passthrough")
	})

	it("does not read an orphaned project state directory as if it were live", () => {
		// Adopting is a decision; re-reading is not. Widening that lives only in another id's directory must
		// stay invisible to this face, however it got there.
		const orphanFile = join(cwd, ".pi", "projects", "movedaway1", "permissions.local.json")
		mkdirSync(join(cwd, ".pi", "projects", "movedaway1"), { recursive: true })
		writeFileSync(orphanFile, JSON.stringify({ permissions: { allow: ["Bash(npm publish)"] } }))
		const out = reload([])
		expect(out.rules).toHaveLength(0)
		expect(policyCarries(out.rules, "Bash(npm publish)")).toBeUndefined()
	})

	it("reports no change when the files say what the session already had", () => {
		projectFile({ deny: ["Bash(rm *)"] })
		const was = live([{ deny: ["Bash(rm *)"] }, "project"])
		const out = reload(was)
		expect(out.changed).toBe(false)
		expect(out.added).toEqual([])
		expect(out.dropped).toEqual([])
		expect(out.heldBack).toEqual([])
	})

	it("is idempotent: a second reload of the same files changes nothing further", () => {
		projectFile({ allow: ["Bash(npm publish)"], deny: ["Bash(rm *)"] })
		const once = reload([])
		const twice = reload(once.rules)
		expect(twice.changed).toBe(false)
		expect(labels(twice.rules)).toEqual(labels(once.rules))
	})

	it("never mutates the snapshot it was handed", () => {
		projectFile({ allow: ["Bash(npm publish)"] })
		const was = live([{ deny: ["Bash(rm *)"] }, "project"])
		const before = [...was]
		const out = reload(was)
		expect(was).toEqual(before)
		expect(out.rules).not.toBe(was)
	})

	it("counts entries it could not use instead of installing them", () => {
		const file = projectFile({ allow: ["Bash(npm publish)"] })
		raw(file, JSON.stringify({ permissions: { allow: ["Bash(npm publish)", 42, "  "] } }))
		const out = reload([])
		expect(out.sources.find((s) => s.source === "project")?.ignored).toBe(2)
		expect(labels(out.rules)).toEqual(["allow Bash(npm publish)"])
	})

	it("folds the three spellings of a tool-wide rule into one answer", () => {
		projectFile({ allow: ["Bash(*)"] })
		const rules = reload([]).rules
		expect(policyCarries(rules, "Bash")).toBeDefined()
		expect(policyCarries(rules, "Bash()")).toBeDefined()
		expect(policyCarries(rules, "Bash(*)")).toBeDefined()
		expect(policyCarries(rules, "Bash(npm publish)")).toBeUndefined()
	})

	it("leaves a configuration file that says nothing about permissions alone", () => {
		// The common case for the user-level file: a real config with no `permissions` block. Reading that
		// as a failure would report a problem on every healthy machine.
		raw(globalFile, JSON.stringify({ classifier: { enabled: true } }))
		const out = reload([])
		expect(out.unreadable).toEqual([])
		expect(out.sources.find((s) => s.source === "global")?.answeredNothing).toBe(true)
	})
})

describe("reload cannot lift a wall", () => {
	it("keeps a deny the files no longer carry, and still denies with it", () => {
		const was = live([{ deny: ["Bash(rm *)"] }, "project"])
		projectFile({ allow: ["Bash(npm publish)"] })
		const out = reload(was)
		expect(out.heldBack).toEqual(["deny Bash(rm *)"])
		expect(out.dropped).toEqual([])
		expect(bash(out.rules, "rm file").behavior).toBe("deny")
	})

	it("keeps an ask the files no longer carry, and still asks with it", () => {
		const was = live([{ ask: ["Bash(npm install *)"] }, "project"])
		projectFile({})
		const out = reload(was)
		expect(out.heldBack).toEqual(["ask Bash(npm install *)"])
		expect(bash(out.rules, "npm install left-pad").behavior).toBe("ask")
	})

	it("does not let a session that was stricter become looser because a file changed", () => {
		// The exact shape the brief asks about: the session was running behind a deny and an allow, an
		// orphan's allow is now in the file, and the file no longer repeats the deny.
		const was = live([{ deny: ["Bash(rm *)"], allow: ["Bash(npm test)"] }, "project"])
		projectFile({ allow: ["Bash(npm publish)"] })
		const out = reload(was)
		expect(bash(out.rules, "rm -rf ./build").behavior).toBe("deny")
		expect(bash(out.rules, "npm publish").behavior).toBe("allow")
		// The allowance that vanished is reported, not silently kept: it costs one prompt, nothing more.
		expect(out.dropped).toEqual(["allow Bash(npm test)"])
		expect(bash(out.rules, "npm test").behavior).toBe("passthrough")
	})

	it("holds a denial back even when the same rule is now present as something weaker", () => {
		// `deny Bash(x)` live, `ask Bash(x)` on disk: the stricter half is what the user was living under,
		// and `evaluateToolPermission` honours deny before ask only if both are in the snapshot.
		const was = live([{ deny: ["Bash(npm publish)"] }, "project"])
		projectFile({ ask: ["Bash(npm publish)"] })
		const out = reload(was)
		expect(out.heldBack).toEqual(["deny Bash(npm publish)"])
		expect(bash(out.rules, "npm publish").behavior).toBe("deny")
	})

	it("only ever drops allows, whatever the files did", () => {
		const was = live(
			[{ deny: ["Bash(rm *)"], ask: ["Bash(npm *)"], allow: ["Bash(npm test)"] }, "project"],
			[{ deny: ["Read(~/.ssh/**)"] }, "global"],
		)
		projectFile({})
		const out = reload(was)
		expect(out.dropped.every((entry) => entry.startsWith("allow "))).toBe(true)
		expect(out.dropped).toEqual(["allow Bash(npm test)"])
		expect(out.heldBack.sort()).toEqual(["ask Bash(npm *)", "deny Bash(rm *)", "deny Read(~/.ssh/**)"])
	})
})

describe("a file that could not be read is not an empty file", () => {
	it("leaves the live policy exactly as it was when the project file is not JSON", () => {
		const file = projectFile({ deny: ["Bash(rm *)"], allow: ["Bash(npm test)"] })
		const was = loadMergedPermissionRules(cwd)
		raw(file, "{ \"permissions\": { \"deny\": [")
		const out = reload(was)
		expect(labels(out.rules)).toEqual(labels(was))
		expect(out.changed).toBe(false)
		expect(out.unreadable).toHaveLength(1)
		expect(out.unreadable[0]).toContain(file)
		expect(bash(out.rules, "rm file").behavior).toBe("deny")
	})

	it("keeps the last rules it understood for the broken file and still reads the others", () => {
		const local = projectFile({ deny: ["Bash(npm publish)"] }, true)
		const was = live([{ deny: ["Bash(npm publish)"] }, "local"], [{ allow: ["Bash(npm test)"] }, "project"])
		projectFile({ allow: ["Bash(npm test)"] })
		raw(local, "not json at all")
		const out = reload(was)
		expect(bash(out.rules, "npm publish").behavior).toBe("deny")
		expect(bash(out.rules, "npm test").behavior).toBe("allow")
		expect(out.unreadable[0]).toContain(local)
	})

	it("treats a deny list that is not a list as unreadable, not as empty", () => {
		const file = projectFile({ deny: ["Bash(rm *)"] })
		const was = live([{ deny: ["Bash(rm *)"] }, "project"])
		raw(file, JSON.stringify({ permissions: { deny: "Bash(rm *)" } }))
		const out = reload(was)
		expect(out.unreadable).toHaveLength(1)
		expect(out.sources.find((s) => s.source === "project")?.problem).toContain("deny")
		expect(bash(out.rules, "rm file").behavior).toBe("deny")
	})

	it("treats a document shaped like an array as unreadable rather than as no rules", () => {
		const file = projectFile({ deny: ["Bash(rm *)"] })
		const was = live([{ deny: ["Bash(rm *)"] }, "project"])
		raw(file, "[]")
		const out = reload(was)
		expect(out.unreadable).toHaveLength(1)
		expect(bash(out.rules, "rm file").behavior).toBe("deny")
	})

	it("reports the same facts in one line a caller can print", () => {
		const was = live([{ deny: ["Bash(rm *)"], allow: ["Bash(npm test)"] }, "project"])
		const file = projectFile({ allow: ["Bash(npm publish)"] })
		raw(file, "{ oops")
		expect(summariseReload(reload(was))).toContain("unreadable and left exactly as they were")
		expect(summariseReload(reload([]))).toContain("no change to this session's policy")
	})
})

describe("an absent or blank file is an answer, not a failure", () => {
	it("reports no problem when there are no rules files at all", () => {
		const out = reload([])
		expect(out.unreadable).toEqual([])
		expect(out.sources.every((s) => s.ok && s.answeredNothing)).toBe(true)
	})

	it("reads a blank file as nothing, and lets an allow it used to grant go", () => {
		const file = projectFile({ allow: ["Bash(npm test)"] })
		const was = live([{ allow: ["Bash(npm test)"] }, "project"])
		raw(file, "   \n")
		const out = reload(was)
		expect(out.unreadable).toEqual([])
		expect(out.dropped).toEqual(["allow Bash(npm test)"])
	})

	it("deletes an allow by deleting the file, but not a deny", () => {
		// The asymmetry stated in the header, at its most literal: removing the file removes what it granted
		// and keeps what it refused. Clearing a wall is not something a missing file gets to decide.
		const file = projectFile({ deny: ["Bash(rm *)"], allow: ["Bash(npm test)"] })
		const was = loadMergedPermissionRules(cwd)
		rmSync(file)
		const out = reload(was)
		expect(out.dropped).toEqual(["allow Bash(npm test)"])
		expect(bash(out.rules, "rm file").behavior).toBe("deny")
		expect(bash(out.rules, "npm test").behavior).toBe("passthrough")
	})
})
