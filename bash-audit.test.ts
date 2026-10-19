/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import {
	auditBashCommand,
	bashRuleView,
	categoryHasStrictOperands,
	envChangesExecution,
	hitsNeverFloor,
	seeThroughWrappers,
} from "./bash-audit.ts"

/**
 * The layer-0 view the bash allow path is built on, tested on its own.
 *
 * `permissions.ts` only ever sees this module's answers, so the three things it must not get wrong — when
 * there IS an argv, which words a rule may be compared with, and whether a rule may be read past the words
 * it names — are pinned here rather than inferred from a verdict.
 */

const cwd = "/home/user/project"

describe("auditBashCommand: the legs", () => {
	it("splits on the shell's own structure, not on a guess", () => {
		const audit = auditBashCommand("git status && echo done | head -5")
		expect(audit.proven).toBe(true)
		if (!audit.proven) return
		expect(audit.legs.map((l) => l.argv)).toEqual([
			["git", "status"],
			["echo", "done"],
			["head", "-5"],
		])
	})

	it("separates the assignment prefix from argv but keeps its name", () => {
		const audit = auditBashCommand("FOO=1 npm test")
		expect(audit.proven).toBe(true)
		if (!audit.proven) return
		expect(audit.legs[0]!.argv).toEqual(["npm", "test"])
		expect(audit.legs[0]!.withAssignments).toEqual(["FOO=1", "npm", "test"])
		expect(audit.legs[0]!.envNames).toEqual(["FOO"])
	})

	it("sees a redirect as a redirect, never as an argument", () => {
		const audit = auditBashCommand("git status > status.txt")
		expect(audit.proven).toBe(true)
		if (!audit.proven) return
		expect(audit.legs[0]!.argv).toEqual(["git", "status"])
	})

	it("carries the leg's own text, so a rule can be reported against the right clause", () => {
		const audit = auditBashCommand("git status && echo done")
		if (!audit.proven) throw new Error("expected proven")
		expect(audit.legs.map((l) => l.text.trim())).toEqual(["git status", "echo done"])
	})

	it("refuses anything the walker will not vouch for, and says which §12 id", () => {
		expect(auditBashCommand("for f in a b; do rm -f $f; done")).toMatchObject({
			proven: false,
			reason: "loop-body",
		})
		expect(auditBashCommand("git log $(whoami)")).toMatchObject({
			proven: false,
			reason: "command-substitution",
		})
		expect(auditBashCommand("echo a <(b)")).toMatchObject({ proven: false, reason: "process-substitution" })
		expect(auditBashCommand("   ")).toMatchObject({ proven: false, reason: "empty-command" })
	})

	it("marks a run-time value rather than pretending it is a literal", () => {
		const audit = auditBashCommand('cat "$HOME/x"')
		if (!audit.proven) throw new Error("expected proven")
		expect(audit.legs[0]!.opaque).toBe(true)
		expect(audit.legs[0]!.argv).toEqual(["cat", "__TRACKED_VAR__/x"])
	})
})

describe("seeThroughWrappers: the six names, and nothing else", () => {
	it.each([
		[["env", "FOO=1", "git", "status"], ["git", "status"]],
		[["sudo", "git", "status"], ["git", "status"]],
		[["sudo", "-u", "postgres", "rm", "-f", "x"], ["rm", "-f", "x"]],
		[["timeout", "5", "git", "status"], ["git", "status"]],
		[["nice", "-n", "5", "git", "status"], ["git", "status"]],
		[["nohup", "git", "status"], ["git", "status"]],
		[["time", "-p", "git", "status"], ["git", "status"]],
		[["/usr/bin/env", "-i", "git", "status"], ["git", "status"]],
		[["sudo", "env", "FOO=1", "git", "status"], ["git", "status"]],
		[["env", "--", "git", "status"], ["git", "status"]],
	])("%j → %j", (argv, inner) => {
		expect(seeThroughWrappers(argv)?.argv).toEqual(inner)
	})

	it("reports the variables the wrapper itself set", () => {
		expect(seeThroughWrappers(["env", "FOO=1", "BAR=2", "git", "status"])?.envNames).toEqual(["FOO", "BAR"])
	})

	it.each([
		["git", "status"],
		["xargs", "git", "status"],
		["stdbuf", "-oL", "git", "status"],
		["setsid", "git", "status"],
		["ionice", "-c3", "git", "status"],
		["watch", "-n", "1", "git", "status"],
	])("%j is not on the list: no inner argv", (...argv) => {
		expect(seeThroughWrappers(argv as string[])).toBeNull()
	})

	it.each([
		["timeout", "git", "status"],
		["timeout", "--kill-after", "5", "git", "status"],
		["sudo", "--preserve-env=SOME", "git", "status"],
	])("%j: a wrapper whose shape we cannot read gives no answer", (...argv) => {
		// No duration, an option we do not model — in each case "where the command starts" is not
		// decidable, so the peel refuses instead of guessing a prefix and handing it to a rule.
		expect(seeThroughWrappers(argv as string[])).toBeNull()
	})

	it("a wrapper that swallows its own option leaves no command behind", () => {
		// `sudo -u` with nothing after it: the answer is an empty argv, which bashRuleCoversArgv refuses
		// for the same reason it refuses `> f` — there is no command for a rule to have authorised.
		expect(seeThroughWrappers(["sudo", "-u"])?.argv ?? []).toEqual([])
	})
})

describe("envChangesExecution: where a rule stops being able to speak for a leg", () => {
	it.each([
		"LD_PRELOAD",
		"LD_AUDIT",
		"LD_ANYTHING_ELSE",
		"DYLD_INSERT_LIBRARIES",
		"NODE_OPTIONS",
		"PYTHONPATH",
		"PATH",
		"HOME",
		"IFS",
		"BASH_ENV",
		"GIT_SSH_COMMAND",
		"GIT_CONFIG_GLOBAL",
		"EDITOR",
		"CC",
		"PI_SUBAGENT_CHILD",
		"PERMISSION_MODES_INHERITED_MODE",
	])("%s changes execution", (name) => {
		expect(envChangesExecution(name)).toBe(true)
	})

	it.each(["FOO", "NODE_ENV", "LANG", "LC_ALL", "TZ", "TERM", "NO_COLOR", "PYTHONUNBUFFERED", "RUST_LOG"])(
		"%s is cosmetic — refusing it would make everyday commands prompt forever",
		(name) => {
			expect(envChangesExecution(name)).toBe(false)
		},
	)
})

describe("hitsNeverFloor", () => {
	it.each(["rm -rf /", "sudo rm -rf /", "timeout 5 rm -rf /", "dd if=/dev/zero of=/dev/sda", "chmod -R 777 /"])(
		"%s is floored",
		(command) => {
			expect(hitsNeverFloor(command, cwd)).toBe(true)
		},
	)

	it.each(["git status", "npm test", "rm -rf ./build", "echo key > /tmp/out.txt"])("%s is not", (command) => {
		expect(hitsNeverFloor(command, cwd)).toBe(false)
	})
})

describe("bashRuleView: the one answer the allow path reads", () => {
	// W3 read the legs and the floor from two places; W8 needs the verdict's CATEGORY as well, and a second
	// `evaluateBash` per call would double the analysis on the hottest path in the extension. So all three
	// answers come back together, and each is pinned here on its own — `bash-allow-layer0.test.ts` pins what
	// `permissions.ts` does with them.

	it("carries the legs, the floor and the strictness flag in one object", () => {
		const view = bashRuleView("rm -rf /tmp/x", cwd)
		expect(view.proven).toBe(true)
		if (!view.proven) return
		expect(view.legs.map((l) => l.argv)).toEqual([["rm", "-rf", "/tmp/x"]])
		expect(view.floored).toBe(false)
		expect(view.strictOperands).toBe(true)
	})

	it("says which commands may not be extended by a rule, and which may", () => {
		const strictOf = (command: string) => {
			const v = bashRuleView(command, cwd)
			return v.proven ? v.strictOperands : `unproven:${v.reason}`
		}
		for (const command of ["rm -rf /tmp/x", "chmod 644 /etc/x", "cat ~/.ssh/id_rsa", "git reset --hard", "sudo systemctl restart docker"]) {
			expect(strictOf(command), command).toBe(true)
		}
		for (const command of ["git status", "npm test", "git commit -m x", "cp a b", "echo hi > /tmp/out.txt"]) {
			expect(strictOf(command), command).toBe(false)
		}
	})

	it("reports the floor exactly where hitsNeverFloor does", () => {
		// Two answers, one verdict: they may not drift apart, or a command would be floored for one caller
		// and covered for the other.
		for (const command of ["rm -rf /", "sudo rm -rf /", "dd if=/dev/zero of=/dev/sda", "git status", "rm -rf ./build"]) {
			const v = bashRuleView(command, cwd)
			expect(v.proven ? v.floored : "unproven", command).toBe(hitsNeverFloor(command, cwd))
		}
	})

	it("is strict for the whole command, not per leg — the direction that cannot leak", () => {
		// A verdict row is not labelled with the leg it came from: `SegmentDecision.command` is display text
		// ("cp to b", "write /tmp/out.txt"), so a per-leg split here would have to guess at evaluateBash's row
		// order, and a wrong guess would leave a target-bearing leg UNMARKED. Reading the flag command-wide
		// can only ever tighten, which is the side a wrong guess belongs on.
		const view = bashRuleView("rm -rf ./build && git status", cwd)
		expect(view.proven).toBe(true)
		if (!view.proven) return
		expect(view.legs).toHaveLength(2)
		expect(view.strictOperands).toBe(true)
	})

	it("is not proven when there is no trustworthy argv, and says which id", () => {
		expect(bashRuleView("for f in a b; do rm -f $f; done", cwd)).toMatchObject({
			proven: false,
			reason: "loop-body",
		})
		expect(bashRuleView("git log $(whoami)", cwd)).toMatchObject({
			proven: false,
			reason: "command-substitution",
		})
		expect(bashRuleView("   ", cwd)).toMatchObject({ proven: false, reason: "empty-command" })
	})
})

describe("categoryHasStrictOperands: the table, not a hunch", () => {
	// Every name here is a category `risk-handlers.ts` / `risk-policy.ts` actually emits — the strict set is
	// written against this codebase's vocabulary, and `strict-operands.test.ts` fails if one of them ever
	// stops existing, which is how a rename would otherwise silently switch the feature off.
	it.each([
		"delete_recursive",
		"delete_outside",
		"delete_data",
		"wipe_protected",
		"history_wipe",
		"device_write",
		"disk_destroy",
		"perm_change",
		"perm_destroy",
		"vcs_discard",
		"persistent_access",
		"privilege",
		"read_secret",
		"write_sensitive",
		"write_outside",
	])("%s is target-bearing", (category) => {
		expect(categoryHasStrictOperands(category)).toBe(true)
	})

	it.each([
		// allow-tier: the gate lets these through with or without a rule, so strict operands are pure cost
		"read_only",
		"write_project",
		"run_project_code",
		"vcs_local",
		// not a path the user can see in the operands
		"system_config",
		"package_system",
		"network_send",
		"cluster_mutation",
		"container_mutation",
		"db_destroy",
		"process_control",
		"remote_exec",
		// the analyzer's own bookkeeping
		"unproven_structure",
		"unproven_value",
		"unknown_command",
		"unparseable_command",
	])("%s keeps the prefix contract", (category) => {
		expect(categoryHasStrictOperands(category)).toBe(false)
	})

	it("reads a merged row as strict when one of its parts is", () => {
		// `mergeDecisions` joins the categories of the strictest tier with `+` — `mv /tmp/a /tmp/b` reports
		// `delete_outside+write_outside`, and the destructive half is the reason the rule must be exact.
		expect(categoryHasStrictOperands("delete_outside+write_outside")).toBe(true)
		expect(categoryHasStrictOperands("read_only+write_project")).toBe(false)
	})
})
