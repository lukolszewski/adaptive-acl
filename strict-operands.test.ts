/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
} from "./permissions.ts"
import { bashRuleView, categoryHasStrictOperands } from "./bash-audit.ts"
import { evaluateBash } from "./risk-policy.ts"
/**
 * W8, end to end: a stored permission must not mean more than the click that wrote it.
 *
 * `bash-rule-argv.test.ts` pins the matcher and `bash-audit.test.ts` pins the view; this file pins the
 * thing both of them can get wrong without any single unit failing — the *table*. Which verdicts make a
 * rule name every word of the call, measured through the entry point the gate actually uses, on commands
 * a person really types. A category renamed in `risk-handlers.ts` would otherwise switch the feature off
 * silently: the matcher would still be correct, the view would still say "loose", and every "Allow
 * always" on a destructive command would go back to covering whatever the next call appends.
 *
 * Two directions are asserted for every row, because a table that only pins the tightening cannot tell
 * "worked" from "disabled everything": the shorter rule must stop covering, and the exact rule must still
 * cover.
 */

const cwd = "/home/user/project"

function behaviorOf(command: string, allow: string[]): string {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig({ allow }, "project")),
	).behavior
}

/** The category layer 0 gives this command — so a row cannot drift away from the tier tables. */
function categoryOf(command: string): string {
	return evaluateBash(command, { cwd, project: cwd, home: "/home/user" }).category
}

describe("target-bearing verdicts: the rule must name every word", () => {
	// [command as it will be typed, the category the tables give it, a SHORTER rule that used to cover it
	// because a specifier was read as a prefix — written by an approval on a shorter invocation, or by hand]
	const ROWS = [
		["rm -rf /tmp/x /tmp/z", "delete_recursive", "Bash(rm -rf /tmp/x)"],
		["rm -rf node_modules --force", "delete_recursive", "Bash(rm -rf node_modules)"],
		["shred -u secret.txt extra", "delete_recursive", "Bash(shred -u secret.txt)"],
		["mv /tmp/a /tmp/b /dest", "delete_outside", "Bash(mv /tmp/a /tmp/b)"],
		["chmod -R 777 /tmp/x --verbose", "perm_change", "Bash(chmod -R 777 /tmp/x)"],
		["chown -R www-data /etc/x /etc/y", "perm_change", "Bash(chown -R www-data /etc/x)"],
		["git reset --hard HEAD~1", "vcs_discard", "Bash(git reset --hard)"],
		["git clean -fdx .", "vcs_discard", "Bash(git clean -fd)"],
		["cat ~/.ssh/id_rsa ~/.ssh/id_ed25519", "read_secret", "Bash(cat ~/.ssh/id_rsa)"],
		["cp ./tmp-dump ~/.ssh/id_rsa extra", "read_secret", "Bash(cp ./tmp-dump ~/.ssh/id_rsa)"],
		["tee ~/.gitconfig extra", "write_sensitive", "Bash(tee ~/.gitconfig)"],
		["cp ./notes.txt /srv/exports/x", "write_outside", "Bash(cp ./notes.txt)"],
		["rsync -a ./out /srv/exports --delete", "delete_recursive", "Bash(rsync -a ./out /srv/exports)"],
		["sudo rm -rf /tmp/x /tmp/z", "privilege", "Bash(rm -rf /tmp/x)"],
	] as const

	it.each(ROWS)("%s (%s)", (command, category, shorterRule) => {
		// The row's premise first: if the tables stop calling this `delete_recursive`, this test is not
		// evidence about anything, so say so rather than passing on a coincidence.
		expect(categoryOf(command), command).toContain(category)
		expect(categoryHasStrictOperands(category), category).toBe(true)
		const view = bashRuleView(command, cwd)
		expect(view.proven, command).toBe(true)
		if (!view.proven) return
		expect(view.strictOperands, command).toBe(true)
		expect(view.floored, command).toBe(false)
		// …then the behaviour.
		expect(behaviorOf(command, [shorterRule]), `${command} ← ${shorterRule}`).toBe("passthrough")
	})

	it("still covers the invocation the rule names, in the same words", () => {
		expect(behaviorOf("rm -rf /tmp/x", ["Bash(rm -rf /tmp/x)"])).toBe("allow")
		expect(behaviorOf("chmod -R 777 /tmp/x", ["Bash(chmod -R 777 /tmp/x)"])).toBe("allow")
		expect(behaviorOf("git reset --hard", ["Bash(git reset --hard)"])).toBe("allow")
		expect(behaviorOf("cat ~/.ssh/id_rsa", ["Bash(cat ~/.ssh/id_rsa)"])).toBe("allow")
		expect(behaviorOf("sudo rm -rf /tmp/x", ["Bash(rm -rf /tmp/x)"])).toBe("allow")
	})

	it("is decided by the verdict, not by the verb's name", () => {
		// `rm -rf /tmp/x` and `rm -rf ./build` are the same verb and the same category; the point of reading
		// the verdict is that a new verb landing in `delete_recursive` is strict with no table here.
		expect(categoryOf("rm -rf ./build")).toBe("delete_recursive")
		expect(behaviorOf("rm -rf ./build extra", ["Bash(rm -rf ./build)"])).toBe("passthrough")
	})

	it("withholds the offer an approval would write when that offer would be broader than the click", () => {
		// The round trip `permissions.ts` performs before showing "Always allow": write the rules, read them
		// back through the matcher, and drop the offer if the command it was written from is not covered.
		// A destructive verb already gets an exact rule from the suggestion engine, so the offer survives —
		// and now the stored rule means exactly the click instead of the click plus whatever follows.
		const set = suggestAllowRuleSetForToolCall("bash", { command: "rm -rf /tmp/x" }, cwd)
		expect(set.persistable).toBe(true)
		expect(set.rules).toEqual(["Bash(rm -rf /tmp/x)"])
		expect(behaviorOf("rm -rf /tmp/x", set.rules)).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", set.rules)).toBe("passthrough")
	})
})

describe("everything else keeps the contract W2 pinned", () => {
	// [command, category, the shorter exact rule that must still cover it]
	const ROWS = [
		["git status --short", "read_only", "Bash(git status)"],
		["git commit -m a -m b", "vcs_local", "Bash(git commit -m a)"],
		["npm test -- --watch", "run_project_code", "Bash(npm test)"],
		["bash x.sh arg", "run_project_code", "Bash(bash x.sh)"],
		// allow-tier writes: a rule that stopped covering these would change no outcome, only add a prompt
		["cp ./a.txt ./b.txt ./c.txt", "write_project", "Bash(cp ./a.txt ./b.txt)"],
		["dd if=/dev/zero of=/tmp/x bs=1M", "write_project", "Bash(dd if=/dev/zero of=/tmp/x)"],
		["truncate -s 0 a.log b.log", "write_project", "Bash(truncate -s 0 a.log)"],
	] as const

	it.each(ROWS)("%s (%s)", (command, category, rule) => {
		expect(categoryOf(command), command).toContain(category)
		expect(categoryHasStrictOperands(category), category).toBe(false)
		expect(behaviorOf(command, [rule]), `${command} ← ${rule}`).toBe("allow")
	})
})

describe("the table is written against categories that exist", () => {
	// A rename in the tier tables is the only way this feature dies quietly. Each name in the strict set is
	// also listed in `bash-audit.test.ts`, which cannot see whether the producer still spells it that way.
	const producers = ["risk-handlers.ts", "risk-policy.ts"].map((f) =>
		readFileSync(join(import.meta.dirname, f), "utf8"),
	)

	it("every strict category is still emitted by the layer-0 tables", () => {
		const strict = [
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
		]
		for (const category of strict) {
			const emitted = producers.some((src) => src.includes(`"${category}"`))
			expect(emitted, `${category} is no longer a category the tables emit`).toBe(true)
			expect(categoryHasStrictOperands(category), category).toBe(true)
		}
	})

	it("names categories the task listed under the vocabulary this repository uses", () => {
		// The wave-2 decision named `file_overwrite`, `permission_change`, `ssh_key_write`. Those strings
		// exist nowhere in the tier tables; the equivalents this table uses are `write_sensitive` /
		// `write_outside`, `perm_change`, `persistent_access`. Pinned so nobody "fixes" the names back.
		for (const absent of ["file_overwrite", "permission_change", "ssh_key_write"]) {
			expect(producers.some((src) => src.includes(`"${absent}"`)), absent).toBe(false)
			expect(categoryHasStrictOperands(absent), absent).toBe(false)
		}
		expect(categoryHasStrictOperands("write_sensitive")).toBe(true)
		expect(categoryHasStrictOperands("perm_change")).toBe(true)
		expect(categoryHasStrictOperands("persistent_access")).toBe(true)
	})
})

describe("the breadth that is left, and who owns it", () => {
	it("the breadth W8 left behind is closed: an approval writes the exact invocation", () => {
		// W8 pinned this as the residual hole it could not close: the engine generalised subcommand-grammar verbs,
		// so a click on `git reset --hard` wrote `Bash(git reset:*)`, which still covered `git reset --hard HEAD~1`
		// — wider than the click. Its comment here said the fix is the suggestion engine deriving an exact
		// specifier from layer-0 argv, "which is W9's job". W9 did that, so the pin records the CLOSED state:
		// the offer is exact, strict operands honour it, and a different invocation of the same verb prompts.
		const set = suggestAllowRuleSetForToolCall("bash", { command: "git reset --hard" }, cwd)
		expect(set.rules).toEqual(["Bash(git reset --hard)"])
		expect(behaviorOf("git reset --hard", set.rules)).toBe("allow")
		expect(behaviorOf("git reset --hard HEAD~1", set.rules)).toBe("passthrough")
	})

	it("a glob the user typed still covers what the glob covers", () => {
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", ["Bash(rm -rf /*)"])).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", ["Bash(rm *)"])).toBe("allow")
	})

	it("a blanket Bash rule is untouched, because it was never a reading of one invocation", () => {
		// Entering auto mode strips these first (dangerous-permissions.ts); the click path refuses to write
		// one ("suggested rule would be tool-wide; nothing written").
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", ["Bash"])).toBe("allow")
	})

	it("refusals still outrank every rule, strict or not", () => {
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", ["Bash(rm -rf /tmp/x /tmp/z)"])).toBe("allow")
		expect(behaviorOf("rm -rf / /tmp/z", ["Bash(rm -rf /)"])).toBe("passthrough")
		expect(behaviorOf('rm -rf "$HOME/x"', ["Bash(rm -rf)"])).toBe("passthrough")
		expect(behaviorOf("for f in a b; do rm -rf $f; done", ["Bash(rm:*)"])).toBe("passthrough")
	})
})

describe("one verdict per command", () => {
	it("the view is the only place the verdict is asked for", () => {
		// Cheap to state, expensive to lose: `bashRuleView` is called once per bash tool call by the allow
		// path, and it is also what `suggestAllowRuleSetForToolCall` round-trips through. If the strictness
		// flag were fetched by a second `evaluateBash` next to the floor check, every bash call in every
		// session would be analysed twice — the walk, the grammar and all.
		const source = readFileSync(join(import.meta.dirname, "bash-audit.ts"), "utf8")
		const calls = source.split("evaluateBash(").length - 1
		// one call site, inside the shared verdict helper
		expect(calls).toBe(1)
		expect(source).toContain("export function bashRuleView")
		expect(source.match(/return evaluateBash\(command, \{ cwd, project: cwd, home: homedir\(\)[^}]*\}\)/g)).toHaveLength(1)
	})
})

describe("a redirect target is named by the same exact rule (W10 extends W8, it does not relax it)", () => {
	// The rule: for a target-bearing verdict an exact specifier must name EVERY word. The other
	// half of "the target": the file the command redirects to, which is not a word and so was invisible.
	// Both directions are pinned, and the last row pins that the target requirement does NOT depend on the
	// strictness flag — `echo hi > ./notes.txt` is `write_project` (allow tier, not strict) and a rule that
	// names no target still refuses it, because the harm is which file the bytes land in and that question
	// cannot be answered from the category of a command whose argv is identical either way.
	it("a target-bearing verdict needs every word AND the target", () => {
		expect(categoryOf("cat < /etc/shadow")).toBe("read_secret")
		expect(behaviorOf("cat < /etc/shadow", ["Bash(cat)"])).toBe("passthrough")
		expect(behaviorOf("cat < /etc/shadow", ["Bash(cat < /etc/shadow)"])).toBe("allow")
		expect(behaviorOf("cat < /etc/shadow", ["Bash(cat < /etc/passwd)"])).toBe("passthrough")
		expect(behaviorOf("cat < /etc/shadow", ["Bash(cat > /etc/shadow)"])).toBe("passthrough")
	})

	it("an appending approval is not a truncating one, target-bearing or not", () => {
		// `cat x >> /tmp/log` is `write_project` (allow tier, NOT strict), yet the operator still decides:
		// the rule that was clicked truncates nothing.
		expect(categoryHasStrictOperands(categoryOf("cat x >> /tmp/log"))).toBe(false)
		expect(behaviorOf("cat x >> /tmp/log", ["Bash(cat x > /tmp/log)"])).toBe("passthrough")
		expect(behaviorOf("cat x >> /tmp/log", ["Bash(cat x >> /tmp/log)"])).toBe("allow")
	})

	it("a target-bearing redirect keeps strict operands on top of the target", () => {
		// Reading a secret and writing it out: `read_secret` is strict (W8's addition) and the command also
		// redirects, so the rule has to name every word AND the file. An extra argument or a different file
		// stops being covered — W8's probe hole (`rm -rf /tmp/x` covering `rm -rf /tmp/x /tmp/z`), one level
		// down, now closed for the redirect half too.
		const view = bashRuleView("cat ~/.ssh/id_rsa > /tmp/out", cwd)
		expect(view.proven).toBe(true)
		if (!view.proven) return
		expect(view.strictOperands).toBe(true)
		expect(view.floored).toBe(false)
		expect(behaviorOf("cat ~/.ssh/id_rsa > /tmp/out", ["Bash(cat > /tmp/out)"])).toBe("passthrough")
		expect(behaviorOf("cat ~/.ssh/id_rsa > /tmp/out", ["Bash(cat ~/.ssh/id_rsa > /tmp/out)"])).toBe("allow")
		expect(behaviorOf("cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 > /tmp/out", ["Bash(cat ~/.ssh/id_rsa > /tmp/out)"])).toBe(
			"passthrough",
		)
		expect(behaviorOf("cat ~/.ssh/id_rsa > ~/.ssh/authorized_keys", ["Bash(cat ~/.ssh/id_rsa > /tmp/out)"])).toBe(
			"passthrough",
		)
		// A non-strict verb writing outside the project behaves the same way about its target, and the clause
		// switches off the prefix loosening too: a specifier that wrote down the file described the whole
		// invocation, so `tee /tmp/x > /tmp/y` does not reach `tee /tmp/x /tmp/z > /tmp/y` even though the
		// verdict is allow-tier. Cost: one extra prompt. Gain: the rule means the click.
		expect(categoryHasStrictOperands(categoryOf("tee /tmp/x > /tmp/y"))).toBe(false)
		expect(behaviorOf("tee /tmp/x > /tmp/y", ["Bash(tee /tmp/x > /tmp/y)"])).toBe("allow")
		expect(behaviorOf("tee /tmp/x /tmp/z > /tmp/y", ["Bash(tee /tmp/x > /tmp/y)"])).toBe("passthrough")
		expect(behaviorOf("tee /tmp/x > /tmp/z", ["Bash(tee /tmp/x > /tmp/y)"])).toBe("passthrough")
		// without the clause the ordinary contract is untouched, same verb same verdict
		expect(behaviorOf("tee /tmp/x /tmp/z", ["Bash(tee /tmp/x)"])).toBe("allow")
	})

	it("adds no category of its own: the strictness table is still the only one", () => {
		// This must not grow a second category list — the mistake that had to be fixed once already. A
		// redirect is not a category: the matcher receives one boolean and one list of targets, and never
		// looks at a category name — asserted as "no category name appears as data, and no set of names is
		// built here", which is what a second table would have to be made of.
		const source = readFileSync(join(import.meta.dirname, "bash-rule-argv.ts"), "utf8")
		expect(source).not.toContain("STRICT_OPERAND_CATEGORIES")
		expect(source).not.toMatch(/"(delete_recursive|write_sensitive|write_outside|read_secret|perm_change|privilege)"/)
		expect(source.match(/new Set\(/g) ?? []).toHaveLength(0)
		expect(source).not.toContain("risk-policy")
		// and the table itself is still defined exactly once, in `bash-audit.ts`
		expect(
			readFileSync(join(import.meta.dirname, "bash-audit.ts"), "utf8").match(/const STRICT_OPERAND_CATEGORIES/g),
		).toHaveLength(1)
	})
})
