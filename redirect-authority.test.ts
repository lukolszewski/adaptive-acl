/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */
import { beforeAll, describe, expect, it } from "vitest"
import { initBashParser } from "./bash-parser.ts"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	type RedirectAuthority,
} from "./permissions.ts"
import { addGrant, createGrantStore } from "./session-grants.ts"
import { runGate } from "./gate.ts"
import { homedir } from "node:os"

/**
 * A `Bash(...)` allow rule and a leg that redirects.
 *
 * An earlier answer was "a rule that names no file covers no command that redirects at all", written to keep
 * `Bash(echo:*)` away from `echo key >> ~/.ssh/authorized_keys`. That blanket refusal is replaced by the
 * question it was standing in for: the redirect has to be somewhere this session is allowed to write (or
 * read) anyway. Same authority a direct `write` / `read` tool call on that path would need, and nothing more —
 *
 *   - so `Bash(make:*)` covers `make > build.log` (a project write needs no approval);
 *   - `Bash(echo:*)` does not cover `echo hi > ~/.bashrc` (live config asks), `> $f` (runtime) or
 *     `echo key >> ~/.ssh/authorized_keys` (the never floor, which runs first);
 *   - and a folder write grant covers a write outside the project, because that is what the same
 *     folder granted a direct `write` call.
 *
 * Every assertion goes through `evaluateToolPermission`, which is what `index.ts` calls on the
 * `tool_call` path, so these rows are the user-visible answers and not a description of the matcher.
 */

const cwd = "/home/user/project"

// The real matcher needs the grammar: without it every command reads `parser-unavailable`, nothing is
// covered, and half of this file would pass by measuring nothing.
beforeAll(async () => {
	await initBashParser()
})

function behaviorOf(
	command: string,
	allow: string[],
	authority?: RedirectAuthority,
): string {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig({ allow }, "project")),
		authority,
	).behavior
}

const HOME = process.env.HOME ?? "/home/user"

describe("the cases this exists for, row by row", () => {
	// [command, rules, why the redirect does not withhold it]
	const COVERED: Array<[string, string[], string]> = [
		["pi -p x", ["Bash(pi:*)"], "no redirect: the rule's own words"],
		["pi -p x 2>/dev/null", ["Bash(pi:*)"], "`/dev/null` is an inert sink, not a file anyone can hurt"],
		["pi -p x > /dev/null 2>&1", ["Bash(pi:*)"], "…and a descriptor dup names no file at all"],
		["pi -p x < prompt.md", ["Bash(pi:*)"], "an input redirect is a READ of a project file, which is free"],
		["grep foo src/a.ts 2>/dev/null", ["Bash(grep:*)"], "same sink, one descriptor further out"],
		["npm test > /tmp/out.txt", ["Bash(npm test:*)"], "a temp file is inside the default write area"],
		["make > build.log 2>&1", ["Bash(make:*)"], "a project file is inside the default write area"],
	]

	it.each(COVERED)("%s is covered by %j (%s)", (command, allow) => {
		expect(behaviorOf(command, allow)).toBe("allow")
	})

	it("covers the compound that used to be denied", () => {
		// `cd folder && nohup pi -p x > log.txt 2>&1 &` used to fall to the gate, which judged the pi leg
		// without the rule, and denied. Both legs still need their own authority — the redirect leg's
		// authority is the file it writes, not a waiver.
		expect(
			behaviorOf("cd folder && nohup pi -p x > log.txt 2>&1 &", ["Bash(pi:*)", "Bash(cd:*)"]),
		).toBe("allow")
	})
})

describe("what a redirect still withholds", () => {
	it("the never floor decides before any rule, redirect target included", () => {
		// The motivating over-grant, still refused — by the floor, which needs no target rule.
		expect(behaviorOf("echo key >> ~/.ssh/authorized_keys", ["Bash(echo:*)"])).toBe("passthrough")
	})

	it("a target decided at run time is not covered, because there is no target to check", () => {
		expect(behaviorOf("echo x > $f", ["Bash(echo:*)"])).toBe("passthrough")
		expect(behaviorOf('echo x > "$f"', ["Bash(echo:*)"])).toBe("passthrough")
	})

	it("live config is not in the default write area", () => {
		// A direct write to `~/.bashrc` asks (`write_sensitive`), so the redirect asks too.
		expect(behaviorOf("echo hi > ~/.bashrc", ["Bash(echo:*)"])).toBe("passthrough")
		// …and the same for the rest of the class, which is what makes this a rule and not one path.
		expect(behaviorOf("echo hi > ~/.ssh/config", ["Bash(echo:*)"])).toBe("passthrough")
	})

	it("a write outside the project with no grant is not covered, and asks for one", () => {
		expect(behaviorOf(`echo hi > ~/notes/out.txt`, ["Bash(echo:*)"])).toBe("passthrough")
	})
})

describe("the authority a redirect target is judged by is the direct call's", () => {
	it("a folder write grant covers the write, exactly as it covers the direct one", () => {
		const grants = createGrantStore()
		addGrant(grants, "write_outside", "~/notes/", "scope")
		expect(behaviorOf(`echo hi > ~/notes/out.txt`, ["Bash(echo:*)"], { grants })).toBe("allow")
		// The same grant, on a sibling folder, is not this folder.
		expect(behaviorOf(`echo hi > ~/other/out.txt`, ["Bash(echo:*)"], { grants })).toBe("passthrough")
	})

	it("a file grant covers exactly that file", () => {
		const grants = createGrantStore()
		addGrant(grants, "write_outside", "~/notes/out.txt", "entity")
		expect(behaviorOf(`echo hi > ~/notes/out.txt`, ["Bash(echo:*)"], { grants })).toBe("allow")
		expect(behaviorOf(`echo hi > ~/notes/other.txt`, ["Bash(echo:*)"], { grants })).toBe("passthrough")
	})

	it("`<` on a secret still needs read authority, and then gets it", () => {
		// A secret is asked for as `read_secret`, so a plain read grant on its folder is not enough.
		const readOnly = createGrantStore()
		addGrant(readOnly, "read_only", "~/.ssh/", "scope")
		expect(behaviorOf(`cat < ~/.ssh/id_rsa`, ["Bash(cat:*)"], { grants: readOnly })).toBe("passthrough")
		const secret = createGrantStore()
		addGrant(secret, "read_secret", `${HOME}/.ssh/id_rsa`, "entity")
		expect(behaviorOf(`cat < ~/.ssh/id_rsa`, ["Bash(cat:*)"], { grants: secret })).toBe("allow")
	})

	it("a `Write(...)` allow rule is enough, because that is what a direct write needs", () => {
		// The rules channel is consulted first for the target exactly as it is for the tool call itself.
		expect(behaviorOf(`echo hi > ~/notes/out.txt`, ["Bash(echo:*)", "Write(~/notes/**)"])).toBe("allow")
		// …and a `Write(...)` deny withholds it, which is what `evaluateToolPermission` does for the direct
		// call: the target is judged by the same channel, in the same order, not by a list kept here.
		expect(
			evaluateToolPermission(
				"bash",
				{ command: `echo hi > ~/notes/out.txt` },
				cwd,
				mergePermissionRules(
					rulesFromPermissionsConfig(
						{ allow: ["Bash(echo:*)", "Write(~/notes/**)"], deny: ["Write(~/notes/**)"] },
						"project",
					),
				),
			).behavior,
		).toBe("passthrough")
	})

	it("plan mode has no write area for a redirect to stand on", () => {
		// Plan writes one file, the plan file, and this layer must not be a second copy of that decision:
		// a project write would otherwise be covered by `Bash(echo:*)` while `write` itself is blocked.
		expect(behaviorOf("echo hi > src/a.ts", ["Bash(echo:*)"], { mode: "plan" })).toBe("passthrough")
		// A read is unaffected — plan mode reads freely.
		expect(behaviorOf("cat < src/a.ts", ["Bash(cat:*)"], { mode: "plan" })).toBe("allow")
		// And a `Write(...)` rule still speaks for the target, because it speaks for the direct call too
		// (index.ts consults the rules before the plan-mode branch).
		expect(behaviorOf("echo hi > src/a.ts", ["Bash(echo:*)", "Write(src/**)"], { mode: "plan" })).toBe("allow")
	})
})

describe("the words still have to match", () => {
	it("a rule for a different command covers nothing, redirect or not", () => {
		expect(behaviorOf("make > build.log", ["Bash(npm test:*)"])).toBe("passthrough")
	})

	it("a rule that names a DIFFERENT file does not cover this one", () => {
		// The clause is a statement about one invocation: what the rule names is what is compared, and an
		// allowed destination does not turn a rule for another destination into a rule for this one.
		expect(behaviorOf("make > build.log", ["Bash(make > other.log)"])).toBe("passthrough")
		expect(behaviorOf("make > build.log", ["Bash(make > build.log)"])).toBe("allow")
	})

	it("a glob is judged the same way as the other word rules", () => {
		// A `*` says something about arguments, nothing about files — so the file is still the target
		// question, and the answer is the same for an allowed place and a live-config one.
		expect(behaviorOf("make > build.log 2>&1", ["Bash(make *)"])).toBe("allow")
		expect(behaviorOf("echo hi > ~/.bashrc", ["Bash(echo *)"])).toBe("passthrough")
	})
})

describe("the gate already judges a redirect target the way it judges a direct write", () => {
	// What passthrough returns to the gate: layer 0 classifies every redirect with the same
	// `decideWrite` / `decideRead` a direct call gets (`astRedirectDecisions` in risk-policy.ts), so the
	// gate's own stores decide — no change was needed there, and this is the pin that says so.
	const policy = { cwd, project: cwd, home: homedir(), env: process.env }

	it("a folder write grant lets the redirecting command through at the gate", async () => {
		const grants = createGrantStore()
		addGrant(grants, "write_outside", "~/notes/", "scope")
		const r = await runGate("bash", { command: `echo hi > ~/notes/out.txt` }, { policy, grants })
		expect(r.outcome, r.reason).toBe("allow-granted")
		expect(r.category).toBe("write_outside")
	})

	it("and without the grant it asks, naming the file", async () => {
		const r = await runGate("bash", { command: `echo hi > ~/notes/out.txt` }, { policy, grants: createGrantStore() })
		expect(r.outcome).toBe("prompt")
		expect(r.entities.map((e) => e.value)).toContain("~/notes/out.txt")
	})
})

describe("the live mode is read from the channel index.ts publishes", () => {
	// `evaluateToolPermission` is handed no mode by its caller today, and the plugin's live state channel is
	// the published mode (index.ts → publishInheritedPermissionMode, read at call time). Pinned here because
	// it is what keeps plan mode's "writes go to the plan file" rule from being widened by a redirect.
	it("plan mode, published, withholds a project write target", () => {
		process.env.ADAPTIVE_ACL_INHERITED_MODE = "plan"
		try {
			expect(behaviorOf("echo hi > src/a.ts", ["Bash(echo:*)"])).toBe("passthrough")
		} finally {
			delete process.env.ADAPTIVE_ACL_INHERITED_MODE
		}
		// The same command under the suite's baseline (no mode published) is covered, so the assertion
		// above is measuring the mode and not something else.
		expect(behaviorOf("echo hi > src/a.ts", ["Bash(echo:*)"])).toBe("allow")
	})
})

describe("unchanged by all of this", () => {
	it("a redirect with no command runs nothing, so no rule speaks for the write", () => {
		expect(behaviorOf("> build.log", ["Bash"])).toBe("passthrough")
		expect(behaviorOf("> build.log", ["Bash(echo:)"])).toBe("passthrough")
	})

	it("a deny or an ask is textual and still fires on the redirecting form", () => {
		const rules = mergePermissionRules(rulesFromPermissionsConfig({ deny: ["Bash(make *)"] }, "project"))
		expect(
			evaluateToolPermission("bash", { command: "make > build.log" }, cwd, rules).behavior,
		).toBe("deny")
	})

	it("an opaque value in the leg is refused before a target is ever looked at", () => {
		expect(behaviorOf('make > "$OUT"', ["Bash(make:*)"])).toBe("passthrough")
	})
})
