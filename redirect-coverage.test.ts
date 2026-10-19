/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import { beforeAll } from "vitest"
import { initBashParser } from "./bash-parser.ts"
import { permissionRuleValueFromString, permissionRuleValueToString } from "./permission-rule-parser.ts"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
} from "./permissions.ts"

/**
 * The "Always allow" offer for a command that writes through a redirect, and the coverage that has to
 * honour it (work.log 2026-10-14 §5.2: the largest withheld class, ~16 % of measured bash calls).
 *
 * Coverage used to be able to speak only about argv, so the only rule that would cover
 * `echo hi > /tmp/out.txt` was `Bash(echo hi)` — which also covers `echo hi > ~/.ssh/authorized_keys`. The
 * offer was withheld for that reason, and withholding was right. What changed is that a specifier can name
 * the file now (`Bash(echo hi > /tmp/out.txt)`), so both directions are pinned for every row:
 *
 *   - the rule that names the target covers that invocation and nothing shaped like it — a different file,
 *     a different operator, a different descriptor, one extra word: all uncovered;
 *   - a rule that names NO target covers no command that redirects at all, including the `:*` and glob forms
 *     that used to wave them through. That is a narrowing of yesterday's behaviour, and it is the half that
 *     makes the recovery safe instead of a new way to over-grant.
 *
 * The floor, the run-time-value refusals and the textual deny/ask path are pinned from their own side too,
 * because a change aimed at the offer must not have reached any of them.
 */

const cwd = "/home/user/project"

// The assertions go through the real matcher, which needs the grammar: without it every command reads
// `parser-unavailable`, nothing is covered, and half of this file would pass by measuring nothing.
beforeAll(async () => {
	await initBashParser()
})

function behaviorOf(command: string, cfg: { allow?: string[]; deny?: string[]; ask?: string[] }): string {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig(cfg, "project")),
	).behavior
}

const offerFor = (command: string) => suggestAllowRuleSetForToolCall("bash", { command }, cwd)

/** The specifier as a person reads it in the dialog and in the file: `Bash(…)` off, escapes standing. */
function specifierOf(rule: string): string {
	return permissionRuleValueFromString(rule).ruleContent ?? ""
}

/** The offer for a single-leg command, with the round trip the dialog depends on. */
function offered(command: string): { rule: string; honoured: string } {
	const set = offerFor(command)
	if (!set.persistable) throw new Error(`${command}: no offer (${set.reason})`)
	expect(set.rules.length, command).toBe(1)
	return { rule: set.rules[0]!, honoured: behaviorOf(command, { allow: set.rules }) }
}

describe("the offer names the file, and the matcher honours exactly that", () => {
	// [command as typed, the specifier an "Always allow" writes, invocations that rule must NOT reach]
	const ROWS: Array<[string, string, string[]]> = [
		[
			"echo hi > /tmp/out.txt",
			"echo hi > /tmp/out.txt",
			["echo hi > /tmp/other.txt", "echo hi >> /tmp/out.txt", "echo hi", "echo hi there > /tmp/out.txt"],
		],
		[
			"git log > report.txt",
			"git log > report.txt",
			["git log > report.txt2", "git log --oneline > report.txt", "git log > ~/.ssh/authorized_keys"],
		],
		[
			"cat x >> /tmp/log",
			"cat x >> /tmp/log",
			["cat x > /tmp/log", "cat x >> /tmp/log2", "cat y >> /tmp/log"],
		],
		// An inert destination is still a destination: what makes the rule safe is that it names one, not
		// that the one it names cannot be hurt. `> /dev/zero` is refused by the floor, not by a name list.
		["echo hi > /dev/null", "echo hi > /dev/null", ["echo hi > /dev/zero", "echo hi > ./out"]],
		// A quoted target is spelled with its quoting resolved, like any other argument.
		["echo hi > 'my file.txt'", "echo hi > my\\ file.txt", ["echo hi > my file.txt"]],
		// Operators that mean something else are not interchangeable with `>`.
		["echo hi >| /tmp/x", "echo hi >| /tmp/x", ["echo hi > /tmp/x", "echo hi >> /tmp/x"]],
		["cat f &> /tmp/all", "cat f &> /tmp/all", ["cat f > /tmp/all", "cat f 2> /tmp/all"]],
		// The descriptor is part of the target: stderr into an approved file is not the approved write.
		["cat f 2> /tmp/x", "cat f 2> /tmp/x", ["cat f > /tmp/x", "cat f 1> /tmp/x"]],
		// A read is the same question: `cat` alone never says which file was read.
		["cat < /etc/shadow", "cat < /etc/shadow", ["cat < /etc/passwd", "cat /etc/shadow"]],
		// Two file targets: both are named, or the rule is not this invocation.
		[
			"ls -la > out.txt 2> err.txt",
			"ls -la > out.txt 2> err.txt",
			["ls -la > out.txt", "ls -la > out.txt 2> other.txt"],
		],
		// A verb that already writes via `of=` and also redirects: both halves are in the rule.
		[
			"dd if=/dev/zero of=/tmp/x bs=1 > /dev/null",
			"dd if=/dev/zero of=/tmp/x bs=1 > /dev/null",
			["dd if=/dev/zero of=/tmp/y bs=1 > /dev/null", "dd if=/dev/zero of=/tmp/x bs=1"],
		],
	]

	for (const [command, specifier, uncovered] of ROWS) {
		it(`${command} → Bash(${specifier})`, () => {
			const offer = offered(command)
			// What the user is shown is what gets stored, spelled exactly.
			expect(specifierOf(offer.rule), command).toBe(specifier)
			// A redirect is never generalised into a prefix: the clause names one file, so the words in
			// front of it decide what lands in it — `git log:*` would be a write-everywhere grant.
			expect(offer.rule, command).not.toContain(":*")
			expect(offer.honoured, command).toBe("allow")
			for (const other of uncovered) {
				expect(behaviorOf(other, { allow: [offer.rule] }), `${command} → ${other}`).toBe("passthrough")
			}
		})
	}

	it("writes one rule per leg, and the redirect leg keeps its own target", () => {
		const set = offerFor("git status && echo hi > out.txt")
		expect(set.persistable, set.reason ?? "").toBe(true)
		// The innocent leg still generalises; the leg that writes does not.
		expect(set.rules).toEqual(["Bash(git status:*)", "Bash(echo hi > out.txt)"])
		expect(behaviorOf("git status && echo hi > out.txt", { allow: set.rules })).toBe("allow")
		// Padding the approved compound with a different target gains nothing.
		expect(behaviorOf("git status && echo hi > ~/.ssh/authorized_keys", { allow: set.rules })).toBe(
			"passthrough",
		)
	})

	it("leaves a descriptor dup alone, so `2>&1` still costs nothing", () => {
		// `make 2>&1 | tail -50` opens no file, so it is not target-bearing and the ordinary contract
		// applies — the decision W9 pinned, kept intact here.
		expect(behaviorOf("make 2>&1 | tail -50", { allow: ["Bash(make:*)", "Bash(tail:*)"] })).toBe("allow")
		const set = offerFor("npm test 2>&1 | tail -20")
		expect(set.persistable, set.reason ?? "").toBe(true)
		expect(behaviorOf("npm test 2>&1 | tail -20", { allow: set.rules })).toBe("allow")
		// A dup sitting next to a real target is still ignored: the rule names the file, not the dup.
		expect(specifierOf(offered("echo hi > a 2>&1").rule)).toBe("echo hi > a")
		expect(behaviorOf("echo hi > a", { allow: ["Bash(echo hi > a)"] })).toBe("allow")
	})

	it("spells a fused redirect canonically, so one invocation has one rule", () => {
		// `echo hi>/tmp/x`, `echo hi > /tmp/x` and `echo hi 1>/tmp/x` are one command to bash, so they must
		// not become three rules that cannot see each other.
		for (const spelling of ["echo hi>/tmp/x", "echo hi > /tmp/x", "echo hi 1>/tmp/x"]) {
			expect(specifierOf(offered(spelling).rule), spelling).toBe("echo hi > /tmp/x")
		}
		expect(behaviorOf("echo hi 1> /tmp/x", { allow: ["Bash(echo hi > /tmp/x)"] })).toBe("allow")
	})

	it("spells a target that itself contains an operator as data, not as structure", () => {
		// The command writes a file literally named `a>b`. The rule escapes the `>`, so the clause cannot be
		// re-read as two clauses, and the same rule never covers a write to `b`.
		const offer = offered("echo a > 'a>b'")
		expect(specifierOf(offer.rule)).toBe("echo a > a\\>b")
		expect(offer.honoured).toBe("allow")
		expect(behaviorOf("echo a > b", { allow: [offer.rule] })).toBe("passthrough")
	})
})

describe("tightening: a rule that names no target covers no command that redirects to one", () => {
	// Each row here was `allow` before this task — the argv-only matcher saw `echo hi` and stopped. They are
	// the cost of the change, paid in prompts by rules written before a redirect could be named, and they
	// are the reason the recovery above is not a loosening: `Bash(echo:*)` covering
	// `echo key > ~/.ssh/authorized_keys` is the exact over-grant the suggestion engine already refuses to
	// WRITE (see SUBCOMMAND_GRAMMAR_TOOLS in bash-permission-match.ts). Refusing it on the side that has to
	// honour the rule is what makes the two agree.
	const TIGHTENED: Array<[string, string[]]> = [
		["echo hi > /tmp/out.txt", ["Bash(echo hi)"]],
		["echo hi > /tmp/out.txt", ["Bash(echo:*)"]],
		["echo hi > /tmp/out.txt", ["Bash(echo *)"]],
		["echo key >> ~/.ssh/authorized_keys", ["Bash(echo key:*)"]],
		["git log > report.txt", ["Bash(git log:*)"]],
		["cat x > /tmp/y", ["Bash(cat:*)"]],
		["cat < /etc/shadow", ["Bash(cat:*)"]],
		["grep x f > /tmp/out", ["Bash(grep *)"]],
	]

	it.each(TIGHTENED)("%s is left to the gate by %j", (command, allow) => {
		expect(behaviorOf(command, { allow })).toBe("passthrough")
	})

	it("still covers the same rule's command when nothing redirects, so the narrowing is about the file", () => {
		expect(behaviorOf("echo hi", { allow: ["Bash(echo hi)"] })).toBe("allow")
		expect(behaviorOf("echo hi there", { allow: ["Bash(echo:*)"] })).toBe("allow")
		expect(behaviorOf("git log --oneline", { allow: ["Bash(git log:*)"] })).toBe("allow")
		expect(behaviorOf("cat x", { allow: ["Bash(cat:*)"] })).toBe("allow")
	})

	it("does not turn into a licence for the words alone", () => {
		// The clause is not decoration: a rule written for a redirect does not reach the same words without
		// one, which is the difference between "this invocation" and "these words, anywhere".
		expect(behaviorOf("echo hi", { allow: ["Bash(echo hi > /tmp/x)"] })).toBe("passthrough")
		expect(behaviorOf("cat x", { allow: ["Bash(cat x >> /tmp/log)"] })).toBe("passthrough")
	})

	it("still refuses a target that only exists at run time, however the rule is spelled", () => {
		// Hard constraint: `>` into a runtime-determined path stays uncovered. The walker either refuses the
		// command or flags the leg `opaque`, and both refusals happen before any rule is read.
		expect(behaviorOf("echo x > $(printf /etc/x)", { allow: ["Bash"] })).toBe("passthrough")
		expect(behaviorOf('echo hi > "$TARGET"', { allow: ["Bash"] })).toBe("passthrough")
		expect(behaviorOf('echo hi > "$TARGET"', { allow: ["Bash(echo hi > /etc/x)"] })).toBe("passthrough")
	})

	it("still refuses the never floor with a rule that names the target exactly", () => {
		expect(
			behaviorOf("echo key >> ~/.ssh/authorized_keys", {
				allow: ["Bash(echo key >> ~/.ssh/authorized_keys)"],
			}),
		).toBe("passthrough")
		// A redirect with no command runs nothing, so no rule — target included — speaks for the write.
		expect(behaviorOf("> /tmp/x", { allow: ["Bash"] })).toBe("passthrough")
	})
})

describe("deny and ask stay textual, redirects included", () => {
	// A denial has to fire on a command that adds words or a redirect — that is why it never moved onto
	// argv, and this is the pin that keeps it there now that allow can name a target.
	it("a deny fires on a command whose words it does not spell out", () => {
		expect(behaviorOf("rm secret.txt > /tmp/out", { deny: ["Bash(rm *)"] })).toBe("deny")
		expect(behaviorOf("echo secret > /tmp/out", { deny: ["Bash(echo *)"] })).toBe("deny")
		expect(behaviorOf("echo secret >> ~/.ssh/authorized_keys", { deny: ["Bash(echo:*)"] })).toBe("deny")
	})

	it("a deny outranks an allow that names the target exactly", () => {
		expect(
			behaviorOf("echo secret > /tmp/out", {
				allow: ["Bash(echo secret > /tmp/out)"],
				deny: ["Bash(echo *)"],
			}),
		).toBe("deny")
	})

	it("an ask still prompts despite the exact target rule", () => {
		expect(
			behaviorOf("cat x > /tmp/y", {
				allow: ["Bash(cat x > /tmp/y)"],
				ask: ["Bash(cat *)"],
			}),
		).toBe("ask")
	})
})

describe("what is still withheld, class by class", () => {
	const WITHHELD: Array<[string, string]> = [
		["echo hi > ~/.ssh/authorized_keys", "the never floor decides before any rule; an offer would hide the reason"],
		["echo x > $(printf /etc/x)", "the target is decided at run time, so layer 0 refuses the command"],
		['echo hi > "$TARGET"', "an opaque target cannot be named by a rule"],
		["cat notes.txt << 'EOF'\nbody\nEOF", "a here-document body is data on the leg"],
		["grep x f <<< hello", "a here-string is input no rule names"],
		["LD_PRELOAD=/tmp/e.so cmd > /tmp/x", "the environment decides what runs, and argv carries none of it"],
		["printf 'a\nb' > /tmp/x", "an argument that spans lines cannot sit in a one-line rule"],
		["echo hi > '/tmp/a\nb'", "neither can a target that spans lines"],
		["> /tmp/x", "a command that runs nothing has no words for a rule to name"],
	]

	it.each(WITHHELD)("%s — %s", (command, why) => {
		const set = offerFor(command)
		expect(set.persistable, `${command} (${why})`).toBe(false)
		expect(set.rules, command).toEqual([])
		// The dialog prints the reason instead of an offer; silence reads as a bug.
		expect(set.reason, command).toBeTruthy()
	})

	it("refuses a compound in which only one leg redirects and cannot be named", () => {
		// Coverage is AND across legs, so one unnameable leg takes the whole set with it rather than
		// storing half a rule that would never fire.
		const set = offerFor("git status && cat notes.txt << 'EOF'\nbody\nEOF")
		expect(set.persistable).toBe(false)
		expect(set.rules).toEqual([])
	})
})

describe("the rule text survives the file it is written into", () => {
	// Rules live in permissions.json as strings and are de-duplicated by their normalised form, so a
	// specifier must round-trip through the rule parser unchanged — including the bare `>` that marks a
	// clause, which is the character this task added to the specifier vocabulary.
	const SPELLINGS = [
		"echo hi > /tmp/out.txt",
		"echo hi > 'my file.txt'",
		"cat f 2> /tmp/x",
		"ls -la > out.txt 2> err.txt",
		"echo a > 'a>b'",
		"echo hi > '|weird|'",
		"cat x >> /tmp/log",
	]

	it("is one line, keeps its clause, and is identical after a round trip", () => {
		for (const command of SPELLINGS) {
			const set = offerFor(command)
			expect(set.persistable, `${command}: ${set.reason}`).toBe(true)
			for (const rule of set.rules) {
				expect(rule, command).not.toContain("\n")
				expect(permissionRuleValueToString(permissionRuleValueFromString(rule)), rule).toBe(rule)
				// The clause is still a clause after the escape codec, i.e. the `>` was not escaped away.
				expect(permissionRuleValueFromString(rule).ruleContent ?? "", rule).toContain(">")
				expect(behaviorOf(command, { allow: [rule] }), command).toBe("allow")
			}
		}
	})

	it("names a target with a newline nowhere, because the producer refuses instead", () => {
		// A specifier spanning lines is not a rule: the loader compares whole entries and the dialog shows
		// one line. Refusal, not a rule with an embedded newline.
		expect(offerFor("echo hi > '/tmp/a\nb'").persistable).toBe(false)
	})
})

describe("the invariant over the curated corpus", () => {
	// `bash-allow-layer0.test.ts` pins "an offer that is made is an offer that covers" across both case
	// files. What is added here is the redirect-specific half of that: the corpus's one redirecting command
	// must STILL be withheld (it targets authorized_keys, so the floor decides), and a list of redirecting
	// commands that this task is about must round-trip — because a property test over a population of zero
	// is exactly the vacuous pass work.log warns about.
	it("keeps the corpus's one redirect row withheld", () => {
		const command = "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA ci@runner' >> ~/.ssh/authorized_keys"
		const set = offerFor(command)
		expect(set.persistable).toBe(false)
		expect(set.rules).toEqual([])
		expect(behaviorOf(command, { allow: ["Bash(echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA ci@runner' >> ~/.ssh/authorized_keys)"] })).toBe(
			"passthrough",
		)
	})

	it("round-trips every redirecting command this file is about", () => {
		const commands = [
			"echo hi > /tmp/out.txt",
			"git log > report.txt",
			"cat x >> /tmp/log",
			"echo hi > /dev/null",
			"echo hi > 'my file.txt'",
			"cat f 2> /tmp/x",
			"ls -la > out.txt 2> err.txt",
			"cat < /etc/shadow",
			"git status && echo hi > out.txt",
			"npm test > /tmp/test.log 2>&1",
		]
		let offers = 0
		for (const command of commands) {
			const set = offerFor(command)
			expect(set.persistable, `${command}: ${set.reason}`).toBe(true)
			offers += set.rules.length
			expect(behaviorOf(command, { allow: set.rules }), command).toBe("allow")
		}
		expect(offers).toBeGreaterThan(commands.length)
	})
})
