/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */
import { beforeAll, describe, expect, it } from "vitest"
import { suggestBashAllowRuleSet } from "./bash-permission-match.ts"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
	type PermissionVerdict,
} from "./permissions.ts"
import { initBashParser } from "./bash-parser.ts"

/**
 * "Allow always" for a command with a run-time value.
 *
 * The value is not in the text, so no literal specifier can name it. Layer 1 (`slot-probe.ts`) answers the
 * only question that matters before one is stored — *does the value change what this command does?* — and
 * this file pins both halves of what follows: the rule written when it does not, the sentence shown when it
 * does, and the one property an offer must never lose, that the rule it writes is a rule that fires.
 *
 * Every pin goes through the real pipeline (`suggestAllowRuleSetForToolCall` → the rules added → 
 * `evaluateToolPermission`), because the offer and the matcher disagreeing is the failure mode this whole
 * path exists to exclude: a rule that never matches is an "Always allow" that silently does nothing.
 */

/** A cwd that exists in no test machine, so no probe can be answered by the filesystem. */
const cwd = "/home/user/project"

beforeAll(async () => {
	await initBashParser()
})

const offerFor = (command: string) => suggestAllowRuleSetForToolCall("bash", { command }, cwd)

function verdictFor(
	command: string,
	config: { allow?: string[]; ask?: string[]; deny?: string[] },
): PermissionVerdict["behavior"] {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig(config, "project")),
	).behavior
}

/** The promise an offer makes: everything it writes, added as rules, allows the very command it described. */
function roundTrip(command: string): string[] {
	const set = offerFor(command)
	expect(set.persistable, `${command} → ${set.reason}`).toBe(true)
	expect(verdictFor(command, { allow: set.rules }), `rules ${JSON.stringify(set.rules)} for ${command}`).toBe(
		"allow",
	)
	return set.rules
}

describe("a value the probe says cannot change the verdict is written down", () => {
	it("keeps the literal text around a partial value and quotes the word", () => {
		// `${PIPESTATUS[0]}` is printed, never opened: `echo` is judged the same whatever it expands to.
		expect(roundTrip('echo "exit ${PIPESTATUS[0]}"')).toEqual(['Bash(echo "exit $…")'])
	})

	it("writes the marker where a whole word is the value", () => {
		// The pattern of `grep` is not a file, so every probe value is judged the same way.
		expect(roundTrip('grep -n "$P" src/')).toEqual(["Bash(grep -n $… src/)"])
	})

	it("writes one rule per leg, and the substitution's own command is a leg", () => {
		// A command substitution runs a command, so layer 0 emits it as a leg of its own and coverage is AND
		// across legs: both rules are needed for the compound to be allowed, which is what makes the two
		// rules one offer rather than two independent grants.
		expect(roundTrip('git show "$(git rev-parse HEAD)"')).toEqual([
			"Bash(git rev-parse:*)",
			"Bash(git show $…)",
		])
	})

	it("never generalises a slot leg into a subcommand prefix", () => {
		// `Bash(grep -n $…)` would allow `grep -n anything` with any operand at all — the words after the
		// subcommand are exactly where the value sits, so they cannot be dropped.
		for (const rule of offerFor('grep -n "$P" src/').rules) {
			expect(rule).not.toContain(":*")
		}
	})

	it("keeps the redirect clause beside a value", () => {
		// The file is part of the invocation a rule names, so it is still written down: the value sits in the
		// words, the target after them.
		expect(roundTrip('echo "$X" > out.txt')).toEqual(["Bash(echo $… > out.txt)"])
	})
})

describe("a value that decides is refused, and the sentence names it", () => {
	const REFUSED: Array<[string, string[]]> = [
		// A read of a path: the value decides whether it is a project file or a credential.
		['wc -l "$F"', ["$F", "read_secret"]],
		['cat -- "$F"', ["$F", "read_secret"]],
		// `rm` names its target: the value decides what is deleted.
		['rm "$X"', ["$X", "never"]],
		// `sort -o` writes a file, so a value can become the flag as well as the path.
		['sort "$X"', ["$X", "output flag"]],
		// An unquoted value is not one word: the shell splits it and expands globs.
		["cat $F", ["$F", "unquoted"]],
	]

	for (const [command, fragments] of REFUSED) {
		it(`refuses ${JSON.stringify(command)}`, () => {
			const set = offerFor(command)
			expect(set.persistable, command).toBe(false)
			expect(set.rules, command).toEqual([])
			for (const fragment of fragments) {
				expect(set.reason, command).toContain(fragment)
			}
		})
	}

	it("refuses an unquoted value even where the probe would allow it", () => {
		// The probe accepts an unquoted slot in `echo`'s arguments, because nothing there opens anything. The
		// rule cannot: `echo $HOME/x` is one word or two depending on a value it has no way to write down.
		const set = offerFor("echo $HOME/x")
		expect(set.persistable).toBe(false)
		expect(set.reason).toContain("unquoted")
	})

	it("refuses a value in a redirect target, where no slot can put it", () => {
		// A redirect target is not an argument position: layer 0 will not vouch for the construct and the
		// walker's refusal stands, so nothing is written.
		expect(offerFor('echo hi > "$F"').persistable).toBe(false)
	})

	it("keeps today's answer where the command is not a template at all", () => {
		// An env prefix whose value is only known at run time is refused by the template parse too (the
		// assignment changes what runs, before any argument is reached), so the text producer's guess stands —
		// and the round trip withholds it, exactly as it did before this path existed.
		expect(offerFor('F="$X" cat').persistable).toBe(false)
		expect(offerFor('cat "$(cat ~/.ssh/id_rsa)"').persistable).toBe(false)
	})
})

describe("a compound is all or nothing", () => {
	it("writes every leg when every leg is describable", () => {
		expect(roundTrip('cd x && grep -n "$P" src/')).toEqual(["Bash(cd x)", "Bash(grep -n $… src/)"])
	})

	it("writes nothing when one leg is refused", () => {
		// Coverage is AND across legs, so half a set would sit in the file never firing.
		const set = offerFor('grep -n "$P" src/ && wc -l "$F"')
		expect(set.persistable).toBe(false)
		expect(set.rules).toEqual([])
		expect(set.reason).toContain("$F")
	})
})

describe("what a written slot rule covers next time", () => {
	const grepRule = ["Bash(grep -n $… src/)"]

	it("covers the same words with another variable", () => {
		expect(verdictFor('grep -n "$Q" src/', { allow: grepRule })).toBe("allow")
	})

	it("covers another value SOURCE, as long as the substitution's own command is authorised too", () => {
		// The marker says "one run-time value here", not "the variable P": a substitution in that position is
		// the same shape. The substitution's command is a leg of the command, though, and stays uncovered —
		// which is why the offer for `$(date)` writes a rule for `date` as well.
		expect(verdictFor('grep -n "$(date)" src/', { allow: grepRule })).toBe("passthrough")
		expect(verdictFor('grep -n "$(date)" src/', { allow: [...grepRule, "Bash(date)"] })).toBe("allow")
	})

	it("never covers a literal word", () => {
		// The whole point of a distinct marker: `$…` is not a glob and not a wildcard.
		expect(verdictFor("grep -n foo src/", { allow: grepRule })).toBe("passthrough")
	})

	it("is not covered by a rule that names no value — that is today's answer for an opaque leg", () => {
		// Including the tool-wide grant: `Bash` / `Bash(*)` names no value either, so it cannot say where one
		// goes. Only a marker can, which is what keeps a blanket rule from hiding a value the probe would
		// have refused (`Bash(*)` does not cover `rm "$X"`, either).
		for (const rule of [
			"Bash",
			"Bash(*)",
			"Bash(grep:*)",
			"Bash(grep -n:*)",
			"Bash(grep -n src/)",
			"Bash(grep * src/)",
		]) {
			expect(verdictFor('grep -n "$P" src/', { allow: [rule] }), rule).toBe("passthrough")
		}
	})

	it("is covered by a hand-written slot rule for the same shape", () => {
		expect(verdictFor('grep -n "$P" src/', { allow: grepRule })).toBe("allow")
	})

	it("refuses a hand-written rule whose value the probe would not vouch for", () => {
		// The re-check at match time is what makes a hand-written rule — and one written before a policy
		// change — as safe as one the offer wrote: `rm "$X"` is not inert, so nothing covers it.
		expect(verdictFor('rm "$X"', { allow: ["Bash(rm $…)"] })).toBe("passthrough")
		expect(verdictFor('cat -- "$F"', { allow: ["Bash(cat -- $…)"] })).toBe("passthrough")
	})

	it("refuses a slot rule written for a leg at the never floor", () => {
		// `rm -rf / "$X"` is judged `never` whatever the value is, so the probe has nothing to complain
		// about — the floor is what has to refuse it, and it does.
		expect(verdictFor('rm -rf / "$X"', { allow: ["Bash(rm -rf / $…)"] })).toBe("passthrough")
	})
})

describe("the writer and the matcher are one producer", () => {
	// The offer runs its own rules back through the matcher that will have to honour them
	// (`permissions.ts` `suggestBashRules`). A writer that spelled anything the matcher reads differently
	// would show up here as an offer that reports itself unhonourable.
	it("does not withdraw an offer it just made, for any case it writes", () => {
		const written = [
			'echo "exit ${PIPESTATUS[0]}"',
			'grep -n "$P" src/',
			'git show "$(git rev-parse HEAD)"',
			'cd x && grep -n "$P" src/',
			'echo "$(date)"',
			'echo "$HOME"',
		]
		for (const command of written) {
			const set = suggestBashAllowRuleSet(command, cwd)
			expect(set.persistable, `${command}: ${set.reason}`).toBe(true)
			expect(offerFor(command).persistable, command).toBe(true)
		}
	})
})
