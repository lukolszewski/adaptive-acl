/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import { beforeAll } from "vitest"
import { auditBashCommand } from "./bash-audit.ts"
import { ruleArgv } from "./bash-rule-argv.ts"
import { permissionRuleValueFromString } from "./permission-rule-parser.ts"
import { suggestBashAllowRuleSet } from "./bash-permission-match.ts"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
} from "./permissions.ts"
import { initBashParser } from "./bash-parser.ts"

/**
 * The "Always allow" offer, built from layer 0's argv instead of from a re-split of the command text.
 *
 * The property every test here guards is the one the offer exists for: a rule that is written is a rule that
 * fires. Before this producer, the specifier was spelled out of the command STRING — the first line of a
 * multi-line command, a redirect, a `<<`, a `$(…)` — and the matcher that has to honour it compares argv, so
 * W3 had to withhold the offer rather than store a rule that would never match. Now the words come from the
 * same parse the matcher reads, which turns "no Always for you" into "here is a rule that covers this" for
 * quoted separators, escaped stars, fd dups and multi-line scripts, and leaves the honest refusals exactly
 * where they were.
 *
 * Nothing here tests what is ALLOWED. The verdicts are W3's and `bash-allow-layer0.test.ts` owns them; this
 * file is about what is OFFERED, and the invariant is that a suggestion never claims more than the call.
 */

const cwd = "/home/user/project"

// Every assertion below goes through the real matcher, which needs the grammar. Without it every command
// would be `parser-unavailable`, no rule would cover anything, and half of these tests would pass by not
// measuring anything at all.
beforeAll(async () => {
	await initBashParser()
})

const offerFor = (command: string) => suggestAllowRuleSetForToolCall("bash", { command }, cwd)

function behaviourOf(command: string, allow: string[]): string {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(rulesFromPermissionsConfig({ allow }, "project")),
	).behavior
}

/** The words a written rule names, in the form the matcher compares them in. */
function wordsNamedBy(rule: string): string[] | null {
	return ruleArgv({ source: "project", behavior: "allow", ruleValue: permissionRuleValueFromString(rule) })
}

/** The specifier as a human reads it in the dialog and in the file: `Bash(…)` off, escapes standing. */
function specifierOf(rule: string): string {
	return permissionRuleValueFromString(rule).ruleContent ?? ""
}

/** The legs of a command, as layer 0 answered them. */
function legsOf(command: string): string[][] {
	const audit = auditBashCommand(command)
	if (!audit.proven) throw new Error(`layer 0 refuses ${JSON.stringify(command)}: ${audit.reason}`)
	return audit.legs.map((l) => l.argv)
}

describe("the offer is the round trip: a rule that is made is a rule that covers", () => {
	// Constraint: for every suggestion emitted, `bashAllowRulesCoverCommand` must cover the command it was
	// written from. Anything else is a bug in the producer, not a user problem.
	const OFFERED = [
		"git status && echo done",
		"npm test 2>&1 | tail -20",
		"ls -la; echo done",
		"echo one\necho two",
		"cd /tmp && ls -la",
		"grep -rn 'TODO' src | head -5",
		// the classes the text producer could not describe at all
		"echo 'a && b'",
		"find . -name '*.ts' | xargs grep -l foo",
		"awk '{print $1}' f.txt",
		"python3 -c 'print(1)'",
		"node -e 'console.log(1)'",
		"touch 'weird name.txt'",
		"time npm test",
		"printf '%s\\n' one two",
		"sed -i.bak s/a/b/ f",
		"tar czf x.tgz src",
		"FOO=1 git status",
	]

	for (const command of OFFERED) {
		it(`offers, and the offer covers: ${JSON.stringify(command)}`, () => {
			const set = offerFor(command)
			expect(set.persistable, set.reason ?? "").toBe(true)
			expect(set.rules.length).toBeGreaterThan(0)
			expect(behaviourOf(command, set.rules), command).toBe("allow")
		})
	}

	it("names the words of a quoted argument rather than the quoting around them", () => {
		// The old producer split on the `&&` INSIDE the quotes and wrote a rule for `echo "a`, which is
		// not a command. The argv has one argument `a && b`, and that is what the specifier spells — with
		// the shell-meaningful characters backslashed, because a bare one would be read as structure.
		const set = suggestBashAllowRuleSet("echo 'a && b'", cwd)
		expect(specifierOf(set.rules[0]!)).toBe("echo a\\ \\&\\&\\ b")
		expect(wordsNamedBy(set.rules[0]!)).toEqual(["echo", "a && b"])
		expect(behaviourOf("echo 'a && b'", set.rules)).toBe("allow")
	})

	it("escapes a star so the rule stays a command and does not become a glob", () => {
		// An unescaped `*` in a specifier is read as a wildcard by the rule parser, which would silently
		// widen `find . -name '*.ts'` into a pattern over any argument list.
		const set = suggestBashAllowRuleSet("find . -name '*.ts'", cwd)
		expect(specifierOf(set.rules[0]!)).toBe("find . -name \\*.ts")
		expect(wordsNamedBy(set.rules[0]!)).toEqual(["find", ".", "-name", "*.ts"])
		expect(behaviourOf("find . -name '*.py'", set.rules)).toBe("passthrough")
	})

	it("keeps an argument that spans lines out of the rule rather than breaking the file", () => {
		// The permissions loader compares rules line by line, so a specifier with a newline in it is not a
		// rule. `git commit -m "…"` generalises past that; a verb without a subcommand grammar cannot.
		const set = offerFor("printf 'a\nb' x")
		expect(set.persistable).toBe(false)
		expect(set.reason).toContain("spans lines")
	})
})

describe("withheld, exactly as W3 left it", () => {
	// Constraint: nothing W3 pinned as uncovered may become covered. These are the commands where a rule
	// would either be honoured for something the user never saw or describe nothing at all.
	const WITHHELD: Array<[string, string]> = [
		["rm -rf /", "never floor: coverage refuses it, so a rule would only hide the reason"],
		["sudo rm -rf /", "a wrapper does not launder the floor, and neither does a rule"],
		["git push --force origin main", "same, for a force push"],
		["echo $(rm -rf /)", "a substitution is a command the parse never saw"],
		["echo $HOME/x", "a variable's value is not argv"],
		['cat "$HOME/x"', "an opaque value cannot be covered by a rule"],
		["grep x <<<hello", "a here-string is input the rule does not name"],
		["cat <<'EOF'\n{\"a\": 1}\nEOF", "a here-document body is data on the leg, never argv"],
		["for f in a b; do rm -f $f; done", "control flow: no argv, no rule"],
		["LD_PRELOAD=/tmp/e.so git status", "the environment decides what runs, and argv cannot carry it"],
		["PATH=/usr/bin ls", "same"],
	]

	for (const [command, why] of WITHHELD) {
		it(`${JSON.stringify(command)} — ${why}`, () => {
			const set = offerFor(command)
			expect(set.persistable, command).toBe(false)
			expect(set.rules, command).toEqual([])
			// The dialog prints the reason instead of the offer; silence reads as a bug.
			expect(set.reason, command).toBeTruthy()
		})
	}

	it("still refuses the three cases whose refusal W3 pinned by wording", () => {
		// `bash-allow-layer0.test.ts` pins this phrase for these commands; it stays true because the
		// refusals that remain are all the same shape: nothing writable would be honoured. (`echo hi >
		// /tmp/out.txt` used to be one of them: a redirect could not be described, so no rule was offered.
		// Once a specifier could name a target, it became an offer — see the block below.)
		for (const command of ["rm -rf /", "cat <<'EOF'\n{\"a\": 1}\nEOF"]) {
			expect(offerFor(command).reason, command).toContain("no rule would cover this command again")
		}
	})
})

describe("a redirect is offered as an exact rule that names the target", () => {
	// These three rows sat in the withheld table above, with the argument that "the write IS the
	// approval, and argv alone would cover writing anywhere". That argument still holds — which is why the
	// offer is not `Bash(echo hi)` but a rule naming the file, the operator and the descriptor, and why the
	// target-less spelling of the same rule stops covering the command. Both directions are pinned here;
	// `redirect-coverage.test.ts` holds the full truth table and the classes this still refuses.
	const RECOVERED: Array<[string, string, string]> = [
		["echo hi > /tmp/out.txt", "echo hi > /tmp/out.txt", "Bash(echo hi)"],
		["echo hi > /dev/null", "echo hi > /dev/null", "Bash(echo:*)"],
		["cat < /etc/passwd", "cat < /etc/passwd", "Bash(cat:*)"],
	]

	for (const [command, specifier, targetLessRule] of RECOVERED) {
		it(`${command}: offered, honoured, and unreachable by ${targetLessRule}`, () => {
			const set = offerFor(command)
			expect(set.persistable, set.reason ?? "").toBe(true)
			expect(permissionRuleValueFromString(set.rules[0]!).ruleContent, command).toBe(specifier)
			expect(behaviourOf(command, set.rules), command).toBe("allow")
			// The whole safety argument in one line: the rule that covers this write covers nothing else.
			expect(behaviourOf(command, [targetLessRule]), command).toBe("passthrough")
		})
	}

	it("still refuses a redirect whose target only exists at run time", () => {
		// Hard constraint: the walker cannot prove the target, so no rule may speak for it.
		expect(offerFor("echo x > $(printf /etc/x)").persistable).toBe(false)
		expect(offerFor('echo hi > "$TARGET"').persistable).toBe(false)
		expect(offerFor("echo hi > ~/.ssh/authorized_keys").persistable).toBe(false)
	})
})

describe("a destructive leg is offered as the exact argv, never as a shorter prefix", () => {
	// W8's rule: where the category is set by the targets the command names (delete_recursive,
	// file_overwrite, vcs_discard, device_write, permission_change, ssh_key_write), coverage requires argv
	// equality — no extension, options included. A suggestion that dropped words would therefore be an offer
	// the matcher refuses to honour: the dead offer W3 removed, arriving from the other side. So the promise
	// this side has to keep is that the rule names EVERY word of the leg, which is what `named.length ===
	// argv.length` below asserts for each row.
	//
	// `uncovered` is the sibling the written rule must NOT reach: fewer words than the rule names, so it is
	// not the command that was approved. (A sibling with EXTRA words — `rm -rf /tmp/x --verbose /tmp/z` — is
	// still prefix-covered until W8's equality lands; that half is W8's assertion to own, not this file's.)
	const EXACT: Array<[string, string, string]> = [
		["rm -rf /tmp/x --verbose", "delete_recursive", "rm -rf /tmp/x"],
		["rm -rf /tmp/x /tmp/y", "delete_recursive", "rm -rf /tmp/x"],
		["git clean -fdx", "vcs_discard", "git clean"],
		["chmod -R 777 /tmp/x", "permission_change", "chmod -R 777"],
		["dd if=/dev/zero of=/tmp/x bs=1", "device_write / file_overwrite", "dd if=/dev/zero of=/tmp/x"],
		["mv /a/one /b/two", "file_overwrite", "mv /a/one"],
		["truncate -s 0 f", "file_overwrite", "truncate -s 0"],
	]

	for (const [command, category, uncovered] of EXACT) {
		it(`${JSON.stringify(command)} (${category}) names every word`, () => {
			const set = suggestBashAllowRuleSet(command, cwd)
			expect(set.persistable, set.reason ?? "").toBe(true)
			expect(set.rules[0]).not.toContain(":*")
			const named = set.rules.map((r) => wordsNamedBy(r))
			const legs = legsOf(command)
			expect(named, command).toEqual(legs)
			for (const argv of legs) {
				// The W8 promise, stated where it can be broken: not one word dropped.
				expect(named.flat().length, command).toBe(argv.length)
			}
			// The offer is still worth making: it covers the command that was approved …
			expect(behaviourOf(command, set.rules), command).toBe("allow")
			// … and it does not reach a call that named fewer words (work.log 2026-10-14: the approval of
			// one scratch path must not be the authority for arbitrary others).
			expect(behaviourOf(uncovered, set.rules), uncovered).toBe("passthrough")
		})
	}

	it("leaves a leg whose risk is not in its targets free to generalise", () => {
		// The asymmetry is the decision: `Bash(git status)` covering `git status --short` is what makes a
		// rule usable, and nothing about `git status` is set by a target.
		const set = suggestBashAllowRuleSet("git status --short", cwd)
		expect(set.rules).toEqual(["Bash(git status:*)"])
		expect(behaviourOf("git status --short --branch", set.rules)).toBe("allow")
	})
})

describe("what comes back is a rule, not a sentence", () => {
	// Whatever the producer decides, the string it writes must survive the permissions file: one line,
	// parseable by the rule parser, readable as an argument list by the matcher.
	const ANY = [
		"git status && echo done",
		"echo 'a && b'",
		"find . -name '*.ts'",
		"awk '{print $1}' f.txt",
		"python3 -c 'print(1)'",
		"printf '%s\\n' one two",
		"echo a\\\\b",
		"touch 'weird name.txt'",
		"docker run -v /:/host alpine ls",
		"git commit -m \"it's ok\"",
		"echo '' x",
	]

	for (const command of ANY) {
		it(`${JSON.stringify(command)} parses back to the words it names`, () => {
			const set = suggestBashAllowRuleSet(command, cwd)
			if (!set.persistable) return // withholding is always allowed; the shape test is about what is written
			for (const rule of set.rules) {
				expect(rule.includes("\n"), rule).toBe(false)
				expect(rule.startsWith("Bash("), rule).toBe(true)
				expect(rule).not.toBe("Bash")
				// A generalising rule is `tool sub:*`; its words are the first words of the leg, which is
				// all the matcher needs. An exact rule has to read back as the whole argv.
				const named = wordsNamedBy(rule)
				expect(named, rule).not.toBeNull()
				expect(named!.length, rule).toBeGreaterThan(0)
			}
		})
	}

	it("never writes the tool-wide rule", () => {
		// `Bash` and `Bash(*)` allow every command there is; no approval of one command means them.
		for (const command of ["ls", "echo ''", "*", "echo *"]) {
			const set = suggestBashAllowRuleSet(command, cwd)
			for (const rule of set.rules) {
				expect(rule, command).not.toBe("Bash")
				expect(rule, command).not.toBe("Bash(*)")
			}
		}
	})
})

describe("the producer and the matcher agree about an odd argument list", () => {
	it("spells an empty argument as an argument", () => {
		// `cmd ""` passes one empty argument; dropping it would authorise `cmd` with nothing.
		const set = suggestBashAllowRuleSet("echo '' x", cwd)
		expect(wordsNamedBy(set.rules[0]!)).toEqual(["echo", "", "x"])
		expect(behaviourOf("echo '' x", set.rules)).toBe("allow")
		expect(behaviourOf("echo x", set.rules)).toBe("passthrough")
	})

	it("carries a backslash through the file codec and back", () => {
		const set = suggestBashAllowRuleSet("echo a\\\\b", cwd)
		expect(wordsNamedBy(set.rules[0]!)).toEqual(["echo", "a\\b"])
		expect(behaviourOf("echo a\\\\b", set.rules)).toBe("allow")
	})

	it("describes every leg of a compound, not just the head", () => {
		const set = suggestBashAllowRuleSet("git status && echo done && ls -1", cwd)
		expect(set.rules.length).toBe(3)
		expect(behaviourOf("git status && echo done && ls -1", set.rules)).toBe("allow")
		// and one unapproved extra step still costs a prompt
		expect(behaviourOf("git status && echo done && rm -rf /tmp/x", set.rules)).toBe("passthrough")
	})
})
