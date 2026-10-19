import { describe, expect, it } from "vitest"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import {
	evaluateToolPermission,
	mergePermissionRules,
	rulesFromPermissionsConfig,
	suggestAllowRuleSetForToolCall,
	type PermissionVerdict,
} from "./permissions.ts"

/**
 * The bash ALLOW path, end to end, now that it is layer 0's answer rather than a re-split of the text.
 *
 * Every assertion below states which side of the switch it is on, because both directions are evidence:
 *
 *   - `keeps` pins a behaviour the old private classifier had, so the move costs nothing that mattered;
 *   - `tightening:` shows a command that used to be waved through by a rule and now goes to the gate —
 *     these are the incidents being closed (a substitution, an opaque value, the never floor);
 *   - `loosening:` shows a command a rule now covers that it did not. Each one is a decision recorded in
 *     this suite (wrappers, argv-with-no-assignments, quoting normalised, a rule naming fewer words than
 *     the call), not an accident, and each is guarded by the never floor.
 *
 * `deny` / `ask` are asserted separately at the bottom: they are still textual, and a change that quietly
 * moved them onto argv would break the one thing a denial must do — fire on a construct the walker refuses.
 */

const cwd = "/home/user/project"

function verdict(
	command: string,
	cfg: RuleCfg,
): PermissionVerdict {
	return evaluateToolPermission(
		"bash",
		{ command },
		cwd,
		mergePermissionRules(
			rulesFromPermissionsConfig(
				// The tables are `as const` (so `%j` prints them and a typo is a type error), which makes every
				// list readonly. The config reader wants mutable arrays, so the copy happens once here at the
				// boundary instead of every table giving up its `as const`.
				{
					allow: cfg.allow ? [...cfg.allow] : undefined,
					deny: cfg.deny ? [...cfg.deny] : undefined,
					ask: cfg.ask ? [...cfg.ask] : undefined,
				},
				"project",
			),
		)
	)
}

/** One rule list per behaviour, readonly so an `as const` table can be handed straight in. */
type RuleCfg = { allow?: readonly string[]; deny?: readonly string[]; ask?: readonly string[] }

const behaviorOf = (command: string, cfg: RuleCfg) => verdict(command, cfg).behavior

describe("allow coverage is the walker's legs, one rule per leg", () => {
	it("keeps: a single command covered by its prefix rule", () => {
		expect(behaviorOf("git status", { allow: ["Bash(git status:*)"] })).toBe("allow")
		expect(behaviorOf("npm run test", { allow: ["Bash(npm run:*)"] })).toBe("allow")
		expect(behaviorOf("git status", { allow: ["Bash(git *)"] })).toBe("allow")
	})

	it("keeps: a compound needs every leg covered, and is covered when it has it", () => {
		expect(behaviorOf("git status && echo done", { allow: ["Bash(git status:*)"] })).toBe("passthrough")
		expect(
			behaviorOf("git status && echo done", { allow: ["Bash(git status:*)", "Bash(echo:*)"] }),
		).toBe("allow")
	})

	it("keeps: padding an authorised command with a destructive leg gains nothing", () => {
		expect(behaviorOf("git status && rm -rf /x", { allow: ["Bash(git status:*)"] })).toBe("passthrough")
		expect(behaviorOf("git status && rm -rf /x", { allow: ["Bash(git:*)"] })).toBe("passthrough")
	})

	it("keeps: a pipeline is covered only when both stages are", () => {
		expect(behaviorOf("git log | grep x", { allow: ["Bash(git log:*)"] })).toBe("passthrough")
		expect(
			behaviorOf("git log | grep x", { allow: ["Bash(git log:*)", "Bash(grep:*)"] }),
		).toBe("allow")
	})

	it("keeps: a tool-wide Bash rule reaches every leg of a proven compound", () => {
		expect(behaviorOf("git status && echo done", { allow: ["Bash"] })).toBe("allow")
	})

	it("the rule string that comes back names the leg it covers", () => {
		const v = verdict("git status && echo done", { allow: ["Bash(git status:*)", "Bash(echo done)"] })
		expect(v.behavior).toBe("allow")
		// The prompt/audit text is built from this string, so it must describe both legs.
		expect(v.behavior === "allow" ? v.rule : "").toContain("git status")
		expect(v.behavior === "allow" ? v.rule : "").toContain("echo done")
	})

	it("a compound is covered by the rules the approval dialog writes for it", () => {
		// The round trip: `git status && echo done` used to write one rule for the head clause while
		// coverage needed every clause, so the command asked again forever.
		expect(
			behaviorOf("git status && echo done", { allow: ["Bash(git status:*)", "Bash(echo done)"] }),
		).toBe("allow")
		expect(
			behaviorOf("git status && rm -rf /tmp/x", {
				allow: ["Bash(git status:*)", "Bash(rm -rf /tmp/x)"],
			}),
		).toBe("allow")
		// …and an exact deletion still does not generalise to a different target.
		expect(
			behaviorOf("git status && rm -rf /tmp/y", {
				allow: ["Bash(git status:*)", "Bash(rm -rf /tmp/x)"],
			}),
		).toBe("passthrough")
	})
})

describe("tightening: an unproven or opaque leg gets no rule coverage at all", () => {
	// Wave-2 decision 3: rules may never widen a leg the walker could not prove. The prompt is the only
	// channel that can. This closes the exposure compound-allow-and.test.ts used to pin as intentional.
	const UNPROVEN = [
		["git log $(whoami)", "command-substitution: the argument is decided at run time"],
		["diff <(git show a) <(git show b)", "process-substitution"],
		["echo $(rm -rf /)", "a whole destructive command inside a substitution"],
		["git status && echo $(rm -rf /tmp/x)", "one proven leg does not carry the compound"],
		["for f in a b; do rm -f $f; done", "loop-body: how many times does the body run?"],
	] as const

	it.each(UNPROVEN)("%s goes to the gate even with a rule for it", (command) => {
		expect(behaviorOf(command, { allow: ["Bash"] })).toBe("passthrough")
	})

	it("a substitution feeding a commit message is not covered by a rule for the commit", () => {
		expect(
			behaviorOf('FOO=$(git rev-parse x) && git commit -m "$FOO"', {
				allow: ["Bash(git commit:*)", "Bash(git rev-parse:*)"],
			}),
		).toBe("passthrough")
	})

	it("an opaque value (a placeholder wearing a literal) is not covered", () => {
		// The walker emits `cat __TRACKED_VAR__/x`; `Bash(cat:*)` cannot vouch for what $HOME resolves to.
		expect(behaviorOf('cat "$HOME/x"', { allow: ["Bash(cat:*)"] })).toBe("passthrough")
		expect(behaviorOf("cat ./notes.txt", { allow: ["Bash(cat:*)"] })).toBe("allow")
	})

	it("a redirect with no command runs nothing, so no rule speaks for the write", () => {
		// Layer 0 emits an empty argv for `> f`; it is still a write and the gate classifies it.
		expect(behaviorOf("> /tmp/x", { allow: ["Bash"] })).toBe("passthrough")
	})
})

describe("tightening: the never floor — a rule may not launder severity", () => {
	const NEVER = [
		["rm -rf /", ["Bash(rm:*)"]],
		["rm -rf /", ["Bash(rm -rf /*)"]],
		["sudo rm -rf /", ["Bash(rm:*)"]],
		["sudo rm -rf /", ["Bash(sudo rm:*)"]],
		["sudo -u root rm -rf /", ["Bash(rm:*)"]],
		["timeout 5 rm -rf /", ["Bash(rm:*)"]],
		["env -i /bin/rm -rf /", ["Bash(rm:*)"]],
		["chmod -R 777 /", ["Bash(chmod:*)"]],
		["dd if=/dev/zero of=/dev/sda", ["Bash(dd:*)"]],
		["rm -rf ~/.bash_history", ["Bash(rm:*)"]],
		["echo key >> ~/.ssh/authorized_keys", ["Bash(echo key:*)"]],
		["git status && rm -rf /", ["Bash(git status:*)", "Bash(rm:*)"]],
	] as const

	it.each(NEVER)("%s is never allowed by %j however well it matches", (command, allow) => {
		// The floor is layer 0's verdict on the command — computed on the WRAPPED argv, because the tier
		// tables peel these wrappers themselves and keep `never` `never` through sudo (§2.2). So the
		// "inner argv too" half of wave-2 decision 1 needs no second check here.
		expect(behaviorOf(command, { allow })).toBe("passthrough")
	})

	it("a never floor on one leg withholds the whole compound", () => {
		expect(
			behaviorOf("git status && dd if=/dev/zero of=/dev/sda", {
				allow: ["Bash(git status:*)", "Bash(dd:*)"],
			}),
		).toBe("passthrough")
	})

	it("an ask-tier deletion is still coverable — the floor is only the never tier", () => {
		// `rm -rf /tmp/x` is ask (delete_recursive), not never: a user who allowed exactly that path
		// must not be asked again, or the rule is a lie.
		expect(behaviorOf("rm -rf /tmp/x", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("allow")
	})
})

describe("wrappers: the six the decision names, and nothing else", () => {
	it.each([
		"env FOO=1 git status",
		"sudo git status",
		"timeout 5 git status",
		"nice -n 5 git status",
		"nohup git status",
		"time git status",
		"time -p git status",
	])("loosening: %s is covered by a rule for the command it runs", (command) => {
		// Wave-2 decision 1, accepted as a loosening: `Bash(git status:*)` now speaks for the wrapped
		// form. Guarded by the never floor above, so `sudo rm -rf /` is still out of reach.
		expect(behaviorOf(command, { allow: ["Bash(git status:*)"] })).toBe("allow")
	})

	it("a stack of them is peeled to the command", () => {
		expect(behaviorOf("sudo env FOO=1 git status", { allow: ["Bash(git status:*)"] })).toBe("allow")
	})

	it.each([
		"stdbuf -oL git status",
		"setsid git status",
		"ionice -c3 git status",
		"unbuffer git status",
		"chrt 5 git status",
	])("%s is NOT seen through — it is not on the list", (command) => {
		expect(behaviorOf(command, { allow: ["Bash(git status:*)"] })).toBe("passthrough")
	})

	it("a wrapper option we do not model ends the peel instead of guessing", () => {
		// `timeout --kill-after 5 …`: where the command starts is not decidable from an unknown option,
		// so there is no inner argv and the rule covers nothing.
		expect(behaviorOf("timeout --kill-after 5 git status", { allow: ["Bash(git status:*)"] })).toBe(
			"passthrough",
		)
	})

	it("a durationless timeout has no command to find", () => {
		expect(behaviorOf("timeout git status", { allow: ["Bash(git status:*)"] })).toBe("passthrough")
	})

	it("tightening: xargs is no longer seen through", () => {
		// The text matcher let `git status:*` cover `xargs git status …`, whose arguments arrive from a
		// pipe at run time — one of the reasons dangerous-permissions.ts lists xargs as a broad grant.
		expect(behaviorOf("xargs git status", { allow: ["Bash(git status:*)"] })).toBe("passthrough")
		expect(behaviorOf("xargs git status", { allow: ["Bash(xargs:*)"] })).toBe("allow")
	})
})

describe("the environment a command runs with", () => {
	it.each([
		["FOO=1 git status", ["Bash(git status:*)"]],
		["NODE_ENV=test npm test", ["Bash(npm test:*)"]],
		["LC_ALL=C sort notes.txt", ["Bash(sort:*)"]],
		["TZ=UTC git status", ["Bash(git status:*)"]],
	] as const)("loosening: a cosmetic `NAME=value` prefix is invisible to argv, so %s is covered", (command, allow) => {
		// The walker separates assignments from argv (spec §3.1), and bash-rule-argv.ts states that this
		// makes a prefix invisible for free. Refusing it would break the round trip: the rule an approval
		// writes names the command, not the prefix.
		expect(behaviorOf(command, { allow: [...allow] })).toBe("allow")
	})

	it.each([
		"LD_PRELOAD=/tmp/e.so git status",
		"env LD_PRELOAD=/tmp/e.so git status",
		"NODE_OPTIONS=--require /tmp/x.js node app.js",
		"GIT_SSH_COMMAND=nc git push origin",
		"PATH=/tmp/bin git status",
		"BASH_ENV=/tmp/rc git status",
		"PERMISSION_MODES_INHERITED_MODE=auto git status",
	])("no rule covers %s — the prefix changes what executes", (command) => {
		// The old path refused these only because its assignment scanner left an unknown name attached to
		// the command. With assignments out of argv the refusal has to be stated, and it is.
		expect(behaviorOf(command, { allow: ["Bash(git status:*)", "Bash(git push:*)", "Bash(node:*)"] })).toBe(
			"passthrough",
		)
	})

	it("an exact rule written with its assignment still covers the same command", () => {
		// Rules persisted before argv matching named the prefix (`Bash(FOO=1 echo hi)`); an approval must
		// keep meaning what it said instead of prompting forever.
		expect(behaviorOf("FOO=1 echo hi", { allow: ["Bash(FOO=1 echo hi)"] })).toBe("allow")
	})
})

describe("argv matching, at the rule boundary", () => {
	it("loosening: a rule naming fewer words than the call covers it (the one documented loosening)", () => {
		expect(behaviorOf("bash x.sh arg", { allow: ["Bash(bash x.sh)"] })).toBe("allow")
		expect(behaviorOf("git status --short", { allow: ["Bash(git status)"] })).toBe("allow")
		// …one way only: a word the call does not have still covers nothing.
		expect(behaviorOf("bash other.sh", { allow: ["Bash(bash x.sh)"] })).toBe("passthrough")
	})

	it("loosening: quoting is resolved on both sides", () => {
		expect(behaviorOf("git commit -m 'fix wip'", { allow: ['Bash(git commit -m "fix wip")'] })).toBe(
			"allow",
		)
	})

	it("tightening: an exact-looking destructive rule is now exactly that", () => {
		// W3 flagged this for the supervisor and pinned it the other way; W8 flips it, deliberately, on the
		// argv probe quoted below (measured 2026-10-14). Before this change the same
		// probe read:
		//
		//   allow       Bash(rm -rf /tmp/x)   <= rm -rf /tmp/x
		//   allow       Bash(rm -rf /tmp/x)   <= rm -rf /tmp/x extra      <-- one more target, free
		//   allow       Bash(rm -rf /tmp/x)   <= rm -rf /tmp/x /tmp/z     <-- a DIFFERENT second target
		//   allow       Bash(rm -rf /tmp/x)   <= rm -rf /tmp/x --verbose  <-- even an added flag
		//   passthrough Bash(rm -rf /tmp/x)   <= rm -rf /tmp/xy
		//   allow       Bash(git status)      <= git status --short       <-- still correct, and still true
		//
		// The middle three were a privilege escalation the moment "Allow always" persisted the rule: one
		// click on a scratch path authorised deleting any path that is not a wipe-protected root (the never
		// floor does not help — `rm -rf /tmp/x /home/u/dev/pm` is ordinary delete_recursive). Where layer 0
		// says the risk IS the targets, `Bash(rm -rf /tmp/x)` now covers that invocation and nothing else.
		// The last row is the boundary: a command whose risk is not set by its targets keeps W2's contract.
		expect(behaviorOf("rm -rf /tmp/x extra", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("passthrough")
		expect(behaviorOf("rm -rf /tmp/y", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("passthrough")
		expect(behaviorOf("rm -rf /tmp/x", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("allow")
	})

	it("a rule the user wrote as a wildcard still means what they typed", () => {
		// Strict operands narrow a specifier that stops mid-invocation, not one that says "anything".
		// `Bash(rm *)` and `Bash(rm:*)` are breadth the user typed themselves — and an "Allow always" click
		// never writes a glob (suggestBashAllowRuleSet writes an exact rule for a destructive verb), so the
		// breadth left here is theirs, not a click's. `compound-allow-and.test.ts` pins the same reading.
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", { allow: ["Bash(rm *)"] })).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", { allow: ["Bash(rm:*)"] })).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", { allow: ["Bash(rm -rf /*)"] })).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", { allow: ["Bash"] })).toBe("allow")
	})

	it("a specifier that is not one argument list covers nothing", () => {
		// `Bash(a && b)` describes no argv; failing closed costs one prompt.
		expect(behaviorOf("git status", { allow: ["Bash(git status && git log)"] })).toBe("passthrough")
		expect(behaviorOf("git status", { allow: ["Bash(git status > out.txt)"] })).toBe("passthrough")
	})
})

describe("strict operands: for a target-bearing command an exact rule means THIS target", () => {
	// W8. Where layer 0 says the command's risk is the paths its operands name (`STRICT_OPERAND_CATEGORIES`
	// in `bash-audit.ts`), an exact specifier must name every word the call passes — options included. The
	// asymmetry is the point: `deny`/`ask` stay textual and broad below, because a denial has to keep firing
	// when the command adds words. Every row here was measured, not reasoned about.

	it("tightening: one extra word — a second target or a flag — is no longer covered", () => {
		// [the call, the exact rule that was written for a shorter invocation of the same command]
		const EXTRA = [
			["rm -rf /tmp/x extra", "Bash(rm -rf /tmp/x)"],
			["rm -rf /tmp/x /tmp/z", "Bash(rm -rf /tmp/x)"],
			["rm -rf /tmp/x --verbose", "Bash(rm -rf /tmp/x)"],
			["rm -rf node_modules --force", "Bash(rm -rf node_modules)"],
			["chmod -R 777 /tmp/x --no-preserve-root", "Bash(chmod -R 777 /tmp/x)"],
			["mv /tmp/a /tmp/b /dest", "Bash(mv /tmp/a /tmp/b)"],
			["git reset --hard HEAD~1", "Bash(git reset --hard)"],
			["cat ~/.ssh/id_rsa ~/.ssh/id_ed25519", "Bash(cat ~/.ssh/id_rsa)"],
			["chown -R www-data /etc/x /etc/y", "Bash(chown -R www-data /etc/x)"],
			["rsync -a ./out /srv/exports --delete", "Bash(rsync -a ./out /srv/exports)"],
			["find . -name x -delete -xdev", "Bash(find . -name x -delete)"],
			["rm -rf ./build ../outside", "Bash(rm -rf ./build)"],
		]
		for (const [call, rule] of EXTRA) {
			expect(behaviorOf(call, { allow: [rule] }), `${call} ← ${rule}`).toBe("passthrough")
		}
	})

	it("an allow-tier target stays prefix-covered, because strictness there would buy no decision", () => {
		// The boundary of the category table, written down rather than discovered later: `write_project`,
		// `read_only`, `run_project_code` are tier `allow`, so a rule that stops covering them changes
		// nothing about the outcome — the gate lets the command through either way — and the prompt would be
		// paid for nothing. If a category ever moves from allow to ask, this row is the one to revisit.
		expect(behaviorOf("cp ./a.txt ./b.txt ./c.txt", { allow: ["Bash(cp ./a.txt ./b.txt)"] })).toBe("allow")
		expect(behaviorOf("dd if=/dev/zero of=/tmp/x bs=1M", { allow: ["Bash(dd if=/dev/zero of=/tmp/x)"] })).toBe(
			"allow",
		)
		expect(behaviorOf("truncate -s 0 a.log b.log", { allow: ["Bash(truncate -s 0 a.log)"] })).toBe("allow")
	})

	it("the invocation the rule names is still covered — the rule is exact, not dead", () => {
		expect(behaviorOf("rm -rf /tmp/x", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("allow")
		expect(behaviorOf("chmod -R 777 /tmp/x", { allow: ["Bash(chmod -R 777 /tmp/x)"] })).toBe("allow")
		expect(behaviorOf("cat ~/.ssh/id_rsa", { allow: ["Bash(cat ~/.ssh/id_rsa)"] })).toBe("allow")
	})

	it("a rule naming two targets covers the call naming the same two, and nothing beyond them", () => {
		expect(behaviorOf("rm -rf /tmp/x /tmp/z", { allow: ["Bash(rm -rf /tmp/x /tmp/z)"] })).toBe("allow")
		expect(behaviorOf("rm -rf /tmp/x /tmp/z /tmp/w", { allow: ["Bash(rm -rf /tmp/x /tmp/z)"] })).toBe(
			"passthrough",
		)
		// …and the order the user approved is the order that is covered: `mv` names a source and a
		// destination, so a rule is not free to stand for the same two paths the other way round.
		expect(behaviorOf("mv /tmp/a /tmp/b", { allow: ["Bash(mv /tmp/a /tmp/b)"] })).toBe("allow")
		expect(behaviorOf("mv /tmp/b /tmp/a", { allow: ["Bash(mv /tmp/a /tmp/b)"] })).toBe("passthrough")
	})

	it("quoting resolved on both sides still makes one invocation of it", () => {
		expect(behaviorOf('rm -rf "/tmp/a dir"', { allow: ["Bash(rm -rf '/tmp/a dir')"] })).toBe("allow")
		expect(behaviorOf('rm -rf "/tmp/a dir" /tmp/z', { allow: ["Bash(rm -rf '/tmp/a dir')"] })).toBe(
			"passthrough",
		)
	})

	it("a target-bearing command behind a wrapper is strict on the inner argv", () => {
		// The never floor is not what stops `sudo rm -rf /tmp/x /tmp/z` here — that pair is `privilege`/ask,
		// not `never` — so strictness has to reach the wrapper-stripped spelling too.
		expect(behaviorOf("sudo rm -rf /tmp/x", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("allow")
		expect(behaviorOf("sudo rm -rf /tmp/x /tmp/z", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("passthrough")
		expect(behaviorOf("timeout 5 rm -rf /tmp/x --force", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe(
			"passthrough",
		)
		// A rule that spells the wrapper names the wrapped form exactly, and that is honoured.
		expect(behaviorOf("sudo rm -rf /tmp/x", { allow: ["Bash(sudo rm -rf /tmp/x)"] })).toBe("allow")
	})

	it("an assignment prefix keeps both spellings honest", () => {
		expect(behaviorOf("FOO=1 rm -rf /tmp/x", { allow: ["Bash(FOO=1 rm -rf /tmp/x)"] })).toBe("allow")
		expect(behaviorOf("FOO=1 rm -rf /tmp/x", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("allow")
		expect(behaviorOf("FOO=1 rm -rf /tmp/x extra", { allow: ["Bash(rm -rf /tmp/x)"] })).toBe("passthrough")
		expect(behaviorOf("FOO=1 rm -rf /tmp/x extra", { allow: ["Bash(FOO=1 rm -rf /tmp/x)"] })).toBe(
			"passthrough",
		)
	})

	it("the never floor is still the floor when the rule is a perfect match", () => {
		// W3's 12-row table re-run with rules that name the command exactly: strict operands did not make
		// these covered, and the floor still withholds them (two independent reasons now, both fail closed).
		for (const [command, rule] of [
			["rm -rf /", "Bash(rm -rf /)"],
			["sudo rm -rf /", "Bash(sudo rm -rf /)"],
			["timeout 5 rm -rf /", "Bash(rm -rf /)"],
			["chmod -R 777 /", "Bash(chmod -R 777 /)"],
			["dd if=/dev/zero of=/dev/sda", "Bash(dd if=/dev/zero of=/dev/sda)"],
			["rm -rf ~/.bash_history", "Bash(rm -rf ~/.bash_history)"],
			["echo key >> ~/.ssh/authorized_keys", "Bash(echo key)"],
			["git status && dd if=/dev/zero of=/dev/sda", "Bash(dd if=/dev/zero of=/dev/sda)"],
		] as const) {
			expect(behaviorOf(command, { allow: [rule] }), `${command} ← ${rule}`).toBe("passthrough")
		}
	})

	it("a compound pays the same strictness on its innocent leg — and that is the fail-closed direction", () => {
		// The verdict is per command, not per leg: a verdict row is not labelled with the leg it came from
		// (`SegmentDecision.command` is display text like "cp to b"), and guessing at that mapping would
		// fail by leaving a target-bearing leg UNMARKED. Cost: this prompt. It can never cost authority.
		expect(
			behaviorOf("git status --short && rm -rf ./build", {
				allow: ["Bash(git status)", "Bash(rm -rf ./build)"],
			}),
		).toBe("passthrough")
		// A `:*` rule on the innocent leg is unaffected, which is why the cost is small in practice.
		expect(
			behaviorOf("git status --short && rm -rf ./build", {
				allow: ["Bash(git status:*)", "Bash(rm -rf ./build)"],
			}),
		).toBe("allow")
	})
})

describe("deny and ask stay textual", () => {
	it("deny beats allow, on any leg", () => {
		expect(
			behaviorOf("git status && rm -rf /x", {
				allow: ["Bash(git status:*)", "Bash(rm:*)"],
				deny: ["Bash(rm *)"],
			}),
		).toBe("deny")
	})

	it("ask forces a prompt despite full allow coverage", () => {
		expect(
			behaviorOf("git status && echo done", {
				allow: ["Bash(git status:*)", "Bash(echo:*)"],
				ask: ["Bash(git status:*)"],
			}),
		).toBe("ask")
	})

	it("a deny still fires on a command layer 0 refuses to analyse", () => {
		// THE reason deny is not on argv: this command has no argv at all (`runtime-only-argument`), yet the
		// rule that names the commit leg must still stop it.
		expect(
			behaviorOf('FOO=$(git rev-parse x) && git commit -m "$FOO"', { deny: ["Bash(git commit *)"] }),
		).toBe("deny")
		expect(behaviorOf("rm -rf /", { deny: ["Bash(rm *)"] })).toBe("deny")
	})

	it.each([
		["rm -rf /tmp/x extra", "rm"],
		["rm -rf /tmp/x /tmp/z", "rm"],
		["rm -rf /tmp/x --verbose", "rm"],
		["chmod -R 777 /tmp/x /tmp/z", "chmod"],
		["chmod -R 777 /tmp/x --verbose", "chmod"],
	])("tightening an allow does not narrow a deny: %s is still denied", (command, verb) => {
		// The asymmetry W8 exists to keep. `deny`/`ask` are scored by the text engine, before any argv
		// exists, so a rule that names a verb still covers words the rule never named — and the order
		// deny → ask → allow means a stricter allow can only move a command from "a rule answered for it"
		// to "the gate decides", never out of a denial's reach.
		for (const deny of [`${verb} *`, `${verb}:*`]) {
			expect(behaviorOf(command, { deny: [`Bash(${deny})`] }), `${command} ← deny ${deny}`).toBe("deny")
			// …with the now-stricter exact allow present as well, which is the case that could have regressed.
			expect(
				behaviorOf(command, {
					allow: ["Bash(rm -rf /tmp/x)", "Bash(chmod -R 777 /tmp/x)"],
					deny: [`Bash(${deny})`],
				}),
				`${command} ← deny ${deny} + strict allow`,
			).toBe("deny")
		}
	})

	it.each(["rm -rf /tmp/x extra", "rm -rf /tmp/x /tmp/z", "git reset --hard HEAD~1"])(
		"an ask rule still asks when the call adds words: %s",
		(command) => {
			expect(behaviorOf(command, { ask: ["Bash(rm:*)", "Bash(git reset:*)"] }), command).toBe("ask")
		},
	)

	it("a loop body is left to the gate, exactly as it was", () => {
		// Pinned so nobody reads argv matching into the deny path: `splitShellSegments` cuts on `;`, so the
		// body arrives as `do rm -f $f` and a `rm *` rule cannot reach it. That gap is the gate's to close
		// (layer 0 refuses the loop `loop-body`), not something this task widens in either direction.
		expect(behaviorOf("for f in a b; do rm -f $f; done", { deny: ["Bash(rm *)"] })).toBe("passthrough")
	})

	it("a deny covers a command with a leading assignment, as it did before", () => {
		expect(behaviorOf("FOO=bar rm x", { deny: ["Bash(rm *)"] })).toBe("deny")
	})

	it("an unproven command with no matching deny still reaches the gate", () => {
		expect(behaviorOf("for f in a b; do rm -f $f; done", { allow: ["Bash(rm:*)"] })).toBe("passthrough")
	})
})

describe("the path tools are untouched by the bash switch", () => {
	const denies = mergePermissionRules(
		rulesFromPermissionsConfig({ deny: ["Read(~/.ssh/id_rsa)", "Bash(git status:*)"] }, "project"),
	)
	const allows = mergePermissionRules(rulesFromPermissionsConfig({ allow: ["Edit(./src/**)"] }, "project"))

	it("a Read deny on a secret path fires (and a bash rule is never consulted for it)", () => {
		// Exact spelling on purpose: a `**` rule can never match a secret — the asymmetry every other
		// suite pins. The point here is only that the bash rewrite did not reach this path.
		expect(evaluateToolPermission("read", { path: "~/.ssh/id_rsa" }, cwd, denies).behavior).toBe("deny")
	})

	it("an Edit allow inside the project fires", () => {
		expect(evaluateToolPermission("edit", { path: "src/a/b.ts" }, cwd, allows).behavior).toBe("allow")
	})

	it("a bash rule is never consulted for another tool", () => {
		const bashOnly = rulesFromPermissionsConfig({ allow: ["Bash(git status:*)"] }, "project")
		expect(evaluateToolPermission("edit", { path: "src/a.ts" }, cwd, bashOnly).behavior).toBe(
			"passthrough",
		)
	})
})

describe("an always-allow offer is only made when it will be honoured", () => {
	// The dialog shows "Always-allow would write: …" before the choice and omits the option when the set
	// is not persistable — an offer that stores a rule which never fires is worse than no offer (the
	// principle index.ts already applies to run-time values and control flow). The rules are still
	// derived from the command text by the suggestion engine, so what is checked here is the round trip:
	// write them, read them back through the matcher, and withhold them if the command they were written
	// from is not covered by them.
	const offered = (command: string) => suggestAllowRuleSetForToolCall("bash", { command }, cwd)

	it("a proven compound keeps its offer, and the offer covers the command", () => {
		const set = offered("git status && echo done")
		expect(set.persistable).toBe(true)
		expect(set.rules).toEqual(["Bash(git status:*)", "Bash(echo done)"])
		expect(behaviorOf("git status && echo done", { allow: set.rules })).toBe("allow")
	})

	it.each([
		["rm -rf /", "never floor: coverage refuses it, so a rule would only hide the reason"],
		["git push --force origin main", "same, for a force push"],
		["cat <<'EOF'\n{\"a\": 1}\nEOF", "a here-document body is data on the leg, never argv"],
		["git log $(whoami)", "an unproven command has no argv to authorise"],
		['cat "$HOME/x"', "an opaque value cannot be covered by a rule"],
	])("withheld: %s — %s", (command) => {
		const set = offered(command)
		expect(set.persistable, command).toBe(false)
		expect(set.rules, command).toEqual([])
		// Some refusal is always explained: the dialog prints it, and silence reads as a bug.
		expect(set.reason, command).toBeTruthy()
	})

	it("offers a redirecting command once the rule can name the file, and honours it", () => {
		// W3 withheld `echo hi > /tmp/out.txt` because the only rule that would cover it was `Bash(echo hi)`,
		// which covers `echo hi > anywhere`. A specifier can name the target now, so the offer exists — and the
		// round trip below is what makes that legal rather than a guess: the producer wrote the rule, this
		// file's own matcher says it covers exactly the command that was approved.
		const set = offered("echo hi > /tmp/out.txt")
		expect(set.persistable, set.reason ?? "").toBe(true)
		expect(set.rules).toEqual(["Bash(echo hi > /tmp/out.txt)"])
		expect(behaviorOf("echo hi > /tmp/out.txt", { allow: set.rules })).toBe("allow")
		// `loosening:` the one class this task recovers, stated as the pin it replaced.
		expect(behaviorOf("echo hi > /tmp/out.txt", { allow: ["Bash(echo hi > /tmp/out.txt)"] })).toBe("allow")
		// …and the direction that keeps it a narrowing rather than a widening: every spelling that names no
		// target stops covering it. `Bash(echo:*)` covered this command BEFORE this task (argv alone matched);
		// it does not now, which is the same over-grant the suggestion engine already refuses to write.
		for (const rule of ["Bash(echo hi)", "Bash(echo:*)", "Bash(echo *)", "Bash(echo hi > /tmp/other.txt)", "Bash(echo hi >> /tmp/out.txt)"]) {
			expect(behaviorOf("echo hi > /tmp/out.txt", { allow: [rule] }), rule).toBe("passthrough")
		}
		// The floor still outranks a rule that names the target exactly.
		expect(behaviorOf("echo hi > ~/.ssh/authorized_keys", { allow: ["Bash(echo hi > ~/.ssh/authorized_keys)"] })).toBe(
			"passthrough",
		)
	})

	it.each(["rm -rf /", "cat <<'EOF'\n{\"a\": 1}\nEOF"])(
		"the refusal for %s says the round trip is what failed", (command) => {
			// These reach the new check (the suggestion engine's own bails fire earlier on a
			// substitution or control flow), and the user is told WHY the offer disappeared.
			expect(offered(command).reason).toContain("no rule would cover this command again")
		},
	)

	it("the invariant over the curated corpus: an offer that is made is an offer that covers", () => {
		const lines = readFileSync(join(import.meta.dirname, "testcases", "cases-v2.jsonl"), "utf8")
			.concat(readFileSync(join(import.meta.dirname, "testcases", "cases-ledger.jsonl"), "utf8"))
			.split("\n")
		let checked = 0
		for (const line of lines) {
			if (!line.trim()) continue
			const command = JSON.parse(line)?.input?.command
			if (typeof command !== "string" || !command.trim()) continue
			const set = suggestAllowRuleSetForToolCall("bash", { command }, cwd)
			if (!set.persistable) continue
			checked++
			expect(behaviorOf(command, { allow: set.rules }), command).toBe("allow")
		}
		// A vacuous pass would be the failure mode of every property test like this one.
		expect(checked).toBeGreaterThan(10)
	})
})

describe("the duplicate stays deleted", () => {
	// A guard, not a behaviour test. This module used to carry its own segmentation and its own
	// run-time-value regex; the whole point of the move is that it cannot quietly grow them back.
	const source = readFileSync(join(import.meta.dirname, "permissions.ts"), "utf8")

	it("permissions.ts does not split a command itself", () => {
		expect(source).not.toContain("splitShellSegments")
		// The scanner it used to live behind is not imported any more either.
		expect(source).not.toMatch(/from "\.\/utils\.ts"/)
	})

	it("permissions.ts does not re-derive 'contains a run-time value' from text", () => {
		expect(source).not.toContain("CONTAINS_RUNTIME_VALUE")
		expect(source).not.toContain("stripSafeWrappers")
		expect(source).not.toContain("stripOutputRedirections")
		expect(source).not.toContain("stripAllLeadingEnvVars")
	})

	it("permissions.ts asks layer 0 and the argv matcher", () => {
		expect(source).toContain("bashRuleView")
		expect(source).toContain("bashRuleCoversArgv")
	})

	it("permissions.ts takes one verdict per command, not one per question", () => {
		// W8 needs the verdict's CATEGORY to decide whether a rule may extend. Asking for it next to the
		// never-floor check would analyse every bash call twice on the hottest path in the extension, so the
		// severity floor and the strictness flag have to arrive on the same view — and this file may not grow
		// its own opinion about either.
		expect(source).not.toContain("hitsNeverFloor")
		expect(source).not.toContain("evaluateBash")
		expect(source).not.toContain("risk-policy")
	})
})
