/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */
import { describe, expect, it } from "vitest"
import { readFileSync } from "node:fs"
import path from "node:path"
import { CMDSUB_PLACEHOLDER, TRACKED_VAR_PLACEHOLDER, type Slot, type TemplateCommand } from "./bash-ast.ts"
import { evaluateBash } from "./risk-policy.ts"
import {
	COMMAND_WORD_FAMILIES,
	OBJECT_PROBE_CLASSES,
	PROBE_CLASSES,
	probePlan,
	probeSlots,
	writeFlagShapes,
	type SlotSpace,
} from "./slot-probe.ts"

/**
 * The slot probe, pinned.
 *
 * Every fixture is a `TemplateCommand` built by hand (`template()`): the walker's placeholder text in argv and
 * a span in `text`, exactly the shape `parseBashTemplate` produces. Nothing here depends on that
 * parser.
 *
 * The last two blocks are a self-check. `risk-handlers.ts` cannot export its word tables, so
 * the test reads the file and enumerates them mechanically, and a pinned count makes a NEW table fail the suite
 * with instructions instead of silently widening what a stored slot rule can cover.
 */

const SPACE: SlotSpace = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

type SlotSpec = {
	argIndex: number
	quoted: boolean
	whole: boolean
	/** The expansion exactly as written in `text`, e.g. `$F` or `$(date)`. */
	at: string
	source?: "var" | "cmdsub"
	name?: string
	inner?: string
	/** Added to the span, to build the whole-command convention (spans offset by `start`). */
	shift?: number
}

/** A TemplateCommand built by hand: the walker's placeholder in argv, slots with spans into `text`. */
function template(text: string, argv: string[], specs: SlotSpec[], start = 0): TemplateCommand {
	const slots: Slot[] = specs.map((spec) => {
		const index = text.indexOf(spec.at)
		if (index < 0) throw new Error(`fixture: ${spec.at} not in ${JSON.stringify(text)}`)
		const from = index + (spec.shift ?? 0)
		const span: [number, number] = [from, from + spec.at.length]
		return {
			argIndex: spec.argIndex,
			quoted: spec.quoted,
			whole: spec.whole,
			source: spec.source ?? "var",
			...(spec.name ? { name: spec.name } : {}),
			...(spec.inner ? { inner: spec.inner } : {}),
			span,
		}
	})
	return {
		argv,
		envVars: [],
		redirects: [],
		heredocs: [],
		text,
		start,
		end: start + text.length,
		connector: "",
		opaque: true,
		slots,
	}
}

const V = TRACKED_VAR_PLACEHOLDER
const C = CMDSUB_PLACEHOLDER

const oneSlot = (text: string, argv: string[], spec: SlotSpec): TemplateCommand => template(text, argv, [spec])

// ------------------------------------------------------------------ inert

describe("inert: no probe value changes the verdict", () => {
	const inert: Array<{ name: string; cmd: () => TemplateCommand }> = [
		{
			name: `echo "exit $X" — the value is printed, and echo opens nothing`,
			cmd: () => oneSlot(`echo "exit $X"`, ["echo", `exit ${V}`], { argIndex: 1, quoted: true, whole: false, at: "$X", name: "X" }),
		},
		{
			name: `printf '%s\\n' "$X" — same, and the format is a literal`,
			cmd: () => oneSlot(`printf '%s\\n' "$X"`, ["printf", "%s\\n", V], { argIndex: 2, quoted: true, whole: true, at: "$X", name: "X" }),
		},
		{
			name: `grep -n "$P" src/ — the slot is the pattern, not a file`,
			cmd: () => oneSlot(`grep -n "$P" src/`, ["grep", "-n", V, "src/"], { argIndex: 2, quoted: true, whole: true, at: "$P", name: "P" }),
		},
		{
			name: `git show "$X" — a read of the project repository whatever the ref is`,
			cmd: () => oneSlot(`git show "$X"`, ["git", "show", V], { argIndex: 2, quoted: true, whole: true, at: "$X", name: "X" }),
		},
		{
			name: `printf '%s\\n' "$(date)" — a substitution in an argument is the same case as a variable`,
			cmd: () =>
				oneSlot(`printf '%s\\n' "$(date)"`, ["printf", "%s\\n", C], {
					argIndex: 2,
					quoted: true,
					whole: true,
					at: "$(date)",
					source: "cmdsub",
					inner: "date",
				}),
		},
		{
			name: `echo $X — an unquoted value is allowed where the words are data`,
			cmd: () => oneSlot(`echo $X`, ["echo", V], { argIndex: 1, quoted: false, whole: true, at: "$X", name: "X" }),
		},
	]
	for (const c of inert) {
		it(c.name, () => {
			expect(probeSlots(c.cmd(), SPACE)).toEqual({ inert: true })
		})
	}
})

// ------------------------------------------------------------------ not inert

describe("not inert: a probe value changes the verdict, and the sentence says which", () => {
	const cases: Array<{ name: string; cmd: () => TemplateCommand; slotText: string; wants: RegExp }> = [
		{
			name: "wc of a secret file",
			cmd: () => oneSlot(`wc -l "$F"`, ["wc", "-l", V], { argIndex: 2, quoted: true, whole: true, at: "$F", name: "F" }),
			slotText: "$F",
			wants: /secret-bearing file/,
		},
		{
			name: "rm of a path outside the project",
			cmd: () => oneSlot(`rm "$X"`, ["rm", V], { argIndex: 1, quoted: true, whole: true, at: "$X", name: "X" }),
			slotText: "$X",
			wants: /outside the project/,
		},
		{
			name: "sort writing a file through -o",
			cmd: () => oneSlot(`sort "$X"`, ["sort", V], { argIndex: 1, quoted: true, whole: true, at: "$X", name: "X" }),
			slotText: "$X",
			wants: /output flag/,
		},
		{
			name: "cat of a secret file",
			cmd: () => oneSlot(`cat "$F"`, ["cat", V], { argIndex: 1, quoted: true, whole: true, at: "$F", name: "F" }),
			slotText: "$F",
			wants: /secret-bearing file/,
		},
		{
			name: "a run-time value inside a word, in front of a secret name",
			cmd: () => oneSlot(`cat "logs/$F"`, ["cat", `logs/${V}`], { argIndex: 1, quoted: true, whole: false, at: "$F", name: "F" }),
			slotText: "$F",
			wants: /could be/,
		},
	]
	for (const c of cases) {
		it(c.name, () => {
			const verdict = probeSlots(c.cmd(), SPACE)
			expect(verdict.inert).toBe(false)
			if (verdict.inert) return
			expect(verdict.reason).toContain(c.slotText)
			expect(verdict.reason).toMatch(c.wants)
			expect(verdict.reason).toMatch(/ instead of /)
		})
	}
})

// ------------------------------------------------------------------ refusals

describe("refused before probing: a word position decides the verdict", () => {
	it(`gcloud compute instances "$A" vm1 — a subcommand word`, () => {
		const cmd = template(`gcloud compute instances "$A" vm1`, ["gcloud", "compute", "instances", V, "vm1"], [
			{ argIndex: 3, quoted: true, whole: true, at: "$A", name: "A" },
		])
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) {
			expect(verdict.reason).toContain("$A")
			expect(verdict.reason).toContain("command words")
			expect(verdict.slot.argIndex).toBe(3)
		}
	})

	it(`git "$SUB" — the subcommand itself`, () => {
		const cmd = oneSlot(`git "$SUB"`, ["git", V], { argIndex: 1, quoted: true, whole: true, at: "$SUB", name: "SUB" })
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("command words")
	})

	it("cat $F — an unquoted value", () => {
		const cmd = oneSlot(`cat $F`, ["cat", V], { argIndex: 1, quoted: false, whole: true, at: "$F", name: "F" })
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("unquoted")
	})

	it("the command behind a wrapper (timeout 5 $CMD)", () => {
		const cmd = oneSlot(`timeout 5 "$CMD"`, ["timeout", "5", V], { argIndex: 2, quoted: true, whole: true, at: "$CMD", name: "CMD" })
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("command words")
	})

	it("command position is never inert", () => {
		const cmd = template(`"$CMD" arg`, [V, "arg"], [{ argIndex: 0, quoted: true, whole: true, at: "$CMD", name: "CMD" }])
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("command position")
	})
})

describe("the whole command decides", () => {
	it("one inert slot and one that is not: the bad one is named", () => {
		const cmd = template(`grep -n "$P" "$F"`, ["grep", "-n", V, V], [
			{ argIndex: 2, quoted: true, whole: true, at: "$P", name: "P" },
			{ argIndex: 3, quoted: true, whole: true, at: "$F", name: "F" },
		])
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) {
			expect(verdict.reason).toContain("$F")
			expect(verdict.reason).not.toContain("$P")
			expect(verdict.slot.name).toBe("F")
		}
	})

	it("a slot that cannot be located in the text is refused, not guessed", () => {		const cmd = oneSlot(`wc -l "$F"`, ["wc", "-l", V], { argIndex: 2, quoted: true, whole: true, at: "$F", name: "F", shift: 999 })
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("could not be found")
	})

	it("a command with no slots is inert", () => {
		expect(probeSlots(template(`wc -l notes.txt`, ["wc", "-l", "notes.txt"], []), SPACE)).toEqual({ inert: true })
	})

	it("after -- a delete still cannot lose its operand", () => {
		const cmd = oneSlot(`rm -- "$X"`, ["rm", "--", V], { argIndex: 2, quoted: true, whole: true, at: "$X", name: "X" })
		expect(probeSlots(cmd, SPACE).inert).toBe(false)
	})

	it("-- skips the flag probes only: the file a value names after it is still probed", () => {
		// A slot rule outlives the call and covers values nobody resolved, so `cat -- "$F"` must not be storable
		// when `cat "$F"` is not: `--` says the word is not an option, never which file it is.
		const cat = oneSlot(`cat -- "$F"`, ["cat", "--", V], { argIndex: 2, quoted: true, whole: true, at: "$F", name: "F" })
		const verdict = probeSlots(cat, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("secret")
		const ls = oneSlot(`ls -- "$X"`, ["ls", "--", V], { argIndex: 2, quoted: true, whole: true, at: "$X", name: "X" })
		expect(probeSlots(ls, SPACE).inert).toBe(false)
	})
})

describe("both span conventions the types allow", () => {
	// `parseBashTemplate` documents spans into the whole command; a hand-built command may use `text`. The
	// second command below is what a parse of `true; <text>` would look like: `text` is a slice, spans absolute.
	it("spans relative to text", () => {
		const cmd = oneSlot(`cat "$F"`, ["cat", V], { argIndex: 1, quoted: true, whole: true, at: "$F", name: "F" })
		expect(probeSlots(cmd, SPACE).inert).toBe(false)
	})
	it("spans offset by start, as a parse of a longer command produces", () => {
		const text = `cat "$F"`
		const cmd = template(text, ["cat", V], [{ argIndex: 1, quoted: true, whole: true, at: "$F", name: "F", shift: 6 }], 6)
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("secret")
	})
	it("a shifted span that lands on nothing is refused", () => {
		const cmd = oneSlot(`cat "$F"`, ["cat", V], { argIndex: 1, quoted: true, whole: true, at: "$F", name: "F", shift: 3 })
		expect(probeSlots(cmd, SPACE).inert).toBe(false)
	})
})

// ------------------------------------------------------------------ the skip rules

describe("which probes a slot is checked with", () => {
	const ids = (cmd: TemplateCommand): string[] => [...new Set(probePlan(cmd, cmd.slots[0]!, SPACE).map((p) => p.classId))]

	it("a slot after -- is probed for the object and the empty value, never for the flags", () => {
		const cmd = oneSlot(`ls -- "$X"`, ["ls", "--", V], { argIndex: 2, quoted: true, whole: true, at: "$X", name: "X" })
		expect(ids(cmd)).toContain("path:secret")
		expect(ids(cmd)).toContain("value-empty")
		expect(ids(cmd)).not.toContain("flag:write-output")
		expect(ids(cmd)).not.toContain("flag:force")
	})

	it("literal text in front of the slot inside its word skips the flag probes", () => {
		const cmd = oneSlot(`sort --output="$X" footxt`, ["sort", `--output=${V}`, "footxt"], {
			argIndex: 1,
			quoted: true,
			whole: false,
			at: "$X",
			name: "X",
		})
		expect(ids(cmd)).not.toContain("flag:write-output")
		expect(ids(cmd)).not.toContain("flag:force")
		expect(ids(cmd)).toContain("path:secret")
	})

	it("a whole argument word is probed for the flags that program actually writes a file with", () => {
		const sort = oneSlot(`sort "$X"`, ["sort", V], { argIndex: 1, quoted: true, whole: true, at: "$X", name: "X" })
		expect(ids(sort)).toContain("flag:write-output")
		expect(ids(sort)).toContain("flag:force")
		const wc = oneSlot(`wc "$X"`, ["wc", V], { argIndex: 1, quoted: true, whole: true, at: "$X", name: "X" })
		expect(ids(wc)).not.toContain("flag:write-output")
		expect(ids(wc)).toContain("flag:force")
	})

	it("the echo/printf argument is probed for shape only", () => {
		const cmd = oneSlot(`echo "exit $X"`, ["echo", `exit ${V}`], { argIndex: 1, quoted: true, whole: false, at: "$X", name: "X" })
		expect(ids(cmd).every((id) => id.startsWith("flag:") || id === "value-empty")).toBe(true)
	})

	it("every probe value is written into the word, not beside it", () => {
		const cmd = oneSlot(`cat "$F"`, ["cat", V], { argIndex: 1, quoted: true, whole: true, at: "$F", name: "F" })
		const values = probePlan(cmd, cmd.slots[0]!, SPACE).map((p) => p.value)
		expect(values).toContain("/home/u/.ssh/id_rsa")
		expect(values).toContain("./backups/dump.sql")
		expect(values).toContain("")
	})
})

// ------------------------------------------------------------------ the probe classes mean something

/**
 * One pair per probe class: the same command twice, with a neutral literal and with a value from the class.
 *
 * This is how a class is bound to the policy's tables without being able to import them. A class whose two legs
 * are judged the same way is a class that no longer stands for anything, and the test says so instead of leaving
 * a silently useless probe in place.
 */
const DEMOS: Array<{ classId: string; neutral: string; probed: string }> = [
	{ classId: "path:secret", neutral: "wc -l ./notes.txt", probed: "wc -l /home/u/.ssh/id_rsa" },
	{ classId: "path:traversal", neutral: "wc -l ./sessions/x", probed: "wc -l ./sessions/../../../../../../../../../../home/u/.ssh/id_rsa" },
	{ classId: "path:outside-project", neutral: "rm ./notes.txt", probed: "rm /home/u/notes/todo.md" },
	{ classId: "path:inside-data", neutral: "rm ./notes.txt", probed: "rm ./backups/dump.sql" },
	{ classId: "path:system-config", neutral: "tee ./x.txt", probed: "tee /etc/systemd/system/api.service" },
	{ classId: "path:history", neutral: "rm ./notes.txt", probed: "rm /home/u/.bash_history" },
	{ classId: "path:protected", neutral: "rm ./notes.txt", probed: "rm /" },
	{ classId: "path:inside-project", neutral: "cat /etc/hosts", probed: "cat ./src/a.ts" },
	{ classId: "vcs-branch", neutral: "git push --force origin feature-x", probed: "git push --force origin main" },
	{ classId: "remote-path", neutral: "rsync ./a /tmp/y", probed: "rsync user@example.com:/srv/x /tmp/y" },
	{ classId: "flag:force", neutral: "rm ./notes.txt", probed: "rm -rf ./notes.txt" },
	{ classId: "flag:write-output", neutral: "sort x", probed: "sort -o/x" },
	{ classId: "value-empty", neutral: "rm -- x", probed: "rm --" },
]

/**
 * Classes that are probed for completeness rather than because they move a tier: a URL, a host name and a second
 * in-project path change WHICH object the policy names, and the object is what the prompt and the grant carry.
 * `path:inside-project` is demonstrated (a read outside the project becomes a free one); the two network shapes
 * are here, declared, so adding a class still needs a line in one of these two lists.
 */
const NOT_DEMONSTRATED = ["url", "host"]

describe("each probe class is bound to a policy rule", () => {
	for (const demo of DEMOS) {
		it(`${demo.classId}: ${JSON.stringify(demo.neutral)} and ${JSON.stringify(demo.probed)} are judged differently`, () => {
			const policy = { cwd: SPACE.cwd, project: SPACE.project, home: SPACE.home, fs: false }
			const neutral = evaluateBash(demo.neutral, policy)
			const probed = evaluateBash(demo.probed, policy)
			expect(`${probed.tier} ${probed.category}`, `${demo.classId} (${demo.neutral} → ${neutral.tier} ${neutral.category})`).not.toBe(
				`${neutral.tier} ${neutral.category}`,
			)
		})
	}

	it("every declared class is either demonstrated or explicitly listed as not", () => {
		const accounted = new Set([...DEMOS.map((d) => d.classId), ...NOT_DEMONSTRATED])
		expect(PROBE_CLASSES.map((c) => c.id).filter((id) => !accounted.has(id))).toEqual([])
	})

	it("the flag class is derived from the walker's own table, per program", () => {
		// `outputFlagWrites` is the authority on which flags write a file; these are the programs it names.
		expect(writeFlagShapes("sort")).toEqual(["-o/x"])
		expect(writeFlagShapes("tee")).toEqual(["-o/x", "--output=/x"])
		expect(writeFlagShapes("wc")).toEqual([])
	})
})

/**
 * A class is only as good as its representatives: there is one per secret class, and a representative
 * that has quietly stopped being secret is a probe that no longer reaches the rule it was picked for.
 */
describe("every representative stands for the rule it was picked for", () => {
	const policy = { cwd: SPACE.cwd, project: SPACE.project, home: SPACE.home, fs: false }

	it("each secret representative is classified read_secret", () => {
		const values = OBJECT_PROBE_CLASSES.find((c) => c.id === "path:secret")!.values.map((v) => expand(v))
		for (const value of values) {
			const decision = evaluateBash(`wc -l ${value}`, policy)
			expect(`${decision.tier} ${decision.category}`, value).toBe("ask read_secret")
		}
	})

	it("each protected representative is never wipe_protected (a recursive delete)", () => {
		for (const value of OBJECT_PROBE_CLASSES.find((c) => c.id === "path:protected")!.values.map((v) => expand(v))) {
			const decision = evaluateBash(`rm -r ${value}`, policy)
			expect(`${decision.tier} ${decision.category}`, value).toBe("never wipe_protected")
		}
	})

	it("each system-config representative is a sensitive write", () => {
		for (const value of OBJECT_PROBE_CLASSES.find((c) => c.id === "path:system-config")!.values.map((v) => expand(v))) {
			const decision = evaluateBash(`tee ${value}`, policy)
			expect(`${decision.tier} ${decision.category}`, value).toBe("ask write_sensitive")
		}
	})

	function expand(value: string): string {
		return value.replaceAll("{{home}}", SPACE.home).replaceAll("{{project}}", SPACE.project)
	}
})

// ------------------------------------------------------------------ the self-check

/**
 * How the sites were found, and what a failure here means.
 *
 * `risk-handlers.ts` compares a WORD against a list or a pattern in many places, and a word that comes from a
 * run-time value is exactly what a stored slot rule would auto-approve. The tables are not exported, so the
 * enumeration is mechanical: every module-level declaration whose name is SCREAMING_SNAKE and whose initialiser
 * is a literal list, `new Set(…)`, a regex or an object literal —
 *
 *     /^(?:export )?const ([A-Z][A-Z0-9_]*)[^\n=]*=\s*(?:new Set\(|\[|\/|\{)/gm
 *
 * — is a candidate, and each one has an entry in SITES below saying what covers it:
 *
 *   · `operand`    — a slot value is compared as an operand word: the named probe classes must exercise it,
 *                    and each of them must be demonstrated in DEMOS to move a verdict;
 *   · `subcommand` — the word is grammar (a subcommand, a verb, a wrapped command): the named family in
 *                    COMMAND_WORD_FAMILIES must refuse a slot there;
 *   · `flag`       — a flag word or a flag's value: probed as an ordinary argument value;
 *   · `program`    — dispatch on argv[0], which is the walker's job, not a slot's.
 *
 * A NEW declaration makes this test fail on the count and on the missing entry. The fix is to decide which of
 * the four it is; if it is `operand`, add a probe class to `slot-probe.ts` (and a DEMO here), and if it is
 * `subcommand`, add the family to COMMAND_WORD_FAMILIES. Do not extend the count without doing one of those.
 *
 * Comparisons written inline inside a handler (not as a module-level declaration) are not enumerated, and are
 * covered by the classes they resemble: the `host:path` shape in rsync/scp/ssh (`remote-path`), the URL shape in
 * curl (`url`/`host`), the SQL patterns in the database handler (the database families refuse those operands),
 * and the editor/`sed`/`awk` script operands (their families refuse them).
 */
type Site =
	| { kind: "operand"; classes: string[]; why: string }
	| { kind: "subcommand"; families: string[]; why: string }
	| { kind: "flag" | "program"; why: string }

const operand = (classes: string[], why: string): Site => ({ kind: "operand", classes, why })
const subcommand = (families: string[], why: string): Site => ({ kind: "subcommand", families, why })
const flag = (why: string): Site => ({ kind: "flag", why })
const program = (why: string): Site => ({ kind: "program", why })

const CLOUDS = ["aws", "gcloud", "gsutil", "az", "doctl", "flyctl", "fly", "vercel", "netlify", "wrangler", "heroku"]

const SITES: Record<string, Site> = {
	FILE_READERS: program("which verb's rows a command gets"),
	ARG_DATA_BINS: operand(["path:secret"], "an argument is data, but a credential-shaped word still asks"),
	PATTERN_FIRST_BINS: operand(["path:secret"], "decides which operand is a pattern and which is a file"),
	PATTERN_FLAGS: flag("the pattern flags decide whether the first operand is a pattern"),
	HOST_READ_OBJECTS: program("dispatch on argv[0]"),
	MACHINE_STATUS_BINS: program("dispatch on argv[0]; the change words are STATUS_CHANGE_WORDS"),
	STATUS_CHANGE_WORDS: subcommand(["ip", "route", "arp", "ifconfig"], "`ip link set` — any argument can be the change"),
	STATUS_CHANGE_FLAGS: flag("the flag-shaped changes in the same family"),
	SHELL_BUILTIN_ALLOW: program("dispatch on argv[0]"),
	SELF_INFO_FLAGS: flag("`--version`/`--help` — a probe value that reports on the tool itself"),
	DEFAULT_REGISTRY: program("chosen by the client, not by an operand"),
	WRAPPERS: subcommand(
		["timeout", "time", "nice", "nohup", "stdbuf", "setsid", "flock", "taskset", "strace", "ltrace", "env", "xargs", "sudo", "doas", "pkexec", "su", "watch"],
		"the word after the wrapper is the command",
	),
	INTERPRETERS: program("dispatch on argv[0]"),
	SHELLS: program("dispatch on argv[0]"),
	TEST_TOOLS: program("dispatch on argv[0]"),
	PKG_PROJECT: program("dispatch on argv[0]"),
	DATA_FILE_RE: operand(["path:inside-data"], "`rm` of a backup/dump is delete_data, not a project write"),
	NEVER_WIPE_HISTORY_RE: operand(["path:history", "path:protected"], "deleting shell history is never history_wipe"),
	ENV_ASSIGNMENT: subcommand(["env"], "`env NAME=value cmd` — the operand after the assignments is the command"),
	ENV_BARE_OPTIONS: flag("env's own options"),
	ENV_VALUE_OPTIONS: flag("env's own options"),
	EDITOR_EXEC_OPTIONS: flag("an editor option can carry code; the editor families refuse every argument word"),
	EDITOR_VALUE_OPTIONS: flag("the same options' values"),
	WRITE_REDIRECT_OPS: flag("redirect operators, not operand words"),
	GIT_READ: subcommand(["git"], "git reads a subcommand word"),
	GIT_LOCAL_WRITE: subcommand(["git"], "git writes a subcommand word"),
	GIT_REMOTE_READ: subcommand(["git"], "git reads a subcommand word"),
	PROTECTED_BRANCH_RE: operand(["vcs-branch"], "a force-push or delete to a protected branch is never vcs_force_protected"),
	GIT_VALUE_OPTS: flag("git's value-taking options"),
	GIT_REPO_DIR_OPTS: flag("which of them says where the repository is"),
	GH_READ_RE: subcommand(["gh", "glab", "hub"], "the group and action words"),
	GH_DEFAULT_HOST: program("chosen by the client"),
	GH_HOST_ENV: program("chosen by the client"),
	DOCKER_READ: subcommand(["docker", "podman", "nerdctl"], "the container runtime's subcommand"),
	KUBECTL_VALUE_FLAGS: flag("kubectl's value-taking options"),
	KUBECTL_READ: subcommand(["kubectl", "oc", "k9s"], "the subcommand and the resource kind"),
	CLI_READ_VERBS: subcommand(CLOUDS, "the read verbs"),
	CLI_MUTATION_VERBS: subcommand(CLOUDS, "the mutation verbs"),
	CLI_SECRET_NOUNS: subcommand(CLOUDS, "the credential nouns"),
	CLI_CONFIG_VERBS: subcommand(CLOUDS, "the local-config verbs"),
	AWS_NEVER: subcommand(["aws"], "the hyphenated op word"),
	AWS_VALUE_FLAGS: flag("aws's value-taking options"),
	DATA_STORE_NOUNS: subcommand(["gcloud", "az", "doctl", "wrangler", "gsutil"], "the product noun"),
	DATA_STORE_CLIENTS: program("dispatch on argv[0]"),
	OBJ_DELETE_RE: subcommand(CLOUDS, "the storage verbs, matched against every positional"),
	OBJ_UPLOAD_RE: subcommand(CLOUDS, "the storage verbs, matched against every positional"),
	NPM_SCRIPT_SAFE_RE: subcommand(["npm", "pnpm", "yarn", "bun"], "the script name, and the subcommand before it"),
	KNOWN_NPX_TOOLS: subcommand(["npx", "bunx", "pnpx"], "the package word"),
	VENV_PROGRAM_RE: program("read off argv[0]"),
	SSH_VALUE_OPTS: flag("ssh's value-taking options, which decide where the host operand starts"),
	SERVICE_STATE_VERBS: subcommand(["service", "rc-service", "systemctl"], "the verb can sit after the unit name"),
	UNIT_READ_SUBS: subcommand(["systemctl"], "the subcommand"),
	SQL_NEVER_RE: subcommand(["psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "duckdb"], "the statement is an operand"),
	SQL_DELETE_NO_WHERE_RE: subcommand(["psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "duckdb"], "the statement is an operand"),
	SQL_MUTATE_RE: subcommand(["psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "duckdb"], "the statement is an operand"),
}

/** Pinned so a new table cannot slip in: `slot-probe.test.ts` must be updated with it (see the block above). */
const PINNED_TABLE_COUNT = 55

describe("self-check: every word table in risk-handlers.ts is answered for", () => {
	const source = readFileSync(path.join(import.meta.dirname, "risk-handlers.ts"), "utf-8")
	const declared = [...source.matchAll(/^(?:export )?const ([A-Z][A-Z0-9_]*)[^\n=]*=\s*(?:new Set\(|\[|\/|\{)/gm)].map((m) => m[1]!)

	it("counts the tables it can see", () => {
		expect(declared.length, `found ${declared.length} module-level word tables in risk-handlers.ts`).toBe(PINNED_TABLE_COUNT)
	})

	it("every declared table has an entry saying what covers it, and no entry is stale", () => {
		const missing = declared.filter((name) => !(name in SITES))
		expect(missing, "a word table was added to risk-handlers.ts: decide whether an operand word now decides a verdict").toEqual([])
		const stale = Object.keys(SITES).filter((name) => !declared.includes(name))
		expect(stale, "an entry names a table that no longer exists: delete it or fix its name").toEqual([])
	})

	it("an operand table names probe classes that exist and are demonstrated", () => {
		const demonstrated = new Set(DEMOS.map((d) => d.classId))
		const known = new Set(PROBE_CLASSES.map((c) => c.id))
		for (const [name, site] of Object.entries(SITES)) {
			if (site.kind !== "operand") continue
			expect(site.classes.length, `${name} names no probe class`).toBeGreaterThan(0)
			for (const id of site.classes) {
				expect(known, `${name} names a probe class that does not exist: ${id}`).toContain(id)
				expect(demonstrated, `${name} names ${id}, which no DEMO shows moving a verdict`).toContain(id)
			}
		}
	})

	it("a subcommand table names families that refuse a slot in their command-word region", () => {
		for (const [name, site] of Object.entries(SITES)) {
			if (site.kind !== "subcommand") continue
			expect(site.families.length, `${name} names no family`).toBeGreaterThan(0)
			for (const family of site.families) expect(COMMAND_WORD_FAMILIES[family], `${name} names an unknown family: ${family}`).toBeDefined()
		}
	})

	it("every family really refuses a slot in the words it reads as grammar", () => {
		for (const [family, arity] of Object.entries(COMMAND_WORD_FAMILIES)) {
			const words = arity === "all" ? 1 : arity
			const argv = [family, ...Array.from({ length: words - 1 }, () => "word"), V]
			const spec: SlotSpec = { argIndex: words, quoted: true, whole: true, at: "$X", name: "X" }
			const verdict = probeSlots(template(`${family} ${argv.slice(1, -1).join(" ")} "$X"`.trim(), argv, [spec]), SPACE)
			expect(verdict.inert, `${family} did not refuse a slot at argv[${words}]`).toBe(false)
			if (!verdict.inert) expect(verdict.reason).toContain("command words")
		}
	})
})

describe("fixtures are wired to the walker's own vocabulary", () => {
	it("the placeholder texts are the walker's", () => {
		expect(V).toBe("__TRACKED_VAR__")
		expect(C).toBe("__CMDSUB_OUTPUT__")
	})

	it("every probe class says what it stands for", () => {
		for (const cls of PROBE_CLASSES) {
			expect(cls.noun.length).toBeGreaterThan(0)
			expect(cls.covers.length).toBeGreaterThan(0)
		}
	})

	it("the secret class carries one representative per name family", () => {
		expect(OBJECT_PROBE_CLASSES.find((c) => c.id === "path:secret")!.values.length).toBeGreaterThan(4)
	})
})

describe("values that leave the machine, and values that climb out of a directory", () => {
	it("a slot in curl is never inert: the value is sent to the host", () => {
		const cmd = oneSlot(`curl -s -H "Authorization: Bearer $T" https://example.com/v2/x`, ["curl", "-s", "-H", `Authorization: Bearer ${V}`, "https://example.com/v2/x"], { argIndex: 3, quoted: true, whole: false, at: "$T", name: "T" })
		const verdict = probeSlots(cmd, SPACE)
		expect(verdict.inert).toBe(false)
		if (!verdict.inert) expect(verdict.reason).toContain("off this machine")
	})
	it("a slot after a literal directory is probed with `..`", () => {
		const cmd = oneSlot(`ls -la "/home/u/proj/sessions/$X"`, ["ls", "-la", `/home/u/proj/sessions/${V}`], { argIndex: 2, quoted: true, whole: false, at: "$X", name: "X" })
		expect(probeSlots(cmd, SPACE).inert).toBe(false)
	})
})
