/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Layer 1 of `plan-runtime-values`: **does a run-time value change what a command does?**
 *
 * A command with a value only known at run time (`cat "$F"`, `$(git rev-parse HEAD)`) reaches the gate as a
 * {@link TemplateCommand}: the value is a {@link Slot}, and the argv word that holds it carries the walker's
 * placeholder text. "Allow always" cannot store a literal for such a command, so the writer asks this module
 * whether the value *matters*: an INERT slot is one whose every plausible value is judged the same way, which
 * makes the command storable as a slot rule (`Bash(cat $…)`); a slot that is not inert refuses the write and
 * says which value would change the verdict, because that sentence is what the user is shown.
 *
 * The answer is measured, never declared. Each slot is replaced, one at a time (the other slots held at a
 * neutral literal), by every value in {@link PROBE_CLASSES}, and the command is judged again by the real
 * policy — `evaluateBash` over layer 0, the verb tables, `classifyPath` and the effect rules. A probe whose
 * **tier or category** differs from the neutral leg's is a value that changes what the command does, so the
 * slot is not inert. The classes are the policy's own vocabulary — the project, outside it, the secret file
 * names, live system config, the protected roots, a URL, a host, a remote path, the protected branch, the
 * empty value, and the output-flag shapes `outputFlagWrites` says this very program writes a file with — so
 * a table added to layer 0 is either reached by one of them or named by the self-check test.
 *
 * Two things are refused before any probing, because no probe list can enumerate them:
 *
 *  - a slot in a **command-word position** of a family whose handler matches argv words against a word table
 *    (`git "$SUB"`, `gcloud compute instances "$A" vm1`, `ip link "$SET"`, the command behind `timeout`).
 *    {@link COMMAND_WORD_FAMILIES} mirrors `risk-handlers.ts`, and the self-check test fails when a word table
 *    appears there that this file has not answered for;
 *  - an **unquoted** slot outside the arguments of `echo`/`printf`: the shell splits it on whitespace and
 *    expands globs, so the words it becomes decide what runs, before any policy is consulted.
 *
 * Deliberate limit, stated rather than hidden: two positions are probed for SHAPE only (the empty value and
 * the flag shapes), because there the word cannot be read as an option or is not opened at all — a slot after
 * `--`, and a slot in the argument list of a data-argument command (`echo`, `printf`). `ls -- "$X"` is inert
 * for that reason; which file a read outside those two positions names is probed, and a secret there is not
 * inert.
 */

import path from "node:path"
import {
	CMDSUB_PLACEHOLDER,
	TRACKED_VAR_PLACEHOLDER,
	type Slot,
	type TemplateCommand,
} from "./bash-ast.ts"
import { outputFlagWrites } from "./bash-walker-meaning.ts"
import { evaluateBash, type PolicyDecision, type PolicyOptions } from "./risk-policy.ts"

/** The path space a verdict is decided in — the same three roots layer 0 resolves entities against. */
export type SlotSpace = { cwd: string; project: string; home: string }

export type SlotVerdict = { inert: true } | { inert: false; reason: string; slot: Slot }

/** Every other slot is filled with this while one of them is probed. */
const NEUTRAL = "x"

/** The walker's placeholder spellings: a slot's argv word contains one of these (§5.10, §6). */
const PLACEHOLDERS = [TRACKED_VAR_PLACEHOLDER, CMDSUB_PLACEHOLDER]

/** Commands whose arguments are data: nothing is opened, so only the shape of the word is probed. */
const DATA_ARGUMENT_PROGRAMS = new Set(["echo", "printf"])

/**
 * Programs that send their arguments off the machine. In these the value is not only an argument that might
 * change the verdict: it is DATA that leaves — a header, a query, a body, a remote command — so a slot rule
 * would let any value, a secret included, be sent to the host the rule names. No probe can say that is
 * harmless, so a slot here is never inert.
 */
const NETWORK_PROGRAMS = new Set([
	"curl", "wget", "http", "https", "xh", "httpie", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp",
	"ssh", "scp", "rsync", "mosh", "gh", "aria2c",
])

/** Categories whose verdict is about something leaving the machine; same reasoning as NETWORK_PROGRAMS. */
const NETWORK_CATEGORIES = new Set(["network_send", "remote_exec", "exfiltration"])

// ------------------------------------------------------------------ command-word families

/**
 * Families whose handler compares an ARGUMENT WORD against a word table, and how far into the argument list
 * that comparison reaches:
 *
 *  - a number: the first N *operand words* (`positionals()`, i.e. `--` honoured, option words skipped) are the
 *    family's grammar — the subcommand, or the subcommand and its noun;
 *  - `"all"`: any argument word at all. Used where the table is scanned with `.some()`/`.find()` over every
 *    positional (`ip link set`, `apt remove bash`, `make deploy`, `find -delete`, SQL in an operand), and for
 *    the wrappers and editors, where an argument word can be the command that runs.
 *
 * A slot inside that region is refused rather than probed: the word it becomes decides the verdict, and no
 * probe list can enumerate a CLI's vocabulary. This table mirrors `risk-handlers.ts` by hand — the handlers do
 * not export their tables — so `slot-probe.test.ts` enumerates the tables it can see in that file and fails,
 * with instructions, when one has no entry here.
 */
export const COMMAND_WORD_FAMILIES: Readonly<Record<string, number | "all">> = {
	// Wrappers: the first word that is not one of the wrapper's own arguments IS the command that runs.
	timeout: "all", time: "all", nice: "all", ionice: "all", nohup: "all", stdbuf: "all", setsid: "all",
	chronic: "all", unbuffer: "all", script: "all", command: "all", builtin: "all", exec: "all", flock: "all",
	taskset: "all", numactl: "all", strace: "all", ltrace: "all", env: "all", xargs: "all",
	sudo: "all", doas: "all", pkexec: "all", su: "all", watch: "all",
	// Machine status and firewalls: the word that turns a read into a change can be any argument.
	ip: "all", route: "all", arp: "all", ifconfig: "all",
	iptables: "all", ip6tables: "all", nft: "all", ufw: "all", "firewall-cmd": "all",
	// Service control and processes: the verb, the unit name and the pattern are all compared as words.
	systemctl: "all", service: "all", "rc-service": "all", kill: "all", pkill: "all", killall: "all", killall5: "all",
	// A script whose text writes files, and the search flags that run something.
	sed: 1, awk: 1, gawk: 1, mawk: 1, find: "all",
	// Databases: the statement is an operand word and decides between read and destroy.
	psql: "all", mysql: "all", mariadb: "all", sqlite3: "all", mongosh: "all", mongo: "all",
	"redis-cli": "all", "clickhouse-client": "all", duckdb: "all",
	// Build and test drivers whose targets are a word table (`make deploy`, `rake publish`).
	make: "all", cmake: "all", ninja: "all", meson: "all", bazel: "all", just: "all", task: "all", rake: "all",
	// Package managers: base-package names, VCS/URL specs and script names are all words from a table.
	apt: "all", "apt-get": "all", aptitude: "all", dnf: "all", yum: "all", zypper: "all", pacman: "all",
	apk: "all", emerge: "all", "nix-env": "all", snap: "all", flatpak: "all", brew: "all", port: "all",
	npm: 2, pnpm: 2, yarn: 2, bun: 2, npx: 1, bunx: 1, pnpx: 1,
	pip: "all", pip2: "all", pip3: "all", pipx: 1, uv: 1, poetry: 1, pdm: 1, conda: 1, mamba: 1,
	cargo: 1, go: 1,
	gem: 1, bundle: 1, composer: 1, mix: 1, dotnet: 1, gradle: 1, gradlew: 1, mvn: 1, sbt: 1, lein: 1,
	stack: 1, cabal: 1, swift: 1, zig: 1,
	// Forges, clusters and clouds: the subcommand words first, and the whole call where a verb anywhere decides.
	git: 1, gh: 2, glab: 2, hub: 2,
	docker: 2, podman: 2, nerdctl: 2, "docker-compose": 2, oras: 1,
	kubectl: 2, oc: 2, k9s: 2, helm: 2, terraform: 2, tofu: 2, pulumi: 2,
	aws: "all", gcloud: "all", gsutil: "all", az: "all", doctl: "all", flyctl: "all", fly: "all",
	vercel: "all", netlify: "all", wrangler: "all", heroku: "all",
	// Editors: an argv option can be a command to run (`vim -c '!rm -rf /'`), so no word there is inert.
	vim: "all", vi: "all", nvim: "all", nano: "all", emacs: "all", code: "all", subl: "all",
	// Interactive multiplexers and terminals.
	tmux: 1, screen: 1,
}

// ------------------------------------------------------------------ probe classes

/**
 * One class of probe value.
 *
 * `covers` names the part of the policy the class exists to exercise, so a class that has stopped standing for
 * anything is visible rather than merely unused. `{{home}}` and `{{project}}` in a value are filled from the
 * {@link SlotSpace}, so the classes work for any home directory a test or a user has.
 */
export type ProbeClass = {
	id: string
	/** What the value is, in the words the refusal shows the user ("could be a secret-bearing file"). */
	noun: string
	/** The policy table or rule this class exercises (documentation for the self-check test). */
	covers: string
	values: readonly string[]
}

/**
 * The values that are about the OBJECT a command names. Each of them, in a slot, is a value whose file, host
 * or branch the policy decides differently — so a slot that accepts all of them is naming objects the same
 * way whatever the value turns out to be.
 *
 * The secret class carries one representative per name family `risk-paths.ts` recognises (listed in the
 * comment above it), rather than one path: the whole point of probing is that the classes come from the
 * policy's tables, and a single `~/.ssh/id_rsa` would only ever exercise the openssh-key rule.
 */
export const OBJECT_PROBE_CLASSES: readonly ProbeClass[] = [
	{
		id: "path:traversal",
		noun: "a path that climbs out with `..`",
		covers: "risk-paths classifyPath resolves `..` — a value after a literal directory (`dir/$X`) can still reach ~/.ssh",
		values: ["../../../../../../../../../../{{home}}/.ssh/id_rsa"],
	},
	{
		id: "path:secret",
		noun: "a secret-bearing file",
		covers: "risk-paths SECRET_NAME_RULES + SECRET_DIRS_UNDER_HOME + credentialNameWord + /etc/shadow",
		values: [
			"{{home}}/.ssh/id_rsa", // openssh_key
			"{{home}}/.kube/config", // kubeconfig + a secret dir under home
			"{{home}}/.aws/credentials", // credentials + a secret dir under home
			"{{home}}/.netrc", // client_auth_files
			"./certs/server.pem", // key_material_ext, inside the project
			"./.env", // dotenv, inside the project
			"./password.txt", // credentialNameWord: the name alone declares it
			"./service-account-prod.json", // gcp_service_account
			"/etc/shadow", // unix_auth_db
		],
	},
	{
		id: "path:outside-project",
		noun: "a path outside the project",
		covers: "an outside read asks, an outside write/delete asks",
		values: ["{{home}}/notes/todo.md"],
	},
	{
		id: "path:inside-data",
		noun: "a data file inside the project",
		covers: "risk-handlers DATA_FILE_RE — `rm` of a backup/dump asks as delete_data",
		values: ["./backups/dump.sql"],
	},
	{
		id: "path:system-config",
		noun: "a live system config file",
		covers: "risk-paths isSensitiveConfig — writes are write_sensitive",
		values: ["/etc/systemd/system/api.service", "{{home}}/.config/systemd/user/api.service"],
	},
	{
		id: "path:history",
		noun: "a shell history file",
		covers: "risk-handlers NEVER_WIPE_HISTORY_RE — never history_wipe",
		values: ["{{home}}/.bash_history"],
	},
	{
		id: "path:protected",
		noun: "a protected location",
		covers: "risk-paths isNeverWipe/isProjectRoot — never wipe_protected",
		values: ["/", "{{home}}", ".", "{{project}}"],
	},
	{
		id: "path:inside-project",
		noun: "one more file inside the project",
		covers: "the free end of the same rules: an in-project read is allow read_only",
		values: ["./src/a.ts"],
	},
	{
		id: "url",
		noun: "a URL",
		covers: "curl/wget GET, `pip install <url>`, cloud storage clients — the scheme decides the object",
		values: ["https://example.com/x"],
	},
	{
		id: "host",
		noun: "a host name",
		covers: "curl/netHost, `gh`/forge objects — a bare host is read as one",
		values: ["example.com"],
	},
	{
		id: "remote-path",
		noun: "a remote path",
		covers: "risk-handlers rsync/scp/ssh `host:path` matching — network_send and exfiltration",
		values: ["user@example.com:/srv/x"],
	},
	{
		id: "vcs-branch",
		noun: "a protected branch name",
		covers: "risk-handlers PROTECTED_BRANCH_RE — force-push/delete to main is never vcs_force_protected",
		values: ["main"],
	},
]

/**
 * The values that are about the SHAPE of the word: a value that stops being an operand, or becomes an option.
 * They are probed everywhere, including the one position where the object is not probed (a data-argument
 * command), because an empty value does change what the command does in both of them.
 *
 * `flag:write-output` has no fixed values: which flags name a file is a per-program fact, so its shapes are
 * derived from `outputFlagWrites` for the program actually being probed (see {@link writeFlagShapes}).
 */
export const SHAPE_PROBE_CLASSES: readonly ProbeClass[] = [
	{
		id: "flag:force",
		noun: "a recursive/force flag",
		covers: "risk-handlers hasFlag(-r/-f/--force) — recursive delete is ask everywhere",
		values: ["-rf", "--force"],
	},
	{
		id: "flag:write-output",
		noun: "an output flag",
		covers: "bash-walker-meaning OUTPUT_FLAG_WRITES — `sort -o FILE` writes exactly as `> FILE` does",
		values: [],
	},
	{
		id: "value-empty",
		noun: "the empty value",
		covers: "an empty argument disappears (classifyVerb filters \"\") — `rm --` prints usage, `cat` reads stdin",
		values: [""],
	},
]

/** Every probe class, for the self-check test: a site must name one of these ids. */
export const PROBE_CLASSES: readonly ProbeClass[] = [...OBJECT_PROBE_CLASSES, ...SHAPE_PROBE_CLASSES]

/** The candidate spellings of a file-writing output flag; each is kept only if the walker reports a write. */
const WRITE_FLAG_SHAPES = ["-o/x", "--output=/x"] as const

/**
 * The output-flag shapes that are really writes for this program, read out of `outputFlagWrites` itself.
 *
 * `sort`, `uniq`, `patch`, `tee` and `git`-diff write a file through a flag, and which of the two spellings each
 * one takes is its own option grammar; asking the walker's table per program keeps this module from carrying a
 * copy of it. A program with no such flag gets no probe — there is nothing there to write.
 */
export function writeFlagShapes(program: string): string[] {
	return WRITE_FLAG_SHAPES.filter((shape) => outputFlagWrites([program, shape]).length > 0)
}

// ------------------------------------------------------------------ the probe

/**
 * Is every run-time value in this command inert — i.e. is the command's verdict the same whatever those values
 * turn out to be?
 *
 * `inert: false` carries the slot that failed and one sentence naming the slot's own source text, the classes
 * of value that would change the verdict, and what the verdict would become. Callers show that sentence.
 */
export function probeSlots(cmd: TemplateCommand, space: SlotSpace): SlotVerdict {
	const slots = cmd.slots ?? []
	if (slots.length === 0) return { inert: true }

	for (const slot of slots) {
		const refusal = positionalRefusal(cmd, slot)
		if (refusal !== null) return { inert: false, reason: refusal, slot }
	}

	const offsets = new Map<Slot, number>()
	for (const slot of slots) {
		const at = locateSlot(cmd, slot)
		if (at === null) {
			return {
				inert: false,
				slot,
				reason: `${writtenSlot(slot)} could not be found in the command text, so the value it holds cannot be checked`,
			}
		}
		offsets.set(slot, at)
	}

	const baseline = legDecision(cmd, offsets, new Map(), space)
	if (baseline !== null && !baseline.unparseable && NETWORK_CATEGORIES.has(baseline.category)) {
		return {
			inert: false,
			slot: slots[0]!,
			reason: `this command sends data off the machine (${baseline.category}), so ${writtenSlot(slots[0]!)} would leave with it whatever it holds`,
		}
	}
	if (baseline === null || baseline.unparseable) {
		return {
			inert: false,
			slot: slots[0]!,
			reason: `the command could not be judged with a plain value in place of ${writtenSlot(slots[0]!)}, so no run-time value in it can be checked`,
		}
	}

	for (const slot of slots) {
		const differing: Array<{ probe: Probe; decision: PolicyDecision }> = []
		for (const probe of probePlan(cmd, slot, space)) {
			const leg = legDecision(cmd, offsets, new Map([[slot, probe.value]]), space)
			if (leg === null || leg.unparseable) {
				differing.push({ probe: { ...probe, noun: "a value the command cannot be judged with" }, decision: baseline })
				continue
			}
			if (leg.tier !== baseline.tier || leg.category !== baseline.category) differing.push({ probe, decision: leg })
		}
		if (differing.length > 0) {
			return { inert: false, slot, reason: reasonFor(cmd, slot, baseline, differing) }
		}
	}
	return { inert: true }
}

// ------------------------------------------------------------------ refusals

/** Why this slot cannot be judged by probing at all, or null when it can. */
function positionalRefusal(cmd: TemplateCommand, slot: Slot): string | null {
	const program = programOf(cmd)
	const written = writtenSlot(slot)
	if (slot.argIndex <= 0) {
		return `${written} sits in command position: the program the value names decides what runs`
	}
	if (!slot.quoted && !DATA_ARGUMENT_PROGRAMS.has(program)) {
		return `${written} is unquoted: the shell splits it on whitespace and expands globs, so the words it becomes decide what runs`
	}
	const arity = COMMAND_WORD_FAMILIES[program]
	const offMachine = NETWORK_PROGRAMS.has(program)
		? `${written} is an argument of ${program}, which sends it off this machine: any value, a secret included, would go to the host`
		: null
	if (arity === undefined) return offMachine
	const commandWord = (): string =>
		`${written} is one of ${program}'s command words (its handler compares the words against a verb/keyword table): the word the value becomes decides what the command does`
	if (arity === "all") return commandWord()
	const rank = operandRank(cmd.argv, slot.argIndex)
	if (rank >= 0 && rank < arity) return commandWord()
	return offMachine
}

/**
 * How many operand words precede `argIndex`, or -1 when it is not an operand position.
 *
 * The same reading of `--` and of option words `positionals()` in risk-handlers uses — deliberately mirrored,
 * because a second, different idea of where a family's operands start is how a word table gets bypassed.
 */
function operandRank(argv: readonly string[], argIndex: number): number {
	const operands: number[] = []
	let noMoreFlags = false
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!
		if (!noMoreFlags && a === "--") {
			noMoreFlags = true
			continue
		}
		if (!noMoreFlags && a.startsWith("-") && a !== "-") continue
		operands.push(i)
	}
	return operands.indexOf(argIndex)
}

// ------------------------------------------------------------------ the legs

/** One value a slot is checked with: which class it came from, the noun the refusal shows, and the value. */
export type Probe = { classId: string; noun: string; value: string }

/** The path space, with filesystem probes off: a verdict must not depend on the machine running the check. */
function policyFor(space: SlotSpace): PolicyOptions {
	return { cwd: space.cwd, project: space.project, home: space.home, fs: false }
}

function programOf(cmd: TemplateCommand): string {
	return path.posix.basename(cmd.argv[0] ?? "")
}

/** Offset of the slot's expansion inside `cmd.text`, for both span conventions the types allow. */
function locateSlot(cmd: TemplateCommand, slot: Slot): number | null {
	const [from, to] = slot.span
	if (!(to > from)) return null
	const length = to - from
	// The tree parse documents spans into the whole command; a hand-built TemplateCommand may use `text`.
	if (cmd.text.slice(from, from + length).startsWith("$")) return from
	const relative = from - cmd.start
	if (relative >= 0 && cmd.text.slice(relative, relative + length).startsWith("$")) return relative
	return null
}

/** The slot's own source text (`$F`, `$(git rev-parse HEAD)`), or a reconstruction when it cannot be located. */
function writtenSlot(slot: Slot): string {
	if (slot.source === "cmdsub") return `$(${slot.inner ?? "…"})`
	return `$${slot.name ?? "…"}`
}

function slotTextAt(cmd: TemplateCommand, slot: Slot, at: number): string {
	return cmd.text.slice(at, at + (slot.span[1] - slot.span[0]))
}

/**
 * The slot's value as bash would see it after the substitution: the probe itself.
 *
 * A quoted slot already sits inside quotes, so the value goes in bare — quoting it again would put the quote
 * characters INTO the value. An unquoted slot is single-quoted so one probe value stays one word. Returns null
 * when the value cannot be written safely into that context, which the caller treats as "not checkable".
 */
function embed(slot: Slot, value: string): string | null {
	if (value === "") return slot.quoted ? "" : "''"
	if (slot.quoted) return /["$`\\]/.test(value) ? null : value
	if (value.includes("'")) return null
	return `'${value}'`
}

/** One leg: the command text with every slot filled (neutral, or one probed), judged by the real policy. */
function legDecision(cmd: TemplateCommand, offsets: Map<Slot, number>, overrides: Map<Slot, string>, space: SlotSpace): PolicyDecision | null {
	const filled = [...(cmd.slots ?? [])].sort((a, b) => (offsets.get(b) ?? 0) - (offsets.get(a) ?? 0))
	let text = cmd.text
	for (const slot of filled) {
		const at = offsets.get(slot)
		if (at === undefined) return null
		const replacement = embed(slot, overrides.get(slot) ?? NEUTRAL)
		if (replacement === null) return null
		text = text.slice(0, at) + replacement + text.slice(at + (slot.span[1] - slot.span[0]))
	}
	return evaluateBash(text, policyFor(space))
}

/**
 * The probe values for one slot, in the order they are tried.
 *
 * Exported so the two skip rules — a slot after `--`, and a slot with literal text in front of it inside its own
 * word — are pinned directly, not only through a verdict that happens to match.
 */
export function probePlan(cmd: TemplateCommand, slot: Slot, space: SlotSpace): Probe[] {
	const program = programOf(cmd)
	const probes: Probe[] = []
	if (objectProbesReach(cmd, slot, program)) {
		for (const cls of OBJECT_PROBE_CLASSES) {
			for (const raw of cls.values) probes.push({ classId: cls.id, noun: cls.noun, value: expand(raw, space) })
		}
	}
	for (const cls of SHAPE_PROBE_CLASSES) {
		const values = cls.id === "flag:write-output" ? writeFlagShapes(program) : cls.values
		const isFlagClass = cls.id === "flag:write-output" || cls.id === "flag:force"
		if (isFlagClass && !flagProbesReach(cmd, slot)) continue
		for (const value of values) probes.push({ classId: cls.id, noun: cls.noun, value })
	}
	return probes
}

function expand(value: string, space: SlotSpace): string {
	return value.replaceAll("{{home}}", space.home).replaceAll("{{project}}", space.project)
}

/**
 * Does the object a value names reach the policy through this slot?
 *
 * Everywhere except the arguments of `echo`/`printf`, which open nothing at all. `--` is NOT an exception: it
 * says the next words are not options, and says nothing about which file they name — `cat -- "$F"` reads a key
 * as readily as `cat "$F"`. A slot rule outlives the call that earned it and covers later values the resolver
 * never saw, so the object has to be probed here; `--` only skips the flag probes ({@link flagProbesReach}).
 */
function objectProbesReach(_cmd: TemplateCommand, _slot: Slot, program: string): boolean {
	return !DATA_ARGUMENT_PROGRAMS.has(program)
}

/**
 * Could a probe value become an option word here?
 *
 * Not after `--` (nothing after it is an option), and not when literal text comes before the slot inside the
 * same word: `--output=$X` can only ever be one long flag whose value is the slot.
 */
function flagProbesReach(cmd: TemplateCommand, slot: Slot): boolean {
	if (slotAfterDoubleDash(cmd, slot)) return false
	return literalPrefix(cmd, slot) === ""
}

/** The literal text of the slot's own argv word, before the placeholder. */
function literalPrefix(cmd: TemplateCommand, slot: Slot): string {
	const word = cmd.argv[slot.argIndex] ?? ""
	for (const placeholder of PLACEHOLDERS) {
		const at = word.indexOf(placeholder)
		if (at >= 0) return word.slice(0, at)
	}
	// No placeholder in the word: a hand-built command that gave the slot no placeholder text. Treat the whole
	// word as literal, which only skips the flag probes — the conservative direction.
	return word
}

function slotAfterDoubleDash(cmd: TemplateCommand, slot: Slot): boolean {
	const at = cmd.argv.indexOf("--")
	return at >= 0 && slot.argIndex > at
}

// ------------------------------------------------------------------ the sentence

function reasonFor(cmd: TemplateCommand, slot: Slot, baseline: PolicyDecision, differing: Array<{ probe: Probe; decision: PolicyDecision }>): string {
	const at = locateSlot(cmd, slot)
	const name = at === null ? writtenSlot(slot) : slotTextAt(cmd, slot, at)
	// The strictest probe decides the sentence — that is the value that would need more than the user granted.
	// At the same tier a word-shape probe comes first: "it could be an output flag" says what changes about the
	// command, where the object classes only say what the file might be.
	const ranked = [...differing].sort((a, b) => {
		const tier = tierRank(b.decision.tier) - tierRank(a.decision.tier)
		if (tier !== 0) return tier
		return Number(isShapeNoun(b.probe.noun)) - Number(isShapeNoun(a.probe.noun))
	})
	const nouns = [...new Set(ranked.map((d) => d.probe.noun))].slice(0, 4)
	const changed = ranked[0]!
	return `${name} could be ${joinWords(nouns)}: ${programOf(cmd)} would be judged ${changed.decision.tier} ${changed.decision.category} instead of ${baseline.tier} ${baseline.category}`
}

function isShapeNoun(noun: string): boolean {
	return SHAPE_PROBE_CLASSES.some((cls) => cls.noun === noun)
}

function tierRank(tier: string): number {
	return tier === "never" ? 3 : tier === "unknown" ? 2 : tier === "ask" ? 1 : 0
}

function joinWords(words: readonly string[]): string {
	if (words.length <= 1) return words[0] ?? ""
	return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`
}
