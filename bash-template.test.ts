/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * `parseBashTemplate` — the template parse of plan-runtime-values.md ("Template parse").
 *
 * One difference from `parseBashCommand` is allowed: a run-time value in an ARGUMENT position becomes a
 * slot instead of a refusal, and the placeholder stays in argv where it was. Everything else is pinned
 * here, because "one difference" is the whole contract:
 *
 *   - the plain parse's answer is byte-identical over the golden corpus and both eval case files
 *     (`parseBashCommand` is the same walk with the template flag off);
 *   - a template parse of an input the plain parse ACCEPTS differs from it by nothing but `slots`;
 *   - every position that is not an argument — the command word for a `$NAME`, redirect targets, env
 *     prefixes, here-string data, test operands — refuses exactly as it does today, with the same §12
 *     id, and so does every command whose arguments the program runs as code.
 */

import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import path from "node:path"
import { beforeAll, describe, expect, it } from "vitest"
import {
	parseBashCommand,
	parseBashTemplate,
	type Slot,
	type TemplateCommand,
	type TemplateParse,
} from "./bash-ast.ts"
import { initBashParser } from "./bash-parser.ts"
import { compareCase, loadGolden, parseWithEnvironmentRetry } from "./bash-walker-golden.ts"
import { walkBash } from "./bash-walker.ts"

beforeAll(async () => {
	await initBashParser()
})

/** The commands a template parse accepted. */
function templateOf(command: string): TemplateCommand[] {
	const parsed = parseBashTemplate(command)
	if (parsed.kind !== "simple") throw new Error(`${command} -> refused ${parsed.reason}`)
	return parsed.commands
}

/** The one command a single-command template parse accepted. */
function onlyCommand(command: string): TemplateCommand {
	const commands = templateOf(command)
	expect(commands).toHaveLength(1)
	return commands[0]
}

/** A template refusal, checked against the plain parse's answer for the same input. */
function refusedLikePlain(command: string): RefusalShape {
	const plain = parseBashCommand(command)
	const template = parseBashTemplate(command)
	expect(template.kind, command).toBe("unproven")
	const got = template as Extract<TemplateParse, { kind: "unproven" }>
	expect(got.reason, `${command}: template id must be the plain id`).toBe(plain.kind === "unproven" ? plain.reason : "simple")
	expect(got.malformed).toBe(plain.kind === "unproven" ? plain.malformed : false)
	return got
}

type RefusalShape = { reason: string; malformed: boolean }

// ---------------------------------------------------------------------------
// a run-time value in an argument position becomes a slot
// ---------------------------------------------------------------------------

describe("argument positions", () => {
	it("a partial quoted value: the word keeps the literal part, the slot says where the value sits", () => {
		const command = onlyCommand('echo "exit ${PIPESTATUS[0]}"')
		expect(command.argv).toEqual(["echo", "exit __TRACKED_VAR__"])
		expect(command.opaque).toBe(true)
		// `${PIPESTATUS[0]}` is a var slot named `PIPESTATUS`: the index is a position inside the value,
		// not a computation of the walker's. No `inner` — that field is a substitution's.
		expect(command.slots).toEqual([{ argIndex: 1, quoted: true, whole: false, source: "var", name: "PIPESTATUS", span: [11, 27] }])
	})

	it("a whole quoted value", () => {
		const command = onlyCommand('wc -l "$F"')
		expect(command.argv).toEqual(["wc", "-l", "__TRACKED_VAR__"])
		expect(command.slots).toEqual([{ argIndex: 2, quoted: true, whole: true, source: "var", name: "F", span: [7, 9] }])
	})

	it("a bare value: unquoted, and one whole argument", () => {
		const command = onlyCommand("cat $F")
		expect(command.argv).toEqual(["cat", "__TRACKED_VAR__"])
		expect(command.slots).toEqual([{ argIndex: 1, quoted: false, whole: true, source: "var", name: "F", span: [4, 6] }])
	})

	it("a bare value inside a longer word", () => {
		const command = onlyCommand("echo $X-suffix")
		expect(command.argv).toEqual(["echo", "__TRACKED_VAR__-suffix"])
		expect(command.slots).toEqual([{ argIndex: 1, quoted: false, whole: false, source: "var", name: "X", span: [5, 7] }])
	})

	it("a braced name reference, which the plain walk refuses in every position", () => {
		const command = onlyCommand('echo "${X}"')
		expect(command.argv).toEqual(["echo", "__TRACKED_VAR__"])
		expect(command.slots).toEqual([{ argIndex: 1, quoted: true, whole: true, source: "var", name: "X", span: [6, 10] }])
	})

	it("a special name carries the name the shell gives it", () => {
		const [slot] = onlyCommand('echo "$?"').slots
		expect(slot).toMatchObject({ source: "var", name: "?", quoted: true, whole: true })
	})

	it("a substitution: the slot carries the source text of the command that runs", () => {
		const commands = templateOf('git show "$(git rev-parse HEAD)"')
		// §6.2 — the substitution's own command is walked and emitted first, so the slot names a command
		// the walk has already vouched for.
		expect(commands.map((one) => one.argv)).toEqual([
			["git", "rev-parse", "HEAD"],
			["git", "show", "__CMDSUB_OUTPUT__"],
		])
		expect(commands[0].slots).toEqual([])
		expect(commands[1].slots).toEqual([
			{ argIndex: 2, quoted: true, whole: true, source: "cmdsub", inner: "git rev-parse HEAD", span: [10, 31] },
		])
	})

	it("backticks are a cmdsub, and `inner` is the text between them", () => {
		const commands = templateOf("echo `cat f`")
		expect(commands.map((one) => one.argv)).toEqual([["cat", "f"], ["echo", "__CMDSUB_OUTPUT__"]])
		expect(commands[1].slots).toEqual([{ argIndex: 1, quoted: false, whole: true, source: "cmdsub", inner: "cat f", span: [5, 12] }])
	})

	it("a substitution in COMMAND position is a slot whose inner is the program that runs", () => {
		// The plain walk refuses this (`command-substitution`); template mode can describe it because the
		// substitution's own command was walked and emitted. Resolution policy is not this module's job.
		const commands = templateOf('"$(curl x)"')
		expect(commands.map((one) => one.argv)).toEqual([["curl", "x"], ["__CMDSUB_OUTPUT__"]])
		expect(commands[1].slots).toEqual([{ argIndex: 0, quoted: true, whole: true, source: "cmdsub", inner: "curl x", span: [1, 10] }])
	})

	it("a value nested in a substitution is a slot of the inner command", () => {
		const commands = templateOf('echo "$(echo $Y)"')
		expect(commands.map((one) => one.argv)).toEqual([
			["echo", "__TRACKED_VAR__"],
			["echo", "__CMDSUB_OUTPUT__"],
		])
		expect(commands[0].slots).toEqual([{ argIndex: 1, quoted: false, whole: true, source: "var", name: "Y", span: [13, 15] }])
		expect(commands[1].slots).toEqual([{ argIndex: 1, quoted: true, whole: true, source: "cmdsub", inner: "echo $Y", span: [6, 16] }])
	})
})

describe("spans", () => {
	const cases = ['echo "exit ${PIPESTATUS[0]}"', 'wc -l "$F"', "cat $F", 'git show "$(git rev-parse HEAD)"', "echo `cat f`"]

	it("every span slices back to the expansion exactly, inside the command's own span", () => {
		for (const command of cases) {
			const all = templateOf(command).flatMap((parsed) => parsed.slots.map((slot) => ({ slot, command: parsed })))
			expect(all.length, command).toBeGreaterThan(0)
			for (const { slot, command: parsed } of all) {
				const written = command.slice(slot.span[0], slot.span[1])
				// The expansion is written inside the command it belongs to.
				expect(slot.span[0]).toBeGreaterThanOrEqual(parsed.start)
				expect(slot.span[1]).toBeLessThanOrEqual(parsed.end)
				// A span is the expansion itself — never the quotes around it — so it starts at `$` or a
				// backtick and cannot end with the closing quote.
				expect(written.startsWith("$") || written.startsWith("`")).toBe(true)
				expect(written.endsWith('"')).toBe(false)
				// A var slot's span names the variable it refers to; a cmdsub slot's own source is its inner.
				if (slot.source === "cmdsub") expect(written).toContain(slot.inner ?? "")
				else expect(written).toContain(slot.name ?? "")
			}
		}
	})

	it("a substitution's span is the whole expansion, delimiters included", () => {
		const [slot] = templateOf('git show "$(git rev-parse HEAD)"')[1].slots
		expect(slot.span).toEqual([10, 31])
		expect('git show "$(git rev-parse HEAD)"'.slice(10, 31)).toBe("$(git rev-parse HEAD)")
		expect(slot.inner).toBe("$(git rev-parse HEAD)".slice(2, -1))
	})

	it("a var's span is the reference, not the quotes around it", () => {
		const [slot] = onlyCommand('wc -l "$F"').slots
		expect('wc -l "$F"'.slice(slot.span[0], slot.span[1])).toBe("$F")
	})
})

describe("an assignment earlier in the same command", () => {
	// How it comes out: the statement-level assignment emits no command of its own (§5.2) and its value is
	// not an ARGUMENT, so it is no slot either. What is emitted is the substitution's own command (§6.2),
	// and the reference to the name is an ordinary var slot — `name: "X"` — which is all this module can
	// say: whether the reference resolves to the assignment's value is the resolver's decision.
	const command = 'X=$(git rev-parse HEAD); git show "$X"'

	it("emits the substitution's command, not the assignment", () => {
		const commands = templateOf(command)
		expect(commands.map((one) => one.argv)).toEqual([
			["git", "rev-parse", "HEAD"],
			["git", "show", "__TRACKED_VAR__"],
		])
		expect(commands.map((one) => one.envVars)).toEqual([[], []])
	})

	it("slots the reference, not the assignment", () => {
		const commands = templateOf(command)
		expect(commands[0].slots).toEqual([])
		expect(commands[1].slots).toEqual([{ argIndex: 2, quoted: true, whole: true, source: "var", name: "X", span: [35, 37] }])
	})
})

// ---------------------------------------------------------------------------
// what stays refused
// ---------------------------------------------------------------------------

describe("positions and commands that stay refused", () => {
	it("a value in command position is not a slot: which program runs is not knowable", () => {
		expect(refusedLikePlain("$CMD arg").reason).toBe("variable-expansion")
	})

	it("a redirect target", () => {
		expect(refusedLikePlain('echo hi > "$F"').reason).toBe("variable-expansion")
	})

	it("a shell's inline code", () => {
		expect(refusedLikePlain('sh -c "$X"').reason).toBe("variable-expansion")
	})

	it("a shell behind a wrapper is still a shell", () => {
		expect(refusedLikePlain('env LC_ALL=C sh -c "$X"').reason).toBe("variable-expansion")
	})

	it("xargs, whose arguments are the command it runs", () => {
		expect(refusedLikePlain('xargs rm "$X"').reason).toBe("variable-expansion")
	})

	it("find -exec, whose arguments are the command it runs", () => {
		expect(refusedLikePlain('find . -exec rm "$X" \\;').reason).toBe("variable-expansion")
	})

	it("an interpreter's inline code", () => {
		expect(refusedLikePlain('python3 -c "$X"').reason).toBe("variable-expansion")
	})

	it("a remote command line", () => {
		expect(refusedLikePlain('ssh host "rm $X"').reason).toBe("variable-expansion")
	})

	it("a shell builtin that runs its arguments as code", () => {
		expect(refusedLikePlain('eval "$X"').reason).toBe("variable-expansion")
	})

	it("control flow, before any value is looked at", () => {
		expect(refusedLikePlain('for f in *; do echo "$f"; done').reason).toBe("loop-body")
	})

	it("a here-string's data, which is never one of the command's argv words", () => {
		expect(refusedLikePlain('cat <<< "$X"').reason).toBe("variable-expansion")
	})

	it("a braced spelling the braces transform", () => {
		expect(refusedLikePlain('echo "${#X}"').reason).toBe("variable-expansion")
		expect(refusedLikePlain('echo "${X[$(id)]}"').reason).toBe("variable-expansion")
	})

	it("a caller-supplied positional parameter: not a name the resolver could look up", () => {
		expect(refusedLikePlain("echo $1").reason).toBe("variable-expansion")
	})

	it("a refused command inside a substitution refuses the template as a whole", () => {
		// The plain walk refuses the OUTER position first (`command-substitution`), so this id is the one
		// place the template walk answers differently: it walked the inside, and what it found there — a
		// loop the walker does not analyse — is the refusal. The template parse is refused either way.
		const refused = parseBashTemplate('echo "$(for i in 1; do echo x; done)"')
		expect(refused.kind === "unproven" ? refused.reason : "simple").toBe("loop-body")
	})
})

// ---------------------------------------------------------------------------
// the plain parse is byte-identical: the golden corpus, the eval case files, and the default
// ---------------------------------------------------------------------------

const GOLDEN = loadGolden()

/** The bash commands of an eval case file, in file order. */
function caseCommands(file: string): string[] {
	const rows = readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), file), "utf8").split("\n")
	return rows.flatMap((line) => {
		if (!line.trim()) return []
		const row = JSON.parse(line) as { tool?: string; input?: { command?: unknown } }
		return row.tool === "bash" && typeof row.input?.command === "string" ? [row.input.command] : []
	})
}

/**
 * One command's plain verdict, as one line: the refusal id and its `malformed` flag, or the commands it
 * emitted with every field. `parseWithEnvironmentRetry` (§12.3) is what keeps the two environment ids —
 * which describe the machine, not the command — from moving the digest under CPU contention.
 */
function verdictOf(command: string): string {
	const parsed = parseWithEnvironmentRetry(parseBashCommand, command)
	if (parsed.kind === "unproven") return `unproven ${parsed.reason} ${parsed.malformed}`
	return `simple ${JSON.stringify(parsed.commands)}`
}

/**
 * Digests of the plain walk over `testcases/cases-v2.jsonl` (58 bash commands) and `testcases/cases-ledger.jsonl`
 * (17), computed on `5570fec` — the commit that added the template types and before the template walk
 * existed — and again after it. Equal digests are the byte-identity proof: argv, spans, connectors,
 * redirects, heredocs, `opaque` and every refusal id of every one of those commands is unchanged.
 */
const PLAIN_DIGESTS: Record<string, { commands: number; digest: string }> = {
	"testcases/cases-v2.jsonl": { commands: 58, digest: "f08a81550f4892d71f251e2f88a92e36a6f155606e0e5a8d46bfc4018208ddd0" },
	"testcases/cases-ledger.jsonl": { commands: 17, digest: "1ed174e33056d5d8680292351b48d9a64136865f988248ce47566d3ee736823e" },
}

describe("parseBashCommand is unchanged", () => {
	for (const file of Object.keys(PLAIN_DIGESTS)) {
		it(`over ${file}`, () => {
			const commands = caseCommands(file)
			expect(commands).toHaveLength(PLAIN_DIGESTS[file].commands)
			const digest = createHash("sha256").update(commands.map(verdictOf).join("\n")).digest("hex")
			expect(digest).toBe(PLAIN_DIGESTS[file].digest)
		})
	}

	it("over the golden corpus: every case, compared against the corpus's own expectation", () => {
		for (const one of GOLDEN) {
			const mismatch = compareCase(one, parseWithEnvironmentRetry(parseBashCommand, one.command))
			expect(mismatch, mismatch ? `${mismatch.id}: ${mismatch.message}` : undefined).toBeNull()
		}
	})

	it("the template walk is off unless it is asked for", () => {
		for (const command of ["echo hi", 'echo "$X"', "cat $F | wc -l", 'git show "$(git rev-parse HEAD)"']) {
			expect(walkBash(command, "plain"), command).toEqual(walkBash(command))
		}
		// No command of a plain parse carries `slots` at all — not an empty array, no property.
		const plain = parseBashCommand('echo "$X"')
		expect(plain.kind).toBe("unproven")
		const accepted = parseBashCommand('echo "a $HOME b"')
		if (accepted.kind !== "simple") throw new Error("fixture")
		expect(Object.keys(accepted.commands[0])).not.toContain("slots")
	})
})

describe("the template walk loosens nothing else", () => {
	// Every input the plain walk ACCEPTS must come out of the template walk with the same commands,
	// differing only by the `slots` property. Anything else would be a second change hiding behind this
	// one — a redirect, a span, a connector, an `opaque` flag — and this is where it would show.
	const accepted = [
		...GOLDEN.map((one) => one.command),
		...caseCommands("testcases/cases-v2.jsonl"),
		...caseCommands("testcases/cases-ledger.jsonl"),
	]

	/** `parseWithEnvironmentRetry` for the template parse: same retry, but the commands keep their slots. */
	function templateWithRetry(command: string, attempts = 3): TemplateParse {
		let last = parseBashTemplate(command)
		for (let attempt = 1; attempt < attempts; attempt++) {
			if (!(last.kind === "unproven" && ["parse-aborted", "parser-unavailable"].includes(last.reason))) break
			last = parseBashTemplate(command)
		}
		return last
	}

	it("a template parse of an accepted command is the plain parse plus slots", () => {
		let checked = 0
		for (const command of accepted) {
			const plain = parseWithEnvironmentRetry(parseBashCommand, command)
			if (plain.kind !== "simple") continue
			const template = templateWithRetry(command)
			expect(template.kind, `${command}: the template walk refused what the plain walk accepted`).toBe("simple")
			if (template.kind !== "simple") continue
			const stripped = template.commands.map(({ slots, ...rest }) => rest)
			expect(stripped, command).toEqual(plain.commands)
			checked++
		}
		// The invariant is only worth its name if it actually looked at something.
		expect(checked).toBeGreaterThan(100)
	})
})

// ---------------------------------------------------------------------------
// the shape of a slot
// ---------------------------------------------------------------------------

describe("slot shape", () => {
	it("a var slot has a name and no inner; a cmdsub slot has an inner and no name", () => {
		const varSlot: Slot = onlyCommand("cat $F").slots[0]
		expect(varSlot).toHaveProperty("name")
		expect(varSlot).not.toHaveProperty("inner")
		// The substitution's own command is emitted first (§6.2), so the slot is on the second command.
		const substitutionSlot: Slot = templateOf('echo "$(id)"')[1].slots[0]
		expect(substitutionSlot).toHaveProperty("inner")
		expect(substitutionSlot).not.toHaveProperty("name")
	})

	it("slots are in the order their words were emitted", () => {
		const slots = onlyCommand('echo "$A" "$B"').slots
		expect(slots.map((one) => [one.argIndex, one.name])).toEqual([
			[1, "A"],
			[2, "B"],
		])
	})

	it("a word with two values of its own is one arrangement of them, and one slot each", () => {
		// Not a claim about which is which at run time — only that both are reported, in source order,
		// on the one argument they share.
		const command = onlyCommand('echo "$A-$B"')
		expect(command.argv).toEqual(["echo", "__TRACKED_VAR__-__TRACKED_VAR__"])
		expect(command.slots.map((one) => one.name)).toEqual(["A", "B"])
		expect(command.slots.every((one) => one.argIndex === 1 && !one.whole)).toBe(true)
	})
})
