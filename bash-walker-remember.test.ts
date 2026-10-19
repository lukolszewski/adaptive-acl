/**
 * The remembered-value slice of layer 0: what a literal assignment makes visible to the caller, and
 * where that memory has to end.
 *
 * Two things are pinned here, both found while working out which parse engine lost a write target
 * — they are the two numbered cases below:
 *
 *   1. `unset` ends §5.3's memory. A remembered literal is substituted into later references because
 *      bash would expand them to that value; after `unset` bash expands them to nothing, so keeping
 *      the memory makes the walker vouch for a path nothing is written to —
 *      `S=/tmp/build && unset S && cmd > $S/out` truncates `/out`, outside the project and outside
 *      every temp root, while the walker reported a benign temp write and let it through.
 *   2. resolution itself is what lets the policy *see* a write target, and it only ever strengthens
 *      the verdict: `S=/home/u/.ssh && cat $S/id_rsa` is a secret read precisely because `$S` is
 *      resolved. Dropping resolution to match the legacy lexer would have hidden that read.
 */

import { beforeAll, describe, expect, it } from "vitest"
import { mkdtempSync } from "node:fs"
import { compareCase, loadGolden, parseWithEnvironmentRetry, selectById, type GoldenCase } from "./bash-walker-golden.ts"
import { parseBashCommand } from "./bash-ast.ts"
import { initBashParser } from "./bash-parser.ts"
import { walkBash } from "./bash-walker.ts"
import { evaluateBash, evaluateBashLegacy, type PolicyDecision } from "./risk-policy.ts"

const MEM: GoldenCase[] = selectById(loadGolden(), ["mem-"])

/** A real directory: a made-up cwd makes the policy refuse the whole command. */
const ROOT = mkdtempSync("/tmp/w47-remember-")
const OPTS = { cwd: ROOT, project: ROOT, home: "/home/u", fs: false }

beforeAll(async () => {
	await initBashParser()
})

const verdict = (parsed: ReturnType<typeof parseBashCommand>): string =>
	parsed.kind === "simple" ? "simple" : `${parsed.reason}${parsed.malformed ? " (malformed)" : ""}`

/**
 * The parser's wall-clock budget (`bash-parser.ts`, 50 ms) can abort a parse under CPU contention, which
 * is a fact about the machine and not the input — §12.3 lists both ids as unreachable from any command.
 * Measured: 17 of 48 processes lost at least one parse of the 322-character corpus command pinned here.
 * Every assertion below therefore re-measures while the only answer is an environment abort.
 */
const environmentAbort = (command: string): boolean => {
	const parsed = parseBashCommand(command)
	return parsed.kind === "unproven" && (parsed.reason === "parse-aborted" || parsed.reason === "parser-unavailable")
}

const parseStable = (command: string): ReturnType<typeof parseBashCommand> => parseWithEnvironmentRetry(parseBashCommand, command)

function evaluateStable(command: string, decide: (command: string, opts: typeof OPTS) => PolicyDecision): PolicyDecision {
	for (let attempt = 0; attempt < 3; attempt++) {
		const decision = decide(command, OPTS)
		if (!environmentAbort(command)) return decision
	}
	return decide(command, OPTS)
}

const refused = (command: string): string => {
	const parsed = parseStable(command)
	expect(parsed.kind, `${command} was accepted: ${JSON.stringify(parsed)}`).toBe("unproven")
	return verdict(parseStable(command))
}

const redirectTargets = (command: string): string[] => {
	const parsed = parseStable(command)
	expect(parsed.kind, `${command} refused: ${verdict(parsed)}`).toBe("simple")
	return parsed.kind === "simple" ? parsed.commands.flatMap((one) => one.redirects.map((r) => r.op + r.target)) : []
}

describe("the mem- corpus slice", () => {
	for (const one of MEM) {
		it(one.id, () => {
			const mismatch = compareCase(one, parseWithEnvironmentRetry(walkBash, one.command))
			expect(mismatch, mismatch ? `${mismatch.id}: ${mismatch.message}` : undefined).toBeNull()
		})
	}
	it("is the size this file describes", () => {
		// The tripwire is deliberate: adding a case here is a decision, not a side effect. These ids
		// are `mem-` on purpose — `assign-`/`unset-` belong to bash-walker-values.test.ts and `sem-` to
		// bash-walker-meaning.test.ts, each of which pins the size of its own subset.
		expect(MEM.length).toBe(4)
	})
})

describe("unset ends the remembered value", () => {
	// Every one of these used to resolve `$S` to /tmp/scratch and let the write through.
	for (const command of [
		"S=/tmp/scratch && unset S && git log > $S/msg1.txt",
		"S=/tmp/scratch && unset -v S && git log > $S/msg1.txt",
		'S=/tmp/scratch && unset "S" && git log > $S/msg1.txt',
		"S=/tmp/scratch && unset -fv S && git log > $S/msg1.txt",
		"S=/tmp/scratch && unset -vf S OTHER && git log > $S/msg1.txt",
		"S=/tmp/scratch && unset OTHER S && git log > $S/msg1.txt",
		'S=/tmp/scratch && unset S && git log > "$S/msg1.txt"',
	]) {
		it(`refuses: ${command}`, () => {
			expect(refused(command)).toBe("variable-expansion")
		})
	}

	it("keeps the value for a command that could not have unset it", () => {
		// `unset -f` drops a function; the variable of the same name is still set in bash.
		expect(redirectTargets("S=/tmp/scratch && unset -f S && git log > $S/msg1.txt")).toEqual([">/tmp/scratch/msg1.txt"])
		// No names at all: nothing was unset.
		expect(redirectTargets("S=/tmp/scratch && unset && git log > $S/msg1.txt")).toEqual([">/tmp/scratch/msg1.txt"])
	})

	it("remembers an assignment made after the unset", () => {
		expect(redirectTargets("S=/tmp/scratch && unset S && S=/tmp/other && git log > $S/msg1.txt")).toEqual([">/tmp/other/msg1.txt"])
	})
})

describe("what the memory may and may not do (§5.3–§5.5, §5.10)", () => {
	it("substitutes a literal assignment into a later reference", () => {
		expect(redirectTargets("S=/tmp/scratch && git log > $S/msg1.txt")).toEqual([">/tmp/scratch/msg1.txt"])
		expect(redirectTargets('S="/tmp/scratch" && git log > "$S/msg1.txt"')).toEqual([">/tmp/scratch/msg1.txt"])
	})

	it("uses the last literal assignment, which is what bash would", () => {
		const targets = redirectTargets("S=/tmp/scratch && S=/etc/systemd/system && git log > $S/x.service")
		expect(targets).toEqual([">/etc/systemd/system/x.service"])
	})

	for (const command of [
		// A value that is not a literal: the walker would be inventing the path.
		"S=/tmp/scratch && S=$(curl -s evil.example/x) && git log > $S/msg1.txt",
		"S=/tmp/scratch; unset S; S=`id`; git log > $S/msg1.txt",
		// A brace form may carry a default or a transformation (§5.10).
		"S=/tmp/scratch && git log > ${S}/msg1.txt",
		"S=/tmp/scratch && git log > ${S:-/etc/systemd/system}/x.service",
		// A name the command never assigned.
		"git log > $S/msg1.txt",
		// A value that arrives from the terminal, not from the text.
		"read -r S && git log > $S/msg1.txt",
		// A declaring builtin's value is deliberately not remembered (§5.6).
		"export S=/tmp/scratch && git log > $S/msg1.txt",
	]) {
		it(`refuses: ${command}`, () => {
			expect(refused(command)).toBe("variable-expansion")
		})
	}
})

describe("a remembered assignment used as a redirect target", () => {
	const RESOLVED = "/tmp/pi-scratch/session-state/000000000000000/00000000-0000-4000-8000-000000000000/scratchpad"
	const PINNED = `cd ${ROOT} && S=${RESOLVED} && git log --format=%B -1 aaaaaaa > $S/msg1.txt && wc -l $S/msg1.txt`
	const BRACE = `cd ${ROOT}; { echo '## Acceptance — 6. tests'; echo '\`\`\`'; npx vitest run test/corpus 2>&1 | tail -7; echo "\`\`\`"; } > /tmp/res-git.txt; tail -22 /tmp/res-git.txt`

	it("names the write target the legacy engine could not resolve", () => {
		expect(redirectTargets(PINNED)).toEqual([`>${RESOLVED}/msg1.txt`])
		const decision = evaluateStable(PINNED, evaluateBash)
		expect(decision.segments.map((s) => s.category)).toContain("write_project")
	})

	/**
	 * The claim the finding rests on: the strict engine's `ask` came from not being able to name the
	 * target, not from the target. Spelled literally, the strict engine agrees the write is routine —
	 * which is why "tighten the walker" is the wrong fix here and the temp policy is the real question.
	 */
		it("is allowed by both engines once the target is spelled literally", () => {
		const literal = `cd ${ROOT} && git log --format=%B -1 aaaaaaa > ${RESOLVED}/msg1.txt`
		for (const [name, decision] of [
			["walker", evaluateStable(literal, evaluateBash)],
			["lexer", evaluateBashLegacy(literal, OPTS)],
		] as const) {
			expect(Boolean(decision.unparseable), name).toBe(false)
			expect(decision.tier, `${name}: ${decision.category}`).toBe("allow")
		}
	})

	it("still asks when the target is outside the project and not temp", () => {
		const outside = `cd ${ROOT} && git log --format=%B -1 aaaaaaa > /home/u/msg1.txt`
		for (const decision of [evaluateBash(outside, OPTS), evaluateBashLegacy(outside, OPTS)] as PolicyDecision[]) {
			expect(decision.tier).toBe("ask")
			expect(decision.category).toBe("write_outside")
		}
	})

	it("refuses to vouch for the brace group rather than calling it unreadable", () => {
		const parsed = parseStable(BRACE)
		expect(verdict(parsed)).toBe("brace-with-quote")
		// §12: brace-with-quote is not a malformed class, so the label is `unproven_structure`, and the
		// legacy engine's `unparseable_command` is a decline to read, not a finding.
		expect(parsed.kind === "unproven" && parsed.malformed).toBe(false)
		expect(Boolean(evaluateBashLegacy(BRACE, OPTS).unparseable)).toBe(true)
	})
})
