/**
 * bash-walker-golden.ts — loader and comparer for `bash-walker.golden.jsonl` (§15).
 *
 * Not a `*.test.ts` file on purpose: vitest only collects tests, and the tests for parts 2 and 3
 * (`bash-walker-values.test.ts`, `bash-walker-heredoc.test.ts`) import this too.
 *
 * `compareCase` is deliberately stricter than the corpus needs:
 *   - accepted: every field of every command must deep-equal `expect` — argv, envVars, redirects,
 *     heredocs, text, start, end, connector, opaque — in the order they were emitted;
 *   - refused: `kind`, `reason` and `malformed` must equal. `nodeType` is a diagnostic (§1) and is
 *     never asserted.
 */

import { readFileSync } from "node:fs"
import path from "node:path"
import type { AstCommand, AstParse, AstRedirect } from "./bash-ast.ts"

export type GoldenCase = {
	id: string
	command: string
	expect: AstParse
	note?: string
}

/** One case that did not match, with the first difference found. */
export type Mismatch = { id: string; message: string }

const FILE = "bash-walker.golden.jsonl"

/** Read the corpus, in file order. `dir` defaults to this module's directory. */
export function loadGolden(dir?: string): GoldenCase[] {
	const file = path.join(dir ?? path.dirname(new URL(import.meta.url).pathname), FILE)
	const cases: GoldenCase[] = []
	for (const [index, line] of readFileSync(file, "utf8").split("\n").entries()) {
		const text = line.trim()
		if (!text) continue
		const raw = JSON.parse(text) as GoldenCase
		if (typeof raw.id !== "string" || typeof raw.command !== "string" || !raw.expect) {
			throw new Error(`${FILE} line ${index + 1}: not a golden case`)
		}
		cases.push(raw)
	}
	return cases
}

/** The cases whose id starts with one of these prefixes — the subset a caller owns. */
export function selectById(cases: readonly GoldenCase[], prefixes: readonly string[]): GoldenCase[] {
	return cases.filter((one) => prefixes.some((prefix) => one.id.startsWith(prefix)))
}

/**
 * §12.3 — the two reasons no input can produce: the parser was not loaded, or the parse ran past the
 * wall-clock budget in `bash-parser.ts`. They describe the machine, not the command, and they are the
 * only verdicts that can differ between two runs of the same input. Measured while pinning a 322-character
 * corpus command: under 48-way CPU contention 17 of 48 processes lost at least one parse to
 * `parse-aborted` (slowest 99 ms against a 50 ms budget), which is why an accepted case of that length
 * needs one more attempt before it may be called a contract violation.
 *
 * The retry is not a tolerance: the retried verdict is the one asserted, and an input that really cannot
 * be parsed still refuses on every attempt.
 */
const ENVIRONMENT_ABORT = ["parse-aborted", "parser-unavailable"]

export function parseWithEnvironmentRetry(parse: (command: string) => AstParse, command: string, attempts = 3): AstParse {
	let last = parse(command)
	for (let attempt = 1; attempt < attempts; attempt++) {
		if (!(last.kind === "unproven" && ENVIRONMENT_ABORT.includes(last.reason))) break
		last = parse(command)
	}
	return last
}

/** Compare one case. `null` means the walker's result is what the corpus requires. */
export function compareCase(one: GoldenCase, got: AstParse): Mismatch | null {
	const fail = (message: string): Mismatch => ({ id: one.id, message })
	if (got.kind === "unproven" || one.expect.kind === "unproven") {
		if (got.kind !== "unproven") return fail(`expected refusal ${describe(one.expect)}, got ${describe(got)}`)
		// Narrow the expectation as well as the result: `one.expect` is the same union, and reading `.reason` off
		// the un-narrowed union is what tsc flagged.
		if (one.expect.kind !== "unproven") return fail(`expected a refusal, got a simple command list`)
		const want = one.expect
		if (got.reason !== want.reason) return fail(`reason: want ${want.reason}, got ${got.reason}`)
		if (got.malformed !== want.malformed) return fail(`malformed: want ${want.malformed}, got ${got.malformed}`)
		return null
	}
	if (one.expect.kind !== "simple") return fail(`expected simple commands, got a refusal`)
	const want = one.expect.commands
	if (got.commands.length !== want.length) {
		return fail(`command count: want ${want.length}, got ${got.commands.length} (${got.commands.map((c) => c.argv.join(" ")).join(" ;; ")})`)
	}
	for (let i = 0; i < want.length; i++) {
		const message = compareCommand(want[i], got.commands[i])
		if (message) return fail(`commands[${i}]: ${message}`)
	}
	return null
}

/** The first difference between two commands, or null when every field matches. */
function compareCommand(want: AstCommand, got: AstCommand): string | null {
	if (!equal(want.argv, got.argv)) return `argv: want ${json(want.argv)}, got ${json(got.argv)}`
	if (!equal(want.envVars, got.envVars)) return `envVars: want ${json(want.envVars)}, got ${json(got.envVars)}`
	if (!equal(want.redirects.map(redirectKey), got.redirects.map(redirectKey))) {
		return `redirects: want ${json(want.redirects)}, got ${json(got.redirects)}`
	}
	if (!equal(want.heredocs, got.heredocs)) return `heredocs: want ${json(want.heredocs)}, got ${json(got.heredocs)}`
	if (want.text !== got.text) return `text: want ${json(want.text)}, got ${json(got.text)}`
	if (want.start !== got.start || want.end !== got.end) return `span: want ${want.start}..${want.end}, got ${got.start}..${got.end}`
	if (want.connector !== got.connector) return `connector: want ${json(want.connector)}, got ${json(got.connector)}`
	if (want.opaque !== got.opaque) return `opaque: want ${want.opaque}, got ${got.opaque}`
	return null
}

/** Redirect fields compared in a fixed order, so an absent `fd` and `fd: undefined` differ. */
function redirectKey(one: AstRedirect): string {
	return [one.op, one.target, one.fdDup, "fd" in one ? String(one.fd) : "-"].join("\u0000")
}

function equal(a: unknown, b: unknown): boolean {
	return JSON.stringify(a) === JSON.stringify(b)
}

function json(value: unknown): string {
	return JSON.stringify(value)
}

function describe(parsed: AstParse): string {
	return parsed.kind === "simple" ? `simple (${parsed.commands.length} commands)` : `unproven ${parsed.reason}`
}
