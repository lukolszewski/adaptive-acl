/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * "you're allowed to write temporary files" is a permission, and its object is a CLASS.
 *
 * The sentence names no path, so nothing in it survives a verbatim-target check — and reading "temporary"
 * out of English in code is forbidden. The split is therefore: the MODEL marks the row with a
 * structured class (`targetClass: "temp_files"`), CODE owns what that class means
 * (`risk-paths.tempGrantDirs()` — /tmp, /var/tmp, $TMPDIR), and the ledger gets one scope row per root.
 *
 * What the class may carry is bounded by the category on the row: read and write (and delete) because you
 * cannot write a directory you may not open or list, and RUN only when the user said the code half — which
 * arrives as a second row, because "one row PER EFFECT" is the extraction prompt's rule. `read_secret` is
 * never in the list: a scratch directory is where a script dumps what it read, so "temp files" is not a
 * licence to go looking for credentials.
 *
 * The extractions below are recorded completions: a model's answer to each message, taken verbatim.
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { applyEvent, createLedger, extractionStats, eventsFromExtraction, resetExtractionStats, type Ledger, type MessageGrantExtraction } from "./auth-ledger.ts"
import { tempGrantDirs } from "./risk-paths.ts"
import { runGate } from "./gate.ts"
import type { PolicyOptions } from "./risk-policy.ts"

const POLICY: PolicyOptions = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }
const EP = { baseUrl: "http://mock", model: "mock" }

/** Every temp root the class can mean, in the shape the ledger stores a scope row. */
const TEMP_VALUES = tempGrantDirs().map((d) => `${d}/`)

function parse(json: string): MessageGrantExtraction {
	const v = JSON.parse(json) as MessageGrantExtraction
	return { grants: v.grants ?? [], revocations: v.revocations ?? [] }
}

/** Fold an extraction into a ledger exactly the way the session does. */
function ledgerFrom(x: MessageGrantExtraction, messageText: string): Ledger {
	const ledger = createLedger()
	for (const ev of eventsFromExtraction(x, "m1", 1, messageText)) applyEvent(ledger, ev)
	return ledger
}

async function gate(command: string, ledger?: Ledger) {
	return runGate("bash", { command }, { policy: POLICY, ledger })
}

afterEach(() => {
	vi.unstubAllGlobals()
	resetExtractionStats()
})

/**
 * Recorded. One write row, classed. This model collapsed "write and execute" into a single row — the honest
 * answer to a sentence whose second effect it did not separate — and the fail-safe of that is a prompt for
 * the run, never a silent allow.
 */
const WRITE_ONLY_MSG = "you're allowed to write temporary files"
const WRITE_ONLY = parse(`{"grants":[{"action":"write temporary files","category":"write_outside","kind":"scope","scope":"named","targetClass":"temp_files","includesSecrets":false,"targets":[],"quote":"you're allowed to write temporary files"}],"revocations":[]}`)

/**
 * Recorded: the same sentence with "and execute" answered as TWO rows — the write and the run — which is
 * what "one row PER EFFECT" asks for and what makes the run half checkable in code without reading a single
 * word of the sentence.
 */
const WRITE_RUN_MSG = "you are allowed to write and execute temporary files"
const WRITE_RUN = parse(`{"grants":[{"action":"write temporary files","category":"write_outside","kind":"scope","scope":"named","targetClass":"temp_files","includesSecrets":false,"targets":[],"quote":"you are allowed to write and execute temporary files"},{"action":"execute temporary files","category":"run_project_code","kind":"scope","scope":"named","targetClass":"temp_files","includesSecrets":false,"targets":[],"quote":"you are allowed to write and execute temporary files"}],"revocations":[]}`)

/** Recorded for a sentence that DOES write a path: class plus target. */
const NAMED_TMP_MSG = "use /tmp for the scratch data, do whatever you need there"
const NAMED_TMP = parse(`{"grants":[{"action":"write scratch files","category":"write_outside","kind":"scope","scope":"named","targetClass":"temp_files","includesSecrets":false,"targets":["/tmp"],"quote":"use /tmp for the scratch data"}],"revocations":[]}`)

/** Recorded for the segment `python3 /tmp/s.py`. */
const RUN_TMP = { effect: "run_project_code", targets: ["/tmp/s.py"], outside_project: true, confidence: "high" }
const GRANT_NO = { authorized: "no", effects: [], allowed_targets: [], forbidden_targets: [], quote: "" }

function stubEffect(answer: unknown) {
	vi.stubGlobal("fetch", async (_url: string, init: Record<string, unknown>) => {
		const body = JSON.parse(String(init.body)) as { response_format?: { json_schema?: { name?: string } } }
		const payload = body.response_format?.json_schema?.name === "effect" ? answer : GRANT_NO
		const json = { choices: [{ message: { content: JSON.stringify(payload) } }] }
		return { ok: true, status: 200, json: async () => json } as unknown as Response
	})
}

describe("the class becomes one scope row per temp root", () => {
	it("registers a row for every root the class means, and nothing else", () => {
		const events = eventsFromExtraction(WRITE_ONLY, "m1", 1, WRITE_ONLY_MSG)
		expect(events.length).toBe(TEMP_VALUES.length)
		for (const ev of events) {
			expect(ev.type).toBe("grant")
			expect(ev.category).toBe("write_outside")
			expect(ev.kind).toBe("scope")
			expect(TEMP_VALUES).toContain(ev.value)
		}
		// The class names scratch directories, so nothing in the result may point at the project or home.
		expect(events.some((e) => e.value === "/home/u/" || e.value === "/home/u/proj/")).toBe(false)
	})

	it("needs no path in the sentence — the quote is the check, not the target", () => {
		// The message contains no directory at all. `targetNamedByUser` would drop this row, which is why a
		// class-derived row bypasses it: the object is the class, and the verbatim guard is the QUOTE.
		expect(WRITE_ONLY_MSG).not.toContain("/")
		const events = eventsFromExtraction(WRITE_ONLY, "m1", 1, WRITE_ONLY_MSG)
		expect(events.length).toBe(TEMP_VALUES.length)
	})

	it("still drops the row when the quote is not the user's own words", () => {
		const forged = parse(JSON.stringify({ ...WRITE_ONLY, grants: [{ ...WRITE_ONLY.grants[0]!, quote: "you may delete the whole disk" }] }))
		expect(eventsFromExtraction(forged, "m1", 1, WRITE_ONLY_MSG)).toEqual([])
	})

	it("keeps the sentence's own path when there is one (the class does not replace targets it cannot see)", () => {
		const events = eventsFromExtraction(NAMED_TMP, "m1", 1, NAMED_TMP_MSG)
		expect(events.length).toBeGreaterThan(0)
		expect(events.every((e) => TEMP_VALUES.includes(e.value))).toBe(true)
	})

	it("runs on the roots the machine actually has", () => {
		// $TMPDIR is wherever this process says it is; the rows must follow, with no duplicate for /tmp.
		const unique = new Set(TEMP_VALUES)
		expect(unique.size).toBe(TEMP_VALUES.length)
		expect(TEMP_VALUES).toContain("/tmp/")
		expect(TEMP_VALUES).toContain("/var/tmp/")
	})
})

describe("at the gate: write and read yes, run only when the user said it", () => {
	it("a write to a temp root runs (layer 0 always allowed temp writes, and the grant keeps it quiet)", async () => {
		const ledger = ledgerFrom(WRITE_ONLY, WRITE_ONLY_MSG)
		expect((await gate("echo note > /tmp/note.txt", ledger)).outcome).toBe("allow")
	})

	it("a READ of a temp root is covered by that write grant (a write grant also permits reading)", async () => {
		const ledger = ledgerFrom(WRITE_ONLY, WRITE_ONLY_MSG)
		const r = await gate("cat /tmp/cpu_gpu.txt", ledger)
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
		expect(r.category).toBe("read_only")
	})

	it("and reading a temp file is NOT coverage for running code that was never mentioned", async () => {
		stubEffect(RUN_TMP)
		const ledger = ledgerFrom(WRITE_ONLY, WRITE_ONLY_MSG)
		const r = await runGate("bash", { command: "python3 /tmp/s.py" }, { policy: POLICY, endpoint: EP, userMessages: [WRITE_ONLY_MSG], ledger })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("run_project_code")
		expect(r.modelCalls.filter((c) => c.task === "effect")).toHaveLength(1)
	})

	it("when the model splits the effects, the run row arrives and the run is answered", async () => {
		stubEffect(RUN_TMP)
		const ledger = ledgerFrom(WRITE_RUN, WRITE_RUN_MSG)
		const run = await runGate("bash", { command: "python3 /tmp/s.py" }, { policy: POLICY, endpoint: EP, userMessages: [WRITE_RUN_MSG], ledger })
		expect(run.outcome).toBe("allow-granted")
		expect(run.grantedBy).toBe("ledger")
		// The write half is still there too — one message, two rows, two effects covered.
		expect((await gate("cat /tmp/cpu_gpu.txt", ledger)).outcome).toBe("allow-granted")
	})

	it("a credential in a temp directory follows the write grant, while a temp READ grant still does not", async () => {
		// A write row covers the read, credentials included — an edit needs a read first — so the read is
		// covered by the same permission that allowed the file to be written there. The other half is
		// untouched and is what is pinned second: a temp grant that only allows READING buys no secret read.
		const ledger = ledgerFrom(WRITE_RUN, WRITE_RUN_MSG)
		const r = await gate("cat /tmp/.aws_credentials", ledger)
		expect(r.category).toBe("read_secret")
		expect(r.outcome).toBe("allow-granted")
		const readOnly = ledgerFrom({ ...WRITE_ONLY, grants: WRITE_ONLY.grants.map((g) => ({ ...g, category: "read_only" })) }, WRITE_ONLY_MSG)
		expect((await gate("cat /tmp/.aws_credentials", readOnly)).outcome).toBe("prompt")
	})
})

describe("garbage from the model costs a prompt, never an allow", () => {
	it("a class on a category a temp directory cannot carry registers nothing", () => {
		const row = { ...WRITE_ONLY.grants[0]!, category: "cluster_mutation" }
		const events = eventsFromExtraction(parse(JSON.stringify({ grants: [row], revocations: [] })), "m1", 1, WRITE_ONLY_MSG)
		expect(events).toEqual([])
		expect(extractionStats.unmapped).toBe(1)
	})

	it("so does a secret category — the class never widens the secret gate", () => {
		const row = { ...WRITE_ONLY.grants[0]!, category: "read_secret" }
		expect(eventsFromExtraction(parse(JSON.stringify({ grants: [row], revocations: [] })), "m1", 1, WRITE_ONLY_MSG)).toEqual([])
	})

	it("a value outside the enum becomes \"none\", which is the narrow reading", async () => {
		// `parseGrantTargetClass` cannot invent a class: with "banana" the row falls back to the target path,
		// and this row has no targets, so it registers nothing — the same outcome as a missing field.
		const row = { ...WRITE_ONLY.grants[0]!, targetClass: "banana" }
		const events = eventsFromExtraction(parse(JSON.stringify({ grants: [row], revocations: [] })), "m1", 1, WRITE_ONLY_MSG)
		expect(events).toEqual([])
		expect(extractionStats.unmapped).toBe(1)
	})

	it("a class cannot name the plugin's own rule files: the row is stored as temp scopes only", () => {
		// A grant that could name `rule_files` would let a sentence about scratch space edit the allow-list.
		// The schema cannot even express it (the grant enum is none|temp_files), and the stored rows show it.
		const ledger = ledgerFrom(WRITE_ONLY, WRITE_ONLY_MSG)
		expect(ledger.grants.every((g) => TEMP_VALUES.includes(g.value))).toBe(true)
		expect(ledger.grants.some((g) => String(g.value).includes("permission-modes"))).toBe(false)
		expect(ledger.grants.some((g) => g.category === "*")).toBe(false)
	})

	it("an `everything` row still behaves as it did before the class existed", () => {
		const message = "go back to editing temporary files"
		const row = { ...WRITE_ONLY.grants[0]!, scope: "everything", quote: "go back to editing temporary files" }
		const events = eventsFromExtraction(parse(JSON.stringify({ grants: [row], revocations: [] })), "m1", 1, message)
		expect(events.map((e) => e.type)).toEqual(["readonly-off"])
	})
})
