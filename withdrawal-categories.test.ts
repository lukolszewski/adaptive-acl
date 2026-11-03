/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * From the answer a model actually sends to the answer the gate gives.
 *
 * The other tests each hold one layer: `extraction-schema.test.ts` checks what the wire may look like,
 * `auth-ledger.test.ts` checks what a fold stores and what `ledgerCovers` answers. Nothing there pinned the
 * route a user cares about: a withdrawal sentence arrives as JSON from a model, becomes ledger rows, and then
 * has to stop a real tool call. That route is what this file walks, end to end, with the raw wire payload as
 * the input — because the thing that breaks first is a SHAPE (a model answering an older single-string
 * field) and a shape only shows up if the test starts from one.
 *
 * Three properties:
 *   "leave X alone"        → every action on X, reads included, and inside X;
 *   "don't write in X"     → writes and deletes inside X, but a read of X is untouched;
 *   a grant never gets the wide form — `any` on a grant row authorises nothing at all.
 *
 * Targets are invented (`/srv/lockup`, `quiet-bucket`); the prose exists only to give the verbatim quote check
 * something to find, and no sentence here is a corpus case: a changed or new assertion must not read English
 * for its verdict — every judgement below is made on structured fields.
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { extractMessageGrants } from "./model-client.ts"
import { applyEvents, createLedger, eventsFromExtraction, ledgerCovers, readOnlyActive, type ExtractedEvent } from "./auth-ledger.ts"
import { runGate } from "./gate.ts"
import { createGrantStore } from "./session-grants.ts"
import type { ModelEndpoint } from "./model-client.ts"

const EP: ModelEndpoint = { baseUrl: "http://mock", model: "mock" }
const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

/** The one message the withdrawal is supposed to come from. The quotes below are substrings of it. */
const MESSAGE = "leave /srv/lockup alone until I tell you otherwise"

/** Serve ONE raw wire payload — the JSON a model sent, before any parsing. */
function mockWire(payload: unknown): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({
			ok: true,
			json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] }),
		})),
	)
}

/** The real route: raw model answer → parsed rows → ledger. No test-local fold. */
async function ledgerFromWire(payload: unknown, message = MESSAGE): Promise<{ ledger: ReturnType<typeof createLedger>; events: ExtractedEvent[] }> {
	mockWire(payload)
	const res = await extractMessageGrants(EP, message)
	if (!res.ok) throw new Error(`extraction call failed: ${res.error}`)
	const events = eventsFromExtraction(res.value, "m1", 1, message)
	const ledger = createLedger()
	applyEvents(ledger, events)
	return { ledger, events }
}

/** A revocation row in whichever shape the model sent it. */
const wire = (category: unknown, targets: string[], quote = "leave /srv/lockup alone") => ({
	grants: [],
	revocations: [{ action: "withdraw work", category, scope: "named", targetClass: "none", targets, quote }],
})

const T = (value: string) => ({ kind: "target" as const, value })

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("the shape a model sends decides nothing about what it withdrew", () => {
	it("the bare string an older wire used still withdraws — the schema offers both shapes", async () => {
		// This is the whole reason for `anyOf`: a model supervised on the old field answers a string, and losing
		// that category silently is the direction that costs an allow, not a prompt.
		const { ledger, events } = await ledgerFromWire(wire("delete_data", ["/srv/lockup"]))
		expect(events.filter((e) => e.type === "forbid").map((e) => e.category)).toEqual(["delete_data", "delete_data"])
		expect(ledgerCovers(ledger, "delete_data", [T("/srv/lockup/x.csv")]).forbidden).toBe(true)
	})

	it("a list withdraws every kind it names, and one junk value in it costs only itself", async () => {
		const { ledger, events } = await ledgerFromWire(wire(["delete_data", "nonsense_kind", "write_outside"], ["/srv/lockup"]))
		const kinds = new Set(events.filter((e) => e.type === "forbid").map((e) => e.category))
		expect([...kinds].sort()).toEqual(["delete_data", "write_outside"])
		expect(ledgerCovers(ledger, "write_outside", [T("/srv/lockup/x.csv")]).forbidden).toBe(true)
	})
})

describe("the gate honours a withdrawal on the tool call it is aimed at", () => {
	it("do-not-touch (`any`) blocks the delete, the write AND the read, through the gate", async () => {
		const { ledger } = await ledgerFromWire(wire(["any"], ["/srv/lockup"]))
		const calls: Array<[string, Record<string, unknown>]> = [
			["bash", { command: "rm /srv/lockup/x.csv" }],
			["write", { path: "/srv/lockup/x.csv", content: "x" }],
			["read", { path: "/srv/lockup/x.csv" }],
			["bash", { command: "cat /srv/lockup/x.csv" }],
		]
		for (const [tool, input] of calls) {
			const r = await runGate(tool, input, { policy: POLICY, ledger, userMessages: [MESSAGE] })
			expect(r.outcome, `${tool} ${JSON.stringify(input)}`).toBe("prompt")
			expect(r.reason).toContain("forbade")
			// A ban the ledger can answer needs no model call to be enforced.
			expect(r.modelCalls, `${tool} ${JSON.stringify(input)}`).toHaveLength(0)
			// Control: the same call with no row behind it is not answered by a ban, so the assertion above is
			// this row's doing and not the environment's (an outside-project path prompts here for its own reasons,
			// and a test that passes either way would be evidence of nothing).
			const control = await runGate(tool, input, { policy: POLICY, ledger: createLedger(), userMessages: [MESSAGE] })
			expect(control.reason, `${tool} ${JSON.stringify(input)}`).not.toContain("forbade")
		}
	})

	it("writes-only blocks writes and deletes inside the target and leaves a read alone", async () => {
		// The second rule, pinned at the hook: "not allowed to change X" is about changing it.
		const writesOnly = "you are not allowed to change anything in /srv/lockup"
		const { ledger } = await ledgerFromWire(
			wire(["write_outside", "delete_outside"], ["/srv/lockup"], "not allowed to change anything in /srv/lockup"),
			writesOnly,
		)
		const blocked: Array<[string, Record<string, unknown>]> = [
			["write", { path: "/srv/lockup/x.csv", content: "x" }],
			["bash", { command: "rm /srv/lockup/x.csv" }],
		]
		for (const [tool, input] of blocked) {
			const r = await runGate(tool, input, { policy: POLICY, ledger, userMessages: [writesOnly] })
			expect(r.outcome, `${tool} ${JSON.stringify(input)}`).toBe("prompt")
			expect(r.reason).toContain("forbade")
		}
		// …and the read is not the thing that was withdrawn: no forbid answers it, so the gate is left alone to
		// do what it does without this row (which, outside the project in a bare test env, is to ask anyway).
		expect(ledgerCovers(ledger, "read_only", [T("/srv/lockup/x.csv")]).forbidden).toBe(false)
		const read = await runGate("read", { path: "/srv/lockup/x.csv" }, { policy: POLICY, ledger, userMessages: [writesOnly] })
		expect(read.reason).not.toContain("forbade")
	})

	it("the ban is aimed at a target: work somewhere else is not blocked by it", async () => {
		const { ledger } = await ledgerFromWire(wire(["any"], ["/srv/lockup"]))
		expect(ledgerCovers(ledger, "delete_data", [T("/srv/other/x.csv")]).forbidden).toBe(false)
		const r = await runGate("bash", { command: "rm /srv/other/x.csv" }, { policy: POLICY, ledger, userMessages: [MESSAGE] })
		expect(r.reason).not.toContain("forbade")
	})

	it("an object-store ban reaches an object inside the bucket, at the gate too", async () => {
		const store = "do not touch quiet-bucket any more"
		const { ledger } = await ledgerFromWire(wire(["any"], ["quiet-bucket"], "do not touch quiet-bucket"), store)
		const r = await runGate("bash", { command: "aws s3 rm s3://quiet-bucket/exports/x.csv" }, { policy: POLICY, ledger, userMessages: [store] })
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
	})
})

describe("`any` with no object named stops the session, and never authorises", () => {
	it("a stop with nothing named prompts for a mutation anywhere (the read-only posture)", async () => {
		const message = "stop doing things to this machine until I say so"
		const { ledger, events } = await ledgerFromWire(
			{ grants: [], revocations: [{ action: "stop work", category: ["any"], scope: "everything", targetClass: "none", targets: [], quote: "stop doing things" }] },
			message,
		)
		// No target survives the verbatim check, so the wide stop must not be invented out of the category.
		expect(events.filter((e) => e.type === "forbid")).toHaveLength(0)
		// …but the sentence itself is a stop, and it is the POSTURE that answers, not a target ban.
		const posture = readOnlyActive(ledger)
		expect(posture?.quote).toBe("stop doing things")
		const r = await runGate("bash", { command: "rm -rf /srv/other/x" }, { policy: POLICY, ledger, userMessages: [message] })
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("not to change anything")
		// Control: without the row the same command is not stopped by a posture.
		const control = await runGate("bash", { command: "rm -rf /srv/other/x" }, { policy: POLICY, ledger: createLedger(), userMessages: [message] })
		expect(control.reason).not.toContain("not to change anything")
	})

	it("a grant row that claims `any` buys nothing: the work still costs its prompt", async () => {
		const message = "you can do whatever you like with /srv/lockup"
		mockWire({
			grants: [{ action: "any work", category: "any", kind: "entity", scope: "named", targetClass: "none", includesSecrets: false, targets: ["/srv/lockup"], quote: "whatever you like with /srv/lockup" }],
			revocations: [],
		})
		const res = await extractMessageGrants(EP, message)
		if (!res.ok) throw new Error(`extraction call failed: ${res.error}`)
		const events = eventsFromExtraction(res.value, "m1", 1, message)
		const ledger = createLedger()
		applyEvents(ledger, events)
		expect(ledgerCovers(ledger, "delete_data", [T("/srv/lockup/x.csv")]).covered).toBe(false)
		const r = await runGate("bash", { command: "rm /srv/lockup/x.csv" }, {
			policy: POLICY,
			grants: createGrantStore(),
			ledger,
			userMessages: [message],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.outcome).not.toBe("allow-granted")
	})
})

/**
 * The L-18 class: ONE message grants a folder and withdraws something in it, and the withdrawal's target is a
 * phrase rather than a name. Nothing here reads the sentence — "the model wrote a phrase" is a fact about the
 * SHAPE of the target value (it has a space in it), which is the one thing code is allowed to notice about a
 * target besides "the user said it".
 */
describe("a withdrawal whose target is a phrase cannot be outvoted by its own message's grant", () => {
	const message =
		"You can delete everything under ./build-cache, the whole folder, it is regenerable. Leave the build artefacts where they are for now."
	const payload = (revocations: unknown[]) => ({
		grants: [
			{
				action: "delete the folder",
				category: "delete_recursive",
				kind: "scope",
				scope: "named",
				targetClass: "none",
				includesSecrets: false,
				targets: ["./build-cache"],
				quote: "delete everything under ./build-cache",
			},
		],
		revocations,
	})
	const phrase = {
		action: "withdraw deletes",
		category: ["any"],
		scope: "named",
		targetClass: "none",
		targets: ["build artefacts"],
		quote: "Leave the build artefacts where they are",
	}

	it("the grant is kept, the sentence is kept as a defused row, and the answer is a deferral not an allow", async () => {
		const { ledger, events } = await ledgerFromWire(payload([phrase]), message)
		// The grant still registers — refusing it would cost prompts on every later action it really covers.
		expect(events.filter((e) => e.type === "grant").map((e) => `${e.category} ${e.value}`)).toEqual(["delete_recursive ./build-cache/"])
		// The model's own rows are untouched; the marker sits beside them and can match nothing.
		expect(events.filter((e) => e.type === "forbid").map((e) => e.category).sort()).toEqual(["*unknown*", "any", "any"])
		const verdict = ledgerCovers(ledger, "delete_recursive", [T("./build-cache/x")], POLICY.home, POLICY.project)
		expect(verdict.covered).toBe(false)
		expect(verdict.forbidden).toBe(false)
		expect(verdict.reason).toContain("deferred")
		// Control: without the withdrawal the same grant auto-answers the same action, so the deferral above is
		// the marker's doing and not a matcher that never worked.
		const { ledger: control } = await ledgerFromWire(payload([]), message)
		expect(ledgerCovers(control, "delete_recursive", [T("./build-cache/x")], POLICY.home, POLICY.project).covered).toBe(true)
	})

	it("through the gate: the delete asks instead of being granted", async () => {
		const { ledger } = await ledgerFromWire(payload([phrase]), message)
		const r = await runGate("bash", { command: "rm -rf ./build-cache" }, { policy: POLICY, ledger, userMessages: [message] })
		expect(r.outcome).toBe("prompt")
		expect(r.outcome).not.toBe("allow-granted")
		const { ledger: control } = await ledgerFromWire(payload([]), message)
		const c = await runGate("bash", { command: "rm -rf ./build-cache" }, { policy: POLICY, ledger: control, userMessages: [message] })
		expect(c.outcome).toBe("allow-granted")
	})

	it("the defusal is a deferral, not a veto: a grant the user makes afterwards answers again", async () => {
		// The bound on the whole mechanism. It may cost prompts inside one message; it may not lock the session,
		// so the ordinary newest-statement-wins rule must still be able to lift it.
		const { ledger } = await ledgerFromWire(payload([phrase]), message)
		mockWire({
			grants: [{ action: "delete the folder", category: "delete_recursive", scope: "named", kind: "scope", targetClass: "none", includesSecrets: false, targets: ["./build-cache"], quote: "go ahead and delete ./build-cache" }],
			revocations: [],
		})
		const later = await extractMessageGrants(EP, "go ahead and delete ./build-cache")
		if (!later.ok) throw new Error(`extraction call failed: ${later.error}`)
		applyEvents(ledger, eventsFromExtraction(later.value, "m2", 2, "go ahead and delete ./build-cache"))
		expect(ledgerCovers(ledger, "delete_recursive", [T("./build-cache/x")], POLICY.home, POLICY.project).covered).toBe(true)
		// …and the marker never turns into a ban of its own, under any category.
		const other = ledgerCovers(ledger, "write_outside", [T("/srv/elsewhere/x")], POLICY.home, POLICY.project)
		expect(other.forbidden).toBe(false)
	})

	it("a placeable target in the same message leaves no marker: the ban is answered by value", async () => {
		const named = { ...phrase, targets: ["./build-cache"] }
		const { ledger, events } = await ledgerFromWire(payload([named]), message)
		expect(events.filter((e) => e.type === "forbid").map((e) => e.category)).toEqual(["any", "any"])
		const verdict = ledgerCovers(ledger, "delete_recursive", [T("./build-cache/x")], POLICY.home, POLICY.project)
		expect(verdict.forbidden).toBe(true)
		expect(verdict.reason).toContain("user forbade")
	})
})
