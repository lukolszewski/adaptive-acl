/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Two structural fixes, pinned against recorded model output from the extraction prompt whose fields this
 * ledger reads.
 *
 * Every extraction JSON below is verbatim recorded model output, not an idealised fixture: a model's answer
 * to the message quoted beside it, at temperature 0. Two of the rows below changed shape when the
 * extraction prompt gained the fields this ledger reads:
 *   - the force-push sentence no longer extracts a revocation at all (the model reads "I know the branch
 *     history is messed up" as commentary, not a withdrawal), so the defused-row pin now uses a labelled
 *     unplaceable row;
 *   - the image sentence's revocation comes back with a CATEGORY (`container_mutation`, scope `category`),
 *     which is exactly what this ledger reads — so the row is no longer invisible to `forbidCompatible` and
 *     the verdict strengthens from "deferred" to "forbidden".
 *
 * Two recorded cases, both of which failed before the fixes:
 *   the force-push case  expect allow, got prompt  — a pronoun-target revocation the code widened into a
 *          session-wide read-only lock (`all: false` was ignored).
 *   the image case  expect block, got allow  — a newer forbid invisible to `forbidCompatible`, so the
 *          ledger auto-allowed a delete the user had just withdrawn.
 */
import { describe, expect, it, vi, afterEach } from "vitest"
import {
	applyEvent,
	applyEvents,
	createLedger,
	importLedger,
	serializeLedger,
	eventsFromExtraction,
	explainLedgerCover,
	ledgerCovers,
	readOnlyActive,
} from "./auth-ledger.ts"
import { runGate } from "./gate.ts"
import { createGrantStore } from "./session-grants.ts"
import type { Entity } from "./risk-policy.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

/** The extraction payload as the model returned it (MessageExtraction shape). */
type Recorded = Parameters<typeof eventsFromExtraction>[0]

// ---------------------------------------------------------------- force-push case (recorded)

const FORCE_PUSH_TEXT = "yes, force-push it, I know the branch history is messed up"
const FORCE_PUSH_EXTRACTION = {
	grants: [
		{
			action: "force push to remote",
			category: "vcs_force_protected",
			kind: "entity",
			scope: "named",
			includesSecrets: false,
			targets: ["it"],
			quote: "force-push it",
		},
	],
	// Recorded: NO revocation. An earlier recording had
	// `{action: "rewrite history", targets: ["it"], all: false, quote: "I know the branch history is messed up"}`
	// — a clause the prompt now tells the model not to extract ("saying what IS in scope is not a
	// withdrawal"), which is the other half of this fix.
	revocations: [],
} satisfies Recorded

const FORCE_PUSH_TARGETS = [T("origin/feature/retry-logic"), T("origin/*")]

function forcePushLedger(extraction: Recorded = FORCE_PUSH_EXTRACTION) {
	const ledger = createLedger()
	applyEvents(ledger, eventsFromExtraction(extraction, "m1", 0, FORCE_PUSH_TEXT))
	return ledger
}

// ---------------------------------------------------------------- image-delete case (recorded)

const IMAGE_GRANT_TEXT = "you can delete the payments:staging image"
const IMAGE_GRANT_EXTRACTION = {
	grants: [
		{
			action: "delete image",
			category: "container_mutation",
			kind: "entity",
			scope: "named",
			includesSecrets: false,
			targets: ["payments:staging"],
			quote: "you can delete the payments:staging image",
		},
	],
	revocations: [],
} satisfies Recorded

const IMAGE_REVOKE_TEXT = "actually never mind, do not delete any images"
const IMAGE_REVOKE_EXTRACTION = {
	grants: [],
	revocations: [
		{
			action: "delete images",
			category: "container_mutation",
			scope: "category",
			targetClass: "none",
			targets: [],
			all: true,
			quote: "do not delete any images",
		},
	],
} satisfies Recorded

const IMAGE_TARGETS = [T("payments:staging")]

function imageLedger(): ReturnType<typeof createLedger> {
	const ledger = createLedger()
	applyEvents(ledger, eventsFromExtraction(IMAGE_GRANT_EXTRACTION, "m1", 0, IMAGE_GRANT_TEXT))
	applyEvents(ledger, eventsFromExtraction(IMAGE_REVOKE_EXTRACTION, "m2", 1, IMAGE_REVOKE_TEXT))
	return ledger
}

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("a pronoun-target revocation never arms the session lock", () => {
	it("recorded rows leave no read-only posture active", () => {
		expect(readOnlyActive(forcePushLedger())).toBeNull()
	})

	it("recorded rows make ledgerCovers neither cover nor forbid the force-push", () => {
		const ledger = forcePushLedger()
		const verdict = ledgerCovers(ledger, "vcs_remote", FORCE_PUSH_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.forbidden).toBe(false)
		expect(verdict.covered).toBe(false)
	})

	it("the recorded sentence leaves no forbid row at all, and the defused path needs no help from English", () => {
		const ledger = forcePushLedger()
		expect(ledger.readOnlyOn).toBeUndefined()
		expect(ledger.forbids).toEqual([])

		// The defused row is still what an UNPLACEABLE revocation becomes, and that is a garbage-input
		// question rather than a model answer: an endpoint that returns a revocation with no usable
		// category and no usable width gets one `*unknown*` row — kept for audit, authorising nothing,
		// arming no posture, and never `"*"` as a category. This row is NOT what the model
		// answers; it is what the code must do with a row that means nothing.
		const junk = forcePushLedger({
			...FORCE_PUSH_EXTRACTION,
			revocations: [{ action: "rewrite history", targets: ["it"], quote: "I know the branch history is messed up" }],
		} as Recorded)
		expect(junk.readOnlyOn).toBeUndefined()
		// The row named a target the message really contains ("it" IS in the sentence), so the defusing
		// keeps the target rather than falling back to `value: "*"` — a defused row may be as narrow as the
		// sentence, it may never be wider. The entity-plus-subtree pair is the shape a non-read
		// category gets, unchanged from before this change.
		const defused = junk.forbids.filter((f) => f.category.startsWith("*") && f.category.endsWith("*"))
		expect(defused.map((f) => `${f.category}:${f.value}`)).toEqual(["*unknown*:it", "*unknown*:it/"])
		expect(defused.every((f) => f.quote === "I know the branch history is messed up")).toBe(true)
		// It cannot answer `forbidden` for the push it seems to be about…
		expect(ledgerCovers(junk, "vcs_remote", FORCE_PUSH_TARGETS, POLICY.home, POLICY.project).forbidden).toBe(false)
		// …and it does take the auto-allow away from the older grant, which is the whole cost: one model call.
		const withGrant = createLedger()
		applyEvent(withGrant, {
			type: "grant", category: "vcs_remote", value: "origin/feature/retry-logic", kind: "entity",
			quote: "you can force-push origin/feature/retry-logic", messageId: "m0", seq: 0,
		})
		applyEvents(withGrant, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "rewrite history", targets: ["it"], quote: "I know the branch history is messed up" }] } as Recorded,
			"m1", 1, FORCE_PUSH_TEXT,
		))
		expect(ledgerCovers(withGrant, "vcs_remote", FORCE_PUSH_TARGETS, POLICY.home, POLICY.project).covered).toBe(false)
	})

	it("the same sentence with scope 'everything' arms readonly-on — the field, not the wording", () => {
		const ledger = forcePushLedger({
			...FORCE_PUSH_EXTRACTION,
			revocations: [{ action: "rewrite history", category: "other", scope: "everything", targetClass: "none", targets: [], quote: "I know the branch history is messed up" }],
		} as Recorded)
		expect(readOnlyActive(ledger)?.seq).toBe(0)
	})

	it("end to end: the force-push is no longer refused with the read-only line", async () => {
		const r = await runGate("bash", { command: "git push --force-with-lease origin feature/retry-logic" }, {
			policy: POLICY,
			ledger: forcePushLedger(),
			userMessages: [FORCE_PUSH_TEXT],
		})
		expect(r.reason).not.toMatch(/read-only/i)
	})
})

describe("a forbid newer than the grant stops the ledger auto-allow", () => {
	it("the recorded rows alone would cover the delete (the bug's other half)", () => {
		const ledger = createLedger()
		applyEvents(ledger, eventsFromExtraction(IMAGE_GRANT_EXTRACTION, "m1", 0, IMAGE_GRANT_TEXT))
		expect(ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project).covered).toBe(true)
	})

	it("recorded rows: the grant is not covered, and the ban is reported as a ban", () => {
		// The newer prompt changed which of the two fail-safe answers this row gets. The earlier recording had
		// no category, so `forbidCompatible` could not see the row and `ledgerCovers` could only DEFER the
		// grant. The prompt now gives the revocation a category, and the model's own category is
		// what this file stores — so the row is now category-compatible and answers `forbidden`. Both
		// verdicts stop the auto-allow; this one stops it without a model call, which is the direction a
		// named ban should move in, and the false-allow bar (0) is unaffected.
		const verdict = ledgerCovers(imageLedger(), "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.covered).toBe(false)
		expect(verdict.by).toEqual([])
		expect(verdict.forbidden).toBe(true)
		expect(verdict.reason).toContain("user forbade")
		expect(verdict.reason).toContain("do not delete any images")
	})

	it("an UNPLACEABLE newer revocation still only defers (the deferral path is intact)", () => {
		// Garbage-input pin: same message, but the row has no usable category, so it cannot bind — and
		// `newerForbid` reads every forbid whatever its category, so the auto-allow is taken away and the
		// gate's own model call decides. Costs one call; never an allow, never a refusal from the row.
		const ledger = createLedger()
		applyEvents(ledger, eventsFromExtraction(IMAGE_GRANT_EXTRACTION, "m1", 0, IMAGE_GRANT_TEXT))
		applyEvents(ledger, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "delete images", targets: [], quote: "do not delete any images" }] } as Recorded,
			"m2", 1, IMAGE_REVOKE_TEXT,
		))
		const verdict = ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.forbidden).toBe(false)
		expect(verdict.covered).toBe(false)
		expect(verdict.reason).toContain("deferred: newer revocation seq 1")
		expect(verdict.reason).toContain("do not delete any images")
	})

	it("explainLedgerCover shows the same verdict for that grant", () => {
		const lines = explainLedgerCover(imageLedger(), "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(lines.some((l) => l.includes("payments:staging"))).toBe(true)
		expect(lines.some((l) => l.includes(": covers payments:staging"))).toBe(false)
	})

	it("a revocation OLDER than the grant does not stop it (grant still covers)", () => {
		const ledger = createLedger()
		applyEvents(ledger, eventsFromExtraction(IMAGE_REVOKE_EXTRACTION, "m1", 0, IMAGE_REVOKE_TEXT))
		applyEvents(ledger, eventsFromExtraction(IMAGE_GRANT_EXTRACTION, "m2", 1, IMAGE_GRANT_TEXT))
		const verdict = ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.covered).toBe(true)
		expect(verdict.forbidden).toBe(false)
	})

	it("a grant NEWER than a category-compatible forbid still covers (newest statement wins)", () => {
		const ledger = createLedger()
		applyEvent(ledger, {
		type: "forbid", category: "container_mutation", value: "*", kind: "scope",
		quote: "do not touch any image", messageId: "m1", seq: 3,
	})
	applyEvent(ledger, {
		type: "grant", category: "container_mutation", value: "payments:staging", kind: "entity",
		quote: "you can delete the payments:staging image", messageId: "m2", seq: 9,
	})
		const verdict = ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.covered).toBe(true)
		expect(verdict.forbidden).toBe(false)
	})

	it("a compatible forbid newer than the grant keeps its own forbidden verdict (unchanged)", () => {
		const ledger = createLedger()
	applyEvent(ledger, {
		type: "grant", category: "container_mutation", value: "payments:staging", kind: "entity",
		quote: "you can delete the payments:staging image", messageId: "m1", seq: 0,
	})
	applyEvent(ledger, {
		type: "forbid", category: "container_mutation", value: "payments:staging", kind: "entity",
		quote: "do not delete payments:staging", messageId: "m2", seq: 4,
	})
		const verdict = ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.forbidden).toBe(true)
		expect(verdict.reason).toContain("user forbade")
	})

	it("a forbid imported from a grants file (seq 0, background authority) does not defer a local grant", () => {
		// `importLedger` rewrites every imported row to seq 0 exactly so that a file cannot outrank a live
		// transcript. The strict `>` in `newerForbid` is what keeps that true — without it, one
		// stale grants file would disable the ledger auto-allow for every session that imported it.
		const source = createLedger()
		applyEvent(source, {
			type: "forbid", category: "container_mutation", value: "*", kind: "scope",
			quote: "do not delete any images", messageId: "old", seq: 7,
		})
		const ledger = createLedger()
		applyEvent(ledger, {
			type: "grant", category: "container_mutation", value: "payments:staging", kind: "entity",
			quote: "you can delete the payments:staging image", messageId: "m1", seq: 1,
		})
		importLedger(ledger, serializeLedger(source))
		expect(ledger.forbids.map((f) => f.seq)).toEqual([0])
		const verdict = ledgerCovers(ledger, "container_mutation", IMAGE_TARGETS, POLICY.home, POLICY.project)
		expect(verdict.covered).toBe(true)
		expect(verdict.forbidden).toBe(false)
	})

	it("end to end: the ledger refuses the withdrawn delete instead of allowing it", async () => {
		const calls: string[] = []
		vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: { body?: string }) => {
			calls.push(String(init?.body ?? "").slice(0, 40))
			return { ok: true, json: async () => ({ choices: [{ message: { content: '{"authorized":false,"reason":"not authorised"}' } }] }) }
		}))
		const r = await runGate("bash", { command: "docker rmi payments:staging" }, {
			policy: POLICY,
			grants: createGrantStore(),
			ledger: imageLedger(),
			endpoint: { baseUrl: "http://mock", model: "mock" },
			userMessages: [IMAGE_GRANT_TEXT, IMAGE_REVOKE_TEXT],
		})
		expect(r.outcome).not.toBe("allow-granted")
		expect(r.grantedBy).not.toBe("ledger")
		// The answer got STRONGER, and the difference is observable here: with no category the row
		// could only defer, so the gate spent its transcript call and then prompted. The recorded row carries
		// the model's own category, so `forbidden` answers it at the ledger and no call is made — the same
		// outcome for the user (no auto-allow), one fewer model call, and nothing is allowed on a row the
		// user's own sentence withdrew.
		expect(calls).toEqual([])
	})
})

describe("a session grant promoted from the ledger vs a later revocation", () => {
	// gate.ts promotes a ledger cover to a session grant (addGrant). Session grants are checked
	// BEFORE the ledger, so the promoted row may outlive the sentence that withdrew it. Written as
	// the behaviour we want; if it fails it is a real gap to decide on.
	it.fails("a later revocation still stops the same command after promotion", async () => {
		// FAILS TODAY (reported, not fixed): gate.ts checks session grants BEFORE the
		// ledger, and a ledger cover is promoted into that store (gate.ts `addGrant`). The promoted row
		// carries no seq and nothing re-validates it against later forbids, so once the delete has been
		// allowed once out of the ledger, the recorded revocation can never reach it again — `it.fails`
		// pins the gap so a future fix flips this line instead of discovering it again.
		const grants = createGrantStore()
		const first = await runGate("bash", { command: "docker rmi payments:staging" }, {
			policy: POLICY,
			grants,
			ledger: (() => {
				const l = createLedger()
				applyEvents(l, eventsFromExtraction(IMAGE_GRANT_EXTRACTION, "m1", 0, IMAGE_GRANT_TEXT))
				return l
			})(),
			userMessages: [IMAGE_GRANT_TEXT],
		})
		expect(first.outcome).toBe("allow-granted")
		expect(first.grantedBy).toBe("ledger")
		expect(grants.grants.some((g) => g.value === "payments:staging")).toBe(true)

		const after = await runGate("bash", { command: "docker rmi payments:staging" }, {
			policy: POLICY,
			grants,
			ledger: imageLedger(),
			userMessages: [IMAGE_GRANT_TEXT, IMAGE_REVOKE_TEXT],
		})
		expect(after.outcome).not.toBe("allow-granted")
	})
})
