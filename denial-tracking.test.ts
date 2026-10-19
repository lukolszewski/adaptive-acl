/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"

import {
	createDenialTrackingState,
	denialStreak,
	DENIAL_LIMITS,
	recordClassifierDenial,
	recordClassifierSuccess,
	shouldFallbackToPrompting,
	type DenialTrackingState,
} from "./denial-tracking.ts"

type Outcome = "denied" | "allowed"

/** Replay a run from the start, the way `index.ts` does: fold the events over a fresh state. */
function replay(events: Outcome[]): DenialTrackingState {
	return events.reduce(
		(state, event) => (event === "denied" ? recordClassifierDenial(state) : recordClassifierSuccess(state)),
		createDenialTrackingState(),
	)
}

/**
 * The rule stated a second time, straight from the spec and without reference to how the module
 * stores anything: three refusals with no allowance between them, or twenty across the run.
 */
function specSaysStop(events: Outcome[]): boolean {
	let refused = 0
	let burst = 0
	for (const event of events) {
		if (event === "denied") {
			refused += 1
			burst += 1
		} else {
			burst = 0
		}
	}
	return burst >= 3 || refused >= 20
}

function specBurst(events: Outcome[]): number {
	let burst = 0
	for (const event of events) burst = event === "denied" ? burst + 1 : 0
	return burst
}

/** Every sequence of length 1..length over {denied, allowed}. */
function allRuns(length: number): Outcome[][] {
	const runs: Outcome[][] = []
	for (let mask = 0; mask < 1 << length; mask++) {
		const run: Outcome[] = []
		for (let bit = 0; bit < length; bit++) run.push(mask & (1 << bit) ? "denied" : "allowed")
		runs.push(run)
	}
	return runs
}

const ALLOWED_FOREVER: Outcome[] = Array.from({ length: DENIAL_LIMITS.maxTotal }, () => "allowed" as const)

describe("denial-tracking", () => {
	it("escalates after consecutive classifier denials", () => {
		let state = createDenialTrackingState()
		state = recordClassifierDenial(state)
		state = recordClassifierDenial(state)
		expect(shouldFallbackToPrompting(state)).toBe(false)
		state = recordClassifierDenial(state)
		expect(shouldFallbackToPrompting(state)).toBe(true)
	})

	it("does not stop a run that has just started", () => {
		expect(shouldFallbackToPrompting(createDenialTrackingState())).toBe(false)
		expect(denialStreak(createDenialTrackingState())).toBe(0)
	})

	it("counts one burst short of the limit, then over it", () => {
		const oneShort = replay(Array.from({ length: DENIAL_LIMITS.maxConsecutive - 1 }, () => "denied" as const))
		expect(shouldFallbackToPrompting(oneShort)).toBe(false)
		expect(denialStreak(oneShort)).toBe(DENIAL_LIMITS.maxConsecutive - 1)
		expect(shouldFallbackToPrompting(recordClassifierDenial(oneShort))).toBe(true)
	})

	it("treats an allowed call as the end of a burst", () => {
		const state = replay(["denied", "allowed", "denied", "denied"])
		expect(denialStreak(state)).toBe(2)
		expect(shouldFallbackToPrompting(state)).toBe(false)
	})

	it("escalates again after a reset: denial, success, denial, denial, denial", () => {
		const state = replay(["denied", "allowed", "denied", "denied", "denied"])
		expect(denialStreak(state)).toBe(3)
		expect(shouldFallbackToPrompting(state)).toBe(true)
	})

	it("never lets an allowance reduce the tally of refusals", () => {
		const three = replay(["denied", "denied", "denied"])
		expect(three.denials).toBe(3)
		expect(recordClassifierSuccess(three).denials).toBe(3)
		expect(recordClassifierSuccess(recordClassifierSuccess(three)).denials).toBe(3)
	})

	it("stops a run that collects a refusal after every approval", () => {
		// The burst never exceeds one, so everything the stop decision rests on is the total.
		const alternating: Outcome[] = []
		for (let round = 0; round < DENIAL_LIMITS.maxTotal; round++) {
			alternating.push("denied", "allowed")
			const expected = round + 1 >= DENIAL_LIMITS.maxTotal
			expect(shouldFallbackToPrompting(replay(alternating))).toBe(expected)
			expect(denialStreak(replay(alternating))).toBeLessThan(DENIAL_LIMITS.maxConsecutive)
		}
	})

	it("reaches the total limit on the twentieth refusal and not before", () => {
		// Nineteen refusals, each followed by an approval: the burst never builds, so only the
		// total can fire — and it fires on the twentieth refusal itself, not on the approval after.
		const nineteenWithApprovals: Outcome[] = []
		for (let n = 0; n < DENIAL_LIMITS.maxTotal - 1; n++) nineteenWithApprovals.push("denied", "allowed")
		expect(shouldFallbackToPrompting(replay(nineteenWithApprovals))).toBe(false)
		expect(shouldFallbackToPrompting(replay([...nineteenWithApprovals, "denied"]))).toBe(true)
		expect(shouldFallbackToPrompting(replay([...nineteenWithApprovals, "denied", "allowed"]))).toBe(true)
	})

	it("cannot be talked out of the total limit by later approvals", () => {
		const over = replay([...Array.from({ length: DENIAL_LIMITS.maxTotal }, () => "denied" as const)])
		expect(shouldFallbackToPrompting(over)).toBe(true)
		expect(shouldFallbackToPrompting(recordClassifierSuccess(over))).toBe(true)
		expect(shouldFallbackToPrompting(replay([...ALLOWED_FOREVER]))).toBe(false)
	})

	it("has nothing to do on an approval when no burst is running", () => {
		const fresh = createDenialTrackingState()
		// Documented no-allocation path: the same value comes back, and reassigning it is a no-op.
		expect(recordClassifierSuccess(fresh)).toBe(fresh)

		const burstBroken = recordClassifierSuccess(recordClassifierDenial(fresh))
		expect(recordClassifierSuccess(burstBroken)).toBe(burstBroken)
		expect(denialStreak(burstBroken)).toBe(0)
		expect(burstBroken.denials).toBe(1)
	})

	it("leaves the state it was handed alone", () => {
		const before: DenialTrackingState = { denials: 4, clearedAt: 2 }
		const snapshot = { ...before }

		const denied = recordClassifierDenial(before)
		const allowed = recordClassifierSuccess(before)

		expect(before).toEqual(snapshot)
		expect(denied).not.toBe(before)
		expect(denied).toEqual({ denials: 5, clearedAt: 2 })
		expect(allowed).toEqual({ denials: 4, clearedAt: 4 })
		expect(denialStreak(allowed)).toBe(0)
	})

	it("hands out an independent starting value each time", () => {
		const first = createDenialTrackingState()
		const second = createDenialTrackingState()
		expect(second).not.toBe(first)
		expect(denialStreak(recordClassifierDenial(first))).toBe(1)
		expect(denialStreak(second)).toBe(0)
	})

	it("keeps counting once a run is already stopped", () => {
		// Nothing caps the counters, so a caller can report how far past the limit things went.
		const state = replay(["denied", "denied", "denied", "denied", "denied"])
		expect(denialStreak(state)).toBe(5)
		expect(state.denials).toBe(5)
		expect(shouldFallbackToPrompting(state)).toBe(true)
	})

	it("publishes the two limits it enforces", () => {
		expect(DENIAL_LIMITS.maxConsecutive).toBe(3)
		expect(DENIAL_LIMITS.maxTotal).toBe(20)
	})

	it("matches the stated rule for every run of eight calls or fewer", () => {
		for (let length = 1; length <= 8; length++) {
			for (const run of allRuns(length)) {
				let state = createDenialTrackingState()
				for (let cut = 1; cut <= run.length; cut++) {
					state = run[cut - 1] === "denied" ? recordClassifierDenial(state) : recordClassifierSuccess(state)
					const prefix = run.slice(0, cut)
					expect(shouldFallbackToPrompting(state), prefix.join(",")).toBe(specSaysStop(prefix))
					expect(denialStreak(state), prefix.join(",")).toBe(specBurst(prefix))
				}
			}
		}
	})
})
