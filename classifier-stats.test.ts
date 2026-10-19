/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The classifier counters behind `/classifier-status`.
 *
 * Motivation: measurement showed ~20 session occurrences of "no classifier
 * endpoint configured" and ~32 of "classifier unavailable" against 1,062
 * eligible calls. All three failure states - disabled, no endpoint, endpoint
 * failing - present to the user as one thing: a prompt. These counters are the
 * only way to tell them apart from inside a run.
 */
import { describe, expect, it } from "vitest"
import { classifierStats, resetClassifierStats, runGate } from "./gate.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

describe("classifier counters", () => {
	it("counts an eligible verdict that had nowhere to send it", async () => {
		resetClassifierStats()
		const r = await runGate("bash", { command: "someprog --do-thing" }, { policy: POLICY })
		expect(classifierStats.eligible).toBe(1)
		expect(classifierStats.noEndpoint).toBe(1)
		expect(classifierStats.calls).toBe(0)
		expect(r.tier).toBe("ask")
	})

	it("counts one eligibility per call, not one per unknown segment", async () => {
		resetClassifierStats()
		await runGate("bash", { command: "prog-a && prog-b" }, { policy: POLICY })
		expect(classifierStats.eligible).toBe(1)
		expect(classifierStats.noEndpoint).toBe(1)
	})

	it("does not count a verdict the static policy already decided", async () => {
		resetClassifierStats()
		await runGate("bash", { command: "ls -la ." }, { policy: POLICY })
		expect(classifierStats.eligible).toBe(0)
		expect(classifierStats.noEndpoint).toBe(0)
	})

	it("does not count an unparseable command, which never reaches the model", async () => {
		resetClassifierStats()
		const r = await runGate("bash", { command: `echo "find / | awk 'x` }, { policy: POLICY })
		expect(r.unparseable).toBe(true)
		expect(classifierStats.eligible).toBe(0)
	})

	it("resets", async () => {
		await runGate("bash", { command: "someprog" }, { policy: POLICY })
		resetClassifierStats()
		expect(classifierStats.eligible).toBe(0)
		expect(classifierStats.noEndpoint).toBe(0)
		expect(classifierStats.grantFailed).toBe(0)
	})
})
