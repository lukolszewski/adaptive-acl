/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The whole golden corpus (`bash-walker.golden.jsonl`) through `walkBash`, in one place.
 *
 * Each walker part's test file runs its own subset (`sep-`, `val-`, `hd-`, `sem-`, …) so a failure
 * points at the module that owns it. This file is the integration proof: every case, no subset, no
 * deferral list — the §12.3 ids that no input can produce are the only reasons without a case.
 */
import { beforeAll, describe, expect, it } from "vitest"
import { initBashParser } from "./bash-parser.ts"
import { compareCase, loadGolden, parseWithEnvironmentRetry } from "./bash-walker-golden.ts"
import { walkBash } from "./bash-walker.ts"

/** spec §12.3 — reason ids no input can produce, so no golden case carries them. */
const UNREACHABLE = ["parse-aborted", "parser-unavailable", "assignment-name-invalid", "command-name-not-a-literal"]

const CASES = loadGolden()

beforeAll(async () => {
	await initBashParser()
})

describe("every golden case", () => {
	for (const one of CASES) {
		it(one.id, () => {
			// `parseWithEnvironmentRetry`: the parser's 50 ms wall-clock budget can abort a long parse under
			// CPU contention, which is a statement about the machine (§12.3 lists both ids as unreachable from
			// any input), not about the command. One retry, and the retried verdict is what is asserted.
			const mismatch = compareCase(one, parseWithEnvironmentRetry(walkBash, one.command))
			// `undefined`, not `null`: expect()'s message parameter is optional, and null is neither.
			expect(mismatch, mismatch ? `${mismatch.id}: ${mismatch.message}` : undefined).toBeNull()
		})
	}
})

describe("the corpus", () => {
	it("has unique ids", () => {
		const ids = CASES.map((one) => one.id)
		expect(new Set(ids).size).toBe(ids.length)
	})

	it("covers inventory-mismatch (§12.3 — reachable since the grammar defect T10c2 item 4 guards against)", () => {
		expect(CASES.some((one) => one.expect.kind === "unproven" && one.expect.reason === "inventory-mismatch")).toBe(true)
	})

	it("carries no case for the ids §12.3 calls unreachable", () => {
		const reasons = new Set(CASES.flatMap((one) => (one.expect.kind === "unproven" ? [one.expect.reason] : [])))
		expect(UNREACHABLE.filter((id) => reasons.has(id))).toEqual([])
	})
})
