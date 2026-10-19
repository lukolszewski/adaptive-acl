/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The context-budget contract: the constants are the measured ones, the estimate is a ceiling, and
 * the fill never breaks an item or leaves a hole.
 */
import { describe, expect, it } from "vitest"

import {
	CHARS_PER_TOKEN,
	DEFAULT_CONTEXT_TOKENS,
	callBudget,
	estimateTokens,
	fitNewestFirst,
	tokensToChars,
} from "./context-budget.ts"

describe("constants", () => {
	// Pinned on purpose: 15 000 characters measured 5 662 tokens on the request that overflowed
	// (2.65 chars/token). Someone who "tunes" this number down is claiming the server got roomier,
	// and that claim has to be argued here, in the open, with a new measurement.
	it("are the measured ones", () => {
		expect(CHARS_PER_TOKEN).toBe(3.2)
		expect(DEFAULT_CONTEXT_TOKENS).toBe(4096)
	})

	it("put the measured failing request outside the served window", () => {
		// 5 662 tokens for 15 000 chars was the failure; our estimate must never say it fits.
		expect(estimateTokens(15_000)).toBe(4688)
		expect(estimateTokens(15_000)).toBeGreaterThan(DEFAULT_CONTEXT_TOKENS)
		expect(estimateTokens("x".repeat(15_000))).toBe(estimateTokens(15_000))
	})
})

describe("estimateTokens / tokensToChars", () => {
	it("rounds up and never under-books a string", () => {
		expect(estimateTokens("")).toBe(0)
		expect(estimateTokens(0)).toBe(0)
		expect(estimateTokens(1)).toBe(1) // one character is still a token the server pays
		expect(estimateTokens(3.2)).toBe(1)
		expect(estimateTokens(4)).toBe(2)
		for (const chars of [1, 7, 99, 1000, 270, 15_000]) {
			expect(estimateTokens(chars)).toBeGreaterThanOrEqual(chars / CHARS_PER_TOKEN)
		}
	})

	it("converts back the pessimistic way", () => {
		expect(tokensToChars(0)).toBe(0)
		expect(tokensToChars(-5)).toBe(0)
		expect(tokensToChars(DEFAULT_CONTEXT_TOKENS)).toBe(13_107)
		// spend the allowance and you can never afford more than you asked about
		for (const tokens of [1, 10, 300, 3796, 4096]) {
			expect(estimateTokens(tokensToChars(tokens))).toBeLessThanOrEqual(tokens)
		}
	})
})

describe("fitNewestFirst", () => {
	const items = ["a", "b", "c", "d"]
	const one = () => 1

	it("keeps the newest contiguous suffix and returns it oldest-first", () => {
		expect(fitNewestFirst(items, one, 2)).toEqual(["c", "d"])
		expect(fitNewestFirst(items, one, 0)).toEqual([])
		expect(fitNewestFirst(items, one, 9)).toEqual(items)
		expect(fitNewestFirst([] as string[], one, 5)).toEqual([])
	})

	it("stops at the first item that does not fit — an older one may not jump over it", () => {
		// sizes: a=1 b=6 c=1, budget 2 → c fits, b does not, so `a` is out even though it would fit
		const sizes: Record<string, number> = { a: 1, b: 6, c: 1 }
		expect(fitNewestFirst(items.slice(0, 3), (t) => sizes[t]!, 2)).toEqual(["c"])
	})

	it("drops an oversize newest item whole instead of sending a fragment", () => {
		const huge = "x".repeat(20_000)
		const kept = fitNewestFirst(["older", huge], (t) => estimateTokens(t), 1000)
		expect(kept).toEqual([])
	})

	it("hands back the input items untouched", () => {
		const texts = ["first", "second", "third"]
		const kept = fitNewestFirst(texts, (t) => estimateTokens(t), 6)
		expect(kept.length).toBeGreaterThan(0)
		for (const k of kept) expect(texts).toContain(k)
	})
})

describe("callBudget", () => {
	it("subtracts the fixed part and the answer reserve from the window", () => {
		expect(callBudget(undefined, 0, 300)).toBe(4096 - 300)
		expect(callBudget(DEFAULT_CONTEXT_TOKENS, 0, 300)).toBe(3796)
		// 3 200 fixed chars = 1 000 tokens, answer gets 300 → 748 left for the variable part
		expect(callBudget(2048, 3200, 300)).toBe(748)
	})

	it("falls back to the served window for anything that is not a usable number", () => {
		for (const bad of [0, -1, NaN, Infinity]) {
			expect(callBudget(bad, 3200, 300)).toBe(callBudget(undefined, 3200, 300))
		}
		expect(callBudget(undefined as unknown as number, 0, 300)).toBe(3796)
	})

	it("never goes negative — zero means 'send nothing optional'", () => {
		expect(callBudget(4096, 100_000, 300)).toBe(0)
		expect(callBudget(100, 0, 300)).toBe(0)
	})
})
