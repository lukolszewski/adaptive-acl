import { describe, expect, it } from "vitest"
import {
	buildTranscriptEntriesFromBranch,
	buildTranscriptForClassifier,
	compactTranscriptEntry,
	formatActionForClassifier,
} from "./classifier-transcript.ts"
import { estimateTokens, tokensToChars } from "./context-budget.ts"

/** N user turns of `chars` each, so a budget can be aimed at a known size. */
function userTurns(n: number, chars: number) {
	return Array.from({ length: n }, (_, i) => ({
		type: "message",
		message: { role: "user", content: `m${i} ${"lorem ipsum dolor sit amet ".repeat(Math.ceil(chars / 26)).slice(0, chars)}` },
	}))
}

describe("classifier-transcript", () => {
	it("includes user text and assistant toolCall history only", () => {
		const transcript = buildTranscriptForClassifier([
			{
				type: "message",
				message: { role: "user", content: "run tests" },
			},
			{
				type: "message",
				message: {
					role: "assistant",
					content: [
						{ type: "text", text: "Sure, running tests now." },
						{
							type: "toolCall",
							id: "t1",
							name: "bash",
							arguments: { command: "npm test" },
						},
					],
				},
			},
		])
		expect(transcript).toContain("User: run tests")
		expect(transcript).toContain("bash npm test")
		expect(transcript).not.toContain("Sure, running")
	})

	it("supports JSONL transcript format", () => {
		const transcript = buildTranscriptForClassifier(
			[
				{
					type: "message",
					message: { role: "user", content: "hi" },
				},
			],
			true,
		)
		expect(transcript).toContain('{"user":"hi"}')
	})

	it("formatActionForClassifier compacts pending tool", () => {
		const compact = compactTranscriptEntry(
			formatActionForClassifier("bash", { command: "node -v" }),
		)
		expect(compact).toBe("bash node -v\n")
	})

	describe("token budget", () => {
		const branch = userTurns(60, 400)

		it("keeps whole entries newest-first and stays inside the budget", () => {
			const budget = 1_000
			const kept = buildTranscriptForClassifier(branch, false, 40, 12_000, budget)
			const full = buildTranscriptForClassifier(branch, false, 100, Number.MAX_SAFE_INTEGER)
			expect(kept.length).toBeGreaterThan(0)
			expect(kept.length).toBeLessThanOrEqual(tokensToChars(budget))
			// a suffix of the untruncated text: nothing was clipped, only whole entries dropped
			expect(full.endsWith(kept)).toBe(true)
			expect(kept.startsWith("User: m")).toBe(true)
			expect(kept).toContain("m59")
			expect(kept.split("User: ").length - 1).toBeLessThan(60)
		})

		it("never shortens an entry, however tight the budget", () => {
			const kept = buildTranscriptForClassifier(branch, false, 40, 12_000, 1)
			// one token buys no entry at all — the newest entry is dropped, not sliced
			expect(kept).toBe("")
			expect(kept).not.toContain("…")
		})

		it("leaves the character cap alone when no budget is given", () => {
			const asToday = buildTranscriptForClassifier(branch)
			expect(asToday).toBe(buildTranscriptForClassifier(branch, false, 40, 12_000))
			expect(asToday.length).toBeLessThanOrEqual(12_000)
			expect(asToday).toBe(buildTranscriptForClassifier(branch, false, 40, 12_000, undefined))
			// and the cap really bites at this size, so the comparison above is not vacuous
			const everything = buildTranscriptForClassifier(branch, false, 100, Number.MAX_SAFE_INTEGER)
			expect(everything.length).toBeGreaterThan(12_000)
			expect(estimateTokens(everything)).toBeGreaterThan(12_000 / 3.2)
		})
	})

	it("buildTranscriptEntriesFromBranch skips non-message entries", () => {
		const entries = buildTranscriptEntriesFromBranch([
			{ type: "label", message: { role: "user", content: "x" } } as any,
			{
				type: "message",
				message: { role: "user", content: "keep" },
			},
		])
		expect(entries).toHaveLength(1)
		expect(entries[0]?.content[0]).toEqual({ type: "text", text: "keep" })
	})
})
