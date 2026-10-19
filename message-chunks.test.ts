/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * message-chunks: the splitter behind chunked grant extraction
 * Pinned properties: pieces fit,
 * pieces reassemble exactly, boundaries degrade paragraph → sentence → whitespace →
 * hard cut, and nothing is ever lost.
 */
import { describe, expect, it } from "vitest"
import { chunkMessage, EXTRACTION_CHUNK_CHARS } from "./message-chunks.ts"

/** `n` prose paragraphs of `sentences` sentences each, separated by blank lines. */
function prose(n: number, sentences = 5): string[] {
	return Array.from({ length: n }, (_, p) =>
		Array.from({ length: sentences }, (_, s) => `Paragraph ${p + 1} sentence ${s + 1}: the migration keeps every artifact under the build directory and notes nothing about permissions.`).join(" "),
	)
}

/** Cut points that end a paragraph, i.e. every offset where a whole paragraph ends. */
function paragraphEnds(paragraphs: string[], sep: string): Set<number> {
	const ends = new Set<number>()
	let at = 0
	for (const p of paragraphs) {
		at += p.length + sep.length
		ends.add(at)
	}
	return ends
}

describe("chunkMessage — the properties every caller relies on", () => {
	const corpus: Array<[string, string]> = [
		["42 prose paragraphs", prose(42).join("\n\n")],
		["one 9 kB paragraph of sentences", prose(1, 120).join(" ")],
		["no whitespace at all", "y".repeat(9000)],
		["crlf paragraphs", prose(20).join("\r\n\r\n")],
		["one long word inside short paragraphs", [...prose(6, 2), "x".repeat(6000), ...prose(6, 2)].join("\n\n")],
		["trailing whitespace run", `${prose(30).join("\n\n")}\n\n   \n  `],
		["leading blank lines", `\n\n${prose(30).join("\n\n")}`],
	]

	it("exports today's slice length as the chunk budget", () => {
		expect(EXTRACTION_CHUNK_CHARS).toBe(4000)
		expect(chunkMessage("x".repeat(EXTRACTION_CHUNK_CHARS))).toHaveLength(1)
		expect(chunkMessage("x".repeat(EXTRACTION_CHUNK_CHARS))).toEqual(["x".repeat(EXTRACTION_CHUNK_CHARS)])
	})

	it.each(corpus)("every piece of a %s fits and the pieces reassemble byte for byte", (_label, text) => {
		const pieces = chunkMessage(text)
		expect(pieces.length).toBeGreaterThan(1)
		expect(pieces.every((p) => p.length > 0 && p.length <= EXTRACTION_CHUNK_CHARS)).toBe(true)
		expect(pieces.join("")).toBe(text)
		expect(pieces.reduce((n, p) => n + p.length, 0)).toBe(text.length)
	})

	it("returns a text that fits as one piece", () => {
		expect(chunkMessage("you may delete the build directory")).toEqual(["you may delete the build directory"])
		expect(chunkMessage("a".repeat(4000), 4000)).toEqual(["a".repeat(4000)])
	})

	it("yields no pieces for empty or whitespace-only input (nothing to extract)", () => {
		expect(chunkMessage("")).toEqual([])
		expect(chunkMessage("   \n\t  \n")).toEqual([])
	})

	it("honours an explicit maxChars", () => {
		const text = prose(20).join("\n\n")
		const pieces = chunkMessage(text, 200)
		expect(pieces.every((p) => p.length <= 200)).toBe(true)
		expect(pieces.join("")).toBe(text)
		expect(pieces.length).toBeGreaterThan(Math.ceil(text.length / 200) - 1)
	})
})

describe("chunkMessage — boundary preference", () => {
	it("a 12 kB message of paragraphs cuts on blank lines and cuts no paragraph", () => {
		const paragraphs = prose(60)
		const text = paragraphs.join("\n\n")
		expect(text.length).toBeGreaterThan(12_000)
		const ends = paragraphEnds(paragraphs, "\n\n")

		const pieces = chunkMessage(text)
		expect(pieces.length).toBeGreaterThan(2)
		expect(pieces.join("")).toBe(text)
		// Every internal edge is a paragraph edge, so no paragraph was split open.
		let at = 0
		for (const piece of pieces.slice(0, -1)) {
			at += piece.length
			expect(ends.has(at)).toBe(true)
		}
		// Fitting paragraphs are packed, not one-per-piece.
		expect(pieces[0]!.length).toBeGreaterThan(3_000)
	})

	it("prefers a blank line over a sentence end further into the window", () => {
		const text = `One two. Three four.\n\n${"Filler sentence. ".repeat(600)}`
		const pieces = chunkMessage(text, 200)
		expect(pieces[0]).toBe("One two. Three four.\n\n")
		expect(pieces.join("")).toBe(text)
	})

	it("a single 9 kB paragraph of sentences splits at sentence ends", () => {
		const text = prose(1, 200).join(" ")
		expect(text.length).toBeGreaterThan(9_000)
		const pieces = chunkMessage(text)
		expect(pieces.length).toBeGreaterThan(2)
		expect(pieces.join("")).toBe(text)
		expect(pieces.every((p) => p.length <= EXTRACTION_CHUNK_CHARS)).toBe(true)
		// Each piece ends on the whitespace that closed a sentence.
		for (const piece of pieces.slice(0, -1)) expect(piece).toMatch(/[.!?][ \t]*$/)
	})

	it("falls back to whitespace when a line has no sentence end in reach", () => {
		const line = "token ".repeat(2000) // 12 kB of whitespace-separated words, no '.'
		const pieces = chunkMessage(line)
		expect(pieces.join("")).toBe(line)
		expect(pieces.every((p) => p.length <= EXTRACTION_CHUNK_CHARS)).toBe(true)
		for (const piece of pieces.slice(0, -1)) expect(piece.endsWith(" ")).toBe(true)
	})

	it("hard-cuts a run with no whitespace at all and loses nothing", () => {
		const text = "z".repeat(9_000)
		const pieces = chunkMessage(text)
		expect(pieces).toHaveLength(3)
		expect(pieces.map((p) => p.length)).toEqual([4000, 4000, 1000])
		expect(pieces.join("")).toBe(text)
	})

	it("a paragraph longer than the budget is split at sentence ends, not dropped", () => {
		const short = prose(3, 2).join("\n\n")
		const huge = prose(1, 300).join(" ")
		const text = `${short}\n\n${huge}`
		const pieces = chunkMessage(text)
		expect(pieces.join("")).toBe(text)
		expect(pieces.some((p) => p.includes(huge.slice(0, 40)))).toBe(true)
		expect(pieces.every((p) => p.length <= EXTRACTION_CHUNK_CHARS)).toBe(true)
	})

	it("makes progress even when maxChars is smaller than a word", () => {
		const pieces = chunkMessage("abcdefghijkl", 3)
		expect(pieces).toEqual(["abc", "def", "ghi", "jkl"])
	})
})
