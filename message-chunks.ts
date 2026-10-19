/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Splitting an oversize user message so grant extraction can read all of it
 * is what this module does, and `message-chunks.test.ts` pins the properties.
 *
 * The per-message extraction call used to send `message.slice(0, 4000)`. A pasted
 * design document whose approval sits in the last paragraph had that approval cut off
 * before the model ever saw it, and the ledger — the session's authorisation memory —
 * then remembered "not authorised" for the rest of the session. Making the slice bigger
 * is not a fix: the limit exists because it is the model's context window.
 *
 * So an oversize message is cut into pieces that each fit, extracted piece by piece and
 * merged. The cut prefers whole thoughts: a blank line, then a sentence end, then any
 * whitespace, and only a stretch with no whitespace at all is cut mid-word. Nothing can
 * be lost by construction — a piece is a span of the input and consecutive pieces share
 * an edge, so `chunkMessage(t).join("") === t`.
 */

/**
 * The widest piece extraction may send, in characters.
 *
 * This is today's flat slice length, kept as a named constant so the merge with the
 * token budget (item 1, `context-budget.ts`) is a one-line change here rather than a
 * hunt through callers. The estimate belongs there, not in this module: a chunk size
 * derived from `ceil(chars / 3.2)` of the model's context window is the same number
 * divided by the prompt overhead, and it changes with configuration.
 */
export const EXTRACTION_CHUNK_CHARS = 4000

/**
 * Candidate cut positions, best first: (0) a blank line — a paragraph edge, (1) a
 * sentence end — `.`, `!` or `?` followed by whitespace, plus any lone newline (line
 * breaks carry the same "a thought ended" signal in pasted logs and code), (2) any
 * whitespace run. Each match contributes the offset just PAST the whitespace, so the
 * separator stays at the tail of the piece that precedes it and every piece after the
 * first begins on content.
 *
 * All three are `g` and are only ever used through `matchAll` on a fresh string, so
 * reusing them across calls cannot carry a `lastIndex` over.
 */
const CUT_LEVELS: RegExp[] = [
	/\r?\n[ \t]*\r?\n[ \t\r\n]*/g,
	/[.!?][ \t]*(?:\r?\n|[ \t]+)|\r?\n/g,
	/\s+/g,
]

/** Offsets just past every separator of one level, ascending (matchAll scans left to right). */
function cutOffsets(text: string, separator: RegExp): number[] {
	const offsets: number[] = []
	for (const match of text.matchAll(separator)) {
		const end = (match.index ?? 0) + match[0].length
		// A cut at the very end would buy an empty piece, so it is not a candidate.
		if (end < text.length) offsets.push(end)
	}
	return offsets
}

/** Rightmost value ≤ `upto`; that is the fullest piece that still fits this level. */
function lastAtOrBelow(offsets: number[], upto: number): number {
	let lo = 0
	let hi = offsets.length - 1
	let best = -1
	while (lo <= hi) {
		const mid = (lo + hi) >> 1
		if (offsets[mid]! <= upto) {
			best = offsets[mid]!
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best
}

/**
 * Where to end the piece that starts at `from`, given the window `[from, limit]`, or -1
 * for "no boundary in reach — cut the window in half" (hard cut).
 *
 * Levels are tried in priority order and the first level that has any boundary in the
 * window decides: a paragraph edge is taken even when a sentence end would have filled
 * the piece better. That is the point of the ordering — filling the piece is worth one
 * extra model call, splitting a sentence that carries an approval is not.
 */
function chooseCut(levels: number[][], from: number, limit: number): number {
	for (const offsets of levels) {
		const at = lastAtOrBelow(offsets, limit)
		if (at > from) return at
	}
	return -1
}

/**
 * Split `text` into pieces of at most `maxChars`, cutting at the best boundary
 * available (blank line → sentence end → whitespace → hard cut).
 *
 * Guarantees, each pinned in message-chunks.test.ts:
 *  - every piece is ≤ `maxChars`;
 *  - pieces are contiguous and `pieces.join("") === text` — separators are never
 *    dropped, so reassembly needs no bookkeeping;
 *  - a text that fits comes back as one piece;
 *  - a paragraph/sentence that fits is never cut: it is packed whole into some piece;
 *  - input that is empty or only whitespace yields `[]` — there is nothing in it to
 *    extract. (Callers that must not skip their request fall back to a slice; see
 *    `extractMessageGrants`.)
 */
export function chunkMessage(text: string, maxChars = EXTRACTION_CHUNK_CHARS): string[] {
	const width = Math.max(1, Math.floor(maxChars))
	if (!text.trim()) return []
	// The common case: a message that fits never pays for boundary discovery.
	if (text.length <= width) return [text]

	const levels = CUT_LEVELS.map((separator) => cutOffsets(text, separator))
	const pieces: string[] = []
	let from = 0
	while (text.length - from > width) {
		const boundary = chooseCut(levels, from, from + width)
		const cut = boundary > 0 ? boundary : from + width
		pieces.push(text.slice(from, cut))
		from = cut
	}
	pieces.push(text.slice(from))
	return pieces
}
