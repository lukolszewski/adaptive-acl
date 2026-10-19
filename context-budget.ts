/**
 * How big a classifier call is allowed to be — the one place that knows.
 *
 * `clf-gate` is served with a **4 096-token context** and that number is fixed by the user, so a
 * request has to be sized to fit *before* it leaves the process. The gates used to cap their
 * history in characters (15 000 of them), which has no relationship at all to a token window: a
 * long session produced a 5 662-token request from 15 000 characters and the server answered
 * `ContextWindowExceededError`, which the gate could only report as "classifier unavailable".
 *
 * We estimate tokens from characters rather than running a real tokenizer: no tokenizer ships with
 * the plugin and adding one costs a dependency. The measured ratio on the request that failed was
 * 2.65 characters per token; `CHARS_PER_TOKEN` is set well above that on purpose, because the
 * corpus is paths, code and JSON — the densest material we send. Under-estimating is the only
 * failure mode that matters, and it is paid for with a few dropped messages.
 *
 * The rule that shapes the whole module: **whole items only**. A message or transcript entry is
 * either sent entire or not sent. Clipping mid-sentence invents evidence — a truncated
 * "…and never touch prod" reads exactly like the approval it was cutting off — so nothing here
 * ever shortens a string. And the fill walks newest→oldest and *stops* at the first item that does
 * not fit rather than skipping it: an older message must not jump over a dropped newer one, or the
 * model sees a gap in the conversation it has no way to know about.
 */

/** What `clf-gate` is served with. Not a guess and not negotiable at runtime: no probing. */
export const DEFAULT_CONTEXT_TOKENS = 4096

/** Characters per token, pessimistic. Measured 2.65 on the request that overflowed. */
export const CHARS_PER_TOKEN = 3.2

/** Token cost of a string (or of a character count, for text not worth materialising). */
export function estimateTokens(text: string | number): number {
	const chars = typeof text === "number" ? text : text.length
	if (!(chars > 0)) return 0
	return Math.ceil(chars / CHARS_PER_TOKEN)
}

/** How many characters a token allowance can pay for — the pessimistic direction of `estimateTokens`. */
export function tokensToChars(tokens: number): number {
	if (!(tokens > 0)) return 0
	return Math.floor(tokens * CHARS_PER_TOKEN)
}

/**
 * Keep whole items, newest first, until the budget is spent.
 *
 * Walks backwards and breaks on the first item that does not fit, so the result is always a
 * contiguous suffix of the input — never a sparse selection with holes in the middle. Items come
 * back in their original (oldest-first) order. A newest item larger than the whole budget yields an
 * empty result: the caller then sends none of them rather than a fragment.
 */
export function fitNewestFirst<T>(
	items: T[],
	size: (item: T) => number,
	budgetTokens: number,
): T[] {
	const kept: T[] = []
	let spent = 0
	for (let i = items.length - 1; i >= 0; i--) {
		const cost = size(items[i] as T)
		if (spent + cost > budgetTokens) break
		spent += cost
		kept.push(items[i] as T)
	}
	kept.reverse()
	return kept
}

/**
 * Tokens left for the variable part of one call: the window, minus what the call's fixed text
 * already costs, minus the room its answer needs. Never negative — a zero budget means "send no
 * optional content", which the callers handle, as opposed to a negative one that no comparison
 * means anything for.
 *
 * `fixedChars` accepts a character count so callers can measure their own prompt by rendering it
 * with the variable part empty. A missing / absurd `contextTokens` falls back to the served window.
 */
export function callBudget(
	contextTokens: number | undefined,
	fixedChars: number,
	reserveTokens: number,
): number {
	const window =
		typeof contextTokens === "number" && Number.isFinite(contextTokens) && contextTokens > 0
			? Math.floor(contextTokens)
			: DEFAULT_CONTEXT_TOKENS
	const fixed = estimateTokens(fixedChars)
	const answer = Number.isFinite(reserveTokens) ? Math.max(0, Math.floor(reserveTokens)) : 0
	return Math.max(0, window - fixed - answer)
}
