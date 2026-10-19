/**
 * The authorisation ledger as the summary of the turns that no longer fit the call
 * (docs/CLASSIFIER-CONTEXT-BUDGET-PLAN.md item 3).
 *
 * A 4 096-token window holds the newest handful of user messages, so in a long session the sentence
 * in which the user actually granted something scrolls out of the grant-transcript call. It is not
 * lost: that sentence already sits in the ledger as a row — model-extracted, quote-verified, cached —
 * and rendering those rows costs no model call at all. The rows are therefore the summary of the older
 * turns, and the newest raw messages keep whatever space is left.
 *
 * What this deliberately is NOT: a summariser. Nothing here writes prose about what the user "meant".
 * A sentence like "the user allowed writes to /x" would be a fresh authority path that `verifyGrant`
 * can check against nothing, so every row carries the user's own words and the verifier still insists
 * that one of them appears verbatim. Rendering can move those words into the window; it cannot invent
 * them, and it cannot widen what any of them covers.
 */

import { homedir } from "node:os"
import { readOnlyActive, type Ledger, type LedgerEntry } from "./auth-ledger.ts"
import { estimateTokens, fitNewestFirst } from "./context-budget.ts"
import { absolutize } from "./model-client.ts"

/** A quote this long is shown in full; longer ones are cut with a trailing ellipsis. The cut is
 *  cosmetic and lives only in the rendered line — the row's `quote` field stays verbatim, because
 *  that is what the verifier searches for. */
export const LEDGER_ROW_QUOTE_CHARS = 120

/** Share of the call budget the rows may take. The rest is for raw messages, and whatever the rows
 *  do not spend goes back to them (the gate re-measures the fixed part with the rows in it). */
export const LEDGER_SHARE = 0.4

/** A row is one line; the newline that separates it from the next one is part of what we send. */
const ROW_LINE_CHARS = 1

/** Kind column width, so the categories of consecutive rows line up in the prompt: `grant`, `forbid`
 *  and `posture` padded to this, then one separating space, is the layout the spec pins. */
const KIND_COLUMN = 7

export type RenderedRow = {
	seq: number
	/** The whole line as it goes into the prompt (quote clipped, one line, no newlines). */
	text: string
	/** The UNCLIPPED verbatim quote of the row — the haystack the verifier may match against. */
	quote: string
}

type RowSpec = {
	seq: number
	kind: "grant" | "forbid" | "posture"
	/** Rows carried in from a grants file sit at `seq 0`: background authority, said earlier than
	 *  anything on this branch, so they lead the list and say so. */
	imported: boolean
	/** Free text for an action the category table could not name (`*copy files*`); kept as stored —
	 *  it tells the model what the user said even where the gate can never match the row. */
	category?: string
	valueKind?: "entity" | "scope"
	value?: string
	quote: string
}

const KIND_ORDER: Record<RowSpec["kind"], number> = { grant: 0, forbid: 1, posture: 2 }

/** Collapse every whitespace run: the rendered line must never contain a newline, whatever the
 *  user's original sentence looked like (pasted messages carry them). */
function oneLine(text: string): string {
	return text.replace(/\s+/g, " ").trim()
}

function clipQuote(text: string): string {
	return text.length > LEDGER_ROW_QUOTE_CHARS ? `${text.slice(0, LEDGER_ROW_QUOTE_CHARS)}…` : text
}

function fromEntry(entry: LedgerEntry, kind: "grant" | "forbid"): RowSpec {
	return {
		seq: entry.seq,
		kind,
		imported: entry.origin === "imported",
		category: entry.category,
		valueKind: entry.kind,
		value: entry.value,
		quote: entry.quote,
	}
}

/** Oldest first: imported rows (always `seq 0`), then `seq` ascending, grants before forbids.
 *  `seq` is the branch ordinal, so ascending `seq` is also the order the user said them in — which
 *  is why a higher `seq` beats a lower one in the fold, and why the line prints it. */
function byAge(a: RowSpec, b: RowSpec): number {
	if (a.imported !== b.imported) return a.imported ? -1 : 1
	if (a.seq !== b.seq) return a.seq - b.seq
	return KIND_ORDER[a.kind] - KIND_ORDER[b.kind]
}

function render(spec: RowSpec): RenderedRow {
	const label = (spec.imported ? `${spec.kind} imported` : spec.kind).padEnd(KIND_COLUMN)
	const subject =
		spec.kind === "posture"
			? "read-only"
			: // `~` means nothing to a model that has never seen this machine, so values go out
				// absolute exactly as the pending action's targets do (see `absolutize`).
				`${oneLine(spec.category ?? "")} ${spec.valueKind}=${absolutize(spec.value ?? "", homedir())}`
	return {
		seq: spec.seq,
		text: `#${spec.seq} ${label} ${subject} — "${clipQuote(oneLine(spec.quote))}"`,
		quote: spec.quote,
	}
}

/** Every row of the ledger as one line each, oldest first. */
export function ledgerRows(ledger: Ledger): RenderedRow[] {
	const specs: RowSpec[] = [
		...ledger.grants.map((g) => fromEntry(g, "grant")),
		...ledger.forbids.map((f) => fromEntry(f, "forbid")),
	]
	// `readOnlyActive` already applies the on/off precedence: a later "you can make changes now"
	// means there is no posture to report.
	const posture = readOnlyActive(ledger)
	if (posture) specs.push({ seq: posture.seq, kind: "posture", imported: false, quote: posture.quote })
	return specs.sort(byAge).map(render)
}

/**
 * Whole rows only, newest first, returned oldest first — the same rule the raw messages follow
 * (`fitNewestFirst`). Higher `seq` has precedence in the fold because the fold is "the user's later
 * word beats the earlier one", so dropping must start from the oldest end.
 */
export function fitLedgerRows(rows: RenderedRow[], budgetTokens: number): RenderedRow[] {
	return fitNewestFirst(rows, (row) => estimateTokens(row.text.length + ROW_LINE_CHARS), budgetTokens)
}
