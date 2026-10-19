/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The ledger as text — the part of the grant call that stands in for the turns too old to be sent
 * raw. What these pins protect is the CONTRACT the model reads: one line per row, oldest first, the
 * user's own words attached, and nothing invented. The budget half protects the other direction: a
 * row that does not fit is dropped whole, and the rows that survive are the newest ones, because the
 * fold they are summarising decides by "the later word wins".
 */
import { describe, expect, it } from "vitest"
import { homedir } from "node:os"
import { applyEvents, createLedger, type ExtractedEvent } from "./auth-ledger.ts"
import { estimateTokens } from "./context-budget.ts"
import {
	LEDGER_ROW_QUOTE_CHARS,
	LEDGER_SHARE,
	fitLedgerRows,
	ledgerRows,
	type RenderedRow,
} from "./ledger-render.ts"

function ledgerOf(events: ExtractedEvent[]) {
	const ledger = createLedger()
	applyEvents(ledger, events)
	return ledger
}

/** Long enough to be clipped, one line, no repeats that would make a wrong slice look right. */
const LONG_QUOTE = "you can copy whatever you need into the scratch folder whenever you like ".repeat(6)

describe("ledgerRows renders one line per row", () => {
	const long = LONG_QUOTE
	const ledger = ledgerOf([
		{ type: "grant", category: "write_outside", value: "~/dev/x/", kind: "scope", quote: long, messageId: "m3", seq: 3 },
		{ type: "forbid", category: "*", value: "/etc/", kind: "scope", quote: "never touch /etc", messageId: "m5", seq: 5 },
		{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "don't change anything", messageId: "m6", seq: 6 },
		{
			type: "grant",
			category: "*frobnicate widgets*",
			value: "/srv/data/report.csv",
			kind: "entity",
			quote: 'frobnicate "/srv/data/report.csv"',
			messageId: "m7",
			seq: 7,
		},
	])

	it("one line per row, oldest first: grants, forbids and the posture", () => {
		const rows = ledgerRows(ledger)
		expect(rows.map((r) => r.seq)).toEqual([3, 5, 6, 7])
		expect(rows.map((r) => r.text)).toEqual([
			`#3 grant   write_outside scope=${homedir()}/dev/x/ — "${long.slice(0, LEDGER_ROW_QUOTE_CHARS)}…"`,
			`#5 forbid  * scope=/etc/ — "never touch /etc"`,
			`#6 posture read-only — "don't change anything"`,
			`#7 grant   *frobnicate widgets* entity=/srv/data/report.csv — "frobnicate "/srv/data/report.csv""`,
		])
	})

	it("expands `~` in a stored value, because the model has never seen this machine", () => {
		const [row] = ledgerRows(ledger)
		expect(row!.text).toContain(`scope=${homedir()}/dev/x/`)
		expect(row!.text).not.toContain("=~/")
	})

	// The two fields have different jobs: `text` is what the model sees, `quote` is what the verifier
	// searches for. Clipping the second one would make a legitimate grant unverifiable.
	it("clips the quote in the line and nowhere else", () => {
		expect(long.length).toBeGreaterThan(LEDGER_ROW_QUOTE_CHARS)
		const [row] = ledgerRows(ledger)
		expect(row!.text).toContain(`${long.slice(0, LEDGER_ROW_QUOTE_CHARS)}…`)
		expect(row!.text).not.toContain(long)
		expect(row!.quote).toBe(long)
	})

	it("keeps a free-text category exactly as stored — it says what the user said", () => {
		const row = ledgerRows(ledger)[3]!
		expect(row.text).toContain("*frobnicate widgets* entity=/srv/data/report.csv")
	})

	it("renders nothing but what the ledger holds, and is one line per row", () => {
		const rows = ledgerRows(ledger)
		expect(rows).toHaveLength(4)
		for (const row of rows) {
			expect(row.text).not.toContain("\n")
			expect(row.text.split("\n")).toHaveLength(1)
		}
	})
})

describe("ledgerRows edge cases", () => {
	it("returns nothing for an empty ledger", () => {
		expect(ledgerRows(createLedger())).toEqual([])
	})

	it("puts imported rows first, marked, at #0", () => {
		const ledger = createLedger()
		ledger.grants.push({
			category: "write_outside",
			value: "/mnt/nas/reports/",
			kind: "scope",
			quote: "work out of the reports share",
			messageId: "",
			seq: 0,
			origin: "imported",
		})
		ledger.grants.push({
			category: "perm_change",
			value: "/srv/app",
			kind: "entity",
			quote: "chmod the app dir",
			messageId: "m2",
			seq: 2,
		})
		ledger.forbids.push({
			category: "*",
			value: "/srv/app/secrets/",
			kind: "scope",
			quote: "but never the secrets folder",
			messageId: "",
			seq: 0,
			origin: "imported",
		})
		const rows = ledgerRows(ledger)
		expect(rows.map((r) => r.text)).toEqual([
			`#0 grant imported write_outside scope=/mnt/nas/reports/ — "work out of the reports share"`,
			`#0 forbid imported * scope=/srv/app/secrets/ — "but never the secrets folder"`,
			`#2 grant   perm_change entity=/srv/app — "chmod the app dir"`,
		])
	})

	it("omits the posture once a later message lifted it", () => {
		const on = { type: "readonly-on" as const, category: "*", value: "*", kind: "scope" as const, quote: "don't change anything", messageId: "m1", seq: 1 }
		expect(ledgerRows(ledgerOf([on])).map((r) => r.text)).toEqual([`#1 posture read-only — "don't change anything"`])
		const ledger = ledgerOf([on, { type: "readonly-off", category: "*", value: "*", kind: "scope", quote: "ok you can make changes now", messageId: "m4", seq: 4 }])
		expect(ledgerRows(ledger)).toEqual([])
	})

	it("orders a grant and a forbid said in the same message grant-first, and flattens a quoted newline", () => {
		const ledger = ledgerOf([
			{ type: "forbid", category: "*", value: "/srv/app/tmp/", kind: "scope", quote: "not the tmp subfolder", messageId: "m4", seq: 4 },
			{ type: "grant", category: "write_outside", value: "/srv/app/", kind: "scope", quote: "write into\n/srv/app, but", messageId: "m4", seq: 4 },
		])
		const rows = ledgerRows(ledger)
		expect(rows.map((r) => r.text)).toEqual([
			`#4 grant   write_outside scope=/srv/app/ — "write into /srv/app, but"`,
			`#4 forbid  * scope=/srv/app/tmp/ — "not the tmp subfolder"`,
		])
	})
})

/** Four equal-width rows: cost per row is identical, so a budget buys exactly that many. */
function sampleRows(): RenderedRow[] {
	return [1, 2, 3, 4].map((seq) => ({ seq, text: `#${seq} grant   write_outside scope=/srv/${"x".repeat(18)}/ — "q"`, quote: "q" }))
}

describe("fitLedgerRows keeps the newest rows whole", () => {
	const rows = sampleRows()
	const cost = (row: RenderedRow) => estimateTokens(row.text.length)

	it("keeps as many newest rows as fit, returned oldest first", () => {
		// equal-width rows, so 2 rows cost exactly 2 * cost and 3 rows are over any 2-row budget
		const kept = fitLedgerRows(rows, cost(rows[3]!) * 2)
		expect(kept).toEqual([rows[2], rows[3]])
		expect(kept.map((r) => r.seq)).toEqual([3, 4])
	})

	it("keeps all of them when they all fit, and none at a budget of 0", () => {
		expect(fitLedgerRows(rows, cost(rows[3]!) * 4)).toEqual(rows)
		expect(fitLedgerRows(rows, 0)).toEqual([])
		expect(fitLedgerRows([], 1000)).toEqual([])
	})

	it("stops at the first row that does not fit instead of reaching an older one", () => {
		const big: RenderedRow = { seq: 2, text: `#2 grant   ${"y".repeat(400)}`, quote: "y" }
		const mixed = [rows[0]!, big, rows[3]!]
		const kept = fitLedgerRows(mixed, cost(rows[3]!))
		expect(kept).toEqual([rows[3]!])
	})
})

describe("the row share", () => {
	it("is a fixed minority of the call, leaving the majority for raw messages", () => {
		expect(LEDGER_SHARE).toBeGreaterThan(0)
		expect(LEDGER_SHARE).toBeLessThanOrEqual(0.5)
	})
})
