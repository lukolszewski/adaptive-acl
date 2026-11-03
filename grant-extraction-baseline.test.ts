/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Baseline for schema-first extraction, updated as the read rows landed and again when the English word
 * list and the location-preposition regex were deleted.
 *
 * The intent of this file is that the behavioural diff is reviewable as a TEST diff: the original
 * version asserted, on committed code, which real sentences authorised nothing. Several of those
 * assertions had to flip — twice — and they are kept here in their new form with the reason attached,
 * so the history is legible rather than quietly edited.
 *
 * The Polish sentences are not localisation coverage. They pin an invariant: authorisation must not
 * depend on English vocabulary, so a sentence in another language must behave exactly like its English
 * equivalent. Before that change the invariant held only halfway — the CATEGORY came from the model's answer
 * while the folder SCOPE was scraped out of the prose with an English preposition list, so the Polish
 * sentence lost its folder grant and the English one kept it. Both halves now come from fields, and the
 * recorded rows below are byte-identical apart from the sentence in `quote`.
 *
 * FIXTURE PROVENANCE: every payload is recorded model output for the message quoted beside it, through
 * the same call the gate makes. Garbage-input rows are labelled as such and are not claims about what the
 * model answers.
 */
import { describe, expect, it } from "vitest"
import {
	applyEvent,
	createLedger,
	eventsFromExtraction,
	ledgerCovers,
} from "./auth-ledger.ts"
import type { Ledger } from "./auth-ledger.ts"

const HOME = "/home/u"

/** One recorded grant row, quoted out of the message it was extracted from. */
type Row = {
	action: string
	category?: string
	kind?: string
	scope?: string
	includesSecrets?: boolean
	targets: string[]
}

function fold(quote: string, row: Row) {
	return eventsFromExtraction(
		{ grants: [{ quote, ...row }], revocations: [] } as never,
		"m1",
		1,
		quote,
	)
}

function registerAndCover(quote: string, row: Row, pending: string, target: string): boolean {
	const l: Ledger = createLedger()
	for (const ev of fold(quote, row)) applyEvent(l, ev)
	return ledgerCovers(l, pending, [{ kind: "target", value: target }], HOME).covered
}

/** Recorded for "you can read files in /etc" and, identically, for its Polish equivalent. */
const ETC_READ = { action: "read files", category: "read_only", kind: "scope", scope: "named", includesSecrets: false, targets: ["/etc"] }
/** Recorded for "I allow you to read /home/u/.pi config contents". */
const PI_READ = { action: "read config files", category: "read_only", kind: "scope", scope: "named", includesSecrets: false, targets: ["/home/u/.pi"] }

describe("folder READS register from the model's `kind`, not from a preposition", () => {
	it('"you can read files in /etc" covers a file under /etc', () => {
		expect(registerAndCover("you can read files in /etc", ETC_READ, "read_only", "/etc/hosts")).toBe(true)
	})

	it("the same permission in Polish behaves the same — CATEGORY and SCOPE both come from fields", () => {
		// "możesz czytać pliki w /etc", recorded. Before this change the sentence produced NOTHING: the
		// category came from the model but the folder scope was scraped from the prose with
		// `/\b(?:in|under|inside|below|within)\s+(~?\/…)/i`, and Polish "w" is not in that list. That was a
		// defect, and this file's own note said the fix is the schema's `kind: "scope"` field rather
		// than a wider English list. The regex is deleted; the field is what the code reads, so the two
		// sentences now behave identically — which is the invariant the original file could only assert
		// halfway.
		const pl = "możesz czytać pliki w /etc"
		const events = fold(pl, ETC_READ)
		expect(events.map((e) => `${e.category}:${e.kind}:${e.value}`)).toEqual(["read_only:scope:/etc/"])
		expect(registerAndCover(pl, ETC_READ, "read_only", "/etc/hosts")).toBe(true)
	})

	it("a folder READ still cannot authorise a WRITE under it", () => {
		// The direction rule, pinned against the MATCHER rather than against the absence of a row:
		// read_only and write_outside are different kind groups, and the mutation-only escape in
		// grantMatchesPending additionally requires the grant category to be a mutating one. Making reads
		// produce scopes must not leak into write authority.
		const quote = "you can read files in /etc"
		expect(registerAndCover(quote, ETC_READ, "read_only", "/etc/hosts")).toBe(true)
		expect(registerAndCover(quote, ETC_READ, "write_outside", "/etc/other.conf")).toBe(false)
		expect(registerAndCover(quote, ETC_READ, "delete_outside", "/etc/hosts")).toBe(false)
	})

	it("and the label is a real category, not an invented one that matches nothing", () => {
		const quote = "I allow you to read /home/u/.pi config contents"
		const events = fold(quote, PI_READ)
		expect(events.every((e) => !(e.category.startsWith("*") && e.category.endsWith("*")))).toBe(true)
		expect(events.some((e) => e.category === "read_only")).toBe(true)
	})

	it("a grant whose category the gate cannot match registers nothing — and never a guessed one", () => {
		// Garbage pin: the word list that used to fill this in is gone, so an endpoint that
		// ignores the enum produces no row. The cost is the prompt the user would have got anyway; the
		// alternative — inventing a category — is what made a display label into authority.
		for (const junk of [undefined, "other", "READ FILES!"]) {
			const rows = fold("you can read files in /etc", { ...ETC_READ, category: junk, action: "frobnicate widgets" })
			expect(rows, String(junk)).toEqual([])
		}
	})
})

describe("what still authorises nothing, and should", () => {
	it("a folder READ does not reach secret-bearing paths under it (kind groups differ)", () => {
		// The blocked call classifies as read_secret; the grant is read_only. This split is
		// deliberate — it is what stops "read this folder" from quietly unlocking credentials
		// inside it. Reaching secrets needs an explicit inclusion (`includesSecrets`), which the
		// extraction model sets and this file records as a second row.
		const quote = "I allow you to read /home/u/.pi config contents"
		expect(registerAndCover(quote, PI_READ, "read_secret", "/home/u/.pi/agent/adaptive-acl.json")).toBe(false)
	})

	it("the Polish equivalent fails the same way, for the same reason", () => {
		// Recorded for "zezwalam ci na odczyt /home/u/.pi": the same row, so the same non-coverage.
		const quote = "zezwalam ci na odczyt /home/u/.pi"
		expect(registerAndCover(quote, PI_READ, "read_secret", "/home/u/.pi/agent/adaptive-acl.json")).toBe(false)
	})

	it('"write into /dir" registers the folder, because `kind` says so and no preposition is read', () => {
		// This used to assert ZERO events ("into" was not in the English preposition
		// list) while "worktree in /dir" did register. That asymmetry was a defect — two spellings of
		// one permission behaving differently because of a preposition. Recorded, the model answers
		// `kind: "scope"` here, so the folder registers; the English wording no longer decides anything.
		const quote = "you can write into /home/u/dev/wt"
		const row = { action: "write files", category: "write_outside", kind: "scope", scope: "named", includesSecrets: false, targets: ["/home/u/dev/wt"] }
		const events = fold(quote, row)
		expect(events.map((e) => `${e.kind}:${e.value}`)).toEqual(["scope:/home/u/dev/wt/"])
		expect(registerAndCover(quote, row, "write_outside", "/home/u/dev/wt/one.ts")).toBe(true)
		expect(registerAndCover(quote, row, "write_outside", "/home/u/dev/other.ts")).toBe(false)
	})
})

describe("what always worked, and stays working", () => {
	it("a named file grant covers that file and not its sibling", () => {
		// Recorded for this exact sentence: `kind: "entity"`, so one file and no folder.
		const quote = "you can write into /home/u/dev/wt/one.ts"
		const row = { action: "write file", category: "write_project", kind: "entity", scope: "named", includesSecrets: false, targets: ["/home/u/dev/wt/one.ts"] }
		expect(registerAndCover(quote, row, "write_project", "/home/u/dev/wt/one.ts")).toBe(true)
		expect(registerAndCover(quote, row, "write_project", "/home/u/dev/wt/two.ts")).toBe(false)
	})
})

describe("LedgerEntry field round-trip", () => {
	// Was pinned with it.fails to prove the defect; now asserts the fix. Kept because the
	// trap is structural, not historical: applyEvent lists fields explicitly, so the next
	// field added to LedgerEntry is silently dropped unless it is added here too.
	it("includesSecrets survives applyEvent", () => {
		const l = createLedger()
		applyEvent(l, {
			type: "grant",
			category: "read_path",
			value: "/home/u/.pi/",
			kind: "scope",
			quote: "czytaj wszystko w /home/u/.pi, także sekrety",
			messageId: "m1",
			seq: 1,
			includesSecrets: true,
		} as never)
		expect(l.grants[0]?.includesSecrets).toBe(true)
	})

	it("a newer sentence that drops the inclusion does not inherit it", () => {
		const l = createLedger()
		applyEvent(l, {
			type: "grant",
			category: "read_path",
			value: "/home/u/.pi/",
			kind: "scope",
			quote: "czytaj wszystko w /home/u/.pi, także sekrety",
			messageId: "m1",
			seq: 1,
			includesSecrets: true,
		} as never)
		applyEvent(l, {
			type: "grant",
			category: "read_path",
			value: "/home/u/.pi/",
			kind: "scope",
			quote: "czytaj wszystko w /home/u/.pi",
			messageId: "m2",
			seq: 2,
		} as never)
		expect(l.grants).toHaveLength(1)
		expect(l.grants[0]?.includesSecrets).toBeUndefined()
	})
})
