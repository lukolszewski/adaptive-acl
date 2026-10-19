/**
 * Baseline for schema-first extraction — Phase 0, then updated when the read rows landed.
 *
 * The intent of this file is that the behavioural diff is reviewable as a TEST diff: the
 * original version asserted, on committed code, which real sentences authorised nothing.
 * Two of those assertions had to flip when `ACTION_MAP` gained read rows and folder reads
 * became scopes. They are kept here in their new form, with the reason attached, so the
 * history is legible rather than quietly edited.
 *
 * The Polish sentence is not localisation coverage. It pins an invariant: authorisation must
 * not depend on English vocabulary, so a sentence in another language must behave exactly
 * like its English equivalent. Note what that invariant does NOT promise — on an endpoint
 * that ignores the schema contract, both languages fall back to the same English word list,
 * so they fail together as well as succeeding together.
 */
import { describe, expect, it } from "vitest"
import {
	applyEvent,
	createLedger,
	eventsFromExtraction,
	ledgerCovers,
	mapActionToCategory,
} from "./auth-ledger.ts"
import type { Ledger } from "./auth-ledger.ts"

const HOME = "/home/u"

function fold(quote: string, action: string, targets: string[]) {
	return eventsFromExtraction(
		{ grants: [{ action, targets, quote }], revocations: [] } as never,
		"m1",
		1,
		quote,
	)
}

function registerAndCover(quote: string, action: string, targets: string[], pending: string, target: string): boolean {
	const l: Ledger = createLedger()
	for (const ev of fold(quote, action, targets)) applyEvent(l, ev)
	return ledgerCovers(l, pending, [{ kind: "target", value: target }], HOME).covered
}

describe("folder READS now register (they did not before the read rows landed)", () => {
	it('"you can read files in /etc" covers a file under /etc', () => {
		expect(registerAndCover("you can read files in /etc", "read files", ["/etc/hosts"], "read_only", "/etc/hosts")).toBe(true)
	})

	it("parity holds for the CATEGORY and breaks for the SCOPE, because the fallback reads English prepositions", () => {
		// "you can read files in /etc", in Polish. The category resolves identically — that part
		// is language-independent because it comes from the action label, not the prose. The
		// folder scope does NOT form: the legacy path scrapes `in|under|inside|below|within`
		// from the user's own words, and Polish "w" is not in that list. That is the defect
		// made visible — the schema's `kind: "scope"` field is what fixes it (tested in
		// schema-first-grants.test.ts), and it only works on an endpoint that enforces the
		// schema. Widening the English preposition list would be the wrong repair.
		const quote = "możesz czytać pliki w /etc"
		// The category resolution IS language-independent, because it reads the model's action
		// label rather than the user's prose. Pin it where it actually lives.
		expect(mapActionToCategory("read files")).toBe("read_only")
		// The scope comes from the user's own words, and Polish "w" is not in the English
		// preposition list — so this sentence produces NO events at all: no scope row, and the
		// only target listed (/etc/hosts) was never named by the user, so the entity row is
		// skipped by targetNamedByUser.
		const events = fold(quote, "read files", ["/etc/hosts"])
		expect(events).toHaveLength(0)
		expect(registerAndCover(quote, "read files", ["/etc/hosts"], "read_only", "/etc/hosts")).toBe(false)
		// Same sentence with an English preposition does register. That asymmetry IS the defect:
		// the fix is the schema's `kind: "scope"` field, not a wider English regex.
	})

	it("a folder READ still cannot authorise a WRITE under it", () => {
		// The direction rule, pinned against the MATCHER rather than against the absence of a
		// row: read_only and write_outside are different kind groups, and the mutation-only
		// escape in grantMatchesPending additionally requires the grant category to be a
		// mutating one. Making reads produce scopes must not leak into write authority.
		const quote = "you can read files in /etc"
		expect(registerAndCover(quote, "read files", ["/etc/hosts"], "read_only", "/etc/hosts")).toBe(true)
		expect(registerAndCover(quote, "read files", ["/etc/hosts"], "write_outside", "/etc/other.conf")).toBe(false)
		expect(registerAndCover(quote, "read files", ["/etc/hosts"], "delete_outside", "/etc/hosts")).toBe(false)
	})

	it("and the label is a real category, not an invented one that matches nothing", () => {
		const events = fold("I allow you to read /home/u/.pi config contents", "read files", ["/home/u/.pi"])
		expect(events.every((e) => !(e.category.startsWith("*") && e.category.endsWith("*")))).toBe(true)
		expect(events.some((e) => e.category === "read_only")).toBe(true)
	})
})

describe("what still authorises nothing, and should", () => {
	it("a folder READ does not reach secret-bearing paths under it (kind groups differ)", () => {
		// The blocked call classifies as read_secret; the grant is read_only. This split is
		// deliberate — it is what stops "read this folder" from quietly unlocking credentials
		// inside it. Reaching secrets needs an explicit inclusion, which on a non-strict
		// endpoint cannot be expressed at all: see the schema-not-honoured warning in
		// /classifier-status and DIRECTED-PERMISSIONS-PLAN.md.
		const quote = "I allow you to read /home/u/.pi config contents"
		expect(registerAndCover(quote, "read files", ["/home/u/.pi"], "read_secret", "/home/u/.pi/agent/permission-modes.json")).toBe(false)
	})

	it("the Polish equivalent fails the same way, for the same reason", () => {
		const quote = "zezwalam ci na odczyt /home/u/.pi"
		expect(registerAndCover(quote, "read files", ["/home/u/.pi"], "read_secret", "/home/u/.pi/agent/permission-modes.json")).toBe(false)
	})

	it('"write into /dir" still yields no entries — "into" is not in the preposition list', () => {
		// Left in place: the prose preposition path is the LEGACY fallback. The correct fix is
		// the model's `kind: "scope"` field, not a wider English regex — see
		// schema-first-grants.test.ts for the version that works without any preposition.
		expect(fold("you can write into /home/u/dev/wt", "write", ["/home/u/dev/wt/one.ts"])).toHaveLength(0)
	})
})

describe("what always worked, and stays working", () => {
	it("a named file grant covers that file and not its sibling", () => {
		const quote = "you can write into /home/u/dev/wt/one.ts"
		expect(registerAndCover(quote, "write", ["/home/u/dev/wt/one.ts"], "write_outside", "/home/u/dev/wt/one.ts")).toBe(true)
		expect(registerAndCover(quote, "write", ["/home/u/dev/wt/one.ts"], "write_outside", "/home/u/dev/wt/two.ts")).toBe(false)
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
