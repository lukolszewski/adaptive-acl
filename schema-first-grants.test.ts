/**
 * Schema-first authorisation extraction.
 *
 * The point of these tests is not that a new field works. It is that the category, the
 * shape (file vs location) and the secret-inclusion decision arrive as STRUCTURE, so the
 * authorisation path never has to read English. `grant-extraction-baseline.test.ts` pins
 * what the legacy word list could not do; this file pins what the enum can.
 */
import { describe, expect, it, beforeEach } from "vitest"
import {
	GRANT_CATEGORY_VALUES,
	applyEvent,
	createLedger,
	eventsFromExtraction,
	isGrantCategory,
	ledgerCovers,
	resetExtractionStats,
	extractionStats,
} from "./auth-ledger.ts"
import { MESSAGE_GRANT_SYSTEM_PROMPT } from "./model-client.ts"
import type { Ledger, MessageGrantExtraction } from "./auth-ledger.ts"

const HOME = "/home/u"

/**
 * The fixture shape: a grant-only extraction.
 *
 * `MessageGrantExtraction` also demands `revocations`, which every case here answers with an empty
 * list and none of them exercises — revocations have their own suite (`tombstones.test.ts`). Taking
 * just the `grants` member says which half of the payload these tests are about, and lets the
 * legacy fixture below be written as what it is instead of smuggled through a cast.
 */
type GrantsOnly = Pick<MessageGrantExtraction, "grants">

function fold(x: GrantsOnly, messageText: string) {
	return eventsFromExtraction({ grants: x.grants ?? [], revocations: [] } as never, "m1", 1, messageText)
}

function covers(x: GrantsOnly, messageText: string, pending: string, target: string): boolean {
	const l: Ledger = createLedger()
	for (const ev of fold(x, messageText)) applyEvent(l, ev)
	return ledgerCovers(l, pending, [{ kind: "target", value: target }], HOME).covered
}

beforeEach(() => resetExtractionStats())

describe("the shape decision is structure, not prose", () => {
	const polish = "zezwalam ci na odczyt wszystkiego w /home/u/.config, bez sekretów"
	const polishGrant: GrantsOnly = {
		grants: [
			{
				action: "read files",
				category: "read_only",
				kind: "scope",
				includesSecrets: false,
				targets: ["/home/u/.config"],
				quote: polish,
			},
		],
	}

	it("a folder permission covers files under it — in Polish, with no English parsed", () => {
		expect(covers(polishGrant, polish, "read_only", "/home/u/.config/user/settings.xml")).toBe(true)
		expect(extractionStats.fromSchema).toBe(1)
		expect(extractionStats.scopes).toBe(1)
	})

	it("and still does not reach secrets, because inclusion is a separate field", () => {
		expect(covers(polishGrant, polish, "read_secret", "/home/u/.config/openssh/secret_key")).toBe(false)
	})

	it("the same sentence with includesSecrets true DOES cover them, as its own row", () => {
		const quote = "zezwalam ci na odczyt wszystkiego w /home/u/.config, także sekretów"
		const withSecrets: GrantsOnly = {
			grants: [
				{
					action: "read files",
					category: "read_only",
					kind: "scope",
					includesSecrets: true,
					targets: ["/home/u/.config"],
					quote,
				},
			],
		}
		// Counted from a clean baseline: these counters track extraction CALLS, and the
		// coverage check below extracts again on purpose.
		resetExtractionStats()
		const events = fold(withSecrets, quote)
		expect(events.some((e) => e.category === "read_secret" && e.kind === "scope" && e.includesSecrets === true)).toBe(true)
		expect(extractionStats.secretInclusions).toBe(1)
		expect(covers(withSecrets, quote, "read_secret", "/home/u/.config/openssh/secret_key")).toBe(true)
	})

	it("an entity grant stays exactly one file: no silent widening to its folder", () => {
		const quote = "możesz zapisać /home/u/dev/wt/one.ts"
		const entity: GrantsOnly = {
			grants: [
				{ action: "write", category: "write_outside", kind: "entity", includesSecrets: false, targets: ["/home/u/dev/wt/one.ts"], quote },
			],
		}
		expect(covers(entity, quote, "write_outside", "/home/u/dev/wt/one.ts")).toBe(true)
		expect(covers(entity, quote, "write_outside", "/home/u/dev/wt/two.ts")).toBe(false)
	})

	it("a FILE path wrongly marked as a scope covers that file and nothing else", () => {
		const quote = "write /home/u/dev/wt/one.ts"
		const mislabelled: GrantsOnly = {
			grants: [
				{ action: "write", category: "write_outside", kind: "scope", includesSecrets: false, targets: ["/home/u/dev/wt/one.ts"], quote },
			],
		}
		// It covers its own path (valueCovers treats "x/" as covering "x"), but it cannot
		// reach a sibling: a wrong kind degrades toward the narrow answer, never the wide one.
		expect(covers(mislabelled, quote, "write_outside", "/home/u/dev/wt/one.ts")).toBe(true)
		expect(covers(mislabelled, quote, "write_outside", "/home/u/dev/wt/other.ts")).toBe(false)
		expect(covers(mislabelled, quote, "write_outside", "/home/u/dev/wt/deep/nested.ts")).toBe(false)
	})
})

describe("the category enum is authoritative, and unverifiable values die", () => {
	it("a category the enum does not contain never becomes a wildcard", () => {
		const quote = "you may wipe everything at /srv/data"
		const bogus: GrantsOnly = {
			grants: [
				{ action: "delete files", category: "delete_everything", kind: "entity", includesSecrets: false, targets: ["/srv/data/x"], quote },
			],
		}
		expect(isGrantCategory("delete_everything")).toBe(false)
		// falls through to the word list, which maps "delete files" — no invented category
		expect(covers(bogus, quote, "delete_everything", "/srv/data/x")).toBe(false)
	})

	it("gate-internal states are not authorisable categories", () => {
		for (const s of ["unproven_value", "unproven_structure", "unknown_command", "interpreter_unknown", "unparseable_command"]) {
			expect(isGrantCategory(s)).toBe(false)
		}
	})

	it("the prompt offers exactly the enum the ledger will accept", () => {
		for (const c of GRANT_CATEGORY_VALUES) expect(MESSAGE_GRANT_SYSTEM_PROMPT).toContain(c)
		expect(MESSAGE_GRANT_SYSTEM_PROMPT).not.toContain("unproven_value")
		expect(GRANT_CATEGORY_VALUES).toContain("other")
	})

	it('"other" falls through to the legacy table rather than matching nothing silently', () => {
		const quote = "you can push to the remote"
		const other: GrantsOnly = {
			grants: [{ action: "push to remote", category: "other", kind: "entity", includesSecrets: false, targets: [], quote }],
		}
		fold(other, quote)
		// The only assertions that matter here: "other" is not treated as a category, and the
		// recovery is attributed to the word list so it is visible in /classifier-status.
		expect(extractionStats.fromSchema).toBe(0)
		expect(extractionStats.legacyWordList).toBe(1)
	})
})

describe("the legacy word list is a counted fallback, not the authorisation path", () => {
	it("still works when the endpoint returns no category at all", () => {
		const quote = "you can delete files under /var/tmp/jobs/"
		const legacy: GrantsOnly = {
			grants: [{ action: "delete files", targets: ["/var/tmp/jobs/"], quote }],
		}
		expect(covers(legacy, quote, "delete_outside", "/var/tmp/jobs/a.txt")).toBe(true)
		expect(extractionStats.fromSchema).toBe(0)
		expect(extractionStats.legacyWordList).toBe(1)
	})

	it("and is preferred AGAINST when a real enum value is present", () => {
		// action says "write", category says read_only: the enum wins, because the action
		// string is a display label with no authority.
		const quote = "you can read files in /home/u/.config/"
		const g: GrantsOnly = {
			grants: [{ action: "write files", category: "read_only", kind: "scope", includesSecrets: false, targets: ["/home/u/.config/"], quote }],
		}
		expect(covers(g, quote, "read_only", "/home/u/.config/app.conf")).toBe(true)
		expect(covers(g, quote, "write_outside", "/home/u/.config/app.conf")).toBe(false)
	})
})
