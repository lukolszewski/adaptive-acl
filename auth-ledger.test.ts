/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, afterAll, it } from "vitest"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
	applyEvent,
	applyEvents,
	createLedger,
	deserializeLedger,
	eventsFromExtraction,
	explainLedgerCover,
	extractionStats,
	importLedger,
	isSyntheticUserTurn,
	kindGroup,
	ledgerCovers,
	MAX_FORBIDS,
	MAX_GRANTS,
	namedForbidCovers,
	readOnlyActive,
	readOnlyLiftedByGrant,
	resetExtractionStats,
	revokeLedgerForbids,
	revokeLedgerGrants,
	serializeLedger,
	type ExtractedEvent,
	type Ledger,
} from "./auth-ledger.ts"
import { runGate } from "./gate.ts"
import { mergeIntoGrantsFile, readGrantsFile } from "./grants-file.ts"
import type { Entity } from "./risk-policy.ts"

const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

function grant(category: string, value: string, seq: number, quote = `you can do it to ${value}`, kind?: "entity" | "scope"): ExtractedEvent {
	return { type: "grant", category, value, kind: kind ?? (value.endsWith("/") ? "scope" : "entity"), quote, messageId: `m${seq}`, seq }
}
function forbid(value: string, seq: number, quote = `do not touch ${value}`, category = "*"): ExtractedEvent {
	return { type: "forbid", category, value, kind: value.endsWith("/") ? "scope" : "entity", quote, messageId: `m${seq}`, seq }
}

/** Fold derived events into a fresh ledger — the shape three blocks below repeat. */
function createLedgerWith(events: ExtractedEvent[]): Ledger {
	const l = createLedger()
	applyEvents(l, events)
	return l
}

/**
 * Fixture provenance.
 *
 * Every `category` / `scope` / `targetClass` / `kind` value in the extraction payloads below is copied from an
 * answer a model actually gave for the message next to it, not invented. Where a payload adds a value the
 * model did not return, the comment says so and the point is a garbage-input pin, not a claim about what the
 * model answers.
 */

describe("kind groups / the enum is the only category source", () => {
	it("keeps the three fs-mutation kinds apart, and unrelated domains apart", () => {
		// Content, destruction and privilege are three harm classes, not one. They shared
		// fs-write until the split; lumping them let a folder write grant authorise chmod.
		expect(kindGroup("write_outside")).toBe("fs-write")
		expect(kindGroup("delete_recursive")).toBe("fs-delete")
		expect(kindGroup("perm_change")).toBe("fs-perm")
		expect(kindGroup("write_outside")).not.toBe(kindGroup("delete_recursive"))
		expect(kindGroup("write_outside")).not.toBe(kindGroup("perm_change"))
		expect(kindGroup("write_outside")).not.toBe(kindGroup("package_system"))
		expect(kindGroup("cluster_mutation")).toBe(kindGroup("container_mutation"))
		expect(kindGroup("vcs_remote")).not.toBe(kindGroup("vcs_discard"))
	})
	it("a usable enum value lands, an unusable one registers nothing — never a guessed category", () => {
		// The ordered table of English regexes that invented a category from the model's display label is gone.
		// What replaces it is the enum the schema already enforces, so the property worth pinning is the pair: a
		// value the gate can match becomes a row the matcher can use; a value it cannot match becomes NO row,
		// which costs one prompt instead of a category nobody asked for. `"other"` is the model's own "nothing
		// fits" and names no capability either.
		const sentence = "you can delete the payments:staging image"
		const landed = eventsFromExtraction(
			{ grants: [{ action: "delete image", category: "container_mutation", kind: "entity", scope: "named", targets: ["payments:staging"], quote: sentence }], revocations: [] },
			"m1", 1, sentence,
		)
		expect(landed.map((e) => `${e.category} ${e.value}`)).toEqual(["container_mutation payments:staging"])

		for (const junk of [undefined, "other", "container", "DELETE_OUTSIDE!"]) {
			const rows = eventsFromExtraction(
				{ grants: [{ action: "delete image", ...(junk ? { category: junk } : {}), kind: "entity", scope: "named", targets: ["payments:staging"], quote: sentence }], revocations: [] },
				"m2", 2, sentence,
			)
			expect(rows, String(junk)).toEqual([])
		}
	})
})

describe("fold: dedup + seq precedence", () => {
	it("dedups same key, keeps highest seq", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 5))
		applyEvent(l, grant("write_outside", "/data/", 9, "again /data/ please"))
		applyEvent(l, grant("write_outside", "/data/", 3, "old /data/"))
		expect(l.grants).toHaveLength(1)
		expect(l.grants[0]!.seq).toBe(9)
		expect(l.grants[0]!.quote).toContain("again")
	})
	it("exact-key flip-flop keeps only the newest side", () => {
		const l = createLedger()
		applyEvents(l, [grant("write_outside", "/data/", 2), forbid("/data/", 5), grant("write_outside", "/data/", 8)])
		// forbid category "*" vs grant category write_outside — different keys, so
		// both survive; precedence is decided at match time by seq.
		const v = ledgerCovers(l, "write_outside", [T("/data/x.txt")])
		expect(v.covered).toBe(true)
	})
	it("revocation between grants blocks, re-grant unblocks", () => {
		const probe = () => ledgerCovers(l, "write_outside", [T("/data/x")])
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 2))
		expect(probe().covered).toBe(true)
		applyEvent(l, forbid("/data/", 5))
		expect(probe().covered).toBe(false)
		expect(probe().forbidden).toBe(true)
		applyEvent(l, grant("write_outside", "/data/", 8))
		expect(probe().covered).toBe(true)
	})
	it("'revoke all' keeps blocking targets a later grant did not re-grant", () => {
		const l = createLedger()
		applyEvents(l, [
			grant("write_outside", "/a/", 2),
			grant("write_outside", "/b/", 3),
			forbid("*", 10, "stop, do not write anywhere"),
			grant("write_outside", "/a/", 15),
		])
		expect(ledgerCovers(l, "write_outside", [T("/a/f")]).covered).toBe(true)
		const b = ledgerCovers(l, "write_outside", [T("/b/f")])
		expect(b.covered).toBe(false)
		expect(b.forbidden).toBe(true)
	})
	it("folded state is independent of processing order", () => {
		const events = [
			grant("write_outside", "/data/", 2),
			forbid("/data/", 5),
			grant("write_outside", "/data/", 8),
			grant("db_mutation", "sessions", 4, "you can drop the sessions table"),
			forbid("*", 6, "actually stop everything"),
			grant("package_system", "ripgrep", 9, "just apt-get install ripgrep"),
			forbid("payments", 7),
		]
		const probes: Array<[string, Entity[]]> = [
			["write_outside", [T("/data/x")]],
			["db_mutation", [T("sessions")]],
			["package_system", [T("ripgrep")]],
			["db_mutation", [T("payments")]],
		]
		const orders = [
			events,
			[...events].reverse(),
			[events[3]!, events[6]!, events[0]!, events[5]!, events[2]!, events[1]!, events[4]!],
			[events[4]!, events[2]!, events[0]!, events[1]!, events[6]!, events[5]!, events[3]!],
		]
		const results = orders.map((order) => {
			const l = createLedger()
			applyEvents(l, order)
			return probes.map(([c, e]) => `${ledgerCovers(l, c, e).covered}/${ledgerCovers(l, c, e).forbidden}`).join(" ")
		})
		expect(new Set(results).size).toBe(1)
		// sanity on the shared verdicts: sessions revoked by "stop everything" (seq 6 > 4),
		// ripgrep re-granted after it (9 > 6), payments forbidden
		expect(results[0]).toBe("true/false false/true true/false false/true")
	})
	it("newest-first partial fold never allows a later-revoked grant", () => {
		// grant at 10, revocation at 40 — processed newest-first
		const l = createLedger()
		applyEvent(l, forbid("/data/", 40))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(false)
		applyEvent(l, grant("write_outside", "/data/", 10)) // older grant arrives later
		const v = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
	})
})

describe("matching", () => {
	it("a write grant reaches mkdir at the location, and never chmod", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "write_outside", [T("/x/x/sub")]).covered).toBe(true)
		// Used to be true, through the shared fs-write group. Copy files here says nothing about
		// who else may read what lands there, and chmod is precisely that decision.
		expect(ledgerCovers(l, "perm_change", [T("/x/x/sub/f")]).covered).toBe(false)
		// The permission is still grantable - it just has to be named by a quote that says it.
		const withPerm = createLedger()
		applyEvent(withPerm, grant("perm_change", "/x/x/", 3, "copy the file and chmod what you copy in /x/x/"))
		expect(ledgerCovers(withPerm, "perm_change", [T("/x/x/sub/f")]).covered).toBe(true)
	})
	it("a delete is answered by a delete-category row, whatever the quote says", () => {
		// Was "deletes require a delete verb in the grant quote". The first line still refuses — not because the
		// quote lacks a destructive word, but because a `write_outside` row is a content grant and a delete is a
		// different direction. The second line is unchanged. The third pins what changed: the row's category
		// decides, and no word in its quote is consulted.
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(false)
		applyEvent(l, grant("delete_outside", "/x/x/old", 5, "and delete /x/x/old when done"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(true)
		const noVerb = createLedger()
		applyEvent(noVerb, grant("delete_outside", "/x/x/old", 3, "the /x/x/old file is in the way, deal with it"))
		expect(ledgerCovers(noVerb, "delete_recursive", [T("/x/x/old")]).covered).toBe(true)
	})
	it("METHOD_VERB_REQUIRED: naming the package is not approving the install", () => {
		const l = createLedger()
		applyEvent(l, grant("package_system", "ripgrep", 3, "ripgrep is missing on this box"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(false)
		applyEvent(l, grant("package_system", "ripgrep", 4, "go ahead and install ripgrep"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(true)
	})
	it("near-names never match across the ledger", () => {
		const l = createLedger()
		applyEvent(l, grant("delete_data", "db-backup", 3, "you can delete db-backup"))
		expect(ledgerCovers(l, "delete_data", [T("db-backup-test")]).covered).toBe(false)
		expect(ledgerCovers(l, "delete_data", [T("db-backup")]).covered).toBe(true)
	})
	it("cross-group grants never match; unmappable actions never match", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 3, "write to /data/ freely"))
		expect(ledgerCovers(l, "package_system", [T("/data/")]).covered).toBe(false)
		applyEvent(l, { type: "grant", category: "*frobnicate the widget*", value: "widget", kind: "entity", quote: "frobnicate the widget", messageId: "m9", seq: 9 })
		expect(ledgerCovers(l, "write_outside", [T("widget")]).covered).toBe(false)
	})
	it("all targets must be covered", () => {
		const l = createLedger()
		applyEvent(l, grant("db_mutation", "sessions", 3, "drop the sessions table"))
		expect(ledgerCovers(l, "db_mutation", [T("sessions"), T("users")]).covered).toBe(false)
	})
	it("bare-verb '*' grant covers unlisted targets of the category", () => {
		const l = createLedger()
		applyEvent(l, grant("vcs_remote", "*", 3, "force-push it", "scope"))
		expect(ledgerCovers(l, "vcs_remote", [T("origin/main")]).covered).toBe(true)
		expect(ledgerCovers(l, "package_system", [T("origin/main")]).covered).toBe(false)
	})
})

describe("caps / eviction", () => {
	it("evicts least-recently-matched grants first, never forbids for grants", () => {
		const l = createLedger()
		for (let i = 0; i < MAX_GRANTS + 10; i++) applyEvent(l, grant("write_outside", `/p${i}/`, i))
		expect(l.grants.length).toBe(MAX_GRANTS)
		// the oldest unmatched ones are gone; matching bumps recency
		expect(ledgerCovers(l, "write_outside", [T(`/p${MAX_GRANTS + 9}/x`)]).covered).toBe(true)
		for (let i = 0; i < MAX_FORBIDS + 5; i++) applyEvent(l, forbid(`/q${i}/`, 1000 + i))
		expect(l.forbids.length).toBe(MAX_FORBIDS)
		expect(l.grants.length).toBe(MAX_GRANTS)
	})
})

describe("eventsFromExtraction verification", () => {
	it("a tool-written interrupt notice yields no events, whatever the extractor says", () => {
		const notice = "[Request interrupted by user for tool use]"
		expect(isSyntheticUserTurn(notice)).toBe(true)
		expect(isSyntheticUserTurn("  [Request interrupted by user]\n")).toBe(true)
		expect(isSyntheticUserTurn("stop, do not change anything")).toBe(false)
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "stop", targets: [], all: true, quote: notice }] },
			"m9", 9, notice,
		)
		expect(ev).toEqual([])
	})
	const msg = "please copy the dataset to /mnt/scratch/exp1/ and then you can delete ./old-dumps, but do not touch ~/backups"
	it("keeps verified grants/revocations, drops unverifiable quotes and targets", () => {
		// The first three rows are a recorded model answer for this message, verbatim; the fourth
		// is the same shape with a quote the message does not contain.
		const ev = eventsFromExtraction(
			{
				grants: [
					{ action: "copy files", category: "write_outside", kind: "scope", scope: "named", includesSecrets: false, targets: ["/mnt/scratch/exp1/"], quote: "copy the dataset to /mnt/scratch/exp1/" },
					{ action: "delete files", category: "delete_outside", kind: "scope", scope: "named", includesSecrets: false, targets: ["./old-dumps"], quote: "delete ./old-dumps" },
					{ action: "delete files", category: "delete_outside", kind: "scope", scope: "named", includesSecrets: false, targets: ["/etc/passwd"], quote: "delete ./old-dumps" }, // target not in message
					{ action: "install tools", category: "package_system", kind: "entity", scope: "named", includesSecrets: false, targets: ["ripgrep"], quote: "install ripgrep now" }, // quote not in message
				],
				revocations: [{ action: "delete files", category: "delete_outside", scope: "named", targetClass: "none", targets: ["~/backups"], all: false, quote: "do not touch ~/backups" }],
			},
			"mid1", 7, msg,
		)
		expect(ev.map((e) => `${e.type}:${e.value}`)).toEqual([
			"grant:/mnt/scratch/exp1/",
			// `kind: "scope"` is the model's recorded answer for `./old-dumps` and is now the ONLY source
			// of a folder permission — the "in|under|inside <path>" regex that read the preposition out of
			// the sentence is deleted.
			"grant:./old-dumps/",
			"forbid:~/backups",
			// A named revocation records the path AND its subtree: a folder grant reaches the
			// files inside it, so "do not touch ~/backups" has to as well, or the earlier grant
			// keeps authorising them. Found by eval case L-02.
			"forbid:~/backups/",
		])
		expect(ev[0]!.kind).toBe("scope")
		expect(ev[0]!.category).toBe("write_outside")
		// Every row carries the model's category. The `"*"` this file used to infer for a named
		// revocation — "every category AT THIS PATH", read off whether the sentence contained a mutating
		// verb — is gone together with the regex that read it.
		expect(ev.slice(2).every((e) => e.category === "delete_outside")).toBe(true)
		expect(ev.every((e) => e.messageId === "mid1" && e.seq === 7)).toBe(true)
	})
	it("bare-verb grant only for bare-verb categories with the verb in the quote", () => {
		// The width field decides this branch now, not the verb alone. `named` with no target is a MISSING
		// VALUE and a missing value never becomes a wildcard: the row below is a model's normal answer to
		// "force-push it" and it used to store `vcs_remote *` = push/force-push ANY ref anywhere. `category`
		// is the model's own word for "every object of that kind", so it still does.
		const named = eventsFromExtraction(
			{ grants: [{ action: "force push to remote", category: "vcs_remote", kind: "entity", scope: "named", targets: [], quote: "force-push it" }], revocations: [] },
			"m1", 2, "ok now force-push it",
		)
		expect(named).toEqual([])
		const whole = eventsFromExtraction(
			{ grants: [{ action: "push to any branch", category: "vcs_remote", kind: "entity", scope: "category", targets: [], quote: "you can push to the remote" }], revocations: [] },
			"m1", 2, "go ahead, you can push to the remote",
		)
		expect(whole).toEqual([expect.objectContaining({ type: "grant", category: "vcs_remote", value: "*", kind: "entity" })])
		const none = eventsFromExtraction(
			{ grants: [{ action: "write files", targets: [], quote: "sounds good" }], revocations: [] },
			"m1", 2, "sounds good",
		)
		expect(none).toEqual([])
	})
	describe("a grant that names no object registers nothing unless the model said the whole category", () => {
		// The prompt makes `named` + EMPTY targets the normal answer for an unnamed object ("force-push it",
		// "drop that table"), so this path is the COMMON case, not a corner. Provenance: the `named` rows below
		// with empty targets are a shape the prompt in this tree does not produce. What a model does answer for
		// the same three sentences, recorded verbatim:
		//   "ok now force-push it"     → {vcs_force_protected, named, targets ["it"], quote "force-push it"}
		//   "you can kill any process you want" → {process_massacre, everything, targets []}
		//   "go ahead and delete all the data"  → {delete_data, everything, targets []}
		// The recorded rows are pinned below as the first test. The `category` rows are labelled width-field
		// pins: what is pinned is the rule code owns — a wildcard requires the model to have asked for one —
		// not a claim about what an endpoint answers today.
		const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
		const pushRow = (scope: string) => ({
			grants: [{ action: "force push to remote", category: "vcs_remote", kind: "entity", scope, includesSecrets: false, targets: [], quote: "force-push it" }],
			revocations: [],
		})
		const deleteRow = (scope: string) => ({
			grants: [{ action: "delete data", category: "delete_data", kind: "entity", scope, includesSecrets: false, targets: [], quote: "go ahead and delete it" }],
			revocations: [],
		})
		const killRow = (scope: string) => ({
			grants: [{ action: "kill process", category: "process_control", kind: "entity", scope, includesSecrets: false, targets: [], quote: "yes kill the process" }],
			revocations: [],
		})

		it("vcs_remote: 'named' + no target stores nothing, is counted, and the gate still asks", async () => {
			resetExtractionStats()
			const text = "ok now force-push it"
			const events = eventsFromExtraction(pushRow("named"), "m1", 3, text)
			expect(events).toEqual([])
			// Counted, because "the grant registered" and "the user never said it" must stay separable —
			// this is the counter /classifier-status prints.
			expect(extractionStats.unmapped).toBe(1)
			expect(extractionStats.lastUnmapped).toBe("force push to remote")
			const ledger = createLedgerWith(events)
			expect(ledger.grants).toHaveLength(0)
			// The command the wildcard used to unlock. It is tier `never` here (protected branch `main`), so the
			// honest assertion is the one that matters: the ledger did not authorise it.
			const forced = await runGate("bash", { command: "git push --force origin main" }, { policy: POLICY, ledger, userMessages: [text] })
			expect(forced.outcome).not.toBe("allow-granted")
			expect(forced.grantedBy).not.toBe("ledger")
			expect(forced.outcome).toBe("prompt-never")
			// …and on an ASK-tier ref the same ledger still asks. This is the case the wildcard used to
			// unlock: before this change the row below stored `vcs_remote *` and this command auto-allowed.
			const ask = await runGate("bash", { command: "git push --force-with-lease origin feature/retry-logic" }, { policy: POLICY, ledger, userMessages: [text] })
			expect(ask.outcome).toBe("prompt")
			expect(ask.grantedBy).toBeUndefined()
		})

		it("and the same row answered 'category' is the wildcard that DOES auto-allow — the field is the difference", async () => {
			// The pair the pin above needs: if the wildcard row did not buy the allow, the pin above would
			// pass for the wrong reason. Answered by the grammar-wildcard branch (the `grammar !== undefined
			// && scope === "category"` test just above this one), which runs
			// before the
			// bare-verb branch; `*` is that grammar's spelling of "every ref, no remote named".
			const events = eventsFromExtraction(pushRow("category"), "m1", 3, "ok now force-push it")
			expect(events.map((e) => `${e.type}:${e.category}:${e.value}`)).toEqual(["grant:vcs_remote:*"])
			const r = await runGate("bash", { command: "git push --force-with-lease origin feature/retry-logic" }, {
				policy: POLICY, ledger: createLedgerWith(events), userMessages: ["ok now force-push it"],
			})
			expect(r.outcome).toBe("allow-granted")
			expect(r.grantedBy).toBe("ledger")
		})

		it("the recorded model row for the same sentence costs one prompt, never a wildcard", async () => {
			// A model's own answer for this message, verbatim. Its target is the pronoun: the word IS in the
			// message so it survives, and `parseVcsTarget` happily reads it as a branch named "it", so the row is
			// STORED — as a ref no repository has. That costs one prompt, which is what the empty-targets row
			// above now costs too, instead of authority over every ref in the remote. The difference between the
			// two shapes is worth keeping straight: `named` + [] registers nothing, `named` + a pronoun registers
			// something impotent.
			const text = "ok now force-push it"
			const events = eventsFromExtraction(
				{ grants: [{ action: "force push to remote", category: "vcs_force_protected", kind: "entity", scope: "named", includesSecrets: false, targets: ["it"], quote: "force-push it" }], revocations: [] },
				"m1", 3, text,
			)
			expect(events.map((e) => `${e.type}:${e.category}:${e.value}`)).toEqual(["grant:vcs_force_protected:it"])
			const r = await runGate("bash", { command: "git push --force-with-lease origin feature/retry-logic" }, { policy: POLICY, ledger: createLedgerWith(events), userMessages: [text] })
			expect(r.outcome).toBe("prompt")
			expect(r.grantedBy).toBeUndefined()
		})

		it("non-grammar bare-verb categories: 'named' + no target stores nothing, 'category' gets the bare '*'", () => {
			// `delete_data` / `process_control` have no grammar, so this is the ONLY path that can produce
			// their wildcard, and both halves of the rule need the verb in the quote ("delete", "kill").
			resetExtractionStats()
			expect(eventsFromExtraction(deleteRow("named"), "m2", 4, "go ahead and delete it")).toEqual([])
			expect(eventsFromExtraction(killRow("named"), "m2", 4, "yes kill the process")).toEqual([])
			expect(extractionStats.unmapped).toBe(2)
			expect(eventsFromExtraction(deleteRow("category"), "m2", 4, "go ahead and delete it").map((e) => `${e.type}:${e.category}:${e.value}:${e.kind}`)).toEqual(["grant:delete_data:*:scope"])
			expect(eventsFromExtraction(killRow("category"), "m2", 4, "yes kill the process").map((e) => `${e.type}:${e.category}:${e.value}:${e.kind}`)).toEqual(["grant:process_control:*:scope"])
		})

		it("a bare-verb 'category' row whose quote lacks the verb still registers nothing", () => {
			// The verb test survives the change: naming the category is not the same as approving the method
			// (METHOD_VERB_REQUIRED's rule, restated for the width field).
			const ev = eventsFromExtraction(
				{ grants: [{ action: "the data", category: "delete_data", kind: "entity", scope: "category", includesSecrets: false, targets: [], quote: "the data is old" }], revocations: [] },
				"m3", 5, "the data is old",
			)
			expect(ev).toEqual([])
		})
	})
	it("scope 'everything' arms the read-only posture, whatever the category (the gate enforces it, not ledgerCovers)", () => {
		// Recorded row, verbatim: a model answers a "nothing may run" sentence with scope
		// `everything` and category `other` — the width field, not the category, is what arms the lock.
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "run risky work", category: "other", scope: "everything", targetClass: "none", targets: [], all: true, quote: "stop, don't run anything risky anymore" }] },
			"m1", 50, "stop, don't run anything risky anymore",
		)
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 10))
		applyEvents(l, ev)
		// posture is set; the older grant (seq 10 < 50) does not lift it
		expect(readOnlyActive(l)?.seq).toBe(50)
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/data/x")], 50)).toBe(false)
		expect(l.forbids).toHaveLength(0)
	})
	it("blanket 'don't change anything' sets the read-only posture, not a wildcard forbid", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "make changes", category: "other", scope: "everything", targetClass: "none", targets: [], all: true, quote: "you are not allowed to change anything" }] },
			"m0", 0, "you are not allowed to change anything",
		))
		expect(readOnlyActive(l)?.quote).toContain("change anything")
		expect(l.forbids).toHaveLength(0) // no more */* forbid row
	})
	it("read-only: later per-target grant lifts that target, blanket re-enable clears it", () => {
		const l = createLedger()
		applyEvent(l, { type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "do not change anything", messageId: "m0", seq: 0 })
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(false)
		applyEvent(l, grant("write_outside", "/x/", 5, "you can write to /x/"))
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(true) // seq 5 > 0
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/y/f")], 0)).toBe(false) // different target
		expect(readOnlyLiftedByGrant(l, "write_outside", [], 0)).toBe(false) // targetless can't be lifted
		// Recorded: a "take the stop back" sentence comes back as a GRANT with scope `everything` and
		// category `other`, and that field — not a phrase list run over the quote — is what lifts it.
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "make changes", category: "other", kind: "entity", scope: "everything", includesSecrets: false, targets: [], quote: "ok you can make changes now" }], revocations: [] },
			"m9", 9, "ok you can make changes now",
		))
		expect(readOnlyActive(l)).toBeNull()
	})
	it("read-only posture is order-independent and re-armable (on/off/on by seq)", () => {
		const evs: ExtractedEvent[] = [
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "read only please", messageId: "a", seq: 2 },
			{ type: "readonly-off", category: "*", value: "*", kind: "scope", quote: "changes are fine", messageId: "b", seq: 5 },
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "actually stop changing things", messageId: "c", seq: 8 },
		]
		const results = [evs, [...evs].reverse(), [evs[1]!, evs[2]!, evs[0]!]].map((order) => {
			const l = createLedger(); applyEvents(l, order); return readOnlyActive(l)?.seq ?? null
		})
		expect(new Set(results.map(String)).size).toBe(1)
		expect(results[0]).toBe(8) // newest on (seq 8) wins
	})
	it("'any images' becomes a category-wide forbid from the model's scope field, not from a kind-word target (G9 regression)", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "delete image", category: "container_mutation", kind: "entity", scope: "named", includesSecrets: false, targets: ["payments:staging"], quote: "you can delete the payments:staging image" }], revocations: [] },
			"m0", 0, "you can delete the payments:staging image",
		))
		expect(ledgerCovers(l, "container_mutation", [T("payments:staging")]).covered).toBe(true)
		// Recorded: the model no longer hands the kind-word back as a target at all — it answers
		// `scope: "category"` with an empty target list, which is the field this file now reads.
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "delete images", category: "container_mutation", scope: "category", targetClass: "none", targets: [], all: true, quote: "do not delete any images" }] },
			"m1", 1, "actually never mind, do not delete any images",
		))
		const v = ledgerCovers(l, "container_mutation", [T("payments:staging")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
		// Scoped to the kind group: the ban never BINDS the unrelated fs write. What changed at this line is
		// what "untouched" means — the seq-1 forbid is the newer statement, so it takes the ledger auto-allow
		// away and the gate's model call decides (covered:false). What still discriminates is `forbidden`: a
		// blanket row (category "*" or value-`*` in a compatible group) at seq 1 would answer forbidden:true,
		// and that over-scope is what this test guards.
		applyEvent(l, grant("write_outside", "/data/", 0))
		const unrelated = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(unrelated.forbidden).toBe(false)
		expect(unrelated.covered).toBe(false)
	})
})

describe("serialize / restore", () => {
	it("round-trips and filters entries from rewound-away messages", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/a/", 2))
		applyEvent(l, grant("write_outside", "/b/", 3))
		applyEvent(l, forbid("/c/", 4))
		l.seen.add("m2"); l.seen.add("m3"); l.seen.add("m4")
		const snap = JSON.parse(JSON.stringify(serializeLedger(l)))
		const full = deserializeLedger(snap)
		expect(full.grants).toHaveLength(2)
		expect(full.forbids).toHaveLength(1)
		expect(full.seen.size).toBe(3)
		const filtered = deserializeLedger(snap, new Set(["m2", "m4"]))
		expect(filtered.grants.map((g) => g.value)).toEqual(["/a/"])
		expect(filtered.forbids).toHaveLength(1)
		expect([...filtered.seen].sort()).toEqual(["m2", "m4"])
	})
	it("unknown version → empty ledger (backfill rebuilds)", () => {
		expect(deserializeLedger({ v: 2, grants: [] }).grants).toEqual([])
		expect(deserializeLedger("garbage").grants).toEqual([])
		expect(deserializeLedger(undefined).grants).toEqual([])
	})
})

// ---------------------------------------------------------------- revocation vs derivation
// A revocation the user made HERE has to
// survive everything this session can do afterwards — a drain re-reading the same
// message, a per-message extraction call, an import of a session that never saw the
// slash command, and a restart. The two tests below are the two halves of that: the
// guard on the door every derivation walks through, and the memory (`seen`) that keeps
// the drain from trying in the first place.

const journalDir = mkdtempSync(join(tmpdir(), "pm-ledger-revoke-"))
afterAll(() => rmSync(journalDir, { recursive: true, force: true }))

/** Two clock readings, fixed. Every expectation below is about their ORDER, never their value. */
const EARLIER = 1_000
const LATER = 5_000

function journalPath(name: string): string {
	return join(journalDir, name)
}

function journalValues(path: string): string[] {
	return (JSON.parse(readFileSync(path, "utf-8")).ledger.grants as { value: string }[]).map((g) => g.value)
}

function journalRevoked(path: string): Array<{ value: string; at: number }> {
	return JSON.parse(readFileSync(path, "utf-8")).ledger.revoked ?? []
}

function writeJournal(path: string, ledger: unknown): void {
	const r = mergeIntoGrantsFile(path, ledger, [], { sourceCwd: "/proj" })
	if (!r.ok) throw new Error(`journal write failed: ${r.error}`)
}

function readJournalLedger(path: string): unknown {
	const r = readGrantsFile(path)
	if (!r.ok) throw new Error(`journal read failed: ${r.error}`)
	return r.file.ledger
}

describe("a revocation is a wall for every derivation path (D4.1)", () => {
	it("keeps a revoked ledger grant absent through re-extraction and a re-import, and keeps its tombstone in the journal", () => {
		const ledger = createLedger()
		applyEvent(ledger, grant("write_project", "/data/x", 3))
		applyEvent(ledger, grant("write_project", "/data/keep", 4))
		expect(ledgerCovers(ledger, "write_project", [T("/data/x")]).covered).toBe(true)

		// A session that never saw the revoke — an export taken before it, or a concurrent
		// branch. This is what makes the re-import below a test rather than a no-op: the
		// file really does still offer `/data/x`.
		const path = journalPath("revoke-then-import.json")
		writeJournal(path, serializeLedger(ledger))
		expect(journalValues(path)).toEqual(["/data/x", "/data/keep"])

		// /grants revoke /data/x — one row removed, one tombstone written. The tombstone is
		// stamped after the row it takes away, because that is what a revocation IS: the user
		// withdrew it later. Every veto below is that comparison, so the clocks have to be
		// real ones and not two made-up numbers on the other side of the row's own `at`.
		const rowAt = ledger.grants.find((g) => g.value === "/data/x")!.at!
		const taken = revokeLedgerGrants(ledger, (g) => g.value === "/data/x", {
			at: rowAt + 1_000,
			quote: "/grants revoke /data/x",
		})
		expect(taken.map((r) => r.value)).toEqual(["/data/x"])
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])

		// Re-extraction. Same event from the same message (the drain re-read it), the same
		// key under a newer message with a higher seq, and the quote reworded: a re-derivation
		// is not one shape, and none of them may cross the tombstone.
		applyEvents(ledger, [
			grant("write_project", "/data/x", 3),
			grant("write_project", "/data/x", 11, "go on, /data/x"),
		])
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])
		expect(ledgerCovers(ledger, "write_project", [T("/data/x")]).covered).toBe(false)

		// Re-import the session the file came from.
		const summary = importLedger(ledger, readJournalLedger(path))
		expect(summary.revokedOnArrival).toBe(1)
		expect(summary.grantsAdded).toBe(0)
		expect(ledger.grants.map((g) => g.value)).toEqual(["/data/keep"])

		// The tombstone is still there — in the ledger and in the journal, after the ledger
		// has been written back over the file that still carried the row.
		expect(ledger.revoked?.map((r) => r.value)).toEqual(["/data/x"])
		writeJournal(path, serializeLedger(ledger))
		expect(journalRevoked(path).map((r) => r.value)).toContain("/data/x")
		expect(journalValues(path)).not.toContain("/data/x")
	})

	it("refuses only the revoked key: other targets, other categories and forbids keep flowing", () => {
		const ledger = createLedger()
		applyEvent(ledger, grant("write_project", "/data/x", 2))
		revokeLedgerGrants(ledger, (g) => g.value === "/data/x", { at: LATER })

		applyEvents(ledger, [
			grant("write_project", "/data/y", 6), // another target
			grant("write_outside", "/data/x", 7), // another category, same target
			forbid("/data/z", 8), // a deny is never refused
		])
		expect(ledger.grants.map((g) => `${g.category}:${g.value}`).sort()).toEqual([
			"write_outside:/data/x",
			"write_project:/data/y",
		])
		expect(ledger.forbids.map((f) => f.value)).toEqual(["/data/z"])
	})

	it("keeps an imported revocation as background: what the user says HERE still earns the key", () => {
		// The other side of the same rule. If a tombstone read off disk could veto a local
		// derivation, one stale file in the auto-import path would block this project's user
		// from ever re-granting that value, with /grants clear as the only way out.
		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 1))
		source.grants[0]!.at = EARLIER
		revokeLedgerGrants(source, (g) => g.value === "/data/x", { at: LATER })

		const target = createLedger()
		const summary = importLedger(target, serializeLedger(source))
		expect(summary.revocationsAdded).toBe(1)
		expect(target.revoked?.[0]?.origin).toBe("imported")

		applyEvent(target, grant("write_project", "/data/x", 5))
		expect(target.grants.map((g) => g.value)).toEqual(["/data/x"])
	})

	it("will not let an import demote a revocation made here, whatever clock the file claims", () => {
		// If the fold let the file's later timestamp win, the surviving row would arrive
		// tagged `imported`, the local guard would stop firing for that key, and the very
		// next re-extraction would walk the revoked grant back in. Ordering is the guard.
		const target = createLedger()
		applyEvent(target, grant("write_project", "/data/x", 1))
		target.grants[0]!.at = EARLIER
		revokeLedgerGrants(target, (g) => g.value === "/data/x", { at: EARLIER + 10 })

		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 7))
		source.grants[0]!.at = LATER + 1_000 // re-earned over there, after their revoke
		source.revoked = [{ category: "write_project", value: "/data/x", kind: "entity", at: LATER + 1_000 }]

		importLedger(target, serializeLedger(source))
		expect(target.revoked?.[0]?.origin).toBeUndefined() // ours is still ours
		expect(target.grants).toEqual([]) // their row was refused at the door
		applyEvent(target, grant("write_project", "/data/x", 12))
		expect(target.grants).toEqual([]) // and the guard still fires
	})
})

describe("taking a forbid back (W49b: /grants revoke on a deny row)", () => {
	/** One sentence, derived the way the drain derives it. Reused because the property under test
	 *  is "the same message cannot put it back", which only exists at this entry point. */
	const searchQuote = "you will not ever search in /home/u/dev"
	const searchPayload = { grants: [], revocations: [{ action: "search files", category: "read_only", scope: "named", targetClass: "none", targets: ["/home/u/dev"], all: false, quote: searchQuote }] }
	const drainSearch = (l: Ledger) => applyEvents(l, eventsFromExtraction(searchPayload as never, "m1", 1, searchQuote))

	it("removes the rows it matched and hands them back with the sentence behind them", () => {
		const l = createLedger()
		drainSearch(l)
		expect(l.forbids.length).toBeGreaterThan(0)
		const taken = revokeLedgerForbids(l, (f) => f.value === "/home/u/dev/", { quote: "/grants revoke /home/u/dev" })
		expect(taken.map((f) => f.value)).toEqual(["/home/u/dev/"])
		// The row carries the user's own words; the caller prints them, so it needs the row and not
		// just a count. A revoke that reports only a number cannot say WHICH sentence stopped.
		expect(taken[0]!.quote).toBe(searchQuote)
		expect(l.forbids.some((f) => f.value === "/home/u/dev/")).toBe(false)
		expect(l.revokedForbids?.map((r) => r.value)).toEqual(["/home/u/dev/"])
	})

	it("stays gone when the very same message is drained again", () => {
		// The acceptance property, and the whole reason this function exists: before this fix the row
		// was spliced out of ledger.forbids by nothing at all, and even a hand-deleted one came back
		// on the next drain because the tombstone gate looked only at grant keys.
		const l = createLedger()
		drainSearch(l)
		expect(l.forbids.length).toBeGreaterThan(0)
		revokeLedgerForbids(l, () => true, { quote: "/grants revoke /home/u/dev" })
		expect(l.forbids).toEqual([])
		const blockedBefore = extractionStats.forbidRevocationsBlocked
		drainSearch(l)
		drainSearch(l)
		expect(l.forbids).toEqual([])
		// Every re-derivation was stopped at the door. How MANY rows one sentence derives is the
		// derivation tests' business (see the derivation table below); this one only claims none of them got in.
		expect(extractionStats.forbidRevocationsBlocked - blockedBefore).toBeGreaterThanOrEqual(1)
	})

	it("revokes exactly the value pointed at, never the row beside it", () => {
		// Same narrow key the grant side uses. Revoking one file must not fall over the folder grant
		// next to it, and here the mirror image: cancelling one ban must not cancel another.
		const l = createLedger()
		applyEvents(l, [forbid("/data/x", 1), forbid("/data/keep", 2)])
		const taken = revokeLedgerForbids(l, (f) => f.value === "/data/x", { at: LATER })
		expect(taken.map((f) => f.value)).toEqual(["/data/x"])
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/keep"])
		expect(l.revokedForbids?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("records nothing when it matched nothing: a failed revoke must not become a standing ban", () => {
		const l = createLedger()
		applyEvent(l, forbid("/data/keep", 1))
		expect(revokeLedgerForbids(l, (f) => f.value === "/nope", { at: LATER })).toEqual([])
		expect(l.revokedForbids).toEqual([])
		applyEvent(l, forbid("/data/keep", 3)) // nothing is walled off, so the row still lands
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/keep"])
	})

	it("never reaches across to the allow side: a grant of the same key still lands", () => {
		// The reason the tombstones live in two lists. rowIdentity has no type field, so a shared
		// list would make this revoke delete a grant that happened to carry the same
		// {category,value,kind} — cancelling a DENY would silently remove an ALLOW.
		const l = createLedger()
		applyEvent(l, forbid("/data/x", 1, "do not touch /data/x", "write_outside"))
		revokeLedgerForbids(l, () => true, { at: LATER })
		expect(l.revoked?.length ?? 0).toBe(0)
		applyEvent(l, grant("write_outside", "/data/x", 5, "you can write /data/x"))
		expect(l.grants.map((g) => g.value)).toEqual(["/data/x"])
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
		const blockedBefore = extractionStats.revocationBlocked
		// Same key, re-derived: the grant side of the wall is the list `revoked`, and this key is in
		// neither wall, so it lands and the grant counter does not move.
		applyEvent(l, grant("write_outside", "/data/x", 7, "write /data/x again"))
		expect(l.grants.length).toBe(1)
		expect(l.grants[0]!.seq).toBe(7)
		expect(extractionStats.revocationBlocked - blockedBefore).toBe(0)
	})

	it("keeps grant revocation behaving exactly as it did: a revoked grant is still walled, a revoked grant does not wall a forbid", () => {
		const l = createLedger()
		const blockedBefore = extractionStats.revocationBlocked
		const forbidBlockedBefore = extractionStats.forbidRevocationsBlocked
		applyEvent(l, grant("write_outside", "/data/x", 2))
		revokeLedgerGrants(l, (g) => g.value === "/data/x", { at: LATER })
		applyEvent(l, grant("write_outside", "/data/x", 9))
		expect(l.grants).toEqual([])
		expect(extractionStats.revocationBlocked - blockedBefore).toBe(1)
		// The other direction of the same wall being two walls.
		applyEvent(l, forbid("/data/x", 9, "do not touch /data/x", "write_outside"))
		expect(l.forbids.map((f) => f.value)).toEqual(["/data/x"])
		expect(l.revokedForbids).toEqual([])
		expect(extractionStats.forbidRevocationsBlocked - forbidBlockedBefore).toBe(0)
	})

	it("survives the snapshot round trip, so /grants clear is not the only way out after a reload", () => {
		const l = createLedger()
		drainSearch(l)
		revokeLedgerForbids(l, () => true, { quote: "/grants revoke /home/u/dev" })
		const blob = JSON.parse(JSON.stringify(serializeLedger(l)))
		expect(blob.revokedForbids?.length).toBeGreaterThan(0)
		const back = deserializeLedger(blob)
		expect(back.forbids).toEqual([])
		expect(back.revokedForbids?.length).toBeGreaterThan(0)
		expect(back.revokedForbids?.[0]?.origin).toBeUndefined() // said HERE, not read off a file
		drainSearch(back)
		expect(back.forbids).toEqual([])
	})

	it("applies a file's own forbid revocations on read, so a stale blob cannot resurrect the ban", () => {
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		revokeLedgerForbids(source, () => true, { at: LATER })
		// A blob written by a writer that forgot to splice: the row AND its tombstone, same key.
		const blob = serializeLedger(source)
		;(blob as { forbids: unknown[] }).forbids = [{ category: "*", value: "/data/x", kind: "entity", quote: "do not touch /data/x", messageId: "m1", seq: 1, at: EARLIER }]
		const restored = deserializeLedger(blob)
		expect(restored.forbids).toEqual([])
		expect(restored.revokedForbids?.map((r) => r.value)).toEqual(["/data/x"])
	})

	it("refuses at the door an imported forbid this session already revoked, and says so", () => {
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		const offered = serializeLedger(source)

		const target = createLedger()
		applyEvent(target, forbid("/data/x", 1))
		revokeLedgerForbids(target, () => true, { at: LATER })
		const summary = importLedger(target, offered)
		expect(summary.forbidsAdded).toBe(0)
		expect(summary.forbidsRefusedHere).toBe(1)
		expect(target.forbids).toEqual([])
	})

	it("keeps a file's revocation as background: the ban it cancelled is not a ban THIS session may not re-derive", () => {
		// The imported-revocation asymmetry, mirrored for forbids. A tombstone that arrived from a
		// journal filters the rows that travel with it, but it must not veto a sentence the user says
		// here, or one stale file would need /grants clear to overcome.
		const source = createLedger()
		applyEvent(source, forbid("/data/x", 1))
		source.forbids[0]!.at = EARLIER
		revokeLedgerForbids(source, () => true, { at: LATER })

		const target = createLedger()
		importLedger(target, serializeLedger(source))
		expect(target.revokedForbids).toEqual([]) // not folded in: background authority cannot veto here
		applyEvent(target, forbid("/data/x", 4))
		expect(target.forbids.map((f) => f.value)).toEqual(["/data/x"])
	})

	it("pins 2514c8d and eval case L-02: a revocation stays at least as wide as the grant it revokes", () => {
		// FORBID_FAMILIES folds fs-write / fs-delete / fs-perm into one fs-mutation family, so a
		// revocation recorded against ONE mutation category still dominates every other one. L-02
		// produced a TRUE false allow when a named revocation stored only its own narrow category
		// while the grant it took back was a folder scope, and 2514c8d wrote the rule that a
		// revocation must be at least as wide as the grant it revokes. The fold stays for this
		// reason even though the same fold is what made one permission-files sentence over-block;
		// the fix for an over-general rule is not to delete it. Narrow the fold and this test goes
		// red before the false allow comes back.
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 3, "you can write anything under /data/", "scope"))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
		// The revocation lands on the destruction side of the family; the grant it takes back is on
		// the content side. That crossing is the whole point of the fold.
		applyEvent(l, { type: "forbid", category: "delete_recursive", value: "/data/", kind: "scope", quote: "stop, that is enough with /data/", messageId: "m9", seq: 9 })
		const v = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
		expect(v.reason).toContain("stop, that is enough")
	})
})

describe("seen travels with the ledger (D4.2)", () => {
	it("restores `seen` across an import so the drain skips old messages, and still lands a genuinely new grant", () => {
		const source = createLedger()
		applyEvent(source, grant("write_project", "/data/x", 3))
		// `seen` is written by the drain layer (gate-bridge.syncLedger), not by applyEvent.
		source.seen.add("m3")
		source.seen.add("m4") // extracted, said nothing
		const blob = serializeLedger(source)

		const target = createLedger()
		const summary = importLedger(target, blob)
		expect(summary.grantsAdded).toBe(1)
		expect(summary.seenImported).toBe(2)
		expect([...target.seen].sort()).toEqual(["m3", "m4"])

		// Direction 1 — no re-derivation. This is the exact filter syncLedger() runs
		// (`refs.filter(r => !ledger.seen.has(r.id))`) over the ids of the branch.
		const refs = ["m3", "m4", "m9"]
		expect(refs.filter((id) => !target.seen.has(id))).toEqual(["m9"])

		// Direction 2 — the message the file had not read still earns its grant.
		applyEvent(target, grant("write_project", "/data/new", 9))
		expect(target.grants.map((g) => g.value)).toEqual(["/data/x", "/data/new"])
		expect(ledgerCovers(target, "write_project", [T("/data/new")]).covered).toBe(true)
		expect(ledgerCovers(target, "write_project", [T("/data/x")]).covered).toBe(true)
	})

	it("is idempotent and union, not a replacement: a local `seen` survives an import", () => {
		const target = createLedger()
		applyEvent(target, grant("write_project", "/local", 1))
		target.seen.add("m1")
		const source = createLedger()
		applyEvent(source, grant("write_project", "/from/file", 2))
		source.seen.add("m2")

		expect(importLedger(target, serializeLedger(source)).seenImported).toBe(1)
		expect(importLedger(target, serializeLedger(source)).seenImported).toBe(0)
		expect([...target.seen].sort()).toEqual(["m1", "m2"])
	})
})

/** Derivation is the only place where a sentence becomes authority, so it is tested through
 *  `eventsFromExtraction` — the entry point the drain calls — and not through the helpers below it.
 *  A unit test on a category helper alone could not tell a wrong category from a wrong target,
 *  and the two defects this block exists for are both target defects wearing category clothes.
 *
 *  Every `rev` below is a model's recorded revocation row for the sentence next to it (see the provenance
 *  header at the top of this file). The block used to hand the code an `action` label and no category, which
 *  was the input shape of the word list it deleted. */
describe("derivation: the width and the category are the model's fields, and a named thing is not a category", () => {
	const derive = (sentence: string, rev: { action: string; category?: string; scope?: string; targetClass?: string; targets?: string[]; all?: boolean }) =>
		eventsFromExtraction({ grants: [], revocations: [{ ...rev, targets: rev.targets ?? [], quote: sentence }] } as never, "m1", 1, sentence)

	// One path space for the whole block: the sentences talk about real paths under this home, and
	// the matchers need the same root layer 0 would hand them.
	const HOME = "/home/u"
	const PROJECT = "/home/u/dev/pm"

	const table = [
		{
			sentence: "I do not want to use ANY permission files",
			rev: { action: "use permission files", category: "other", scope: "category", targetClass: "rule_files", targets: [], all: true },
			// The bug: the noun `permission` bought the privilege category, the no-target fallback
			// bought value "*", and the fs-mutation family fold turned that into a ban on every write
			// and recursive delete in the workspace; the matchers below are the reproduction.
			mustNot: (r: { category: string; value: string }[]) =>
				r.some((e) => e.category === "perm_change" && e.value === "*") || r.some((e) => e.category === "*" && e.value === "*"),
			// It derives RULE-FILE-SCOPED rows, not a posture row: the sentence names files, and a
			// class the user's own words named is a target. Two rows because the class has two homes —
			// the global rule file and the project's rule directory — and each appears exactly once.
			must: (r: { type: string; value: string; quote: string }[]) =>
				r.length === 2 &&
				r.every((e) => e.type === "forbid" && e.value !== "*" && e.quote === "I do not want to use ANY permission files") &&
				r.some((e) => e.value.endsWith("adaptive-acl.json")) &&
				r.some((e) => e.value.includes(".pi/projects/")),
		},
		{
			sentence: "you will not ever search in /home/u/dev",
			rev: { action: "search files", category: "read_only", scope: "named", targetClass: "none", targets: ["/home/u/dev"], all: false },
			// category "*" here means the prefix contains the project, so a sentence about reading
			// outside the repo blocked writing a file inside it. Two rows for one sentence on top.
			mustNot: (r: { category: string }[]) => r.length > 1 || r.some((e) => e.category === "*"),
			must: (r: { category: string; value: string; kind: string }[]) =>
				r.length === 1 && r[0]!.category === "read_only" && r[0]!.kind === "scope" && r[0]!.value === "/home/u/dev/",
		},
		{
			sentence: "no writes anywhere, ever",
			rev: { action: "write files", category: "write_outside", scope: "category", targetClass: "none", targets: [], all: true },
			// The fix must not neuter a real posture: a sentence that names no target keeps its
			// category-wide scope, exactly as it had it.
			mustNot: () => false,
			must: (r: { category: string; value: string }[]) =>
				r.length === 1 && r[0]!.value === "*" && (r[0]!.category === "write_outside" || r[0]!.category === "write_project"),
		},
		{
			sentence: "chmod is not allowed on any file",
			rev: { action: "change permissions", category: "perm_change", scope: "category", targetClass: "none", targets: [], all: true },
			// The keyword still works where it belongs: an ACL verb is an ACL sentence.
			mustNot: () => false,
			must: (r: { category: string; value: string }[]) => r.length === 1 && r[0]!.category === "perm_change" && r[0]!.value === "*",
		},
	]

	it.each(table)("$sentence", ({ sentence, rev, mustNot, must }) => {
		const rows = derive(sentence, rev)
		expect(mustNot(rows)).toBe(false)
		expect(must(rows)).toBe(true)
	})

	it("keeps the ACL verb requirement honest in both directions", () => {
		// What replaced the word list is the enum, so "honest in both directions" now means: a NOUN in the
		// label selects nothing even when the model could not name a category, and an ACL category appears
		// only because the model put it in `category`. Both halves are needed — the first is the bug that
		// cost a user every write in their workspace, the second is the one the enum must still reach.
		const nounOnly = derive("I do not want to use ANY permission files", {
			action: "use permission files", category: "other", scope: "named", targetClass: "rule_files",
		})
		expect(nounOnly.length).toBeGreaterThan(0)
		expect(nounOnly.every((e) => e.category !== "perm_change" && e.category !== "*")).toBe(true)

		const aclVerb = derive("chmod is not allowed on any file", {
			action: "change permissions", category: "perm_change", scope: "category", targetClass: "none",
		})
		expect(aclVerb.map((e) => `${e.category}:${e.value}`)).toEqual(["perm_change:*"])

		// …and a plain read sentence is still a read sentence, whatever the label says.
		const readRow = derive("do not read anything in /etc", {
			action: "read files", category: "read_only", scope: "named", targetClass: "none", targets: ["/etc"],
		})
		expect(readRow.map((e) => `${e.category}:${e.value}`)).toEqual(["read_only:/etc/"])
	})

	it("derives a target for a class sentence: no value '*' row comes from a sentence that named a thing", () => {
		const rows = derive("stop writing permissions.json", {
			action: "write permissions.json", category: "write_project", scope: "named", targetClass: "none", targets: ["permissions.json"],
		})
		expect(rows.length).toBeGreaterThan(0)
		expect(rows.some((e) => e.value === "*")).toBe(false)
		expect(rows.some((e) => e.category === "perm_change")).toBe(false)
	})

	it("a rule-file class with an unusable category keeps the paths instead of widening to '*'", () => {
		// Recorded, a model answers this sentence `{category: "other", scope: "category",
		// targetClass: "rule_files"}`. `other` names no capability, so the row is defused — but the two
		// paths the CLASS names are narrower than `"*"`, so an unusable category must not throw them away.
		// Defused means it can never answer `forbidden`: it costs a model call, not a refusal.
		const rows = derive("I do not want to use ANY permission files", {
			action: "use permission files", category: "other", scope: "category", targetClass: "rule_files",
		})
		expect(rows.every((e) => e.value !== "*")).toBe(true)
		expect(rows.every((e) => e.category === "*unknown*")).toBe(true)
		expect(rows.some((e) => e.value.endsWith("adaptive-acl.json"))).toBe(true)
		expect(ledgerCovers(createLedgerWith(rows), "write_project", [T("/home/u/dev/pm/x.ts")], HOME, PROJECT).forbidden).toBe(false)
	})

	it("a blanket search complaint is the model's width call, and code never turns it into a lock", () => {
		// The counterweight. The code used to decide BY REGEX that a blanket complaint about scanning a home
		// directory was not a category-wide read ban; recorded, the model itself answers `scope: "category"`,
		// and the model's answer stands — a disagreement may be counted, never applied. What code still owns is
		// the KIND of row: a forbid (which costs prompts) and never the session posture, which is exactly what
		// the deleted `isReadOnlyPosture` armed on this very sentence.
		const rows = derive("you will not search half a tb of files in my home to find clues", {
			action: "search files", category: "read_only", scope: "category", targetClass: "none",
		})
		expect(rows.every((e) => e.type === "forbid")).toBe(true)
		expect(rows.map((e) => `${e.category}:${e.value}`)).toEqual(["read_only:*"])
		const l = createLedgerWith(rows)
		expect(ledgerCovers(l, "read_only", [T("/home/u/x.md")], HOME).forbidden).toBe(true)
		expect(ledgerCovers(l, "write_outside", [T("/home/u/x.md")], HOME).forbidden).toBe(false)
	})

	it("a named revocation carries the model's category — never an inferred '*'", () => {
		// `"*"` used to mean "every category AT THIS PATH", inferred here from whether the sentence
		// contained a mutating verb. The inference and its regex are deleted, so the row is exactly as
		// wide as the model's own answer; what that answer does not reach goes to the gate's model call
		// instead of being guessed from prose.
		const rows = derive("do not touch ~/backups", {
			action: "delete files", category: "delete_outside", scope: "named", targetClass: "none", targets: ["~/backups"],
		})
		expect(rows.every((e) => e.category === "delete_outside")).toBe(true)
		expect(rows.every((e) => e.category !== "*")).toBe(true)
		expect(rows.map((e) => e.value)).toEqual(["~/backups", "~/backups/"])
	})

	it("keeps a read ban from outranking a write inside the prefix it names", () => {
		// The user-visible defect, pinned at the MATCHER rather than at the row shape: a folder grant
		// for the project, plus the derived read-only forbid whose prefix contains that project.
		// Before the fix the first pair of assertions came back `forbidden`, quoting the search sentence
		// as the reason a file inside the repo could not be written.
		const sentence = "you will not ever search in /home/u/dev"
		const l = createLedger()
		applyEvent(l, grant("write_project", "/home/u/dev/pm/", 0, "you can write under /home/u/dev/pm/", "scope"))
		applyEvent(l, grant("read_only", "/home/u/dev/pm/", 0, "you can read under /home/u/dev/pm/", "scope"))
		applyEvents(l, derive(sentence, { action: "search files", category: "read_only", scope: "named", targetClass: "none", targets: ["/home/u/dev"] }))

		const inside = [T("/home/u/dev/pm/corpus/STATE.md")]
		const write = ledgerCovers(l, "write_project", inside)
		expect(write.forbidden).toBe(false)
		// The read ban is the NEWER row here (grants seq 0, derived forbid seq 1), so it no longer
		// stays invisible to the write — it defers the seq-0 grant instead of binding it, which is one
		// extra model call and never a refusal. The assertion this test exists for is the one above:
		// a read-shaped row must not answer `forbidden` for a write (a `"*"` category would).
		expect(write.covered).toBe(false)
		expect(write.reason).toContain("deferred: newer revocation seq 1")

		// …and the read the sentence DID forbid is still blocked at the very same path. The ban is the
		// NEWER statement here (the user permitted the folder first, then refused the search), which is
		// the sequence the complaint was about; a ban older than a grant is lifted by it, by design.
		const read = ledgerCovers(l, "read_only", inside)
		expect(read.covered).toBe(false)
		expect(read.forbidden).toBe(true)
		expect(read.reason).toContain("search")
	})

	it("derives one row per named location for a read sentence, not the entity-plus-subtree pair", () => {
		const rows = derive("do not read anything in /etc", {
			action: "read files", category: "read_only", scope: "named", targetClass: "none", targets: ["/etc"],
		})
		expect(rows).toHaveLength(1)
		expect(rows[0]).toEqual(expect.objectContaining({ type: "forbid", category: "read_only", value: "/etc/", kind: "scope" }))

		// The shape comes from the name: an extension means a file, so the row names the file rather
		// than a `<file>/` prefix that could only ever match itself. Recorded, the model files both of
		// these under `read_secret`, not `read_only` — the harm of a credentials file is in its bytes.
		const file = derive("do not read ~/.kube/config.json", {
			action: "read config file", category: "read_secret", scope: "named", targetClass: "none", targets: ["~/.kube/config.json"],
		})
		expect(file).toHaveLength(1)
		expect(file[0]).toEqual(expect.objectContaining({ category: "read_secret", value: "~/.kube/config.json", kind: "entity" }))

		// What the heuristic cannot know: `credentials` has no extension, so it is spelled as a place.
		// Pinned because it is a CHOICE, not an accident — a prefix row still covers the file itself
		// (`valueCovers` reads `t + "/"` as containing `t`), so the ban is no weaker, only its spelling
		// in `/grants` is. A future "fix" that makes this an entity row must say what it costs.
		const noExtension = derive("do not read ~/.aws/credentials", {
			action: "read credentials", category: "read_secret", scope: "named", targetClass: "none", targets: ["~/.aws/credentials"],
		})
		expect(noExtension).toHaveLength(1)
		expect(noExtension[0]).toEqual(expect.objectContaining({ value: "~/.aws/credentials/", kind: "scope" }))
		const l = createLedger()
		applyEvents(l, noExtension)
		expect(ledgerCovers(l, "read_secret", [T("/home/u/.aws/credentials")], "/home/u").forbidden).toBe(true)
	})

	it("leaves a mutation sentence's pair exactly as eval case L-02 pinned it, under the model's category", () => {
		const rows = derive("do not delete anything under ~/scratch-data", {
			action: "delete files", category: "delete_outside", scope: "named", targetClass: "none", targets: ["~/scratch-data"],
		})
		expect(rows.map((e) => `${e.category}:${e.value}:${e.kind}`)).toEqual([
			"delete_outside:~/scratch-data:entity",
			"delete_outside:~/scratch-data/:scope",
		])
	})

	it("lets the allow-tier scan tell a read ban from a mutation ban, and keeps the old default", () => {
		// An in-project write is ALLOW-tier, so it never reaches ledgerCovers' forbid comparison at
		// all — the named-forbid scan is what decides, which is why the row shape alone was never the
		// whole fix. `pendingCategory` is optional: absent, the scan is exactly as blind as it has ever
		// been, and a caller that has not been updated cannot silently loosen anything. That is pinned
		// here rather than assumed, because a half-wired fix looks finished.
		const l = createLedger()
		applyEvents(l, derive("you will not search anything under /home/u/dev", { action: "search files", category: "read_only", scope: "named", targetClass: "none", targets: ["/home/u/dev"] }))
		const inside = [T("/home/u/dev/pm/corpus/STATE.md")]
		expect(namedForbidCovers(l, inside, HOME, PROJECT)).not.toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "write_project")).toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only")).not.toBeNull()
		// A compound that mutates anything keeps every ban: fail-closed is the tie-break, not the
		// exception. `read_secret` is a read, so a read_secret ban binds a read_secret action too.
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only+write_project")).not.toBeNull()
		expect(namedForbidCovers(l, inside, HOME, PROJECT, "read_only+read_secret")).not.toBeNull()
	})

	it("narrows only read-shaped rows: 'do not touch X' still downgrades an allowed write", () => {
		const l = createLedger()
		applyEvents(l, derive("do not touch ~/backups", {
			action: "delete files", category: "delete_outside", scope: "named", targetClass: "none", targets: ["~/backups"],
		}))
		expect(namedForbidCovers(l, [T("/home/u/backups/ledger.ts")], HOME, PROJECT, "write_project")).not.toBeNull()
		expect(namedForbidCovers(l, [T("/home/u/backups/ledger.ts")], HOME, PROJECT, "delete_recursive")).not.toBeNull()
	})
})


describe("reach is the row's own category — the two bridges are gone", () => {
	/*
	 * Recorded extraction rows, not hand-written: each row below is a category a model actually filed for the
	 * message quoted beside it. The point of using them is that these are the categories the model actually
	 * writes, so "what does the ledger reach now" is answered against real output and not against a fixture
	 * chosen to pass.
	 */
	function row(over: Partial<ExtractedEvent> & { category: string; value: string; quote: string; seq: number }): ExtractedEvent {
		return {
			type: "grant",
			kind: over.value.endsWith("/") ? "scope" : "entity",
			messageId: `m${over.seq}`,
			...over,
		}
	}

	it("a content row over the same path does not answer a delete (the fs-write → fs-delete bridge)", () => {
		// Recorded for `copy the dataset file to /srv/exports/` (eval case L-01): the sentence was only ever
		// about copying.
		const l = createLedger()
		applyEvents(l, [row({ category: "write_outside", value: "/srv/exports/", quote: "copy the dataset file to /srv/exports/", seq: 1 })])
		expect(ledgerCovers(l, "write_outside", [T("/srv/exports/run.csv")]).covered).toBe(true)
		// The write half is still covered and the delete half is not. Before this the second line depended on
		// DELETE_VERB_RE finding a destructive word in that quote — and "copy … with rsync" has none, so it
		// refused for a reason that had nothing to do with what the model had said.
		expect(ledgerCovers(l, "delete_recursive", [T("/srv/exports/run.csv")]).covered).toBe(false)
		expect(ledgerCovers(l, "write_outside+delete_recursive", [T("/srv/exports/run.csv")]).covered).toBe(false)
	})

	it("a delete row answers its own delete, with or without a word code recognises", () => {
		// Recorded for `clear s3://acme-data/dev/ only`.
		const l = createLedger()
		applyEvents(l, [row({ category: "delete_data", value: "s3://acme-data/dev/", quote: "clear s3://acme-data/dev/ only", seq: 1 })])
		expect(ledgerCovers(l, "delete_data", [T("s3://acme-data/dev/exports.csv")]).covered).toBe(true)
		// And the same row shape with a quote no verb list would have matched: the category is the evidence
		// (the model's field stands), so this covers too. It is the behaviour change, pinned where it can be
		// seen rather than argued about.
		const other = createLedger()
		applyEvents(other, [row({ category: "delete_data", value: "s3://acme-data/dev/", quote: "the dev/ prefix in acme-data is junk, sort it", seq: 1 })])
		expect(ledgerCovers(other, "delete_data", [T("s3://acme-data/dev/exports.csv")]).covered).toBe(true)
	})

	it("a container row no longer reaches the send half of a publish compound (the container → send bridge removed)", () => {
		// Recorded for `delete the Payments:Staging image` — and note what no recorded answer ever produced: a
		// `network_send` row. Every recorded publish-ish sentence filed its row under the artifact, so the
		// send half of `container_mutation+network_send` was reachable ONLY through the bridge. With the
		// bridge gone the ledger stops short of the compound, which costs a prompt; the transcript call can
		// still grant it when its `effects` name both halves.
		const l = createLedger()
		applyEvents(l, [row({ category: "container_mutation", value: "payments:staging", quote: "delete the Payments:Staging image", seq: 1 })])
		expect(ledgerCovers(l, "container_mutation", [T("payments:staging")]).covered).toBe(true)
		expect(ledgerCovers(l, "container_mutation+network_send", [T("payments:staging")]).covered).toBe(false)
		// A plain send was never reachable from a container row, and still is not.
		expect(ledgerCovers(l, "network_send", [T("payments:staging")]).covered).toBe(false)
	})

	it("a row stored under the category layer 0 used to file it just stops matching", () => {
		// A grants.json written before the rename holds `cluster_mutation s3://acme-data/dev/` for a prefix the
		// user really did approve. Layer 0 now files that delete as `delete_data`, so the old row answers
		// nothing and the user is asked once more. Nothing may go the other way: an old row must not reach a
		// command it could not reach before, and the row keeps its own reach for what still carries its name.
		const l = createLedger()
		applyEvents(l, [row({ category: "cluster_mutation", value: "s3://acme-data/dev/", quote: "clear out the dev/ prefix in the acme-data bucket", seq: 1 })])
		expect(ledgerCovers(l, "delete_data", [T("s3://acme-data/dev/exports.csv")]).covered).toBe(false)
		expect(ledgerCovers(l, "cluster_mutation", [T("s3://acme-data/dev/exports.csv")]).covered).toBe(true)
	})

	it("a bucket row sharing the fs-delete group reaches no filesystem path and no write", () => {
		// `delete_data` is the shared name for a local data-file delete AND a bucket-object delete, so the
		// entity is the only thing telling the two apart. Both directions of the widening are checked: the
		// delete siblings, and the one-way fs-delete → fs-write direction that lets a delete scope answer a
		// write inside it — an s3 prefix must not use it, because an s3 upload is network_send, a
		// different group entirely.
		const bucket = createLedger()
		applyEvents(bucket, [row({ category: "delete_data", value: "s3://acme-data/dev/", quote: "clear out the dev/ prefix in the acme-data bucket", seq: 1 })])
		expect(ledgerCovers(bucket, "delete_data", [T("s3://acme-data/dev/exports.csv")]).covered).toBe(true)
		for (const [category, target] of [
			["delete_outside", "/home/dev/proj/dev/x.csv"],
			["delete_recursive", "./dev/x.csv"],
			["write_outside", "/home/dev/proj/dev/x.csv"],
			["write_project", "./dev/x.csv"],
			["network_send", "s3://acme-data/dev/x.csv"],
		] as const) {
			expect(ledgerCovers(bucket, category, [T(target)]).covered, `${category} ${target}`).toBe(false)
		}
		// and the reverse: a local data-file row says nothing about the bucket
		const local = createLedger()
		applyEvents(local, [row({ category: "delete_data", value: "./backups/", kind: "scope", quote: "clear out ./backups", seq: 1 })])
		expect(ledgerCovers(local, "delete_data", [T("s3://acme-data/backups/x")]).covered).toBe(false)
		expect(ledgerCovers(local, "delete_data", [T("./backups/dump.sql")]).covered).toBe(true)
	})

	it("under a read-only posture a delete-category row lifts a delete on the target it names", () => {
		// Recorded for `clean up /var/log/nginx` (eval case L-16), with the posture from the
		// readonly-supersede replay. The verb half of `readOnlyLiftedByGrant` is gone, so what lifts the
		// posture is a row in the delete family that covers the target — nothing else.
		const l = createLedger()
		l.readOnlyOn = { seq: 1, quote: "do not change anything on this box" }
		applyEvents(l, [row({ category: "delete_outside", value: "/var/log/nginx/", quote: "clean up /var/log/nginx", seq: 5 })])
		expect(readOnlyLiftedByGrant(l, "delete_recursive", [T("/var/log/nginx/access.log")], 1)).toBe(true)
		expect(readOnlyLiftedByGrant(l, "delete_recursive", [T("/var/log/other/access.log")], 1)).toBe(false)
		// A content row does not lift a delete, posture or no posture.
		const content = createLedger()
		content.readOnlyOn = { seq: 1, quote: "do not change anything on this box" }
		applyEvents(content, [row({ category: "write_outside", value: "/var/log/nginx/", quote: "copy the logs into /var/log/nginx", seq: 5 })])
		expect(readOnlyLiftedByGrant(content, "delete_recursive", [T("/var/log/nginx/access.log")], 1)).toBe(false)
	})
})

/**
 * A withdrawal can name several actions, or every action, on one thing.
 *
 * The rows below are the shapes the extraction call returns now (a revocation `category` is a list, and `any`
 * is on the revocation enum). Targets are invented (`/srv/warehouse`, `cold-archive`) because the point here is
 * the fold and the matcher, not any real sentence.
 */

/** A stored row from an earlier message — the shape the `row` helper inside the block above has, local here
 *  because that one is block-scoped and this block stands on its own. */
function storedRow(over: { category: string; value: string; quote: string; seq: number; kind?: "entity" | "scope"; type?: "grant" | "forbid" }): ExtractedEvent {
	return {
		type: over.type ?? "forbid",
		category: over.category,
		value: over.value,
		kind: over.kind ?? (over.value.endsWith("/") ? "scope" : "entity"),
		quote: over.quote,
		messageId: `m${over.seq}`,
		seq: over.seq,
	}
}

/** One revocation row through the real fold, with the message the quote must be found in. */
function withdraw(
	categories: string | string[],
	targets: string[],
	opts: { scope?: string; quote?: string; message?: string; targetClass?: string } = {},
) {
	const quote = opts.quote ?? (targets[0] ? `leave ${targets[0]} alone` : "do not do any of that")
	const message = opts.message ?? `${quote}, nothing else matters`
	const events = eventsFromExtraction(
		{
			grants: [],
			revocations: [{ action: "withdraw work", category: categories, scope: opts.scope ?? "named", targetClass: opts.targetClass ?? "none", targets, quote }],
		},
		"m1",
		5,
		message,
	)
	return { events, message }
}

describe("a withdrawal names several kinds, or every kind", () => {
	it("a list of kinds becomes one forbid row per kind, per target shape", () => {
		const { events } = withdraw(["write_outside", "delete_outside"], ["/srv/warehouse"])
		const forbids = events.filter((e) => e.type === "forbid")
		// Two kinds × (the named thing + its subtree) — the subtree pair is what makes a folder grant written
		// earlier stop authorising files inside it (eval case L-02), and every kind needs it.
		expect(forbids.map((e) => `${e.category}:${e.value}:${e.kind}`).sort()).toEqual([
			"delete_outside:/srv/warehouse/:scope",
			"delete_outside:/srv/warehouse:entity",
			"write_outside:/srv/warehouse/:scope",
			"write_outside:/srv/warehouse:entity",
		])
	})

	it("a read kind in the list keeps its own narrow shape while the mutation kinds get the pair", () => {
		const { events } = withdraw(["read_only", "delete_outside"], ["/srv/warehouse"])
		const byCat = new Map<string, string[]>()
		for (const e of events.filter((x) => x.type === "forbid")) {
			byCat.set(e.category, [...(byCat.get(e.category) ?? []), `${e.value} (${e.kind})`])
		}
		// A negated read is one sentence about one object: no subtree pair, or a ban on reading one file would
		// also ban reading the directory entry beside it.
		expect(byCat.get("read_only")).toEqual(["/srv/warehouse/ (scope)"])
		expect(byCat.get("delete_outside")?.sort()).toEqual(["/srv/warehouse (entity)", "/srv/warehouse/ (scope)"])
	})

	it("`any` is stored as one category, not fanned out over every value in the enum", () => {
		const { events } = withdraw(["any"], ["/srv/warehouse"])
		expect(events.every((e) => e.category === "any")).toBe(true)
		expect(events.filter((e) => e.type === "forbid")).toHaveLength(2)
		// `any` subsumes the rest of the list rather than sitting beside it.
		const wider = withdraw(["delete_data", "any"], ["/srv/warehouse"])
		expect(wider.events.map((e) => e.category)).toEqual(["any", "any"])
	})

	it("one `any` row answers every kind of action on the target it names", () => {
		const ledger = createLedger()
		applyEvents(ledger, withdraw(["any"], ["/srv/warehouse"]).events)
		for (const [category, target] of [
			["delete_data", "/srv/warehouse/exports.csv"],
			["delete_recursive", "/srv/warehouse/exports.csv"],
			["write_outside", "/srv/warehouse/exports.csv"],
			["write_sensitive", "/srv/warehouse/exports.csv"],
			["system_config", "/srv/warehouse/exports.csv"],
			["perm_change", "/srv/warehouse/exports.csv"],
			["read_only", "/srv/warehouse/exports.csv"],
			["cluster_mutation", "/srv/warehouse/exports.csv"],
		] as const) {
			const verdict = ledgerCovers(ledger, category, [T(target)])
			expect(verdict.forbidden, `${category} ${target}`).toBe(true)
			expect(verdict.covered, `${category} ${target}`).toBe(false)
		}
		// …and nothing anywhere else: the ban is aimed at a target, not at the session.
		expect(ledgerCovers(ledger, "delete_data", [T("/srv/other/x.csv")]).forbidden).toBe(false)
	})

	it("a single-kind withdrawal still answers its own kinds, and nothing outside the family", () => {
		const ledger = createLedger()
		applyEvents(ledger, withdraw(["delete_data"], ["/srv/warehouse"]).events)
		expect(ledgerCovers(ledger, "delete_data", [T("/srv/warehouse/x.csv")]).forbidden).toBe(true)
		// A writes ban inside the same fs-mutation family binds too — deliberately, and since before the list
		// arrived (`FORBID_FAMILIES`, 2514c8d: a forbid must be at least as wide as the grant it revokes). The
		// list did not widen this and the pin is here so the next narrowing is a decision, not a side effect.
		expect(ledgerCovers(ledger, "write_outside", [T("/srv/warehouse/x.csv")]).forbidden).toBe(true)
		// What a one-kind ban does NOT reach is a different kind of work entirely: reading, and cluster work.
		// (`network_send` is deliberately NOT a control here — the store family binds it, and the test for that
		// is the one below.)
		expect(ledgerCovers(ledger, "read_only", [T("/srv/warehouse/x.csv")]).forbidden).toBe(false)
		expect(ledgerCovers(ledger, "cluster_mutation", [T("/srv/warehouse/x.csv")]).forbidden).toBe(false)
	})

	it("a forbid on a store reaches the objects inside it", () => {
		// The target rule, stated in `target-grammar.ts`: a container reaches what is in it. The row spells the
		// store the way a user does — one word — and the actions arrive as URIs.
		const ledger = createLedger()
		applyEvents(ledger, withdraw(["any"], ["cold-archive"], { quote: "leave cold-archive alone" }).events)
		for (const target of ["s3://cold-archive/exports/2024.csv", "gs://cold-archive/x", "s3://cold-archive"]) {
			expect(ledgerCovers(ledger, "delete_data", [T(target)]).forbidden, target).toBe(true)
		}
		expect(ledgerCovers(ledger, "delete_data", [T("s3://other-bucket/x")]).forbidden).toBe(false)
		// A prefix row stops at the prefix.
		const prefix = createLedger()
		applyEvents(prefix, [storedRow({ category: "any", value: "s3://cold-archive/exports/", quote: "leave cold-archive/exports alone", seq: 2 })])
		expect(ledgerCovers(prefix, "delete_data", [T("s3://cold-archive/exports/a.csv")]).forbidden).toBe(true)
		expect(ledgerCovers(prefix, "delete_data", [T("s3://cold-archive/inbox/a.csv")]).forbidden).toBe(false)
		// GRANTS keep today's matching, unchanged: this reach is the component matcher's, which predates the list
		// (`entityMatchesTarget("s3://cold-archive/exports/2024.csv","cold-archive")` was already true). Pinned
		// so a future change to the container rule cannot quietly widen a grant.
		const grants = createLedger()
		applyEvents(grants, [storedRow({ type: "grant", category: "delete_data", value: "cold-archive", quote: "you can clear cold-archive", seq: 1 })])
		expect(ledgerCovers(grants, "delete_data", [T("s3://cold-archive/exports/2024.csv")]).covered).toBe(true)
		expect(ledgerCovers(grants, "delete_data", [T("s3://other-bucket/x")]).covered).toBe(false)
	})

	it("a writes ban on a store also stops deletes inside it, and a delete ban stops uploads", () => {
		// The object-store half of FORBID_FAMILIES: a bucket is entered by uploading (`network_send`) and
		// emptied by deleting objects (`delete_data`); "do not write in X" has to stop both, exactly as the
		// fs-mutation family makes a writes ban on a directory stop `rm` inside it.
		const ledger = createLedger()
		applyEvents(ledger, [storedRow({ category: "network_send", value: "s3://cold-archive/", quote: "you are not allowed to change anything in cold-archive", seq: 3 })])
		expect(ledgerCovers(ledger, "delete_data", [T("s3://cold-archive/exports/2024.csv")]).forbidden).toBe(true)
		expect(ledgerCovers(ledger, "network_send", [T("s3://cold-archive/exports/2024.csv")]).forbidden).toBe(true)
		// The family is bounded by the target: another store is untouched, and so is a category that shares
		// neither a group nor the store family.
		expect(ledgerCovers(ledger, "delete_data", [T("s3://other/x.csv")]).forbidden).toBe(false)
		expect(ledgerCovers(ledger, "delete_outside", [T("/srv/cold-archive/x.csv")]).forbidden).toBe(false)
	})

	it("`any` with no object named is the whole-session stop, and it is the model that named it", () => {
		const ledger = createLedgerWith(withdraw(["any"], [], { quote: "leave everything alone" }).events)
		const active = readOnlyActive(ledger)
		expect(active?.quote).toBe("leave everything alone")
		expect(ledger.forbids).toHaveLength(0)
	})

	it("`any` at the model's `category` width leaves a BAN behind the posture, so an earlier grant cannot answer it", () => {
		// The posture is a default, not a veto — the gate consults grants first and `readOnlyLiftedByGrant` lifts it
		// for a target. Measured with a model on the committed image cases and G9: the same withdrawal sentence that at
		// base folded to `forbid container_mutation *` (prompt) folded to `readonly-on *` and the older grant won,
		// so the wider word had the weaker effect. `any` with nothing named has to block MORE, never less.
		const { events } = withdraw(["any"], [], { scope: "category", quote: "do not touch the images any more" })
		const ledger = createLedgerWith(events)
		expect(readOnlyActive(ledger)?.quote).toBe("do not touch the images any more")
		expect(ledger.forbids.filter((f) => f.category === "any" && f.value === "*").map((f) => f.kind)).toEqual(["scope"])
		// A grant of the same kind given BEFORE the sentence: the ban dominates, that is the whole point.
		applyEvent(ledger, grant("container_mutation", "payments:staging", 1, "you can restart payments:staging"))
		const verdict = ledgerCovers(ledger, "container_mutation", [T("payments:staging")])
		expect(verdict.forbidden).toBe(true)
		expect(verdict.covered).toBe(false)
		// And the ban answers kinds the sentence never spelled out, because `any` is every action.
		expect(ledgerCovers(ledger, "read_only", [T("payments:staging")]).forbidden).toBe(true)
	})

	it("at the model's `named` width it writes no `*` row — the width stays the model's, not code's", () => {
		// The posture already covers everything for that row; inventing a wildcard the model did not claim is the
		// one thing the fold must not do, and this pin is what keeps the fix above honest.
		const { events } = withdraw(["any"], [], { scope: "named", quote: "leave everything alone" })
		expect(events.some((e) => e.type === "forbid" && e.value === "*")).toBe(false)
		expect(events.filter((e) => e.type === "readonly-on")).toHaveLength(1)
	})

	it("`any` on a target the user never wrote does NOT arm the stop — a row code cannot place costs a call", () => {
		// An unusable row may never arm the session lock. The quote is verbatim, the target is not.
		const { events } = withdraw(["any"], ["/nowhere/mentioned"], { quote: "leave the warehouse alone" })
		const ledger = createLedgerWith(events)
		expect(readOnlyActive(ledger)).toBeNull()
		expect(ledger.forbids.some((f) => f.category === "*unknown*")).toBe(true)
	})

	it("a grant row that carries `any` is inert: it authorises nothing and is never matched", () => {
		const ledger = createLedger()
		applyEvent(ledger, { type: "grant", category: "any", value: "/srv/warehouse", kind: "entity", quote: "do whatever you like with /srv/warehouse", messageId: "m1", seq: 1 })
		for (const category of ["delete_data", "write_outside", "read_only"]) {
			expect(ledgerCovers(ledger, category, [T("/srv/warehouse/x.csv")]).covered, category).toBe(false)
		}
	})

	it("a list survives the serialize round trip as the rows it produced (no new row shape)", () => {
		// The ledger row is still `{category, value, kind}`: `any` is one more category string, so a snapshot
		// written today loads in a build that predates the list and one written yesterday loads today.
		const ledger = createLedgerWith(withdraw(["any"], ["/srv/warehouse"]).events)
		const restored = deserializeLedger(serializeLedger(ledger))
		expect(restored.forbids.map((f) => f.category)).toEqual(ledger.forbids.map((f) => f.category))
		expect(ledgerCovers(restored, "read_only", [T("/srv/warehouse/x.csv")]).forbidden).toBe(true)
	})

	it("explainLedgerCover says the `any` row is what refused, in the same words the gate used", () => {
		const ledger = createLedgerWith(withdraw(["any"], ["/srv/warehouse"]).events)
		const lines = explainLedgerCover(ledger, "write_outside", [T("/srv/warehouse/x.csv")])
		expect(lines.join("\n")).toContain("segment write_outside uncovered")
	})
})
