/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import {
	applyEvent,
	createLedger,
	deserializeLedger,
	explainLedgerCover,
	eventsFromExtraction,
	extractionStats,
	ledgerCovers,
	namedForbidCovers,
	resetExtractionStats,
	serializeLedger,
	type ExtractedEvent,
	type Ledger,
} from "./auth-ledger.ts"
import { parseVcsTarget } from "./target-grammar.ts"
import type { Entity } from "./risk-policy.ts"

// In a reported session, a user who had granted pushes watched
// `git push origin feature/ABC123` get denied while `/grants` listed rows for that very
// branch. Every row in the first table below is a value the gate or the extractor really
// writes; every ❌ in the old reading was a row that could never match anything.
//
// The pending entity is the gate's OWN spelling for a push (`risk-handlers.ts`: target
// `"origin/<branch>"`, scope `"origin/*"`), so this file pins the matcher against the
// string the gate emits rather than against an invented one.

const PUSH = "origin/feature/ABC123"

const target = (value: string): Entity => ({ kind: "target", value }) as Entity

/** A ledger built the way the extraction pipeline builds one, so `kind` and the fold are real. */
function ledgerOf(...rows: Array<[string, string]>): Ledger {
	const ledger = createLedger()
	rows.forEach(([category, value], i) => {
		const event: ExtractedEvent = {
			type: "grant",
			category,
			value,
			kind: value.endsWith("/") ? "scope" : "entity",
			quote: `you can push ${value}`,
			messageId: `m${i + 1}`,
			seq: i + 1,
		}
		applyEvent(ledger, event)
	})
	return ledger
}

/** One row, one pending push, one verdict — the table below is run through the real entry point. */
function covers(rowValue: string, pending = PUSH, category = "vcs_remote"): boolean {
	return ledgerCovers(ledgerOf([category, rowValue]), category, [target(pending)]).covered
}

describe("what a vcs_remote row must cover", () => {
	// Every ✅ here was ❌ before the grammar was consulted: the four `origin/…` rows are the
	// gate's own scope spellings, and `refs/heads/…` is what a user copies out of `git branch`.
	const table: Array<[string, boolean, string]> = [
		["*", true, "the bare-verb row keeps its category-wide meaning"],
		["origin", true, "a named remote is 'every branch on it'"],
		["origin/", true, "the same reading in the scope spelling"],
		["origin/*", true, "the value the prompt's 'broader scope' button writes"],
		["origin/feature/*", true, "a trailing glob stops at the '/' boundary"],
		["refs/heads/feature/ABC123", true, "the spelling `git branch` prints"],
		["origin/feature/ABC123", true, "the gate's own target, stored verbatim"],
		["feature/ABC123", true, "the ref without its remote"],
		["ABC123", true, "the last component: how people say it"],
		["master", false, "a different branch"],
		["gh workflow run", false, "a forge command, not a ref"],
		["any branch", false, "prose: never stored, and matches nothing if it is"],
		["branch", false, "a kind-word is not a name"],
		["new branch", false, "prose"],
		["the new branch", false, "prose with a deixis in it"],
		["origin remote", false, "names the remote but is a sentence, not a ref"],
	]

	for (const [value, expected, why] of table) {
		it(`${JSON.stringify(value)} ${expected ? "covers" : "does not cover"} the push — ${why}`, () => {
			expect(covers(value)).toBe(expected)
		})
	}

	it("covers every branch on origin except the protected ones", () => {
		// The trade-off the owner accepted: "all branches on origin" must not mean `main`.
		for (const branch of ["feature/ABC123", "ABC123", "hotfix/ticket-77", "tickets/ABC123"]) {
			expect(covers("origin/*", `origin/${branch}`), branch).toBe(true)
		}
		for (const branch of ["main", "master", "develop", "release/2026-07", "production"]) {
			expect(covers("origin/*", `origin/${branch}`), branch).toBe(false)
		}
	})

	it("a row naming a protected branch is the only way to push it", () => {
		expect(covers("main", "origin/main")).toBe(true)
		expect(covers("origin/main", "origin/main")).toBe(true)
	})

	it("keeps a vcs_local row out of a push", () => {
		// Different kind group: a grant to commit locally says nothing about publishing.
		const ledger = ledgerOf(["vcs_local", "origin/feature/ABC123"])
		expect(ledgerCovers(ledger, "vcs_remote", [target(PUSH)]).covered).toBe(false)
	})

	it("still reports the reason a miss was a miss", () => {
		const ledger = ledgerOf(["vcs_remote", "any branch"])
		const verdict = ledgerCovers(ledger, "vcs_remote", [target(PUSH)])
		expect(verdict.covered).toBe(false)
		expect(verdict.forbidden).toBe(false)
		expect(verdict.reason).toBe("no matching ledger entry")
	})
})

/**
 * The same table, one segment wider.
 *
 * `git commit && git push` is one command with two effects, and the ledger is now asked about
 * each of them separately — the rule session grants already ran (`grantsCover`). So the compound
 * needs a row per segment: that is not a regression the grammar introduced, it is the half of the
 * bug the grammar could not fix. The reported failure was that a pending
 * `vcs_local+vcs_remote` matched only against `vcs_remote`, so a stored `vcs_remote` row covered
 * nothing at all while session grants covered it fine.
 */
describe("the same table, for the compound pending vcs_local+vcs_remote", () => {
	const table: Array<[string, boolean]> = [
		["*", true],
		["origin", true],
		["origin/*", true],
		["origin/feature/*", true],
		["refs/heads/feature/ABC123", true],
		["origin/feature/ABC123", true],
		["feature/ABC123", true],
		["master", false],
		["any branch", false],
		["the new branch", false],
	]

	for (const [value, expected] of table) {
		it(`${JSON.stringify(value)} on the vcs_remote row, with a vcs_local row beside it`, () => {
			const ledger = ledgerOf(["vcs_local", "*"], ["vcs_remote", value])
			expect(ledgerCovers(ledger, "vcs_local+vcs_remote", [target(PUSH)]).covered).toBe(expected)
		})
	}

	it("a vcs_remote row alone does not cover a compound pending — that is the per-segment rule", () => {
		// Pinning the direction: the fix is not "a vcs_remote row reaches the compound", it is
		// "each effect needs its own authority", exactly as session grants require.
		const ledger = ledgerOf(["vcs_remote", "origin/*"])
		expect(ledgerCovers(ledger, "vcs_local+vcs_remote", [target(PUSH)]).covered).toBe(false)
	})

	it("protects the same branches in the compound as in the single segment", () => {
		const ledger = ledgerOf(["vcs_local", "*"], ["vcs_remote", "origin/*"])
		expect(ledgerCovers(ledger, "vcs_local+vcs_remote", [target("origin/feature/ABC123")]).covered).toBe(true)
		expect(ledgerCovers(ledger, "vcs_local+vcs_remote", [target("origin/main")]).covered).toBe(false)
	})

	it("is covered whichever order the segments are written in", () => {
		// Segment order is composition order, and it must never decide a security answer.
		const rows: Array<[string, string]> = [["vcs_local", "*"], ["vcs_remote", "origin/*"]]
		const forward = ledgerCovers(ledgerOf(...rows), "vcs_local+vcs_remote", [target(PUSH)]).covered
		const backward = ledgerCovers(ledgerOf(...rows), "vcs_remote+vcs_local", [target(PUSH)]).covered
		expect(forward).toBe(true)
		expect(backward).toBe(true)
	})
})

describe("a forbid written in the gate's own scope spelling binds every branch on it", () => {
	// Forbids stay wide by design (see FORBID_FAMILIES): the row `origin/*` is the user's words for
	// "nothing on origin", so it must reach every branch the grammar can reach — the same
	// `valueCovers` the grants use, not a second, narrower reading of the same string.
	const push = [target(PUSH)]

	it("blocks a branch a grant would otherwise cover, by seq", () => {
		const ledger = ledgerOf(["vcs_remote", "origin/feature/ABC123"])
		expect(ledgerCovers(ledger, "vcs_remote", push).covered).toBe(true)
		applyEvent(ledger, {
			type: "forbid",
			category: "vcs_remote",
			value: "origin/*",
			kind: "entity",
			quote: "do not push anything to origin",
			messageId: "m9",
			seq: 99,
		})
		const verdict = ledgerCovers(ledger, "vcs_remote", push)
		expect(verdict.covered).toBe(false)
		expect(verdict.forbidden).toBe(true)
		expect(verdict.reason).toContain("do not push anything to origin")
	})

	it("binds the allow-tier scan too, through the same value rule", () => {
		const ledger = ledgerOf(["vcs_remote", "origin/*"])
		// Same row, read as a forbid rather than a grant.
		ledger.forbids.push({ ...ledger.grants[0]! })
		ledger.grants = []
		const hit = namedForbidCovers(ledger, push, undefined, undefined, "vcs_remote")
		expect(hit?.entity).toBe(PUSH)
		expect(hit?.entry.value).toBe("origin/*")
	})
})

describe("the artifact-publish bridge", () => {
	// `docker push myrepo/app:1.0` is ONE intent and layer 0 files it as two effects:
	// container_mutation+network_send. The sentence that grants it can only name the artifact, so a
	// container row whose own words named the publish answers the send half of THAT compound.
	const IMAGE = "myrepo/app:1.0"
	const COMPOUND = "container_mutation+network_send"

	function imageRow(category: string, value: string, quote: string): Ledger {
		const ledger = createLedger()
		applyEvent(ledger, {
			type: "grant",
			category,
			value,
			kind: "entity",
			quote,
			messageId: "m1",
			seq: 1,
		})
		return ledger
	}

	it("a container row naming the artifact covers both halves of the publish compound", () => {
		const ledger = imageRow("container_mutation", "myrepo/app", "you can push images to myrepo/app")
		expect(ledgerCovers(ledger, COMPOUND, [target(IMAGE)]).covered).toBe(true)
	})

	it("never reaches a plain network_send, which has no container segment to hang the bridge on", () => {
		const ledger = imageRow("container_mutation", "myrepo/app", "you can push images to myrepo/app")
		// A push to a registry and a curl to a URL are different authorities: that is why the two
		// groups were split, and the bridge must not undo that split.
		expect(ledgerCovers(ledger, "network_send", [target("https://collector.example.com/beacon")]).covered).toBe(false)
		expect(ledgerCovers(ledger, "network_send", [target(IMAGE)]).covered).toBe(false)
	})

	it("needs the publish verb in the row's own words, not just an artifact noun", () => {
		const ledger = imageRow("container_mutation", "myrepo/app", "look at what is in myrepo/app")
		expect(ledgerCovers(ledger, COMPOUND, [target(IMAGE)]).covered).toBe(false)
	})

	it("reaches the send half from anything in the cluster group (the group the row is in, not its name)", () => {
		const ledger = imageRow("cluster_mutation", "myrepo/app", "you can publish myrepo/app")
		expect(ledgerCovers(ledger, COMPOUND, [target(IMAGE)]).covered).toBe(true)
	})

	it("is one-way: a network_send row never authorises the container half", () => {
		const row = imageRow("network_send", "myrepo/app", "you can push myrepo/app up to the registry")
		// Its own segment is covered, and only that one: the compound still needs authority for the
		// container half, which this row does not supply.
		expect(ledgerCovers(row, "network_send", [target(IMAGE)]).covered).toBe(true)
		expect(ledgerCovers(row, COMPOUND, [target(IMAGE)]).covered).toBe(false)
		const containerOnly = imageRow("network_send", "myrepo/app", "you can push myrepo/app up")
		expect(ledgerCovers(containerOnly, "container_mutation", [target(IMAGE)]).covered).toBe(false)
	})
})

/* ------------------------------------------------------------------ extraction */

/** One sentence, one grant the model answered with `answer`. */
function extract(message: string, answer: { action: string; category?: string; targets: string[]; kind?: string }): ExtractedEvent[] {
	return eventsFromExtraction({ grants: [{ quote: message, ...answer }], revocations: [] } as never, "m1", 1, message)
}

/** The values the sentence leaves behind, as `category value` for readable failures. */
function stored(events: ExtractedEvent[]): string[] {
	return events.filter((e) => e.type === "grant").map((e) => `${e.category} ${e.value}`)
}

function ledgerFrom(events: ExtractedEvent[]): Ledger {
	const ledger = createLedger()
	for (const ev of events) applyEvent(ledger, ev)
	return ledger
}

describe("the noun in the sentence outranks the verb the model read", () => {
	it("files 'docker push' under the publish compound and remembers what the model said", () => {
		resetExtractionStats()
		const events = extract("you are allowed to run docker push", {
			action: "docker push",
			category: "vcs_remote",
			targets: ["docker"],
		})
		expect(events).toHaveLength(1)
		expect(events[0]).toEqual(expect.objectContaining({
			type: "grant",
			category: "container_mutation+network_send",
			value: "*",
			kind: "entity",
			modelCategory: "vcs_remote",
		}))
		expect(extractionStats.crossChecked).toBe(1)
	})

	it("and that row then covers the image push layer 0 files as the same compound", () => {
		const ledger = ledgerFrom(extract("you are allowed to run docker push", {
			action: "docker push",
			category: "vcs_remote",
			targets: ["docker"],
		}))
		expect(ledgerCovers(ledger, "container_mutation+network_send", [target("myrepo/app:1.0")]).covered).toBe(true)
	})

	it("never turns the model's wrong label into a second segment", () => {
		// `container_mutation+vcs_remote` with the category-wide `*` would authorise every push to
		// every remote off a sentence about docker. The second half is the EFFECT the verb names.
		expect(stored(extract("you are allowed to run docker push", {
			action: "docker push",
			category: "vcs_remote",
			targets: ["docker"],
		}))).toEqual(["container_mutation+network_send *"])
	})

	it("leaves the category alone when the model's answer agrees with the noun", () => {
		resetExtractionStats()
		const events = extract("you can push images to myrepo/app", {
			action: "push image",
			category: "container_mutation",
			targets: ["myrepo/app"],
		})
		expect(stored(events)).toEqual(["container_mutation myrepo/app"])
		expect(events[0]?.modelCategory).toBeUndefined()
		expect(extractionStats.crossChecked).toBe(0)
	})

	it("stores the artifact row the sentence really granted, and the compound covers through the bridge", () => {
		const ledger = ledgerFrom(extract("you can push images to myrepo/app", {
			action: "push image",
			category: "container_mutation",
			targets: ["images"],
		}))
		expect(ledger.grants.map((g) => `${g.category} ${g.value}`)).toEqual(["container_mutation myrepo/app"])
		expect(ledgerCovers(ledger, "container_mutation+network_send", [target("myrepo/app:1.0")]).covered).toBe(true)
		// … and nothing wider: the same row says nothing about sending an arbitrary URL.
		expect(ledgerCovers(ledger, "network_send", [target("https://collector.example.com/beacon")]).covered).toBe(false)
	})

	it("survives the snapshot round trip, because an override nobody can see is not an audit trail", () => {
		const ledger = ledgerFrom(extract("you are allowed to run docker push", {
			action: "docker push",
			category: "vcs_remote",
			targets: ["docker"],
		}))
		const restored = deserializeLedger(JSON.parse(JSON.stringify(serializeLedger(ledger))))
		expect(restored.grants[0]?.modelCategory).toBe("vcs_remote")
		expect(restored.grants[0]?.category).toBe("container_mutation+network_send")
	})
})

describe("extraction stores typed targets or nothing", () => {
	it("a ref in the sentence is stored in the gate's own spelling", () => {
		expect(stored(extract("push ABC123 to origin", { action: "push", category: "vcs_remote", targets: ["ABC123"] })))
			.toEqual(["vcs_remote origin/ABC123"])
		expect(stored(extract("push refs/heads/feature/ABC123 to origin", { action: "push", category: "vcs_remote", targets: ["refs/heads/feature/ABC123"] })))
			.toEqual(["vcs_remote origin/feature/ABC123"])
		expect(stored(extract("push ghcr.io/org/app:1", { action: "push", category: "container_mutation", targets: ["ghcr.io/org/app:1"] })))
			.toEqual(["container_mutation ghcr.io/org/app:1"])
	})

	it("'any branch on origin' is storable at last, as the value the prompt's scope button writes", () => {
		expect(stored(extract("you can push any branch on origin", { action: "push", category: "vcs_remote", targets: ["origin"] })))
			.toEqual(["vcs_remote origin/*"])
	})

	it("a quantifier with no remote and only the tool as a target is the category-wide row", () => {
		expect(stored(extract("you can push any branch", { action: "push", category: "vcs_remote", targets: ["branch"] })))
			.toEqual(["vcs_remote *"])
	})

	it("reads the quantifier in both numbers, because a regex that matches nothing reads as a rule", () => {
		// `branches?` in a regex is "branche" + optional s. Pinned in both numbers so a typo in the
		// kind-word table cannot pass by matching nothing.
		for (const message of ["you can push any branch", "you can push any branches", "you can push every branch", "you can push all branches"]) {
			expect(stored(extract(message, { action: "push", category: "vcs_remote", targets: ["branch"] })), message).toEqual(["vcs_remote *"])
		}
		// … and the remote half still wins when the sentence names one: a quantifier with a place
		// attached is a scoped row, not the category-wide one.
		for (const message of ["you can push every branch to origin", "you can push all branches on origin"]) {
			expect(stored(extract(message, { action: "push", category: "vcs_remote", targets: ["branch"] })), message).toEqual(["vcs_remote origin/*"])
		}
		for (const message of ["you can push any tag to ghcr.io", "you can push all tags to ghcr.io"]) {
			expect(stored(extract(message, { action: "push", category: "container_mutation", targets: ["tag"] })), message).toEqual(["container_mutation ghcr.io"])
		}
	})

	it("prose is never stored, however sure the model sounds about it", () => {
		// A dead row is worse than no row: it shows up in /grants as authority the gate does not have.
		for (const message of ["the new branch", "any branch", "push it to the new branch", "any branch is fine"] as const) {
			expect(extract(message, { action: "push", category: "vcs_remote", targets: ["the new branch", "branch"] }), message)
				.toEqual([])
		}
	})

	it("a quantifier without the publish verb grants nothing either", () => {
		expect(extract("what is in any branch", { action: "branch listing", category: "vcs_remote", targets: ["branch"] })).toEqual([])
	})

	it("keeps working for the categories that have no grammar", () => {
		// The normalisation is scoped to grammar categories: a path target still goes through
		// targetNamedByUser and is stored the way it always was.
		expect(stored(extract("you can write into /home/u/dev/wt/one.ts", { action: "write", category: "write_outside", targets: ["/home/u/dev/wt/one.ts"] })))
			.toEqual(["write_outside /home/u/dev/wt/one.ts"])
	})

	it("no sentence in a generated batch leaves a value the grammar cannot read (no dead rows)", () => {
		const remotes = ["origin", "upstream", "git.example.com"]
		const branches = ["ABC123", "feature/ABC123", "refs/heads/tickets/9", "hotfix/x"]
		const openers = ["you can push", "go ahead and publish", "you may release", "i allow you to push"]
		const batch: Array<{ message: string; targets: string[] }> = []
		for (const opener of openers) {
			branches.forEach((branch, i) => {
				const remote = remotes[i % remotes.length]!
				batch.push({ message: `${opener} ${branch} to ${remote}`, targets: [branch] })
			})
			for (const remote of remotes) {
				batch.push({ message: `${opener} any branch on ${remote}`, targets: ["branch", remote] })
				batch.push({ message: `${opener} every branch to ${remote}`, targets: ["branches"] })
			}
			batch.push({ message: `${opener} any branch`, targets: ["branch"] })
			batch.push({ message: `${opener} the new branch`, targets: ["the new branch"] })
			batch.push({ message: `${opener} it`, targets: ["it"] })
			batch.push({ message: `${opener} docker push`, targets: ["docker"] })
		}
		expect(batch.length).toBeGreaterThanOrEqual(50)

		let rows = 0
		for (const { message, targets } of batch) {
			for (const ev of extract(message, { action: "push", category: "vcs_remote", targets })) {
				if (!ev.category.startsWith("vcs_remote")) continue
				rows++
				expect(parseVcsTarget(ev.value), `${message} -> ${ev.value}`).toBeDefined()
			}
		}
		// A batch that stored nothing would pass the loop above vacuously.
		expect(rows).toBeGreaterThan(20)
	})
})

describe("explainLedgerCover: the row and the reason, for /grants explain", () => {
	function lines(ledger: Ledger, category = "vcs_remote", pending: Entity[] = [target(PUSH)]): string[] {
		return explainLedgerCover(ledger, category, pending)
	}

	it("names the row that covers", () => {
		expect(lines(ledgerOf(["vcs_remote", "origin/*"]))).toEqual([`row vcs_remote "origin/*" seq 1: covers ${PUSH}`])
	})

	it("says the group is what failed, for a row about a different kind of action", () => {
		// Same target, wrong category: a grant to commit locally is not a grant to publish. The second
		// line is the verdict the gate reaches — a rejection line never stands alone.
		expect(lines(ledgerOf(["vcs_local", PUSH]))).toEqual([
			`row vcs_local "${PUSH}" seq 1: rejected: group`,
			`segment vcs_remote uncovered: ${PUSH}`,
		])
	})

	it("says the value is what failed, which is the near miss users actually hit", () => {
		expect(lines(ledgerOf(["vcs_remote", "origin/main"]))).toEqual([
			`row vcs_remote "origin/main" seq 1: rejected: value`,
			`segment vcs_remote uncovered: ${PUSH}`,
		])
	})

	it("says the verb is what failed when the row names the entity but not the method", () => {
		expect(explainLedgerCover(ledgerOf(["package_system", "ripgrep"]), "package_system", [target("ripgrep")])).toEqual([
			`row package_system "ripgrep" seq 1: rejected: verb`,
			`segment package_system uncovered: ripgrep`,
		])
	})

	it("names the forbid that outranks the grant, by seq", () => {
		const ledger = ledgerOf(["vcs_remote", PUSH])
		applyEvent(ledger, {
			type: "forbid",
			category: "vcs_remote",
			value: "origin/*",
			kind: "entity",
			quote: "nothing to origin this week",
			messageId: "m7",
			seq: 7,
		})
		expect(lines(ledger)).toEqual([
			`row vcs_remote "${PUSH}" seq 1: rejected: forbid seq 7`,
			`segment vcs_remote uncovered: ${PUSH}`,
		])
	})

	it("reports the segment nobody covered, which is what a compound denial needs", () => {
		expect(lines(ledgerOf(["vcs_remote", "origin/*"]), "vcs_local+vcs_remote")).toEqual([
			`row vcs_remote "origin/*" seq 1: covers ${PUSH}`,
			`segment vcs_local uncovered: ${PUSH}`,
		])
	})

	it("says nothing when there is nothing to say, rather than inventing a line", () => {
		expect(lines(createLedger())).toEqual([`segment vcs_remote uncovered: ${PUSH}`])
		expect(explainLedgerCover(ledgerOf(["vcs_remote", "origin/*"]), "vcs_remote", [])).toEqual([])
	})

	it("is pure: explaining must not change what the gate later decides", () => {
		const ledger = ledgerOf(["vcs_remote", "origin/*"])
		explainLedgerCover(ledger, "vcs_remote", [target(PUSH)])
		expect(ledger.grants[0]?.lastMatchedAt).toBeUndefined()
		// The contrast is the point: the real lookup records the hit, which is what eviction reads.
		ledgerCovers(ledger, "vcs_remote", [target(PUSH)])
		expect(ledger.grants[0]?.lastMatchedAt).toBeTypeOf("number")
	})
})
