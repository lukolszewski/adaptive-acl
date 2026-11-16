/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * A READ grant on a non-file OBJECT covers both read categories, and never a file.
 *
 * The bug this pins: "you may read system state with gcloud" became a `read_system_state` row on `gcloud`, and
 * layer 0 answers `gcloud compute instances list` with `read_only` on that same object. Two read categories in
 * two kind groups meant the stored row answered NOTHING — it was recorded, it listed in `/grants`, and every
 * `gcloud` read asked again. The word the analyzer picked for a subcommand is a spelling difference about an
 * object, so the pair (`read_system_state` ↔ `read_only`) now answers across, in both directions.
 *
 * What keeps that from being a blanket is the TARGET, and it is the half worth reading twice:
 *   · an OBJECT is not a path, so a machine-state grant still never reaches a file, in either direction;
 *   · `read_secret` is not in the pair, either way — reading a thing's state and reading credentials are
 *     different permissions;
 *   · a `*` row names no object and keeps exactly today's behaviour.
 *
 * Every rule is asked of BOTH stores, because the session store is consulted first and the ledger second: two
 * answers to one question is how a clicked approval ends up weaker than the same sentence spoken.
 */
import { describe, expect, it } from "vitest"
import { applyEvent, applyEvents, createLedger, eventsFromExtraction, explainLedgerCover, ledgerCovers, type Ledger } from "./auth-ledger.ts"
import { addGrant, createGrantStore, explainGrantsCover, grantsCover } from "./session-grants.ts"
import { isPathTarget } from "./grant-verify.ts"
import { runGate } from "./gate.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }
const HOME = "/home/u"
const PROJECT = "/home/u/proj"

/** The gate's own entities: a kind-`target` value, as layer 0 renders it. */
const at = (value: string) => [{ kind: "target", value } as never]

function storeWith(rows: Array<{ category: string; value: string; kind?: "entity" | "scope" }>) {
	const store = createGrantStore()
	for (const row of rows) addGrant(store, row.category, row.value, row.kind ?? "entity")
	return store
}

function ledgerWith(rows: Array<{ category: string; value: string; kind?: "entity" | "scope" }>): Ledger {
	const ledger = createLedger()
	rows.forEach((row, i) =>
		applyEvent(ledger, {
			type: "grant",
			category: row.category,
			value: row.value,
			kind: row.kind ?? "entity",
			quote: `fixture grant ${i}`,
			messageId: `m${i}`,
			seq: i + 1,
		}),
	)
	return ledger
}

/** The same question asked of both stores, so a drift between them fails here rather than at a prompt. */
function bothSides(row: { category: string; value: string; kind?: "entity" | "scope" }, pending: string, target: string): [boolean, boolean] {
	return [
		grantsCover(storeWith([row]), pending, at(target), HOME, PROJECT).covered,
		ledgerCovers(ledgerWith([row]), pending, at(target), HOME, PROJECT).covered,
	]
}

describe("the read pair answers across, on an object, in both directions", () => {
	it("a read_system_state row on gcloud answers a read_only read of gcloud", () => {
		expect(bothSides({ category: "read_system_state", value: "gcloud" }, "read_only", "gcloud")).toEqual([true, true])
	})

	it("a read_only row on gcloud answers a read_system_state read of gcloud", () => {
		expect(bothSides({ category: "read_only", value: "gcloud" }, "read_system_state", "gcloud")).toEqual([true, true])
	})

	it("the pair is about the object, so every non-path shape of target works and no near object does", () => {
		// Objects, one per row: a group of CLIs, a cluster, a host:port, a host, a bucket URI,
		// and a named thing a person says out loud.
		const objects = ["gcloud", "aws ec2", "prod-cluster", "localhost/nginx", "docs.example.com", "s3://bucket/", "the firewall rules"]
		for (const object of objects) {
			expect(bothSides({ category: "read_system_state", value: object }, "read_only", object), object).toEqual([true, true])
			expect(bothSides({ category: "read_only", value: object }, "read_system_state", object), object).toEqual([true, true])
		}
		// …and naming one object is not naming another, in either direction.
		expect(bothSides({ category: "read_system_state", value: "gcloud" }, "read_only", "aws ec2")).toEqual([false, false])
		expect(bothSides({ category: "read_only", value: "gcloud" }, "read_system_state", "prod-cluster")).toEqual([false, false])
	})

	it("a compound row carries its half, and a compound pending cannot be half-answered", () => {
		// `read_only+read_secret` is one command that reads a file AND a credential; the pair must not hand the
		// credential half to a machine-state row just because the other half matched.
		expect(bothSides({ category: "read_system_state", value: "gcloud" }, "read_only+read_secret", "gcloud")).toEqual([false, false])
	})
})

describe("what the pair never reaches, in either direction", () => {
	const PAIRS: Array<[string, string]> = [
		["read_system_state", "read_only"],
		["read_only", "read_system_state"],
	]
	// The three shapes of path the gate renders: home-relative, absolute, project-relative. The machine-state rule says a machine
	// grant never reaches a file, and the pair does not open that door — the target check refuses all three.
	const PATHS = ["~/notes/todo.md", "/etc/x", "./x", "/home/u/.ssh/id_ed25519", "../up"]

	it("no path, in either direction", () => {
		for (const [rowCategory, pending] of PAIRS) {
			for (const path of PATHS) {
				// The row names the SAME string as the target, so the only thing that can refuse it is the path
				// test — not a value mismatch standing in for it.
				expect(bothSides({ category: rowCategory, value: path }, pending, path), `${rowCategory} → ${pending} ${path}`).toEqual([false, false])
			}
		}
	})

	it("…and the control: the same row and the same value as an object IS covered, so the refusal is the shape", () => {
		for (const [rowCategory, pending] of PAIRS) {
			expect(bothSides({ category: rowCategory, value: "gcloud" }, pending, "gcloud"), `${rowCategory} → ${pending}`).toEqual([true, true])
		}
	})

	it("read_secret stays a separate permission, both ways", () => {
		expect(bothSides({ category: "read_system_state", value: "gcloud" }, "read_secret", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "read_only", value: "gcloud" }, "read_secret", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "read_secret", value: "gcloud" }, "read_system_state", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "read_secret", value: "gcloud" }, "read_only", "gcloud")).toEqual([false, false])
	})

	it("a read grant still buys no change, and a write still buys no machine read", () => {
		expect(bothSides({ category: "read_system_state", value: "gcloud" }, "cluster_mutation", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "read_only", value: "gcloud" }, "write_outside", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "write_outside", value: "/home/u/x/", kind: "scope" }, "read_system_state", "localhost")).toEqual([false, false])
	})

	it("a `*` value behaves as today: it answers its own category and not the pair", () => {
		// A `*` row is a LEDGER shape: `valueCovers` reads it as "any value" for the row's own category, and no
		// session grant ever holds one (the marker is the targetless pending, not a stored value). Both halves of
		// that are today's behaviour, pinned here so the pair cannot be what changes either one.
		const own = ledgerWith([{ category: "read_only", value: "*" }])
		expect(ledgerCovers(own, "read_only", at("gcloud"), HOME, PROJECT).covered).toBe(true)
		const status = ledgerWith([{ category: "read_system_state", value: "*" }])
		expect(ledgerCovers(status, "read_system_state", at("gcloud"), HOME, PROJECT).covered).toBe(true)
		// …and a row that names no object is not evidence about THIS object, which is the rule the machine-read
		// direction (`machineReadEntailedBy`) already applied to `*`, now applied to the pair both ways.
		expect(bothSides({ category: "read_only", value: "*" }, "read_system_state", "gcloud")).toEqual([false, false])
		expect(bothSides({ category: "read_system_state", value: "*" }, "read_only", "gcloud")).toEqual([false, false])
	})
})

describe("`/grants explain` reports the match the gate decides", () => {
	it("the session store prints the covering row", () => {
		const lines = explainGrantsCover(storeWith([{ category: "read_system_state", value: "gcloud" }]), "read_only", at("gcloud"), HOME, PROJECT)
		expect(lines).toContain('row read_system_state "gcloud" (entity): covers gcloud')
	})

	it("the ledger prints the covering row", () => {
		const lines = explainLedgerCover(ledgerWith([{ category: "read_system_state", value: "gcloud" }]), "read_only", at("gcloud"), HOME, PROJECT)
		expect(lines.some((l) => l.startsWith('row read_system_state "gcloud" seq 1: covers gcloud'))).toBe(true)
		expect(lines.join("\n")).not.toContain("uncovered")
	})

	it("…and a path is still reported uncovered, so the explanation cannot promise what the gate refuses", () => {
		const grants = explainGrantsCover(storeWith([{ category: "read_system_state", value: "gcloud" }]), "read_only", at("/etc/x"), HOME, PROJECT)
		expect(grants.join("\n")).toContain("rejected:")
		const ledger = explainLedgerCover(ledgerWith([{ category: "read_system_state", value: "gcloud" }]), "read_only", at("/etc/x"), HOME, PROJECT)
		expect(ledger.join("\n")).toContain("segment read_only uncovered")
	})
})

describe("end to end: the stored sentence answers the command it was about", () => {
	async function gate(command: string, ledger?: Ledger) {
		return runGate("bash", { command }, { policy: POLICY, ledger })
	}

	it("`gcloud compute instances list` is answered by a read_system_state grant on gcloud", async () => {
		const asked = await gate("gcloud compute instances list")
		expect(asked.outcome).toBe("prompt")
		expect(asked.category).toBe("read_system_state")
		// Either label answers it: rows stored before cloud reads were relabelled say read_only.
		for (const category of ["read_system_state", "read_only"]) {
			const allowed = await gate("gcloud compute instances list", ledgerWith([{ category, value: "gcloud" }]))
			expect(allowed.outcome, category).toBe("allow-granted")
			expect(allowed.grantedBy, category).toBe("ledger")
		}
	})

	it("…and the control: the same grant answers no change to that account, and no other account's read", async () => {
		const ledger = ledgerWith([{ category: "read_system_state", value: "gcloud" }])
		const del = await gate("gcloud compute instances delete vm1", ledger)
		// The category is asserted only as "not a read", because which mutation word layer 0 picks for a cloud
		// delete is that layer's business and not this rule's: what this file pins is that the READ pair never buys it.
		expect(["read_only", "read_system_state"]).not.toContain(del.category)
		expect(del.outcome).toBe("prompt")
		const other = await gate("aws ec2 describe-instances", ledger)
		expect(other.outcome).toBe("prompt")
	})

	it("the session store covers the same command the ledger does", async () => {
		const r = await runGate(
			"bash",
			{ command: "gcloud compute instances list" },
			{ policy: POLICY, grants: storeWith([{ category: "read_system_state", value: "gcloud" }]) },
		)
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("session-grant")
	})

	it("the sentence the user actually said is enough: extraction → ledger → the read runs", async () => {
		// The whole bug, from the sentence to the command, with the model's answer recorded rather than called. The
		// row the extraction stores is what the user approved; the command layer 0 classifies is the other read
		// word about the same object; and the mutation beside it is still the user's question to answer.
		const TEXT = "you may read system state with gcloud"
		const ledger = createLedger()
		applyEvents(
			ledger,
			eventsFromExtraction(
				{
					grants: [
						{
							action: "read machine status",
							category: "read_system_state",
							kind: "entity",
							scope: "named",
							includesSecrets: false,
							targets: ["gcloud"],
							quote: TEXT,
						},
					],
					revocations: [],
				} as never,
				"m1",
				1,
				TEXT,
			),
		)
		expect(ledger.grants.map((g) => `${g.category} ${g.value}`)).toEqual(["read_system_state gcloud"])
		expect((await gate("gcloud compute instances list", ledger)).outcome).toBe("allow-granted")
		expect((await gate("gcloud compute instances delete vm1", ledger)).outcome).toBe("prompt")
	})
})

describe("isPathTarget is the one path test both decisions use", () => {
	it("a leading /, ~ or . is a path; everything else is an object", () => {
		for (const path of ["/etc/x", "~/x", "./x", "../x", ".", "~"]) expect(isPathTarget(path), path).toBe(true)
		for (const object of ["gcloud", "aws ec2", "prod-cluster", "localhost/nginx", "docs.example.com", "s3://bucket/", "the firewall rules", "*", ""])
			expect(isPathTarget(object), object).toBe(false)
	})
})

describe("a forbid binds both read labels, so revoking reads of gcloud revokes both", () => {
	for (const [forbidCategory, pending] of [["read_only", "read_system_state"], ["read_system_state", "read_only"]] as const) {
		it(`${forbidCategory} forbid on gcloud stops a ${pending} grant on gcloud`, () => {
			const ledger = ledgerWith([{ category: pending, value: "gcloud" }])
			expect(ledgerCovers(ledger, pending, at("gcloud"), HOME, PROJECT).covered).toBe(true)
			applyEvent(ledger, { type: "forbid", category: forbidCategory, value: "gcloud", kind: "entity", quote: "stop reading gcloud", messageId: "m9", seq: 9 })
			const v = ledgerCovers(ledger, pending, at("gcloud"), HOME, PROJECT)
			expect(v.covered).toBe(false)
			expect(v.forbidden).toBe(true)
		})
	}

	it("a read forbid still binds only its own target", () => {
		// Revocation first: any NEWER revocation defers every older row to the gate's model call by design, so a
		// later one would prove nothing about targets.
		const ledger = createLedger()
		applyEvent(ledger, { type: "forbid", category: "read_only", value: "gcloud", kind: "entity", quote: "stop reading gcloud", messageId: "m1", seq: 1 })
		applyEvent(ledger, { type: "grant", category: "read_system_state", value: "aws", kind: "entity", quote: "you may read aws", messageId: "m2", seq: 2 })
		expect(ledgerCovers(ledger, "read_system_state", at("aws"), HOME, PROJECT).covered).toBe(true)
		expect(ledgerCovers(ledger, "read_system_state", at("gcloud"), HOME, PROJECT).forbidden).toBe(true)
	})
})
