/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The confirmation path for the widening half of `/grants adopt`.
 *
 * What this suite is really guarding is one asymmetry: every bug here can grant instead of deny, so
 * each test states the fail-safe AND its inverse. "Nothing was written when no id was named" proves
 * nothing unless the same fixture writes when an id IS named, and "durable: false wrote no journal"
 * proves nothing unless the durable call next to it writes one. The other recurring shape is the
 * assertion on the STORED value rather than on a call having happened — the whole point of routing
 * through the canonicaliser is which string lands in the row, and a test that only checks that
 * `confirmAdoption` ran would pass with the wrong path stored.
 *
 * Fixtures are real: a tmp checkout with a carried project id, an orphan id beside it holding a rules
 * file and/or a journal written by the real writers, and a live store from `createGrantStore()`. The
 * plan half comes from `planAdoption()`, so these tests break if the two modules drift apart.
 */

import { afterEach, describe, expect, it } from "vitest"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	adoptChoiceId,
	buildAdoptChoices,
	confirmAdoptChoices,
	renderAdoptChoices,
	resolveAdoptSelection,
	type AdoptChoice,
	type AdoptGrantChoice,
} from "./adopt-confirm.ts"
import { planAdoption, type Candidate } from "./grants-adopt.ts"
import { buildGrantsFile, writeGrantsFile } from "./grants-file.ts"
import { addGrant, createGrantStore, revokeRows } from "./session-grants.ts"
import { writeProjectIdMarker } from "./utils.ts"

const LIVE = "livecheckout1"
const HOME = "/home/tester"
const SPACE = { home: HOME }

const made: string[] = []

/** A checkout whose project id is carried in `.pi/project.json`, so state paths are constants. */
function checkout(): string {
	const dir = mkdtempSync(join(tmpdir(), "pm-adoptc-"))
	made.push(dir)
	expect(writeProjectIdMarker(dir, LIVE)).toBe(true)
	return dir
}

function orphanDir(cwd: string, id: string): string {
	const dir = join(cwd, ".pi", "projects", id)
	mkdirSync(dir, { recursive: true })
	return dir
}

function orphanAllows(cwd: string, rules: string[], id = "movedaway1", file = "permissions.json"): void {
	const body = { permissions: { allow: rules } }
	writeFileSync(join(orphanDir(cwd, id), file), JSON.stringify(body, null, 2) + "\n")
}

type Row = { category: string; value: string; kind?: "entity" | "scope"; durable?: boolean }

/** An orphan journal on disk, built by the real writer so the shape is the one we read back. */
function orphanRows(cwd: string, rows: Row[], id = "movedaway1"): string {
	const path = join(orphanDir(cwd, id), "grants.json")
	const { file } = buildGrantsFile({
		ledger: { v: 1, grants: [], forbids: [], seen: [] },
		grants: rows.map((r) => ({
			category: r.category,
			value: r.value,
			kind: r.kind ?? (r.value.endsWith("/") ? "scope" : "entity"),
			at: Date.now(),
			...(r.durable ? { durable: true } : {}),
		})),
		sourceCwd: `/old/checkout/${id}`,
	})
	expect(writeGrantsFile(path, file)).toBe(true)
	return path
}

const liveFile = (cwd: string, local = false): string =>
	join(cwd, ".pi", "projects", LIVE, local ? "permissions.local.json" : "permissions.json")
const liveJournal = (cwd: string): string => join(cwd, ".pi", "projects", LIVE, "grants.json")

/** An empty live journal, the way a session that persisted nothing would leave it. */
function seedLiveJournal(cwd: string): string {
	const path = liveJournal(cwd)
	mkdirSync(join(cwd, ".pi", "projects", LIVE), { recursive: true })
	const { file } = buildGrantsFile({
		ledger: { v: 1, grants: [], forbids: [], seen: [] },
		grants: [],
		sourceCwd: cwd,
	})
	expect(writeGrantsFile(path, file)).toBe(true)
	return path
}

function allowList(cwd: string, local = false): string[] {
	if (!existsSync(liveFile(cwd, local))) return []
	const doc = JSON.parse(readFileSync(liveFile(cwd, local), "utf-8")) as {
		permissions?: { allow?: string[] }
	}
	return doc.permissions?.allow ?? []
}

function journalRows(cwd: string): { value: string; durable?: boolean }[] | null {
	if (!existsSync(liveJournal(cwd))) return null
	const doc = JSON.parse(readFileSync(liveJournal(cwd), "utf-8")) as { grants?: { value: string }[] }
	return doc.grants ?? []
}

const plan = (cwd: string, project?: string): Candidate[] =>
	planAdoption({ cwd, home: HOME, ...(project ? { project } : {}) }).pending

/** The one choice in a one-item pending list, with its id. */
function one(cwd: string, project?: string): { choices: AdoptChoice[]; pending: Candidate[] } {
	const pending = plan(cwd, project)
	return { pending, choices: buildAdoptChoices(pending, { cwd, home: HOME, ...(project ? { project } : {}) }) }
}

const targets = (choices: AdoptChoice[]): string[] => choices.map((c) => c.id)

/** The journal-row half of the union. Narrowing rather than casting: if the union changes, these break
 *  loudly instead of reading `undefined` off the wrong variant. */
function rowsOf(choices: readonly AdoptChoice[]): AdoptGrantChoice[] {
	return choices.filter((c): c is AdoptGrantChoice => c.kind === "grant")
}

function onlyRow(choices: readonly AdoptChoice[]): AdoptGrantChoice {
	const hits = rowsOf(choices)
	expect(hits).toHaveLength(1)
	return hits[0]!
}

afterEach(() => {
	for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe("an item is aimed at by identity, never by position", () => {
	it("derives the id from the canonical value and ignores the order of the list", () => {
		const cwd = checkout()
		orphanAllows(cwd, ["Edit(./src/cli/**)"])
		orphanRows(cwd, [
			{ category: "write_project", value: "./src/deep/x.ts" },
			{ category: "delete_recursive", value: "./build/" },
		])

		const first = buildAdoptChoices(plan(cwd), { cwd, ...SPACE })
		const again = buildAdoptChoices([...plan(cwd)].reverse(), { cwd, ...SPACE })

		expect(targets(first).sort()).toEqual(targets(again).sort())
		expect(first).toHaveLength(3)
		// Nothing about an id is positional.
		expect(first.every((c) => !/^\d+$/.test(c.id))).toBe(true)

		const row = rowsOf(first).find((c) => c.category === "write_project")!
		// The id is a lower-cased handle (a tmp dir name here mixes case, so the difference is visible);
		// the value stored keeps the spelling it had, which the test below pins separately.
		expect(row.id).toBe(`grant:write_project:entity:${cwd.toLowerCase()}/src/deep/x.ts`)
		// The id quotes the path that WILL be stored, not the one the moved checkout wrote.
		expect(row.id).toContain(`${cwd.toLowerCase()}/src/deep/x.ts`)
		expect(row.id).not.toContain("./src/deep")

		// A rule text is a specifier, not a path, so it is kept as written.
		expect(first.find((c) => c.kind === "rule")!.id).toBe("rule:edit(./src/cli/**)")
		// A scope keeps its trailing separator — that separator IS the grant.
		expect(rowsOf(first).find((c) => c.category === "delete_recursive")!.id).toBe(
			`grant:delete_recursive:scope:${cwd}/build/`.toLowerCase(),
		)
	})

	it("resolves an id against a re-rendered list to the same item", () => {
		const cwd = checkout()
		orphanRows(cwd, [
			{ category: "write_project", value: "./src/deep/x.ts" },
			{ category: "delete_recursive", value: "./build/" },
		])
		const id = `grant:write_project:entity:${cwd}/src/deep/x.ts`
		const wanted = `${cwd}/src/deep/x.ts`

		for (const pending of [plan(cwd), [...plan(cwd)].reverse(), plan(cwd).slice(0, 2).reverse()]) {
			const choices = buildAdoptChoices(pending, { cwd, ...SPACE })
			const { picked, refused } = resolveAdoptSelection({ choices, ids: [id], space: { ...SPACE, project: cwd } })
			expect(refused).toEqual([])
			expect(picked).toHaveLength(1)
			expect(onlyRow(picked).target).toBe(wanted)
		}

		// Retyped in the wrong case it still resolves, and what is stored is the item's own value.
		const shouted = resolveAdoptSelection({
			choices: buildAdoptChoices(plan(cwd), { cwd, ...SPACE }),
			ids: [id.toUpperCase()],
			space: { ...SPACE, project: cwd },
		})
		expect(shouted.refused).toEqual([])
		expect(onlyRow(shouted.picked).target).toBe(wanted)
	})

	it("answers a row number with the reason it cannot work, and writes nothing", () => {
		const cwd = checkout()
		orphanAllows(cwd, ["Edit(./src/cli/**)"])
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({ cwd, store, choices: one(cwd).choices, ids: ["0", "1"] })

		expect(out.picked).toEqual([])
		expect(out.refused).toHaveLength(2)
		expect(out.refused.every((r) => /row number/.test(r.reason))).toBe(true)
		expect(out.report).toEqual({ rules: [], grants: [], refused: [] })
		expect(store.grants).toEqual([])
		expect(allowList(cwd)).toEqual([])

		// The same face, aimed by id, does write — otherwise the assertions above prove nothing.
		const named = confirmAdoptChoices({
			cwd,
			store,
			choices: one(cwd).choices,
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`, "rule:edit(./src/cli/**)"],
		})
		expect(named.report.grants).toHaveLength(1)
		expect(allowList(cwd)).toEqual(["Edit(./src/cli/**)"])
	})

	it("refuses a blanket 'confirm everything' rather than granting the whole list", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({ cwd, store, pending: plan(cwd), ids: ["*", "all", "Everything"] })

		expect(out.picked).toEqual([])
		expect(out.refused.every((r) => /blanket confirm/.test(r.reason))).toBe(true)
		expect(store.grants).toEqual([])
	})

	it("refuses an id that matches more than one item instead of picking one", () => {
		const cwd = checkout()
		orphanRows(cwd, [
			{ category: "write_project", value: "./src/deep/x.ts" },
			{ category: "delete_recursive", value: "./src/deep/x.ts" },
		])
		const choices = buildAdoptChoices(plan(cwd), { cwd, ...SPACE })
		expect(choices).toHaveLength(2)
		const store = createGrantStore()

		// The bare value names two rows — one content, one destruction. Decline, and say why.
		const vague = confirmAdoptChoices({ cwd, store, choices, ids: ["./src/deep/x.ts"] })
		expect(vague.picked).toEqual([])
		expect(vague.refused[0]!.reason).toMatch(/matches 2 pending items/)
		expect(store.grants).toEqual([])

		// The full id names one.
		const exact = confirmAdoptChoices({ cwd, store, choices, ids: [choices[0]!.id] })
		expect(exact.report.grants.map((g) => g.category)).toEqual(["write_project"])
		expect(store.grants).toHaveLength(1)
	})

	it("folds two spellings of one target into one decision and one row", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }], "movedaway1")
		orphanRows(cwd, [{ category: "write_project", value: `${cwd}/src/deep/x.ts` }], "otheroldid1")

		const pending = plan(cwd)
		expect(pending).toHaveLength(2)
		const choices = buildAdoptChoices(pending, { cwd, ...SPACE })
		expect(choices).toHaveLength(1)
		expect(choices[0]!.origins).toEqual(["movedaway1/grants.json", "otheroldid1/grants.json"])
		expect(renderAdoptChoices(choices)[0]).toContain("2 spellings of one target")

		const store = createGrantStore()
		const out = confirmAdoptChoices({ cwd, store, choices, ids: [choices[0]!.id] })
		expect(store.grants).toHaveLength(1)
		expect(out.picked).toHaveLength(1)
	})

	it("prints the id beside the item it names, so what is copied is what is applied", () => {
		const cwd = checkout()
		orphanAllows(cwd, ["Edit(./src/cli/**)"])
		const lines = renderAdoptChoices(buildAdoptChoices(plan(cwd), { cwd, ...SPACE }))
		expect(lines).toHaveLength(1)
		expect(lines[0]).toContain("Edit(./src/cli/**)")
		expect(lines[0]).toContain("id=rule:edit(./src/cli/**)")
	})
})

describe("values reach the store canonicalised", () => {
	it("stores the absolute path for a row the orphan wrote project-relatively", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({ cwd, store, pending: plan(cwd), ids: ["grant:write_project:entity:" + `${cwd}/src/deep/x.ts`] })

		// The assertion is on the stored string, not on a call having happened.
		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.value).toBe(`${cwd}/src/deep/x.ts`)
		expect(out.report.grants[0]!.value).toBe(`${cwd}/src/deep/x.ts`)
	})

	it("resolves `~` against the caller's home, not the machine's", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "read_secret", value: "~/dotfiles/x.ts" }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({
			cwd,
			store,
			home: HOME,
			pending: plan(cwd),
			ids: ["grant:read_secret:entity:/home/tester/dotfiles/x.ts"],
		})

		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.value).toBe("/home/tester/dotfiles/x.ts")
		expect(out.refused).toEqual([])
	})

	it("resolves against the caller's project root, not `cwd` by default", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const store = createGrantStore()
		const root = "/moved/project"

		const choices = buildAdoptChoices(plan(cwd, root), { cwd, project: root, home: HOME })
		expect(onlyRow(choices).target).toBe(`${root}/src/deep/x.ts`)

		const out = confirmAdoptChoices({ cwd, store, project: root, home: HOME, choices, ids: [choices[0]!.id] })
		expect(store.grants[0]!.value).toBe(`${root}/src/deep/x.ts`)
		expect(onlyRow(out.picked).target).toBe(`${root}/src/deep/x.ts`)
	})

	it("leaves a value that is not inside the project alone rather than inventing a path", () => {
		const cwd = checkout()
		const hand = (value: string): Candidate => ({
			kind: "grant",
			category: "write_outside",
			value,
			target: value,
			scope: "entity",
			durable: false,
			origin: { id: "movedaway1", file: "grants.json" },
		})
		const choices = buildAdoptChoices([hand("../elsewhere/x.ts"), hand("s3://bucket/key")], { cwd, ...SPACE })

		expect(rowsOf(choices).map((c) => c.target)).toEqual(["../elsewhere/x.ts", "s3://bucket/key"])
		expect(adoptChoiceId(hand("../elsewhere/x.ts"), { project: cwd, home: HOME })).toBe(
			"grant:write_outside:entity:../elsewhere/x.ts",
		)

		const store = createGrantStore()
		confirmAdoptChoices({ cwd, store, choices, ids: ["grant:write_outside:entity:../elsewhere/x.ts"] })
		expect(store.grants.map((r) => r.value)).toEqual(["../elsewhere/x.ts"])
	})
})

describe("durable: false means this session only", () => {
	it("grants the row in memory and changes no byte of the journal", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const journal = seedLiveJournal(cwd)
		const before = readFileSync(journal, "utf-8")
		expect(journalRows(cwd)).toEqual([])

		const store = createGrantStore()
		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal,
			durable: false,
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.durable).toBeUndefined()
		expect(readFileSync(journal, "utf-8")).toBe(before)
		expect(journalRows(cwd)).toEqual([])
		expect(out.report.journal).toBeUndefined()
		expect(out.journalSkipped).toMatch(/this session only/)
	})

	it("creates no journal at all when a session-only choice is confirmed into an empty checkout", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const store = createGrantStore()

		confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal: liveJournal(cwd),
			durable: false,
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(existsSync(liveJournal(cwd))).toBe(false)
		expect(store.grants).toHaveLength(1)
	})

	it("and, when durability was asked for, the row does land in the journal", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		seedLiveJournal(cwd)
		const store = createGrantStore()

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal: liveJournal(cwd),
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(out.report.journal).toMatchObject({ ok: true, added: 1 })
		expect(journalRows(cwd)?.map((r) => r.value)).toEqual([`${cwd}/src/deep/x.ts`])
		expect(out.journalSkipped).toBeUndefined()
		expect(out.journalCarried).toBeUndefined()
	})
})

describe("a journal write reports what it carried", () => {
	it("says so when the merge persisted rows this confirmation never chose", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const store = createGrantStore()
		// Something the gate earned for this session only, sitting in the same store.
		addGrant(store, "write_outside", "/home/u/scratch/notes.md", "entity", false)

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal: liveJournal(cwd),
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		// `confirmAdoption()` mirrors the whole store, so the session-only row is durable now. That is
		// the mirror's behaviour, not this module's choice — but a caller that printed only "saved" would be
		// hiding it, so the result says it out loud.
		expect(out.picked).toHaveLength(1)
		expect(out.report.journal).toMatchObject({ ok: true, added: 2 })
		expect(out.journalCarried).toMatch(/session-only/)
		expect(journalRows(cwd)?.map((r) => r.value).sort()).toEqual(
			["/home/u/scratch/notes.md", `${cwd}/src/deep/x.ts`].sort(),
		)
	})
})

describe("no explicit list, no write", () => {
	for (const [name, ids] of [
		["ids omitted", undefined],
		["ids null", null],
		["ids empty", []],
		["ids blank", ["   ", ""]],
	] as const) {
		it(`${name} confirms nothing and creates no file`, () => {
			const cwd = checkout()
			orphanAllows(cwd, ["Edit(./src/cli/**)"])
			orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
			const store = createGrantStore()

			const out = confirmAdoptChoices({
				cwd,
				store,
				pending: plan(cwd),
				journal: liveJournal(cwd),
				...(ids === undefined ? {} : { ids }),
			})

			expect(out.picked).toEqual([])
			expect(out.refused[0]!.reason).toMatch(/never confirmed by default/)
			expect(out.report).toEqual({ rules: [], grants: [], refused: [] })
			expect(store.grants).toEqual([])
			expect(existsSync(liveFile(cwd))).toBe(false)
			expect(existsSync(liveJournal(cwd))).toBe(false)
		})
	}

	it("and the same fixture does write once an id is named, so the test above is not vacuous", () => {
		const cwd = checkout()
		orphanAllows(cwd, ["Edit(./src/cli/**)"])
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal: liveJournal(cwd),
			ids: ["rule:edit(./src/cli/**)", `grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(out.report.rules).toEqual(["Edit(./src/cli/**)"])
		expect(allowList(cwd)).toEqual(["Edit(./src/cli/**)"])
		expect(journalRows(cwd)?.map((r) => r.value)).toEqual([`${cwd}/src/deep/x.ts`])
	})
})

describe("refusals come back with their reasons", () => {
	it("will not confirm a Bash allow broad enough to bypass the classifier, and says so", () => {
		const cwd = checkout()
		const smuggled: Candidate = {
			kind: "rule",
			rule: "Bash(git *)",
			behavior: "allow",
			tool: "Bash",
			specifier: "git *",
			origin: { id: "movedaway1", file: "permissions.json" },
			into: "project",
		}
		const store = createGrantStore()

		const out = confirmAdoptChoices({ cwd, store, choices: buildAdoptChoices([smuggled], { cwd, ...SPACE }), ids: ["rule:bash(git *)"] })

		expect(out.report.rules).toEqual([])
		expect(out.refused[0]!.reason).toMatch(/bypasses the classifier/)
		expect(allowList(cwd)).toEqual([])
	})

	it("passes a refusal from confirmAdoption through to the caller", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const store = createGrantStore()
		addGrant(store, "write_project", `${cwd}/src/deep/x.ts`, "entity")

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(out.report.grants).toEqual([])
		expect(out.report.refused[0]!.reason).toMatch(/already holds a row/)
		expect(out.refused).toEqual(out.report.refused)
		expect(out.picked).toHaveLength(1)
		expect(store.grants).toHaveLength(1)
	})

	it("reports an unknown id without touching anything", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const store = createGrantStore()

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			ids: ["grant:write_project:entity:/somewhere/else.ts", "rule:edit(./src/cli/**)"],
		})

		expect(out.refused).toHaveLength(2)
		expect(out.refused.every((r) => /no pending item matches/.test(r.reason))).toBe(true)
		expect(store.grants).toEqual([])
		expect(existsSync(liveFile(cwd))).toBe(false)
	})
})

describe("confirming twice changes nothing", () => {
	it("stores one row when the same id is named twice, in one call or in two", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts" }])
		const choices = buildAdoptChoices(plan(cwd), { cwd, ...SPACE })
		const id = choices[0]!.id
		const store = createGrantStore()

		const twice = confirmAdoptChoices({ cwd, store, choices, ids: [id, id] })
		expect(twice.picked).toHaveLength(1)
		expect(store.grants).toHaveLength(1)

		const again = confirmAdoptChoices({ cwd, store, choices, ids: [id] })
		expect(again.report.grants).toEqual([])
		expect(again.refused[0]!.reason).toMatch(/already holds/)
		expect(store.grants).toHaveLength(1)
		expect(store.grants[0]!.value).toBe(`${cwd}/src/deep/x.ts`)
	})

	it("writes one allow entry however many times the rule id is confirmed", () => {
		const cwd = checkout()
		orphanAllows(cwd, ["Edit(./src/cli/**)"])
		const choices = buildAdoptChoices(plan(cwd), { cwd, ...SPACE })

		confirmAdoptChoices({ cwd, store: createGrantStore(), choices, ids: ["rule:edit(./src/cli/**)"] })
		confirmAdoptChoices({ cwd, store: createGrantStore(), choices, ids: ["rule:edit(./src/cli/**)"] })

		expect(allowList(cwd)).toEqual(["Edit(./src/cli/**)"])
	})

	it("will not walk back a target this session revoked, and writes no journal for it", () => {
		const cwd = checkout()
		orphanRows(cwd, [{ category: "write_project", value: "./src/deep/x.ts", durable: true }])
		const store = createGrantStore()
		addGrant(store, "write_project", `${cwd}/src/deep/x.ts`, "entity", true)
		expect(revokeRows(store, (row) => row.value === `${cwd}/src/deep/x.ts`, { quote: "/grants revoke" })).toHaveLength(1)

		const out = confirmAdoptChoices({
			cwd,
			store,
			pending: plan(cwd),
			journal: liveJournal(cwd),
			ids: [`grant:write_project:entity:${cwd}/src/deep/x.ts`],
		})

		expect(out.report.grants).toEqual([])
		expect(out.refused[0]!.reason).toMatch(/adoption is not a re-grant/)
		expect(store.grants).toEqual([])
		expect(existsSync(liveJournal(cwd))).toBe(false)
	})
})
