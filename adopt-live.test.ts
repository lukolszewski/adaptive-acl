/**
 * An adopted rule becomes live in the session that adopted it.
 *
 * This is the pairing D12 left open, and the test that replaces the pinned one in `index.test.ts`
 * ("… effective next session" + "the gate still blocks the adopted call"). The two move together: whoever
 * wires `makeAdoptedRulesLive()` into `/grants adopt confirm` must change that message and that assertion in
 * the same commit, because the assertion is the only thing keeping the message honest.
 *
 * The flow is the real one — `adoptOrphans` (quiet tightening) → `buildAdoptChoices` → `confirmAdoptChoices`
 * by the id that was printed → `makeAdoptedRulesLive` — and the verdicts are read at
 * `evaluateToolPermission`, the same call `index.ts` makes with the policy snapshot, so "live now" here means
 * the matcher would actually let the call through. Nothing is asserted on the module's own report alone.
 *
 * Fixtures are tmp checkouts with a carried project id, so the orphan is a second id in the same
 * `.pi/projects/` and no real project's state is read or written.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { adoptOrphans } from "./grants-adopt.ts"
import { buildAdoptChoices, confirmAdoptChoices } from "./adopt-confirm.ts"
import { makeAdoptedRulesLive } from "./adopt-live.ts"
import { setConfigPath } from "./config.ts"
import {
	addPermissionRule,
	loadMergedPermissionRules,
	writeProjectPermissionsFile,
} from "./permissions-loader.ts"
import { evaluateToolPermission, type PermissionRule } from "./permissions.ts"
import { policyCarries, ruleLabel } from "./reload-policy.ts"
import { createGrantStore, type GrantStore } from "./session-grants.ts"
import { writeProjectIdMarker } from "./utils.ts"

const LIVE_ID = "livesession1"
const ORPHAN_ID = "movedaway1"

let cwd = ""
const roots: string[] = []

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "pm-adoptlive-"))
	roots.push(cwd)
	expect(writeProjectIdMarker(cwd, LIVE_ID)).toBe(true)
	// The global rules source is a path inside the fixture: without this the reload would read the
	// developer's own ~/.pi/agent/permission-modes.json and the assertions would be about the machine.
	setConfigPath(join(cwd, "permission-modes.json"))
})

afterEach(() => {
	for (const dir of roots) rmSync(dir, { recursive: true, force: true })
	roots.length = 0
})

/** An orphan left by a moved checkout: one wall to take quietly, one allowance to hold for a human. */
function plantOrphan(): void {
	const dir = join(cwd, ".pi", "projects", ORPHAN_ID)
	mkdirSync(dir, { recursive: true })
	writeFileSync(
		join(dir, "permissions.local.json"),
		JSON.stringify({ deny: ["Bash(rm *)"], allow: ["Bash(npm publish)"] }) + "\n",
	)
}

function bash(rules: PermissionRule[], command: string): string {
	return evaluateToolPermission("bash", { command }, cwd, rules).behavior
}

/** The printed id of the one widening item the scan found. */
function onlyId(choices: { id: string }[]): string {
	expect(choices).toHaveLength(1)
	return choices[0]!.id
}

describe("an adopted rule is live in the session that adopted it", () => {
	it("re-reads the policy so the confirmed rule covers the next call", () => {
		plantOrphan()
		const store: GrantStore = createGrantStore()

		const adopted = adoptOrphans({ cwd })
		// The snapshot the session is running on: the orphan's allow is nowhere in it, and the write to the
		// rules file alone does not change that. This is the state D12 described.
		const before = loadMergedPermissionRules(cwd)
		expect(policyCarries(before, "Bash(npm publish)")).toBeUndefined()

		const choices = buildAdoptChoices(adopted.pending, { cwd })
		const confirmed = confirmAdoptChoices({
			cwd,
			store,
			ids: [onlyId(choices)],
			pending: adopted.pending,
		})
		expect(confirmed.report.rules).toEqual(["Bash(npm publish)"])

		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })

		expect(policyCarries(result.rules, "Bash(npm publish)")).toBeDefined()
		expect(bash(result.rules, "npm publish")).toBe("allow")
		expect(result.effects[0]).toMatchObject({ rule: "Bash(npm publish)", live: true })
		expect(result.effects[0]!.detail).toMatch(/live now/i)
		expect(result.effects[0]!.detail).not.toMatch(/next session/i)
	})

	it("leaves the call blocked when nothing re-reads the policy — the half of D12 that stays true", () => {
		// The counterpart assertion, kept in the same file as the one above so the pair cannot drift: writing
		// the rule is not what makes it live. If someone installs the reload at a different place and this
		// starts passing, the pairing below is no longer doing anything and the command's wording lies.
		plantOrphan()
		const adopted = adoptOrphans({ cwd })
		const before = loadMergedPermissionRules(cwd)
		const choices = buildAdoptChoices(adopted.pending, { cwd })
		confirmAdoptChoices({ cwd, store: createGrantStore(), ids: [onlyId(choices)], pending: adopted.pending })
		expect(bash(before, "npm publish")).toBe("passthrough")
	})

	it("mints no session grant — the pairing is the file, re-read", () => {
		plantOrphan()
		const store = createGrantStore()
		const adopted = adoptOrphans({ cwd })
		const before = loadMergedPermissionRules(cwd)
		const choices = buildAdoptChoices(adopted.pending, { cwd })
		const confirmed = confirmAdoptChoices({
			cwd,
			store,
			ids: [onlyId(choices)],
			pending: adopted.pending,
		})
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })
		// A `Bash(npm publish)` rule has no entity to grant, so any row minted here would be wildcard- or
		// category-shaped — wider than what the human confirmed. Nothing in this path touches the store.
		expect(store.grants).toHaveLength(0)
		expect(result.reload?.added).toContain("allow Bash(npm publish)")
	})

	it("keeps the wall that came with the orphan ahead of the allow it also brought", () => {
		plantOrphan()
		const adopted = adoptOrphans({ cwd })
		const before = loadMergedPermissionRules(cwd)
		const choices = buildAdoptChoices(adopted.pending, { cwd })
		const confirmed = confirmAdoptChoices({
			cwd,
			store: createGrantStore(),
			ids: [onlyId(choices)],
			pending: adopted.pending,
		})
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })
		// The quiet tightening is live too — a lost deny restored is the reason the feature exists, and it
		// should not have to wait for a restart. And it outranks the newly adopted allow.
		expect(policyCarries(result.rules, "Bash(rm *)", "deny")).toBeDefined()
		expect(bash(result.rules, "rm -rf ./build")).toBe("deny")
		expect(bash(result.rules, "npm publish")).toBe("allow")
	})

	it("is not adopt-specific: any rule written to the files mid-session becomes live through it", () => {
		// The same face serves the ordinary "allow always" path, which today reloads by a private call in
		// index.ts. Nothing here knows or cares which UI wrote the file.
		addPermissionRule({ rule: "Bash(npm test)", behavior: "allow", destination: "project", cwd })
		const result = makeAdoptedRulesLive({ cwd, written: ["Bash(npm test)"], live: [] })
		expect(result.effects[0]!.live).toBe(true)
		expect(bash(result.rules, "npm test")).toBe("allow")
	})

	it("says which rules came in that this confirmation did not name", () => {
		// The files are the source of truth, so an edit made during the session arrives with the adopt. The
		// caller gets the list rather than a message that implies the session only gained what it confirmed.
		plantOrphan()
		const adopted = adoptOrphans({ cwd })
		const before = loadMergedPermissionRules(cwd)
		writeProjectPermissionsFile(cwd, { allow: ["Bash(npm audit)"] })
		const choices = buildAdoptChoices(adopted.pending, { cwd })
		const confirmed = confirmAdoptChoices({
			cwd,
			store: createGrantStore(),
			ids: [onlyId(choices)],
			pending: adopted.pending,
		})
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })
		expect(result.effects.map((e) => e.rule)).toEqual(["Bash(npm publish)"])
		expect(result.unrequested).toContain("allow Bash(npm audit)")
	})

	it("reports one effect per rule the confirmation named, in the order it named them", () => {
		addPermissionRule({ rule: "Bash(npm publish)", behavior: "allow", destination: "project", cwd })
		addPermissionRule({ rule: "Bash(npm test)", behavior: "allow", destination: "project", cwd })
		const result = makeAdoptedRulesLive({
			cwd,
			written: ["Bash(npm publish)", "Bash(npm test)"],
			live: [],
		})
		expect(result.effects.map((e) => [e.rule, e.live])).toEqual([
			["Bash(npm publish)", true],
			["Bash(npm test)", true],
		])
	})
})

describe("nothing is made live for an item nobody confirmed", () => {
	it("changes no policy when the confirmation named no id", () => {
		plantOrphansAndAdopt()
		const before = loadMergedPermissionRules(cwd)
		const confirmed = confirmAdoptChoices({
			cwd,
			store: createGrantStore(),
			ids: [],
			pending: adoptOrphans({ cwd }).pending,
		})
		expect(confirmed.report.rules).toEqual([])
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })
		expect(result.reload).toBeUndefined()
		expect(result.rules.map(ruleLabel)).toEqual(before.map(ruleLabel))
		expect(result.effects).toEqual([])
		expect(bash(result.rules, "npm publish")).not.toBe("allow")
		expect(result.summary).toMatch(/nothing was written/i)
	})

	it("changes no policy when the id given was a row number", () => {
		plantOrphansAndAdopt()
		const before = loadMergedPermissionRules(cwd)
		const pending = adoptOrphans({ cwd }).pending
		const confirmed = confirmAdoptChoices({ cwd, store: createGrantStore(), ids: ["1"], pending })
		expect(confirmed.report.rules).toEqual([])
		expect(confirmed.refused.map((r) => r.reason).join(" ")).toMatch(/row number/i)
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })
		expect(policyCarries(result.rules, "Bash(npm publish)")).toBeUndefined()
	})

	it("does not widen the snapshot for a rule text the caller invented", () => {
		// A caller that hands over a rule nobody wrote gets an honest "not live", not a policy that contains
		// the string it was passed.
		const result = makeAdoptedRulesLive({ cwd, written: ["Bash(curl *)"], live: [] })
		expect(result.effects[0]!.live).toBe(false)
		expect(result.rules).toHaveLength(0)
		expect(result.effects[0]!.detail).toMatch(/effective next session/i)
		expect(result.effects[0]!.detail).toMatch(/did not find it/i)
	})
})

describe("a rules file it cannot re-read leaves the policy alone", () => {
	it("keeps D12's honest wording and the wall the session was already running behind", () => {
		plantOrphansAndAdopt()
		const before = loadMergedPermissionRules(cwd)
		const pending = adoptOrphans({ cwd }).pending
		const choices = buildAdoptChoices(pending, { cwd })
		const confirmed = confirmAdoptChoices({ cwd, store: createGrantStore(), ids: [onlyId(choices)], pending })
		expect(bash(before, "rm -rf ./build")).toBe("deny")

		// The file the confirmation just wrote is now unreadable — the half-written save, not the clean one.
		const local = join(cwd, ".pi", "projects", LIVE_ID, "permissions.local.json")
		writeFileSync(local, '{ "permissions": { "allow": [ ')
		const result = makeAdoptedRulesLive({ cwd, written: confirmed.report.rules, live: before })

		expect(result.effects[0]!.live).toBe(false)
		expect(result.effects[0]!.detail).toMatch(/effective next session/i)
		expect(result.effects[0]!.detail).toMatch(/could not be re-read/i)
		expect(bash(result.rules, "npm publish")).not.toBe("allow")
		// The deny that was live a moment ago is still live: a broken file empties nothing.
		expect(bash(result.rules, "rm -rf ./build")).toBe("deny")
	})
})

/** Plant an orphan and take its tightening, so a test starts exactly where a real `/grants adopt` leaves off. */
function plantOrphansAndAdopt(): void {
	plantOrphan()
	adoptOrphans({ cwd })
}
