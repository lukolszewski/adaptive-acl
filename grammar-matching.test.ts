/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The three match sites that decide whether an existing approval covers a publish target
 * (`grantsCover`, `verifyGrant`, `rowCoversTargets`) consult the category's grammar first —
 * docs/CLASSIFIER-SPEC.md §3, "publish targets are matched by grammar, not by string".
 *
 * What these pins are worth: every one of them is the gate's OWN spelling. For
 * `git push origin feature/ABC123` layer 0 emits target `origin/feature/ABC123` and scope
 * `origin/*` (risk-handlers.ts:618), and "Allow for session (scope origin/*)" stores exactly
 * that scope string — so before the grammar the button the user pressed covered nothing, and
 * the denial told them to grant something that could never work. The container case is the
 * same defect one category over: a row can now say "any tag of myrepo/app".
 *
 * Pinned in the other direction too: an all-branches row is not a `main` row, so
 * `origin/*` must NOT cover `origin/main`, and the compound categories still need one row per
 * effect (every-segment rule unchanged).
 */
import { describe, expect, it } from "vitest"

import { rowCoversTargets } from "./durable-approval.ts"
import { verifyGrant, type GrantExtraction } from "./grant-verify.ts"
import {
	addGrant,
	createGrantStore,
	explainGrantsCover,
	grantsCover,
	type GrantStore,
	type SessionGrant,
} from "./session-grants.ts"

const extraction = (over: Partial<GrantExtraction>): GrantExtraction => ({
	authorized: "yes",
	allowed_targets: [],
	forbidden_targets: [],
	quote: "",
	...over,
})

/** The quote always has to be the user's own words, verbatim, so each case passes its own sentence. */
function grant(opts: {
	category: string
	entity: string
	allowed?: string[]
	forbidden?: string[]
	quote: string
}) {
	return verifyGrant({
		extraction: extraction({ allowed_targets: opts.allowed ?? [], forbidden_targets: opts.forbidden ?? [], quote: opts.quote }),
		category: opts.category,
		entities: [T(opts.entity)],
		userMessages: [opts.quote],
	})
}

const T = (value: string) => ({ kind: "target" as const, value })

function storeWith(...rows: Array<[string, string, "entity" | "scope"]>): GrantStore {
	const store = createGrantStore()
	for (const [category, value, kind] of rows) addGrant(store, category, value, kind)
	return store
}

const covered = (store: GrantStore, category: string, target: string) =>
	grantsCover(store, category, [T(target)]).covered

describe("grantsCover matches publish targets by grammar", () => {
	it("the gate's own scope value `origin/*` covers the branch it was offered for", () => {
		// The regression this whole task exists for: the scope row is written by index.ts straight
		// from the gate's scope entity, and the string matcher saw `*` as a component to equal.
		expect(covered(storeWith(["vcs_remote", "origin/*", "scope"]), "vcs_remote", "origin/feature/ABC123")).toBe(true)
	})

	it("an entity row naming the branch by its last component covers the full ref", () => {
		expect(covered(storeWith(["vcs_remote", "feature/ABC123", "entity"]), "vcs_remote", "origin/feature/ABC123")).toBe(true)
	})

	it("all-branches on a remote is not all-branches including the protected ones", () => {
		const store = storeWith(["vcs_remote", "origin/*", "scope"])
		expect(covered(store, "vcs_remote", "origin/main")).toBe(false)
		expect(covered(store, "vcs_remote", "origin/release/2.1")).toBe(false)
		// …and a row that names the protected branch itself still says yes to it.
		expect(covered(storeWith(["vcs_remote", "origin/main", "entity"]), "vcs_remote", "origin/main")).toBe(true)
	})

	it("a branch row never reaches a different branch on the same remote", () => {
		const store = storeWith(["vcs_remote", "origin/feature/x", "entity"])
		expect(covered(store, "vcs_remote", "origin/feature/x-prod")).toBe(false)
		expect(covered(store, "vcs_remote", "origin/other")).toBe(false)
		expect(covered(store, "vcs_remote", "upstream/feature/x")).toBe(false)
	})

	it("a publish under a compound category still needs a row for every effect", () => {
		// Unchanged every-segment rule, now running over grammar matches: `vcs_local` has no grammar,
		// so its half falls through to the string rule while `vcs_remote`'s half is read as a ref.
		const onlyRemote = storeWith(["vcs_remote", "origin/*", "scope"])
		expect(covered(onlyRemote, "vcs_local+vcs_remote", "origin/feature/ABC123")).toBe(false)
		const both = storeWith(["vcs_local", "origin/feature/ABC123", "entity"], ["vcs_remote", "origin/*", "scope"])
		expect(covered(both, "vcs_local+vcs_remote", "origin/feature/ABC123")).toBe(true)
	})

	it("a repository row covers any tag of that repository, under both halves of the publish compound", () => {
		const rows: Array<[string, string, "entity" | "scope"]> = [
			["container_mutation", "myrepo/app", "scope"],
			["network_send", "myrepo/app", "scope"],
		]
		expect(covered(storeWith(...rows), "container_mutation+network_send", "myrepo/app:1.0")).toBe(true)
		// A different repository in the same registry is a different authority.
		const other = storeWith(["container_mutation", "myrepo/other", "scope"], ["network_send", "myrepo/other", "scope"])
		expect(covered(other, "container_mutation+network_send", "myrepo/app:1.0")).toBe(false)
		// A tagged row is that tag only.
		const tagged = storeWith(["container_mutation", "myrepo/app:1.0", "entity"], ["network_send", "myrepo/app:1.0", "entity"])
		expect(covered(tagged, "container_mutation+network_send", "myrepo/app:2.0")).toBe(false)
	})

	it("categories without a grammar keep the path rule exactly as it was", () => {
		const store = storeWith(["write_outside", "/tmp/out/", "scope"])
		expect(covered(store, "write_outside", "/tmp/out/a.txt")).toBe(true)
		expect(covered(store, "write_outside", "/tmp/other/a.txt")).toBe(false)
	})
})

describe("verifyGrant matches the model's targets by grammar", () => {
	it("an all-branches target covers the branch the user was asked about", () => {
		const v = grant({
			category: "vcs_remote",
			entity: "origin/feature/ABC123",
			allowed: ["origin/*"],
			quote: "push any branch to origin",
		})
		expect(v.granted).toBe(true)
		expect(v.matches).toEqual([{ entity: "origin/feature/ABC123", target: "origin/*" }])
	})

	it("all-branches still is not a licence for a protected branch", () => {
		const v = grant({
			category: "vcs_remote",
			entity: "origin/main",
			allowed: ["origin/*"],
			quote: "push any branch to origin",
		})
		expect(v.granted).toBe(false)
		expect(v.reason).toContain("not named by the user")
	})

	it("a near-name is refused even though the component rule used to accept the run", () => {
		// `feature/x` vs `origin/feature/x-prod`: the whole-token rule already refused this. Pinned again
		// here because the grammar answers `false` and the string rule is then NOT consulted — an authority
		// has to be named, not resembled.
		expect(
			grant({
				category: "vcs_remote",
				entity: "origin/feature/x-prod",
				allowed: ["feature/x"],
				quote: "push feature/x",
			}),
		).toMatchObject({ granted: false })
		expect(
			grant({
				category: "vcs_remote",
				entity: "origin/feature/x",
				allowed: ["origin/feature"],
				quote: "push it",
			}),
		).toMatchObject({ granted: false })
	})

	it("a repository target covers the tag being pushed, under both effects of the publish compound", () => {
		const v = grant({
			category: "container_mutation+network_send",
			entity: "myrepo/app:1.0",
			allowed: ["myrepo/app"],
			quote: "push myrepo/app to the registry",
		})
		expect(v.granted).toBe(true)
		expect(v.matches.map((m) => m.target)).toEqual(["myrepo/app"])
	})

	it("a forbidden target vetoes, named exactly or by its scope", () => {
		expect(
			grant({
				category: "vcs_remote",
				entity: "origin/main",
				allowed: ["origin/*"],
				forbidden: ["origin/main"],
				quote: "push the feature branches but never origin/main",
			}),
		).toMatchObject({ granted: false, reason: expect.stringContaining("user-forbidden") })
		expect(
			grant({
				category: "vcs_remote",
				entity: "origin/feature/x",
				allowed: ["origin/feature/x"],
				forbidden: ["origin/*"],
				quote: "origin is closed for pushes",
			}),
		).toMatchObject({ granted: false, reason: expect.stringContaining("user-forbidden") })
	})

	it("a forbid is never narrowed by the grammar's authority limit", () => {
		// The wildcard reading of `origin/*` means "every branch except protected" when it is granting
		// permission. As a veto it has to keep meaning every branch, or typing the grammar would quietly
		// weaken "never push anything to origin" for exactly the branches worth protecting.
		for (const forbidden of ["origin/*", "origin", "*"]) {
			for (const entity of ["origin/main", "origin/release/2.1", "origin/feature/x"]) {
				const label = `forbidden "${forbidden}" vs "${entity}"`
				expect(grant({ category: "vcs_remote", entity, allowed: [entity], forbidden: [forbidden], quote: `never push to ${forbidden}` }).granted, label).toBe(false)
			}
		}
		// …and a forbid that names one branch still names only that branch.
		expect(
			grant({
				category: "vcs_remote",
				entity: "origin/feature/x",
				allowed: ["origin/feature/x"],
				forbidden: ["origin/dev"],
				quote: "push feature/x, leave dev alone",
			}).granted,
		).toBe(true)
	})
})

describe("rowCoversTargets revokes the publish rows that really covered the target", () => {
	const row = (category: string, value: string, kind: "entity" | "scope"): SessionGrant => ({
		category,
		value,
		kind,
		at: 1,
	})

	it("deny-always on one push revokes the scope row and that branch's row, and leaves other branches alone", () => {
		// The bug this pins: "Deny always" on a push found no row to revoke, so the allowance the user had
		// just refused went on covering every later push.
		const denies = rowCoversTargets(["origin/feature/x"])
		expect(denies(row("vcs_remote", "origin/*", "scope"))).toBe(true)
		expect(denies(row("vcs_remote", "origin/feature/x", "entity"))).toBe(true)
		expect(denies(row("vcs_remote", "feature/x", "entity"))).toBe(true)
		expect(denies(row("vcs_remote", "origin/other", "entity"))).toBe(false)
		expect(denies(row("vcs_remote", "upstream/feature/x", "entity"))).toBe(false)
		// A protected branch is outside an all-branches row's authority, so denying a protected push does
		// not revoke it — the row never covered it in the first place, and denying must not delete rows that
		// were never the reason.
		expect(rowCoversTargets(["origin/main"])(row("vcs_remote", "origin/*", "scope"))).toBe(false)
		expect(rowCoversTargets(["origin/main"])(row("vcs_remote", "origin/main", "entity"))).toBe(true)
	})

	it("deny-always on one tag revokes the repository row, since that row was the allowance for any tag", () => {
		const denies = rowCoversTargets(["myrepo/app:1.0"])
		expect(denies(row("container_mutation", "myrepo/app", "scope"))).toBe(true)
		expect(denies(row("network_send", "myrepo/app:1.0", "entity"))).toBe(true)
		expect(denies(row("network_send", "myrepo/app:2.0", "entity"))).toBe(false)
		expect(denies(row("network_send", "other/app", "entity"))).toBe(false)
	})

	it("a compound row is read by whichever of its effects has a grammar", () => {
		// `container_mutation+network_send` is stored verbatim by durableRowsForApproval (it does not split
		// segments the way addGrant does), so the compound itself has to reach the image grammar.
		expect(rowCoversTargets(["myrepo/app:1.0"])(row("container_mutation+network_send", "myrepo/app", "entity"))).toBe(true)
		// One effect that covers is enough to revoke: a deny has to stick, and the cost of dropping one row
		// that was not strictly needed is a prompt, where the cost of leaving it is another push the user
		// already refused. `vcs_local` has no grammar, so it can only ever add a yes, never take one away.
		expect(rowCoversTargets(["origin/feature/x"])(row("vcs_local+vcs_remote", "origin/*", "scope"))).toBe(true)
		// And where the grammar's own half says no, no amount of prefix arithmetic revokes it: the row never
		// covered this target, and deleting an unrelated allowance is not what "deny this one" means.
		expect(rowCoversTargets(["origin/main"])(row("vcs_local+vcs_remote", "origin/*", "scope"))).toBe(false)
	})

	it("path rows are untouched", () => {
		const denies = rowCoversTargets(["/tmp/dir/x"], { home: "/home/dev" })
		expect(denies(row("write_outside", "/tmp/dir/", "scope"))).toBe(true)
		expect(denies(row("write_outside", "~/.ssh/id_rsa", "entity"))).toBe(false)
		expect(rowCoversTargets(["/home/dev/.ssh/id_rsa"], { home: "/home/dev" })(row("read_secret", "~/.ssh/id_rsa", "entity"))).toBe(true)
		expect(rowCoversTargets(["/tmp/dir/x"])(row("vcs_remote", "myrepo/app", "entity"))).toBe(false)
	})
})

describe("explainGrantsCover says what the store did with each row", () => {
	it("names the row that covered the target and the row that did not, one line per row", () => {
		const store = storeWith(
			["vcs_remote", "origin/*", "scope"],
			["vcs_remote", "origin/dev", "entity"],
		)
		expect(explainGrantsCover(store, "vcs_remote", [T("origin/feature/ABC123")])).toEqual([
			`row vcs_remote "origin/*" (scope): covers origin/feature/ABC123`,
			`rejected: vcs_remote "origin/dev" (entity) — covers none of: origin/feature/ABC123`,
		])
	})

	it("reports the effect a compound has no rows for, which is the reason a publish still prompts", () => {
		const store = storeWith(["container_mutation", "myrepo/app", "scope"])
		expect(explainGrantsCover(store, "container_mutation+network_send", [T("myrepo/app:1.0")])).toEqual([
			`row container_mutation "myrepo/app" (scope): covers myrepo/app:1.0`,
			`segment network_send has no rows`,
		])
	})

	it("says so when there is nothing to match, instead of returning a silent empty list", () => {
		expect(explainGrantsCover(createGrantStore(), "write_outside", [])).toEqual([
			`nothing to match: the action names no target`,
		])
		expect(explainGrantsCover(storeWith(["write_outside", "/tmp/out/", "scope"]), "", [T("/tmp/out/a")])).toEqual([
			`no category to explain`,
		])
	})

	it("reads the store without changing it", () => {
		const store = storeWith(["vcs_remote", "origin/*", "scope"])
		const before = JSON.stringify(store)
		explainGrantsCover(store, "vcs_remote", [T("origin/feature/x")], "/home/dev", "/home/dev/proj")
		expect(JSON.stringify(store)).toBe(before)
	})
})
