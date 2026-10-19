/**
 * `/grants adopt` — the behaviour the supervisor's command is built on.
 *
 * The one thing worth reading closely here is the split: a deny that a moved directory left behind is
 * taken quietly (it can only make the wall stricter, and a deny that vanishes without a sound is the
 * worst failure this codebase has), while an allow is always returned for a human to confirm, because
 * authority comes from an explicit human act and a file cannot supply one. Most of these tests are that
 * split, checked at the file it would be written to rather than in a return value — the failure we are
 * protecting against is a write nobody noticed, not a wrong object.
 *
 * Everything runs in a tmp tree with a `.pi/project.json` marker, so the live project id is a known
 * constant and the orphan is a second id in the same `.pi/projects/`. Nothing here touches a real
 * project's state.
 */

import { afterEach, describe, expect, it } from "vitest"
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildGrantsFile, writeGrantsFile } from "./grants-file.ts"
import { adoptOrphans, confirmAdoption, planAdoption } from "./grants-adopt.ts"
import { addGrant, createGrantStore, revokeRows } from "./session-grants.ts"
import { writeProjectIdMarker } from "./utils.ts"

const LIVE = "livesession1"
const ORPHAN = "movedaway1"

const roots: string[] = []

/** A checkout with a carried project id, so `getProjectId()` cannot depend on the path. */
function checkout(): string {
	const dir = mkdtempSync(join(tmpdir(), "pm-adopt-"))
	roots.push(dir)
	expect(writeProjectIdMarker(dir, LIVE)).toBe(true)
	return dir
}

function stateDir(cwd: string, id: string): string {
	const dir = join(cwd, ".pi", "projects", id)
	mkdirSync(dir, { recursive: true })
	return dir
}

function writeJson(file: string, body: unknown): string {
	writeFileSync(file, JSON.stringify(body, null, 2) + "\n")
	return file
}

/** Put a rules document into one of the two orphan files. */
function orphanRules(
	cwd: string,
	body: Record<string, unknown>,
	file = "permissions.json",
	id = ORPHAN,
): string {
	return writeJson(join(stateDir(cwd, id), file), { permissions: body })
}

/** Put a journal into an orphan's directory, built by the real writer so the shape is honest. */
function orphanJournal(
	cwd: string,
	rows: { category: string; value: string; kind: "entity" | "scope"; at?: number; durable?: boolean }[],
	id = ORPHAN,
): string {
	const { file } = buildGrantsFile({
		ledger: { v: 1, grants: [], forbids: [], seen: [] },
		grants: rows.map((r) => ({ at: Date.now(), ...r })),
		sourceCwd: `/old/place/${id}`,
	})
	return writeGrantsFile(join(stateDir(cwd, id), "grants.json"), file) ? join(stateDir(cwd, id), "grants.json") : ""
}

function liveFile(cwd: string, local = false): string {
	// No mkdir: a read helper that creates the directory it is checking would make "nothing was
	// written" untestable.
	return join(cwd, ".pi", "projects", LIVE, local ? "permissions.local.json" : "permissions.json")
}

/** Write the live project's rules file, creating its directory the way the plugin would. */
function writeLive(cwd: string, perms: Record<string, unknown>, local = false): string {
	mkdirSync(join(cwd, ".pi", "projects", LIVE), { recursive: true })
	return writeJson(liveFile(cwd, local), { permissions: perms })
}

/** Where the live project's journal would be, without creating anything. */
function liveJournal(cwd: string): string {
	return join(cwd, ".pi", "projects", LIVE, "grants.json")
}

/** The live rules file parsed, or null when it was never written. */
function liveRules(cwd: string, local = false): { allow?: string[]; deny?: string[]; ask?: string[] } | null {
	const file = liveFile(cwd, local)
	if (!existsSync(file)) return null
	return JSON.parse(readFileSync(file, "utf-8")).permissions
}

const texts = (items: { rule?: string; value?: string }[] | undefined) =>
	(items ?? []).map((i) => i.rule ?? i.value ?? "")

afterEach(() => {
	for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe("the tightening half is taken quietly", () => {
	it("copies an orphan's deny into the live project and leaves its allow alone", () => {
		const cwd = checkout()
		orphanRules(cwd, { deny: ["Bash(git push*)"], allow: ["Bash(npm test)"] })

		const out = adoptOrphans({ cwd })

		expect(out.plan.orphans).toEqual([ORPHAN])
		expect(texts(out.apply)).toEqual(["Bash(git push*)"])
		expect(texts(out.pending)).toEqual(["Bash(npm test)"])
		expect(out.failed).toEqual([])
		expect(liveRules(cwd)?.deny).toEqual(["Bash(git push*)"])
		// The widening half is not in the file. This is the whole ticket in one assertion.
		expect(liveRules(cwd)?.allow ?? []).not.toContain("Bash(npm test)")
	})

	it("is idempotent and removes nothing: a second adopt writes no bytes at all", () => {
		const cwd = checkout()
		orphanRules(cwd, { deny: ["Bash(git push*)"], ask: ["Write(~/dotfiles/**)"] })
		writeLive(cwd, { deny: ["Read(~/.pi/**)"], allow: ["Bash(npm test)"] })
		const before = readFileSync(liveFile(cwd), "utf-8")

		const first = adoptOrphans({ cwd })
		expect(texts(first.apply).sort()).toEqual(["Bash(git push*)", "Write(~/dotfiles/**)"])

		const second = adoptOrphans({ cwd })
		expect(second.apply).toEqual([])
		expect(second.plan.skipped.map((s) => s.what).sort()).toEqual([
			"Bash(git push*)",
			"Write(~/dotfiles/**)",
		])
		expect(second.plan.skipped.every((s) => /already/i.test(s.reason))).toBe(true)

		const after = JSON.parse(readFileSync(liveFile(cwd), "utf-8")).permissions
		// Both adopted rules are there exactly once...
		expect(after.deny.filter((r: string) => r === "Bash(git push*)")).toHaveLength(1)
		// ...and every rule the project already had is still there, in the list it was in.
		expect(after.deny).toContain("Read(~/.pi/**)")
		expect(after.allow).toEqual(["Bash(npm test)"])
		expect(readFileSync(liveFile(cwd), "utf-8")).not.toBe(before)

		// A third call finds nothing left to do, so the file is not rewritten — no churn, no new bytes.
		const settled = readFileSync(liveFile(cwd), "utf-8")
		const mtimeBefore = statSync(liveFile(cwd)).mtimeMs
		expect(adoptOrphans({ cwd }).apply).toEqual([])
		expect(readFileSync(liveFile(cwd), "utf-8")).toBe(settled)
		expect(statSync(liveFile(cwd)).mtimeMs).toBe(mtimeBefore)
	})

	it("keeps a personal rule personal: an orphan's permissions.local.json stays local", () => {
		const cwd = checkout()
		orphanRules(cwd, { deny: ["Bash(sudo *)"] }, "permissions.local.json")

		const out = adoptOrphans({ cwd })

		expect(out.apply[0].into).toBe("local")
		expect(liveRules(cwd, true)?.deny).toEqual(["Bash(sudo *)"])
		expect(liveFile(cwd, false) && existsSync(liveFile(cwd, false))).toBe(false)
	})

	it("keeps one entry per rule text and takes the strictest behaviour seen for it", () => {
		const cwd = checkout()
		// The same text arrives twice, from two orphans, as ask in one file and deny in another.
		orphanRules(cwd, { ask: ["Bash(git push*)"] }, "permissions.json", "orphanone1")
		orphanRules(cwd, { deny: ["Bash(git push*)"] }, "permissions.local.json", "oroptwotwo")

		const out = adoptOrphans({ cwd })

		expect(out.apply).toHaveLength(1)
		expect(out.apply[0].behavior).toBe("deny")
		expect(liveRules(cwd, true)?.deny).toEqual(["Bash(git push*)"])
		expect(liveRules(cwd, false)).toBeNull()
	})

	it("does not re-adopt what the live project already carries at the same or a stricter level", () => {
		const cwd = checkout()
		writeLive(cwd, { deny: ["Bash(git push*)"] })
		// An ask sits BELOW a deny, so the project's deny already does more than this orphan's ask.
		orphanRules(cwd, { ask: ["Bash(git push*)"], deny: ["Read(~/.ssh/**)"] })

		const out = adoptOrphans({ cwd })

		expect(texts(out.apply)).toEqual(["Read(~/.ssh/**)"])
		expect(out.plan.skipped.map((s) => s.what)).toEqual(["Bash(git push*)"])
		expect(out.plan.skipped[0].reason).toMatch(/or stricter/)
		expect(liveRules(cwd)?.deny).toEqual(["Bash(git push*)", "Read(~/.ssh/**)"])
	})

	it("reports a rules file it cannot read instead of calling the directory clean", () => {
		const cwd = checkout()
		writeFileSync(join(stateDir(cwd, ORPHAN), "permissions.json"), '{ "permissions": { "deny": ["Bash(git push*)" }')

		const out = adoptOrphans({ cwd })

		expect(out.plan.skipped).toHaveLength(1)
		expect(out.plan.skipped[0].reason).toMatch(/not valid JSON/)
		expect(out.apply).toEqual([])
		expect(existsSync(liveFile(cwd))).toBe(false)
	})
})

describe("the widening half waits for a human", () => {
	it("leaves an orphan's allow out of the rules file until it is confirmed", () => {
		const cwd = checkout()
		orphanRules(cwd, { allow: ["Edit(./src/cli/**)"], deny: ["Bash(git push*)"] })

		const out = adoptOrphans({ cwd })
		expect(out.pending).toHaveLength(1)
		expect(liveRules(cwd)?.allow ?? []).toEqual([])

		const store = createGrantStore()
		const confirmed = confirmAdoption({ cwd, store, items: out.pending })
		expect(confirmed.rules).toEqual(["Edit(./src/cli/**)"])
		expect(liveRules(cwd)?.allow).toEqual(["Edit(./src/cli/**)"])
		// The deny that was taken silently is still there beside it.
		expect(liveRules(cwd)?.deny).toEqual(["Bash(git push*)"])
	})

	it("will not offer — or confirm — a Bash allow that bypasses the classifier", () => {
		const cwd = checkout()
		orphanRules(cwd, { allow: ["Bash(git *)", "Edit(./src/cli/**)"] })

		const plan = planAdoption({ cwd })
		expect(plan.pending.map((p) => p.kind === "rule" && p.rule)).toEqual(["Edit(./src/cli/**)"])
		expect(plan.skipped.map((s) => s.what)).toEqual(["Bash(git *)"])
		expect(plan.skipped[0].reason).toMatch(/bypasses the classifier/)

		// Even handed straight to the confirm face, it is refused.
		const smuggled = plan.skipped[0]
		const store = createGrantStore()
		const out = confirmAdoption({
			cwd,
			store,
			items: [{ kind: "rule", rule: smuggled.what, behavior: "allow", tool: "Bash", specifier: "git *", origin: smuggled.origin, into: "project" }],
		})
		expect(out.rules).toEqual([])
		expect(out.refused[0].reason).toMatch(/bypasses the classifier/)
		expect(liveRules(cwd)).toBeNull()
	})

	it("holds an orphan's grant rows as pending and writes nothing for them", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./src/deep/x.ts", kind: "entity" }])

		const journal = liveJournal(cwd)
		const out = adoptOrphans({ cwd })

		expect(out.pending).toHaveLength(1)
		expect(out.pending[0]).toMatchObject({ kind: "grant", category: "write_project", value: "./src/deep/x.ts" })
		expect(existsSync(journal)).toBe(false)
		expect(adoptOrphans({ cwd }).apply).toEqual([])
		expect(existsSync(journal)).toBe(false)
	})

	it("leaves the orphan's ledger half where it is and says why", () => {
		const cwd = checkout()
		const file = join(stateDir(cwd, ORPHAN), "grants.json")
		writeJson(file, {
			v: 1,
			exportedAt: "2026-10-14T00:00:00.000Z",
			sourceCwd: "/old/place",
			ledger: {
				v: 1,
				grants: [{ category: "write_project", value: "/old/x", kind: "entity", seq: 3 }],
				forbids: [{ category: "delete_recursive", value: "/old/data", kind: "scope", seq: 4, quote: "never touch /old/data" }],
				seen: [],
			},
			grants: [],
		})

		const plan = planAdoption({ cwd })

		expect(plan.pending).toEqual([])
		expect(plan.skipped[0].what).toBe("grants.json (ledger half)")
		expect(plan.skipped[0].reason).toContain("1 ledger grants and 1 forbids")
		expect(plan.skipped[0].reason).toContain("/grants import")
		expect(readFileSync(file, "utf-8")).toContain("never touch /old/data")
	})
})

describe("revocations outrank an adoption", () => {
	it("will not walk back a row this session revoked", () => {
		const cwd = checkout()
		const path = `${cwd}/src/deep/x.ts`
		orphanJournal(cwd, [{ category: "write_project", value: path, kind: "entity", durable: true }])

		const store = createGrantStore()
		addGrant(store, "write_project", path, "entity", true)
		expect(revokeRows(store, (row) => row.value === path, { quote: "/grants revoke" })).toHaveLength(1)

		const out = adoptOrphans({ cwd })
		expect(out.pending).toHaveLength(1)
		const confirmed = confirmAdoption({ cwd, store, items: out.pending })

		expect(confirmed.grants).toEqual([])
		expect(confirmed.refused[0].reason).toMatch(/an adoption is not a re-grant/)
		expect(store.grants).toEqual([])
	})

	it("recognises a revocation spelled absolutely against a row spelled ./", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./src/deep/x.ts", kind: "entity" }])

		const store = createGrantStore()
		addGrant(store, "write_project", `${cwd}/src/deep/x.ts`, "entity")
		revokeRows(store, (row) => row.value === `${cwd}/src/deep/x.ts`)

		const confirmed = confirmAdoption({ cwd, store, items: planAdoption({ cwd }).pending })
		expect(confirmed.grants).toEqual([])
		expect(confirmed.refused[0].what).toContain("./src/deep/x.ts")
		expect(store.grants).toEqual([])
	})

	it("keeps a revocation of a folder from declining an unrelated row of the same category", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./other/y.ts", kind: "entity" }])

		const store = createGrantStore()
		addGrant(store, "write_project", `${cwd}/src/`, "scope")
		revokeRows(store, (row) => row.kind === "scope")

		const confirmed = confirmAdoption({ cwd, store, items: planAdoption({ cwd }).pending })
		expect(confirmed.refused).toEqual([])
		expect(texts(confirmed.grants)).toEqual([`${cwd}/other/y.ts`])
	})
})

describe("paths are adopted into the path space that exists now", () => {
	it("stores the current absolute path for a row the orphan wrote project-relatively", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./src/deep/x.ts", kind: "entity", durable: true }])

		const store = createGrantStore()
		const confirmed = confirmAdoption({ cwd, store, items: planAdoption({ cwd }).pending })

		expect(store.grants).toHaveLength(1)
		// The assertion is on the stored value, not on a call having happened.
		expect(store.grants[0].value).toBe(`${cwd}/src/deep/x.ts`)
		expect(store.grants[0]).toMatchObject({ category: "write_project", kind: "entity", durable: true })
		expect(texts(confirmed.grants)).toEqual([`${cwd}/src/deep/x.ts`])
	})

	it("reports a journal row whose value could never match a target instead of offering it", () => {
		const cwd = checkout()
		// Written by hand, not by `buildGrantsFile()`, because the writer prunes such rows itself — an
		// older or hand-edited journal can still hold one, and an adopt must not launder it into the store.
		writeJson(join(stateDir(cwd, ORPHAN), "grants.json"), {
			v: 1,
			exportedAt: "2026-10-14T00:00:00.000Z",
			sourceCwd: "/old/place",
			ledger: { v: 1, grants: [], forbids: [], seen: [] },
			grants: [{ category: "vcs_remote", value: "origin/main", kind: "entity", at: 1 }],
		})

		const store = createGrantStore()
		const plan = planAdoption({ cwd })
		expect(plan.pending).toEqual([])
		expect(plan.skipped[0].what).toBe("origin/main")
		expect(plan.skipped[0].reason).toMatch(/never match a target/)
		expect(confirmAdoption({ cwd, store, items: plan.pending }).grants).toEqual([])
		expect(store.grants).toEqual([])
	})

	it("reports a row the session already holds as nothing to do, and does not store it twice", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./src/deep/x.ts", kind: "entity" }])

		const store = createGrantStore()
		// The same target, spelled the way the gate spells it: project-relative on one side, absolute
		// on the other. Matching them is the canonicaliser's job, not a string compare's.
		addGrant(store, "write_project", `./src/deep/x.ts`, "entity")

		const confirmed = confirmAdoption({ cwd, store, items: planAdoption({ cwd }).pending })
		expect(confirmed.grants).toEqual([])
		expect(confirmed.refused[0].reason).toMatch(/already holds a row/)
		expect(store.grants).toHaveLength(1)
		expect(store.grants[0].value).toBe("./src/deep/x.ts")
	})

	it("mirrors the store into the journal only once a human has confirmed", () => {
		const cwd = checkout()
		orphanJournal(cwd, [{ category: "write_project", value: "./src/deep/x.ts", kind: "entity", durable: true }])
		const journal = liveJournal(cwd)
		mkdirSync(stateDir(cwd, LIVE), { recursive: true })
		writeGrantsFile(journal, buildGrantsFile({ ledger: { v: 1, grants: [], forbids: [], seen: [] }, grants: [], sourceCwd: cwd }).file)
		const before = JSON.parse(readFileSync(journal, "utf-8"))
		expect(before.grants).toEqual([])

		// Adopt first: the pending row must not have reached the journal.
		const out = adoptOrphans({ cwd })
		expect(JSON.parse(readFileSync(journal, "utf-8")).grants).toEqual([])

		const store = createGrantStore()
		const confirmed = confirmAdoption({ cwd, store, items: out.pending, journal })
		expect(confirmed.journal).toMatchObject({ path: journal, ok: true })
		const after = JSON.parse(readFileSync(journal, "utf-8"))
		expect(after.grants.map((g: { value: string }) => g.value)).toEqual([`${cwd}/src/deep/x.ts`])
	})
})

describe("nothing adoptable, nothing written", () => {
	it("creates no file and changes no bytes when the orphan holds only allow rules", () => {
		const cwd = checkout()
		const orphanFile = orphanRules(cwd, { allow: ["Edit(./src/cli/**)"] })
		const orphanBefore = readFileSync(orphanFile, "utf-8")
		const projectsBefore = readdirSorted(cwd)

		const out = adoptOrphans({ cwd })

		expect(out.apply).toEqual([])
		expect(out.pending).toHaveLength(1)
		expect(existsSync(liveFile(cwd))).toBe(false)
		expect(existsSync(liveFile(cwd, true))).toBe(false)
		expect(existsSync(liveJournal(cwd))).toBe(false)
		// Adopt copies: the orphan keeps its own file, unread-and-unchanged, for the next run or for
		// `/grants import`.
		expect(readFileSync(orphanFile, "utf-8")).toBe(orphanBefore)
		expect(readdirSorted(cwd)).toEqual(projectsBefore)
	})

	it("says nothing at all when there is no orphan directory", () => {
		const cwd = checkout()
		const plan = planAdoption({ cwd })
		expect(plan).toMatchObject({ cwd, projectId: LIVE, orphans: [], apply: [], pending: [], skipped: [] })
		expect(adoptOrphans({ cwd }).apply).toEqual([])
		expect(existsSync(liveFile(cwd))).toBe(false)
	})

	it("skips a journal it cannot read without failing the rest of the scan", () => {
		const cwd = checkout()
		writeFileSync(join(stateDir(cwd, ORPHAN), "grants.json"), "nope")
		orphanRules(cwd, { deny: ["Bash(git push*)"] })

		const out = adoptOrphans({ cwd })

		expect(texts(out.apply)).toEqual(["Bash(git push*)"])
		expect(out.plan.skipped[0].reason).toMatch(/not valid JSON/)
	})
})

function readdirSorted(cwd: string): string[] {
	const walk = (dir: string, prefix: string): string[] => {
		const out: string[] = []
		for (const name of readdirSync(dir)) {
			const rel = `${prefix}${name}`
			const full = join(dir, name)
			out.push(rel)
			if (statSync(full).isDirectory()) out.push(...walk(full, `${rel}/`))
		}
		return out
	}
	return walk(cwd, "").sort()
}
