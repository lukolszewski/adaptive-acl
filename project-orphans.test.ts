/**
 * Orphaned project state, made visible.
 *
 * `<cwd>/.pi/projects/` can hold state for ids the current session does not use:
 * after a move, the old id's directory sits there with every rule it ever had, and
 * nothing reads it. Losing a **deny** rule invisibly is the worst failure mode in
 * this codebase — the next session does not error, it simply stops refusing. The
 * supervisor warns from this listing, so the listing has to be honest about three
 * separate things: which ids exist, which of them hold rule files, and whether any
 * rule it could read forbids something.
 *
 * This module is fs-only and changes nothing: no pi import, no `process.env`, no
 * migrate / adopt / merge / delete.
 */

import { describe, expect, it, afterEach } from "vitest"
import {
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { getProjectId, listProjectStateDirs } from "./utils.ts"

const LIVE = "4b2c143b"
const ORPHAN = "cecea944"

let roots: string[] = []

function root(): string {
	const dir = mkdtempSync(join(tmpdir(), "pm-orphan-"))
	roots.push(dir)
	return dir
}

function stateDir(cwd: string, id: string): string {
	const dir = join(cwd, ".pi", "projects", id)
	mkdirSync(dir, { recursive: true })
	return dir
}

function put(cwd: string, id: string, file: string, body: unknown): string {
	const filePath = join(stateDir(cwd, id), file)
	writeFileSync(filePath, typeof body === "string" ? body : JSON.stringify(body, null, 2) + "\n")
	return filePath
}

afterEach(() => {
	for (const r of roots) rmSync(r, { recursive: true, force: true })
})

describe("listProjectStateDirs", () => {
	it("names an id other than the one in use, with everything it holds", () => {
		const cwd = root()
		put(cwd, ORPHAN, "permissions.local.json", {
			permissions: { deny: ["Bash(git push*)", "Bash(npm publish*)", "Read(~/.pi/**)"] },
		})
		put(cwd, ORPHAN, "grants.json", { v: 1, grants: [] })

		const found = listProjectStateDirs(cwd, LIVE)
		expect(found).toHaveLength(1)
		expect(found[0]).toEqual({
			id: ORPHAN,
			path: join(cwd, ".pi", "projects", ORPHAN),
			rules: { permissions: false, local: true },
			grants: true,
			hasDenyRules: true,
		})
	})

	it("never lists the id currently in use", () => {
		const cwd = root()
		put(cwd, LIVE, "permissions.json", { permissions: { deny: ["Bash(git push*)"] } })
		expect(listProjectStateDirs(cwd, LIVE)).toEqual([])
	})

	it("finds a deny in either file and in either shape", () => {
		const nested = root()
		put(nested, ORPHAN, "permissions.json", { permissions: { deny: ["Write(~/.pi/**)"] } })
		expect(listProjectStateDirs(nested, LIVE)[0].hasDenyRules).toBe(true)

		const flat = root()
		put(flat, ORPHAN, "permissions.json", { deny: ["Bash(rm -rf /*)"] })
		expect(listProjectStateDirs(flat, LIVE)[0].hasDenyRules).toBe(true)

		const onlyInLocal = root()
		put(onlyInLocal, ORPHAN, "permissions.json", { permissions: { allow: ["Bash(npm test)"] } })
		put(onlyInLocal, ORPHAN, "permissions.local.json", { permissions: { deny: ["Bash(git push*)"] } })
		const [entry] = listProjectStateDirs(onlyInLocal, LIVE)
		expect(entry.rules).toEqual({ permissions: true, local: true })
		expect(entry.hasDenyRules).toBe(true)
	})

	it("does not call an allow-only directory a deny, nor claim it is empty", () => {
		const cwd = root()
		put(cwd, ORPHAN, "permissions.json", { permissions: { allow: ["Bash(npm run:*)"] } })
		const [entry] = listProjectStateDirs(cwd, LIVE)
		expect(entry.rules.permissions).toBe(true)
		expect(entry.hasDenyRules).toBe(false)
		expect(entry.grants).toBe(false)
	})

	it("does not call an empty or shapeless deny list a forbid", () => {
		const empty = root()
		put(empty, ORPHAN, "permissions.json", { permissions: { deny: [] } })
		expect(listProjectStateDirs(empty, LIVE)[0].hasDenyRules).toBe(false)

		const blank = root()
		put(blank, ORPHAN, "permissions.json", { permissions: { deny: ["", "   "] } })
		expect(listProjectStateDirs(blank, LIVE)[0].hasDenyRules).toBe(false)

		const wrongType = root()
		put(wrongType, ORPHAN, "permissions.json", { permissions: { deny: "Bash(git push*)" } })
		expect(listProjectStateDirs(wrongType, LIVE)[0].hasDenyRules).toBe(false)
	})

	it("tolerates a file it cannot parse: present, unreadable, reported as no forbid found", () => {
		const cwd = root()
		const broken = put(cwd, ORPHAN, "permissions.json", '{ "permissions": { "deny": ["Bash(git push*)" }')
		put(cwd, ORPHAN, "permissions.local.json", "not json at all")

		let found!: ReturnType<typeof listProjectStateDirs>
		expect(() => {
			found = listProjectStateDirs(cwd, LIVE)
		}).not.toThrow()

		expect(found).toHaveLength(1)
		expect(found[0].rules).toEqual({ permissions: true, local: true })
		// Not proof of safety — the caller's job is to say "unreadable", not "clean".
		expect(found[0].hasDenyRules).toBe(false)
		expect(readFileSync(broken, "utf-8")).toContain("git push")
	})

	it("says nothing when there is nothing to say", () => {
		const bare = root()
		expect(listProjectStateDirs(bare, LIVE)).toEqual([])

		const onlyLive = root()
		mkdirSync(join(stateDir(onlyLive, LIVE), "tmp", "outside-writes"), { recursive: true })
		expect(listProjectStateDirs(onlyLive, LIVE)).toEqual([])

		const withStrayFile = root()
		mkdirSync(stateDir(withStrayFile, LIVE), { recursive: true })
		writeFileSync(join(withStrayFile, ".pi", "projects", "README.txt"), "not an id\n")
		expect(listProjectStateDirs(withStrayFile, LIVE)).toEqual([])
	})

	it("still reports an orphan whose directory holds no rule file at all", () => {
		const cwd = root()
		mkdirSync(join(stateDir(cwd, ORPHAN), "tmp"), { recursive: true })
		const found = listProjectStateDirs(cwd, LIVE)
		expect(found).toHaveLength(1)
		expect(found[0]).toEqual({
			id: ORPHAN,
			path: join(cwd, ".pi", "projects", ORPHAN),
			rules: { permissions: false, local: false },
			grants: false,
			hasDenyRules: false,
		})
	})

	it("comes back in id order so output can be compared", () => {
		const cwd = root()
		for (const id of ["ffff0000", ORPHAN, "0000aaaa"]) stateDir(cwd, id)
		expect(listProjectStateDirs(cwd, LIVE).map((d) => d.id)).toEqual([
			"0000aaaa",
			ORPHAN,
			"ffff0000",
		])
	})

	it("reads and changes nothing", () => {
		const cwd = root()
		const denyFile = put(cwd, ORPHAN, "permissions.local.json", {
			permissions: { deny: ["Bash(git push*)"] },
		})
		const before = readdirSync(join(cwd, ".pi", "projects", ORPHAN)).sort()
		const beforeBytes = readFileSync(denyFile, "utf-8")

		listProjectStateDirs(cwd, LIVE)
		listProjectStateDirs(cwd, LIVE)

		expect(readdirSync(join(cwd, ".pi", "projects", ORPHAN)).sort()).toEqual(before)
		expect(readFileSync(denyFile, "utf-8")).toBe(beforeBytes)
		expect(readdirSync(join(cwd, ".pi"))).toEqual(["projects"])
	})

	it("pairs with getProjectId: the id in use is the one excluded", () => {
		const cwd = root()
		mkdirSync(join(cwd, ".pi"), { recursive: true })
		writeFileSync(join(cwd, ".pi", "permission-modes-" + LIVE + ".md"), "# pi marker\n")
		put(cwd, LIVE, "permissions.json", { permissions: { allow: ["Bash(npm test)"] } })
		put(cwd, ORPHAN, "permissions.local.json", {
			permissions: { deny: ["Bash(git push*)", "Bash(rm -rf /*)"] },
		})

		const live = getProjectId(cwd)
		expect(live).toBe(LIVE)
		const found = listProjectStateDirs(cwd, live)
		expect(found.map((d) => d.id)).toEqual([ORPHAN])
		expect(found[0].hasDenyRules).toBe(true)
	})
})
