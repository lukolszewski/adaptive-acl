/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * A checkout must carry its own identity.
 *
 * Project state lives at `<cwd>/.pi/projects/<id>/`, so the id is the address of
 * a project's authority, not a label on it. Deriving the id from the path means a
 * `mv` — a worktree move, a rename, a sibling checkout — drops every rule that
 * directory held, allows and denies alike, with nothing printed and nothing to
 * retry. That is not a hypothetical here: this tree moved, its id changed, and the
 * only copies of `Bash(git push*)`, `Bash(npm publish*)`, `Bash(rm -rf /*)` and the
 * `~/.pi` read/write denies were left behind in the orphaned directory.
 *
 * So the id is resolved carried-first: `.pi/project.json` inside the tree beats
 * `sha256(cwd)[0:8]`. A third source sat between those — pi's
 * `.pi/permission-modes-<id>.md`, which no program ever wrote — and was removed on
 * 2026-10-21. The tests below build two real tmpdirs and move content between them —
 * never the real tree.
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest"
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
	getPlanFilePath,
	getProjectId,
	getProjectTmpDir,
	hashPath,
	readProjectIdMarker,
	writeProjectIdMarker,
} from "./utils.ts"
import { getProjectPermissionsDir, getProjectPermissionsPath } from "./permissions-loader.ts"

const ID = "pm-corpus"

function tree(): string {
	return mkdtempSync(join(tmpdir(), "pm-move-"))
}

function stampAt(root: string, id: string): void {
	mkdirSync(join(root, ".pi"), { recursive: true })
	writeFileSync(
		join(root, ".pi", "project.json"),
		JSON.stringify({ projectId: id }, null, 2) + "\n",
	)
}

function rawMarker(root: string): string {
	return readFileSync(join(root, ".pi", "project.json"), "utf-8")
}

let roots: string[] = []

beforeEach(() => {
	roots = []
})

afterEach(() => {
	for (const r of roots) rmSync(r, { recursive: true, force: true })
})

function fresh(): string {
	const dir = tree()
	roots.push(dir)
	return dir
}

describe("getProjectId — resolution order", () => {
	it("the carried marker wins over the path hash", () => {
		const dir = fresh()
		stampAt(dir, ID)
		expect(getProjectId(dir)).toBe(ID)
		expect(getProjectId(dir)).not.toBe(hashPath(dir))
	})

	it("falls back to the path hash when nothing is stamped", () => {
		const dir = fresh()
		expect(getProjectId(dir)).toBe(hashPath(dir))
		mkdirSync(join(dir, ".pi"), { recursive: true })
		writeFileSync(join(dir, ".pi", "notes.md"), "")
		expect(getProjectId(dir)).toBe(hashPath(dir))
	})

	it("a stamp that appears mid-session takes over on the next call", () => {
		const dir = fresh()
		expect(getProjectId(dir)).toBe(hashPath(dir))
		stampAt(dir, ID)
		expect(getProjectId(dir)).toBe(ID)
	})

	it("an unusable carried file falls through instead of throwing", () => {
		const dir = fresh()
		mkdirSync(join(dir, ".pi"), { recursive: true })
		writeFileSync(join(dir, ".pi", "project.json"), "{ projectId broken")
		expect(getProjectId(dir)).toBe(hashPath(dir))
		writeFileSync(join(dir, ".pi", "project.json"), JSON.stringify({ projectId: "../evil" }))
		expect(getProjectId(dir)).toBe(hashPath(dir))
		writeFileSync(join(dir, ".pi", "project.json"), JSON.stringify([]))
		expect(getProjectId(dir)).toBe(hashPath(dir))
	})
})

describe("a move carries the identity with the tree", () => {
	it("the same contents in two locations report one id", () => {
		const before = fresh()
		stampAt(before, ID)
		mkdirSync(join(before, ".pi", "projects", ID), { recursive: true })
		writeFileSync(
			join(before, ".pi", "projects", ID, "permissions.local.json"),
			JSON.stringify({ permissions: { deny: ["Bash(git push*)", "Bash(rm -rf /*)"] } }, null, 2),
		)
		const after = fresh()
		cpSync(before, after, { recursive: true })

		expect(getProjectId(after)).toBe(ID)
		expect(getProjectId(after)).toBe(getProjectId(before))
		// The rules are reachable under the new path, unchanged.
		expect(existsSync(getProjectPermissionsPath(after, true))).toBe(true)
		expect(getProjectPermissionsDir(after)).toBe(join(after, ".pi", "projects", ID))
	})

	it("the same contents without a stamp are two different projects — the bug this fixes", () => {
		const before = fresh()
		mkdirSync(join(before, ".pi", "projects"), { recursive: true })
		const after = fresh()
		cpSync(before, after, { recursive: true })
		expect(getProjectId(after)).not.toBe(getProjectId(before))
		expect(getProjectId(after)).toBe(hashPath(after))
	})

	it("a copied stamp is honoured too", () => {
		const before = fresh()
		stampAt(before, "45ea0551")
		const after = fresh()
		cpSync(before, after, { recursive: true })
		expect(getProjectId(after)).toBe("45ea0551")
		expect(hashPath(after)).not.toBe("45ea0551")
	})
})

describe("writeProjectIdMarker", () => {
	it("stamps an unstamped tree and is readable afterwards", () => {
		const dir = fresh()
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		expect(readProjectIdMarker(dir)).toBe(ID)
		expect(getProjectId(dir)).toBe(ID)
		expect(JSON.parse(rawMarker(dir)).projectId).toBe(ID)
	})

	it("switches the live id without a restart", () => {
		const dir = fresh()
		expect(getProjectId(dir)).toBe(hashPath(dir))
		writeProjectIdMarker(dir, ID)
		expect(getProjectId(dir)).toBe(ID)
	})

	it("keeps keys it does not own", () => {
		const dir = fresh()
		mkdirSync(join(dir, ".pi"), { recursive: true })
		writeFileSync(
			join(dir, ".pi", "project.json"),
			JSON.stringify({ note: "hand-written", other: 1 }, null, 2),
		)
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		const doc = JSON.parse(rawMarker(dir))
		expect(doc).toEqual({ note: "hand-written", other: 1, projectId: ID })
	})

	it("refuses a different id than the one the tree already carries", () => {
		const dir = fresh()
		stampAt(dir, ID)
		expect(writeProjectIdMarker(dir, "something-else")).toBe(false)
		expect(readProjectIdMarker(dir)).toBe(ID)
		expect(getProjectId(dir)).toBe(ID)
		expect(rawMarker(dir)).toContain(ID)
		expect(rawMarker(dir)).not.toContain("something-else")
	})

	it("accepts the same id again", () => {
		const dir = fresh()
		stampAt(dir, ID)
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		expect(readProjectIdMarker(dir)).toBe(ID)
	})

	it("stamps a tree that carries nothing, since there is no id to strand", () => {
		const dir = fresh()
		expect(getProjectId(dir)).toBe(hashPath(dir))
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		expect(readProjectIdMarker(dir)).toBe(ID)
		expect(getProjectId(dir)).toBe(ID)
	})

	it("replaces only when told to, with force", () => {
		const dir = fresh()
		stampAt(dir, ID)
		expect(writeProjectIdMarker(dir, "renamed-tree", { force: true })).toBe(true)
		expect(readProjectIdMarker(dir)).toBe("renamed-tree")
		expect(getProjectId(dir)).toBe("renamed-tree")
	})

	it("refuses a carried file it cannot parse, and leaves the bytes alone", () => {
		const dir = fresh()
		mkdirSync(join(dir, ".pi"), { recursive: true })
		const corrupt = '{"projectId": "half-written"\n'
		writeFileSync(join(dir, ".pi", "project.json"), corrupt)
		expect(writeProjectIdMarker(dir, ID)).toBe(false)
		expect(writeProjectIdMarker(dir, ID, { force: true })).toBe(false)
		expect(rawMarker(dir)).toBe(corrupt)
		expect(readProjectIdMarker(dir)).toBe(null)
	})

	it("stamps a placeholder that carries no identity, since there is none to lose", () => {
		const dir = fresh()
		mkdirSync(join(dir, ".pi"), { recursive: true })
		writeFileSync(join(dir, ".pi", "project.json"), "   ")
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		expect(readProjectIdMarker(dir)).toBe(ID)
		writeFileSync(join(dir, ".pi", "project.json"), JSON.stringify({ projectId: "NO PEAK HERE" }))
		expect(writeProjectIdMarker(dir, ID)).toBe(true)
		expect(readProjectIdMarker(dir)).toBe(ID)
	})

	it("rejects anything that is not one safe path segment, writing nothing", () => {
		for (const bad of ["../evil", "", "a".repeat(40), "Has-Upper", "with space", "-leading", "a/b", "dots.json", "ünïcode"]) {
			const dir = fresh()
			expect(writeProjectIdMarker(dir, bad), JSON.stringify(bad)).toBe(false)
			expect(existsSync(join(dir, ".pi", "project.json")), JSON.stringify(bad)).toBe(false)
			expect(readProjectIdMarker(dir)).toBe(null)
		}
	})

	it("accepts the shapes the charset allows, at both length ends", () => {
		for (const ok of ["a", "abc123", "a-b_c", "z".repeat(32)]) {
			const dir = fresh()
			expect(writeProjectIdMarker(dir, ok), ok).toBe(true)
			expect(readProjectIdMarker(dir)).toBe(ok)
			expect(getProjectId(dir)).toBe(ok)
		}
	})
})

describe("one id, every call site", () => {
	it("rules dir, both rule files, the snapshot dir and the plan file all resolve through it", () => {
		const dir = fresh()
		stampAt(dir, ID)
		const base = join(dir, ".pi", "projects", ID)
		expect(getProjectPermissionsDir(dir)).toBe(base)
		expect(getProjectPermissionsPath(dir)).toBe(join(base, "permissions.json"))
		expect(getProjectPermissionsPath(dir, true)).toBe(join(base, "permissions.local.json"))
		expect(getProjectTmpDir(dir)).toBe(join(base, "tmp", "outside-writes"))
		expect(getPlanFilePath(dir)).toBe(join(base, "plan.md"))
	})

	it("and they still agree after the tree moves", () => {
		const before = fresh()
		stampAt(before, ID)
		const after = fresh()
		cpSync(before, after, { recursive: true })
		const rel = [
			getProjectPermissionsDir(after),
			getProjectPermissionsPath(after, true),
			getProjectTmpDir(after),
			getPlanFilePath(after),
		].map((p) => p.slice(after.length))
		const idSegment = rel.map((p) => p.split("/")[3])
		expect(new Set(idSegment).size).toBe(1)
		expect(idSegment[0]).toBe(ID)
		expect(rel.every((p) => p.startsWith(`/.pi/projects/${ID}`))).toBe(true)
	})
})
