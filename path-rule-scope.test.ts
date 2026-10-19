/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, it, expect, afterAll } from "vitest"
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir, homedir } from "node:os"
import { join } from "node:path"
import { suggestPathAllowRule, pathMatchesRulePattern } from "./path-permission-match.ts"

const root = mkdtempSync(join(tmpdir(), "prm-rule-scope-"))
mkdirSync(join(root, "src/a"), { recursive: true })
writeFileSync(join(root, "src/a/b.ts"), "x")
mkdirSync(join(root, ".ssh"), { recursive: true })
writeFileSync(join(root, ".ssh/id_rsa"), "key")

describe("a file grant grants a file", () => {
	it("names the exact file, not its first directory segment", () => {
		expect(suggestPathAllowRule("Edit", "src/a/b.ts", root)).toBe("Edit(./src/a/b.ts)")
	})
	it("does not sweep the tree above it", () => {
		expect(suggestPathAllowRule("Edit", "src/a/b.ts", root)).not.toContain("**")
	})
	it("treats a not-yet-existing path as a file, so creating it grants only it", () => {
		expect(suggestPathAllowRule("Write", "new/deep.ts", root)).toBe("Write(./new/deep.ts)")
	})
})

describe("a folder grant grants that folder's contents", () => {
	it("a trailing slash is decisive", () => {
		expect(suggestPathAllowRule("Edit", "src/a/", root)).toBe("Edit(./src/a/**)")
	})
	it("an existing directory without a slash means the same thing", () => {
		expect(suggestPathAllowRule("Edit", "src/a", root)).toBe("Edit(./src/a/**)")
	})
	it("and the resulting rule really matches what is inside it", () => {
		const rule = suggestPathAllowRule("Edit", "src/a/", root)
		const spec = rule.slice(rule.indexOf("(") + 1, -1)
		expect(pathMatchesRulePattern(join(root, "src/a/b.ts"), spec, root)).toBe(true)
	})
})

describe("a folder grant does not reach secrets", () => {
	const secret = join(root, ".ssh/id_rsa")
	it("a subtree glob will not match a secret-bearing path", () => {
		expect(pathMatchesRulePattern(secret, "./**", root)).toBe(false)
		expect(pathMatchesRulePattern(secret, ".ssh/**", root)).toBe(false)
	})
	it("naming the secret exactly still works - inclusion is explicit, never incidental", () => {
		expect(pathMatchesRulePattern(secret, ".ssh/id_rsa", root)).toBe(true)
	})
	it("while ordinary siblings under the same glob still match", () => {
		expect(pathMatchesRulePattern(join(root, "src/a/b.ts"), "./**", root)).toBe(true)
	})
})

void homedir
afterAll(() => rmSync(root, { recursive: true, force: true }))
