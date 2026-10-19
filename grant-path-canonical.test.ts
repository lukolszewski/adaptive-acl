/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"
import { applyEvent, createLedger, ledgerCovers, type ExtractedEvent } from "./auth-ledger.ts"
import { canonicalPath } from "./grant-verify.ts"
import { grantsCover, createGrantStore, addGrant } from "./session-grants.ts"
import type { Entity } from "./risk-policy.ts"

const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

const HOME = "/home/u"
const PROJECT = "/home/u/dev/pm"

function grant(
	category: string,
	value: string,
	quote: string,
	seq = 5,
	kind: "entity" | "scope" = value.endsWith("/") ? "scope" : "entity",
): ExtractedEvent {
	return { type: "grant", category, value, kind, quote, messageId: `m${seq}`, seq }
}

describe("canonicalPath — one path space for both sides of a match", () => {
	it("resolves project-relative values, which is how displayPath renders every in-project target", () => {
		expect(canonicalPath("./a/b", { project: "/p" })).toBe("/p/a/b")
		expect(canonicalPath("./a//b", { project: "/p" })).toBe("/p/a/b")
		expect(canonicalPath(".", { project: "/p" })).toBe("/p/")
		expect(canonicalPath("./", { project: "/p" })).toBe("/p/")
		expect(canonicalPath("./*", { project: "/p" })).toBe("/p/")
	})

	it("leaves `..` unresolved rather than guessing a root that would widen reach", () => {
		expect(canonicalPath("../x", { project: "/p" })).toBe("../x")
	})

	it("never resolves a bare word against the project root", () => {
		// `ripgrep`, `origin/main`, `sessions` are names, not locations. Resolving them would invent a
		// path the user never said and change what the basename matching means.
		expect(canonicalPath("ripgrep", { project: "/p" })).toBe("ripgrep")
		expect(canonicalPath("origin/main", { project: "/p" })).toBe("origin/main")
	})

	it("keeps the ~ expansion that already worked, and absolute paths untouched", () => {
		expect(canonicalPath("~/dev/x", { home: HOME })).toBe("/home/u/dev/x")
		expect(canonicalPath("/etc/nginx/nginx.conf", { project: "/p", home: HOME })).toBe(
			"/etc/nginx/nginx.conf",
		)
	})

	it("falls back to the old leading-`./`-strip when no project is known", () => {
		// Every pre-existing caller passes no project; their behaviour must be identical.
		expect(canonicalPath("./a/b", {})).toBe("a/b")
		expect(canonicalPath("./a/b", { home: HOME })).toBe("a/b")
	})
})

describe("ledgerCovers — an absolutely-worded grant covers project-relative entities", () => {
	// The live defect, verbatim: the user's sentence extracted correctly
	// (`delete_recursive scope /home/u/dev/pm`) and covered nothing, because layer 0 emits `./.probe/tmp`
	// and the matcher compared it against an absolute prefix. The denial blamed the missing approval.
	const mk = () => {
		const l = createLedger()
		applyEvent(
			l,
			grant(
				"delete_recursive",
				"/home/u/dev/pm/",
				"you are allowed to delete files under /home/u/dev/pm",
				138,
			),
		)
		return l
	}

	it("covers the exact targets that were denied on 2026-10-14", () => {
		expect(ledgerCovers(mk(), "delete_recursive", [T("./.probe/tmp")], HOME, PROJECT).covered).toBe(true)
		expect(
			ledgerCovers(
				mk(),
				"delete_recursive",
				[T("./corpus/.pi/projects/cecea944")],
				HOME,
				PROJECT,
			).covered,
		).toBe(true)
	})

	it("still covers the absolute spelling (the fix equalises spellings, it does not swap them)", () => {
		expect(
			ledgerCovers(mk(), "delete_recursive", [T("/home/u/dev/pm/.probe/tmp")], HOME, PROJECT).covered,
		).toBe(true)
	})

	it("without a project it behaves exactly as before, so no caller silently widens", () => {
		expect(ledgerCovers(mk(), "delete_recursive", [T("./.probe/tmp")], HOME).covered).toBe(false)
	})

	it("does not let a scope escape into a sibling directory", () => {
		const l = mk()
		expect(
			ledgerCovers(l, "delete_recursive", [T("/home/u/dev/pm2/x")], HOME, PROJECT).covered,
		).toBe(false)
		expect(
			ledgerCovers(l, "delete_recursive", [T("/home/u/dev/pm-other/x")], HOME, PROJECT).covered,
		).toBe(false)
	})

	it("keeps the delete-verb gate: naming the location is not naming the action", () => {
		const l = createLedger()
		applyEvent(l, grant("delete_recursive", "/home/u/dev/pm/", "what is under /home/u/dev/pm", 3))
		expect(ledgerCovers(l, "delete_recursive", [T("./x")], HOME, PROJECT).covered).toBe(false)
	})

	it("keeps a read grant from becoming a delete grant", () => {
		const l = createLedger()
		applyEvent(l, grant("read_only", "/home/u/dev/pm/", "you can read anything in /home/u/dev/pm", 3))
		expect(ledgerCovers(l, "delete_recursive", [T("./x")], HOME, PROJECT).covered).toBe(false)
	})

	it("leaves the home-relative rendering working as it always did", () => {
		const l = createLedger()
		applyEvent(l, grant("read_secret", "~/.pi/", "you are allowed to read files under ~/.pi", 4))
		expect(ledgerCovers(l, "read_secret", [T("~/.pi/agent/settings.json")], HOME, PROJECT).covered).toBe(
			true,
		)
	})
})

describe("grantsCover — session grants resolve in the same space", () => {
	it("covers a project-relative entity with an absolute scope", () => {
		const s = createGrantStore()
		addGrant(s, "write_outside", "/home/u/dev/pm/", "scope")
		expect(grantsCover(s, "write_outside", [T("./corpus/index.ts")], HOME, PROJECT).covered).toBe(true)
		expect(grantsCover(s, "write_outside", [T("./corpus/index.ts")], HOME).covered).toBe(false)
	})

	it("covers a relative scope with a relative entity", () => {
		const s = createGrantStore()
		addGrant(s, "write_outside", "./corpus/", "scope")
		expect(grantsCover(s, "write_outside", [T("./corpus/.pi/x.json")], HOME, PROJECT).covered).toBe(true)
		expect(grantsCover(s, "write_outside", [T("./grant/x.json")], HOME, PROJECT).covered).toBe(false)
	})

	it("DOCUMENTS current behaviour: an entity grant naming a directory reaches files under it", () => {
		// Component-run matching in entityMatchesTarget, not new logic — recorded so that narrowing it
		// later (plan item C decides this) is a deliberate change rather than a surprise.
		const s = createGrantStore()
		addGrant(s, "delete_recursive", "/home/u/dev/pm", "entity")
		expect(grantsCover(s, "delete_recursive", [T("./x/y")], HOME, PROJECT).covered).toBe(true)
	})

	it("still refuses an unrelated file when a file was named", () => {
		const s = createGrantStore()
		addGrant(s, "write_outside", "/home/u/dev/pm/corpus/a.ts", "entity")
		expect(grantsCover(s, "write_outside", [T("./corpus/b.ts")], HOME, PROJECT).covered).toBe(false)
	})
})
