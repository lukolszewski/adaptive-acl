/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The target grammars for publish targets: git refs and container images, read from the spellings the
 * gate itself emits.
 *
 * The tables below are coverage measured on reported publish sessions, turned into pins. Before the
 * grammar, `origin/*` — the exact value the gate stores when the user accepts the broader-scope
 * option — covered nothing, and no row could ever say "any tag of myrepo/app".
 */
import { describe, expect, it } from "vitest"
import {
	coversByGrammar,
	describeTarget,
	grammarFor,
	imageCovers,
	isProtectedBranch,
	namedByUserStructurally,
	parseImageRef,
	parseVcsTarget,
	PROTECTED_BRANCH_RE,
	vcsCovers,
} from "./target-grammar.ts"

/** The git-ref rows a reported push session measured, in the order its expected column is written. */
const VCS_ROW_TABLE = [
	"*",
	"origin",
	"origin/",
	"feature/ABC123",
	"ABC123",
	"origin/*",
	"origin/feature/*",
	"refs/heads/feature/ABC123",
	"master",
	"any branch",
	"branch",
	"origin/feature/ABC123",
]

const VCS_ROW_EXPECTED = [true, true, true, true, true, true, true, true, false, undefined, false, true]

describe("git ref coverage against the gate's own target form", () => {
	it("reproduces the row table for a pending push to origin/feature/ABC123", () => {
		const rows = VCS_ROW_TABLE.map((row) => vcsCovers(row, "origin/feature/ABC123"))
		expect(rows).toEqual(VCS_ROW_EXPECTED)
	})

	it("reads the parse behind that table", () => {
		expect(parseVcsTarget("origin/feature/ABC123")).toEqual({ remote: "origin", branch: "feature/ABC123" })
		expect(parseVcsTarget("origin/*")).toEqual({ remote: "origin", anyBranch: true })
		expect(parseVcsTarget("origin/feature/*")).toEqual({ remote: "origin", branchGlob: "feature/" })
		expect(parseVcsTarget("origin", "origin")).toEqual({ remote: "origin", anyBranch: true })
		expect(parseVcsTarget("origin/", "origin")).toEqual({ remote: "origin", anyBranch: true })
		expect(parseVcsTarget("origin/")).toEqual({ branch: "origin" }) // a bare word is a branch unless it is the pending's remote
		expect(parseVcsTarget("origin/", "upstream")).toEqual({ branch: "origin" })
		expect(parseVcsTarget("origin", "upstream")).toEqual({ branch: "origin" })
		expect(parseVcsTarget("refs/heads/feature/ABC123")).toEqual({ branch: "feature/ABC123" })
		expect(parseVcsTarget("refs/remotes/origin/feat/x")).toEqual({ remote: "origin", branch: "feat/x" })
		expect(parseVcsTarget("feat/x")).toEqual({ branch: "feat/x" })
		expect(parseVcsTarget("origin/(current branch)")).toEqual({ remote: "origin", branchUnknown: true })
		expect(parseVcsTarget("*")).toEqual({ anyRemote: true, anyBranch: true })
	})

	it("never parses prose or a URL", () => {
		expect(parseVcsTarget("any branch")).toBeUndefined()
		expect(parseVcsTarget("push it to origin please")).toBeUndefined()
		expect(parseVcsTarget("https://github.com/a/b")).toBeUndefined()
		expect(parseVcsTarget("/home/u/dev/pm")).toBeUndefined()
		expect(parseVcsTarget("")).toBeUndefined()
	})

	it("reads the remote side of a refspec as the branch", () => {
		for (const spec of ["HEAD:feat/x", ":feat/x", "local:feat/x", "+HEAD:feat/x", "+feat/x"]) {
			// The remote came from the push's argument, never from this string, so it is not part of the row.
			expect(parseVcsTarget(spec, "origin"), spec).toEqual({ branch: "feat/x" })
		}
		expect(parseVcsTarget("HEAD:feat/x")).toEqual({ branch: "feat/x" })
		expect(parseVcsTarget("HEAD:")).toBeUndefined()
		expect(parseVcsTarget("HEAD:feat:x")).toBeUndefined()
	})

	it("returns undefined when either side is unreadable, never false", () => {
		expect(vcsCovers("any branch", "origin/feature/ABC123")).toBeUndefined()
		expect(vcsCovers("origin/*", "some prose here")).toBeUndefined()
		expect(vcsCovers("refs/tags/v1.0", "origin/feature/x")).toBeUndefined() // tags are not refs this grammar reads
		expect(vcsCovers("origin/a*b", "origin/feature/x")).toBeUndefined() // a star off the end is not a shape here
	})

	it("keeps git's case sensitivity on both sides of a match", () => {
		expect(vcsCovers("origin/Feature-ABC123", "origin/feature-ABC123")).toBe(false)
		expect(vcsCovers("Upstream/feature-ABC123", "upstream/feature-ABC123")).toBe(false)
	})

	it("a target with no branch at all (`git push --mirror origin`) is reachable only by `*`", () => {
		expect(parseVcsTarget("origin")).toEqual({ branch: "origin" }) // a bare word is only a remote against a pending
		expect(vcsCovers("*", "origin")).toBe(true)
		expect(vcsCovers("origin", "origin")).toBe(false)
		expect(vcsCovers("origin/*", "origin")).toBe(false)
	})

	it("covers only `*` when the pending branch is not named", () => {
		const results = VCS_ROW_TABLE.map((row) => ({ row, covered: vcsCovers(row, "origin/(current branch)") }))
		expect(results.filter((r) => r.covered === true).map((r) => r.row)).toEqual(["*"])
		expect(vcsCovers("origin", "origin/(current branch)")).toBe(false)
		expect(vcsCovers("origin/*", "origin/(current branch)")).toBe(false)
		expect(vcsCovers("origin/feature/ABC123", "origin/(current branch)")).toBe(false)
	})
})

describe("protected branches are excluded from all-branches rows", () => {
	it("copies the list layer 0 uses (risk-handlers.ts PROTECTED_BRANCH_RE)", () => {
		expect(PROTECTED_BRANCH_RE.source).toBe("^(main|master|trunk|develop|dev|release[\\/-].*|production|prod|stable)$")
		expect(PROTECTED_BRANCH_RE.flags).toBe("i")
	})
	it.each(["main", "master", "release/1.0", "release-1.0", "develop", "dev", "trunk", "production", "prod", "stable"])(
		"`origin/*` does not cover %I",
		(branch) => {
			expect(isProtectedBranch(branch)).toBe(true)
			expect(vcsCovers("origin/*", `origin/${branch}`)).toBe(false)
			expect(vcsCovers("origin/feature/*", `origin/${branch}`)).toBe(false)
		},
	)

	it("names protected branches as not-protected examples too", () => {
		expect(isProtectedBranch("feature/ABC123")).toBe(false)
		expect(isProtectedBranch("releases/1.0")).toBe(false)
		expect(isProtectedBranch("mainline")).toBe(false)
	})

	it("a row that names the protected branch still covers it", () => {
		expect(vcsCovers("origin/main", "origin/main")).toBe(true)
		expect(vcsCovers("main", "origin/main")).toBe(true)
	})

	it("the bare-verb `*` row keeps its meaning: it covers protected branches too", () => {
		expect(vcsCovers("*", "origin/main")).toBe(true)
	})

	it("globs match a path prefix and nothing looser", () => {
		expect(vcsCovers("origin/feature/*", "origin/feature/ABC123")).toBe(true)
		expect(vcsCovers("origin/feature/*", "origin/fix/x")).toBe(false)
		expect(vcsCovers("origin/feature/*", "origin/featureX")).toBe(false)
	})

	it("never matches a branch by prefix or substring", () => {
		expect(vcsCovers("origin/feature/x", "origin/feature/x-prod")).toBe(false)
		expect(vcsCovers("origin/feature", "origin/feature/ABC123")).toBe(false)
		expect(vcsCovers("origin/ABC123", "origin/feature/ABC123")).toBe(true) // today's basename rule
	})

	it("refspecs cover the branch they name and no longer one", () => {
		for (const spec of ["HEAD:feat/x", "+feat/x", ":feat/x"]) {
			expect(vcsCovers(spec, "origin/feat/x"), spec).toBe(true)
			expect(vcsCovers(spec, "origin/feat/x2"), spec).toBe(false)
		}
	})

	it("a row naming another remote covers nothing on this one", () => {
		expect(vcsCovers("upstream/*", "origin/feature/x")).toBe(false)
		expect(vcsCovers("upstream/feature/x", "origin/feature/x")).toBe(false)
		expect(vcsCovers("origin/*", "upstream/feature/x")).toBe(false)
	})
})

// ------------------------------------------------------------------ images

/** The image rows a reported publish session measured against `network_send myrepo/app:1.0`. */
const IMAGE_ROW_TABLE = ["myrepo", "myrepo/app", "myrepo/app:1.0", "app", "ghcr.io", "docker", "*"]
const IMAGE_ROW_EXPECTED = [false, true, true, true, false, false, true]

describe("container image coverage against the gate's own target form", () => {
	it("reproduces the row table for a pending push of myrepo/app:1.0", () => {
		expect(IMAGE_ROW_TABLE.map((row) => imageCovers(row, "myrepo/app:1.0"))).toEqual(IMAGE_ROW_EXPECTED)
	})

	it("reads the parse behind that table", () => {
		expect(parseImageRef("myrepo/app:1.0")).toEqual({ repo: "myrepo/app", tag: "1.0" })
		expect(parseImageRef("myrepo/app")).toEqual({ repo: "myrepo/app" })
		expect(parseImageRef("app")).toEqual({ repo: "app" })
		expect(parseImageRef("ghcr.io")).toEqual({ registry: "ghcr.io" })
		expect(parseImageRef("ghcr.io/")).toEqual({ registry: "ghcr.io" })
		expect(parseImageRef("ghcr.io/org/app")).toEqual({ registry: "ghcr.io", repo: "org/app" })
		expect(parseImageRef("localhost:5000/app:latest")).toEqual({ registry: "localhost:5000", repo: "app", tag: "latest" })
		expect(parseImageRef("ghcr.io:8443/org/app@sha256:abc")).toEqual({
			registry: "ghcr.io:8443",
			repo: "org/app",
			digest: "sha256:abc",
		})
		expect(parseImageRef("*")).toEqual({ anyImage: true })
	})

	it("never parses a path, a URL or prose as an image", () => {
		expect(parseImageRef("https://ghcr.io/x")).toBeUndefined()
		expect(parseImageRef("./a")).toBeUndefined()
		expect(parseImageRef("/var/lib/app")).toBeUndefined()
		expect(parseImageRef("~/app")).toBeUndefined()
		expect(parseImageRef("push the image")).toBeUndefined()
		expect(parseImageRef("myrepo/*")).toBeUndefined() // no repo globs: the caller keeps its own rule
	})

	it("a registry alone covers anything in that registry and nothing elsewhere", () => {
		expect(imageCovers("ghcr.io", "ghcr.io/org/app:2")).toBe(true)
		expect(imageCovers("ghcr.io/", "ghcr.io/org/app")).toBe(true)
		expect(imageCovers("ghcr.io", "myrepo/app:1.0")).toBe(false)
		expect(imageCovers("myrepo/app", "ghcr.io/myrepo/app:1.0")).toBe(false) // a row with no registry is not host-less here
		expect(imageCovers("ghcr.io/org/app", "ghcr.io/org/app:1.0")).toBe(true)
	})

	it("a row with a tag or digest pins it", () => {
		expect(imageCovers("myrepo/app:1.0", "myrepo/app:2.0")).toBe(false)
		expect(imageCovers("myrepo/app:1.0", "myrepo/app")).toBe(false)
		expect(imageCovers("myrepo/app@sha256:aaa", "myrepo/app@sha256:bbb")).toBe(false)
		expect(imageCovers("myrepo/app@sha256:aaa", "myrepo/app@sha256:aaa")).toBe(true)
		expect(imageCovers("myrepo/app", "myrepo/app@sha256:aaa")).toBe(true) // no tag named = any tag
	})

	it("returns undefined when either side is unreadable, never false", () => {
		expect(imageCovers("docker push", "myrepo/app:1.0")).toBeUndefined()
		expect(imageCovers("myrepo/app", "https://x/y")).toBeUndefined()
	})
})

// --------------------------------------------------------------- dispatch + text

describe("grammar selection is by category, never by shape", () => {
	it("maps the four publish categories and nothing else", () => {
		expect(grammarFor("vcs_remote")).toBe("vcs")
		expect(grammarFor("vcs_force_protected")).toBe("vcs")
		expect(grammarFor("container_mutation")).toBe("image")
		expect(grammarFor("network_send")).toBe("image")
		expect(grammarFor("fs-write")).toBeUndefined()
		expect(grammarFor("read_secret")).toBeUndefined()
		expect(grammarFor("constructor")).toBeUndefined()
		expect(grammarFor("  ")).toBeUndefined()
	})

	it("dispatches coversByGrammar and stays silent without a grammar", () => {
		expect(coversByGrammar("vcs_remote", "origin/*", "origin/feature/x")).toBe(true)
		expect(coversByGrammar("vcs_force_protected", "origin/*", "origin/main")).toBe(false)
		expect(coversByGrammar("network_send", "myrepo/app", "myrepo/app:1.0")).toBe(true)
		expect(coversByGrammar("container_mutation", "myrepo/app", "myrepo/app:1.0")).toBe(true)
		expect(coversByGrammar("fs-write", "origin/*", "origin/feature/x")).toBeUndefined()
		// A compound category is the caller's to split; a segment list has no grammar of its own.
		expect(coversByGrammar("container_mutation+network_send", "myrepo/app", "myrepo/app:1.0")).toBeUndefined()
		expect(coversByGrammar("vcs_remote", "any branch", "origin/feature/x")).toBeUndefined()
	})
})

describe("does the user's own wording name this row?", () => {
	it("accepts the wording a user actually writes", () => {
		expect(namedByUserStructurally("vcs_remote", "origin/*", "you can push any branch to origin")).toBe(true)
		expect(namedByUserStructurally("vcs_remote", "origin/feature/ABC123", "push feature/ABC123 to origin")).toBe(true)
		expect(namedByUserStructurally("vcs_remote", "origin/feature/ABC123", "push it to origin")).toBe(false)
		expect(namedByUserStructurally("vcs_remote", "feature/ABC123", "go ahead with ABC123")).toBe(true)
	})

	it("requires a whole token, not a substring", () => {
		expect(namedByUserStructurally("vcs_remote", "origin/feature/ABC123", "push ABC1234 to origin")).toBe(false)
		expect(namedByUserStructurally("vcs_remote", "origin/feature/ABC123", "push abc123 to origin")).toBe(true) // case-insensitive
		expect(namedByUserStructurally("vcs_remote", "origin/*", "originally I meant main")).toBe(false)
	})

	it("names a glob row by the prefix it scopes", () => {
		expect(namedByUserStructurally("vcs_remote", "origin/feature/*", "any feature branch on origin")).toBe(true)
		expect(namedByUserStructurally("vcs_remote", "origin/feature/*", "any branch on origin")).toBe(false)
	})

	it("names image rows by registry and repo", () => {
		expect(namedByUserStructurally("network_send", "myrepo/app:1.0", "push myrepo/app")).toBe(true)
		expect(namedByUserStructurally("container_mutation", "ghcr.io/org/app", "push ghcr.io/org/app:2")).toBe(true)
		expect(namedByUserStructurally("network_send", "myrepo/app", "push the image please")).toBe(false)
	})

	it("a row that names nothing gives no structural evidence", () => {
		expect(namedByUserStructurally("vcs_remote", "*", "do whatever you like")).toBe(false)
		expect(namedByUserStructurally("network_send", "*", "push anything")).toBe(false)
	})

	it("undefined when there is no grammar or the row does not parse", () => {
		expect(namedByUserStructurally("fs-write", "origin/*", "push it to origin")).toBeUndefined()
		expect(namedByUserStructurally("vcs_remote", "any branch", "push any branch")).toBeUndefined()
	})
})

describe("describeTarget", () => {
	it("says what each stored value means", () => {
		expect(describeTarget("vcs_remote", "origin/*")).toBe("all branches on origin")
		expect(describeTarget("vcs_remote", "origin/feature/x")).toBe("origin/feature/x")
		expect(describeTarget("vcs_remote", "feature/x")).toBe("branch feature/x on any remote")
		expect(describeTarget("network_send", "myrepo/app")).toBe("any tag of myrepo/app")
		expect(describeTarget("network_send", "myrepo/app:1.0")).toBe("myrepo/app:1.0")
	})

	it("covers the shapes the table does not list", () => {
		expect(describeTarget("vcs_remote", "*")).toBe("any branch on any remote")
		expect(describeTarget("vcs_remote", "origin/feature/*")).toBe("all branches on origin matching feature/*")
		expect(describeTarget("vcs_remote", "origin/(current branch)")).toBe("the branch being pushed to origin")
		expect(describeTarget("vcs_remote", "refs/heads/feat/x")).toBe("branch feat/x on any remote")
		expect(describeTarget("container_mutation", "*")).toBe("any image on any registry")
		expect(describeTarget("container_mutation", "ghcr.io")).toBe("every image in ghcr.io")
		expect(describeTarget("network_send", "ghcr.io/org/app:2")).toBe("ghcr.io/org/app:2")
		expect(describeTarget("network_send", "myrepo/app@sha256:abc")).toBe("myrepo/app@sha256:abc")
	})

	it("says nothing when there is no grammar or nothing parsed", () => {
		expect(describeTarget("fs-write", "origin/*")).toBeUndefined()
		expect(describeTarget("vcs_remote", "any branch")).toBeUndefined()
		expect(describeTarget("network_send", "./src/app.ts")).toBeUndefined()
	})
})
