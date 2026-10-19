/**
 * Characterisation of what the AST layer already does with commands inside
 * `$( ... )`.
 *
 * This exists because a change was written for item 2 ("substitution
 * inheritance") on the assumption that an inner command hides behind generic
 * `unproven_value`. Inspection disproved that: where the walker succeeds, the
 * inner command is already emitted as its own classified segment, so the
 * inheritance edit only duplicated segments. These tests pin the behaviour that
 * is actually load-bearing, so the next reader does not rebuild the same thing,
 * and they pin the one case where the walker refuses.
 */
import { describe, expect, it } from "vitest"
import { evaluateBash } from "./risk-policy.ts"
import type { PolicyDecision } from "./risk-policy.ts"

const OPTS = { cwd: "/home/dev/proj", project: "/home/dev/proj", home: "/home/dev", fs: false }
const dec = (cmd: string): PolicyDecision => evaluateBash(cmd, OPTS)
const cats = (cmd: string) => dec(cmd).segments.map((s) => s.category)

describe("what is inside a substitution is already analysed", () => {
	it("a delete inside a substitution is classified as a delete", () => {
		const cmd = 'echo "$(rm -rf ./build)"'
		expect(cats(cmd)).toContain("delete_recursive")
		expect(dec(cmd).tier).toBe("ask")
	})

	it("a disk operation inside a substitution reaches never", () => {
		expect(dec('echo "$(mkfs /dev/sda1)"').tier).toBe("never")
	})

	it("the inner segment says it came from a substitution", () => {
		expect(dec('echo "$(rm -rf ./build)"').segments.some((s) => s.description.includes("in command substitution"))).toBe(true)
	})

	it("an outer authority violation survives a benign inner command", () => {
		expect(["ask", "never"]).toContain(dec('cp "$(pwd)/x" /etc/y').tier)
	})

	it("a read-only inner command does not make the outer value proven", () => {
		const d = dec('cat "$(pwd)/f"')
		expect(d.tier).toBe("unknown")
		expect(d.category).toContain("unproven_value")
	})
})

describe("the refusal case the walker still cannot vouch for", () => {
	it("a quoted argument consisting only of a substitution is structure-unproven", () => {
		const d = dec('echo "$(date)"')
		expect(d.tier).toBe("unknown")
		// Not unproven_value: the walker refuses the construct itself, so the whole
		// command comes back structure-unproven and pays a model call. This is the
		// friction gap that remains, and it is a walker problem, not an
		// inner-command-analysis problem.
		expect(d.category).toBe("unproven_structure")
	})

	it("a secret read inside a substitution is reported as it really is", () => {
		const d = dec('echo "$(cat ~/.ssh/id_rsa)"')
		console.log("[characterise] secret-in-substitution:", d.tier, d.category, JSON.stringify(cats('echo "$(cat ~/.ssh/id_rsa)"')))
		// Pinned: must never come back `allow`.
		expect(d.tier).not.toBe("allow")
	})
})
