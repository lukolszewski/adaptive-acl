/**
 * Denial-message precision. The gate's job is not only to decide but to tell the
 * agent WHY, so it can rewrite instead of bouncing to the user. Measured
 * justification: docs/DENY-MESSAGES-PLAN.md.
 *
 * The last block guards a different property: every sentence in this file is advice an agent acts on, so
 * it may only name a capability the extension actually provides. That is checked against `index.ts`, the
 * one place a tool can be registered, rather than asserted against a list kept here.
 */
import { describe, expect, it } from "vitest"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import {
	buildPreciseDenial,
denialFamily,
	futilityFor,
	gateDenialMessage,
	unattendedEscalation,
	UNATTENDED_PARK_AFTER_HUMAN_DENIAL,
	wallFor,
} from "./gate-bridge.ts"
import type { GateResult } from "./gate.ts"

type Seg = { tier: string; category: string; command: string; targets?: string[] }

function result(opts: {
	tier?: "allow" | "ask" | "never"
	category?: string
	description?: string
	reason?: string
	unparseable?: boolean
	segments?: Seg[]
	entities?: Array<{ kind: string; value: string }>
}) {
	const segments = (opts.segments ?? []).map((s) => ({
		tier: s.tier,
		category: s.category,
		command: s.command,
		description: s.command,
		entities: (s.targets ?? []).map((value) => ({ kind: "target", value })),
	}))
	return {
		outcome: "prompt",
		tier: opts.tier ?? "ask",
		category: opts.category ?? segments[0]?.category ?? "unknown_command",
		entities: opts.entities ?? [],
		description: opts.description ?? "run a command",
		reason: opts.reason ?? "model: not authorised by the user",
		unparseable: opts.unparseable,
		policy: {
			tier: opts.tier ?? "ask",
			category: opts.category ?? "unknown_command",
			entities: opts.entities ?? [],
			description: opts.description ?? "run a command",
			reason: opts.reason ?? "",
			segments,
			unknown: [],
		},
		modelCalls: [],
	} as unknown as GateResult
}

describe("futility", () => {
	it("is never for a never-tier verdict", () => {
		expect(futilityFor({ tier: "never" })).toBe("never")
		expect(futilityFor({ tier: "never", unattended: true })).toBe("never")
	})
	it("is rewrite when no human can answer", () => {
		expect(futilityFor({ tier: "ask", unattended: true })).toBe("only-after-rewrite")
	})
	it("is rewrite when the command could not be parsed", () => {
		expect(futilityFor({ tier: "ask", unparseable: true })).toBe("only-after-rewrite")
	})
	it("is user approval when a human is there to ask", () => {
		expect(futilityFor({ tier: "ask" })).toBe("only-with-user-approval")
	})
})

describe("buildPreciseDenial", () => {
	it("names the mechanism and a rewrite for a substitution", () => {
		const msg = buildPreciseDenial({
			head: "Not auto-approved: echo",
			segments: [{ command: 'echo "$(date)"', category: "unproven_value", targets: [] }],
			futility: "only-after-rewrite",
		})
		expect(msg).toContain("DENIED:")
		expect(msg).toContain("command substitution")
		expect(msg).toContain("FIX:")
		expect(msg).toContain("run the substitution as its own read-only call")
		expect(msg).toContain("RETRY: only after you change the command")
	})

	it("names only the offending segment, not harmless siblings in the chain", () => {
		const msg = buildPreciseDenial({
			head: "Not auto-approved",
			segments: [{ command: "ln -sfn /a /x/x/node_modules", category: "write_outside", targets: ["/x/x/node_modules"] }],
			futility: "only-after-rewrite",
		})
		expect(msg).toContain("/x/x/node_modules")
		expect(msg).not.toContain("echo done")
		expect(msg).not.toContain("npm test")
		// Inverse of the same rule: the omission above is about WHICH segments were passed (the
		// caller filters to blocked ones), not a builder that drops commands. Give it the sibling as a
		// blocked segment and it must appear — otherwise "only the offending segment" could be passing
		// for any bug that loses commands entirely.
		const both = buildPreciseDenial({
			head: "Not auto-approved",
			segments: [
				{ command: "echo done", category: "unknown_command", targets: [] },
				{ command: "ln -sfn /a /x/x/node_modules", category: "write_outside", targets: ["/x/x/node_modules"] },
			],
			futility: "only-after-rewrite",
		})
		expect(both).toContain("echo done")
		expect(both).toContain("ln -sfn /a /x/x/node_modules")
		expect(both.split("DENIED:").length - 1).toBe(2)
	})

	it("summarises segments beyond the third", () => {
		const segs = Array.from({ length: 5 }, (_x, i) => ({
			command: `cmd${i}`,
			category: "unknown_command",
			targets: [],
		}))
		expect(buildPreciseDenial({ head: "x", segments: segs, futility: "never" })).toContain("(+2 more blocked segments)")
	})

	it("names a secret path but never its contents", () => {
		const SECRET = "hunter2-material-never-echoed"
		const msg = buildPreciseDenial({
			head: "Not auto-approved",
			segments: [{ command: "grep aws ~/.aws/credentials", category: "read_secret", targets: ["~/.aws/credentials"] }],
			futility: "only-with-user-approval",
		})
		expect(msg).toContain("~/.aws/credentials")
		expect(msg).toContain("Never print the contents")
		expect(msg).not.toContain(SECRET)
		// The actionable route must arrive with the path FILLED IN: `fix` strings are templated from
		// the segment target just like `mechanism` is, and if that wiring is ever dropped the guidance
		// silently degrades into a literal placeholder an agent cannot act on.
		expect(msg).toContain("Read(~/.aws/credentials)")
		expect(msg).not.toContain("{target}")
		// Inverse of the `{target}` check: the template is not merely absent, the substitution happened.
		expect(msg).toContain("this reads a secret-bearing path (~/.aws/credentials)")
		// "grant a narrower read path" was the old advice and is wrong for a secret: narrowing to a
		// non-secret sibling never reaches the path that was blocked.
		expect(msg).not.toContain("narrower read path")
		// Inverse of that negation: what replaces it must be present, or the assertion only proves
		// a string was deleted, not that the right route is offered.
		expect(msg).toMatch(/folder glob will not reach a secret/i)
		expect(msg).toMatch(/add a rule naming the exact path/i)
	})

	it("still gives a fix for a category with no specific guidance", () => {
		const msg = buildPreciseDenial({
			head: "x",
			segments: [{ command: "weird-tool run", category: "made_up_category", targets: [] }],
			futility: "only-after-rewrite",
		})
		expect(msg).toContain("FIX:")
		expect(msg).toContain("literal arguments")
		// The rest of the fallback line is the operative part, and until now nothing asserted it
		// survives: "literal arguments" alone would still pass if the clause naming the two things to
		// avoid (substitution, chaining) had been dropped.
		expect(msg).toContain("Split this into separate calls")
		expect(msg).toMatch(/no substitution, no chaining/)
		expect(msg).toMatch(/keeping targets inside the project/)
		// The same fallback backs the mechanism line for an unknown category.
		expect(msg).toMatch(/could not establish that this is safe/i)
	})
})

describe("wall type", () => {
	it("sees analysis walls as things a rewrite can fix", () => {
		for (const c of ["unproven_value", "unproven_structure", "unparseable_command", "interpreter_unknown", "unknown_command"]) {
			expect(wallFor(c)).toBe("analysis")
		}
	})
	it("sees authority walls as things only a person can clear", () => {
		for (const c of ["write_outside", "delete_outside", "read_secret", "privilege", "vcs_remote"]) {
			expect(wallFor(c)).toBe("authority")
		}
	})
})

describe("denialFamily", () => {
	it("survives a rewrite of an analysis denial", () => {
		const a = denialFamily({ tool: "bash", category: "unproven_value", targets: [] })
		const b = denialFamily({ tool: "bash", category: "unproven_structure", targets: [] })
		expect(a).toBe(b)
	})
	it("keeps retries at the same place together", () => {
		const a = denialFamily({ tool: "bash", category: "write_outside", targets: ["/x/x/a/node_modules"] })
		const b = denialFamily({ tool: "bash", category: "write_outside", targets: ["/x/x/b/node_modules"] })
		expect(a).toBe(b)
	})
	it("does not merge unrelated targets into one escalation", () => {
		const a = denialFamily({ tool: "bash", category: "write_outside", targets: ["/x/x/a/f.ts"] })
		const b = denialFamily({ tool: "bash", category: "write_outside", targets: ["/y/y/g/f.ts"] })
		expect(a).not.toBe(b)
	})
})

describe("unattended ladder", () => {
	it("offers neither parking nor asking on the first denial", () => {
		for (const wall of ["analysis", "authority"] as const) {
			const msg = unattendedEscalation({ wall, attempt: 1, tier: "ask" })
			expect(msg).toMatch(/do NOT park/i)
			expect(msg).toMatch(/do not ask the user yet/i)
			expect(msg).toMatch(/keep working/i)
		}
	})
	it("parks after a person already said no, without inviting a rewrite", () => {
		// Asserted PRESENT first: an earlier revision of this file only ever asserted texts were
		// absent, so "a rung exists" was never actually evidence of anything.
		expect(UNATTENDED_PARK_AFTER_HUMAN_DENIAL).toMatch(/a person denied this/i)
		expect(UNATTENDED_PARK_AFTER_HUMAN_DENIAL).toMatch(/do not rewrite it and do not ask again/i)
		expect(UNATTENDED_PARK_AFTER_HUMAN_DENIAL).toMatch(/list it in your end-of-run report/i)
		// Inverse of "do not rewrite": a human denial must not read like the rewrite-first rung.
		expect(UNATTENDED_PARK_AFTER_HUMAN_DENIAL).not.toMatch(/clear on the first rewrite/i)
	})
	it("pushes a second rewrite before it lets the agent stop, on an analysis wall", () => {
		const msg = unattendedEscalation({ wall: "analysis", attempt: 2, tier: "ask" })
		expect(msg).toMatch(/genuinely different shape/i)
		// The sentence used to end "If that also fails, ask the user." — an instruction with no addressee:
		// an unattended session has no way to put a question in front of anybody.
		expect(msg).toMatch(/an ask cannot be answered in this run/i)
		// Inverse of the pin this file used to hold ("the rung that sends the agent to the person must name
		// the tool"): the rung that DOES stop the agent must name the action that replaced the call,
		// otherwise the negations would also pass on a rung that gives no advice at all.
		const authority = unattendedEscalation({ wall: "authority", attempt: 2, tier: "ask" })
		expect(authority).toMatch(/park the step/i)
		expect(authority).toMatch(/end-of-run report/i)
	})
	it("sends a second authority denial to the report, with enough to answer in one reply", () => {
		const msg = unattendedEscalation({ wall: "authority", attempt: 2, tier: "ask" })
		expect(msg).toMatch(/park the step/i)
		expect(msg).toMatch(/narrowest rule/)
		expect(msg).toMatch(/exact target/)
		// What the agent is told instead of a dialog: the deny is final for this run, so it must not sit
		// there waiting for a prompt that will never arrive.
		expect(msg).toMatch(/Nobody is watching this session/i)
		expect(msg).toMatch(/nothing is waiting for an answer/i)
	})
	it("parks with a report rather than stalling, at three", () => {
		const msg = unattendedEscalation({ wall: "analysis", attempt: 3, tier: "ask" })
		expect(msg).toMatch(/Park it now/)
		expect(msg).toMatch(/end-of-run report/)
	})
	it("does not waste a rewrite budget on a never verdict", () => {
		const msg = unattendedEscalation({ wall: "authority", attempt: 1, tier: "never" })
		expect(msg).toMatch(/only a human can clear it/)
		expect(msg).toMatch(/park it/i)
		expect(msg).toMatch(/end-of-run report/i)
		// And it says who is missing, so the agent does not go looking for a prompt.
		expect(msg).toMatch(/no prompt can be shown/i)
		expect(msg).toMatch(/nobody is there to answer/i)
	})
	it("promises no answer that cannot arrive — no wait, no timeout, no pending prompt", () => {
		// The old rungs promised "the request waits up to 10 minutes and fails closed" for a request the
		// runtime cannot make. A bounded wait would be a promise to keep the worker idle with nobody
		// listening; the honest version is that the deny is the answer.
		for (const msg of EVERY_RUNG) {
			expect(msg, msg).not.toMatch(/\bfails closed\b/)
			expect(msg, msg).not.toMatch(/\b\d+ ?(minutes?|seconds?)\b/)
			expect(msg, msg).not.toMatch(/\bwaits\b/i)
		}
		// Inverse: the rungs that end the rewrite loop DO say where the answer comes from, so the three
		// negations above are a routing change and not a deleted instruction.
		for (const msg of STOPPING_RUNGS) expect(msg).toMatch(/end-of-run report/i)
	})
})

describe("the denial text agrees with the tools that exist", () => {
	it("names no tool the extension does not register", () => {
		const registered = registeredToolNames()
		// The scan has to find something, or every assertion below passes because it found nothing.
		expect(registered.has("plan_ready")).toBe(true)
		for (const msg of EVERY_RUNG) expect(toolNamesNotRegistered(msg, registered), msg).toEqual([])
	})

	it("both halves of that check work: a name is found, and an unregistered one fails", () => {
		// Written against the rung this task deleted, verbatim. Without it, a regex that stopped matching or
		// a scan that found no registered names would make the test above vacuous — the failure mode this
		// repo has already been bitten by: a negative assertion nobody checked the inverse of.
		const registered = registeredToolNames()
		// The negative half needs a name that will never be real, because `request_user_permission` became real in
		// index.ts (D11) — keeping it here would assert that a registered tool is unregistered, which is exactly the
		// vacuous-fixture trap this file exists to avoid.
		const decoyRung =
			" Ask the user now with request_somebody_else_permission (the request waits up to 10 minutes and fails closed — if nobody answers, move on)"
		expect(toolNamesNotRegistered(decoyRung, registered)).toEqual(["request_somebody_else_permission"])
		// The allow side, and it is now the name that used to be the decoy: the tool was registered, so naming it is
		// a sentence an agent can actually act on.
		expect(
			toolNamesNotRegistered(
				"Ask the user now with request_user_permission before retrying",
				registered,
			),
		).toEqual([])
		expect(toolNamesNotRegistered("call plan_ready to submit the plan", registered)).toEqual([])
	})
})

/** Everything shaped like a tool name inside a message an agent will act on. */
const TOOL_SHAPED = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g

/** The tool-shaped names in `text` that are NOT registered — the offenders, so a failure prints them. */
function toolNamesNotRegistered(text: string, registered: Set<string>): string[] {
	return (text.match(TOOL_SHAPED) ?? []).filter((name) => !registered.has(name))
}

/**
 * Tool names `index.ts` actually registers, read off its source. Not imported: the entry point registers
 * hooks on a live `pi` object, and the agreement being tested is between the shipped TEXT and the shipped
 * REGISTRATION, both of which are source facts. `index.ts` is read-only for this file.
 */
function registeredToolNames(): Set<string> {
	const src = readFileSync(join(import.meta.dirname, "index.ts"), "utf8")
	// The house pattern for a tool name used more than once: `const X_TOOL_NAME = "x"`.
	const constants = new Map<string, string>()
	for (const m of src.matchAll(/const\s+([A-Z0-9_]+)\s*=\s*"([^"]+)"/g)) constants.set(m[1]!, m[2]!)
	const names = new Set<string>()
	for (const m of src.matchAll(/registerTool\([\s\S]{0,400}?name:\s*("[^"]+"|[A-Za-z_][\w.]*)/g)) {
		const field = m[1]
		if (!field) continue
		const resolved = field.startsWith('"') ? field.slice(1, -1) : constants.get(field)
		if (resolved) names.add(resolved)
	}
	return names
}

/** The ladder, every rung the module can produce without `humanPresent`. */
const LADDER_INPUTS = [
	{ wall: "analysis", attempt: 1, tier: "ask" },
	{ wall: "authority", attempt: 1, tier: "ask" },
	{ wall: "analysis", attempt: 2, tier: "ask" },
	{ wall: "authority", attempt: 2, tier: "ask" },
	{ wall: "analysis", attempt: 3, tier: "ask" },
	{ wall: "authority", attempt: 9, tier: "ask" },
	{ wall: "analysis", attempt: 1, tier: "never" },
	{ wall: "authority", attempt: 1, tier: "never" },
] as const

/**
 * The rung texts plus one control that names a registered tool, so the loop over them is not vacuously
 * empty. The control that must FAIL lives in the vacuity test above (the deleted rung).
 */
const EVERY_RUNG: string[] = [
	...LADDER_INPUTS.map((one) => unattendedEscalation(one)),
	"call plan_ready to submit the plan",
]

/** The rungs that end the rewrite loop — the ones that must leave a decision a person can act on. */
const STOPPING_RUNGS = [
	unattendedEscalation({ wall: "authority", attempt: 2, tier: "ask" }),
	unattendedEscalation({ wall: "analysis", attempt: 3, tier: "ask" }),
	unattendedEscalation({ wall: "authority", attempt: 1, tier: "never" }),
]

describe("gateDenialMessage", () => {
	it("drops the decider-only reason and the lumped affected list", () => {
		const msg = gateDenialMessage(
			result({
				description: "create link outside the project",
				category: "read_only+write_outside",
				segments: [
					{ tier: "allow", category: "read_only", command: "echo done" },
					{ tier: "ask", category: "write_outside", command: "ln -sfn /a /x/x/nm", targets: ["/x/x/nm"] },
				],
				entities: [{ kind: "target", value: "/x/x/nm" }],
			}),
		)
		expect(msg).not.toContain("not authorised by the user")
		expect(msg).not.toContain("Affected:")
		expect(msg).toContain("authority wall")
		expect(msg).toContain("ln -sfn /a /x/x/nm")
		expect(msg).not.toContain("echo done")
		// Inverses. Both negations say information is NOT printed in the old lumped form; that is only
		// useful if the same information IS printed in the attributed form.
		// `reason` is a decider's private prose (and here it is a fake), so it goes — but category and
		// target must arrive. The head line carries the WHOLE-call category as layer 0 rendered it (a
		// compound: the harmless leg is not hidden either), while the DENIED line names the leg.
		expect(msg).toContain("category: read_only+write_outside")
		expect(msg).toContain("target: /x/x/nm")
		expect(msg).toContain("decided by:")
		// And `echo done` is absent because it is tier `allow`, not because the builder lost it:
		// make it a blocked leg and its own line appears.
		const compound = gateDenialMessage(
			result({
				category: "unknown_command+write_outside",
				segments: [
					{ tier: "ask", category: "unknown_command", command: "echo done" },
					{ tier: "ask", category: "write_outside", command: "ln -sfn /a /x/x/nm", targets: ["/x/x/nm"] },
				],
			}),
		)
		expect(compound).toContain("echo done")
	})

	it("tells an unattended agent to rewrite rather than to ask", () => {
		const msg = gateDenialMessage(result({ segments: [{ tier: "ask", category: "unproven_value", command: 'echo "$(date)"' }] }), {
			unattended: true,
		})
		expect(msg).toContain("RETRY: only after you change the command")
		expect(msg).not.toContain("Ask the user for approval")
		// Inverse: the RETRY line that DOES name the person, so the negation above is a routing
		// difference and not a deleted sentence. Two inputs reach it: no flag at all, and the flag with
		// a human present (where the flag, not the command, is the thing to change).
		expect(gateDenialMessage(result({}))).toContain("RETRY: only with the user's explicit approval. Ask them, naming the exact target.")
		expect(gateDenialMessage(result({}), { unattended: true, humanPresent: true })).toContain(
			"RETRY: only with the user's explicit approval",
		)
	})

	it("flags a never verdict as unfixable", () => {
		const msg = gateDenialMessage(
			result({ tier: "never", description: "destroy the disk", segments: [{ tier: "never", category: "disk_destroy", command: "mkfs /dev/sda" }] }),
		)
		expect(msg).toContain("Blocked (high-risk, never auto-approved)")
		expect(msg).toContain("RETRY: never by rewriting")
		// The half that was never asserted: the never line has to tell the agent what TO do, or it
		// reads as a dead end and the agent retries anyway.
		expect(msg).toMatch(/only a human can clear this/i)
		expect(msg).toMatch(/ask the user, or park it and report at the end/i)
		expect(msg).toMatch(/do not retry it and do not try a variant/i)
	})
})
