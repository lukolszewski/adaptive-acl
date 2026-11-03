/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The effect model's read verdict, end to end through `runGate`.
 *
 * The unit tests in `model-client.test.ts` pin the mapping. These pin the two things a mapping can get
 * right and the pipeline still get wrong:
 *
 *   1. the verdict really comes from the model path — every model-path command here is one layer 0 hands
 *      over as `unknown` with no read answer of its own, so an allow or a category without an effect call
 *      would mean the test had selected a command the walker can prove and had proved nothing (the shape
 *      of a trap a harness can fall into: one that cannot see a code path reports success on it silently);
 *   2. the verdict reaches the USER honestly. A `read_only` answer that prompted as `write_outside` told
 *      the user "this writes outside the project" about a `cat`, and offered them an approval no grant
 *      shape matches.
 *
 * The boundary of what layer 0 vouches for moved: `cat $(echo /tmp/cpu_gpu.txt)` used to need the model
 * because an unresolved read had no verdict, and now layer 0 answers it — an outside read asks either way.
 * So the commands that exercise the model path are the ones whose leg is a command layer 0 does not know
 * (`parallel`, `python3 script.py`) or a shape it refuses outright, never a plain `cat` with a fuzzy path.
 *
 * The effect answers are RECORDED completions: captured from a model's answer to the very segment text
 * layer 0 hands the model — `classifyEffect`, the same call the gate makes. Where a case needs an answer
 * the models did not give — a wrong one, to prove the fail-safe — it says so inline.
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { applyEvent, createLedger } from "./auth-ledger.ts"
import { runGate } from "./gate.ts"
import type { EffectClassification } from "./model-client.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }
const EP = { baseUrl: "http://mock", model: "mock" }
const MSGS = ["check what the temp file says"]

/**
 * Answer the gate's calls: the effect call gets `effectAnswer`, the authoriser says no (so an ask stays a
 * prompt instead of quietly becoming an allow-granted, which would hide the tier under test).
 */
function stubModel(effectAnswer: unknown): { tasks: string[] } {
	const tasks: string[] = []
	vi.stubGlobal("fetch", async (_url: string, init: Record<string, unknown>) => {
		const body = JSON.parse(String(init.body)) as { response_format?: { json_schema?: { name?: string } } }
		const isEffect = body.response_format?.json_schema?.name === "effect"
		tasks.push(isEffect ? "effect" : "grant")
		const payload = isEffect
			? effectAnswer
			: { authorized: "no", effects: [], allowed_targets: [], forbidden_targets: [], quote: "" }
		return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] }) } as unknown as Response
	})
	return { tasks }
}

const parsed = (json: string): EffectClassification => JSON.parse(json) as EffectClassification

/**
 * The command the model-path tests are driven with. Layer 0 knows no verb called `parallel`, so its only
 * leg is `unknown/unknown_command` with no entities: every category, object and tier below is the model's,
 * and nothing in this file can pass because a bash table happened to agree.
 */
const UNKNOWN_READ = "parallel cat :::: /tmp/list"

/** Recorded from a model's answer for `parallel cat :::: /tmp/list`. */
const TMP_READ = parsed('{"effect":"read_only","targets":["/tmp/list"],"outside_project":true,"confidence":"high"}')
/** Recorded from a model's answer for `parallel cat :::: ~/.ssh/id_ed25519` — the model
 *  called it what it is. */
const KEY_READ = parsed('{"effect":"read_secret","targets":["~/.ssh/id_ed25519"],"outside_project":true,"confidence":"high"}')
/** Recorded from a model's answer for
 *  `parallel cat :::: /home/other/.pi/agent/sessions/2026-01-01.jsonl`. */
const OTHER_HOME = parsed('{"effect":"read_only","targets":["/home/other/.pi/agent/sessions/2026-01-01.jsonl"],"outside_project":true,"confidence":"high"}')
/** `xargs -a "$LIST" cat` — recorded from a model's answer: the model saw the list as
 *  project-scoped, which is the answer that still has to reach allow. */
const XARGS_INSIDE = 'xargs -a "$LIST" cat'
const INSIDE_READ = parsed('{"effect":"read_only","targets":["files listed in $LIST"],"outside_project":false,"confidence":"high"}')
/** Recorded from a model's answer for `mapfile -t a < /tmp/x; cat "${a[0]}"` (layer 0
 *  refuses `mapfile`, so its own leg is unknown). */
const MAPFILE_READ_CMD = 'mapfile -t a < /tmp/x; cat "${a[0]}"'
const MAPFILE_READ = parsed('{"effect":"read_only","targets":["/tmp/x"],"outside_project":true,"confidence":"high"}')
/** Recorded from a model's answer for `for f in /tmp/a /tmp/b; do process $f; done`. */
const RUN_LOOP = "for f in /tmp/a /tmp/b; do process $f; done"
const RUN_LOOP_ANSWER = parsed('{"effect":"run_project_code","targets":["/tmp/a","/tmp/b"],"outside_project":true,"confidence":"high"}')

afterEach(() => {
	vi.unstubAllGlobals()
})

/** The gate's own evidence that the verdict was the model's: an effect call really happened. */
function effectCalls(r: { modelCalls: Array<{ task: string }> }): number {
	return r.modelCalls.filter((c) => c.task === "effect").length
}

describe("a read the effect model reported is a read — and outside the project it asks", () => {
	it("prompts for a read layer 0 cannot vouch for, on the objects the model named", async () => {
		const model = stubModel(TMP_READ)
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })

		// A read outside the project needs the user's permission, and the prompt describes a READ naming
		// the object, so one approval can cover the next read of the same place too.
		expect(r.outcome).toBe("prompt")
		expect(r.tier).toBe("ask")
		expect(r.category).toBe("read_only")
		expect(r.entities.map((e) => e.value)).toContain("/tmp/list")
		// Nothing here came from layer 0: its single leg is `unknown` and it named no entity at all.
		expect(r.policy.unknown).toHaveLength(1)
		expect(r.policy.segments.every((s) => s.entities.length === 0)).toBe(true)
		expect(effectCalls(r)).toBeGreaterThan(0)
		expect(model.tasks.filter((t) => t === "effect").length).toBeGreaterThan(0)
	})

	it("prompts for a compound whose read target only the model can name", async () => {
		stubModel(MAPFILE_READ)
		const r = await runGate("bash", { command: MAPFILE_READ_CMD }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(r.category).not.toBe("write_outside")
		expect(effectCalls(r)).toBeGreaterThan(0)
	})

	it("a read the model says stays inside the project still reaches allow", async () => {
		stubModel(INSIDE_READ)
		const r = await runGate("bash", { command: XARGS_INSIDE }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("allow")
		expect(r.policy.category).not.toContain("write_outside")
		expect(effectCalls(r)).toBeGreaterThan(0)
	})

	it("a recorded run answer for code outside the project asks as a run, on the model's own objects", async () => {
		// A recorded answer for the segment
		// `python3 /opt/tools/clean.py` (layer 0 refuses it: a script outside the project is `unknown_command`).
		stubModel({ effect: "run_project_code", targets: ["/opt/tools/clean.py"], outside_project: true, confidence: "high" })
		const r = await runGate("bash", { command: "python3 /opt/tools/clean.py" }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("run_project_code")
		expect(r.entities.map((e) => e.value)).toContain("/opt/tools/clean.py")
		expect(r.modelCalls.map((c) => c.task)).toContain("effect")
	})

	it("the same shape recorded for a loop asks as a run on the model's targets", async () => {
		stubModel(RUN_LOOP_ANSWER)
		const r = await runGate("bash", { command: RUN_LOOP }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("run_project_code")
		expect(r.entities.map((e) => e.value)).toContain("/tmp/a")
		expect(effectCalls(r)).toBeGreaterThan(0)
	})

	it("the same answer with nothing named still asks — and asks as a read", async () => {
		// The recorded shape above minus its targets: the object cannot even be named, and the gate asks
		// anyway — the prompt just has less to show, which is why naming the object still matters.
		stubModel({ ...TMP_READ, targets: [] })
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(r.category).not.toBe("write_outside")
	})

	it("an unresolvable target is not evidence, so it asks rather than allows", async () => {
		// Hand-built wrong answer (the models name concrete paths): the value is an unexpanded `$var`, so the
		// secret table cannot be applied to it. Unknown never means allow — and an outside read does not
		// even need to be unknown, since the read is outside the project.
		stubModel({ ...TMP_READ, targets: ["$CACHE/out.txt"] })
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
	})

	it("a secret named as the target of a read is reported as a secret read at the gate, not only in the mapping", async () => {
		// The recorded answer for the same shape with a key in place of the temp file: layer 0 saw nothing
		// secret (it has no verdict for `parallel` at all), so this is the model's category travelling to the
		// user — the prompt must not say "read" about a private key.
		stubModel(KEY_READ)
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_secret")
	})

	it("a target under a home that is not the session's asks as a read", async () => {
		// The shape of a script reading an agent's own session transcripts by absolute path. Recorded
		// answer; this needs no special rule — a path under another account is never inside this project —
		// but the two cases are pinned here so they stay prompts for the right reason.
		stubModel(OTHER_HOME)
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(r.category).not.toBe("write_outside")
	})
})

describe("what the model called a secret or a write is untouched by the read path", () => {
	it("the recorded read_secret answer asks as read_secret", async () => {
		stubModel(KEY_READ)
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_secret")
		expect(effectCalls(r)).toBeGreaterThan(0)
	})

	it("write_project reaching outside is still an ask, still write_outside", async () => {
		stubModel({ effect: "write_project", targets: ["/home/u/.config/app/conf.toml"], outside_project: true, confidence: "high" })
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("write_outside")
	})

	it("low confidence is the analysis category, as the spec maps it", async () => {
		stubModel({ ...TMP_READ, confidence: "low" })
		const r = await runGate("bash", { command: UNKNOWN_READ }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("interpreter_unknown")
	})
})

describe("these tests measure the model path, not layer 0", () => {
	it("a command the walker can prove never reaches the effect model in either direction", async () => {
		const model = stubModel(TMP_READ)
		// Inside the project: it is allowed, and no model call is made for it.
		const inside = await runGate("bash", { command: "cat ./notes/todo.md" }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(inside.outcome).toBe("allow")
		expect(inside.modelCalls).toHaveLength(0)
		// Outside the project: the same proof, the opposite verdict — and still no effect call. The tier moved
		// from allow to prompt; what it pins (layer 0 settles the VERDICT alone) is unchanged. The grant
		// call it makes is the ordinary transcript-authorisation step every ask pays, not a classification.
		const outside = await runGate("bash", { command: "cat /home/u/notes/todo.md" }, { policy: POLICY, endpoint: EP, userMessages: MSGS })
		expect(outside.outcome).toBe("prompt")
		expect(outside.category).toBe("read_only")
		expect(outside.modelCalls.filter((c) => c.task === "effect")).toHaveLength(0)
		expect(model.tasks.filter((t) => t === "effect")).toHaveLength(0)
	})

	it("a prompt from the effect model still bows to a named forbid", async () => {
		// "do not read anything in /tmp" is the user's own words about the very path the recorded answer
		// names. The read already asks, so what this pins is the stronger answer: the ledger's
		// revocation is what the user is told, and the request is not waved through by anything else.
		stubModel(TMP_READ)
		const ledger = createLedger()
		applyEvent(ledger, {
			type: "forbid", category: "read_only", value: "/tmp/", kind: "scope",
			quote: "do not read anything in /tmp", messageId: "m1", seq: 1,
		})
		const r = await runGate("bash", { command: UNKNOWN_READ }, {
			policy: POLICY, endpoint: EP, userMessages: ["do not read anything in /tmp"], ledger,
		})
		expect(r.tier).toBe("ask")
		expect(r.outcome).toBe("prompt")
		// The forbid path answers from the ledger before the model is consulted, so the revocation is what
		// the reason carries. (The description is filled only by the allow→ask downgrade.)
		expect(r.reason).toContain("do not read anything in /tmp")
		expect(r.outcome).toBe("prompt")
	})
})
