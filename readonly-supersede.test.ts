/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Regression: a later, explicit permission must supersede an earlier read-only
 * posture (session pi-20260926-150552.C05mXU, replayed verbatim).
 *
 * Two defects made a named-file permission useless for the rest of that session:
 *  1. A scoping complaint about SEARCHING ("you will not search half a tb of
 *     files in my home to find clues") armed the session-wide read-only posture,
 *     because any blanket revocation with an unmappable action did so.
 *  2. The later grant — "apply that fix to /usr/bin/gettemp.py I give you
 *     permission to use sudo to write to that file providing you make a backup
 *     first" — was recorded at a HIGHER seq than the posture and still could not
 *     lift it: it landed as write_outside (kind group fs-write) while the write
 *     classifies as write_sensitive (group secret) because /usr/bin is a
 *     sensitive prefix, and the lift required group equality.
 *
 * Every extraction payload below is recorded model output for the message quoted beside it — the same
 * call the gate makes — because the fields the code now reads (`scope`, `category`, `kind`) only mean what
 * the model's own answers say they mean. Where a payload is deliberately NOT what the model returns, the
 * comment says so and it is a garbage-input pin.
 */
import { describe, expect, it } from "vitest"
import {
	applyEvent,
	applyEvents,
	createLedger,
	eventsFromExtraction,
	ledgerCovers,
	readOnlyActive,
	readOnlyLiftedByGrant,
	type ExtractedEvent,
} from "./auth-ledger.ts"
import { runGate } from "./gate.ts"
import { normalizeGrantValue } from "./grant-verify.ts"
import type { Entity } from "./risk-policy.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

function ledgerWith(entries: ExtractedEvent[]) {
	const l = createLedger()
	for (const e of entries) applyEvent(l, e)
	return l
}

/** The verbatim sentences from the session, in the order the user sent them. */
const RO_QUOTE = "you will not search half a tb of files in my home to find clues"
const GRANT_QUOTE =
	"apply that fix to /usr/bin/gettemp.py I give you permission to use sudo to write to that file providing you make a backup first"
const TARGET = "/usr/bin/gettemp.py"

describe("read-only posture must not arm on a non-mutation complaint", () => {
	it("a blanket complaint about searching does NOT arm the posture", () => {
		// Recorded row, verbatim. The posture is armed by `scope: "everything"` and by nothing else, so a
		// scoping complaint that the model files as `scope: "category"` under `read_only` cannot lock the
		// session — which is the defect this file exists for, now closed by a field instead of by three
		// regexes guessing what the sentence was about.
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "search files", category: "read_only", scope: "category", targetClass: "none", targets: [], all: true, quote: RO_QUOTE }] },
			"m73", 73, RO_QUOTE,
		)
		const l = createLedger()
		applyEvents(l, ev)
		expect(readOnlyActive(l)).toBeNull()
		expect(l.readOnlyOn).toBeUndefined()
		// One row, and it is a ban on READING, not a session lock: the sentence named reads, so that is
		// as far as it reaches. A write in the same path space is untouched.
		expect(l.forbids).toHaveLength(1)
		expect(l.forbids[0]!.category).toBe("read_only")
		expect(ledgerCovers(l, "write_outside", [T("/home/u/notes.md")]).forbidden).toBe(false)
		expect(ledgerCovers(l, "read_only", [T("/home/u/notes.md")]).forbidden).toBe(true)
	})
	it("still ARMS on 'stop, don't run anything risky anymore' (fail-safe kept)", () => {
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "run risky work", category: "other", scope: "everything", targetClass: "none", targets: [], all: true, quote: "stop, don't run anything risky anymore" }] },
			"m1", 50, "stop, don't run anything risky anymore",
		)
		const l = createLedger()
		applyEvents(l, ev)
		expect(readOnlyActive(l)?.seq).toBe(50)
	})
	it("still ARMS on an explicit read-only instruction", () => {
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "make changes", category: "other", scope: "everything", targetClass: "none", targets: [], all: true, quote: "do not change anything" }] },
			"m1", 5, "read only, do not change anything",
		)
		const l = createLedger()
		applyEvents(l, ev)
		expect(readOnlyActive(l)?.seq).toBe(5)
	})
	it("a row with no usable width never arms the posture either", () => {
		// Garbage pin: `scope` missing, junk, or a width this file does not know keeps the
		// sentence as a defused forbid. The cost is one model call on any older grant; it is never a lock
		// and never an allow.
		for (const junk of [undefined, "", "ALL", "everything-ish"]) {
			const l = createLedger()
			applyEvents(l, eventsFromExtraction(
				{ grants: [], revocations: [{ action: "work", category: "other", ...(junk ? { scope: junk } : {}), targetClass: "none", targets: [], quote: "read only, do not change anything" }] },
				"m1", 5, "read only, do not change anything",
			))
			expect(readOnlyActive(l), String(junk)).toBeNull()
			expect(l.forbids.map((f) => f.category), String(junk)).toEqual(["*unknown*"])
		}
	})
})

describe("a later named permission supersedes the posture (session replay)", () => {
	/** Ledger as it actually stood in that session. */
	const sessionLedger = () => {
		const l = createLedger()
		l.readOnlyOn = { seq: 73, quote: RO_QUOTE }
		l.grants.push({
			category: "write_outside",
			value: TARGET,
			kind: "entity",
			quote: GRANT_QUOTE,
			messageId: "m77",
			seq: 77,
		})
		return l
	}

	it("grants the exact file across the fs-write ↔ write_sensitive group boundary", () => {
		const l = sessionLedger()
		expect(readOnlyLiftedByGrant(l, "write_sensitive", [T(TARGET)], 73)).toBe(true)
		expect(ledgerCovers(l, "write_sensitive", [T(TARGET)]).covered).toBe(true)
	})
	it("does NOT extend to any other sensitive file", () => {
		const l = sessionLedger()
		expect(readOnlyLiftedByGrant(l, "write_sensitive", [T("/usr/bin/other.py")], 73)).toBe(false)
		expect(ledgerCovers(l, "write_sensitive", [T("/etc/hosts")]).covered).toBe(false)
	})
	it("the widening is limited to path mutations — a foreign family never lifts", () => {
		const l = createLedger()
		l.readOnlyOn = { seq: 1, quote: "read only" }
		l.grants.push({ category: "network_send", value: TARGET, kind: "entity", quote: `you can upload ${TARGET}`, messageId: "m5", seq: 5 })
		expect(readOnlyLiftedByGrant(l, "write_sensitive", [T(TARGET)], 1)).toBe(false)
		expect(ledgerCovers(l, "write_sensitive", [T(TARGET)]).covered).toBe(false)
	})
	it("a write grant never lifts a DELETE it has no verb for", () => {
		const l = createLedger()
		l.readOnlyOn = { seq: 1, quote: "read only" }
		l.grants.push({ category: "write_outside", value: TARGET, kind: "entity", quote: `you can write ${TARGET}`, messageId: "m5", seq: 5 })
		expect(readOnlyLiftedByGrant(l, "delete_recursive", [T(TARGET)], 1)).toBe(false)
	})
	it("an OLDER grant (seq below the posture) still cannot lift it", () => {
		const l = createLedger()
		l.readOnlyOn = { seq: 73, quote: RO_QUOTE }
		l.grants.push({ category: "write_outside", value: TARGET, kind: "entity", quote: `you can write ${TARGET}`, messageId: "m10", seq: 10 })
		expect(readOnlyLiftedByGrant(l, "write_sensitive", [T(TARGET)], 73)).toBe(false)
	})

	it("end to end: runGate allows the authorised write, prompts the other one", async () => {
		const allowed = await runGate("write", { path: TARGET, content: "x" }, { policy: POLICY, ledger: sessionLedger() })
		expect(allowed.outcome).toBe("allow-granted")

		const blocked = await runGate("write", { path: "/usr/bin/unrelated.py", content: "x" }, { policy: POLICY, ledger: sessionLedger() })
		expect(blocked.outcome).toBe("prompt")
		expect(blocked.reason).toMatch(/read-only/i)
	})
})

describe("a directory permission covers the directory, and only the model says it does", () => {
	const WT = "/home/u/dev/wt"
	// Recorded for "you can write into /home/u/dev/wt": `kind: "scope"` is the model's own answer, and it
	// is the ONLY source of a folder permission.
	const wtQuote = "you can write into /home/u/dev/wt"
	const wtRow = { action: "write files", category: "write_outside", kind: "scope", scope: "named", includesSecrets: false, targets: [WT], quote: wtQuote }

	it("extracts the folder from `kind: \"scope\"`, not from a location preposition", () => {
		const ev = eventsFromExtraction({ grants: [wtRow], revocations: [] }, "m1", 1, wtQuote)
		const scope = ev.find((e) => e.kind === "scope")
		expect(scope?.value).toBe(`${WT}/`)
	})
	it("and that scope then covers a file never mentioned before", async () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction({ grants: [wtRow], revocations: [] }, "m1", 1, wtQuote))
		const r = await runGate("write", { path: `${WT}/brand-new-file.ts`, content: "x" }, { policy: POLICY, ledger: l })
		expect(r.outcome).toBe("allow-granted")
	})
	it("a sentence the model marks `entity` records ONE row, not the folder row the regex invented", () => {
		// Recorded: "you are allowed to create a new worktree in /home/u/dev/wt for this" comes back
		// `kind: "entity"` with the folder as its target. The deleted location-preposition rule used to
		// emit a second, folder-shaped row anyway, so `/grants` showed a scope the user never agreed to.
		// Measured here rather than asserted from the diff: the entity row still reaches files inside the
		// folder, because `entityMatchesTarget` matches component runs — so what the deleted rule bought
		// was a second spelling of the same authority, and what its removal costs is nothing at the gate.
		const quote = "you are allowed to create a new worktree in /home/u/dev/wt for this"
		const ev = eventsFromExtraction(
			{ grants: [{ action: "create worktree", category: "write_outside", kind: "entity", scope: "named", includesSecrets: false, targets: [WT], quote: "create a new worktree in /home/u/dev/wt for this" }], revocations: [] },
			"m1", 1, quote,
		)
		expect(ev.map((e) => `${e.kind}:${e.value}`)).toEqual(["entity:/home/u/dev/wt"])
		const l = createLedger()
		applyEvents(l, ev)
		expect(ledgerCovers(l, "write_outside", [T(`${WT}/brand-new-file.ts`)], "/home/u").covered).toBe(true)
		expect(ledgerCovers(l, "write_outside", [T(WT)], "/home/u").covered).toBe(true)
		// …and it is still bounded to that folder: the sibling directory is not behind this row.
		expect(ledgerCovers(l, "write_outside", [T("/home/u/dev/other/x.ts")], "/home/u").covered).toBe(false)
	})
	it("a read permission scopes as a READ, never as a write", () => {
		const ev = eventsFromExtraction(
			{ grants: [{ action: "read files", category: "read_only", kind: "scope", scope: "named", includesSecrets: false, targets: ["/etc"], quote: "you can read files in /etc" }], revocations: [] },
			"m1", 1, "you can read files in /etc",
		)
		// Reads DO produce a folder scope (that was the point — "read everything in /etc" used to record
		// nothing usable). What must never happen is that scope being a write-shaped row. The semantic
		// guarantee — a read scope cannot authorise a write — is pinned in
		// grant-extraction-baseline.test.ts against the matcher itself, which is stronger than pinning the
		// absence of a row here.
		expect(ev.some((e) => e.kind === "scope")).toBe(true)
		expect(ev.filter((e) => e.kind === "scope").every((e) => e.category === "read_only")).toBe(true)
	})
	it("a named FILE with no `kind: \"scope\"` stays a file grant", () => {
		const ev = eventsFromExtraction(
			{ grants: [{ action: "write file", category: "write_project", kind: "entity", scope: "named", includesSecrets: false, targets: [`${WT}/one.ts`], quote: `you can write into ${WT}/one.ts` }], revocations: [] },
			"m1", 1, `you can write into ${WT}/one.ts`,
		)
		expect(ev.some((e) => e.kind === "scope")).toBe(false)
	})
})

describe("path form: ~/… and /home/u/… are the same place", () => {
	// The gate builds entities home-relatively (displayPath → `~/dev/wt/x`) while a
	// user words a permission absolutely. Measured before the fix: a scope
	// `/home/u/dev/wt/` covered the absolute entity but NOT the `~/dev/wt/…` one.
	const l = () => {
		const ldr = createLedger()
		ldr.grants.push({
			category: "write_outside", value: "/home/u/dev/wt/", kind: "scope",
			quote: "work in /home/u/dev/wt", messageId: "m1", seq: 1,
		})
		return ldr
	}
	it("absolute scope grant covers the gate's tilde entity, end to end", async () => {
		const r = await runGate("write", { path: "/home/u/dev/wt/new.ts", content: "x" }, { policy: POLICY, ledger: l() })
		expect(r.outcome).toBe("allow-granted")
	})
	it("still does not leak to a sibling directory", async () => {
		const r = await runGate("write", { path: "/home/u/dev/other/new.ts", content: "x" }, { policy: POLICY, ledger: l() })
		expect(r.outcome).not.toBe("allow-granted")
	})
	it("revoke matching normalises tilde, absolute and trailing slash", () => {
		expect(normalizeGrantValue("~/dev/wt/", "/home/u")).toBe(normalizeGrantValue("/home/u/dev/wt", "/home/u"))
		expect(normalizeGrantValue("/home/u/dev/wt/", "/home/u")).toBe(normalizeGrantValue("~/dev/wt", "/home/u"))
		expect(normalizeGrantValue("~/dev/wt", "/home/u")).not.toBe(normalizeGrantValue("~/dev/other", "/home/u"))
	})
})

describe("temp dirs need no grant, even under read-only posture", () => {
	// Answer: agent-created scratch under /tmp is fine. No scope machinery needed —
	// risk-paths already treats /tmp, /var/tmp, /dev/shm as temp writes.
	const ro = () => {
		const l = createLedger()
		l.readOnlyOn = { seq: 1, quote: "read only" }
		return l
	}
	it("allows creating and writing scratch files under /tmp", async () => {
		expect((await runGate("bash", { command: "mkdir -p /tmp/wt-scratch" }, { policy: POLICY, ledger: ro() })).outcome).toBe("allow")
		expect((await runGate("bash", { command: "echo x > /tmp/wt-scratch/patch.py" }, { policy: POLICY, ledger: ro() })).outcome).toBe("allow")
		expect((await runGate("write", { path: "/var/tmp/x.py", content: "y" }, { policy: POLICY, ledger: ro() })).outcome).toBe("allow")
	})
	it("does not treat /tmp itself as writable scratch", async () => {
		const r = await runGate("bash", { command: "rm -rf /tmp" }, { policy: POLICY, ledger: ro() })
		expect(r.outcome).not.toBe("allow")
	})
})

describe("compound permission: 'use sudo to write to that file'", () => {
	// Recorded: the model answers GRANT_QUOTE with ONE ROW PER EFFECT — the write, the elevation, and
	// the backup the user made a condition. The code used to synthesise the elevation half from
	// `/\bsudo\b|\bsu -\b|\bas root\b|\belevat\w*/i` run over the quote; that inference (HOW something was
	// done, read as permission for it) is deleted, and the sibling row is what arrives instead.
	const recordedGrantRows = [
		{ action: "write file", category: "write_sensitive", kind: "entity", scope: "named", includesSecrets: false, targets: [TARGET], quote: "apply that fix to /usr/bin/gettemp.py" },
		{ action: "run with elevated privileges", category: "privilege", kind: "entity", scope: "named", includesSecrets: false, targets: ["sudo"], quote: "I give you permission to use sudo" },
		{ action: "copy file", category: "read_only", kind: "entity", scope: "named", includesSecrets: false, targets: [TARGET], quote: "providing you make a backup first" },
	]

	it("records the elevation half as its own row", () => {
		const ev = eventsFromExtraction({ grants: recordedGrantRows, revocations: [] }, "m77", 77, GRANT_QUOTE)
		expect(ev.some((e) => e.type === "grant" && e.category === "privilege")).toBe(true)
		expect(ev.some((e) => e.type === "grant" && e.category === "write_sensitive" && e.value === TARGET)).toBe(true)
	})
	it("and does NOT widen the write row into an elevation grant", () => {
		// What the deleted regex used to add: `privilege` over the FILE, from the method word inside the
		// quote. The recorded elevation row names the tool (`"sudo"`), which no path target can equal, so
		// a sudo'd follow-up costs one prompt rather than being auto-allowed off a sentence that named the
		// file. Reported as an outcome change: the fix belongs to the extraction prompt's "a tool name is
		// never a name" rule, not to a regex in the matcher's path.
		const ev = eventsFromExtraction({ grants: recordedGrantRows, revocations: [] }, "m77", 77, GRANT_QUOTE)
		expect(ev.filter((e) => e.category === "privilege").map((e) => e.value)).toEqual(["sudo"])
		const l = createLedger()
		applyEvents(l, ev)
		expect(ledgerCovers(l, "privilege", [T(TARGET)]).covered).toBe(false)
	})
	it("does not invent a privilege grant when sudo was not mentioned", () => {
		const ev = eventsFromExtraction(
			{ grants: [{ action: "write file", category: "write_project", kind: "entity", scope: "named", includesSecrets: false, targets: ["/home/u/proj/a.ts"], quote: "you can write to /home/u/proj/a.ts" }], revocations: [] },
			"m1", 1, "you can write to /home/u/proj/a.ts",
		)
		expect(ev.some((e) => e.category === "privilege")).toBe(false)
	})
})

describe("a revocation reaches everywhere its grant reached (eval case L-02)", () => {
	// The corpus script: folder delete granted, then "actually stop - do not delete anything
	// under ~/scratch-data anymore". The grant arrives from the model as kind=scope, so it
	// covers files INSIDE the folder; the revocation named that same folder but was recorded
	// as a single path. The earlier grant therefore kept authorising `rm -rf
	// ~/scratch-data/run3` — a true false allow, invisible to the unit suite and found only
	// by running the gate eval against a live endpoint.
	const grantQuote = "you can delete anything under ~/scratch-data"
	const revokeQuote = "actually stop - do not delete anything under ~/scratch-data anymore"
	const grantEvent = () =>
		eventsFromExtraction(
			{ grants: [{ action: "delete files", category: "delete_outside", kind: "scope", scope: "named", includesSecrets: false, targets: ["~/scratch-data"], quote: grantQuote }], revocations: [] } as never,
			"m1", 1, grantQuote,
		)
	const revokeEvents = () =>
		eventsFromExtraction(
			{ grants: [], revocations: [{ action: "delete files", category: "delete_outside", scope: "named", targetClass: "none", targets: ["~/scratch-data"], all: false, quote: "do not delete anything under ~/scratch-data anymore" }] } as never,
			"m2", 2, revokeQuote,
		)
	const run3: Entity[] = [{ kind: "target", value: "~/scratch-data/run3" }]

	it("the folder grant alone does cover a file inside it", () => {
		const l = createLedger()
		applyEvents(l, grantEvent())
		expect(ledgerCovers(l, "delete_recursive", run3, "/home/u").covered).toBe(true)
	})

	it("and the later revocation beats it", () => {
		const l = createLedger()
		applyEvents(l, grantEvent())
		applyEvents(l, revokeEvents())
		expect(ledgerCovers(l, "delete_recursive", run3, "/home/u").covered).toBe(false)
	})

	it("a named revocation of a location records the exact path AND its subtree", () => {
		const ev = revokeEvents()
		expect(ev.some((e) => e.type === "forbid" && e.value === "~/scratch-data")).toBe(true)
		expect(ev.some((e) => e.type === "forbid" && e.value === "~/scratch-data/" && e.kind === "scope")).toBe(true)
		// Both rows carry the model's category. They used to carry `"*"` — "every category at this path",
		// inferred from the sentence's verbs — which is why a revocation could outrank a grant the
		// sentence never spoke about.
		expect(ev.every((e) => e.category === "delete_outside")).toBe(true)
	})
})
