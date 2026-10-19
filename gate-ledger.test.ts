/**
 * Gate ↔ ledger integration: runGate's ledger step (pure code path, mocked or
 * absent endpoint) and gate-bridge syncLedger (mocked fetch).
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { applyEvent, createLedger, eventsFromExtraction } from "./auth-ledger.ts"
import { collectUserMessageRefs, syncLedger } from "./gate-bridge.ts"
import { runGate, limitUserMessages } from "./gate.ts"
import { createGrantStore } from "./session-grants.ts"
import { extractMessageGrants, MESSAGE_GRANT_SYSTEM_PROMPT, type MessageExtraction } from "./model-client.ts"
import { GRANT_CALL_RESERVE_TOKENS, GRANT_NUMBERING_OVERHEAD_CHARS } from "./model-client.ts"
import { DEFAULT_CONTEXT_TOKENS, callBudget, estimateTokens } from "./context-budget.ts"
import { EXTRACTION_CHUNK_CHARS } from "./message-chunks.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
const EP = { baseUrl: "http://mock", model: "mock" }

function ledgerWith(entries: Parameters<typeof applyEvent>[1][]) {
	const l = createLedger()
	for (const e of entries) applyEvent(l, e)
	return l
}

const rsyncGrant = {
	type: "grant" as const,
	category: "write_outside",
	value: "/x/x/",
	kind: "scope" as const,
	quote: "copy the file to /x/x/ with rsync",
	messageId: "m1",
	seq: 1,
}

/** OpenAI-style fetch mock: picks the extraction by which user message text
 *  appears in the request body; records call count. */
function mockExtractionFetch(map: Array<[string, MessageExtraction]>, opts?: { failFor?: string }) {
	const calls: string[] = []
	const fn = vi.fn(async (_url: unknown, init?: { body?: string }) => {
		// match on the user prompt only — the system prompt's few-shot examples
		// would otherwise satisfy any needle
		const parsed = JSON.parse(String(init?.body ?? "{}")) as { messages?: Array<{ content?: string }> }
		const body = String(parsed.messages?.[1]?.content ?? "")
		const hit = map.find(([needle]) => body.includes(needle))
		calls.push(hit?.[0] ?? body.split("\n")[1]?.slice(0, 30) ?? "?")
		if (opts?.failFor && body.includes(opts.failFor)) {
			return { ok: false, status: 500, text: async () => "boom" }
		}
		const payload: MessageExtraction = hit?.[1] ?? { grants: [], revocations: [] }
		return {
			ok: true,
			json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] }),
		}
	})
	vi.stubGlobal("fetch", fn)
	return { fn, calls }
}

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("runGate ledger step", () => {
	it("ledger grant covers mkdir at an rsync-granted location (kind-group widening), no model call", async () => {
		const grants = createGrantStore()
		const r = await runGate("bash", { command: "mkdir -p /x/x/sub" }, {
			policy: POLICY,
			grants,
			ledger: ledgerWith([rsyncGrant]),
			userMessages: ["copy the file to /x/x/ with rsync"],
			// no endpoint: if the ledger step did not grant, this would be "prompt"
		})
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
		expect(r.modelCalls).toHaveLength(0)
		// promoted to a session grant so repeats skip the ledger scan
		expect(grants.grants.some((g) => g.category === "write_outside" && g.value === "/x/x/sub")).toBe(true)
	})
	it("rsync grant does NOT cover a recursive delete there (verb gate)", async () => {
		const r = await runGate("bash", { command: "rm -rf /x/x/old" }, {
			policy: POLICY,
			ledger: ledgerWith([rsyncGrant]),
			userMessages: [],
		})
		expect(r.outcome).toBe("prompt")
	})
	it("ledger forbid goes straight to prompt — the recent-window fallback is NOT consulted", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "mkdir -p /x/x/sub" }, {
			policy: POLICY,
			endpoint: EP,
			ledger: ledgerWith([
				rsyncGrant,
				{ type: "forbid", category: "*", value: "/x/x/", kind: "scope", quote: "actually leave /x/x/ alone", messageId: "m9", seq: 9 },
			]),
			// a stale grant is still inside the window — must not overrule the revocation
			userMessages: ["copy the file to /x/x/ with rsync"],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
		expect(fn).not.toHaveBeenCalled()
	})
})

describe("unparseable commands short-circuit before any model call", () => {
	it("malformed command → prompt with unparseable flag, no effect model call", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: `ssh h "find / | awk 'x` }, {
			policy: POLICY,
			endpoint: EP, // present, but must NOT be called
		})
		expect(r.unparseable).toBe(true)
		expect(r.outcome).toBe("prompt")
		expect(r.modelCalls).toHaveLength(0)
		expect(fn).not.toHaveBeenCalled()
	})
	it("well-formed unknown command still reaches the effect model (not misflagged)", async () => {
		const r = await runGate("bash", { command: "ls -la | grep foo" }, { policy: POLICY })
		expect(r.unparseable).toBeFalsy()
	})
})

describe("named forbids bind on allow-tier (gap fix)", () => {
	const forbidTmp = {
		type: "forbid" as const,
		category: "*",
		value: "/tmp/results.bin",
		kind: "entity" as const,
		quote: "do not delete /tmp/results.bin",
		messageId: "m5",
		seq: 5,
	}
	it("'do not delete X' turns a temp-location delete from allow into a prompt", async () => {
		const r = await runGate("bash", { command: "rm /tmp/results.bin" }, {
			policy: POLICY,
			ledger: ledgerWith([forbidTmp]),
			userMessages: [],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
		expect(r.description).toContain("user said")
	})
	it("a later re-grant lifts the forbid (seq precedence)", async () => {
		const r = await runGate("bash", { command: "rm /tmp/results.bin" }, {
			policy: POLICY,
			ledger: ledgerWith([
				forbidTmp,
				{ type: "grant", category: "delete_outside", value: "/tmp/results.bin", kind: "entity", quote: "ok you can delete /tmp/results.bin now", messageId: "m9", seq: 9 },
			]),
			userMessages: [],
		})
		expect(r.outcome).toBe("allow")
	})
	it("a session grant (one plain Allow) lifts it for the session", async () => {
		const grants = createGrantStore()
		grants.grants.push({ category: "write_project", value: "/tmp/results.bin", kind: "entity", at: 1 })
		const r = await runGate("bash", { command: "rm /tmp/results.bin" }, {
			policy: POLICY,
			grants,
			ledger: ledgerWith([forbidTmp]),
			userMessages: [],
		})
		expect(r.outcome).toBe("allow-granted")
	})
	it("blanket revocations do not turn normal project work into prompts", async () => {
		const r = await runGate("write", { path: "src/a.ts", content: "x" }, {
			policy: POLICY,
			ledger: ledgerWith([
				{ type: "forbid", category: "*", value: "*", kind: "scope", quote: "stop doing anything risky", messageId: "m5", seq: 5 },
			]),
			userMessages: [],
		})
		expect(r.outcome).toBe("allow")
	})
	it("unrelated allow-tier work is untouched by a named forbid", async () => {
		const r = await runGate("bash", { command: "rm /tmp/other.bin" }, {
			policy: POLICY,
			ledger: ledgerWith([forbidTmp]),
			userMessages: [],
		})
		expect(r.outcome).toBe("allow")
	})
	it("scope forbid 'results/' covers ./results (normalisation fix)", async () => {
		const r = await runGate("bash", { command: "rm -rf ./results" }, {
			policy: POLICY,
			ledger: ledgerWith([
				{ type: "forbid", category: "*", value: "results/", kind: "scope", quote: "do not delete the results/ folder", messageId: "m5", seq: 5 },
			]),
			userMessages: [],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
	})
})

describe("read-only posture ('don't change anything')", () => {
	const roLedger = () => ledgerWith([
		{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "you are not allowed to change anything", messageId: "m0", seq: 0 },
	])
	it("blocks an outside-project write (mutation), no model call", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "rm -rf ~/notes-old" }, {
			policy: POLICY, endpoint: EP, ledger: roLedger(),
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toMatch(/read-only/i)
		expect(r.reason).toContain("change anything")
		expect(fn).not.toHaveBeenCalled()
	})
	it("still ALLOWS project-folder and /tmp writes (excluded by default)", async () => {
		const rProj = await runGate("write", { path: "src/a.ts", content: "x" }, { policy: POLICY, ledger: roLedger() })
		expect(rProj.outcome).toBe("allow")
		const rTmp = await runGate("bash", { command: "echo hi > /tmp/out.txt" }, { policy: POLICY, ledger: roLedger() })
		expect(rTmp.outcome).toBe("allow")
	})
	it("still ALLOWS reads", async () => {
		const r = await runGate("bash", { command: "cat /etc/hosts" }, { policy: POLICY, ledger: roLedger() })
		expect(r.outcome).toBe("allow")
	})
	it("a later per-target grant lifts that target only", async () => {
		const l = ledgerWith([
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "don't change anything", messageId: "m0", seq: 0 },
			{ type: "grant", category: "write_outside", value: "/srv/exports/", kind: "scope", quote: "you can write to /srv/exports/", messageId: "m5", seq: 5 },
		])
		const rAllowed = await runGate("bash", { command: "rsync -a ./out /srv/exports/" }, { policy: POLICY, ledger: l })
		expect(rAllowed.outcome).toBe("allow-granted")
		const rBlocked = await runGate("bash", { command: "rsync -a ./out /other/place/" }, { policy: POLICY, ledger: l })
		expect(rBlocked.outcome).toBe("prompt")
		expect(rBlocked.reason).toMatch(/read-only/i)
	})
	it("a blanket re-enable clears the posture", async () => {
		const l = ledgerWith([
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "read-only for now", messageId: "m0", seq: 0 },
			{ type: "readonly-off", category: "*", value: "*", kind: "scope", quote: "ok you can make changes now", messageId: "m9", seq: 9 },
		])
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "rm -rf ~/notes-old" }, { policy: POLICY, endpoint: EP, ledger: l, userMessages: [] })
		// posture cleared → falls through to normal ask handling (transcript/ prompt),
		// no longer the read-only reason
		expect(r.reason).not.toMatch(/read-only/i)
	})
	it("session grant (prompt approval) wins over read-only", async () => {
		const grants = createGrantStore()
		grants.grants.push({ category: "delete_recursive", value: "~/notes-old", kind: "entity", at: 1 })
		const r = await runGate("bash", { command: "rm -rf ~/notes-old" }, { policy: POLICY, grants, ledger: roLedger() })
		expect(r.outcome).toBe("allow-granted")
	})
})

describe("collectUserMessageRefs", () => {
	const branch = [
		{ type: "message", id: "a1", message: { role: "user", content: "hello" } },
		{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "hi" }] } },
		{ type: "message", message: { role: "user", content: [{ type: "text", text: "copy data to /x/x/" }] } },
		{ type: "custom" },
		{ type: "message", id: "a4", message: { role: "user", content: [{ type: "text", text: "<tool_result>skip me</tool_result>" }] } },
	]
	it("keeps ids, synthesizes stable ones, preserves branch seq, skips non-user/tool-result", () => {
		const refs = collectUserMessageRefs(branch as never)
		expect(refs).toEqual([
			{ id: "a1", seq: 0, text: "hello" },
			{ id: "#2", seq: 2, text: "copy data to /x/x/" },
		])
	})
})

describe("syncLedger", () => {
	const refs = [
		{ id: "m0", seq: 0, text: "hello there" },
		{ id: "m1", seq: 2, text: "copy the dataset to /x/x/ with rsync" },
		{ id: "m2", seq: 4, text: "thanks, looks good" },
	]
	const extractions: Array<[string, MessageExtraction]> = [
		// A schema-shaped extraction: the endpoint had to answer the enum, so the fixture spells
		// category / kind / includesSecrets out instead of leaving the word list to infer them.
		["copy the dataset", {
			grants: [{
				action: "copy files",
				category: "write_outside",
				kind: "scope",
				includesSecrets: false,
				targets: ["/x/x/"],
				quote: "copy the dataset to /x/x/ with rsync",
			}],
			revocations: [],
		}],
	]

	it("processes newest-first within maxCalls, folds verified grants", async () => {
		const { calls } = mockExtractionFetch(extractions)
		const ledger = createLedger()
		const res = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(calls).toEqual(["thanks, looks good", "copy the dataset"])
		// (needle "thanks, looks good" resolves via the fallback label — it is
		// not in the extraction map, so the mock returns an empty extraction)
		expect(res).toMatchObject({ processed: 2, pending: 1, changed: true })
		expect(ledger.grants).toEqual([expect.objectContaining({ value: "/x/x/", seq: 2, messageId: "m1" })])
		expect(ledger.seen.has("m0")).toBe(false)
	})
	it("second pass drains the rest; already-seen messages cost nothing", async () => {
		const { fn } = mockExtractionFetch(extractions)
		const ledger = createLedger()
		await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		const res2 = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(res2).toMatchObject({ processed: 1, pending: 0 })
		const res3 = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(res3).toMatchObject({ processed: 0, pending: 0, changed: false })
		expect(fn).toHaveBeenCalledTimes(3)
	})
	it("a failed extraction leaves the message unseen for retry", async () => {
		mockExtractionFetch(extractions, { failFor: "thanks, looks good" })
		const ledger = createLedger()
		const res = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 3 })
		expect(res.pending).toBe(1) // m2 failed, stays unseen
		expect(ledger.seen.has("m2")).toBe(false)
		expect(ledger.grants).toHaveLength(1) // m1 still folded
	})
	it("a tool-written interrupt notice is marked seen without a model call", async () => {
		const { fn } = mockExtractionFetch(extractions)
		const ledger = createLedger()
		const withNotice = [...refs, { id: "m3", seq: 6, text: "[Request interrupted by user for tool use]" }]
		const res = await syncLedger({ refs: withNotice, ledger, endpoint: EP, maxCalls: 10 })
		expect(fn).toHaveBeenCalledTimes(3) // the notice cost nothing
		expect(ledger.seen.has("m3")).toBe(true)
		expect(ledger.readOnlyOn).toBeUndefined()
		expect(res.pending).toBe(0)
	})
	it("messages beyond backfillLimit are skipped permanently without calls", async () => {
		const { fn } = mockExtractionFetch(extractions)
		const many = Array.from({ length: 10 }, (_, i) => ({ id: `x${i}`, seq: i, text: `filler ${i}` }))
		const ledger = createLedger()
		const res = await syncLedger({ refs: many, ledger, endpoint: EP, maxCalls: 20, backfillLimit: 3 })
		expect(fn).toHaveBeenCalledTimes(3) // only the newest 3
		expect(res.pending).toBe(0)
		expect(ledger.seen.size).toBe(10)
	})
})

/** A user message of exactly `chars` characters, tagged so a kept suffix traces back to its input. */
const FILLER = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore "
function messageOf(tag: number, chars: number): string {
	const body = FILLER.repeat(Math.ceil(chars / FILLER.length) + 1)
	return (`m${tag} ` + body).slice(0, chars)
}

describe("grant window sized to the model's context", () => {
	// The corpus case that broke: a 56-turn session, 15 000 characters of it, one request.
	const history = Array.from({ length: 56 }, (_, i) => messageOf(i, i === 0 ? 260 : 268))

	it("the measured 15 000-char history does not fit, and is cut to a newest-aligned suffix", () => {
		const chars = history.reduce((n, m) => n + m.length, 0)
		expect(chars).toBe(15_000)
		expect(estimateTokens(chars)).toBe(4688) // litellm counted 5 662 for this request
		expect(estimateTokens(chars)).toBeGreaterThan(DEFAULT_CONTEXT_TOKENS)

		const budget = callBudget(undefined, 0, GRANT_CALL_RESERVE_TOKENS)
		const kept = limitUserMessages(history, budget)
		expect(kept.length).toBeGreaterThan(0)
		expect(kept.length).toBeLessThan(history.length)
		// contiguous and newest-aligned: no message jumped over a dropped newer one
		expect(kept).toEqual(history.slice(-kept.length))
		expect(kept[kept.length - 1]).toBe(history[history.length - 1])
		const spent = kept.reduce((n, m) => n + estimateTokens(m.length + GRANT_NUMBERING_OVERHEAD_CHARS), 0)
		expect(spent).toBeLessThanOrEqual(budget)
	})

	it("a bare call defaults to the bare-call budget", () => {
		expect(limitUserMessages(history)).toEqual(limitUserMessages(history, callBudget(undefined, 0, GRANT_CALL_RESERVE_TOKENS)))
	})

	it("never sends a message it shortened", () => {
		const kept = limitUserMessages(history)
		expect(kept.length).toBeGreaterThan(0)
		for (const m of kept) expect(history).toContain(m)
		expect(kept.some((m) => m.includes("…"))).toBe(false)
		expect(kept.every((m) => m.length === 268 || m.length === 260)).toBe(true)
	})

	it("excludes a message bigger than the whole budget, whole", () => {
		const huge = messageOf(0, 20_000)
		// alone: it is the newest and it does not fit, so nothing is sent at all
		expect(limitUserMessages([messageOf(1, 40), huge], 500)).toEqual([])
		// behind a fitting one: it is dropped, and nothing older than it is rescued
		const kept = limitUserMessages([messageOf(1, 20), huge, messageOf(3, 40)], 500)
		expect(kept).toEqual([messageOf(3, 40)])
		expect(kept.some((m) => m.includes("…"))).toBe(false)
	})

	it("keeps the 60-message window cap on top of the token budget", () => {
		const many = Array.from({ length: 90 }, (_, i) => messageOf(i, 12))
		expect(limitUserMessages(many, 100_000)).toEqual(many.slice(-60))
	})

	it("prompts without a model call when nothing fits the window", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "rm -rf ~/notes-old" }, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: 4096 },
			userMessages: [messageOf(0, 20_000)],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("classifier window")
		expect(r.modelCalls).toHaveLength(0)
		expect(fn).not.toHaveBeenCalled()
	})

	it("still pays the grant call when the history does fit (so the test above is not vacuous)", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "rm -rf ~/notes-old" }, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: 4096 },
			userMessages: ["delete ~/notes-old"],
		})
		expect(fn).toHaveBeenCalledTimes(1)
		expect(r.modelCalls.some((c) => c.task === "grant")).toBe(true)
	})
})

// ---------------------------------------------------------------- oversize messages (context budget item 2)

const USER_PREFIX = "User message:\n"
const USER_SUFFIX = "\n\nExtract granted and withdrawn permissions."

const nothing: MessageExtraction = { grants: [], revocations: [] }

/** The approval the old `slice(0, 4000)` cut off: a delete grant worded at the very end. */
const BUILD_GRANT: MessageExtraction = {
	grants: [
		{
			action: "delete files",
			category: "delete_recursive",
			kind: "entity",
			includesSecrets: false,
			targets: ["/home/u/proj/build"],
			quote: "you may delete the build directory /home/u/proj/build",
		},
	],
	revocations: [],
}

/** A pasted ~12 kB design document: prose paragraphs, the one approval sentence LAST. */
function twelveKbSpec(): string {
	const sections = Array.from(
		{ length: 70 },
		(_, i) =>
			`Section ${i + 1} of the pasted design document. It covers the migration order, the rollback path and the artifact layout, and says nothing whatever about what the agent may do.`,
	).join("\n\n")
	return `${sections}\n\nWhen the run finishes, you may delete the build directory /home/u/proj/build.`
}

/** Fetch stub for the chunked path: keeps every request body, answers per piece. */
function stubPerPiece(answer: (piece: string, index: number) => MessageExtraction | "fail") {
	const bodies: string[] = []
	const contentOf = (callIndex: number) =>
		String(
			(JSON.parse(bodies[callIndex] ?? "{}") as { messages?: Array<{ content?: string }> }).messages?.[1]
				?.content ?? "",
		)
	const pieceOf = (callIndex: number) => {
		const content = contentOf(callIndex)
		expect(content.startsWith(USER_PREFIX)).toBe(true)
		expect(content.endsWith(USER_SUFFIX)).toBe(true)
		return content.slice(USER_PREFIX.length, content.length - USER_SUFFIX.length)
	}
	const fn = vi.fn(async (_url: unknown, init?: { body?: string }) => {
		bodies.push(String(init?.body ?? "{}"))
		const verdict = answer(pieceOf(bodies.length - 1), bodies.length - 1)
		if (verdict === "fail") return { ok: false, status: 500, text: async () => "boom" }
		return { ok: true, json: async () => ({ choices: [{ message: { content: JSON.stringify(verdict) } }] }) }
	})
	vi.stubGlobal("fetch", fn)
	return { bodies, pieces: () => bodies.map((_, i) => pieceOf(i)) }
}

describe("oversize messages are extracted in chunks (context budget item 2)", () => {
	it("keeps a grant written in the LAST paragraph of a 12 kB message", async () => {
		const message = twelveKbSpec()
		expect(message.length).toBeGreaterThan(12_000)
		const { pieces } = stubPerPiece((piece) => (piece.includes("you may delete the build directory") ? BUILD_GRANT : nothing))

		const res = await extractMessageGrants(EP, message)

		expect(res.ok).toBe(true)
		if (!res.ok) throw new Error(res.error)
		expect(res.value.grants).toHaveLength(1)
		expect(res.value.grants[0]).toMatchObject({ category: "delete_recursive", targets: ["/home/u/proj/build"] })

		const sent = pieces()
		expect(sent.length).toBeGreaterThan(1)
		expect(sent.every((p) => p.length <= EXTRACTION_CHUNK_CHARS)).toBe(true)
		// every piece of the message reached some request, in order, none lost
		expect(sent.join("")).toBe(message)
	})

	it("folds that grant into the ledger against the full message text", async () => {
		const message = twelveKbSpec()
		stubPerPiece((piece) => (piece.includes("you may delete the build directory") ? BUILD_GRANT : nothing))
		const res = await extractMessageGrants(EP, message)
		if (!res.ok) throw new Error(res.error)
		// callers hand eventsFromExtraction the FULL message, so a quote taken from a
		// late piece is still verified verbatim — and a fabricated one still dropped
		const events = eventsFromExtraction(res.value, "m7", 7, message)
		expect(events).toContainEqual(expect.objectContaining({ type: "grant", value: "/home/u/proj/build", messageId: "m7", seq: 7 }))
		const invented = eventsFromExtraction(res.value, "m8", 8, "a message that never mentioned the build directory")
		expect(invented).toHaveLength(0)
	})

	it("de-duplicates a grant two consecutive chunks both reported", async () => {
		const message = twelveKbSpec()
		const { pieces } = stubPerPiece((_piece, i) => (i === 1 || i === 2 ? BUILD_GRANT : nothing))
		const res = await extractMessageGrants(EP, message)
		if (!res.ok) throw new Error(res.error)
		expect(pieces().length).toBeGreaterThan(2)
		expect(res.value.grants).toHaveLength(1)
	})

	it("a piece whose call fails fails the message, in order, without partial rows", async () => {
		const message = twelveKbSpec()
		const { pieces } = stubPerPiece((_piece, i) => (i === 1 ? "fail" : BUILD_GRANT))
		const res = await extractMessageGrants(EP, message)
		expect(res.ok).toBe(false)
		if (res.ok) throw new Error("expected failure")
		expect(res.error).toMatch(/^chunk 2\/\d+: HTTP 500/)
		expect(pieces()).toHaveLength(2) // stopped at the failure, did not continue
	})

	it("a failed piece means applyEvents is never reached: nothing folded, message unseen", async () => {
		stubPerPiece(() => "fail")
		const ledger = createLedger()
		const res = await syncLedger({ refs: [{ id: "big", seq: 3, text: twelveKbSpec() }], ledger, endpoint: EP, maxCalls: 5 })
		expect(ledger.grants).toHaveLength(0)
		expect(ledger.forbids).toHaveLength(0)
		expect(ledger.seen.has("big")).toBe(false)
		expect(res).toMatchObject({ processed: 1, pending: 1, changed: false }) // attempted, failed, not folded
	})

	it("a message that fits sends exactly one request, identical to today's", async () => {
		const message = "you can delete /home/u/proj/build when the run is done"
		const { bodies, pieces } = stubPerPiece(() => nothing)
		const res = await extractMessageGrants(EP, message)
		expect(res.ok).toBe(true)
		expect(pieces()).toEqual([message])
		expect(bodies).toHaveLength(1)
		const sent = JSON.parse(bodies[0]!) as Record<string, unknown>
		const msgs = sent.messages as Array<{ role: string; content: string }>
		expect(msgs).toHaveLength(2)
		expect(msgs[0]!.content).toBe(MESSAGE_GRANT_SYSTEM_PROMPT)
		expect(msgs[1]!.content).toBe(`User message:\n${message}\n\nExtract granted and withdrawn permissions.`)
		expect(sent.max_tokens).toBe(400)
		expect((sent.response_format as { json_schema: { name: string } }).json_schema.name).toBe("message_permissions")
	})

	it("a whitespace-only message still makes one truncated call, as it does today", async () => {
		const { pieces } = stubPerPiece(() => nothing)
		const res = await extractMessageGrants(EP, " \n".repeat(6000))
		expect(res.ok).toBe(true)
		expect(pieces()).toHaveLength(1)
		expect(pieces()[0]!.length).toBe(EXTRACTION_CHUNK_CHARS)
	})
})

// ---------------------------------------------------------------- the ledger as the summary of older turns (context budget item 3)

// Appended here rather than merged into the header import block, so nothing above this line changed.
import { applyEvents } from "./auth-ledger.ts"
import { verifyGrant, type GrantExtraction } from "./grant-verify.ts"
import { MESSAGE_REF_MAX_CHARS, collectUserMessagesFromBranch } from "./gate-bridge.ts"
import { tokensToChars } from "./context-budget.ts"

const OUT_SCOPE = "/home/me/proj/out/"
/** The words the user actually wrote, back in message #3 of a 100-message history. */
const ROW_QUOTE = "copy the reports into /home/me/proj/out/ and work there from now on"
/** A label the category table cannot name: the row still renders, and `grantAuthorises` can never
 *  match it, so the ONLY way this write gets authorised is the model reading the row. */
const copyFilesGrant = {
	type: "grant" as const,
	category: "*copy files*",
	value: OUT_SCOPE,
	kind: "scope" as const,
	quote: ROW_QUOTE,
	messageId: "m3",
	seq: 3,
}
const PENDING_WRITE = { path: `${OUT_SCOPE}x.txt`, content: "x" }
const YES_FROM_ROW: GrantExtraction = { authorized: "yes", allowed_targets: [OUT_SCOPE], forbidden_targets: [], quote: ROW_QUOTE }
const MODEL_SAYS_NO: GrantExtraction = { authorized: "no", allowed_targets: [], forbidden_targets: [], quote: "" }

function ledgerFrom(events: Parameters<typeof applyEvent>[1][]) {
	const l = createLedger()
	applyEvents(l, events)
	return l
}

/** 100 synthetic messages of 250 chars; #3 is the one that carried the grant. Synthetic on purpose:
 *  no real paths, hosts or credentials in a fixture that is also a budget test. */
const GRANT_MESSAGE = (`${ROW_QUOTE} ` + FILLER.repeat(3)).slice(0, 250)
const LONG_HISTORY = Array.from({ length: 100 }, (_, i) => (i === 3 ? GRANT_MESSAGE : messageOf(i, 250)))

/** Fetch stub for the GRANT-transcript call (task A) — `mockExtractionFetch` above answers task C. */
function stubGrantCall(answer: GrantExtraction) {
	const bodies: string[] = []
	const prompts: string[] = []
	const fn = vi.fn(async (_url: unknown, init?: { body?: string }) => {
		const parsed = JSON.parse(String(init?.body ?? "{}")) as {
			messages?: Array<{ content?: string }>
			response_format?: { json_schema?: { name?: string } }
		}
		bodies.push(String(init?.body ?? "{}"))
		prompts.push(String(parsed.messages?.[1]?.content ?? ""))
		// a call on the ledger-extraction schema here would mean the test drove the wrong task
		expect(parsed.response_format?.json_schema?.name).toBe("authorisation")
		return { ok: true, json: async () => ({ choices: [{ message: { content: JSON.stringify(answer) } }] }) }
	})
	vi.stubGlobal("fetch", fn)
	return { fn, bodies, prompts }
}

describe("the ledger is the summary of the turns that no longer fit (item 3)", () => {
	it("a 100-message history: the grant survives as a row, the raw message does not", async () => {
		const { fn, bodies, prompts } = stubGrantCall(YES_FROM_ROW)
		expect(LONG_HISTORY).toHaveLength(100)
		expect(LONG_HISTORY[3]!.length).toBe(250)

		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			ledger: ledgerFrom([copyFilesGrant]),
			userMessages: LONG_HISTORY,
		})

		expect(fn).toHaveBeenCalledTimes(1)
		const prompt = prompts[0]!
		// the row is in the call; the message that produced it is not
		expect(prompt).toContain("Authorisation so far (verified earlier, oldest first):")
		expect(prompt).toContain(`#3 grant   *copy files* scope=${OUT_SCOPE} — "${ROW_QUOTE}"`)
		expect(prompt).toContain(LONG_HISTORY[99]!)
		expect(prompt).not.toContain(LONG_HISTORY[3]!)

		// and the whole request still fits the window it was sized for (system + user content)
		const sent = JSON.parse(bodies[0]!) as { messages: Array<{ content: string }>; max_tokens: number }
		expect(sent.messages).toHaveLength(2)
		const chars = sent.messages.reduce((n, m) => n + m.content.length, 0)
		expect(chars).toBeLessThan(tokensToChars(DEFAULT_CONTEXT_TOKENS))
		expect(sent.max_tokens).toBe(GRANT_CALL_RESERVE_TOKENS)

		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("with no row for that grant, the same answer cannot be verified", async () => {
		const { fn } = stubGrantCall(YES_FROM_ROW)
		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			// a ledger that holds OTHER rows — just not this one
			ledger: ledgerFrom([{ ...copyFilesGrant, value: "/srv/unrelated/", quote: "copy the reports into /srv/unrelated/", messageId: "m9", seq: 9 }]),
			userMessages: LONG_HISTORY,
		})
		expect(fn).toHaveBeenCalledTimes(1) // the recent window is still worth sending
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toBe("quote not found verbatim in any user message")
	})

	it("rows alone still pay the call, with the message list rendered as (none)", async () => {
		const { fn, prompts } = stubGrantCall(YES_FROM_ROW)
		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			ledger: ledgerFrom([copyFilesGrant]),
			userMessages: [messageOf(0, 20_000)], // the newest message alone is bigger than the window
		})
		expect(fn).toHaveBeenCalledTimes(1)
		const prompt = prompts[0]!
		expect(prompt.startsWith("Authorisation so far (verified earlier, oldest first):", 0)).toBe(true)
		expect(prompt).toContain("User messages (oldest first):\n(none)")
		expect(prompt).toContain(`#3 grant   *copy files* scope=${OUT_SCOPE}`)
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("and the verdict stays the model's: an answer of 'no' still prompts", async () => {
		const { fn } = stubGrantCall(MODEL_SAYS_NO)
		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			ledger: ledgerFrom([copyFilesGrant]),
			userMessages: [messageOf(0, 20_000)],
		})
		expect(fn).toHaveBeenCalledTimes(1)
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toBe("model: not authorised by the user")
	})

	it("with no row to stand in, a message too big for the window still skips the call", async () => {
		const { fn } = stubGrantCall(YES_FROM_ROW)
		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			ledger: createLedger(),
			userMessages: [messageOf(0, 20_000)],
		})
		expect(fn).not.toHaveBeenCalled()
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("classifier window")
	})

	it("a later forbid row stops the call at the gate — the model never gets to answer", async () => {
		const { fn } = stubGrantCall(YES_FROM_ROW)
		const r = await runGate("write", PENDING_WRITE, {
			policy: POLICY,
			endpoint: { ...EP, contextTokens: DEFAULT_CONTEXT_TOKENS },
			ledger: ledgerFrom([
				copyFilesGrant,
				{ type: "forbid", category: "*", value: OUT_SCOPE, kind: "scope", quote: "leave /home/me/proj/out/ alone", messageId: "m50", seq: 50 },
			]),
			userMessages: LONG_HISTORY,
		})
		expect(fn).not.toHaveBeenCalled()
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
	})

	it("and a forbid the model names vetoes a quote that came only from a row", () => {
		// The existing step-2 path, unchanged: a ledger row widens WHERE the words may come from,
		// never WHAT they grant.
		const v = verifyGrant({
			extraction: { ...YES_FROM_ROW, forbidden_targets: [OUT_SCOPE] },
			category: "write_outside",
			entities: [{ kind: "target", value: `${OUT_SCOPE}x.txt` }],
			userMessages: [],
			ledgerQuotes: [ROW_QUOTE],
		})
		expect(v.granted).toBe(false)
		expect(v.reason).toContain("user-forbidden")
		expect(v.source).toBeUndefined()
	})

	it("attributes a quote to the messages when both carry it, to the ledger when only a row does", () => {
		const entities = [{ kind: "target" as const, value: `${OUT_SCOPE}x.txt` }]
		const inBoth = verifyGrant({
			extraction: YES_FROM_ROW,
			category: "write_outside",
			entities,
			userMessages: [`${ROW_QUOTE}, and nothing else`],
			ledgerQuotes: [ROW_QUOTE],
		})
		expect(inBoth.granted).toBe(true)
		expect(inBoth.source).toBe("message")

		const rowOnly = verifyGrant({
			extraction: YES_FROM_ROW,
			category: "write_outside",
			entities,
			userMessages: [messageOf(1, 250)],
			ledgerQuotes: [ROW_QUOTE],
		})
		expect(rowOnly.granted).toBe(true)
		expect(rowOnly.source).toBe("ledger")

		// the clip lives in the rendered line only — the haystack the verifier searches stays verbatim
		const clipped = verifyGrant({
			extraction: { ...YES_FROM_ROW, quote: ROW_QUOTE.slice(0, 40) },
			category: "write_outside",
			entities,
			userMessages: [],
			ledgerQuotes: [ROW_QUOTE],
		})
		expect(clipped.granted).toBe(true)
		expect(clipped.source).toBe("ledger")
	})
})

describe("the message-ref cap is a dump guard, not a size limit", () => {
	const branch = (text: string) => [{ type: "message", id: "big", message: { role: "user", content: text } }]

	it("leaves a 10 000-char message whole — refs and the gate's raw list alike", () => {
		const text = "u".repeat(10_000)
		expect(collectUserMessageRefs(branch(text) as never)).toEqual([{ id: "big", seq: 0, text }])
		expect(collectUserMessagesFromBranch(branch(text) as never)).toEqual([text])
	})

	it("still clamps a 40 000-char paste, head and tail, on both paths", () => {
		const text = "v".repeat(40_000)
		const ref = collectUserMessageRefs(branch(text) as never)[0]!.text
		expect(ref).toContain("[truncated]")
		expect(ref.length).toBeLessThan(text.length)
		expect(ref.length).toBeLessThan(MESSAGE_REF_MAX_CHARS + 32) // head + the marker + tail
		expect(ref.startsWith("v".repeat(1000))).toBe(true)
		expect(ref.endsWith("v".repeat(1000))).toBe(true)
		// the list index.ts hands the gate goes through the same clamp, so tokens budget it downstream
		expect(collectUserMessagesFromBranch(branch(text) as never)).toEqual([ref])
		expect(MESSAGE_REF_MAX_CHARS).toBeGreaterThan(4_000)
	})
})
