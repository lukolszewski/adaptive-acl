/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Pinned behaviour of `stripChatmlControlRegions`.
 *
 * Some OpenAI-compatible endpoints emit reasoning as ChatML control regions **inside the text body**
 * rather than in a separate field, so a stage's reply can be thinking-junk followed by the verdict —
 * or thinking-junk and no verdict at all, when the token cap cut the reply off mid-region.
 *
 * These tests pin the cleanup as *structural only*: it removes delimiter-bounded spans and infers
 * nothing. Whether there is a verdict stays entirely the strict parser's decision, which is why the
 * adversarial cases assert that a verdict written **among** the thinking disappears with it.
 *
 * The control tokens are assembled from parts so that no ChatML token appears literally in source —
 * they break shell quoting, generation tooling and, confusingly, anything that greps for them.
 */
import { describe, expect, it } from "vitest"
import { parseClassifierResponse, stripChatmlControlRegions } from "./classifier-client.ts"

const OPEN = "<" + "|"
const CLOSE = "|" + ">"
const region = (body: string): string => `${OPEN}${body}${CLOSE}`

// The shipped verdict shape (verdictFromParsedObject reads shouldBlock + reason), so these fixtures
// double as a note about what the parser actually accepts.
const VERDICT = `{"shouldBlock":false,"reason":"the person named this exact path"}`

describe("stripChatmlControlRegions", () => {
	it("drops a control region and keeps the verdict that follows it on the same line", () => {
		const raw = `${region(`im_start assistant thinking about scope ${VERDICT}`)}`
		expect(stripChatmlControlRegions(raw)).toBe("")
		// Same region shape, but this time the verdict sits outside it — the real reply shape.
		const withAnswer = region("im_start assistant long reasoning") + VERDICT
		expect(stripChatmlControlRegions(withAnswer)).toBe(VERDICT)
	})

	it("keeps a verdict on its own line after the region, newlines and all", () => {
		const raw = `${region("im_start assistant reasoning about the call")}
${VERDICT}`
		expect(stripChatmlControlRegions(raw)).toBe(`
${VERDICT}`)
	})

	it("keeps what sits between two regions and drops both regions", () => {
		const raw = region("im_start assistant") + VERDICT + region("im_end")
		expect(stripChatmlControlRegions(raw)).toBe(VERDICT)
	})

	it("treats an unterminated opener as junk running to the end of the reply", () => {
		// A reply cut off by the token cap mid-region: nothing after the opener is content.
		const raw = VERDICT + region("complete") + "still thinking about whether" + OPEN + "im_start assistant trailing thought"
		expect(stripChatmlControlRegions(raw)).toBe(VERDICT + "still thinking about whether")
	})

	it("does not turn an unclosed region containing a brace into parseable material", () => {
		const raw = OPEN + `im_start assistant ${VERDICT}`
		expect(stripChatmlControlRegions(raw)).toBe("")
		expect(stripChatmlControlRegions(raw).includes("shouldBlock")).toBe(false)
	})

	it("removes a verdict written inside the thinking, so strip-then-parse cannot resurrect it", () => {
		// This is why order matters: parse-then-strip would read a verdict out of the model's own musing.
		const raw = region(`im_start assistant I could answer ${VERDICT} but that would be wrong`)
		const stripped = stripChatmlControlRegions(raw)
		expect(stripped).toBe("")
		expect(stripped).not.toContain("release")
	})

	it("returns an opener-free reply byte for byte, including text that merely mentions a pipe", () => {
		const clean = `the user asked to delete ./build, which they named explicitly ${VERDICT}`
		expect(stripChatmlControlRegions(clean)).toBe(clean)
		expect(stripChatmlControlRegions("a | b |> not a real region")).toBe("a | b |> not a real region")
		expect(stripChatmlControlRegions("")).toBe("")
	})

	it("is idempotent, so a second pass changes nothing", () => {
		const raw = region("im_start a") + VERDICT + region("im_end b") + OPEN + "im_start unclosed tail"
		const once = stripChatmlControlRegions(raw)
		expect(stripChatmlControlRegions(once)).toBe(once)
		expect(once).toBe(VERDICT)
	})
})

// ── the wiring: strict read first, stripped read only as a second attempt ────────────────────────
describe("parseClassifierResponse with ChatML junk in the reply", () => {
	it("still reads a verdict that follows a control region", () => {
		const raw = region("im_start assistant reasoning that never ends cleanly") + JSON.stringify({ shouldBlock: true, reason: "not asked for" })
		const got = parseClassifierResponse(raw, "single")
		expect(got).not.toBeNull()
		expect(got?.allow).toBe(false)
	})

	it("returns null rather than inventing a verdict when the reply is only thinking", () => {
		const raw = region("im_start assistant I could say allow here but no verdict object exists")
		expect(parseClassifierResponse(raw, "single")).toBeNull()
	})

	it("leaves a clean reply on the strict path unchanged", () => {
		const clean = JSON.stringify({ shouldBlock: false, reason: "the person named this exact path" })
		expect(parseClassifierResponse(clean, "single")).toEqual(parseClassifierResponse(stripChatmlControlRegions(clean), "single"))
		expect(parseClassifierResponse(clean, "single")?.allow).toBe(true)
	})
})
