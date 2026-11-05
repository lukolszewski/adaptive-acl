/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */
import { describe, expect, it } from "vitest"

import { extraRequestFieldsProblem, mergeRequestFields } from "./request-fields.ts"

describe("mergeRequestFields", () => {
	const body = {
		model: "m",
		temperature: 0,
		max_tokens: 300,
		messages: [{ role: "user", content: "x" }],
		response_format: { type: "json_schema" },
		reasoning: { effort: "low", summary: "auto" },
	}

	it("returns an equal copy when nothing is configured", () => {
		const out = mergeRequestFields(body, undefined)
		expect(out).toEqual(body)
		expect(out).not.toBe(body)
		expect(mergeRequestFields(body, {})).toEqual(body)
	})

	it("adds new fields, including nested objects", () => {
		const out = mergeRequestFields(body, { chat_template_kwargs: { enable_thinking: false }, seed: 42 })
		expect(out.chat_template_kwargs).toEqual({ enable_thinking: false })
		expect(out.seed).toBe(42)
	})

	it("merges into an existing object key by key", () => {
		const out = mergeRequestFields(body, { reasoning: { effort: "none" } })
		expect(out.reasoning).toEqual({ effort: "none", summary: "auto" })
	})

	it("null removes a field instead of sending null", () => {
		const out = mergeRequestFields(body, { temperature: null, reasoning: { summary: null } })
		expect("temperature" in out).toBe(false)
		expect(out.reasoning).toEqual({ effort: "low" })
	})

	it("never mutates the input body", () => {
		const copy = structuredClone(body)
		mergeRequestFields(body, { temperature: null, reasoning: { effort: "none" } })
		expect(body).toEqual(copy)
	})

	it("skips refused keys: model, prompt, schema, stream and the limit stay as built", () => {
		const out = mergeRequestFields(body, {
			model: "other",
			messages: null,
			response_format: null,
			max_tokens: 99999,
			stream: true,
			seed: 1,
		})
		expect(out.model).toBe("m")
		expect(out.messages).toEqual(body.messages)
		expect(out.response_format).toEqual(body.response_format)
		expect(out.max_tokens).toBe(300)
		expect("stream" in out).toBe(false)
		expect(out.seed).toBe(1)
	})
})

describe("extraRequestFieldsProblem", () => {
	it("accepts undefined and plain objects", () => {
		expect(extraRequestFieldsProblem(undefined)).toBeUndefined()
		expect(extraRequestFieldsProblem({ reasoning_effort: "none" })).toBeUndefined()
	})

	it("rejects non-objects", () => {
		for (const v of [null, [], "x", 3, true]) expect(extraRequestFieldsProblem(v)).toMatch(/JSON object/)
	})

	it("names every refused key", () => {
		expect(extraRequestFieldsProblem({ max_tokens: 1, model: "x" })).toMatch(/max_tokens, model/)
	})
})
