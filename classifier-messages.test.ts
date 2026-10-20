/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest"

import {
	AUTO_MODE_REJECTION_PREFIX,
	buildClassifierUnavailableMessage,
	buildYoloRejectionMessage,
	DENIAL_WORKAROUND_GUIDANCE,
	isClassifierDenial,
} from "./classifier-messages.ts"

const REASON = "removing files outside the project directory"

describe("classifier-messages", () => {
	it("marks its own rejections as denials", () => {
		expect(isClassifierDenial(buildYoloRejectionMessage(REASON))).toBe(true)
	})

	it("does not treat ordinary text as a denial", () => {
		expect(isClassifierDenial("")).toBe(false)
		expect(isClassifierDenial("Sure, here is the summary you asked for.")).toBe(false)
		// Similar meaning, wrong lead-in: detection is a prefix test, not a paraphrase test.
		expect(isClassifierDenial(`Denied. Reason: ${REASON}`)).toBe(false)
		expect(isClassifierDenial(`hidden ${AUTO_MODE_REJECTION_PREFIX}`)).toBe(false)
	})

	it("keeps the prefix short and open so a reason can be appended to it", () => {
		expect(AUTO_MODE_REJECTION_PREFIX.length).toBeLessThan(80)
		expect(AUTO_MODE_REJECTION_PREFIX.endsWith(" ")).toBe(true)
	})

	it("puts the reason directly behind the prefix, unedited", () => {
		const msg = buildYoloRejectionMessage(REASON)
		expect(msg.startsWith(`${AUTO_MODE_REJECTION_PREFIX}${REASON}`)).toBe(true)
		expect(msg.slice(AUTO_MODE_REJECTION_PREFIX.length).startsWith(REASON)).toBe(true)
	})

	it("embeds the shared workaround advice verbatim", () => {
		const msg = buildYoloRejectionMessage(REASON)
		expect(msg).toContain(DENIAL_WORKAROUND_GUIDANCE)
		expect(DENIAL_WORKAROUND_GUIDANCE.length).toBeGreaterThan(200)
	})

	it("orders the advice: reason, then carry on elsewhere, then detour rules, then rules", () => {
		const msg = buildYoloRejectionMessage(REASON)
		const advice = msg.indexOf(DENIAL_WORKAROUND_GUIDANCE)
		const ruleFile = msg.indexOf("adaptive-acl.json")
		expect(msg.indexOf(REASON)).toBeLessThan(advice)
		expect(advice).toBeLessThan(ruleFile)
		expect(ruleFile).toBeGreaterThan(-1)
		// Independent work is offered before the model starts looking for detours.
		expect(/[Uu]ntouched/.test(msg.slice(0, advice))).toBe(true)
	})

	it("offers both an honest detour and a bad-faith example in the advice", () => {
		expect(DENIAL_WORKAROUND_GUIDANCE).toMatch(/ls tool/)
		expect(DENIAL_WORKAROUND_GUIDANCE).toMatch(/bash -c/)
		expect(DENIAL_WORKAROUND_GUIDANCE).toMatch(/bad-faith/)
		// Escalation to a human stays part of the reusable advice.
		expect(DENIAL_WORKAROUND_GUIDANCE).toMatch(/wait for their call/)
	})

	it("points at this plugin's real rule syntax, not an invented one", () => {
		const msg = buildYoloRejectionMessage(REASON)
		expect(msg).toContain("adaptive-acl.json")
		expect(msg).toContain("permissions.json")
		expect(msg).toMatch(/Bash\(<command prefix>:\*\)/)
		expect(msg).toMatch(/Read\(<path>\)/)
		expect(msg).not.toContain("Bash(prompt:")
	})

	it("names both the tool and the model when the classifier cannot be reached", () => {
		const msg = buildClassifierUnavailableMessage("bash", "anthropic/claude-haiku-4-5")
		expect(msg).toContain("bash")
		expect(msg).toContain("anthropic/claude-haiku-4-5")
	})

	it("offers wait-and-retry plus a fallback, and exempts read-only steps", () => {
		const msg = buildClassifierUnavailableMessage("write", "openai/gpt-4o-mini")
		expect(msg).toMatch(/wait a moment/i)
		expect(msg).toMatch(/again/i)
		expect(msg).toMatch(/come back to it later/i)
		expect(msg).toMatch(/read-only/i)
		expect(msg).toMatch(/classifier/i)
		// A refusal notice is not a denial: nothing was judged, so nothing carries the prefix.
		expect(isClassifierDenial(msg)).toBe(false)
	})
})
