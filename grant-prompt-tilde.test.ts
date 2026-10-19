/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Two failure modes that silently cost a user their grant.
 *
 * 1. `~` in what we send the model. A user wrote "I allow you to read
 *    /home/u/.pi config contents"; the gate rendered the target as
 *    `~/.pi/agent/permission-modes.json`. To a model that has never seen this
 *    machine those are unrelated strings, and it answered "not authorised" with an
 *    empty quote even though the grant was in the very message list it was given.
 *
 * 2. An action our category table cannot name. It is stored under a `*action*`
 *    label, and `compatible()` treats only bare `"*"` as a wildcard — so the grant
 *    is recorded and covers nothing, which is indistinguishable from never having
 *    been granted.
 */
import { describe, expect, it } from "vitest"
import { homedir } from "node:os"
import { absolutize, buildGrantUserPrompt } from "./model-client.ts"
import { eventsFromExtraction, extractionStats, mapActionToCategory } from "./auth-ledger.ts"

const TARGET = { kind: "target" as const, value: "~/.pi/agent/permission-modes.json" }
const QUOTE = "I allow you to read /home/u/.pi config contents"

function prompt(overrides: Partial<Parameters<typeof buildGrantUserPrompt>[0]> = {}) {
	return buildGrantUserPrompt({
		userMessages: [QUOTE],
		description: "read secret-bearing path ~/.pi/agent/permission-modes.json",
		category: "read_secret",
		entities: [TARGET],
		command: "jq . ~/.pi/agent/permission-modes.json",
		...overrides,
	})
}

describe("the grant question cannot hide behind a tilde", () => {
	it("shows the model absolute targets", () => {
		const p = prompt()
		expect(p).toContain(`${homedir()}/.pi/agent/permission-modes.json`)
		expect(p).not.toContain("Action targets: ~/.")
	})

	it("states the equivalence outright, in case expansion misses", () => {
		expect(prompt()).toContain(`"~" means ${homedir()}`)
	})

	it("expands embedded paths, not just whole values", () => {
		expect(absolutize("~/a", "/home/u")).toBe("/home/u/a")
		expect(absolutize("jq . ~/a/b --arg x=~/c", "/home/u")).toBe("jq . /home/u/a/b --arg x=/home/u/c")
	})

	it("leaves absolute and relative paths alone", () => {
		expect(absolutize("/already/abs", "/home/u")).toBe("/already/abs")
		expect(absolutize("src/x.ts", "/home/u")).toBe("src/x.ts")
	})
})

describe("a grant that cannot register is visible", () => {
	it("'read files' maps now — it used to fall through and register nothing", () => {
		// Regression pin for the hole this closed: ACTION_MAP had no read
		// row at all, so a user's explicit folder read became the inert label `*read files*`.
		// Asserting the CLOSED hole, and that the secret row still wins by ordering.
		expect(mapActionToCategory("read files")).toBe("read_only")
		expect(mapActionToCategory("read secret files")).toBe("read_secret")
	})

	it("counts the unmapped action and keeps its wording", () => {
		const before = extractionStats.unmapped
		const events = eventsFromExtraction(
			{ grants: [{ action: "frobnicate widgets", targets: ["/home/u/.pi"], quote: QUOTE }], revocations: [] } as never,
			"m1",
			1,
			QUOTE,
		)
		expect(extractionStats.unmapped).toBe(before + 1)
		expect(extractionStats.lastUnmapped).toBe("frobnicate widgets")
		// the recorded label can never match a real pending category
		expect(events.some((e) => e.category === "*frobnicate widgets*")).toBe(true)
	})

	it("counts a mapped action as mapped", () => {
		const before = extractionStats.mapped
		eventsFromExtraction(
			{ grants: [{ action: "delete the build dir", targets: ["/home/u/proj/build"], quote: "delete /home/u/proj/build" }], revocations: [] } as never,
			"m2",
			2,
			"delete /home/u/proj/build",
		)
		expect(extractionStats.mapped).toBe(before + 1)
	})
})

// ---------------------------------------------------------------- ledger rows in the same prompt (context budget item 3)

// Appended here rather than merged into the header import block, so nothing above this line changed.
import { GRANT_SYSTEM_PROMPT, grantCallFixedChars } from "./model-client.ts"

/** Two rows in the shape `ledger-render.ts` emits: absolute values, one line each, quote attached. */
const ROWS = [
	`#3 grant   write_outside scope=${homedir()}/dev/x/ — "you can write anything under ${homedir()}/dev/x"`,
	`#5 forbid  * scope=${homedir()}/etc/ — "never touch ${homedir()}/etc"`,
]
const SECTION = `Authorisation so far (verified earlier, oldest first):\n${ROWS.join("\n")}\n\n`
const FIXED = {
	description: "read secret-bearing path ~/.pi/agent/permission-modes.json",
	category: "read_secret",
	entities: [TARGET],
	command: "jq . ~/.pi/agent/permission-modes.json",
}

describe("the ledger block in the grant prompt", () => {
	// The regression this pins: a caller that passes an empty list must not get a stray header,
	// because every existing prompt-shape test (and the token measurement) assumes today's bytes.
	it("is byte-identical when there are no rows — empty list and absent key alike", () => {
		expect(prompt({ ledgerRows: [] })).toBe(prompt())
		expect(prompt({ ledgerRows: undefined })).toBe(prompt())
		expect(grantCallFixedChars({ ...FIXED, ledgerRows: [] })).toBe(grantCallFixedChars(FIXED))
	})

	it("opens the prompt, ahead of the message list, and moves nothing else", () => {
		const withRows = prompt({ ledgerRows: ROWS })
		expect(withRows.startsWith(SECTION)).toBe(true)
		expect(withRows).toContain(`${SECTION}User messages (oldest first):`)
		expect(withRows.indexOf("User messages")).toBeLessThan(withRows.indexOf("Pending action"))
		// every byte that used to be at the start is the same, just pushed down by the block
		expect(withRows.slice(SECTION.length)).toBe(prompt())
	})

	it("costs exactly what it renders, which is how the gate budgets it", () => {
		// `grantCallFixedChars` renders the real prompt with an empty message list, so the difference
		// between the two calls IS the section — no block size is estimated anywhere.
		const grown = grantCallFixedChars({ ...FIXED, ledgerRows: ROWS }) - grantCallFixedChars(FIXED)
		expect(grown).toBe(SECTION.length)
		expect(SECTION.length).toBeGreaterThan(0)
	})

	it("is explained to the model in the system prompt", () => {
		expect(GRANT_SYSTEM_PROMPT).toContain('"Authorisation so far"')
		expect(GRANT_SYSTEM_PROMPT).toContain('overrides an earlier "grant" line')
	})
})
