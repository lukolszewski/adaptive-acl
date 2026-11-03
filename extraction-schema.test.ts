/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The extraction schema's width fields, and what a row means when they are absent.
 *
 * Two things are pinned here, and neither is "a field round-trips":
 *
 *  1. The wire schema asks the model ONE question about width (`scope`) and asks it of
 *     revocations as well as grants. Revocations used to carry no category at all, which is
 *     how "do not delete any images" became an fs forbid that can never block a container
 *     command.
 *  2. A row that arrives WITHOUT those fields — an endpoint that ignores the strict schema,
 *     or a model that answers garbage — parses to the NARROWEST reading available. Dropping a
 *     junk value may make a row unusable; it may never make it blanket, never arm a
 *     session posture, never allow.
 *
 * Fixtures are recorded endpoint output, never hand-written ideals. Each block says what it is
 * and why the shape is what it is.
 */
import { afterEach, describe, expect, it, vi } from "vitest"

import { GRANT_CATEGORY_VALUES, REVOCATION_CATEGORY_VALUES, eventsFromExtraction } from "./auth-ledger.ts"
import { extractMessageGrants, MESSAGE_GRANT_SYSTEM_PROMPT, type MessageExtraction } from "./model-client.ts"

const EP = { baseUrl: "http://mock", model: "mock", timeoutMs: 1000 }

/** Bodies of every request the stubbed transport saw — the schema is module-private, so the
 *  only honest way to assert on it is to read what actually went out. */
let bodies: Record<string, unknown>[] = []

function stubTransport(answer: unknown): void {
	bodies = []
	vi.stubGlobal("fetch", async (_url: string, init: { body?: string }) => {
		bodies.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>)
		const text = JSON.stringify({ choices: [{ message: { content: JSON.stringify(answer) } }] })
		return { ok: true, status: 200, text: async () => text } as Response
	})
}

/** Run one extraction through the real parser and return what the ledger will receive. */
async function parse(answer: unknown): Promise<MessageExtraction> {
	stubTransport(answer)
	const r = await extractMessageGrants(EP, "a message")
	if (!r.ok) throw new Error(`stubbed call failed: ${r.error}`)
	return r.value
}

function sentSchema(): any {
	return (bodies[0]! as any).response_format.json_schema.schema
}

function itemSchema(list: "grants" | "revocations"): any {
	return sentSchema().properties[list].items
}

const SCOPES = ["named", "category", "everything"]
const CLASSES = ["none", "rule_files"]
/** `targetClass` is on the GRANT side with its own two values. The two sides do not share an enum:
 *  a grant may name the temp class and never the plugin's rule files, a revocation the other way round.
 *  The GRANT enum also names `local_machine` and `current_cluster`, for the same reason `temp_files`
 *  exists — "this machine" and "my cluster" are objects the user points at without writing a
 *  string, so there is nothing for the verbatim check to find. The revocation side is untouched: withdrawing
 *  permission over a machine is still not a class, and this side can never name the plugin's rule files. */
const GRANT_CLASSES = ["none", "temp_files", "local_machine", "current_cluster"]
const REQUIRED = {
	grants: ["action", "category", "kind", "scope", "targetClass", "includesSecrets", "targets", "quote"],
	revocations: ["action", "category", "scope", "targetClass", "targets", "quote"],
}

/** One empty answer, captured so the schema can be inspected. */
async function captureSchema(): Promise<void> {
	await parse({ grants: [], revocations: [] })
}

/** The shape a revocation's `category` must have on the wire: ONE shape, an array — `anyOf` was tried and
 *  measured worse, while the parser still reads the older bare string, so tolerance does not need a second
 *  branch in the grammar. */
function categoryField(): any {
	return itemSchema("revocations").properties.category
}

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("the wire schema: width is asked, once, as an enum", () => {
	it("revocations carry category, scope and targetClass, all required", async () => {
		await captureSchema()
		const item = itemSchema("revocations")
		// `category` was a single enum value, then an array, then `anyOf: [string, array]` for one round, and is
		// an array again because that is what measured better on the smallest model tried (loosening 151 base /
		// 160 array / 166 anyOf over 233 real session messages) at the same score on the two larger ones.
		// Stronger than the original single-enum assertion: the ELEMENT enum is checked against the full
		// vocabulary, it must contain every grant value AND `any`, and the list is bounded — and the second test in
		// this file pins that a bare string still parses, which is where the old shape is honoured.
		const field = categoryField()
		expect(field.type).toBe("array")
		expect(field.anyOf).toBeUndefined()
		expect(field.items.enum).toEqual([...REVOCATION_CATEGORY_VALUES])
		expect(field.minItems).toBe(1)
		expect(field.maxItems).toBeGreaterThan(1)
		expect(item.properties.scope.enum).toEqual(SCOPES)
		expect(item.properties.targetClass.enum).toEqual(CLASSES)
		expect(item.required).toEqual(REQUIRED.revocations)
		expect(item.additionalProperties).toBe(false)
	})

	it("`any` is on the revocation enum and never on the grant one", async () => {
		// The asymmetry is the design: only a forbid may withdraw every action, because a missed grant row costs
		// a prompt while a missed forbid category costs an allow. A grant row naming `any` is dropped by
		// validation, and the schema never offers it, so the model is not even asked for it.
		await captureSchema()
		const field = categoryField()
		expect(field.items.enum).toContain("any")
		expect(GRANT_CATEGORY_VALUES).not.toContain("any")
		expect(itemSchema("grants").properties.category.enum).not.toContain("any")
		for (const value of GRANT_CATEGORY_VALUES) {
			expect(field.items.enum, value).toContain(value)
		}
	})

	it("grants carry the same scope enum, beside the unchanged kind", async () => {
		await captureSchema()
		const item = itemSchema("grants")
		expect(item.properties.scope.enum).toEqual(SCOPES)
		expect(item.required).toEqual(REQUIRED.grants)
		// kind (is the named thing a location?) and scope (how wide within its category?) are
		// different questions and stay separate fields.
		expect(item.properties.kind.enum).toEqual(["entity", "scope"])
		// The grant class enum, and it is NOT the revocation's — `rule_files` cannot be named by a grant.
		expect(item.properties.targetClass.enum).toEqual(GRANT_CLASSES)
		expect(item.properties.targetClass.enum).not.toContain("rule_files")
		expect(itemSchema("revocations").properties.targetClass.enum).toEqual(CLASSES)
		expect(itemSchema("revocations").properties.targetClass.enum).not.toContain("temp_files")
	})

	it("`all` is off the wire — one field answers width, so two cannot disagree", async () => {
		await captureSchema()
		expect(itemSchema("revocations").properties.all).toBeUndefined()
		expect(itemSchema("revocations").required).not.toContain("all")
		expect(JSON.stringify(sentSchema())).not.toContain('"all"')
	})

	it("strict mode still holds: every property of every item is required", async () => {
		await captureSchema()
		for (const list of ["grants", "revocations"] as const) {
			const item = itemSchema(list)
			expect(Object.keys(item.properties).sort()).toEqual([...item.required].sort())
			expect(item.additionalProperties).toBe(false)
		}
		expect((bodies[0]! as any).response_format.json_schema.strict).toBe(true)
	})
})

/**
 * Recorded output. These came from the PREVIOUS schema, so they are exactly what an endpoint that ignores the
 * new fields sends: no category, no scope, no targetClass, plus an `all` we no longer ask for.
 */
const RECORDED = {
	forcePush: {
		message: "yes, force-push it, I know the branch history is messed up",
		answer: {
			grants: [
				{
					action: "force push to remote",
					category: "vcs_force_protected",
					kind: "entity",
					includesSecrets: false,
					targets: ["it"],
					quote: "force-push it",
				},
			],
			revocations: [
				{ action: "rewrite history", targets: ["it"], all: false, quote: "I know the branch history is messed up" },
			],
		},
	},
	containerDelete: {
		message: "you can delete the payments:staging image",
		answer: {
			grants: [
				{
					action: "delete image",
					category: "container_wipe",
					kind: "entity",
					includesSecrets: false,
					targets: ["payments:staging"],
					quote: "you can delete the payments:staging image",
				},
			],
			revocations: [],
		},
	},
	containerDeleteRevoke: {
		message: "actually never mind, do not delete any images",
		answer: {
			grants: [],
			revocations: [{ action: "delete files", targets: [], all: true, quote: "do not delete any images" }],
		},
	},
}

describe("a row with no width field parses to the narrowest reading", () => {
	it("recorded revocation with no category and no scope: an empty category list, 'named', and NOT blanket", async () => {
		const row = (await parse(RECORDED.containerDeleteRevoke.answer)).revocations[0]!
		// An unusable category used to read as the string "other"; the field is a list now, so it reads as NO
		// usable category. Same meaning, same fail-safe — the ledger turns it into one defused row.
		expect(row.category).toEqual([])
		expect(row.scope).toBe("named")
		expect(row.targetClass).toBe("none")
		// Derived `all` is false: a row that never said "everything" cannot lock a session.
		// The cost is one extra model call at the gate, never a wrong allow.
		expect(row.all).toBe(false)
		expect(row.quote).toBe("do not delete any images")
	})

	it("recorded junk revocation keeps its shape — no widening, and no English parsed here", async () => {
		const row = (await parse(RECORDED.forcePush.answer)).revocations[0]!
		expect(row.all).toBe(false)
		expect(row.scope).toBe("named")
		// The pronoun target is untouched at this layer: dropping it is auth-ledger's job, and a
		// parse step that read meaning out of "it" would be code interpreting English.
		expect(row.targets).toEqual(["it"])
	})

	it("recorded grant keeps the model's category and defaults to scope 'named'", async () => {
		const row = (await parse(RECORDED.containerDelete.answer)).grants[0]!
		expect(row.category).toBe("container_wipe")
		expect(row.scope).toBe("named")
		expect(row.kind).toBe("entity")
		expect(row.targets).toEqual(["payments:staging"])
	})
})

describe("garbage in, narrow row out — never a lock, never an allow", () => {
	it("a scope that is not one of the three enum values becomes 'named'", async () => {
		for (const junk of ["all", "Everything", "category ", "", null, 7, true, undefined]) {
			const row = (
				await parse({ grants: [], revocations: [{ action: "a", scope: junk, targets: [], quote: "q" }] })
			).revocations[0]!
			expect(row.scope).toBe("named")
			expect(row.all).toBe(false)
		}
	})

	it("a category outside the enum is discarded — the model's guess is not obeyed", async () => {
		for (const junk of ["delete_everything", "unproven_value", "fs-write", "", null]) {
			const rows = await parse({
				grants: [{ action: "g", category: junk, kind: "entity", includesSecrets: false, targets: [], quote: "q" }],
				revocations: [{ action: "r", category: junk, scope: "category", targetClass: "none", targets: [], quote: "q" }],
			})
			expect(rows.grants[0]!.category).toBe("other")
			// The revocation side is a list, so a discarded value is an empty list. Nothing is
			// invented to fill it: an empty list means the ledger defuses the row (one model call), never "*".
			expect(rows.revocations[0]!.category).toEqual([])
			// Width is a separate field: an unusable category does not silently widen the row,
			// and `category` scope stays the model's own statement, not code's consolation prize.
			expect(rows.revocations[0]!.scope).toBe("category")
			expect(rows.revocations[0]!.all).toBe(true)
		}
	})

	it("targetClass is validated too: only 'rule_files' means anything", async () => {
		const bad = (await parse({ grants: [], revocations: [{ action: "r", targetClass: "files", targets: [], quote: "q" }] })).revocations[0]!
		expect(bad.targetClass).toBe("none")
		const good = (await parse({ grants: [], revocations: [{ action: "r", targetClass: "rule_files", targets: [], quote: "q" }] })).revocations[0]!
		expect(good.targetClass).toBe("rule_files")
		// Naming a class is not naming a width: the row stays as narrow as its scope says.
		expect(good.all).toBe(false)
	})

	it("a row that says 'everything' is blanket because THE MODEL said so, not because code gave up", async () => {
		const row = (
			await parse({
				grants: [],
				revocations: [
					{
						action: "change anything",
						category: "other",
						scope: "everything",
						targetClass: "none",
						targets: [],
						quote: "do not change anything",
					},
				],
			})
		).revocations[0]!
		expect(row.scope).toBe("everything")
		expect(row.all).toBe(true)
	})

	it("a named revocation that ALSO claims all:true on a stale answer keeps the narrow width", async () => {
		// A contradiction between the field we ask for (`scope`) and one we no longer send
		// (`all`). We never widen a returned "named" from a field that was not requested. The
		// error direction is one extra prompt at the gate, never an unapproved action.
		const row = (
			await parse({ grants: [], revocations: [{ action: "r", scope: "named", targets: ["~/backups"], all: true, quote: "q" }] })
		).revocations[0]!
		expect(row.scope).toBe("named")
		expect(row.all).toBe(false)
		expect(row.targets).toEqual(["~/backups"])
	})

	it("missing lists become empty lists, missing strings empty strings", async () => {
		const rows = await parse({ grants: null, revocations: [{}] })
		expect(rows.grants).toEqual([])
		expect(rows.revocations).toHaveLength(1)
		expect(rows.revocations[0]).toMatchObject({
			action: "",
			category: [],
			scope: "named",
			targetClass: "none",
			all: false,
			targets: [],
			quote: "",
		})
	})

	it("a non-array list yields no rows at all", async () => {
		const rows = await parse({ grants: "yes", revocations: { 0: {} } })
		expect(rows.grants).toEqual([])
		expect(rows.revocations).toEqual([])
	})
})

describe("a revocation's category is a list", () => {
	const rev = (category: unknown) =>
		parse({ grants: [], revocations: [{ action: "r", category, scope: "named", targetClass: "none", targets: ["/x"], quote: "q" }] })

	it("every kind the sentence withdrew survives, in order, without duplicates", async () => {
		const row = (await rev(["write_outside", "delete_outside", "write_outside"])).revocations[0]!
		expect(row.category).toEqual(["write_outside", "delete_outside"])
	})

	it("`any` is a value the revocation enum accepts", async () => {
		const row = (await rev(["any"])).revocations[0]!
		expect(row.category).toEqual(["any"])
		// Width is still its own field: `any` says WHICH ACTIONS, never how many targets — no field is
		// reinterpreted because a second one looks similar.
		expect(row.scope).toBe("named")
		expect(row.all).toBe(false)
	})

	it("a bare string is still read — recordings made before the list fold unchanged", async () => {
		expect((await rev("delete_data")).revocations[0]!.category).toEqual(["delete_data"])
	})

	it("one junk value does not poison the list, and a whole-list junk answer is empty", async () => {
		expect((await rev(["delete_data", "delete_everything"])).revocations[0]!.category).toEqual(["delete_data"])
		expect((await rev(["delete_everything", 7, null])).revocations[0]!.category).toEqual([])
	})

	it("a list longer than the schema allows is refused WHOLE, not truncated", async () => {
		// Keeping a prefix would drop a category the user named, which is a weaker ban that reads as obedience.
		// Refusing the list defuses the row: no auto-allow from it, one model call.
		const tooMany = ["read_only", "write_outside", "delete_outside", "system_config", "process_control", "network_send", "vcs_remote"]
		expect((await rev(tooMany)).revocations[0]!.category).toEqual([])
		expect((await rev(tooMany.slice(0, 6))).revocations[0]!.category).toHaveLength(6)
	})

	it("a GRANT row that names `any` is dropped by validation, not honoured", async () => {
		const rows = await parse({
			grants: [{ action: "g", category: "any", kind: "entity", scope: "named", targetClass: "none", includesSecrets: false, targets: ["/x"], quote: "q" }],
			revocations: [],
		})
		// `parseCategory` does not know the value, so the grant row arrives as "other" and the ledger registers
		// nothing from it: the work costs its ordinary prompt. A grant never buys every action.
		expect(rows.grants[0]!.category).toBe("other")
		const events = eventsFromExtraction(
			{ grants: [{ targets: ["/x"], category: "any", quote: "you may do anything to /x" }] } as never,
			"m1",
			1,
			"you may do anything to /x",
		)
		expect(events.filter((e) => e.type === "grant")).toHaveLength(0)
	})
})

describe("the parsed row reaches the ledger", () => {
	it("the recorded revocation still arrives as exactly one blanket forbid row, no posture", () => {
		// Pinned, not endorsed: while the row carries no category the ledger derives one from the
		// `action` label, which is the behaviour reading `r.category` replaces. What this test
		// owns is the contract the parser must not break — the row is not dropped, is not widened into
		// a session posture, and arrives exactly once.
		const events = eventsFromExtraction(
			{
				grants: [],
				revocations: [{ action: "delete files", targets: [], all: false, quote: "do not delete any images" }],
			} as never,
			"m1",
			7,
			RECORDED.containerDeleteRevoke.message,
		)
		expect(events.filter((e) => e.type === "forbid")).toHaveLength(1)
		expect(events.some((e) => e.type === "readonly-on")).toBe(false)
		expect(events[0]!.value).toBe("*")
	})
})

describe("the prompt explains every field the schema demands", () => {
	it("every required field name is defined in the prompt", async () => {
		await captureSchema()
		for (const list of ["grants", "revocations"] as const) {
			for (const key of itemSchema(list).required as string[]) {
				expect(MESSAGE_GRANT_SYSTEM_PROMPT, `${list}.${key}`).toContain(`"${key}"`)
			}
		}
	})

	it("the prompt's own examples are valid against the schema it sends", () => {
		// The "→ {json}" marker is OUR prompt's syntax, not user prose: this checks the examples
		// we ship so an example cannot drift from the schema the endpoint has to satisfy.
		const examples = promptExampleRows()
		expect(examples.length).toBeGreaterThanOrEqual(4)
		for (const example of examples) {
			for (const list of ["grants", "revocations"] as const) {
				const rows = example[list] as Array<Record<string, unknown>>
				expect(Array.isArray(rows), list).toBe(true)
				for (const row of rows) {
					for (const key of REQUIRED[list]) expect(Object.keys(row), `${list} row missing ${key}`).toContain(key)
					for (const key of Object.keys(row)) expect(ALLOWED[list], `${list}.${key}`).toContain(key)
					// A grant still names ONE value and may never name `any`; a revocation names a
					// non-empty list drawn from the revocation enum. Both halves are checked, so an example cannot
					// drift from the schema in either direction.
					if (list === "revocations") {
						expect(Array.isArray(row.category), JSON.stringify(row)).toBe(true)
						expect((row.category as unknown[]).length).toBeGreaterThan(0)
						for (const value of row.category as string[]) {
							expect(REVOCATION_CATEGORY_VALUES, value).toContain(value)
						}
					} else {
						expect(GRANT_CATEGORY_VALUES, String(row.category)).toContain(row.category)
						expect(row.category).not.toBe("any")
					}
					expect(SCOPES).toContain(row.scope)
					expect(typeof row.action).toBe("string")
					expect(Array.isArray(row.targets)).toBe(true)
					expect(typeof row.quote).toBe("string")
					if (list === "revocations") expect(CLASSES).toContain(row.targetClass)
					if (list === "grants") expect(["entity", "scope"]).toContain(row.kind)
				}
			}
		}
	})

	it("no example still uses the field that left the wire", () => {
		// Whole-prompt, not only the example rows: `all` left the wire (width is asked once, as `scope`),
		// so the prompt must not name it as a field anywhere. Ordinary English is fine - the quantity list under
		// "targets" says "all of them", which is not the quoted field name this check is about.
		expect(MESSAGE_GRANT_SYSTEM_PROMPT).not.toContain('"all"')
	})
})

/** The JSON of every "→ {…}" example line in the prompt, parsed. Prompt syntax, not user prose. */
function promptExampleRows(): Array<Record<string, unknown>> {
	return MESSAGE_GRANT_SYSTEM_PROMPT.split("\n")
		.filter((line) => line.includes("→ {"))
		.map((line) => JSON.parse(line.slice(line.indexOf("→ {") + 2).trim()) as Record<string, unknown>)
}

const ALLOWED = {
	grants: [...REQUIRED.grants],
	revocations: [...REQUIRED.revocations],
}
