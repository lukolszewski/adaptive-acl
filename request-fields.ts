/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * `classifier.extraRequestFields`: the user's own fields, merged into a classifier request body last.
 *
 * The client used to add a chat-template knob to every request; which field turns thinking off (or sets a seed,
 * or tags spend on a gateway) depends on the server, so it is the user's config, not a guess made here.
 */

import { REFUSED_EXTRA_REQUEST_FIELDS } from "./config.ts"

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v)
}

/**
 * Why `fields` cannot be used, or `undefined` when it can. Config loading reports this as an error; the merge
 * below refuses the same keys again so a value that skipped validation still cannot replace the schema.
 */
export function extraRequestFieldsProblem(fields: unknown): string | undefined {
	if (fields === undefined) return undefined
	if (!isPlainObject(fields)) return "classifier.extraRequestFields must be a JSON object"
	const refused = Object.keys(fields).filter((k) => REFUSED_EXTRA_REQUEST_FIELDS.includes(k))
	if (refused.length > 0) {
		return `classifier.extraRequestFields may not set ${refused.join(", ")} (the classifier owns ${
			refused.length === 1 ? "this field" : "these fields"
		}; use classifier.maxOutputTokens for the answer limit)`
	}
	return undefined
}

/** Deep merge: objects merge key by key, `null` deletes the key, anything else (arrays included) replaces. */
function mergeInto(target: Record<string, unknown>, extra: Record<string, unknown>): void {
	for (const [key, value] of Object.entries(extra)) {
		if (value === null) {
			delete target[key]
		} else if (isPlainObject(value) && isPlainObject(target[key])) {
			const nested = { ...(target[key] as Record<string, unknown>) }
			mergeInto(nested, value)
			target[key] = nested
		} else if (isPlainObject(value)) {
			const nested: Record<string, unknown> = {}
			mergeInto(nested, value)
			target[key] = nested
		} else {
			target[key] = value
		}
	}
}

/**
 * A new body with `extra` merged in. The input is never mutated. Refused top-level keys are skipped, never
 * applied: the model, the prompt and the output schema stay what the classifier built.
 */
export function mergeRequestFields(
	body: Record<string, unknown>,
	extra: Record<string, unknown> | undefined,
): Record<string, unknown> {
	const out = { ...body }
	if (!extra || !isPlainObject(extra)) return out
	const allowed: Record<string, unknown> = {}
	for (const [k, v] of Object.entries(extra)) {
		if (!REFUSED_EXTRA_REQUEST_FIELDS.includes(k)) allowed[k] = v
	}
	mergeInto(out, allowed)
	return out
}
