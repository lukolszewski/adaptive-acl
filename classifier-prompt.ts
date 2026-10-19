/** Assembles the auto-mode classifier system prompt from the bundled prompt templates. */
/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const PROMPTS_DIR = join(
	dirname(fileURLToPath(import.meta.url)),
	"classifier-prompts",
)

const BASE_FILE = "auto_mode_system_prompt.txt"
const RULES_FILE = "permissions_external.txt"

export type AutoModeRules = {
	allow?: string[]
	soft_deny?: string[]
	environment?: string[]
}

type RulesKey = keyof AutoModeRules

/**
 * Our placeholder vocabulary. A rule block is delimited by a `{{rules:*}}` pair; the
 * whole rules file and the verdict block are pulled into the base prompt by `{{include:*}}`.
 */
type RuleTag = { key: RulesKey; open: string; close: string }

const RULE_TAGS: readonly RuleTag[] = [
	{ key: "allow", open: "{{rules:allow}}", close: "{{/rules:allow}}" },
	{ key: "soft_deny", open: "{{rules:deny}}", close: "{{/rules:deny}}" },
	{ key: "environment", open: "{{rules:env}}", close: "{{/rules:env}}" },
]

const RULES_INCLUDE = "{{include:permissions}}"
const VERDICT_INCLUDE = "{{include:verdict}}"

const BULLET = "- "

const VERDICT_FORMAT = `## Verdict Format

Emit one JSON object as your entire reply: no markdown fences, no prose before or after it.
Shape: {"thinking": string, "shouldBlock": boolean, "reason": string}
- shouldBlock=true → hold the action for explicit user confirmation
- shouldBlock=false → allow the action to proceed unattended
Keep thinking to a few clauses and reason to one short sentence.`

// --------------------------------------------------------------------------------------
// File loading (cached; clearClassifierPromptCache drops it for tests)

const fileCache = new Map<string, string>()

function promptFile(name: string): string {
	const cached = fileCache.get(name)
	if (cached !== undefined) return cached
	const text = readFileSync(join(PROMPTS_DIR, name), "utf8")
	fileCache.set(name, text)
	return text
}

export function getBaseClassifierPrompt(): string {
	return promptFile(BASE_FILE)
}

export function getExternalPermissionsTemplate(): string {
	return promptFile(RULES_FILE)
}

/** For tests — drop cached prompt reads so the next call hits disk again. */
export function clearClassifierPromptCache(): void {
	fileCache.clear()
}

// --------------------------------------------------------------------------------------
// Placeholder mechanism (index arithmetic only — no regexes over the templates)

/** Byte span between an `open`/`close` marker pair, markers included. */
type Span = { from: number; bodyFrom: number; bodyTo: number; to: number }

function findSpan(text: string, open: string, close: string): Span | undefined {
	const from = text.indexOf(open)
	if (from < 0) return undefined
	const bodyFrom = from + open.length
	const bodyTo = text.indexOf(close, bodyFrom)
	if (bodyTo < 0) return undefined
	return { from, bodyFrom, bodyTo, to: bodyTo + close.length }
}

/** Splice `replacement` over `text`, replacing exactly the `[from, to)` span. */
function splice(text: string, span: Span, replacement: string): string {
	return text.slice(0, span.from) + replacement + text.slice(span.to)
}

/**
 * Swap the contents of a `{{rules:*}}` block. `replacement` of `undefined` keeps the
 * block exactly as written, which is how the bundled defaults survive untouched.
 */
function swapBlock(text: string, tag: RuleTag, replacement?: string): string {
	const span = findSpan(text, tag.open, tag.close)
	if (!span) return text
	const body = text.slice(span.bodyFrom, span.bodyTo)
	return splice(text, span, replacement ?? body)
}

/** Replace every occurrence of a standalone marker; an unresolved marker is dropped, never leaked. */
function swapMarker(
	text: string,
	marker: string,
	replacement?: string,
): string {
	let out = ""
	let cursor = 0
	for (;;) {
		const at = text.indexOf(marker, cursor)
		if (at < 0) break
		out += text.slice(cursor, at) + (replacement ?? "")
		cursor = at + marker.length
	}
	return out + text.slice(cursor)
}

/** The `- ` bullets inside a block, markers and bullet glyphs stripped. */
function readBullets(block: string): string[] {
	const found: string[] = []
	for (const line of block.split("\n")) {
		const trimmed = line.trim()
		if (trimmed.startsWith(BULLET)) {
			found.push(trimmed.slice(BULLET.length).trim())
		}
	}
	return found
}

/** Render caller-supplied rules as bullets, or `undefined` when the caller gave none. */
function renderBullets(values: readonly string[] | undefined): string | undefined {
	const kept = (values ?? [])
		.map((value) => value.trim())
		.filter((value) => value.length > 0)
	if (kept.length === 0) return undefined
	return kept.map((value) => `${BULLET}${value}`).join("\n")
}

// --------------------------------------------------------------------------------------
// Public assembly

export function getDefaultAutoModeRules(): AutoModeRules {
	const template = getExternalPermissionsTemplate()
	const defaults: AutoModeRules = {}
	for (const tag of RULE_TAGS) {
		const span = findSpan(template, tag.open, tag.close)
		defaults[tag.key] = span
			? readBullets(template.slice(span.bodyFrom, span.bodyTo))
			: []
	}
	return defaults
}

/**
 * Build the classifier system prompt. Rules supplied by the caller replace the defaults of
 * that one block only; omitted or empty blocks keep the defaults shipped in the template.
 */
export function buildClassifierSystemPrompt(autoMode?: AutoModeRules): string {
	let rules = getExternalPermissionsTemplate()
	for (const tag of RULE_TAGS) {
		rules = swapBlock(rules, tag, renderBullets(autoMode?.[tag.key]))
	}

	let prompt = getBaseClassifierPrompt()
	prompt = swapMarker(prompt, RULES_INCLUDE, rules)
	return swapMarker(prompt, VERDICT_INCLUDE, VERDICT_FORMAT)
}
