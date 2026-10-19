/**
 * The transcript we show the safety model.
 *
 * It holds exactly two kinds of evidence: what the user typed, and which tools the agent ran with
 * what arguments. Assistant prose is left out on purpose — the model being graded is the one that
 * wrote it, so quoting it back would let that same text argue for its own actions.
 *
 * Two spellings come out of `toCompactBlock`: a human-readable line (`User: …`, `Bash {…}`) and,
 * with `jsonlTranscript`, one JSON object per block. Both are capped by the caller's entry/char
 * budget, oldest entries dropped first.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { redactForClassifier } from "./classifier-redact.ts"
import { toClassifierInput } from "./classifier-tool-projection.ts"
import { tokensToChars } from "./context-budget.ts"

export type TranscriptBlock =
	| { type: "text"; text: string }
	| { type: "tool_use"; name: string; input: unknown }

export type TranscriptEntry = {
	role: "user" | "assistant"
	content: TranscriptBlock[]
}

type PiMessageEntry = {
	type?: string
	message?: {
		role?: string
		content?: unknown
	}
}

function extractUserText(content: unknown): string[] {
	const texts: string[] = []
	if (typeof content === "string" && content.trim()) {
		texts.push(content.trim())
		return texts
	}
	if (!Array.isArray(content)) return texts
	for (const block of content) {
		if (block?.type === "text" && typeof block.text === "string") {
			const t = block.text.trim()
			if (t) texts.push(t)
		}
	}
	return texts
}

function extractAssistantToolCalls(content: unknown): TranscriptBlock[] {
	const blocks: TranscriptBlock[] = []
	if (!Array.isArray(content)) return blocks
	for (const block of content) {
		if (block?.type === "toolCall" && typeof block.name === "string") {
			blocks.push({
				type: "tool_use",
				name: block.name,
				input: block.arguments ?? {},
			})
		}
		// Older sessions stored on disk carry the block under its transport name rather than pi's
		if (block?.type === "tool_use" && typeof block.name === "string") {
			blocks.push({
				type: "tool_use",
				name: block.name,
				input: block.input ?? {},
			})
		}
	}
	return blocks
}

/** Build transcript from pi session branch entries (getBranch()). */
export function buildTranscriptEntriesFromBranch(
	branch: PiMessageEntry[],
): TranscriptEntry[] {
	const transcript: TranscriptEntry[] = []
	for (const entry of branch) {
		if (entry?.type !== "message") continue
		const msg = entry.message
		if (!msg?.role) continue

		if (msg.role === "user") {
			const texts = extractUserText(msg.content)
			if (texts.length === 0) continue
			transcript.push({
				role: "user",
				content: texts.map((text) => ({ type: "text", text })),
			})
			continue
		}

		if (msg.role === "assistant") {
			const toolBlocks = extractAssistantToolCalls(msg.content)
			if (toolBlocks.length === 0) continue
			transcript.push({ role: "assistant", content: toolBlocks })
		}
	}
	return transcript
}

function encodeToolValue(toolName: string, input: unknown): unknown {
	try {
		return toClassifierInput(toolName, (input ?? {}) as Record<string, unknown>)
	} catch {
		return input
	}
}

function toCompactBlock(
	block: TranscriptBlock,
	role: TranscriptEntry["role"],
	jsonl: boolean,
): string {
	if (block.type === "tool_use") {
		const encoded = encodeToolValue(
			block.name,
			block.input as Record<string, unknown>,
		)
		if (encoded === "") return ""
		if (jsonl) {
			return `${JSON.stringify({ [block.name]: encoded })}\n`
		}
		const s =
			typeof encoded === "string" ? encoded : JSON.stringify(encoded)
		return `${block.name} ${s}\n`
	}
	if (block.type === "text" && role === "user") {
		const text = redactForClassifier(block.text)
		return jsonl
			? `${JSON.stringify({ user: text })}\n`
			: `User: ${text}\n`
	}
	return ""
}

function toCompact(entry: TranscriptEntry, jsonl: boolean): string {
	return entry.content
		.map((b) => toCompactBlock(b, entry.role, jsonl))
		.join("")
}

export function formatActionForClassifier(
	toolName: string,
	toolInput: unknown,
): TranscriptEntry {
	return {
		role: "assistant",
		content: [{ type: "tool_use", name: toolName, input: toolInput }],
	}
}

export function buildTranscriptForClassifier(
	branch: PiMessageEntry[],
	jsonl = false,
	maxEntries = 40,
	maxChars = 12_000,
	budgetTokens?: number,
): string {
	// A token budget, when the caller has one (it knows the model's window), replaces the fixed
	// character cap; entries are still dropped whole from the oldest end and never truncated — dropping
	// one is a statement about the conversation, shortening one is a lie.
	const budgeted = budgetTokens !== undefined
	const charBudget = budgeted ? tokensToChars(budgetTokens!) : maxChars
	// Without a budget the oldest-entry drop stops at one entry, as it always has: something is better
	// than nothing when the cap is only a courtesy. A token budget is not a courtesy — it is the size of
	// the server's window — so under a budget even the newest entry goes rather than overflow.
	const keepAtLeast = budgeted ? 0 : 1
	const entries = buildTranscriptEntriesFromBranch(branch)
	let slice =
		entries.length > maxEntries ? entries.slice(-maxEntries) : entries
	let text = slice.map((e) => toCompact(e, jsonl)).join("")
	while (slice.length > keepAtLeast && text.length > charBudget) {
		slice = slice.slice(1)
		text = slice.map((e) => toCompact(e, jsonl)).join("")
	}
	return text
}

export function compactTranscriptEntry(
	entry: TranscriptEntry,
	jsonl = false,
): string {
	return toCompact(entry, jsonl)
}
