/**
 * Permission rule strings — `Tool` or `Tool(specifier)` — plus the escape codec that carries a
 * specifier between its in-file spelling and its in-memory value.
 *
 * Parsing is one left-to-right walk carrying a single bit of state: whether the previous
 * character was an unescaped backslash. An armed backslash makes the next character literal
 * data, so nothing has to be looked "escaped" by scanning backwards for a run of backslashes,
 * and both parentheses we care about fall out of the same walk.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

export interface PermissionRuleValue {
	toolName: string
	ruleContent?: string
}

/**
 * The whole escape vocabulary. Each escapable character maps to its own escaped spelling, which
 * also defines what is escapable: anything else that follows a backslash (`\n`, `\*`) is data in
 * both directions, and so is a backslash with nothing after it.
 */
const ESCAPES: Readonly<Record<string, string | undefined>> = {
	"\\": "\\\\",
	"(": "\\(",
	")": "\\)",
}

/** Specifiers that mean "this tool, whatever the arguments". */
const TOOL_WIDE = new Set(["", "*"])

export function unescapeRuleContent(content: string): string {
	const end = content.length
	let decoded = ""
	let at = 0
	while (at < end) {
		// A backslash means something only directly in front of an escapable character; step over
		// the pair and keep the character itself. Anywhere else it is just a backslash — including
		// one at the very end, where `content[at + 1]` is undefined and so is not in ESCAPES.
		if (content[at] === "\\" && ESCAPES[content[at + 1]] !== undefined) {
			decoded += content[at + 1]
			at += 2
			continue
		}
		decoded += content[at]
		at += 1
	}
	return decoded
}

export function escapeRuleContent(content: string): string {
	const end = content.length
	let encoded = ""
	// Everything below `copied` is already in `encoded`; ordinary runs are carried over in one slice.
	let copied = 0
	for (let at = 0; at < end; at++) {
		const escaped = ESCAPES[content[at]]
		if (escaped === undefined) continue
		if (at > copied) encoded += content.slice(copied, at)
		encoded += escaped
		copied = at + 1
	}
	// No special character at all: hand back the input instead of rebuilding it.
	if (copied === 0) return content
	return encoded + content.slice(copied)
}

/** Where the specifier is delimited: the first and the last parenthesis not eaten by an escape. */
type SpecifierBounds = { open: number; close: number }

function scanSpecifierBounds(rule: string): SpecifierBounds {
	const end = rule.length
	let open = -1
	let close = -1
	let armed = false
	for (let at = 0; at < end; at++) {
		const ch = rule[at]
		// A run of backslashes arms the character after it only when the run is odd; toggling once
		// per character tracks that parity without ever counting.
		if (ch === "\\") {
			armed = !armed
			continue
		}
		if (!armed) {
			if (ch === "(" && open === -1) open = at
			if (ch === ")") close = at
		}
		armed = false
	}
	return { open, close }
}

/** What any string that is not a well-formed call reduces to: the trimmed whole thing is the name. */
function ruleIsJustAToolName(rule: string): PermissionRuleValue {
	return { toolName: rule.trim() }
}

export function permissionRuleValueFromString(ruleString: string): PermissionRuleValue {
	const { open, close } = scanSpecifierBounds(ruleString)

	// Only a call whose closing paren is the very last character of the input carries a specifier.
	// So `"Bash(ls) "` — trailing whitespace included — stays one (unmatchable) tool name, while
	// whitespace *inside* the parens is specifier text and survives verbatim.
	if (open === -1 || close <= open || close !== ruleString.length - 1) {
		return ruleIsJustAToolName(ruleString)
	}

	const toolName = ruleString.slice(0, open).trim()
	if (toolName === "") return ruleIsJustAToolName(ruleString)

	const specifier = ruleString.slice(open + 1, close)
	if (TOOL_WIDE.has(specifier)) return { toolName }

	return { toolName, ruleContent: unescapeRuleContent(specifier) }
}

export function permissionRuleValueToString(ruleValue: PermissionRuleValue): string {
	const { toolName, ruleContent } = ruleValue
	// No specifier — absent or empty — means the tool-level rule, spelled without parentheses.
	if (!ruleContent) return toolName
	return `${toolName}(${escapeRuleContent(ruleContent)})`
}
