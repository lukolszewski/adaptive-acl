/**
 * Pure helpers for the adaptive-acl extension.
 *
 * - Bash read-only classifier used by Plan mode and the default/accept-edits
 *   gates (SAFE allowlist AND not DESTRUCTIVE).
 * - Outside-cwd / project-root detection for the auto-mode relaxation.
 * - Numbered "Plan:" extraction and [DONE:n] step tracking used by Plan mode's
 *   execute/track flow.
 *
 * The plan-step helpers follow the shape of pi's own bundled
 * `examples/extensions/plan-mode/utils.ts` (MIT, pi coding agent contributors).
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, writeFileSync, unlinkSync } from "node:fs"
import { createHash } from "node:crypto"
import { homedir } from "node:os"
import path from "node:path"

const MAX_TRACKED_WRITES = 100

// Commands that mutate state — never allowed in plan mode, and prompt elsewhere.
const DESTRUCTIVE_PATTERNS: RegExp[] = [
	/\brm\b/i,
	/\brmdir\b/i,
	/\bmv\b/i,
	/\bcp\b/i,
	/\bmkdir\b/i,
	/\btouch\b/i,
	/\bchmod\b/i,
	/\bchown\b/i,
	/\bchgrp\b/i,
	/\bln\b/i,
	/\btee\b/i,
	/\btruncate\b/i,
	/\bdd\b/i,
	/\bshred\b/i,
	// File redirects only — fd-to-fd (2>&1 / >&2) is stripped before matching.
	/(^|[^<])>(?!>)/,
	/>>/, // append redirect
	/\bnpm\s+(install|uninstall|update|ci|link|publish)/i,
	/\byarn\s+(add|remove|install|publish)/i,
	/\bpnpm\s+(add|remove|install|publish)/i,
	/\bpip\s+(install|uninstall)/i,
	/\bapt(-get)?\s+(install|remove|purge|update|upgrade)/i,
	/\bbrew\s+(install|uninstall|upgrade)/i,
	/\bgit\s+(add|commit|push|pull|merge|rebase|reset|checkout|branch\s+-[dD]|stash|cherry-pick|revert|tag|init|clone)/i,
	/\bfind\b[^\n|;&]*\s-delete\b/i,
	/\bfind\b[^\n|;&]*\s-exec\b/i,
	/\bfind\b[^\n|;&]*\s-execdir\b/i,
	/\bfind\b[^\n|;&]*\s-fexec\b/i,
	/\bsudo\b/i,
	/\bsu\b/i,
	/\bkill\b/i,
	/\bpkill\b/i,
	/\bkillall\b/i,
	/\breboot\b/i,
	/\bshutdown\b/i,
	/\bsystemctl\s+(start|stop|restart|enable|disable)/i,
	/\bservice\s+\S+\s+(start|stop|restart)/i,
	/\b(vim?|nano|emacs|code|subl)\b/i,
	// Network fetch primitives are never tier-1 read-only (defense in depth;
	// adjudication ⑤) — data exfiltration and |sh execution vectors.
	/\bcurl\b/i,
	/\bwget\b/i,
];

// Read-only commands allowed without confirmation.
const SAFE_PATTERNS: RegExp[] = [
	/^\s*cat\b/,
	/^\s*head\b/,
	/^\s*tail\b/,
	/^\s*less\b/,
	/^\s*more\b/,
	/^\s*grep\b/,
	/^\s*find\b/,
	/^\s*ls\b/,
	/^\s*pwd\b/,
	/^\s*echo\b/,
	/^\s*printf\b/,
	/^\s*wc\b/,
	/^\s*sort\b/,
	/^\s*uniq\b/,
	/^\s*diff\b/,
	/^\s*file\b/,
	/^\s*stat\b/,
	/^\s*du\b/,
	/^\s*df\b/,
	/^\s*tree\b/,
	/^\s*which\b/,
	/^\s*whereis\b/,
	/^\s*type\b/,
	// No bare `env` here: `env VAR=x <cmd>` is an execution prefix, and the
	// SAFE patterns only anchor the start of the command (adjudication ⑤).
	/^\s*printenv\b/,
	/^\s*uname\b/,
	/^\s*whoami\b/,
	/^\s*id\b/,
	/^\s*date\b/,
	/^\s*cal\b/,
	/^\s*uptime\b/,
	/^\s*ps\b/,
	/^\s*top\b/,
	/^\s*htop\b/,
	/^\s*free\b/,
	/^\s*git\s+(status|log|diff|show|branch|remote|config\s+--get)/i,
	/^\s*git\s+ls-/i,
	/^\s*npm\s+(list|ls|view|info|search|outdated|audit)/i,
	/^\s*yarn\s+(list|info|why|audit)/i,
	/^\s*node\s+--version/i,
	/^\s*node\s+-v\b/i,
	/^\s*python\s+--version/i,
	/^\s*jq\b/,
	// `sed -n` is read-only except the `w` command, which writes a file
	// (`1w /path` or the `s///w path` suffix — the w hugs digits/delimiters,
	// so \b never fires there).
	/^\s*sed\s+-n(?![^\n]*(?:["',;/0-9}]|\s)w\s*["']?\s*[/~])/i,
	// No `awk` here: it is an interpreter with system()/redirect execution
	// vectors that the SAFE match cannot inspect (adjudication ⑤).
	/^\s*rg\b/,
	/^\s*fd\b/,
	/^\s*bat\b/,
	/^\s*eza\b/,
];

// Build/test commands allowed in auto-mode classifier fallback (after blacklist).
// Also gates tier-2 run-scripts (adjudication ③): offline conservative face
// must never be looser than the online auto-approve face.
const AUTO_FALLBACK_SCRIPT_NAMES =
	"test|build|lint|check|typecheck|verify|coverage|unit|ci|dev|start|preview|serve|watch"
const AUTO_FALLBACK_SCRIPT_TAIL = "(?:\\s|$)"
const AUTO_FALLBACK_BASH_PATTERNS: RegExp[] = [
	new RegExp(`^\\s*npm\\s+test${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(
		`^\\s*npm\\s+run\\s+(${AUTO_FALLBACK_SCRIPT_NAMES})${AUTO_FALLBACK_SCRIPT_TAIL}`,
		"i",
	),
	new RegExp(
		`^\\s*(pnpm|yarn|bun)\\s+run\\s+(${AUTO_FALLBACK_SCRIPT_NAMES})${AUTO_FALLBACK_SCRIPT_TAIL}`,
		"i",
	),
	new RegExp(`^\\s*(pnpm|yarn|bun)\\s+test${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(`^\\s*go\\s+test${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(`^\\s*cargo\\s+test${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	/^\s*make(\s+(test|check|build))?\s*$/i,
	/^\s*cmake\s+--build\b/i,
	new RegExp(`^\\s*pytest${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(`^\\s*vitest${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(`^\\s*jest${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
];

// Flags that turn routine test/build commands into arbitrary execution vectors.
const AUTO_FALLBACK_UNSAFE_ARG_PATTERNS: RegExp[] = [
	/(?:^|\s)-exec(?:=|\s|$)/i,
	/(?:^|\s)-toolexec(?:=|\s)/i,
	/(?:^|\s)--script-shell(?:=|\s)/i,
	/(?:^|\s)--node-options(?:=|\s)/i,
	/(?:^|\s)--config(?:=|\s)/i,
	/(?:^|\s)-c(?:=|\s+)\S/i,
	/(?:^|\s)--runner(?:=|\s)/i,
	/(?:^|\s)--preload(?:=|\s)/i,
	/(?:^|\s)--require(?:=|\s)/i,
	/(?:^|\s)--import(?:=|\s)/i,
	/(?:^|\s)--setupFiles(?:=|\s)/i,
	/(?:^|\s)--globalSetup(?:=|\s)/i,
	/(?:^|\s)--globalTeardown(?:=|\s)/i,
	/(?:^|\s)--target(?:=|\s+)(?:install|package|deploy)\b/i,
	/\s--(?:\s|$)/,
	/\bcmake\s+--build\b\s+(?:\/|~|\.\.)/i,
];

// Paths outside cwd in otherwise-routine test/build commands.
const AUTO_FALLBACK_OUTSIDE_PATH_PATTERNS: RegExp[] = [
	/(?:^|\s)-o(?:=|\s+)(?:(?:\/|~|\.\.)|["'](?:\/|~|\.\.))/i,
	/(?:^|\s)--manifest-path(?:=|\s+)(?:(?:\/|~|\.\.)|["'](?:\/|~|\.\.))/i,
	/(?:^|\s)--target(?:=|\s+)(?:(?:\/|~|\.\.)|["'](?:\/|~|\.\.))/i,
	/(?:^|\s)--chdir(?:=|\s+)(?:(?:\/|~|\.\.)|["'](?:\/|~|\.\.))/i,
	/(?:^|\s)--project-directory(?:=|\s+)(?:(?:\/|~|\.\.)|["'](?:\/|~|\.\.))/i,
	/(?:^|\s)[\w-]+=(?:\/|~|\.\.)/,
	/(?:^|\s|=)(?:\/[^\s]*|~\/[^\s]*|\.\.(?:\/[^\s]*)?)/,
	/(?:^|\s)["'](?:\/|~|\.\.)[^"']*["']/,
	/(?:^|\s)[\w-]+=["'](?:\/|~|\.\.)[^"']*["']/,
];

const NESTED_SHELL_PATTERNS: RegExp[] = [/`/, /\$\(/, /\$\{/, /<\(/, />\(/];

/**
 * Strip fd-to-fd redirects like `2>&1`, `>&2`, `1<&0`.
 * These do not write files and must not trip the `>` destructive check.
 * Agents commonly append `2>&1` when exploring in plan mode.
 */
export function stripFdToFdRedirects(command: string): string {
	return command.replace(/(?:\d*)>&\d+/g, " ").replace(/(?:\d*)<&\d+/g, " ")
}

function isCharEscaped(command: string, index: number): boolean {
	let backslashes = 0
	for (let j = index - 1; j >= 0 && command[j] === "\\"; j--) {
		backslashes++
	}
	return backslashes % 2 === 1
}

/** Split compound shell commands into segments (best-effort; not a full shell parser). */
export function splitShellSegments(command: string): string[] {
	const segments: string[] = []
	let current = ""
	let quote: "'" | '"' | null = null

	for (let i = 0; i < command.length; i++) {
		const ch = command[i]!
		if (quote) {
			current += ch
			if (ch === quote && (quote === "'" || !isCharEscaped(command, i))) {
				quote = null
			}
			continue
		}
		if (ch === "'" || ch === '"') {
			if (!isCharEscaped(command, i)) quote = ch
			current += ch
			continue
		}
		if (ch === ";" && !isCharEscaped(command, i)) {
			if (current.trim()) segments.push(current.trim())
			current = ""
			continue
		}
		if (
			(command.startsWith("&&", i) || command.startsWith("||", i)) &&
			!isCharEscaped(command, i)
		) {
			if (current.trim()) segments.push(current.trim())
			current = ""
			i += 1
			continue
		}
		if (ch === "|" && command[i + 1] !== "|" && !isCharEscaped(command, i)) {
			if (current.trim()) segments.push(current.trim())
			current = ""
			continue
		}
		if (ch === "&" && command[i + 1] !== "&" && !isCharEscaped(command, i)) {
			if (command[i - 1] === ">" || command[i + 1] === ">") {
				current += ch
				continue
			}
			if (current.trim()) segments.push(current.trim())
			current = ""
			continue
		}
		if (ch === "\n" && !isCharEscaped(command, i)) {
			if (current.trim()) segments.push(current.trim())
			current = ""
			continue
		}
		current += ch
	}

	if (current.trim()) segments.push(current.trim())
	return segments
}

function hasNestedShellExecution(command: string): boolean {
	let quote: "'" | '"' | null = null
	let scanText = ""

	for (let i = 0; i < command.length; i++) {
		const ch = command[i]!
		if (quote === "'") {
			if (ch === "'" && !isCharEscaped(command, i)) quote = null
			continue
		}
		if (quote === '"') {
			scanText += ch
			if (ch === '"' && !isCharEscaped(command, i)) quote = null
			continue
		}
		if (ch === "'" || ch === '"') {
			if (!isCharEscaped(command, i)) {
				quote = ch
				if (ch === '"') scanText += ch
				continue
			}
		}
		scanText += ch
	}

	return NESTED_SHELL_PATTERNS.some((p) => p.test(scanText))
}

function isSafeSingleCommand(command: string): boolean {
	if (hasNestedShellExecution(command)) return false
	const normalized = stripFdToFdRedirects(command)
	const isDestructive = DESTRUCTIVE_PATTERNS.some((p) => p.test(normalized))
	const isSafe = SAFE_PATTERNS.some((p) => p.test(normalized))
	return !isDestructive && isSafe
}

function hasUnsafeFallbackArgs(segment: string): boolean {
	return AUTO_FALLBACK_UNSAFE_ARG_PATTERNS.some((p) => p.test(segment))
}

function hasOutsideCwdFallbackTargets(segment: string): boolean {
	return AUTO_FALLBACK_OUTSIDE_PATH_PATTERNS.some((p) => p.test(segment))
}

function matchesAutoFallbackPattern(segment: string): boolean {
	return (
		AUTO_FALLBACK_BASH_PATTERNS.some((p) => p.test(segment)) &&
		!hasUnsafeFallbackArgs(segment) &&
		!hasOutsideCwdFallbackTargets(segment)
	)
}

/** A command is "safe" iff every shell segment matches the allowlist AND none are destructive. */
export function isSafeCommand(command: string): boolean {
	return segmentsSatisfy(splitShellSegments(command), isSafeSingleCommand)
}

/** Auto-mode fallback after blacklist: safe read-only OR routine build/test commands. */
export function isAutoFallbackBash(command: string): boolean {
	const segments = splitShellSegments(command)
	if (segments.length === 0) return false
	return segments.every(
		(seg) =>
			!hasNestedShellExecution(seg) &&
			(isSafeSingleCommand(seg) || matchesAutoFallbackPattern(seg)),
	)
}

function segmentsSatisfy(
	segments: string[],
	predicate: (segment: string) => boolean,
): boolean {
	return segments.length > 0 && segments.every(predicate)
}

/**
 * Both tier verdicts from ONE splitShellSegments pass — the auto-mode tier
 * ladder calls isSafeCommand and isAutoApprovableBash back to back on the
 * same command, and each re-tokenized it. Pure; equivalent to
 * calling the two functions separately.
 */
export function classifyBashTiers(command: string): {
	safe: boolean
	autoApprovable: boolean
} {
	const segments = splitShellSegments(command)
	return {
		safe: segmentsSatisfy(segments, isSafeSingleCommand),
		autoApprovable:
			segments.length > 0 &&
			segments.every(
				(seg) =>
					!hasNestedShellExecution(seg) &&
					(isSafeSingleCommand(seg) || isAutoApprovableSingleCommand(seg)),
			),
	}
}

// ---------------------------------------------------------------------------
// Auto-mode auto-approvable commands (broader than isAutoFallbackBash).
// Common dev workflow commands with controlled side-effects that don't need
// classifier review in auto mode.
//
// Adjudication 2026-09-12:
// - run-scripts are restricted to the AUTO_FALLBACK_SCRIPT_NAMES whitelist;
// - git hook vectors (commit/merge/rebase/cherry-pick/revert) and worktree-
//   loss forms (restore/checkout) are tier-3, not tier-2;
// - docker run/exec are tier-3 (host-mount execution vectors);
// - tier-2 reuses the fallback guardrails (unsafe args, outside-cwd paths).
// ---------------------------------------------------------------------------

// Tier-2 auto approvals: routine builds/tests and cwd-local git ops.
// Network fetch, package install, arbitrary interpreters, git fetch/pull,
// git hook vectors, worktree-loss git forms, and docker run/exec require
// tier-3 classifier review.
const AUTO_APPROVABLE_PATTERNS: RegExp[] = [
	// Build / run scripts (whitelist-gated; deploy-like names fall to tier-3)
	new RegExp(`^\\s*npm\\s+run\\s+(${AUTO_FALLBACK_SCRIPT_NAMES})${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	new RegExp(`^\\s*(pnpm|yarn|bun)\\s+run\\s+(${AUTO_FALLBACK_SCRIPT_NAMES})${AUTO_FALLBACK_SCRIPT_TAIL}`, "i"),
	/^\s*(make|cmake)\b/i,
	/^\s*cargo\s+(build|check|clippy|fmt|test)\b/i,
	/^\s*go\s+(build|vet|fmt|mod|test)\b/i,
	// Git local write operations with no hook vector and no worktree-loss form
	// (no commit/merge/rebase/cherry-pick/revert/restore/checkout).
	/^\s*git\s+(add|stash|branch|switch|tag|init|clone|reset)\b/i,
	// File operations within workflow (outside-cwd paths blocked by guardrails)
	/^\s*mkdir\b/i,
	/^\s*touch\b/i,
	/^\s*cp\b/i,
	/^\s*mv\b/i,
	// Code formatting / linting / type-checking (pinned tools only)
	/^\s*npx\s+(prettier|eslint|tsc|esbuild|vite|next|nuxt|astro)\b/i,
	/^\s*(prettier|eslint|biome)\b/i,
	/^\s*tsc\b/i,
	// Test runners
	/^\s*npm\s+test\b/i,
	/^\s*(pnpm|yarn|bun)\s+test\b/i,
	/^\s*(vitest|jest|mocha|ava|tap)\b/i,
	/^\s*pytest\b/i,
	/^\s*go\s+test\b/i,
	/^\s*cargo\s+test\b/i,
	// Docker local dev without execution forms (run/exec are tier-3)
	/^\s*docker\s+(build|compose|logs|ps|images)\b/i,
];

const AUTO_APPROVABLE_EXCLUDE: RegExp[] = [
	/\brm\b/,
	/\bsudo\b/,
	/\bsu\b/,
	/--force\b/,
	/\s-f\b/,
	/\bgit\s+push\b/,
	/\bgit\s+reset\s+--hard\b/,
	/\bgit\s+clean\b/,
	/\bnpm\s+publish\b/,
	/\b--exec\b/,
	/\b-exec\b/,
	/\bexec\b/,
	/\bkill\b/,
	/\bpkill\b/,
	/\bkillall\b/,
	/\breboot\b/,
	/\bshutdown\b/,
	/\bdd\b/,
	/\bshred\b/,
	/\bchmod\b/,
	/\bchown\b/,
	/>/,
];

function isAutoApprovableSingleCommand(command: string): boolean {
	if (hasNestedShellExecution(command)) return false
	const normalized = stripFdToFdRedirects(command)
	if (AUTO_APPROVABLE_EXCLUDE.some((p) => p.test(normalized))) return false
	// Adjudication ③ (2026-09-12): tier-2 must not be looser than the
	// classifier-offline fallback — reuse its unsafe-arg and outside-cwd guards.
	if (hasUnsafeFallbackArgs(normalized)) return false
	if (hasOutsideCwdFallbackTargets(normalized)) return false
	return AUTO_APPROVABLE_PATTERNS.some((p) => p.test(normalized))
}

/**
 * Broader auto-mode check: approves common dev workflow commands (package
 * installs, builds, git local ops, file ops) without classifier review.
 * Every shell segment must be approvable and no segment may be dangerous.
 */
export function isAutoApprovableBash(command: string): boolean {
	return classifyBashTiers(command).autoApprovable
}

export interface TodoItem {
	step: number;
	text: string;
	completed: boolean;
}

export function cleanStepText(text: string): string {
	let cleaned = text
		.replace(/\*{1,2}([^*]+)\*{1,2}/g, "$1") // strip bold/italic
		.replace(/`([^`]+)`/g, "$1") // strip inline code
		.replace(
			/^(Use|Run|Execute|Create|Write|Read|Check|Verify|Update|Modify|Add|Remove|Delete|Install)\s+(the\s+)?/i,
			"",
		)
		.replace(/\s+/g, " ")
		.trim();

	if (cleaned.length > 0) {
		cleaned = cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
	}
	if (cleaned.length > 50) {
		cleaned = `${cleaned.slice(0, 47)}...`;
	}
	return cleaned;
}

/**
 * Extract a numbered list under a `Plan:` header into TodoItems.
 * Shape follows pi's bundled `examples/extensions/plan-mode/utils.ts` (MIT).
 */
export function extractTodoItems(message: string): TodoItem[] {
	const items: TodoItem[] = [];
	const headerMatch = message.match(/\*{0,2}Plan:\*{0,2}\s*\n/i);
	if (!headerMatch) return items;

	const planSection = message.slice(message.indexOf(headerMatch[0]) + headerMatch[0].length);
	const numberedPattern = /^\s*(\d+)[.)]\s+\*{0,2}([^*\n]+)/gm;

	for (const match of planSection.matchAll(numberedPattern)) {
		const text = match[2]
			.trim()
			.replace(/\*{1,2}$/, "")
			.trim();
		if (text.length > 5 && !text.startsWith("`") && !text.startsWith("/") && !text.startsWith("-")) {
			const cleaned = cleanStepText(text);
			if (cleaned.length > 3) {
				items.push({ step: items.length + 1, text: cleaned, completed: false });
			}
		}
	}
	return items;
}

export function extractDoneSteps(message: string): number[] {
	const steps: number[] = [];
	for (const match of message.matchAll(/\[DONE:(\d+)\]/gi)) {
		const step = Number(match[1]);
		if (Number.isFinite(step)) steps.push(step);
	}
	return steps;
}

/** Mark any `[DONE:n]` steps found in `text` complete. Returns how many tags were seen. */
export function markCompletedSteps(text: string, items: TodoItem[]): number {
	const doneSteps = extractDoneSteps(text);
	for (const step of doneSteps) {
		const item = items.find((t) => t.step === step);
		if (item) item.completed = true;
	}
	return doneSteps.length;
}

const COMPLETION_SIGNALS: RegExp[] = [
	/\b(plan|task|work|job|everything|all)\s+(is\s+|are\s+|has\s+been\s+)?(complete|completed|done|finished)\b/i,
	/\ball\s+done\b/i,
	/\bno\s+(more|further)\s+(steps|tasks|actions|work)\b/i,
	/\b(i'?m|i\s+am)\s+(done|finished)\b/i,
	/\bfinished\b/i,
];

/** Heuristic: does the assistant text claim the work is finished? */
export function isCompletionSignal(text: string): boolean {
	return COMPLETION_SIGNALS.some((p) => p.test(text));
}

/** Compact token count, e.g. 1234 -> "1.2k", 12000 -> "12k". */
export function formatCount(n: number): string {
	if (!Number.isFinite(n) || n <= 0) return "0";
	if (n < 1000) return String(Math.round(n));
	const k = n / 1000;
	return `${k >= 10 ? Math.round(k) : k.toFixed(1)}k`;
}

/** Expand leading `~` for path comparisons (does not resolve symlinks). */
function expandUserPath(p: string): string {
	const home = homedir()
	if (p === "~") return home
	if (p.startsWith("~/")) return path.join(home, p.slice(2))
	return p
}

/**
 * Returns true iff `targetPath` resolves to a location outside `cwd`.
 *
 * Empty string is treated as "inside cwd" (no path = nothing to be outside of).
 * Lexical resolution is used first; symlink components under cwd are checked so
 * a path like `link/file` cannot escape when `link` points outside cwd.
 */
export function isOutsideCwd(targetPath: string, cwd: string): boolean {
	if (!targetPath) return false
	const p = expandUserPath(targetPath)
	const resolved = path.isAbsolute(p)
		? path.resolve(p)
		: path.resolve(cwd, p)
	const cwdAbs = path.resolve(cwd)

	if (resolved === cwdAbs) return false
	if (!resolved.startsWith(cwdAbs + path.sep)) return true

	return pathEscapesCwdViaSymlink(resolved, cwdAbs)
}

function pathEscapesCwdViaSymlink(target: string, cwdAbs: string): boolean {
	try {
		const realCwd = existsSync(cwdAbs) ? realpathSync(cwdAbs) : cwdAbs
		let probe = target
		while (probe === cwdAbs || probe.startsWith(cwdAbs + path.sep)) {
			if (existsSync(probe)) {
				const real = realpathSync(probe)
				if (real === realCwd) return false
				if (!real.startsWith(realCwd + path.sep) && real !== realCwd) {
					return true
				}
			}
			const parent = path.dirname(probe)
			if (parent === probe) break
			probe = parent
		}
		return false
	} catch {
		return false
	}
}

/**
 * Heuristic: does a bash command reference paths outside `cwd`?
 *
 * Flags:
 *   - absolute paths anywhere in the command
 *   - `..` traversal (cd .., ls ../foo)
 *   - `~` or `$HOME` / `$TMPDIR` expansions
 *
 * Conservative: false negatives are acceptable (we still prompt for destructive
 * commands separately), false positives are NOT — we don't want to over-prompt.
 */
export function commandTargetsOutsideCwd(command: string, cwd: string): boolean {
	if (!command || !command.trim()) return false;

	// Absolute path anywhere in the command.
	// `/` must be at the start of a token (after whitespace, ;&|() or string start),
	// and the next char must be a real path char (not `.` to avoid `./` and `../` false positives).
	if (/(^|[\s;&|('])(\/[A-Za-z0-9_\-])/.test(command)) return true;

	// Tilde expansion: `~` at start of token (not in the middle of a path)
	if (/(^|[\s;&|()])(~|\$HOME|\$TMPDIR|\$TMP|\$PWD\b)/.test(command)) return true;

	// `..` as a path component (not as part of `...` or `./..`)
	if (/(^|[\s;&|(])\.\.($|[\s/&|)])/.test(command)) return true;

	return false;
}

const SENSITIVE_DIR_NAMES = new Set([".git"])
const SENSITIVE_FILE_PATTERN =
	/^\.env(?:\.|$)|^id_rsa$|^id_ed25519$|^credentials$/

function pathHasSensitiveSegment(resolvedPath: string): boolean {
	const parts = resolvedPath.split(path.sep)
	for (const part of parts) {
		if (SENSITIVE_DIR_NAMES.has(part)) return true
		if (SENSITIVE_FILE_PATTERN.test(part)) return true
	}
	return false
}

/** True when a tool path targets .git, .env*, SSH keys, or similar sensitive locations. */
export function isSensitivePath(targetPath: string, cwd: string): boolean {
	if (!targetPath) return false
	const p = expandUserPath(targetPath)
	const resolved = path.isAbsolute(p)
		? path.resolve(p)
		: path.resolve(cwd, p)
	return pathHasSensitiveSegment(resolved)
}

/** Heuristic: does a bash command reference sensitive paths (.git, .env, ~/.ssh, etc.)? */
export function commandReferencesSensitivePath(command: string): boolean {
	if (!command.trim()) return false
	if (/(?:^|[\s;&|('"[(])\.git(?:\/|\s|$|['")\]])/.test(command)) return true
	if (/(?:^|[\s;&|('"[(])\.env(?:\.|\s|$|['")\]])/.test(command)) return true
	if (/\bid_rsa\b/.test(command)) return true
	if (/\bid_ed25519\b/.test(command)) return true
	if (/(?:^|[\s;&|()])~\/\.ssh\b/.test(command)) return true
	if (/(?:^|[\s;&|()])\$HOME\/\.ssh\b/.test(command)) return true
	return false
}

/**
 * Walk up from `cwd` looking for a project root marker (.git or package.json).
 * Returns the project root path, or `null` if none found within 20 levels.
 */
export function findProjectRoot(cwd: string): string | null {
	let dir = path.resolve(cwd);
	for (let i = 0; i < 20; i++) {
		// Stop at filesystem root
		if (dir === path.dirname(dir)) return null;
		// Detect: .git, package.json
		if (
			existsSync(path.join(dir, ".git")) ||
			existsSync(path.join(dir, "package.json"))
		) {
			return dir;
		}
		dir = path.dirname(dir);
	}
	return null;
}

/**
 * Project identity.
 *
 * Every piece of project state — permission rules, the grants journal, the plan
 * file, outside-write snapshots — lives under `<cwd>/.pi/projects/<id>/`, so the
 * id is not a label, it is the *address* of a project's authority. An id derived
 * from the path therefore moves with nothing: rename the directory the checkout
 * sits in and every rule for it — allows **and denies** — disappears with no
 * error, and the next session happily asks for what the last one forbade.
 *
 * So the id is resolved from the first source that has an opinion, cheapest and
 * most portable first:
 *
 *   1. `<cwd>/.pi/project.json` → `{ "projectId": "…" }`. Lives inside the
 *      checkout, so it is the only source that survives a move;
 *   2. `<cwd>/.pi/permission-modes-<id>.md`, if such a file exists — read here, never
 *      written here. Checked 2026-10-21 rather than assumed: nothing in pi's `dist/`
 *      mentions this name and nothing in this package creates it, so today this tier
 *      resolves nothing. It stays because reading an extra candidate is free and a
 *      marker by that name would be honoured if some tool ever wrote one — but it is
 *      not a contract anyone offers, and no behaviour may depend on it;
 *   3. `hashPath(cwd)` — correct while the tree stays where it was.
 *
 * Resolution reads the filesystem and says nothing: no logging, no `process.env`,
 * nothing that would make a verdict depend on the session it was asked in.
 */

/** The id becomes one path segment, hence: lowercase alnum, then up to 31 of `-`/`_`. */
const PROJECT_ID_SHAPE = /^[a-z0-9][a-z0-9_-]{0,31}$/
const PROJECT_ID_FILE = path.join(".pi", "project.json")
/** pi generates this name from a hash, so it is hex-only. */
const PI_MARKER_NAME = /^permission-modes-([a-f0-9]+)\.md$/

type CarriedId =
	/** No file, or a file with no content and no other keys — free to be stamped. */
	| { state: "absent" }
	/** Present but not JSON we can trust: never replaced silently. */
	| { state: "unparseable" }
	/** Parseable JSON carrying no usable `projectId` (blank, wrong type, bad charset). */
	| { state: "unidentified"; doc: Record<string, unknown> }
	| { state: "id"; id: string; doc: Record<string, unknown> }

function readCarriedId(cwd: string): CarriedId {
	const file = path.join(cwd, PROJECT_ID_FILE)
	let raw: string
	try {
		if (!existsSync(file)) return { state: "absent" }
		raw = readFileSync(file, "utf-8")
	} catch {
		return { state: "unparseable" }
	}
	if (!raw.trim()) return { state: "absent" }
	let doc: unknown
	try {
		doc = JSON.parse(raw)
	} catch {
		return { state: "unparseable" }
	}
	if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
		return { state: "unidentified", doc: {} }
	}
	const kept = doc as Record<string, unknown>
	const field = kept.projectId
	if (typeof field === "string" && PROJECT_ID_SHAPE.test(field)) {
		return { state: "id", id: field, doc: kept }
	}
	return { state: "unidentified", doc: kept }
}

/** pi's marker, if this tree has one — read off the filename, contents are pi's. */
function readPiMarkerId(cwd: string): string | null {
	const piDir = path.join(cwd, ".pi")
	try {
		if (!existsSync(piDir)) return null
		for (const name of readdirSync(piDir)) {
			const hit = PI_MARKER_NAME.exec(name)
			if (hit) return hit[1]
		}
	} catch {
		/* unreadable .pi/ is "no marker", not an error — resolution continues */
	}
	return null
}

// Positive-result cache only: an id that came from a marker is stable for this
// cwd. The hash fallback stays uncached, so a marker created mid-session takes
// over on the next call (and `writeProjectIdMarker` drops the entry it invalidates).
const projectIdCache = new Map<string, string>()

/**
 * Stamp the checkout with an id of its own (`.pi/project.json`) so the id — and
 * therefore the rules + journal directory — travels with it instead of being
 * re-derived from wherever it happens to sit.
 *
 * Every refusal returns `false` and throws nothing:
 *  - `id` is not a single safe path segment;
 *  - the carried file already names a **different** id: swapping ids relocates
 *    the state directory, which is the exact failure this module exists to
 *    prevent, so it takes `{ force: true }` to mean "yes, on purpose";
 *  - the carried file is not parseable — we do not write over a file we could
 *    not read, because we cannot know what identity it held;
 *  - no carried id, but pi's `.md` marker names a different one — same
 *    consequence, so same rule.
 *
 * Writing the id pi already uses is always allowed (the state directory does not
 * move, it just stops depending on the path). Unknown keys in the file are kept:
 * it is hand-edited. A successful write drops the cached id for `cwd`.
 */
export function writeProjectIdMarker(
	cwd: string,
	id: string,
	opts: { force?: boolean } = {},
): boolean {
	if (!PROJECT_ID_SHAPE.test(id)) return false
	const carried = readCarriedId(cwd)
	if (carried.state === "unparseable") return false
	// Whichever source is authoritative today is the id whose state directory a
	// swap would strand.
	const currentId = carried.state === "id" ? carried.id : readPiMarkerId(cwd)
	if (currentId !== null && currentId !== id && !opts.force) return false
	const file = path.join(cwd, PROJECT_ID_FILE)
	try {
		const doc = carried.state === "absent" ? {} : carried.doc
		mkdirSync(path.dirname(file), { recursive: true })
		const tmp = `${file}.tmp-${process.pid}`
		writeFileSync(
			tmp,
			JSON.stringify({ ...doc, projectId: id }, null, 2) + "\n",
			{ mode: 0o644 },
		)
		renameSync(tmp, file)
		projectIdCache.delete(cwd)
		return true
	} catch (err) {
		console.warn(`[adaptive-acl] Failed to write ${file}:`, err)
		return false
	}
}

/** The carried marker's id, or null when there is none that can be used. */
export function readProjectIdMarker(cwd: string): string | null {
	const carried = readCarriedId(cwd)
	return carried.state === "id" ? carried.id : null
}

export function getProjectId(cwd: string): string {
	const cached = projectIdCache.get(cwd)
	if (cached) return cached
	const carried = readCarriedId(cwd)
	if (carried.state === "id") {
		projectIdCache.set(cwd, carried.id)
		return carried.id
	}
	const piMarker = readPiMarkerId(cwd)
	if (piMarker) {
		projectIdCache.set(cwd, piMarker)
		return piMarker
	}
	return hashPath(cwd)
}

/** First 8 hex chars of sha256(input). Deterministic. */
export function hashPath(p: string): string {
	return createHash("sha256").update(p).digest("hex").slice(0, 8)
}

/**
 * Where project state lives for `cwd` — `<cwd>/.pi/projects/<projectId>` unless a test installed a temp root.
 *
 * Production never sets the override. The seam exists because a suite that simulates a session with
 * `cwd = process.cwd()` writes into the REAL checkout's state, and those rows are not invisible: `/grants outside-writes`
 * reads this very directory, so a test fixture named `/tmp/outside.txt` shows up as if the user had written it. Measured
 * on 2026-10-16: 55 rows left behind in the port checkout by unit tests — 43 from `mkdtemp` dirs the suites had already
 * deleted, 12 from hardcoded fixtures like `/tmp/outside.txt` and `/opt/outside.txt`.
 */
let projectStateRootOverride: string | null = null

/**
 * Test seam, same shape as `config.ts:setConfigPath`. Install a temp root in a `beforeEach`, clear it in `afterEach`.
 * It redirects the outside-writes journal only — the plan file path is unchanged, because that is the leak being plugged
 * and widening it would change behaviour tests elsewhere legitimately assert.
 */
export function setProjectStateRoot(dir: string | null): void {
	projectStateRootOverride = dir
}

/** The state dir for `cwd`, honouring the test override. Does not create anything. */
export function getProjectStateDir(cwd: string): string {
	const id = getProjectId(cwd)
	return projectStateRootOverride
		? path.join(projectStateRootOverride, id)
		: path.join(cwd, ".pi", "projects", id)
}

/**
 * Return the absolute path to the project's outside-writes snapshot dir,
 * creating it (and all parents) if it doesn't exist.
 *
 * Layout: `<cwd>/.pi/projects/<projectId>/tmp/outside-writes/`
 *
 * Created lazily on first call so empty projects don't litter their tree.
 * Safe to call repeatedly — idempotent.
 */
export function getProjectTmpDir(cwd: string): string {
	const dir = path.join(getProjectStateDir(cwd), "tmp", "outside-writes")
	mkdirSync(dir, { recursive: true })
	return dir
}

/** What one project id owns under `.pi/projects/<id>/`. */
export type ProjectStateDir = {
	id: string
	path: string
	rules: { permissions: boolean; local: boolean }
	grants: boolean
	/** True when the directory holds a deny rule — the case that must never go quiet. */
	hasDenyRules: boolean
}

/**
 * A deny list that can be read is a deny list; anything else (absent file, blank
 * file, malformed JSON, `deny: "Bash(rm *)"` written as a string instead of an
 * array) reads as "no deny rule found here" — which is *not* the same claim as
 * "this directory is safe". The listing type has no `unknown`, so a caller that
 * wants to say "unreadable" has to say so itself; what this guarantees is only
 * that a read-only scan never throws.
 */
function holdsDenyRules(filePath: string): boolean {
	let doc: unknown
	try {
		if (!existsSync(filePath)) return false
		const raw = readFileSync(filePath, "utf-8")
		if (!raw.trim()) return false
		doc = JSON.parse(raw)
	} catch {
		return false
	}
	if (!doc || typeof doc !== "object" || Array.isArray(doc)) return false
	const root = doc as Record<string, unknown>
	const nested = root.permissions
	const lists =
		nested && typeof nested === "object" && !Array.isArray(nested)
			? (nested as Record<string, unknown>)
			: root
	const deny = lists.deny
	return Array.isArray(deny) && deny.some((r) => typeof r === "string" && !!r.trim())
}

/**
 * Read-only inventory of `<cwd>/.pi/projects/` for every id **except**
 * `currentId` — the state a moved or renamed checkout left behind. Nothing here
 * migrates, adopts, merges or deletes: it reports, and the caller decides how
 * loud to be. Every subdirectory is listed, including ones holding nothing but
 * a scratch `tmp/` and ones whose name this plugin would never have generated,
 * because an orphan we did not create is still evidence. Files directly under
 * `.pi/projects/` are not ids and are skipped. Sorted by id, so the output is
 * stable enough to compare in a test.
 */
export function listProjectStateDirs(cwd: string, currentId: string): ProjectStateDir[] {
	const root = path.join(cwd, ".pi", "projects")
	let dirs: string[]
	try {
		dirs = readdirSync(root, { withFileTypes: true })
			.filter((e) => e.isDirectory())
			.map((e) => e.name)
	} catch {
		return []
	}
	const found: ProjectStateDir[] = []
	for (const id of dirs) {
		if (id === currentId) continue
		const dir = path.join(root, id)
		const permissions = path.join(dir, "permissions.json")
		const local = path.join(dir, "permissions.local.json")
		found.push({
			id,
			path: dir,
			rules: { permissions: existsSync(permissions), local: existsSync(local) },
			grants: existsSync(path.join(dir, "grants.json")),
			hasDenyRules: holdsDenyRules(permissions) || holdsDenyRules(local),
		})
	}
	return found.sort((a, b) => a.id.localeCompare(b.id))
}

/**
 * Check if `targetPath` is inside the project root (if one can be detected
 * or is provided). Returns false if no project root is found — caller should
 * fall back to `isOutsideCwd` in that case.
 */
export function isInsideProject(
	targetPath: string,
	cwd: string,
	projectRoot?: string | null,
): boolean {
	const root = projectRoot ?? findProjectRoot(cwd);
	if (!root) return false;
	const resolved = path.isAbsolute(targetPath)
		? path.resolve(targetPath)
		: path.resolve(cwd, targetPath);
	const rootAbs = path.resolve(root);
	return resolved.startsWith(rootAbs + path.sep) || resolved === rootAbs;
}

export interface OutsideWriteSnapshot {
	timestamp: string
	originalPath: string
	toolName: "edit" | "write"
	backupContent: string | null
}

/**
 * Persist a snapshot of a write that auto mode performed outside cwd.
 * Filename: `<iso-timestamp-sanitized>__<path-hash>.json`
 *
 * Caps at MAX_TRACKED_WRITES (100) — when full, evicts the oldest by
 * timestamp before writing the new one. This prevents the tmp dir from
 * growing unboundedly in long-running sessions.
 *
 * Never throws — failures are logged via console.warn and swallowed.
 */
export function trackOutsideWrite(
	cwd: string,
	snapshot: OutsideWriteSnapshot,
): void {
	try {
		const dir = getProjectTmpDir(cwd)
		const files = readdirSync(dir).filter((f) => f.endsWith(".json"))
		if (files.length >= MAX_TRACKED_WRITES) {
			// Evict oldest by filename (which starts with ISO timestamp, sortable)
			const sorted = files.sort()
			const evictCount = files.length - MAX_TRACKED_WRITES + 1
			for (let i = 0; i < evictCount; i++) {
				try {
					unlinkSync(path.join(dir, sorted[i]!))
				} catch {
					/* ignore */
				}
			}
		}
		const safeTs = snapshot.timestamp.replace(/[:.]/g, "-")
		const filename = `${safeTs}__${hashPath(snapshot.originalPath)}.json`
		writeFileSync(
			path.join(dir, filename),
			JSON.stringify(snapshot, null, 2),
			{ mode: 0o600 },
		)
	} catch (err) {
		console.warn("[adaptive-acl] Failed to track outside write:", err)
	}
}

/**
 * Read all snapshots from the project's tmp dir, sorted by timestamp
 * ascending. Malformed JSON files are skipped (logged). Returns [] on
 * any error or when dir doesn't exist.
 */
export function listTrackedOutsideWrites(
	cwd: string,
): OutsideWriteSnapshot[] {
	try {
		const dir = getProjectTmpDir(cwd)
		const files = readdirSync(dir).filter((f) => f.endsWith(".json"))
		const snaps: OutsideWriteSnapshot[] = []
		for (const f of files) {
			try {
				const raw = readFileSync(path.join(dir, f), "utf-8")
				const parsed = JSON.parse(raw) as OutsideWriteSnapshot
				// Basic shape validation
				if (
					typeof parsed.timestamp === "string" &&
					typeof parsed.originalPath === "string" &&
					(parsed.toolName === "edit" || parsed.toolName === "write") &&
					(parsed.backupContent === null ||
						typeof parsed.backupContent === "string")
				) {
					snaps.push(parsed)
				}
			} catch (err) {
				console.warn(`[adaptive-acl] Skipping malformed snapshot ${f}:`, err)
			}
		}
		return snaps.sort((a, b) => a.timestamp.localeCompare(b.timestamp))
	} catch (err) {
		console.warn("[adaptive-acl] Failed to list tracked writes:", err)
		return []
	}
}

/**
 * Restore the original content (or delete the file if it didn't exist)
 * for a tracked outside write. Returns the action taken.
 *
 * - `backupContent !== null` and file differs → write backup, return `restored`
 * - `backupContent !== null` and file matches → return `noop`
 * - `backupContent === null` and file exists → unlink, return `deleted`
 * - `backupContent === null` and file missing → return `noop`
 *
 * Never throws — file-system errors are returned as `{restored: false, action: "noop"}`.
 */
export function restoreOutsideWrite(snapshot: OutsideWriteSnapshot): {
	restored: boolean
	action: "restored" | "deleted" | "noop"
} {
	try {
		const { originalPath, backupContent } = snapshot
		if (backupContent === null) {
			if (existsSync(originalPath)) {
				unlinkSync(originalPath)
				return { restored: true, action: "deleted" }
			}
			return { restored: true, action: "noop" }
		}
		// Non-null backup: compare current content
		if (existsSync(originalPath)) {
			const current = readFileSync(originalPath, "utf-8")
			if (current === backupContent) {
				return { restored: true, action: "noop" }
			}
		}
		// Write backup (creates parent dirs if needed)
		mkdirSync(path.dirname(originalPath), { recursive: true })
		writeFileSync(originalPath, backupContent, { mode: 0o644 })
		return { restored: true, action: "restored" }
	} catch (err) {
		console.warn("[adaptive-acl] Failed to restore outside write:", err)
		return { restored: false, action: "noop" }
	}
}

/**
 * Delete the snapshot file corresponding to `snapshot`. Safe to call
 * when the file doesn't exist (no-op).
 *
 * Filename is reconstructed the same way as `trackOutsideWrite`.
 */
export function popTrackedOutsideWrite(
	cwd: string,
	snapshot: OutsideWriteSnapshot,
): void {
	try {
		const dir = getProjectTmpDir(cwd)
		const safeTs = snapshot.timestamp.replace(/[:.]/g, "-")
		const filename = `${safeTs}__${hashPath(snapshot.originalPath)}.json`
		const filepath = path.join(dir, filename)
		if (existsSync(filepath)) unlinkSync(filepath)
	} catch (err) {
		console.warn("[adaptive-acl] Failed to pop tracked write:", err)
	}
}

/**
 * Remove skill XML blocks from the system prompt whose names are NOT in the
 * allowedSkills list.
 *
 * Skill blocks in the actual pi prompt follow this XML schema (see
 * `@earendil-works/pi-coding-agent/dist/core/skills.js:formatSkillsForPrompt`):
 *
 *   <available_skills>
 *     <skill>
 *       <name>SKILL_NAME</name>
 *       <description>...</description>
 *       <location>...absolute path to SKILL.md...</location>
 *     </skill>
 *     ...
 *   </available_skills>
 *
 * NOTE: This is NOT the Agent Skills spec's `<skill name="...">` attribute
 * format. The v1.1.4 implementation used that wrong schema and silently let
 * all skills through (regex matched zero of the real blocks). v1.1.5 fixed
 * the regex to match the child `<name>` element.
 *
 * The function is a no-op (returns the prompt unchanged) when:
 *   - allowedSkills is ["*"] (allow all — default behavior)
 *   - allowedSkills is empty (filter nothing — same as "*")
 *   - No skill blocks are found in the prompt text
 *
 * Skill names are constrained to [a-z0-9-] per the Agent Skills spec, so
 * no regex escaping is needed.
 *
 * @param prompt         Full system prompt text
 * @param allowedSkills  Array of skill names to keep, or ["*"] for all
 * @returns Modified prompt with disallowed skill blocks removed
 */
// ---- Mode prompt anchor injection (v2.0.0) ------------------------------

export const MODE_PROMPT_BEGIN = "<!-- adaptive-acl:context -->"
export const MODE_PROMPT_END = "<!-- /adaptive-acl:context -->"

const MODE_PROMPT_BLOCK_RE =
	/<!-- adaptive-acl:context -->[\s\S]*?<!-- \/adaptive-acl:context -->\n?/

export type PermissionMode = "ask" | "plan" | "auto" | "bypass"
export type PlanPhase = "exploring" | "refining" | "executing"

export function injectModePrompt(
	systemPrompt: string,
	modeBlock: string,
): string {
	const stripped = systemPrompt.replace(MODE_PROMPT_BLOCK_RE, "")
	if (!modeBlock.trim()) return stripped
	return `${stripped}\n${MODE_PROMPT_BEGIN}\n${modeBlock.trim()}\n${MODE_PROMPT_END}`
}

export interface ResolveModePromptOpts {
	mode: PermissionMode
	planPhase?: PlanPhase
	planFilePath?: string
	needsAskReminder?: boolean
	needsBypassSecurityReminder?: boolean
}

export function resolveModePrompt(opts: ResolveModePromptOpts): string {
	const {
		mode,
		planPhase = "exploring",
		planFilePath,
		needsAskReminder,
		needsBypassSecurityReminder,
	} = opts

	if (mode === "ask" && needsAskReminder) {
		return "[Ask] Edits, outside-cwd access, and mutating commands need approval. Inside-cwd reads are automatic."
	}

	if (mode === "plan" && planFilePath) {
		let block = `[Plan Mode] You are in plan mode. In this mode:
- Only use read-only tools (read, grep, find, ls, and read-only bash like git status/log/diff).
- Explore the codebase, understand architecture, and design an implementation approach.
- Do NOT edit, write, or run mutating commands. Do NOT implement anything yet.
- Maintain your plan as a numbered list in: ${planFilePath}
- Use \`read\` to review and \`edit\` to update ONLY the plan file.
- When your plan is complete and concrete, tell the user it is ready for review.
- The user will approve or refine the plan before execution begins.`;
		if (planPhase === "executing") {
			block = `[Plan/executing] Execute steps from plan.md. Mark progress with [DONE:n] tags.`;
		}
		return block;
	}

	if (mode === "bypass" && needsBypassSecurityReminder) {
		return "[Bypass] All tool calls are auto-approved with no permission checks. You are responsible for security: avoid exfiltrating secrets, running untrusted downloads, or destructive commands outside the user's intent. Prefer isolated environments."
	}

	// auto and default: zero routine injection
	return ""
}

/** Stable hash of plan content for popup throttling. */
export function hashPlan(content: string): string {
	return createHash("sha256").update(content).digest("hex").slice(0, 16)
}

// ---- Plan file helpers (v2.0.0) -----------------------------------------

const PLAN_FILE_TEMPLATE = `# Plan

<!-- adaptive-acl:plan -->
Plan:
1. (pending)
<!-- /adaptive-acl:plan -->
`

export function getPlanFilePath(cwd: string): string {
	const id = getProjectId(cwd)
	return path.join(cwd, ".pi", "projects", id, "plan.md")
}

export function readPlanFile(cwd: string): string | null {
	try {
		const filePath = getPlanFilePath(cwd)
		if (!existsSync(filePath)) return null
		return readFileSync(filePath, "utf-8")
	} catch {
		return null
	}
}

export function writePlanFile(cwd: string, content: string): void {
	assertWritablePlanPath(cwd)
	const filePath = getPlanFilePath(cwd)
	mkdirSync(path.dirname(filePath), { recursive: true })
	writeFileSync(filePath, content, { mode: 0o644 })
}

export function ensurePlanFile(cwd: string): string {
	const filePath = getPlanFilePath(cwd)
	try {
		assertWritablePlanPath(cwd)
		if (!existsSync(filePath)) {
			mkdirSync(path.dirname(filePath), { recursive: true })
			writeFileSync(filePath, PLAN_FILE_TEMPLATE, { mode: 0o644 })
		}
	} catch (err) {
		console.warn("[adaptive-acl] Failed to ensure plan file:", err)
	}
	return filePath
}

function assertWritablePlanPath(cwd: string): void {
	const planPath = path.resolve(getPlanFilePath(cwd))
	const cwdResolved = path.resolve(cwd)
	if (planPathHasSymlinkAncestor(planPath, cwdResolved)) {
		throw new Error(`Refusing to write symlinked plan path: ${planPath}`)
	}
	try {
		if (existsSync(planPath) && lstatSync(planPath).isSymbolicLink()) {
			throw new Error(`Refusing to write symlinked plan file: ${planPath}`)
		}
	} catch (err) {
		if (err instanceof Error && err.message.startsWith("Refusing")) throw err
	}
}

export function resolveWorkspacePath(targetPath: string, cwd: string): string {
	if (!targetPath) return path.resolve(cwd)
	const p = expandUserPath(targetPath)
	return path.isAbsolute(p) ? path.resolve(p) : path.resolve(cwd, p)
}

export function isPlanFilePath(targetPath: string, cwd: string): boolean {
	if (!targetPath) return false
	const resolved = resolveWorkspacePath(targetPath, cwd)
	const planPath = path.resolve(getPlanFilePath(cwd))
	if (resolved !== planPath) return false
	if (planPathHasSymlinkAncestor(planPath, path.resolve(cwd))) return false
	if (!existsSync(planPath)) return true
	try {
		return realpathSync(resolved) === realpathSync(planPath)
	} catch {
		return false
	}
}

function planPathHasSymlinkAncestor(filePath: string, stopAt: string): boolean {
	const stop = path.resolve(stopAt)
	let current = path.resolve(filePath)
	while (true) {
		if (current === stop) break
		try {
			if (lstatSync(current).isSymbolicLink()) return true
		} catch {
			/* missing segment — ok while creating plan file */
		}
		const parent = path.dirname(current)
		if (parent === current) break
		current = parent
	}
	return false
}

export function isPlaceholderPlanItem(text: string): boolean {
	const t = text.trim().toLowerCase()
	return t === "(pending)" || t === "pending" || t.length <= 3
}

export function filterSubstantivePlanItems(items: TodoItem[]): TodoItem[] {
	return items.filter((item) => !isPlaceholderPlanItem(item.text))
}

/** Extract the `Plan:` section from an assistant message for plan.md sync. */
export function extractPlanSection(message: string): string | null {
	const headerMatch = message.match(/\*{0,2}Plan:\*{0,2}\s*\n/i)
	if (!headerMatch) return null
	const start = message.indexOf(headerMatch[0])
	const section = message.slice(start).trim()
	return section.length > 0 ? section : null
}

/** True when plan.md is missing, empty, or still the default placeholder template. */
export function shouldSyncAssistantPlanToFile(planContent: string | null): boolean {
	if (!planContent?.trim()) return true
	if (!planContent.includes("<!-- adaptive-acl:plan -->")) return false
	return filterSubstantivePlanItems(extractTodoItems(planContent)).length === 0
}

// ---- Auto risk patterns (v2.0.0) ----------------------------------------

const AUTO_RISK_PATTERNS: Array<{ category: string; pattern: RegExp }> = [
	{ category: "delete", pattern: /\brm\b/i },
	{ category: "delete", pattern: /\brmdir\b/i },
	{ category: "delete", pattern: /\bshred\b/i },
	{ category: "delete", pattern: /\bdd\b/i },
	{ category: "delete", pattern: /\bfind\b[^\n|;&]*\s-delete\b/i },
	{ category: "delete", pattern: /\bfind\b[^\n|;&]*\s-exec\b/i },
	{ category: "delete", pattern: /\bfind\b[^\n|;&]*\s-execdir\b/i },
	{ category: "delete", pattern: /\bfind\b[^\n|;&]*\s-fexec\b/i },
	{ category: "destructive", pattern: /\bgit\s+(add|commit|push|pull|merge|rebase|reset|checkout|branch\s+-[dD]|stash|cherry-pick|revert|tag|init|clone)/i },
	{ category: "destructive", pattern: /\bmv\b/i },
	{ category: "destructive", pattern: /\bcp\b/i },
	{ category: "destructive", pattern: /\bmkdir\b/i },
	{ category: "destructive", pattern: /\btouch\b/i },
	{ category: "destructive", pattern: /\d?>(?!&\d)/ },
	{ category: "destructive", pattern: />>/ },
	{ category: "package-install", pattern: /\bnpm\s+(install|uninstall|update|ci|link|publish)/i },
	{ category: "package-install", pattern: /\byarn\s+(add|remove|install|publish)/i },
	{ category: "package-install", pattern: /\bpnpm\s+(add|remove|install|publish)/i },
	{ category: "package-install", pattern: /\bpip\s+(install|uninstall)/i },
	{ category: "package-install", pattern: /\bapt(-get)?\s+(install|remove|purge|upgrade)/i },
	{ category: "package-install", pattern: /\bbrew\s+(install|uninstall|upgrade)/i },
	{ category: "network", pattern: /\bcurl\b/i },
	{ category: "network", pattern: /\bwget\b/i },
	{ category: "network", pattern: /https?:\/\//i },
	{ category: "privilege", pattern: /\bsudo\b/i },
	{ category: "privilege", pattern: /\bchmod\b/i },
	{ category: "privilege", pattern: /\bchown\b/i },
	{ category: "process", pattern: /\bkill\b/i },
	{ category: "process", pattern: /\bpkill\b/i },
	{ category: "process", pattern: /\bkillall\b/i },
	{ category: "system", pattern: /\breboot\b/i },
	{ category: "system", pattern: /\bshutdown\b/i },
	{ category: "system", pattern: /\bsystemctl\s+(start|stop|restart|enable|disable)/i },
]

export interface AutoRiskCheckInput {
	tool: string
	command?: string
	path?: string
}

export interface AutoRiskResult {
	match: boolean
	category: string
	reason: string
}

export function checkAutoRisk(
	input: AutoRiskCheckInput,
	cwd: string,
): AutoRiskResult {
	const noMatch: AutoRiskResult = { match: false, category: "", reason: "" }

	if (input.tool === "bash") {
		const cmd = input.command ?? ""
		for (const { category, pattern } of AUTO_RISK_PATTERNS) {
			if (pattern.test(cmd)) {
				return {
					match: true,
					category,
					reason: `Risky bash (${category}): ${cmd}`,
				}
			}
		}
		return noMatch
	}

	if (input.tool === "edit" || input.tool === "write") {
		const pathStr = input.path ?? ""
		if (pathStr && isOutsideCwd(pathStr, cwd)) {
			return {
				match: true,
				category: "outside-cwd-write",
				reason: `Write outside cwd: ${pathStr}`,
			}
		}
	}

	return noMatch
}

export function filterSkillsFromPrompt(
	prompt: string,
	allowedSkills: string[],
): string {
	// Fast-path: allow all
	if (
		!allowedSkills ||
		allowedSkills.length === 0 ||
		(allowedSkills.length === 1 && allowedSkills[0] === "*")
	) {
		return prompt
	}

	// Fast-path: no skill blocks at all
	if (!prompt.includes("<skill")) return prompt

	// Remove `<skill>...</skill>` blocks whose child `<name>` element is NOT in
	// allowedSkills. We deliberately allow flexible whitespace/indentation
	// between `<skill>` and `<name>` because pi's `formatSkillsForPrompt` uses
	// two-space indentation, but external callers might re-format.
	//
	// The capture group matches one line of `<name>...</name>` (no nested tags
	// allowed inside the name — Agent Skills spec constrains names to
	// [a-z0-9-]). `[\s\S]*?` is lazy so it stops at the FIRST `</skill>`,
	// which is correct because skills don't nest.
	return prompt.replace(
		/<skill>\s*<name>([^<]+)<\/name>[\s\S]*?<\/skill>/g,
		(match, name: string) => (allowedSkills.includes(name) ? match : ""),
	)
}

