/**
 * Broad-Bash-rule detection.
 *
 * An *allow* rule such as `Bash(python:*)` hands the shell to the model without ever
 * asking the classifier what the command does: the rule short-circuits the gate before
 * any effect is reasoned about. Entering auto mode therefore removes those rules, and
 * leaving auto mode puts them back. Nothing outside this module decides which rules
 * count as broad — the answer lives in `DANGEROUS_BASH_PATTERNS` plus `coversArgsBlindly`.
 *
 * A rule is broad when its content is a listed program with an all-arguments tail
 * (`git`, `git:*`, `git*`, `git *`, `git -<flag>*`), or when it names no command at all
 * (`Bash` / `Bash(*)`). A rule that pins a subcommand or an argument — `npm run test`,
 * `git status`, `npm install lodash:*` — stays in force.
 */

import {
	permissionRuleValueToString,
	type PermissionRuleValue,
} from "./permission-rule-parser.ts"
import type { PermissionRule } from "./permissions.ts"

/** Interpreters and runners present on every platform we support. */
export const CROSS_PLATFORM_CODE_EXEC = [
	"python",
	"python3",
	"python2",
	"node",
	"deno",
	"tsx",
	"ruby",
	"perl",
	"php",
	"lua",
	"npx",
	"bunx",
	"npm run",
	"yarn run",
	"pnpm run",
	"bun run",
	"bash",
	"sh",
	"ssh",
] as const

/**
 * Program names whose blanket allow rule is a code-execution bypass. One- and two-word
 * names both appear: `npm` alone is broad, and so is the `npm install` verb, because a
 * lifecycle script (postinstall, build.rs, setup.py) runs arbitrary code either way.
 */
export const DANGEROUS_BASH_PATTERNS: readonly string[] = [
	...CROSS_PLATFORM_CODE_EXEC,
	"zsh",
	"fish",
	"eval",
	"exec",
	"env",
	"xargs",
	"sudo",
	"curl",
	"wget",
	"git",
	// Package managers with lifecycle-script execution (adjudication ②,
	// 2026-09-12): broad install/exec verb rules bypass the classifier —
	// npm postinstall, pip setup.py, cargo build.rs are arbitrary code runs.
	// Bare names catch Bash(npm:*); verb forms catch Bash(npm install:*).
	"npm",
	"npm install",
	"npm uninstall",
	"npm update",
	"npm ci",
	"npm link",
	"npm exec",
	"yarn",
	"yarn add",
	"yarn remove",
	"yarn install",
	"yarn link",
	"yarn exec",
	"pnpm",
	"pnpm add",
	"pnpm remove",
	"pnpm install",
	"pnpm link",
	"pnpm exec",
	"pnpm dlx",
	"bun",
	"bun add",
	"bun remove",
	"bun install",
	"bunx",
	"pip",
	"pip install",
	"pip uninstall",
	"pip download",
	"pip3",
	"pip3 install",
	"pip3 uninstall",
	"cargo",
	"cargo install",
	"cargo run",
	"uv",
	"uv run",
	"uv pip",
	"poetry",
	"poetry install",
	"poetry add",
	"poetry run",
	"gem",
	"gem install",
	"composer",
	"composer install",
	"composer require",
	"go run",
	"go install",
	"go generate",
]

/** Lookup table for the name part of a rule; the list itself is only built once. */
const LISTED_PROGRAMS: ReadonlySet<string> = new Set(
	DANGEROUS_BASH_PATTERNS.map((name) => name.toLowerCase()),
)

/**
 * Text that can sit to the right of a program name while the rule still covers every
 * invocation of it. Compared byte-for-byte: `git  *` (two spaces) is not a shape the
 * settings file produces, and treating it as one would quietly widen the rule set.
 */
const ALL_ARGUMENTS_TAILS = ["", ":*", "*", " *"] as const

/** Joins a program to its flag wildcard in the `git -<flag>*` shape. */
const FLAG_PREFIX = " -"

/** Does `<program><tail>` form cover the whole command space of that program? */
function namesAListedProgram(rule: string): boolean {
	return ALL_ARGUMENTS_TAILS.some(
		(tail) =>
			rule.endsWith(tail) &&
			LISTED_PROGRAMS.has(rule.slice(0, rule.length - tail.length)),
	)
}

/**
 * The flag form: `git -*`, `npm install -*`. No listed name contains a hyphen, so the
 * first ` -` in the content is exactly where the program part ends; a flag list without
 * the trailing star (`git -C`) only covers what was spelled out and stays in force.
 */
function flagsAreWhitelisted(rule: string): boolean {
	if (!rule.endsWith("*")) return false
	const split = rule.indexOf(FLAG_PREFIX)
	return split > 0 && LISTED_PROGRAMS.has(rule.slice(0, split))
}

/**
 * Would this Bash allow rule let a command through without the classifier seeing it?
 * Always false for tools other than Bash — path tools carry a file glob, not a command.
 */
export function isDangerousBashPermission(
	toolName: string,
	ruleContent: string | undefined,
): boolean {
	if (toolName !== "Bash") return false
	// A rule naming no command at all is the widest grant the file can express.
	if (ruleContent === undefined || ruleContent.length === 0) return true

	const rule = ruleContent.trim().toLowerCase()
	return rule === "*" || namesAListedProgram(rule) || flagsAreWhitelisted(rule)
}

/** Same question, asked from the classifier's point of view. */
export function isDangerousClassifierPermission(
	toolName: string,
	ruleContent: string | undefined,
): boolean {
	return isDangerousBashPermission(toolName, ruleContent)
}

export type StripDangerousResult = {
	active: PermissionRule[]
	stashed: PermissionRule[]
}

/** Only grants can bypass anything: a deny or ask rule is never stashed. */
function grantsAClassifierBypass(rule: PermissionRule): boolean {
	if (rule.behavior !== "allow") return false
	const { toolName, ruleContent } = rule.ruleValue
	return isDangerousClassifierPermission(toolName, ruleContent)
}

/** Split the rule set into "safe to keep while auto mode runs" and "put aside". */
export function stripDangerousPermissionRules(
	rules: PermissionRule[],
): StripDangerousResult {
	return {
		active: rules.filter((rule) => !grantsAClassifierBypass(rule)),
		stashed: rules.filter((rule) => grantsAClassifierBypass(rule)),
	}
}

/**
 * What makes two rules the same rule for merge purposes: the behaviour, the rule text
 * and the file it came from. A global `Bash(git:*)` and a project one are different rows.
 */
function ruleFingerprint(rule: PermissionRule): string {
	return JSON.stringify([
		rule.behavior,
		permissionRuleValueToString(rule.ruleValue),
		rule.source,
	])
}

/**
 * Put the stashed grants back, skipping any the user re-added by hand in the meantime.
 * Input order is kept: active rules first, then the stash in the order it was removed.
 */
export function restoreDangerousPermissionRules(
	active: PermissionRule[],
	stashed: PermissionRule[],
): PermissionRule[] {
	if (stashed.length === 0) return active

	const alreadyThere = new Set(active.map(ruleFingerprint))
	const worthAdding = stashed.filter((rule) => {
		const fingerprint = ruleFingerprint(rule)
		if (alreadyThere.has(fingerprint)) return false
		alreadyThere.add(fingerprint)
		return true
	})
	return [...active, ...worthAdding]
}

/** Rule as the user wrote it, for the notice that explains why it was stripped. */
export function formatDangerousRuleDisplay(
	ruleValue: PermissionRuleValue,
): string {
	const { toolName, ruleContent } = ruleValue
	return `${toolName}(${ruleContent ?? "*"})`
}
