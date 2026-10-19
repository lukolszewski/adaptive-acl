/**
 * Permission rule evaluation over the configured allow / deny / ask lists.
 * Order: deny → ask → allow → passthrough. A deny is final; an allow never reaches the classifier,
 * which is why `dangerous-permissions.ts` strips the broad ones before auto mode starts.
 *
 * The two halves of this file are matched by two different engines, on purpose:
 *
 *   - **allow** is argv matching. Layer 0 (`bash-audit.ts` → the walker) produces the legs of the
 *     command and `bash-rule-argv.ts` asks whether the words a rule names are those legs' words — and,
 *     for a leg that redirects, whether the rule names the file it writes. A
 *     command layer 0 will not vouch for has no argv, so no rule can cover it and it goes to the prompt;
 *     and where the verdict says the command's risk is the targets its operands name, an exact rule only
 *     covers the invocation it names — no extra target, no added flag;
 *   - **deny / ask** stay textual (`bashCommandMatchesRuleContent`). A denial has to fire on a construct
 *     the walker refuses — `for f in *; do rm -f $f; done` must be stopped by `Bash(rm *)` even though
 *     there is no argv to compare — so a deny cannot be made to depend on argv.
 *
 * There used to be a second copy of the allow decision here: this file split the command into segments
 * itself and the text matcher then stripped wrappers, redirections and `NAME=value` prefixes before
 * comparing strings. That is the duplicate this layout removes — see `bash-allow-layer0.test.ts`, which
 * fails if a scanner comes back.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import {
	bashCommandMatchesRuleContent,
	suggestBashAllowRule,
	suggestBashAllowRuleSet,
} from "./bash-permission-match.ts"
import { bashRuleView, envChangesExecution, type BashLeg, type BashRuleView } from "./bash-audit.ts"
import { bashRuleCoversArgv } from "./bash-rule-argv.ts"
import {
	pathToolMatchesRuleContent,
	suggestPathAllowRule,
} from "./path-permission-match.ts"
import {
	permissionRuleValueFromString,
	permissionRuleValueToString,
	type PermissionRuleValue,
} from "./permission-rule-parser.ts"
import { classifyPath } from "./risk-paths.ts"
import path from "node:path"
import { homedir } from "node:os"

export type PermissionBehavior = "allow" | "deny" | "ask"

export type PermissionRuleSource = "global" | "project" | "local"

export interface PermissionRule {
	source: PermissionRuleSource
	behavior: PermissionBehavior
	ruleValue: PermissionRuleValue
}

export type PermissionVerdict =
	| { behavior: "deny"; rule: string; source: PermissionRuleSource }
	| { behavior: "ask"; rule: string; source: PermissionRuleSource }
	| { behavior: "allow"; rule: string; source: PermissionRuleSource }
	| { behavior: "passthrough" }

export interface PermissionsConfig {
	allow?: string[]
	deny?: string[]
	ask?: string[]
}

const PI_TO_CC_TOOL: Record<string, string> = {
	bash: "Bash",
	read: "Read",
	grep: "Read",
	find: "Read",
	ls: "Read",
	edit: "Edit",
	write: "Write",
}

export function mapPiToolToCcTool(toolName: string): string | null {
	return PI_TO_CC_TOOL[toolName] ?? null
}

export function rulesFromPermissionsConfig(
	config: PermissionsConfig,
	source: PermissionRuleSource,
): PermissionRule[] {
	const rules: PermissionRule[] = []
	for (const behavior of ["deny", "ask", "allow"] as PermissionBehavior[]) {
		const list = config[behavior]
		if (!list) continue
		for (const ruleString of list) {
			rules.push({
				source,
				behavior,
				ruleValue: permissionRuleValueFromString(ruleString),
			})
		}
	}
	return rules
}

export function mergePermissionRules(
	...ruleSets: PermissionRule[][]
): PermissionRule[] {
	const seen = new Set<string>()
	const merged: PermissionRule[] = []
	for (const set of ruleSets) {
		for (const rule of set) {
			const key = `${rule.behavior}:${permissionRuleValueToString(rule.ruleValue)}`
			if (seen.has(key)) continue
			seen.add(key)
			merged.push(rule)
		}
	}
	return merged
}

/**
 * Textual match, used for deny/ask on bash and for the path tools (allow included).
 *
 * The `Bash` branch is reached by deny and ask only: {@link evaluateToolPermission} asks
 * {@link bashAllowRulesCoverCommand} for allow and returns whatever it says. That is why the behaviour
 * here is still the one `compound-rule-coverage.test.ts` pins — a single rule can never express
 * AND-across-legs, which is exactly why allow moved to a place that sees the whole rule set.
 */
function ruleMatchesToolCall(
	rule: PermissionRule,
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
): boolean {
	const ccTool = mapPiToolToCcTool(toolName)
	if (!ccTool) return false
	if (rule.ruleValue.toolName !== ccTool) return false

	if (ccTool === "Bash") {
		const cmd = String(input.command ?? "")
		return bashCommandMatchesRuleContent(
			cmd,
			rule.ruleValue.ruleContent,
			rule.behavior,
		)
	}

	const pathStr = String(input.path ?? "")
	if (!pathStr && rule.ruleValue.ruleContent !== undefined) {
		return false
	}

	if (ccTool === "Read") {
		return pathToolMatchesRuleContent(
			"Read",
			pathStr,
			rule.ruleValue.ruleContent,
			cwd,
		)
	}
	if (ccTool === "Edit") {
		return pathToolMatchesRuleContent(
			"Edit",
			pathStr,
			rule.ruleValue.ruleContent,
			cwd,
		)
	}
	if (ccTool === "Write") {
		return pathToolMatchesRuleContent(
			"Write",
			pathStr,
			rule.ruleValue.ruleContent,
			cwd,
		)
	}

	return false
}



/**
 * Per-leg AND for allow rules, over the walker's legs instead of over a re-split of the text.
 *
 * A compound is allowed only when every leg has its own authority, so padding an authorised command
 * with `&& rm -rf /x` still gains nothing. What replaced the text path is:
 *
 *   - legs from layer 0 (`bashRuleView`), so `&&`, `;`, `|`, `&`, a newline and a subshell are the
 *     shell's own answer about where one command ends, not this file's guess;
 *   - `bashRuleCoversArgv` per leg, so quoting is resolved on both sides and one rule cannot cover two
 *     legs it was never written for;
 *   - four refusals, each of which hands the command back to the gate: an unproven command (no trustworthy
 *     argv exists to have been authorised), an `opaque` leg (a run-time value in a literal's costume), a
 *     leg whose environment changes execution, and the never floor — a wrapper, a `&&` or a rule
 *     may not launder severity, so `sudo rm -rf /` stays `never`;
 *   - strict operands where the verdict says the command's risk is the targets it names: there a rule
 *     has to name every word the call passes, so an approval written for one target cannot be spent on
 *     another (`bash-audit.ts` owns the category table; `bash-rule-argv.ts` owns the matching);
 *   - the redirect targets of each leg (`leg.targets`), which narrow every specifier: a rule that does
 *     not name the file a command writes does not cover that command. Strictness there is not a category
 *     question — `echo hi > ./notes.txt` and `echo hi > ~/.ssh/authorized_keys` are one argv apart, and
 *     the category is what the target *is*, so the answer cannot depend on it.
 *
 * One verdict per call, and one refusal order: the floor is checked first because it is the cheapest
 * answer and the one that outranks every rule.
 *
 * Returns the covering rule per leg, or null when anything is uncovered or refused.
 */
function bashAllowRulesCoverCommand(
	command: string,
	rules: PermissionRule[],
	cwd: string,
): { rules: string[]; source: PermissionRuleSource } | null {
	const allowRules = rules.filter((r) => r.behavior === "allow")
	if (allowRules.length === 0) return null

	// Fail closed on a thrown analysis, never on a thrown tool call: this runs inside the `tool_call`
	// hook, and an exception here would take the extension down instead of asking the user.
	let view: BashRuleView
	try {
		view = bashRuleView(command, cwd)
	} catch {
		return null
	}
	if (!view.proven) return null
	if (view.floored) return null

	const covered: string[] = []
	let source: PermissionRuleSource | undefined
	for (const leg of view.legs) {
		const spellings = legSpellings(leg)
		if (spellings.length === 0) return null
		// One coverage question per leg: the strictness flag is the command's (the verdict is not labelled
		// per leg) and the targets are the leg's (a compound's second clause writes a different file).
		const coverage = { strictOperands: view.strictOperands, targets: leg.targets }
		const hit = allowRules.find((r) => spellings.some((argv) => bashRuleCoversArgv(r, argv, coverage)))
		if (!hit) return null
		covered.push(`${leg.text} \u2190 ${permissionRuleValueToString(hit.ruleValue)}`)
		if (source === undefined) source = hit.source
	}
	if (source === undefined) return null
	return { rules: covered, source }
}

/**
 * Every argv a leg may be matched against — empty when the leg may not be covered at all.
 *
 * The spellings, in order of how much they say:
 *   1. the walker's argv, which is what the command runs;
 *   2. that argv with its `NAME=value` prefix spelled back in, because an exact rule written before
 *      argv matching (`Bash(FOO=1 echo hi)`) names those words and must keep honouring the approval it
 *      was written from — the env names themselves have already been refused or accepted as a set;
 *   3. the wrapper-stripped argv, for the six wrappers `bash-audit.ts` may see through, guarded by the
 *      never floor so `Bash(git status:*)` cannot carry `sudo rm -rf /` past it.
 *
 * All three are handed to the matcher with the same `strictOperands` flag the command's verdict produced,
 * so a target-bearing command has to be named exactly in whichever spelling a rule happens to use.
 *
 * A leg is refused outright when it runs nothing (argv empty — `> f` is still a write and no rule here
 * speaks for it), when it carries a run-time value, or when it sets a variable that changes execution.
 */
function legSpellings(leg: BashLeg): string[][] {
	if (leg.argv.length === 0) return []
	if (leg.opaque) return []
	if (leg.envNames.some(envChangesExecution)) return []
	const out: string[][] = []
	const seen = new Set<string>()
	for (const argv of leg.inner ? [leg.argv, leg.withAssignments, leg.inner] : [leg.argv, leg.withAssignments]) {
		const key = argv.join("\u0000")
		if (seen.has(key)) continue
		seen.add(key)
		out.push(argv)
	}
	return out
}

export function evaluateToolPermission(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
	rules: PermissionRule[],
): PermissionVerdict {
	const ccTool = mapPiToolToCcTool(toolName)
	if (!ccTool) {
		return { behavior: "passthrough" }
	}

	// deny then ask, both textual: a denial must fire even on a construct layer 0 refuses to parse.
	for (const behavior of ["deny", "ask"] as PermissionBehavior[]) {
		for (const rule of rules) {
			if (rule.behavior !== behavior) continue
			if (!ruleMatchesToolCall(rule, toolName, input, cwd)) continue
			return {
				behavior,
				rule: permissionRuleValueToString(rule.ruleValue),
				source: rule.source,
			}
		}
	}

	if (ccTool === "Bash") {
		// Allow on argv — and only here. Anything this refuses (an unproven command, an opaque leg, the
		// never floor) falls to the gate, which has the tables, grants and model to judge it.
		const all = bashAllowRulesCoverCommand(String(input.command ?? ""), rules, cwd)
		if (!all) return { behavior: "passthrough" }
		return { behavior: "allow", rule: all.rules.join("; "), source: all.source }
	}

	for (const rule of rules) {
		if (rule.behavior !== "allow") continue
		if (!ruleMatchesToolCall(rule, toolName, input, cwd)) continue
		return {
			behavior: "allow",
			rule: permissionRuleValueToString(rule.ruleValue),
			source: rule.source,
		}
	}

	return { behavior: "passthrough" }
}

export type AllowRuleSet = {
	rules: string[]
	persistable: boolean
	reason?: string
}

/**
 * EVERY rule an "always allow" would write for this tool call.
 *
 * One rule per command leg, so an approval on a compound authorises exactly the compound that was
 * shown — not just its first clause. Destructive verbs contribute an exact rule rather than a prefix,
 * and a leg that no rule can describe (a redirect, a here-document, a run-time value) contributes nothing.
 *
 * For bash the set is then checked against the very matcher that will have to honour it
 * ({@link bashAllowRulesCoverCommand}) and withheld when it would not: an offer that stores a rule which
 * never fires is the failure AGENTS.md already calls worse than no offer. The producer derives its
 * specifier from layer 0's argv, so the check normally passes by construction; what still lands here is a
 * command at the never floor (`rm -rf /`, a force push) — withheld because coverage refuses it and the gate
 * denies it anyway, so a rule would only make the prompt look like a bug.
 *
 * Path tools still yield a single rule and inherit the known first-segment over-grant in
 * suggestPathAllowRule; narrowing that is a separate decision.
 */
export function suggestAllowRuleSetForToolCall(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
): AllowRuleSet {
	const ccTool = mapPiToolToCcTool(toolName)
	if (ccTool === "Bash") return suggestBashRules(String(input.command ?? ""), cwd)
	const pathStr = String(input.path ?? "")
	if (ccTool === "Read" || ccTool === "Edit" || ccTool === "Write") {
		return { rules: [suggestPathAllowRule(ccTool, pathStr, cwd)], persistable: true }
	}
	return { rules: [ccTool ?? toolName], persistable: true }
}

function suggestBashRules(command: string, cwd: string): AllowRuleSet {
	// The producer is told the project root because the command's CATEGORY decides whether its rule may be
	// a prefix at all: where the risk is in the target the rule has to name every word the call ran.
	const written = suggestBashAllowRuleSet(command, cwd)
	if (!written.persistable) return written
	const asRules: PermissionRule[] = written.rules.map((rule) => ({
		source: "project",
		behavior: "allow",
		ruleValue: permissionRuleValueFromString(rule),
	}))
	if (bashAllowRulesCoverCommand(command, asRules, cwd)) return written
	return {
		rules: [],
		persistable: false,
		reason:
			"no rule would cover this command again (a here-document body, a run-time value, or a step that is never auto-approved)",
	}
}

/**
 * The folder-scope rule an "allow always (this folder)" would write, or undefined when the offer
 * would be a lie.
 *
 * Folder scope exists because a per-file approval prompts again for the next file in the same
 * directory: four unit files under `deploy/systemd/` cost four prompts and four rules, which is the
 * whole complaint this answers. `suggestPathAllowRule` already turns a trailing slash into a subtree
 * rule (and treats it as decisive even for a directory that does not exist yet), so nothing new is
 * derived here — only the folder of the thing being approved.
 *
 * Returns undefined for a secret-classified target because a `**` rule can never match a secret (see
 * `pathMatchesRulePattern`: reaching a credential has to name it exactly). Offering the folder there
 * would store a rule that silently does nothing — the mirror image of the dishonest offer
 * `suggestAllowRuleSetForToolCall` already withholds, where the stored rule would be *broader* than
 * the approval. Withholding is the honest move in both directions.
 */
export function suggestFolderAllowRule(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
): string | undefined {
	const ccTool = mapPiToolToCcTool(toolName)
	if (ccTool !== "Read" && ccTool !== "Edit" && ccTool !== "Write") return undefined
	const raw = String(input.path ?? "").trim().replace(/^["']|["']$/g, "")
	if (!raw) return undefined
	const home = homedir()
	const expanded = raw === "~" ? home : raw.startsWith("~/") ? path.join(home, raw.slice(2)) : raw
	const abs = path.isAbsolute(expanded)
		? path.resolve(expanded)
		: path.resolve(cwd, expanded)
	const posixAbs = abs.split(path.sep).join("/")
	if (classifyPath(posixAbs, { cwd, project: cwd, home }).isSecret) return undefined
	const dir = path.posix.dirname(posixAbs)
	if (!dir || dir === "/") return undefined
	return suggestPathAllowRule(ccTool, dir + "/", cwd)
}

export function suggestAllowRuleForToolCall(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
): string {
	const ccTool = mapPiToolToCcTool(toolName)
	if (ccTool === "Bash") {
		return suggestBashAllowRule(String(input.command ?? ""), cwd)
	}
	const pathStr = String(input.path ?? "")
	if (ccTool === "Read") return suggestPathAllowRule("Read", pathStr, cwd)
	if (ccTool === "Edit") return suggestPathAllowRule("Edit", pathStr, cwd)
	if (ccTool === "Write") return suggestPathAllowRule("Write", pathStr, cwd)
	return ccTool ?? toolName
}

export function formatMergedRulesForDisplay(rules: PermissionRule[]): string {
	const lines: string[] = []
	for (const behavior of ["deny", "ask", "allow"] as PermissionBehavior[]) {
		const subset = rules.filter((r) => r.behavior === behavior)
		if (!subset.length) continue
		lines.push(`${behavior}:`)
		for (const r of subset) {
			lines.push(
				`  [${r.source}] ${permissionRuleValueToString(r.ruleValue)}`,
			)
		}
	}
	return lines.length ? lines.join("\n") : "(no permission rules configured)"
}
