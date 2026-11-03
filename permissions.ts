/**
 * Permission rule evaluation over the configured allow / deny / ask lists.
 * Order: deny → ask → allow → passthrough. A deny is final; an allow never reaches the classifier,
 * which is why `dangerous-permissions.ts` strips the broad ones before auto mode starts.
 *
 * The two halves of this file are matched by two different engines, on purpose:
 *
 *   - **allow** is argv matching. Layer 0 (`bash-audit.ts` → the walker) produces the legs of the
 *     command and `bash-rule-argv.ts` asks whether the words a rule names are those legs' words — and,
 *     for a leg that redirects, whether the file it writes is somewhere this session is allowed to
 *     write at all (the rule may name it, or the redirect target may already be an allowed place:
 *     {@link redirectAuthority}). A
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
import { bashRuleCoversArgv, type RedirectTarget } from "./bash-rule-argv.ts"
import { evaluateToolCall } from "./risk-policy.ts"
import { grantsCover, type GrantStore } from "./session-grants.ts"
import {
	ledgerCovers,
	namedForbidCovers,
	readOnlyActive,
	readOnlyLiftedByGrant,
	type Ledger,
} from "./auth-ledger.ts"
import { resolveInheritedPermissionMode } from "./mode-inherit.ts"
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

/**
 * The session state that decides whether a redirect target is a place a direct `write` / `read` of it
 * would be allowed.
 *
 * A rule is a file and the two questions above are answers about a file; this is the rest of the
 * answer, and it lives in the session: an approval given at a prompt, a sentence that granted (or
 * revoked) something, the read-only posture, the mode. `evaluateToolPermission` is handed none of that
 * by its callers today, so it is handed over here instead of being guessed at. Leaving it out is the
 * fail-closed reading and still the useful one: a `Write(…)`/`Edit(…)`/`Read(…)` allow rule naming the
 * target, or the mode's own write area (the project, a temp directory, `/dev/null`), still covers it.
 */
export type RedirectAuthority = {
	/** Session grants: the store the gate consults first when a write is not allowed outright. */
	grants?: GrantStore
	/** The authorisation ledger: long-range grants, named forbids and the read-only posture. */
	ledger?: Ledger
	/**
	 * The live mode. Only `plan` changes the answer, and it does so by refusing: plan mode's only write
	 * area is the plan file, which this layer must not name. Omitted, the process-published mode is read
	 * (`mode-inherit.ts`, the plugin's live-state channel) — so a caller that passes nothing still cannot
	 * write through a rule while the session is in plan mode.
	 */
	mode?: string
}

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

/**
 * The tool names a rule can be about: the spellings `mapPiToolToCcTool` produces, and nothing else.
 *
 * A rule naming anything else (`Bash(npm test)` with its closing paren lost to a trailing space, a
 * `Grep(…)` ported from a Claude Code settings file) is a line that looks active and matches nothing at
 * all — the failure `permissions-loader.ts` warns about when it loads one.
 */
export const KNOWN_RULE_TOOLS: ReadonlySet<string> = new Set(Object.values(PI_TO_CC_TOOL))

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
 *   - the redirect targets of each leg (`leg.targets`), which decide for every specifier whether the rule
 *     may speak for a file at all. Two ways a target is cleared, and only two: the rule names it
 *     (`Bash(echo hi > /tmp/out.txt)`), or a direct `write`/`read` of it would be allowed anyway —
 *     {@link redirectAuthority}. The second is what makes `Bash(make:*)` cover `make > build.log`: a
 *     project write needs no approval, so the redirect adds no authority the user did not already have.
 *     It is not a category question — `echo hi > ./notes.txt` and `echo hi > ~/.ssh/authorized_keys` are
 *     one argv apart, and the category is what the target *is* — so the check is the path's, not the
 *     command's:
 *
 *       · an output redirect is cleared only when a `write` call on that path would go through without
 *         asking: an `Edit(…)`/`Write(…)` allow rule, a file or folder write grant, or the mode's own
 *         write area;
 *       · an input redirect is a read, and needs what a `read` call needs — which a secret still does
 *         not have without its own authority;
 *       · `/dev/null` and descriptor dups are not special cases here: the first is allowed by the same
 *         table as any other inert sink, the second never reaches this code (`fileTargetsOf`);
 *       · a runtime target (`> $f`), a secret, live config, or anywhere the allowed area stops is not
 *         cleared — the command goes back to the gate, which judges the target itself.
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
	authority?: RedirectAuthority,
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

	const targetAllowed = redirectAuthority(cwd, rules, authority)
	const covered: string[] = []
	let source: PermissionRuleSource | undefined
	for (const leg of view.legs) {
		const spellings = legSpellings(leg)
		if (spellings.length === 0) return null
		// One coverage question per leg: the strictness flag is the command's (the verdict is not labelled
		// per leg) and the targets are the leg's (a compound's second clause writes a different file).
		const coverage = { strictOperands: view.strictOperands, targets: leg.targets, targetAllowed }
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
	// The pair, not just the name: `PAGER=cat` sets a variable and still runs the command (`bash-audit.ts`
	// {@link envChangesExecution} decides which values are neutral).
	if (leg.env.some((e) => envChangesExecution(e.name, e.value))) return []
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

/**
 * A redirect target, asked the question a direct `write` / `read` tool call on that same path asks.
 *
 * The order is the one a real call walks, which is why it is stated once here:
 *
 *   1. **the configured rules** — the path tool's own channel, so a `Write(src/**)` or `Read(~/.gnupg/)`
 *      allow covers it, and a `Write(…)` ask or deny withholds it;
 *   2. **the mode** — plan mode writes one file, and naming it from here would be inventing a second
 *      copy of that decision, so a write target is simply not cleared in plan mode;
 *   3. **the gate's own sync answer** for a direct call ({@link pathAuthorityAllows}): the mode's default
 *      write area (project, temp), or a stored grant / ledger row / posture that the gate would honour.
 *      No model call is made here — this runs inside the `tool_call` hook on the hottest path there is —
 *      so "the gate would have asked the classifier" is not an answer this layer may give.
 */
function redirectAuthority(
	cwd: string,
	rules: PermissionRule[],
	authority: RedirectAuthority | undefined,
): (target: RedirectTarget) => boolean {
	// A leg is asked about the same file once per spelling per candidate rule; the answer cannot change
	// inside one call, and `classifyPath` + `decideWrite` should not be paid for each of them.
	const seen = new Map<string, boolean>()
	return (target) => {
		const key = `${target.op}\u0000${target.target}`
		const known = seen.get(key)
		if (known !== undefined) return known
		const answer = resolveRedirectTarget(target, cwd, rules, authority)
		seen.set(key, answer)
		return answer
	}
}

/** One target, the one question: a direct `write` / `read` of this file, allowed or not? */
function resolveRedirectTarget(
	target: RedirectTarget,
	cwd: string,
	rules: PermissionRule[],
	authority: RedirectAuthority | undefined,
): boolean {
	const kind = redirectToolOf(target)
	// 1. the same function a direct write/read call goes through, over the same rule set
	const byRule = evaluateToolPermission(kind, { path: target.target }, cwd, rules)
	if (byRule.behavior === "allow") return true
	if (byRule.behavior !== "passthrough") return false
	// 2. plan mode's write area is the plan file; a redirect is not how it gets named.
	if (kind === "write" && (authority?.mode ?? resolveInheritedPermissionMode()) === "plan") return false
	// 3. everything the gate's tables and stores say about this exact path, without the model
	return pathAuthorityAllows(kind, target.target, cwd, authority)
}

/** Which tool call a redirect is: `<` and `<&` read a file, every other operator writes one. */
function redirectToolOf(target: RedirectTarget): "write" | "read" {
	return target.op === "<" || target.op === "<&" ? "read" : "write"
}

/**
 * Would a direct `write` / `read` of this path run without asking, as far as code can tell?
 *
 * This is the synchronous half of `runGate` for one call (`gate.ts`), in the same order and with the same
 * predicates: tier `allow` (with the user-forbid override), tier `never` refused outright, and tier `ask`
 * answered only by the session grants, then the ledger, then the read-only posture. The one thing it does
 * not do is the model call, because there is no endpoint here and because a rule must never be the thing
 * that spends one.
 *
 * The policy is built the way `bash-audit.ts` builds the one layer 0 already used for this command —
 * `project: cwd` — so a target is classified against the same root the gate's `gatePolicy` carries.
 */
function pathAuthorityAllows(
	kind: "write" | "read",
	raw: string,
	cwd: string,
	authority: RedirectAuthority | undefined,
): boolean {
	const home = homedir()
	const project = cwd
	const ledger = authority?.ledger
	const policy = evaluateToolCall(kind, { path: raw }, { cwd, project, home, env: process.env })
	if (policy.tier === "allow") {
		// `do not touch /x` binds even where the tables would let the write go through, which is the
		// override the gate applies before it returns its own allow.
		return namedForbidCovers(ledger ?? null, policy.entities, home, project, policy.category) === null
	}
	if (policy.tier !== "ask") return false
	if (authority?.grants) {
		if (grantsCover(authority.grants, policy.category, policy.entities, home, project).covered) return true
	}
	if (ledger) {
		const lv = ledgerCovers(ledger, policy.category, policy.entities, home, project)
		if (lv.forbidden) return false
		if (lv.covered) return true
		// A posture is a user instruction, not a default: it holds here exactly as it holds at the gate.
		// Read categories are exempt by definition, so only a write can be stopped by it.
		const ro = readOnlyActive(ledger)
		if (ro && kind === "write" && !readOnlyLiftedByGrant(ledger, policy.category, policy.entities, ro.seq, home, project)) return false
	}
	return false
}

export function evaluateToolPermission(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
	rules: PermissionRule[],
	authority?: RedirectAuthority,
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
		const all = bashAllowRulesCoverCommand(String(input.command ?? ""), rules, cwd, authority)
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
 * and a leg that no rule can describe (a here-string, a run-time value) contributes nothing.
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
			"no rule would cover this command again (a here-string, a run-time value, or a step that is never auto-approved)",
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
			// A rule whose tool this extension cannot match never fires; `/permissions` is where a user looks
			// when a rule they wrote does nothing, so it says so there (the loader also warns once on load).
			const dead = KNOWN_RULE_TOOLS.has(r.ruleValue.toolName) ? "" : "  ← no such tool: this rule never fires"
			lines.push(
				`  [${r.source}] ${permissionRuleValueToString(r.ruleValue)}${dead}`,
			)
		}
	}
	return lines.length ? lines.join("\n") : "(no permission rules configured)"
}
