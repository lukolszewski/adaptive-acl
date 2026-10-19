/**
 * Re-reading the rules files into the policy a session is running on.
 *
 * A rule written mid-session — by an "always" click, by `/grants adopt confirm` — is not part of the policy
 * until something re-reads the file. The adopt path had no such re-read, and the honest move at the time was
 * the wording ("effective next session") rather than quietly widening authority. Naming a gap honestly is not
 * closing it, and this module closes it: a reload face a caller can actually call, so "adopted" can come to
 * mean "live now" without anyone minting a shadow grant to cover the gap.
 *
 * ------------------------------------------------------------- what already exists, and why it is not enough
 * `index.ts` has a private `reloadMergedPermissionRules(cwd)` inside the extension closure (activation,
 * every `before_agent_start`, `/permissions`, and the always-allow branch that writes rules). It is not a
 * face any module can call, and — the part that matters — it is built on `loadMergedPermissionRules()`,
 * which answers "what are the rules?" with `[]` for three quite different situations: the file is absent,
 * the file is blank, and the file is there but could not be read or parsed. The third is not "no rules"; it
 * is "no rules I could read", exactly the distinction `grants-adopt.ts` draws for these same files ("an
 * unreadable deny list is not a clean one"). A reload built on that read takes a half-written
 * `permissions.json` as "this project keeps no deny rules now" and takes down every wall the session was
 * running behind — a lost deny nobody wrote, which AGENTS.md calls the worst failure this codebase has,
 * triggered by the reload itself. That applies to the existing call sites today, not only to this one.
 *
 * So each source here is read on its own and gets a verdict. `ok` means the file answered, and its rules
 * replace that source's contribution. Anything else means the source said NOTHING at all, and the
 * contribution it made last time is carried over untouched.
 *
 * ------------------------------------------------------------ the one rule a reload may never break
 * A reload may install whatever the files carry, and may drop an entry whose only effect was to ALLOW
 * something — for allowances the file stays the source of truth, so deleting one takes effect immediately.
 * What it may never do is lift a wall. Every `deny` / `ask` the live policy held is carried forward unless
 * the files still carry it themselves, because the only supported way to make a session refuse LESS is to
 * refuse MORE somewhere else: revocation dominates addition everywhere else in this subsystem, and a
 * re-read of a file is the weakest possible claim that a refusal was meant to end. A held-back wall costs
 * one restart to clear; a wall that vanished because a file was briefly unreadable costs whatever the model
 * does next.
 *
 * That asymmetry is a real consequence, stated plainly: delete a deny rule from `permissions.json` and this
 * face will keep honouring it for the rest of the session. The report says so (`heldBack`) instead of
 * hiding it, because "the file no longer says that" and "the session forgot it" are different sentences.
 *
 * ------------------------------------------------------------------------ what a reload is NOT
 *  - not a merge of other projects' state — it reads the three files the gate already reads, and nothing in
 *    an orphaned directory;
 *  - not a place that invents a rule: a rule in no file and not already live never appears;
 *  - not responsible for auto mode's strip of classifier-bypassing bash allows. Hand it the BASE snapshot
 *    (what `loadMergedPermissionRules` returned, before `stripDangerousPermissionRules`) and re-apply the
 *    strip to whatever comes back, exactly as the activation path does today.
 */

import { existsSync, readFileSync } from "node:fs"

import { getConfigPath } from "./config.ts"
import { getProjectPermissionsPath } from "./permissions-loader.ts"
import {
	permissionRuleValueFromString,
	permissionRuleValueToString,
} from "./permission-rule-parser.ts"
import {
	type PermissionBehavior,
	type PermissionRule,
	type PermissionRuleSource,
	type PermissionsConfig,
	mergePermissionRules,
	rulesFromPermissionsConfig,
} from "./permissions.ts"

/** The three files a policy is made of, in the order `mergePermissionRules` gives precedence. */
const SOURCES: readonly PermissionRuleSource[] = ["global", "project", "local"]

const BEHAVIOURS: readonly PermissionBehavior[] = ["deny", "ask", "allow"]

/** One rules file, as the reload saw it. */
export type RuleSourceRead = {
	source: PermissionRuleSource
	file: string
	/** True when the file answered: its rules may stand as that source's whole contribution. */
	ok: boolean
	/** Why it did not answer, in words a user can act on. Absent when `ok`. */
	problem?: string
	/** What it contributed — empty when `ok` and the file had nothing to say. */
	rules: PermissionRule[]
	/** Entries inside a readable list that were not usable rule strings. Counted, never installed. */
	ignored: number
	/** `ok` and the file was absent or blank: it answered "nothing", which is not a failure. */
	answeredNothing: boolean
}

export type PolicyReload = {
	/** The snapshot to install. A NEW array — the snapshot handed in is never mutated. */
	rules: PermissionRule[]
	sources: RuleSourceRead[]
	/** Rules this reload put into the policy that the session did not already have. */
	added: string[]
	/** Rules the session had and the files no longer grant. By construction these are allows only. */
	dropped: string[]
	/** Deny/ask rules the files no longer carry that were kept anyway — see the header. */
	heldBack: string[]
	/** `<file> — <why>`, one per source that could not be read. Its rules were left as they were. */
	unreadable: string[]
	/** False when the installed snapshot holds exactly the rules the session already had. */
	changed: boolean
}

export type ReloadOptions = {
	/** The checkout whose project + local rules files are read. */
	cwd: string
	/** The policy the session is running on: `loadMergedPermissionRules()`'s output, before any strip. This is
	 *  the last thing the session INSTALLED, not a fresh read of the files — a fresh read has already seen
	 *  whatever was just written, and then the reload could report a change it did not make. */
	live: readonly PermissionRule[]
	/** Test seam for the user-level config path. Defaults to `getConfigPath()`, like the loader. */
	globalFile?: string
}

/**
 * `<behavior> <rule>` — one string per distinct rule.
 *
 * It is both the label every report here uses and the identity `mergePermissionRules` dedups on, because
 * they are the same question: two entries a re-read cannot tell apart ARE the same rule.
 */
export function ruleLabel(rule: PermissionRule): string {
	return `${rule.behavior} ${permissionRuleValueToString(rule.ruleValue)}`
}

/**
 * Is this rule in the policy — and if so, which source is carrying it?
 *
 * The caller asks "is `Bash(npm publish)` live now", and the answer must survive being asked in a different
 * spelling than the file happens to use, so the text is parsed and re-serialised the way the loader
 * serialises it: `Bash`, `Bash()` and `Bash(*)` are three spellings of one tool-wide rule and must not read
 * as three near-misses.
 */
export function policyCarries(
	rules: readonly PermissionRule[],
	rule: string,
	behavior: PermissionBehavior = "allow",
): PermissionRule | undefined {
	const wanted = `${behavior} ${permissionRuleValueToString(permissionRuleValueFromString(rule))}`
	return rules.find((candidate) => ruleLabel(candidate) === wanted)
}

/** Why a file gave us nothing, phrased for a user rather than for a log. */
function describeFailure(err: unknown): string {
	if (err instanceof SyntaxError) return "it is not valid JSON"
	const code = (err as { code?: unknown } | null)?.code
	if (typeof code === "string") return code === "ENOENT" ? "it vanished while being read" : code
	const name = (err as { name?: unknown } | null)?.name
	return typeof name === "string" ? name : "it could not be read"
}

/**
 * What a parsed JSON document has to say about permissions.
 *
 * Tolerant about shape in the same three ways the loader is — a `permissions` block, or the three lists at
 * the top level, or a config that simply never mentions permissions — and intolerant in exactly one new
 * place, which is the whole reason this face does its own reading: a document that is not shaped like a
 * rules document at all is reported, not read as "no rules". `silent` matters as much as `unreadable`: the
 * user-level config is a real config file and most of them contain no `permissions` block, so reporting
 * that as a failure would cry wolf on every healthy machine.
 */
type DocumentRead =
	| { kind: "lists"; bag: Record<string, unknown> }
	| { kind: "silent" }
	| { kind: "unreadable"; why: string }

function readDocument(doc: unknown): DocumentRead {
	if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
		return { kind: "unreadable", why: "it is not a document with allow / ask / deny lists" }
	}
	const root = doc as Record<string, unknown>
	const nested = root.permissions
	if (nested && typeof nested === "object" && !Array.isArray(nested)) {
		return { kind: "lists", bag: nested as Record<string, unknown> }
	}
	for (const behavior of BEHAVIOURS) {
		if (root[behavior] !== undefined) return { kind: "lists", bag: root }
	}
	return { kind: "silent" }
}

function readOneFile(file: string, source: PermissionRuleSource): RuleSourceRead {
	const nothing = { source, file, ok: true, rules: [] as PermissionRule[], ignored: 0, answeredNothing: true }
	let raw: string
	try {
		if (!existsSync(file)) return nothing
		raw = readFileSync(file, "utf-8")
	} catch (err) {
		return { source, file, ok: false, problem: describeFailure(err), rules: [], ignored: 0, answeredNothing: false }
	}
	if (!raw.trim()) return nothing

	let doc: unknown
	try {
		doc = JSON.parse(raw)
	} catch (err) {
		return { source, file, ok: false, problem: describeFailure(err), rules: [], ignored: 0, answeredNothing: false }
	}
	const document = readDocument(doc)
	if (document.kind === "unreadable") {
		return { source, file, ok: false, problem: document.why, rules: [], ignored: 0, answeredNothing: false }
	}
	if (document.kind === "silent") return nothing
	const bag = document.bag

	const lists: PermissionsConfig = {}
	let ignored = 0
	for (const behavior of BEHAVIOURS) {
		const list = bag[behavior]
		if (list === undefined) continue
		if (!Array.isArray(list)) {
			return {
				source,
				file,
				ok: false,
				problem: `its ${behavior} list is not a list`,
				rules: [],
				ignored: 0,
				answeredNothing: false,
			}
		}
		const usable = list.filter((entry) => typeof entry === "string" && entry.trim() !== "") as string[]
		ignored += list.length - usable.length
		if (usable.length > 0) lists[behavior] = usable
	}
	const rules = rulesFromPermissionsConfig(lists, source)
	return { source, file, ok: true, rules, ignored, answeredNothing: rules.length === 0 }
}

function sourceFile(source: PermissionRuleSource, cwd: string, globalFile?: string): string {
	if (source === "global") return globalFile ?? getConfigPath()
	// One call site for both project files — the same face `addPermissionRule()` writes through, so what
	// this reads is what a confirm just wrote, in the same directory the gate reads.
	return getProjectPermissionsPath(cwd, source === "local")
}

/**
 * Read the three rules files again and produce the snapshot to install.
 *
 * Reads only: no file is written, created or deleted, and the array handed in is left alone. Two
 * guarantees, both checked by `reload-policy.test.ts` at the matcher's face rather than on this return
 * value: an entry that refuses something survives a reload that cannot see it any more, and an entry that
 * only ever allowed something follows the file — in immediately, out immediately.
 */
export function reloadPermissionPolicy(opts: ReloadOptions): PolicyReload {
	const reads = SOURCES.map((source) => readOneFile(sourceFile(source, opts.cwd, opts.globalFile), source))

	const unreadable: string[] = []
	const installed: PermissionRule[] = []
	for (const read of reads) {
		if (read.ok) {
			installed.push(...read.rules)
			continue
		}
		unreadable.push(`${read.file} — ${read.problem}`)
		// Last-known-good, per source. The other two files still speak, so a broken `permissions.local.json`
		// cannot empty the project's or the user's rules along with it.
		installed.push(...opts.live.filter((rule) => rule.source === read.source))
	}

	const fromDisk = mergePermissionRules(installed)
	const seen = new Set(fromDisk.map(ruleLabel))
	// The asymmetry the header argues for: an allow the files dropped is gone; a refusal the files dropped
	// is held back. `fromDisk` can therefore never be the place a deny disappears.
	const heldBack = opts.live.filter((rule) => rule.behavior !== "allow" && !seen.has(ruleLabel(rule)))
	const rules = mergePermissionRules(heldBack, fromDisk)

	const before = new Set(opts.live.map(ruleLabel))
	const after = new Set(rules.map(ruleLabel))
	const added = rules.filter((rule) => !before.has(ruleLabel(rule))).map(ruleLabel)
	const dropped = opts.live.filter((rule) => !after.has(ruleLabel(rule))).map(ruleLabel)

	return {
		rules,
		sources: reads,
		added,
		dropped,
		heldBack: heldBack.map(ruleLabel),
		unreadable,
		changed: added.length > 0 || dropped.length > 0,
	}
}

/** One line a caller can print after installing a reload. Facts only, never "adopted". */
export function summariseReload(reload: PolicyReload): string {
	const parts: string[] = [
		reload.changed
			? `${reload.added.length} rule(s) new in this session's policy`
			: "no change to this session's policy",
	]
	if (reload.dropped.length > 0) parts.push(`${reload.dropped.length} allowance(s) the files no longer grant`)
	if (reload.heldBack.length > 0) {
		parts.push(`${reload.heldBack.length} deny/ask rule(s) still honoured — a re-read does not lift a wall`)
	}
	if (reload.unreadable.length > 0) {
		parts.push(`${reload.unreadable.length} rules file(s) unreadable and left exactly as they were`)
	}
	return parts.join(" · ")
}
