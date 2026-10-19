/**
 * The confirmation half of `/grants adopt`.
 *
 * `adoptOrphans()` (grants-adopt.ts) takes an orphan's deny/ask rules quietly and hands everything
 * widening back as `pending: Candidate[]`. `/grants adopt` prints those as `? <value>` and stops, so
 * today a user who *wants* one of them has no route except hand-editing a rules file or a journal —
 * which is authority obtained by bypassing the very UI that is supposed to record it. This module is
 * the missing route: render `pending` as items a person can pick, then apply exactly the picked ones
 * through `confirmAdoption()`.
 *
 * It holds no policy of its own. What counts as widening, which file a rule belongs in, what a
 * revocation vetoes, how a row is added — all of that stays in grants-adopt.ts / session-grants.ts,
 * and every write here goes through them. What lives here is the human half: identity, selection, and
 * the fail-safe direction.
 *
 * ------------------------------------------------------------ why a choice is aimed at by id, not by row
 * `/grants revoke` refuses index targeting because the list is re-rendered from two stores in an order
 * that shifts as rows are promoted — a stale index then deletes the wrong entry. An adopt has the same
 * shape with a worse consequence: a stale index *grants* the wrong thing, silently, and nothing errors.
 * So each choice carries an id built from its canonical value (`grant-verify.canonicalPath`), the id
 * survives a re-render, a re-sort, and a re-scan, and it is copyable off the screen the way a
 * `/grants` value is. A row number is not just unsupported, it is named back to the user as a mistake —
 * an unanswered "3" is one prompt away from confusion, where a wrong write is forever.
 *
 * ------------------------------------------------------------- why the id is built on canonical paths
 * An orphan's rows are spelled in the old checkout's language (`./src/x`, `~/x`, absolute), and a row
 * confirmed here is stored resolved into THIS project's path space. Building the id from the canonical
 * value means the two spellings of one file fold into one decision — and the human sees the path that
 * will actually be stored, not the one a moved directory left behind.
 *
 * --------------------------------------------------------------- the fail-safe: no list, no write
 * An adoption is the one place in this subsystem where a bug could grant instead of deny. So the
 * confirm face takes the selection as an explicit list and treats "missing", null, blank and empty
 * identically: nothing is called at all. Not `confirmAdoption`, not a journal merge, not a rules file.
 * A blanket "confirm everything" is refused for the same reason in reverse — one decision per item is
 * the whole point, and "all" is what an injected line in a transcript would ask for.
 */

import { homedir } from "node:os"

import {
	confirmAdoption,
	type Candidate,
	type ConfirmationReport,
	type GrantCandidate,
	type RuleCandidate,
} from "./grants-adopt.ts"
import { canonicalPath, type PathSpace } from "./grant-verify.ts"
import type { PermissionRuleDestination } from "./permissions-loader.ts"
import type { PermissionBehavior } from "./permissions.ts"
import type { GrantStore } from "./session-grants.ts"

/** Something offered for a decision, aimed at by `id`. */
export type AdoptGrantChoice = {
	kind: "grant"
	/** Copyable handle derived from the canonical value: `grant:<category>:<kind>:<target>`. */
	id: string
	category: string
	scope: "entity" | "scope"
	/** What the row will store — `canonicalPath(value)`, so `./x` here is the absolute path there. */
	target: string
	/** How the orphan spelled it, so the render can show the old spelling beside the resolved one. */
	sourceSpelling: string
	/** That journal row was an "always", so a confirmed row may be durable too. */
	durableInSource: boolean
	/** One line for a picker or a log: what confirming this actually unlocks. */
	label: string
	/** Where it came from, and anything about it the picker cannot show any other way. */
	detail: string
	/** Every orphan file that carried a spelling of this target. */
	origins: string[]
	/** Handed to `confirmAdoption()` (with `value` canonicalised) if the human picks it. */
	item: GrantCandidate
}

/** A pending allow rule, aimed at by `id`. */
export type AdoptRuleChoice = {
	kind: "rule"
	/** `rule:<rule text>`. */
	id: string
	rule: string
	behavior: PermissionBehavior
	/** Which live rules file it lands in — an orphan's `permissions.local.json` stays local. */
	into: PermissionRuleDestination
	label: string
	detail: string
	origins: string[]
	item: RuleCandidate
}

export type AdoptChoice = AdoptGrantChoice | AdoptRuleChoice

/** A refusal with the reason the human will be shown. Never thrown, never swallowed. */
export type AdoptionRefusal = { what: string; reason: string }

/** The path space the ids are built in. Same three inputs the confirm face takes. */
export type AdoptSpace = { cwd?: string; project?: string; home?: string }

export type ResolveAdoptOptions = {
	choices: readonly AdoptChoice[]
	/** Whatever the human typed or picked, one entry per item. Order is irrelevant. */
	ids: readonly string[]
	/** The space the ids were built in; pass the same one `buildAdoptChoices()` got. */
	space?: PathSpace
}

export type ConfirmAdoptOptions = {
	cwd: string
	/** The live session store. Rows go in through `confirmAdoption()` → `addGrant()`, so this store's
	 *  dedup, caps and tombstones apply to an adopted row exactly as to a prompt-earned one. */
	store: GrantStore
	/** The ids the human named. Omitted, null, blank or empty means confirm NOTHING — see the header. */
	ids?: readonly string[] | null
	/** Give either the choices you rendered (so the ids are guaranteed to be the ones on screen)… */
	choices?: readonly AdoptChoice[]
	/** …or the `pending` list they came from, and they are rebuilt here. `choices` wins if both. */
	pending?: readonly Candidate[]
	project?: string
	home?: string
	/** Live journal to mirror into. Ignored when `durable` is false: a session-only choice has
	 *  nothing to persist, and writing it anyway is how "this session only" becomes permanent. */
	journal?: string
	/** Default true, matching `confirmAdoption()`. False = try it for this session, write no file. */
	durable?: boolean
}

export type ConfirmAdoptResult = {
	/** The choices the ids resolved to — exactly what was applied, in nothing's order but theirs. */
	picked: AdoptChoice[]
	/** Selection refusals first (unknown id, ambiguous, blanket, nothing named), then every refusal
	 *  `confirmAdoption()` made. A caller that prints only `report` loses these. */
	refused: AdoptionRefusal[]
	/** Verbatim from `confirmAdoption()` — empty when nothing was picked. */
	report: ConfirmationReport
	/** Set when a journal was offered and deliberately left alone. */
	journalSkipped?: string
	/** Set when the journal write carried more than this confirmation chose.
	 *  `confirmAdoption()` mirrors the WHOLE store into the journal, so a session-only row the gate
	 *  put there earlier is persisted by an unrelated durable adopt. Nothing here can stop that
	 *  without inventing a second merge policy, so it is reported instead — a caller that tells the
	 *  user "saved for this project" after seeing `report.journal.ok` would be understating what
	 *  landed. */
	journalCarried?: string
}

const NOTHING_NAMED =
	"no id was given — an adoption is never confirmed by default, so nothing was written"
const BLANKET_IDS = new Set(["*", "**", "all", "any", "everything", "*:*"])
const ROW_NUMBER = /^\d+$/

function pathSpace(opts: AdoptSpace): PathSpace {
	return { home: opts.home ?? homedir(), project: opts.project ?? opts.cwd }
}

function originOf(item: Candidate): string {
	return `${item.origin.id}/${item.origin.file}`
}

/** Fold one id out of the parts that make this candidate itself, canonical value included. */
function makeId(parts: readonly string[]): string {
	return parts.join(":").trim().toLowerCase()
}

/**
 * The stable handle for one candidate.
 *
 * Derived from what the candidate IS — category, kind and canonical target for a row; rule text for a
 * rule — so the same item gets the same id from any scan, in any order, in any checkout. Lower-cased
 * because a human retyping it should not have to match our casing; the value stored is the candidate's
 * own, never the typed string, so casing here is a convenience and not an authority.
 */
export function adoptChoiceId(item: Candidate, space?: PathSpace): string {
	return item.kind === "rule"
		? makeId(["rule", item.rule])
		: makeId(["grant", item.category, item.scope, canonicalPath(item.value, space)])
}

function describe(choice: AdoptChoice): string {
	const where = choice.origins.join(", ")
	if (choice.kind === "rule") {
		return `writes an allow into the ${choice.into} rules file · from ${where}`
	}
	const notes = [`from ${where}`]
	if (choice.origins.length > 1) notes.push(`${choice.origins.length} spellings of one target`)
	if (choice.sourceSpelling !== choice.target) notes.push(`stored as ${choice.target}`)
	if (choice.durableInSource) notes.push("the orphan had it as an always")
	return notes.join(" · ")
}

/** One pending journal row, in the shape a human reads. `detail` is filled in after folding. */
function grantChoice(id: string, item: GrantCandidate, space: PathSpace): AdoptGrantChoice {
	const target = canonicalPath(item.value, space)
	return {
		kind: "grant",
		id,
		category: item.category,
		scope: item.scope,
		target,
		sourceSpelling: item.value,
		durableInSource: item.durable,
		label: `${item.category} ${item.scope} ${target}`,
		detail: "",
		origins: [originOf(item)],
		item,
	}
}

/** One pending allow rule. The text is a specifier, so it is never canonicalised. */
function ruleChoice(id: string, item: RuleCandidate): AdoptRuleChoice {
	return {
		kind: "rule",
		id,
		rule: item.rule,
		behavior: item.behavior,
		into: item.into,
		label: `allow ${item.rule}`,
		detail: "",
		origins: [originOf(item)],
		item,
	}
}

/**
 * Turn `pending` into decidable items, one per distinct canonical target.
 *
 * Reads only. Two candidates whose canonical identity is the same fold into one item — one decision,
 * one write — and both origins are kept on it. Folding cannot grant more than listing both would,
 * because the store downstream dedups case-insensitively: once one spelling is held, confirming the
 * other is refused as "already holds a row". So the twin was never reachable through a second click
 * anyway; hiding it is the honest render, not a narrowing.
 */
export function buildAdoptChoices(
	pending: readonly Candidate[],
	opts: AdoptSpace = {},
): AdoptChoice[] {
	const space = pathSpace(opts)
	const built: AdoptChoice[] = []
	const slotOf = new Map<string, number>()

	for (const item of pending) {
		const id = adoptChoiceId(item, space)
		const slot = slotOf.get(id)
		const held = slot === undefined ? undefined : built[slot]
		if (held) {
			const from = originOf(item)
			if (!held.origins.includes(from)) held.origins.push(from)
			continue
		}
		slotOf.set(id, built.length)
		built.push(item.kind === "rule" ? ruleChoice(id, item) : grantChoice(id, item, space))
	}
	for (const choice of built) choice.detail = describe(choice)
	return built
}

/** The lines a human decides from, id last so it is the thing they copy. */
export function renderAdoptChoices(choices: readonly AdoptChoice[]): string[] {
	return choices.map((c) => `  ${c.label}  [${c.detail}]  id=${c.id}`)
}

/** Does this typed string name this choice — by id, by its printed label, or by its value? */
function names(choice: AdoptChoice, text: string, space: PathSpace): boolean {
	if (choice.id === text) return true
	if (choice.label.toLowerCase() === text) return true
	if (choice.kind === "rule") return choice.rule.trim().toLowerCase() === text
	if (!choice.target) return false
	return canonicalPath(text, space).toLowerCase() === choice.target.toLowerCase()
}

/**
 * Point each named id at the choice it means.
 *
 * Never by position. A typed string is matched against the id first, then against what the item was
 * printed as, then — for a row — against its canonical value, so a user who copied the value out of the
 * old `? <value>` line still lands on the right item. Every tier is checked and the union decides: one
 * hit picks, no hit reports `unknown id`, more than one reports ambiguity rather than choosing. A
 * bare row number is answered with the reason it cannot work, and `*` / `all` is refused — this face
 * exists to record one deliberate decision per widening item.
 */
export function resolveAdoptSelection(
	opts: ResolveAdoptOptions,
): { picked: AdoptChoice[]; refused: AdoptionRefusal[] } {
	const space = opts.space ?? {}
	const picked: AdoptChoice[] = []
	const refused: AdoptionRefusal[] = []
	const taken = new Set<string>()

	for (const raw of opts.ids) {
		const text = String(raw ?? "").trim()
		const key = text.toLowerCase()
		if (!key) {
			refused.push({ what: "(blank)", reason: "an empty id names no item" })
			continue
		}
		if (BLANKET_IDS.has(key)) {
			refused.push({
				what: text,
				reason: "a blanket confirm is not offered — one id per item, taken from the list",
			})
			continue
		}
		if (ROW_NUMBER.test(key)) {
			refused.push({
				what: text,
				reason:
					"that is a row number, and this list re-renders in a shifting order — confirm the copyable id (id=…) instead",
			})
			continue
		}

		// Every comparison is against the normalised form: an id copied off the screen and one retyped
		// in the wrong case must reach the same item, and the item's own value — not the typed string —
		// is what gets stored, so relaxing the case here cannot relax what is granted.
		const hits = opts.choices.filter((choice) => names(choice, key, space))
		if (hits.length === 0) {
			refused.push({
				what: text,
				reason: "no pending item matches this id — re-run /grants adopt and copy the id=… value",
			})
			continue
		}
		if (hits.length > 1) {
			refused.push({
				what: text,
				reason: `matches ${hits.length} pending items (${hits.map((h) => h.id).join(", ")}) — name one of them exactly`,
			})
			continue
		}

		const choice = hits[0]!
		if (taken.has(choice.id)) continue
		taken.add(choice.id)
		picked.push(choice)
	}
	return { picked, refused }
}

/** The candidate as it should reach `confirmAdoption()`: path value already canonicalised. */
function selectedItem(choice: AdoptChoice): Candidate {
	return choice.kind === "grant" ? { ...choice.item, value: choice.target } : choice.item
}

/**
 * Apply exactly the items a human named, and report the rest.
 *
 * Three things this will not do:
 *  - confirm anything when no id was named (no call at all — no row, no rules file, no journal);
 *  - resolve an id by position, or guess between two items one string could mean;
 *  - persist a session-only choice (`durable: false` skips the journal entirely).
 *
 * Everything that is written goes through `confirmAdoption()` with the caller's own project root, so
 * the canonical path the id was built on is the canonical path stored, and each row arrives by
 * `addGrant()` — which means the store's own dedup and its revocation screens screen an adopted row
 * just as they screen one earned at a prompt. Refusals are returned, never logged-and-dropped: a caller
 * that shows `report.grants` without `refused` would be reporting a partial success as a full one.
 */
export function confirmAdoptChoices(opts: ConfirmAdoptOptions): ConfirmAdoptResult {
	const space = pathSpace(opts)
	const untouched: ConfirmationReport = { rules: [], grants: [], refused: [] }
	const named = (opts.ids ?? []).filter((v) => typeof v === "string" && v.trim() !== "")
	if (named.length === 0) {
		return { picked: [], refused: [{ what: "(nothing selected)", reason: NOTHING_NAMED }], report: untouched }
	}

	const choices = opts.choices ?? buildAdoptChoices(opts.pending ?? [], opts)
	const { picked, refused } = resolveAdoptSelection({ choices, ids: named, space })
	if (picked.length === 0) {
		return { picked: [], refused, report: untouched }
	}

	const durable = opts.durable ?? true
	const journal = durable ? opts.journal : undefined
	const report = confirmAdoption({
		cwd: opts.cwd,
		items: picked.map(selectedItem),
		store: opts.store,
		...(opts.project !== undefined ? { project: opts.project } : {}),
		...(opts.home !== undefined ? { home: opts.home } : {}),
		...(journal !== undefined ? { journal } : {}),
		durable,
	})

	const sessionOnly = opts.store.grants.filter((row) => row.durable !== true).length
	return {
		picked,
		refused: [...refused, ...report.refused],
		report,
		...(!durable && opts.journal !== undefined
			? {
					journalSkipped:
						"durable: false — this session only, so the journal was not written",
				}
			: {}),
		...(durable && report.journal?.ok && sessionOnly > 0
			? {
					journalCarried: `${sessionOnly} session-only row(s) were already in the store and the merge carries them into the journal too`,
				}
			: {}),
	}
}
