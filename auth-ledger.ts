/**
 * Authorisation ledger (proper-permission-ledger.md §2): compact per-session
 * state of what the user granted or withdrew, folded from per-message
 * extraction (model-client task C). Fixes window amnesia — authorisation is
 * no longer a function of scroll position.
 *
 * Fold semantics: grants and forbids are deduped per (category, value, kind);
 * cross-type precedence is decided by `seq` AT MATCH TIME (a grant covers a
 * target only if no matching forbid has a higher seq). Insertion never
 * removes a broader entry because of a narrower later one (a "revoke all"
 * must keep blocking targets a later grant did not re-grant), so the folded
 * state is independent of processing order — which is what makes newest-first
 * background backfill safe to use while incomplete (§2.6).
 *
 * Revocations are a third thing in this file beside grants and forbids: a row in
 * `ledger.revoked` says "this grant was taken back at this time", the only form a
 * revocation can take if another session is ever to see it. `revokeLedgerGrants`
 * writes them, `deserializeLedger` honours them, `grants-file.ts` persists them, and
 * `applyEvent` refuses to re-add a key one of them names — which is what stops a
 * backfill re-extraction from walking a revoked grant back in.
 */

import type { Entity } from "./risk-policy.ts"
import {
	BARE_VERB_CATEGORIES,
	METHOD_VERB_REQUIRED,
	canonicalPath,
	entityMatchesTarget,
	expandHome,
	targetNamedByUser,
} from "./grant-verify.ts"
import {
	asBackgroundRevocations,
	foldRevocations,
	localRevocationKeys,
	partitionRevoked,
	rowIdentity,
	type GrantRevocation,
} from "./session-grants.ts"

export type LedgerEntry = {
	/** Gate category the grant/forbid maps to; "*" = all categories (revocations);
	 *  "*<free text>*" = unmappable action, never matches (targeted fallback only). */
	category: string
	/** Normalized target, scope prefix ending in "/", or "*" for bare-verb/all. */
	value: string
	kind: "entity" | "scope"
	/** Verbatim user sentence (verified against the source message). */
	quote: string
	messageId: string
	/** Ordinal of the source message on the branch — decides precedence. */
	seq: number
	/** Row came from a grants file, not from a message on this branch. Such rows
	 *  carry `seq: 0` (background authority) and no `messageId`, so a rewind here
	 *  does not retract them and the restore filter does not drop them. */
	origin?: "imported"
	/** The verified quote contained secret-shaped material. Set explicitly on re-derivation so a newer sentence
	 *  that drops the inclusion cannot inherit it from an older duplicate row. Declared here because the field is
	 *  written (`addLedgerEntry`) and read by `model-client.ts` / eval tooling; it was simply missing from the type. */
	includesSecrets?: boolean
	/** Precedence/value the row had in its source session, kept for audit. */
	sourceSeq?: number
	sourceMessageId?: string
	lastMatchedAt?: number
	/** Wall-clock ms of the moment this session last heard the sentence that earned
	 *  the row. `seq` orders rows inside ONE transcript and means nothing across
	 *  sessions; `at` is the single clock two sessions share, which makes it the clock
	 *  a revocation is compared against (see `GrantRevocation` and `grants-file.ts`).
	 *  Absent means "written before revocations existed", which reads as the oldest
	 *  thing on disk — so a revocation vetoes it rather than the reverse. */
	at?: number
}

export type Ledger = {
	grants: LedgerEntry[]
	forbids: LedgerEntry[]
	/** Message ids already extracted (or deliberately skipped: beyond backfill cap). */
	seen: Set<string>
	/** Read-only posture from a blanket "don't change anything" (§ readonly-posture-plan).
	 *  When active, ask/unknown *mutations* are refused (allow-tier project/temp work
	 *  still proceeds). Tracked as two max-seq scalars so the fold is order-independent
	 *  and a later "you can make changes now" (higher seq) re-enables. */
	readOnlyOn?: { seq: number; quote: string }
	readOnlyOffSeq?: number
	/** Revocations kept as rows: `{category, value, kind, at}` taken away from grant
	 *  rows this ledger no longer holds. Needed because a merge can only add — without
	 *  a row saying "this was taken back", a journal that unions two sessions either
	 *  keeps authority nobody can revoke or deletes additions nobody meant to delete.
	 *  Exact-key only, and deliberately NOT a forbid: a forbid outrules a grant at match
	 *  time across a family of categories and is lifted by the next sentence, a
	 *  revocation only erases rows earned at or before it — one category, one target. */
	revoked?: GrantRevocation[]
	/** The same row shape, aimed at the FORBID list: `{category,value,kind}` the user took back
	 *  out of `ledger.forbids` (today that means `/grants revoke <value>`).
	 *
	 *  A SEPARATE list rather than more rows in `revoked`, and the reason is the identity
	 *  function: `rowIdentity` is category+value+kind with nothing in it saying which list the
	 *  row came from, so one shared list cannot tell "take back the ban on /x" apart from "take
	 *  back the grant on /x". Sharing it would let revoking a forbid delete a grant of the same
	 *  key (`partitionRevoked`) and stop a re-derived grant from ever landing (`applyEvent`) —
	 *  cancelling a DENY would silently remove an ALLOW. Two lists, picked by the event's own
	 *  type at the one door rows enter through. */
	revokedForbids?: ForbidRevocation[]
}

export type ExtractedEvent = {
	/** grant/forbid carry category+value+kind; readonly-on/off use them as "*". */
	type: "grant" | "forbid" | "readonly-on" | "readonly-off"
	category: string
	value: string
	kind: "entity" | "scope"
	quote: string
	messageId: string
	seq: number
	/** See LedgerEntry.includesSecrets. */
	includesSecrets?: boolean
}

/** A "user" message the transcript tool wrote on the user's behalf, not words the user typed.
 *  Claude Code records `[Request interrupted by user for tool use]` when Esc is pressed mid-call;
 *  read as speech it is an unmappable blanket "stop" and arms the read-only posture for the rest of
 *  the session (measured: 28 of 60 corpus over-blocks). Such a line authorises and forbids nothing. */
export const SYNTHETIC_USER_TURN_RE = /^\s*\[request interrupted by user(?: for tool use)?\]\s*$/i

export function isSyntheticUserTurn(text: string): boolean {
	return SYNTHETIC_USER_TURN_RE.test(text)
}

/** Is the read-only posture in force right now? (latest on beats latest off.) */
export function readOnlyActive(ledger: Ledger): { quote: string; seq: number } | null {
	const on = ledger.readOnlyOn
	if (!on) return null
	if ((ledger.readOnlyOffSeq ?? -1) >= on.seq) return null
	return on
}

/** Under read-only, does a ledger grant made AFTER the posture (seq > roSeq) cover
 *  ALL pending targets? Such a later grant re-permits that specific target
 *  ("don't change anything" … later … "you can write to /x/"). A targetless
 *  mutation cannot be lifted this way — only a blanket re-enable clears it. */
export function readOnlyLiftedByGrant(
	ledger: Ledger,
	category: string,
	entities: Entity[],
	roSeq: number,
	home?: string,
	project?: string,
): boolean {
	const primary = category.split("+")[0] ?? category
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	if (targets.length === 0) return false
	// ANY delete segment arms the verb gate — never just the first-listed one.
	const needDeleteVerb = compoundHas(category, DELETE_CATEGORIES)
	return targets.every((t) =>
		ledger.grants.some(
			(g) =>
				g.seq > roSeq &&
				valueCovers(g, t, home, project) &&
				grantMatchesPending(g, primary, t, home, project) &&
				(!needDeleteVerb || DELETE_VERB_RE.test(g.quote)),
		)
	)
}

/** Path-mutating categories. Reads are deliberately absent: "you can read
 *  /etc/passwd" must never authorise writing it. */
const FS_MUTATION_CATEGORIES = new Set([
	"write_outside",
	"write_project",
	"write_sensitive",
	"system_config",
	"perm_change",
	"delete_outside",
	"delete_recursive",
	"delete_data",
])

/**
 * The subset of mutation categories where READING is genuinely entailed: the user said the
 * agent may create or edit content here, and you cannot edit what you cannot open.
 *
 * Deliberately narrower than FS_MUTATION_CATEGORIES. `delete_*` is excluded because "you may
 * delete /w" does not say anything about reading /w — deletion is not a read capability in
 * disguise. `system_config` and `perm_change` are excluded because they authorize service or
 * metadata changes, not content access. `write_sensitive` IS included (you are editing those
 * files) but note it still cannot reach `read_secret`, which is what keeps credentials behind
 * their own gate regardless of what may be written to the folder.
 */
const FS_WRITE_CATEGORIES = new Set(["write_outside", "write_project", "write_sensitive"])

/** Does a grant entry authorise this pending category, for this pending target?
 *
 *  Group equality as usual, PLUS a target-first widening: a grant that NAMES the
 *  exact path authorises any path-mutating category on that path. Without it an
 *  explicit per-file permission dies on the group boundary — "write to
 *  /usr/bin/foo" extracts as write_outside (fs-write) while the write itself
 *  classifies as write_sensitive (secret), because /usr/bin is a sensitive
 *  prefix, and the two never met. Scopes and wildcards are NOT widened: naming
 *  one file is not permission for a whole tree. */
function grantMatchesPending(
	g: LedgerEntry,
	primary: string,
	target: string,
	home?: string,
	project?: string,
): boolean {
	if (grantAuthorises(g, primary)) return true
	if (
		g.kind === "entity" &&
		g.value !== "*" &&
		FS_MUTATION_CATEGORIES.has(g.category) &&
		FS_MUTATION_CATEGORIES.has(primary) &&
		// Privilege stays out of the naming-a-file widening. It exists to fix a group mismatch on
		// CONTENT mutation ("write to /usr/bin/foo" extracting as write_outside while the write
		// classifies as write_sensitive); it never meant "and you may chmod it".
		!PRIVILEGE_CATEGORIES.has(g.category) &&
		!PRIVILEGE_CATEGORIES.has(primary) &&
		valueCovers(g, target, home, project)
	)
		return true
	// WRITE IMPLIES READ. A file you may not open is not a file you may edit: "you can write
	// into /w" that still prompts for every read of /w is friction with no security content,
	// and the user's own wording ("write", "work in", "create files there") already contains
	// the read. Direction matters absolutely here — this is one-way. read_secret is NOT in
	// this list, and neither is anything delete-shaped: credentials stay behind their own
	// gate no matter what was written into the folder. Pinning both refusals is the point of
	// the matrix in directed-permissions.test.ts.
	if (primary === "read_only" && FS_WRITE_CATEGORIES.has(g.category) && valueCovers(g, target, home, project)) {
		return true
	}
	return false
}

export const MAX_GRANTS = 200
export const MAX_FORBIDS = 100

/**
 * Extraction diagnostics.
 *
 * When the model extracts an action our category table cannot name, the grant is
 * stored under a `*action*` pseudo-category - and `compatible()` treats only bare
 * `"*"` as a wildcard, so that label can never match a real pending category. The
 * grant is therefore recorded and authorises nothing: silent in effect.
 *
 * That is the failure mode worth counting, because it is indistinguishable from
 * "the user never granted it". Surfaced by /classifier-status.
 */
export const extractionStats = {
	mapped: 0,
	unmapped: 0,
	lastUnmapped: "",
	/** Categories that came from the model as an enum value — the schema-first path. */
	fromSchema: 0,
	/** Categories recovered by the English word list, i.e. the endpoint ignored the schema. */
	legacyWordList: 0,
	/** Grants the model marked as a location scope, so folder permissions registered. */
	scopes: 0,
	/** Grants the model marked as covering secrets. */
	secretInclusions: 0,
	/** Grant rows refused at the door because this session had already revoked that exact
	 *  key. A refusal is invisible by construction — no prompt, no grant — so without a
	 *  counter "the revoke held" and "the sentence was never extracted" are
	 *  indistinguishable from outside. */
	revocationBlocked: 0,
	/** Forbid rows stopped by the same wall, counted apart because the two kinds mean opposite
	 *  things: a grant that cannot come back is a permission the user took away, a forbid that
	 *  cannot come back is a ban the user cancelled. Summed into one counter, neither is legible. */
	forbidRevocationsBlocked: 0,
}

export function resetExtractionStats(): void {
	extractionStats.mapped = 0
	extractionStats.unmapped = 0
	extractionStats.lastUnmapped = ""
	extractionStats.fromSchema = 0
	extractionStats.legacyWordList = 0
	extractionStats.scopes = 0
	extractionStats.secretInclusions = 0
	extractionStats.revocationBlocked = 0
	extractionStats.forbidRevocationsBlocked = 0
}

export function createLedger(): Ledger {
	return { grants: [], forbids: [], seen: new Set(), revoked: [], revokedForbids: [] }
}

// ---------------------------------------------------------------- kind groups

/** Category → matching group (§2.4). Ledger matching compares groups, not exact
 *  categories, so a grant reaches the siblings inside its own group. What a group may NOT
 *  decide is direction - that is grantAuthorises' job, because "copy to /x/" covering mkdir
 *  follows from writing content, while covering chmod never did. */
const KIND_GROUPS: Record<string, string> = {
	write_outside: "fs-write",
	// Split from writes on purpose. One group for both meant a folder grant for either authorised
	// both, and the direction that mattered - "you may edit" buying "you may remove" - was decided
	// by adjacency rather than by anyone. The legitimate half is now a named one-way rule.
	delete_outside: "fs-delete",
	delete_recursive: "fs-delete",
	delete_data: "fs-delete",
	// Privilege is a different harm class from content: chmod decides who ELSE may read what the
	// user granted. Never implied by a write or a delete; it has to be named.
	perm_change: "fs-perm",
	package_system: "pkg",
	privilege: "priv",
	network_send: "net-send",
	vcs_remote: "vcs-remote",
	vcs_discard: "vcs-discard",
	cluster_mutation: "cluster",
	container_mutation: "cluster",
	db_mutation: "db",
	// write_project only reaches ledger matching via the named-forbid downgrade
	// (an allow-tier action the user explicitly forbade); grouping it with
	// fs-write lets a later "ok, you can delete X now" lift the forbid.
	write_project: "fs-write",
	remote_exec: "exec",
	agent_spawn: "exec",
	network_listen: "listen",
	// Split on purpose. Both used to be "secret", and `compatible()` is pure group
	// equality, so a grant to READ a secret path authorised WRITING it — and vice
	// versa — through the kind-group widening. Reading and mutating a secret-bearing
	// path are different permissions and must never be interchangeable, so they get
	// distinct groups and neither reaches the other. This is strictly tighter: it can
	// only cost an extra prompt, never grant a false allow.
	read_secret: "secret-read",
	write_sensitive: "secret-write",
	process_control: "proc",
	system_config: "sysconf",
	interactive_editor: "editor",
}

export function kindGroup(category: string): string {
	const primary = category.split("+")[0] ?? category
	return KIND_GROUPS[primary] ?? primary
}

function compatible(entryCategory: string, pendingCategory: string): boolean {
	if (entryCategory === "*") return true
	return kindGroup(entryCategory) === kindGroup(pendingCategory)
}

/**
 * Mutation groups, collapsed for ONE direction only: forbids.
 *
 * A revocation has to dominate everything the user's sentence could plausibly have covered, so
 * "stop touching /x" recorded against any single mutation category still blocks the others. Grants
 * are directed (grantAuthorises); forbids deliberately are not. That asymmetry is what keeps
 * 2514c8d - a forbid must be at least as wide as the grant it revokes - true after the split:
 * narrowing grants must never narrow a revocation along with them.
 */
const FORBID_FAMILIES: Record<string, string> = {
	"fs-write": "fs-mutation",
	"fs-delete": "fs-mutation",
	"fs-perm": "fs-mutation",
}

function forbidCompatible(entryCategory: string, pendingCategory: string): boolean {
	if (compatible(entryCategory, pendingCategory)) return true
	const a = FORBID_FAMILIES[kindGroup(entryCategory)] ?? kindGroup(entryCategory)
	const b = FORBID_FAMILIES[kindGroup(pendingCategory)] ?? kindGroup(pendingCategory)
	return a === b
}

/** Harm is privilege or persistence, not content. Naming one file to write it is not naming it to
 *  chmod it, so these never cross the target-first widening either. */
const PRIVILEGE_CATEGORIES = new Set([
	"perm_change",
	"perm_destroy",
	"privilege",
	"privilege_persist",
	"persistent_access",
])

/**
 * Does a stored grant authorise this pending category? Directed, and per segment.
 *
 * Per segment because a compound grant (`write_outside+perm_change`, from one approval of one
 * command) names exactly its own effects - which is what the coarse group used to fake, at the cost
 * of letting an unrelated category in through the same door. The coarse group is gone, so the
 * compound has to say so itself; that path is why the per-segment fix in session-grants.ts had to
 * land first.
 */
function grantAuthorises(g: LedgerEntry, pendingCategory: string): boolean {
	if (g.category === "*") return true
	const pending = kindGroup(pendingCategory)
	const segments = new Set(g.category.split("+").map((s) => kindGroup(s)))
	if (segments.has(pending)) return true
	// One-way, by name: a delete grant over a folder already permits destroying every byte inside
	// it, so writing there is not a new class of harm. The reverse is refused outright.
	if (pending === "fs-write" && segments.has("fs-delete")) return true
	// The recorded mv/rename trade-off, now expressed as a direction rather than a shared group:
	// destruction is reachable from a content grant only when the user's own words named it.
	// ledgerCovers arms the same verb gate for every delete-shaped pending, so this only ever
	// narrows relative to the old grouping.
	if (pending === "fs-delete" && segments.has("fs-write") && DELETE_VERB_RE.test(g.quote)) return true
	return false
}

const DELETE_CATEGORIES = new Set(["delete_recursive", "delete_outside", "delete_data"])

/** Categories whose pending action READS, and nothing else. Two uses, both about keeping a read
 *  from standing in for a mutation: a derived forbid that names only these must not bind an action
 *  that mutates (`namedForbidCovers`), and a sentence that named only these derives a row in these
 *  categories instead of a wide one (`namedTargetCategory`). The split is the one that keeps
 *  `read_secret` out of a folder write grant — reading a path and changing it have never been
 *  interchangeable in this file. */
const READ_CATEGORIES = new Set(["read_only", "read_secret"])

/**
 * A compound category (`write_outside+delete_outside`, from one command that both
 * moves and removes) carries EVERY effect of the segments that produced it, but the
 * join order is composition order, not severity.
 *
 * Reading `category.split("+")[0]` therefore makes a security decision depend on
 * which segment happened to be listed first: with a write primary the delete-verb
 * gate was skipped entirely, so one operand order demanded a delete-specific grant
 * and the other let a plain write grant authorise the delete. That fails OPEN.
 *
 * Two dual rules, both monotone:
 *  - `compoundHas` — requirements that only ever ADD a check: true if ANY segment
 *    is in the set. Strictly fewer grants can satisfy the pending action.
 *  - `compoundAll` — exemptions: true only if EVERY segment is exempt.
 *
 * Categories that SELECT an authority (kindGroup / session-grants / grant-verify)
 * must NOT use these: switching which stored grants match can loosen, and that path
 * needs per-segment coverage instead.
 */
export function compoundHas(category: string, set: Set<string>): boolean {
	return category.split("+").some((c) => set.has(c))
}

export function compoundAll(category: string, set: Set<string>): boolean {
	const parts = category.split("+")
	return parts.length > 0 && parts.every((c) => set.has(c))
}

/**
 * Verbs that make a user quote count as authorising a delete.
 *
 * `mv`/`move`/`rename` are here because a MOVE is what produces the
 * `delete_outside` half of `delete_outside+write_outside` (the source stops
 * existing at its old path). Without them a move could never satisfy the verb
 * gate its own category arms, so an approved `mv` re-prompted forever — the gap
 * was invisible while segment order decided whether the gate ran at all, and
 * became binding once that gate was made order-independent.
 *
 * `unlink|rmdir|trash|shred` were added after measuring usage (70/35/12/10 occurrences) and
 * because they are delete-ONLY words: unlike `move`, they cannot appear incidentally in a
 * quote that authorises something else, so they widen the gate with no English-word risk.
 *
 * This regex is tested against the user's OWN quoted words, not model text, so
 * recognising "move" for a move grants nothing nobody asked for; the grant's
 * target still has to cover the entity.
 */
const DELETE_VERB_RE = /\b(delete|remove|rm|clean|clear|wipe|prune|drop|erase|purge|mv|move|rename|unlink|rmdir|trash|shred)\b/i

// Why `mv|move|rename` belong in the delete-evidence set, and why that is not a bug to
// tighten: a move DESTROYS its source path. `mv /w/a /tmp` means /w/a is gone, so a user who
// authorises moving files into /w has authorised the disappearance of those paths. Four tests
// pin this (gate-move.test.ts, compound-category.test.ts, one titled "accepted trade-off").
// An earlier attempt here split a stricter DESTRUCTIVE_VERB_RE without read those tests first
// and broke four of them; the recorded trade-off wins, and this note exists so the next
// reader does not rediscover it as a hole.

// ---------------------------------------------------------------- action mapping

/**
 * The categories the grant-extraction schema offers the model as an enum, and the only
 * values a model-supplied category may take. Gate-internal states (`unproven_value`,
 * `unknown_command`, `interpreter_unknown`, …) are deliberately absent: they describe why
 * the analyzer stopped, not a capability a user can grant.
 *
 * `"other"` must exist because this schema runs in strict mode, where every property is
 * required — the model always needs an out, and "other" falls through to the legacy table
 * rather than inventing a category.
 */
export const GRANT_CATEGORY_VALUES = [
	"read_only",
	"read_secret",
	"write_project",
	"write_outside",
	"write_sensitive",
	"delete_outside",
	"delete_recursive",
	"delete_data",
	"wipe_protected",
	"history_wipe",
	"device_write",
	"disk_destroy",
	"system_config",
	"system_power",
	"system_destroy",
	"perm_change",
	"perm_destroy",
	"persistent_access",
	"privilege",
	"privilege_persist",
	"security_teardown",
	"process_control",
	"process_massacre",
	"package_system",
	"remote_exec",
	"network_listen",
	"network_send",
	"exfiltration",
	"vcs_remote",
	"vcs_local",
	"vcs_discard",
	"vcs_force_protected",
	"vcs_history_rewrite",
	"cluster_mutation",
	"cluster_wide_destroy",
	"container_mutation",
	"container_privileged",
	"container_wipe",
	"db_mutation",
	"db_destroy",
	"run_project_code",
	"agent_spawn",
	"interactive_editor",
	"other",
] as const

const GRANT_CATEGORY_SET: ReadonlySet<string> = new Set(GRANT_CATEGORY_VALUES)

/** Is `c` a category the gate can actually match a pending action against? */
export function isGrantCategory(c: string): boolean {
	return GRANT_CATEGORY_SET.has(c)
}

/**
 * LEGACY: free-text `action` → gate category. Ordered: domain nouns before generic verbs
 * ("delete the pod" is cluster, not fs).
 *
 * Not the authorisation path any more — the model names the category from
 * {@link GRANT_CATEGORY_VALUES} and that value wins. This table runs only for endpoints
 * that ignore the schema contract, and every use of it is counted, so a session quietly
 * riding on English word lists is visible instead of merely unlucky. Do not extend it: add
 * a value to the enum. It cannot express any language but English by construction.
 */
const ACTION_MAP: Array<[RegExp, string]> = [
	[/\b(kubectl|k8s|kubernetes|namespace|pod|deployment|statefulset|helm|cluster)\b/i, "cluster_mutation"],
	[/\b(docker|container|image)s?\b/i, "container_mutation"],
	[/\b(table|database|db|sql|schema|collection|redis)\b/i, "db_mutation"],
	[/\b(push|force-push|publish|release|pull request|\bpr\b)\b/i, "vcs_remote"],
	[/\b(discard|reset --hard|stash drop|revert)\b/i, "vcs_discard"],
	[/\b(install|uninstall|apt|apt-get|brew|dnf|yum|pacman|pip|npm|package)\b/i, "package_system"],
	[/\b(sudo|root|privilege|elevated)\b/i, "privilege"],
	[/\b(installer|curl.*\|.*(bash|sh)|download.*(run|execute)|remote script)\b/i, "remote_exec"],
	[/\b(serve|server|listen|listener|tunnel|expose|port)\b/i, "network_listen"],
	[/\b(upload|send|post|transfer|exfil)\b/i, "network_send"],
	[/\b(kill|restart|stop|terminate)\b/i, "process_control"],
	[/\b(systemctl|firewall|mount|sysctl|cron|service)\b/i, "system_config"],
	[/\b(ssh|remote host|connect)\b/i, "remote_exec"],
	[/\b(secret|credential|token|\.env|key|password)\b/i, "read_secret"],
	// PRIVILEGE takes an ACL VERB, and this row sits ABOVE the read row so the phrase can fire at
	// all: in English an ACL edit is "grant … access", and `access` is also a read verb, so one of
	// the two rows had to win by position and the specific phrase should.
	//
	// The bare NOUN used to live here (`permission`), and that one word is why "I do not want to use
	// ANY permission files" became `{category:"perm_change", value:"*"}`: the noun bought the
	// privilege category, the no-target fallback bought `value:"*"`, and the fs-mutation family fold
	// (D29, load-bearing for revocations) then blocked every write and recursive delete in the
	// workspace and quoted the user's own sentence back at them. A noun names a thing; only a verb
	// says what the user wants done to it. A sentence that names the noun instead gets the rule-file
	// target class below, which is what it actually talked about.
	[/\b(chmod|chown|chgrp|setfacl|chacl|cacls|icacls)\b|\b(?:grant|give|add|revoke|withdraw|remove|change|set)\w*\b[^.]{0,24}?\baccess\b/i, "perm_change"],
	// READS. These rows were absent, which is why "read files" produced an inert
	// `*read files*` label and a user's explicit folder permission registered nothing.
	// Ordered AFTER the secret row so "read secret files" still lands on read_secret.
	[/\b(read|view|open|list|browse|inspect|show|cat|access)\b/i, "read_only"],
	[/\b(delete|remove|rm\b|erase|wipe|clean|clear|purge)\b/i, "delete_outside"],
	[/\b(write|create|mkdir|copy|cp\b|move|mv\b|rsync|save|put|store|work in|extract)\b/i, "write_outside"],
]

export function mapActionToCategory(action: string): string | undefined {
	for (const [re, cat] of ACTION_MAP) if (re.test(action)) return cat
	return undefined
}

// ---------------------------------------------------------------- fold / insert

function normValue(v: string): string {
	return v.trim().toLowerCase().replace(/^["'`]+|["'`.,;:!?]+$/g, "")
}

function sameKey(a: LedgerEntry, b: ExtractedEvent | LedgerEntry): boolean {
	return a.category === b.category && normValue(a.value) === normValue(b.value) && a.kind === b.kind
}

/** Apply one extracted event under the seq-aware dedup rule. Same-key entries
 *  (in either list) keep only the highest seq; broader/partial overlaps are
 *  BOTH kept and resolved by seq at match time. */
export function applyEvent(ledger: Ledger, ev: ExtractedEvent): void {
	if (ev.type === "readonly-on") {
		if (!ledger.readOnlyOn || ev.seq > ledger.readOnlyOn.seq) {
			ledger.readOnlyOn = { seq: ev.seq, quote: ev.quote }
		}
		return
	}
	if (ev.type === "readonly-off") {
		ledger.readOnlyOffSeq = Math.max(ledger.readOnlyOffSeq ?? -1, ev.seq)
		return
	}
	if (!ev.value || !ev.category) return
	// A revocation said IN THIS SESSION is a wall every derivation path stops at, and it is
	// checked here rather than at the callers because there is exactly one door through
	// which a derived row enters the ledger: today that is the newest-first backfill drain
	// (`gate-bridge.syncLedger` → `applyEvents`) and the per-message extraction call, and
	// any future derivation inherits the rule by walking through this function. Without it,
	// `/grants revoke` removes the row and the next drain of the same message puts it back —
	// the worst kind of failed revocation, because the user cannot see it happen.
	//
	// Exact `{category, value, kind}`, the same narrow key a revocation has always used:
	// blocking a broader family here would be a new kind of authority, and revoking one file
	// must never fall over the folder grant sitting next to it.
	//
	// Two deliberate limits. (1) LOCAL revocations only — a tombstone that arrived from
	// a journal is background authority, and letting it veto what the user says in this
	// session would hand a stale file the power to block legitimate work permanently, which
	// is the rule `importLedger` already states for imported forbids. (2) Each side reads
	// only its own list: a revoked GRANT blocks that grant from being re-derived, a revoked
	// FORBID blocks that forbid from being re-derived, and neither reaches across. The grant
	// half is byte-for-byte what it was. The forbid half is new because the argument that
	// used to justify "grants only" — "refusing a forbid here would weaken a deny" — had a
	// premise that no longer holds: at the time there was no way at all to take a forbid back,
	// so any row that could stop one was a deny weakening nobody had asked for. A forbid
	// tombstone can now exist for exactly one reason, `revokeLedgerForbids` called in THIS
	// session, which is the user cancelling their own ban; letting the same sentence re-derive
	// it is the failed revocation this file already refuses to allow on the grant side.
	//
	// No timestamp comparison on this path, deliberately. A derived row's `at` is "now", so
	// comparing clocks here would let every re-derivation win and the guard would be
	// decoration; a stored `at` carries real recency only when the row was STORED with one
	// (see `restoreGrantRows`). A key revoked here stays revoked here for the rest of this
	// session's ledger; re-approving it is the prompt path's job (session grants), not the
	// ledger's.
	const tombstones = ev.type === "grant" ? ledger.revoked : ledger.revokedForbids
	if (localRevocationKeys(tombstones).has(rowIdentity(ev))) {
		if (ev.type === "grant") extractionStats.revocationBlocked++
		else extractionStats.forbidRevocationsBlocked++
		return
	}
	const mine = ev.type === "grant" ? ledger.grants : ledger.forbids
	const other = ev.type === "grant" ? ledger.forbids : ledger.grants

	// exact-key flip-flop against the opposite list: higher seq wins, O(1) per key
	const twinIdx = other.findIndex((e) => sameKey(e, ev))
	if (twinIdx >= 0) {
		if (other[twinIdx]!.seq >= ev.seq) return // newer contradiction already present
		other.splice(twinIdx, 1)
	}

	const dupIdx = mine.findIndex((e) => sameKey(e, ev))
	if (dupIdx >= 0) {
		if (mine[dupIdx]!.seq < ev.seq) {
			// Spread keeps fields not named here; includesSecrets is set explicitly so a
			// newer sentence that drops the inclusion does not inherit it from the older one.
			mine[dupIdx] = {
				...mine[dupIdx]!,
				quote: ev.quote,
				messageId: ev.messageId,
				seq: ev.seq,
				includesSecrets: ev.includesSecrets,
				// Re-earned, so re-dated: `at` answers "when did this row last come from the
				// user's own mouth", which is what a revocation is measured against.
				at: Date.now(),
			}
		}
		return
	}
	// Carries every field deliberately. This push used an explicit list that silently
	// dropped includesSecrets, so a secret-inclusion grant was parsed, stored and then
	// stripped of the one flag that made it valid — a defect invisible to every test
	// until one asserted on the stored entry rather than the returned event.
	mine.push({
		category: ev.category,
		value: ev.value,
		kind: ev.kind,
		quote: ev.quote,
		messageId: ev.messageId,
		seq: ev.seq,
		includesSecrets: ev.includesSecrets,
		at: Date.now(),
	})
	enforceCaps(ledger)
}

export function applyEvents(ledger: Ledger, events: ExtractedEvent[]): void {
	for (const ev of events) applyEvent(ledger, ev)
}

/** Eviction is fail-safe by construction: dropping a grant costs one extra
 *  prompt; forbids are evicted only from their own overflow, never for grants. */
function enforceCaps(ledger: Ledger): void {
	while (ledger.grants.length > MAX_GRANTS) {
		let worst = 0
		for (let i = 1; i < ledger.grants.length; i++) {
			const a = ledger.grants[i]!, b = ledger.grants[worst]!
			if ((a.lastMatchedAt ?? 0) < (b.lastMatchedAt ?? 0) ||
				((a.lastMatchedAt ?? 0) === (b.lastMatchedAt ?? 0) && a.seq < b.seq)) worst = i
		}
		ledger.grants.splice(worst, 1)
	}
	while (ledger.forbids.length > MAX_FORBIDS) {
		let worst = 0
		for (let i = 1; i < ledger.forbids.length; i++) {
			if (ledger.forbids[i]!.seq < ledger.forbids[worst]!.seq) worst = i
		}
		ledger.forbids.splice(worst, 1)
	}
}

// ---------------------------------------------------------------- matching

function valueCovers(entry: LedgerEntry, target: string, home?: string, project?: string): boolean {
	if (entry.value === "*") return true
	if (entry.kind === "scope") {
		// Canonicalise BOTH sides into ONE path space before comparing. Two renderings have to be
		// undone, not one: `displayPath` emits `~/dev/x` for home-external paths (fixed long ago by
		// `expandHome`) and `./dev/x` for in-project paths (fixed here, by `canonicalPath`). Before
		// this, an absolutely-worded scope covered `~/…` targets and silently missed every
		// project-internal one, which reads to the user as "my permission was ignored".
		// Component compare stays component-wise: `/dev/pm2/x` must never be covered by `/dev/pm/`.
		const space = { home, project }
		const s = canonicalPath(entry.value, space).toLowerCase().replace(/^\.\//, "")
		const t = canonicalPath(target, space).toLowerCase().replace(/^\.\//, "")
		if (s.endsWith("/") && (t.startsWith(s) || t + "/" === s)) return true
	}
	return entityMatchesTarget(target, entry.value, home, project)
}

/**
 * Named-forbid scan for ALLOW-tier actions ("do not delete X" must bind even
 * where the risk tables say allow). Considers "target" AND "path" entities
 * (allow segments mark touched files as kind "path"). Blanket forbids
 * (value "*", i.e. "stop doing risky things") are ignored here — they revoke
 * grants, they do not turn default-allowed project work into prompts. A grant
 * for the same value with a higher seq ("ok, you can delete it now") lifts
 * the forbid, category-agnostically: lifting only restores the default allow.
 *
 * `pendingCategory` narrows WHICH rows may bind, and it is optional in the strictest sense: when it
 * is absent this is exactly the scan it always was, so a caller that has not been updated cannot
 * silently loosen anything. When it IS given, a forbid that names only read categories stops binding
 * an action that is not read-shaped — which is not a nicety. An in-project write is ALLOW-tier, so
 * the block a user hit over "you will not fucking search in /home/u/dev" came through THIS scan
 * and not through `ledgerCovers`; a read-shaped row that still binds a write here reproduces the
 * defect while looking fixed. Every ambiguity is fail-closed: a compound pending category binds as
 * soon as ANY segment reads, and a forbid with any mutating segment binds always.
 */
export function namedForbidCovers(
	/** `null` = no ledger in this session, therefore no user-stated forbids to consult. Kept nullable rather than
	 *  asserted away: `gate.ts` legitimately runs before a ledger exists, and "no ledger" must not be papered over
	 *  with a non-null assertion. Rule-file and policy forbids are applied by the caller, not here. */
	ledger: Ledger | null,
	entities: Entity[],
	home?: string,
	project?: string,
	/** What the pending action classifies as, when the caller knows it — `policy.category` at both call sites. */
	pendingCategory?: string,
): { entity: string; entry: LedgerEntry } | null {
	if (!ledger) return null
	// A read-shaped forbid declines a pending action that is MUTATING ALL THE WAY DOWN, and binds
	// anything with a read in it. Both halves matter: `write_project` alone is a write the sentence
	// never spoke about, while `read_only+delete_data` contains the read the sentence DID forbid, so
	// a compound must not slip past it. `compoundHas` is the additive rule this file already uses for
	// exactly that — requirements that only ever add a check — and a caller that passes nothing keeps
	// every ban.
	const skipReadForbids = typeof pendingCategory === "string" && !compoundHas(pendingCategory, READ_CATEGORIES)
	const values = entities.filter((e) => e.kind === "target" || e.kind === "path").map((e) => e.value)
	for (const v of values) {
		let best: LedgerEntry | null = null
		for (const f of ledger.forbids) {
			if (f.value === "*") continue
			if (skipReadForbids && READ_CATEGORIES.has(f.category)) continue
			if (!valueCovers(f, v, home, project)) continue
			if (!best || f.seq > best.seq) best = f
		}
		if (!best) continue
		const lifted = ledger.grants.some((g) => g.seq > best!.seq && valueCovers(g, v, home, project))
		if (!lifted) return { entity: v, entry: best }
	}
	return null
}

export type LedgerVerdict = {
	covered: boolean
	/** A matching forbid outrules every matching grant — go straight to prompt,
	 *  do NOT let the recent-window fallback overrule an explicit revocation. */
	forbidden: boolean
	by: Array<{ entity: string; entry: LedgerEntry }>
	reason: string
}

/**
 * All target entities of the pending action must be covered by grant entries of
 * a compatible kind group, each with seq above any matching forbid. Verb gates:
 * METHOD_VERB_REQUIRED categories and (via kind-group widening) deletes require
 * the grant quote to carry the action verb.
 */
export function ledgerCovers(
	ledger: Ledger,
	category: string,
	entities: Entity[],
	home?: string,
	project?: string,
): LedgerVerdict {
	const primary = category.split("+")[0] ?? category
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const no: LedgerVerdict = { covered: false, forbidden: false, by: [], reason: "no matching ledger entry" }
	if (targets.length === 0) return no

	const needVerb = METHOD_VERB_REQUIRED.has(primary) ? BARE_VERB_CATEGORIES[primary] : undefined
	// ANY delete segment arms the verb gate. Order of `category` segments is
	// composition order, so keying this off `primary` let `write_outside+delete_*`
	// skip the delete requirement while `delete_*+write_outside` enforced it.
	const needDeleteVerb = compoundHas(category, DELETE_CATEGORIES)

	const by: LedgerVerdict["by"] = []
	for (const t of targets) {
		const forbidSeq = ledger.forbids
			.filter((f) => forbidCompatible(f.category, primary) && valueCovers(f, t, home, project))
			.reduce((m, f) => Math.max(m, f.seq), -1)
		const grant = ledger.grants.find((g) =>
			grantMatchesPending(g, primary, t, home, project) &&
			valueCovers(g, t, home, project) &&
			g.seq > forbidSeq &&
			(!needVerb || needVerb.test(g.quote)) &&
			(!needDeleteVerb || DELETE_VERB_RE.test(g.quote)),
		)
		if (!grant) {
			if (forbidSeq >= 0) {
				const f = ledger.forbids.find((x) => x.seq === forbidSeq && forbidCompatible(x.category, primary) && valueCovers(x, t, home))
				return { covered: false, forbidden: true, by: [], reason: `user forbade "${t}" ("${(f?.quote ?? "").slice(0, 80)}")` }
			}
			return no
		}
		by.push({ entity: t, entry: grant })
	}
	const now = Date.now()
	for (const m of by) m.entry.lastMatchedAt = now
	return { covered: true, forbidden: false, by, reason: `ledger: ${by.map((m) => `${m.entity}←"${m.entry.value}"`).join(", ")}` }
}

// ---------------------------------------------------------------- extraction → events

export type MessageGrantExtraction = {
	grants: Array<{
		action?: string
		/** Enum value from GRANT_CATEGORY_VALUES; authoritative when present. */
		category?: string
		/** entity = this target only; scope = everything under this location. */
		kind?: string
		includesSecrets?: boolean
		targets: string[]
		quote: string
	}>
	revocations: Array<{ action?: string; targets: string[]; all: boolean; quote: string }>
}

function quoteInMessage(quote: string, message: string): boolean {
	const q = quote.replace(/\s+/g, " ").trim().toLowerCase()
	if (q.length < 3) return false
	return message.replace(/\s+/g, " ").trim().toLowerCase().includes(q)
}

function targetKind(value: string): "entity" | "scope" {
	return value.endsWith("/") ? "scope" : "entity"
}

/** Pronouns/deixis the model sometimes emits as "targets" ("force-push it").
 *  They are not names; dropping them routes the grant into the bare-verb path. */
const PRONOUN_TARGETS = new Set([
	"it", "that", "this", "them", "these", "those", "everything", "anything",
	"all", "stuff", "things", "one",
])

/** Generic kind-words the model sometimes emits as revocation "targets"
 *  ("do not delete any images" → targets ["images"]). They are not names and
 *  can never match a concrete entity, which would silently drop the revocation
 *  — escalate to a category-wide forbid instead (fail-safe direction). */
const GENERIC_KIND_TARGETS = new Set([
	"image", "images", "container", "containers", "file", "files", "folder",
	"folders", "directory", "directories", "dir", "dirs", "table", "tables",
	"database", "databases", "db", "dbs", "branch", "branches", "package",
	"packages", "service", "services", "pod", "pods", "namespace", "namespaces",
	"repo", "repos", "repository", "repositories", "volume", "volumes", "data",
	"backup", "backups", "dump", "dumps", "server", "servers", "process",
	"processes",
])

/** Explicit read-only posture phrases — always lock the session. */
const READ_ONLY_ASSERTION_RE =
	/\b(?:read[- ]?only|analysis[- ]only|analyze[- ]only|just (?:look|read|inspect|browse|check)|only look|hands? off)\b/i

/** Read-side activities. A blanket complaint whose subject is only these is about
 *  SCOPE/EFFORT, not about mutating anything. */
const READISH_ACTIVITY_RE =
	/\b(?:search(?:ing|ed)?|find(?:ing)?|grep|ripgrep|scan(?:ning|ned)?|look(?:ing|ed)?|browse(?:|ing|d)|read(?:ing)?|investigat\w+|explor\w+|hunt(?:ing|ed)?|clues?)\b/i

/** Mutating or executing activity. Any of these makes a blanket revocation real,
 *  so ambiguity keeps the posture (fail-safe: at worst one extra prompt). */
const MUTATION_OR_RUN_RE =
	/\b(?:chang\w+|modify|modifying|modif\w*|edit\w*|writ(?:e|es|ing)|touch\w*|alter\w*|delet\w+|remov\w+|run|running|execut\w+|install\w+|apply|applying|applie[sd]|commit\w+|push\w*|create\w+|add\w*|make|makes|making|fix\w*|configur\w*)\b/i

/** Does a blanket, action-unmappable revocation mean "no mutations this session"?
 *
 *  It used to be: ANY such revocation locked every write for the rest of the
 *  session. That turned a scoping complaint — "you will not search half a tb of
 *  files in my home to find clues" — into a read-only lock that then refused
 *  files the user had explicitly authorised by name, and the refusal quoted the
 *  unrelated sentence back at them.
 *
 *  Decided by EXCLUSION rather than an allowlist so it stays fail-safe: only a
 *  complaint about reading/searching, with no mutating or executing verb
 *  anywhere, fails to arm the posture. "stop, don't run anything risky anymore"
 *  still arms it. */
function isReadOnlyPosture(quote: string, messageText: string): boolean {
	const text = `${quote} ${messageText}`
	if (READ_ONLY_ASSERTION_RE.test(text)) return true
	if (MUTATION_OR_RUN_RE.test(text)) return true
	return !READISH_ACTIVITY_RE.test(text)
}

/** Clear phrases that globally re-enable changes, lifting the read-only posture. */
const RE_ENABLE_CHANGES =
	/(?:(?:you (?:can|may)|go ahead(?: and)?|feel free to|ok(?:ay)? to|it'?s (?:ok|okay|fine) to|resume|re-?enable|allow)\b[^.]*\b(?:make changes?|changes?|modif\w*|writ\w*|edit\w*)\b)|(?:\bchanges? (?:are (?:ok|okay|fine|allowed|permitted)|enabled|allowed)\b)|(?:\b(?:no longer|not) read[- ]?only\b)/i

/**
 * The rule-file TARGET CLASS: "permission files", "rule files", and the filenames themselves.
 *
 * This exists because a class of files is not a category of action. The word inside the class name
 * (`permission`) used to hit the privilege row of `ACTION_MAP`, which turned "I do not want to use
 * ANY permission files" into a `perm_change` category-wide forbid, and D29's family fold then
 * spread that over every write and recursive delete in the workspace. Read as what it is — a set of
 * paths the user refused to have used — the sentence scopes a forbid to those paths and leaves the
 * rest of the tree alone.
 *
 * Detection is code-side, over the quote that `quoteInMessage` already verified word for word, so
 * the paths below are not the model inventing targets: the phrase that summons them is the user's
 * own. The `*` row of `permissions-loader`'s project layer lives under `.pi/projects/<id>/`, which
 * no session can spell without the cwd, hence the project-relative form for that half.
 */
const RULE_FILE_CLASS_RE =
	/\b(?:permissions?|rules?) files?\b|\bpermissions?\.json\b|\bpermission-modes\.json\b|\bpermissions\.local\.json\b|\bgrants\.json\b/i

/** The paths the class names, spelled the way the gate RENDERS them — `~/…` outside the project,
 *  `./…` inside — because `canonicalPath` resolves both halves at match time against the caller's
 *  own home and project root. Hardcoding an absolute `/home/<user>` here would match nobody else. */
const RULE_FILE_PATHS = ["~/.pi/agent/permission-modes.json", "./.pi/projects/"]

/** Paths named by the class, or none when the sentence also said an ACL verb: a sentence that
 *  names `chmod` really is about privilege, and the verb is the stronger signal of the two. */
function ruleFileTargets(quote: string, mapped: string | undefined): string[] {
	if (mapped && PRIVILEGE_CATEGORIES.has(mapped)) return []
	return RULE_FILE_CLASS_RE.test(quote) ? RULE_FILE_PATHS : []
}

/** A negated read binds the read categories in `READ_CATEGORIES` and nothing else. */

/**
 * Which category a forbid that NAMES a target may carry.
 *
 * `"*"` means "every category AT THIS PATH" and it is the oldest meaning a named row has — "do not
 * touch ~/backups" really does forbid the delete, the write and the chmod. What it must never do is
 * be INFERRED from a sentence that named an action and named it as reading:
 * "you will not fucking search in /home/u/dev" produced `{category:"*", value:"/home/u/dev/"}`,
 * a prefix that contains the project, so a sentence about reading outside the repo blocked writing
 * a file inside it and quoted the user's own words back as the reason.
 *
 * Anything with a mutating verb anywhere in it stays wide, which is the fail-closed side: "stop
 * reading and writing /x" keeps `"*"`. Read verbs alone bind to the read categories.
 *
 * Search verbs are deliberately NOT in `ACTION_MAP`, and that is why this reads the sentence and not
 * only the mapped category: mapping `search` would also turn a blanket complaint about scanning a
 * whole home directory ("you will not search half a tb of files") into a session-wide read ban — the
 * same over-block in the other direction, already solved once by `isReadOnlyPosture`. This is the
 * narrow half of that vocabulary, and it applies only where the sentence also named a target.
 */
function namedTargetCategory(mapped: string | undefined, evidence: string): string {
	if (MUTATION_OR_RUN_RE.test(evidence)) return "*"
	if (mapped && READ_CATEGORIES.has(mapped)) return mapped
	if (mapped) return "*"
	return READISH_ACTIVITY_RE.test(evidence) ? "read_only" : "*"
}

/**
 * The one row a sentence gets when it names a place rather than a specific file operation.
 *
 * Two callers, one reason each. A read-shaped revocation: one sentence, one row, and a negated read
 * has no business naming a mutation's subtree. A TARGET CLASS row: the code owns the list, so it can
 * say which of its own paths are files and which are directories, and `~/.pi/agent/…json/` is a
 * prefix of a file that has no children — a row that can never match anything but itself.
 *
 * The shape comes from the name itself: a name with an extension is a file, so the row names the
 * file; anything else is a place, so the row names the place — the prefix form, which `valueCovers`
 * already reads as covering the directory itself (`t + "/" === s`) as well as everything under it.
 * That is why one row is enough: the entity-plus-subtree pair this file emits for a user-named
 * mutation target bought nothing a scope row does not already cover, it only doubled what the user
 * has to notice in `/grants` and take back.
 */
function singleRowShape(value: string): { value: string; kind: "entity" | "scope" } {
	const bare = value.endsWith("/") ? value.slice(0, -1) : value
	const base = bare.slice(bare.lastIndexOf("/") + 1)
	const looksLikeFile = /\.[^./]+$/.test(base)
	if (looksLikeFile) return { value: bare, kind: "entity" }
	return { value: `${bare}/`, kind: "scope" }
}

/**
 * Convert one message's extraction into ledger events, dropping anything the
 * code cannot verify against the message text (fail-safe: a dropped event
 * costs at most one prompt later). The extraction context is the single
 * message, so requiring targets to appear in it verbatim is sound here —
 * unlike task A, there is no pending action for the model to echo from.
 */
export function eventsFromExtraction(
	x: MessageGrantExtraction,
	messageId: string,
	seq: number,
	messageText: string,
): ExtractedEvent[] {
	const out: ExtractedEvent[] = []
	if (isSyntheticUserTurn(messageText)) return out
	for (const g of x.grants ?? []) {
		const quote = String(g.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		// Schema-first: the category comes from an enum the model had to satisfy, so no
		// English vocabulary sits on this path. The word list is reached only when that value
		// is missing or "other", i.e. the endpoint ignored the schema.
		const modelCategory = String(g.category ?? "").trim().toLowerCase()
		const fromSchema = isGrantCategory(modelCategory) && modelCategory !== "other" ? modelCategory : undefined
		const mapped = fromSchema ?? mapActionToCategory(String(g.action ?? ""))
		if (fromSchema) {
			extractionStats.fromSchema++
			extractionStats.mapped++
		} else if (mapped) {
			extractionStats.legacyWordList++
			extractionStats.mapped++
		} else {
			extractionStats.unmapped++
			extractionStats.lastUnmapped = String(g.action ?? "").slice(0, 80)
		}
		const category = mapped ?? `*${String(g.action ?? "").slice(0, 60)}*`
		// Structural fields, not phrases: the model says whether this is a location and
		// whether the user's words included credentials. Absent means the narrow answer.
		const wantsScope = String(g.kind ?? "") === "scope"
		const includesSecrets = g.includesSecrets === true
		if (wantsScope) extractionStats.scopes++
		if (includesSecrets) extractionStats.secretInclusions++
		const targets = (g.targets ?? [])
			.map(String)
			.filter((t) => t.trim().length >= 2 && !PRONOUN_TARGETS.has(t.trim().toLowerCase()))
		if (targets.length === 0) {
			// bare-verb grant ("force-push it"): only for bare-verb categories,
			// and the quote itself must carry the verb.
			if (!mapped) continue
			const verbRe = BARE_VERB_CATEGORIES[mapped]
			if (!verbRe || !verbRe.test(quote)) continue
			out.push({ type: "grant", category, value: "*", kind: "scope", quote, messageId, seq })
			continue
		}
		// A LOCATION permission grants the directory, not one file. "you can work in
		// /home/me/proj", "edits under ~/tmp/x/" — the preposition is what makes the
		// path a scope rather than a target. Without this, approving a folder is
		// recorded file-by-file and every new file in it prompts again.
		//
		// Bounded three ways: (a) only for path-MUTATING categories, so "read
		// anything in /etc" stays a read permission; (b) the path must appear
		// verbatim in the verified quote; (c) scopes are session-scoped like any
		// other grant, and /grants revoke removes one — which is why there is no
		// path-depth ceiling: revocability is the control, not a prefix ban.
		// Emitted from the QUOTE, not from the file targets: a directory permission
		// names the directory and usually no file at all, so deriving it inside the
		// per-target loop (which is gated on the file being user-named) drops it
		// entirely. Verified by test.
		const loc = /\b(?:in|under|inside|below|within)\s+(~?\/[^\s,.;:!?)'"]+)/i.exec(quote)
		const locRaw = loc?.[1]?.replace(/["'`]+$/, "")
		// Scopes from the verified quote. Historically this fired for path-MUTATING
		// categories only, which produced a confusing asymmetry: "you can write into /x"
		// became one folder permission while "you can read everything in /x" became nothing
		// usable, so every file under the folder prompted again. Reads are included now — the
		// three bounds are unchanged (verified quote, user-named path, path-shaped category),
		// and it stays narrow in the direction that matters: a read_only scope cannot reach
		// read_secret, because those are different kind groups.
		if (
			!wantsScope &&
			mapped &&
			(FS_MUTATION_CATEGORIES.has(mapped) || mapped === "read_only") &&
			locRaw &&
			locRaw.length >= 2
		) {
			if (targetNamedByUser(locRaw, [messageText])) {
				const scopeValue = locRaw.endsWith("/") ? locRaw : `${locRaw}/`
				out.push({ type: "grant", category, value: scopeValue, kind: "scope", quote, messageId, seq })
			}
		}
		for (const t of targets) {
			if (!targetNamedByUser(t, [messageText])) continue
			if (wantsScope) {
				// One folder permission, not one grant per file inside it. Note the failure
				// direction: a FILE path marked as a scope keeps its own name and cannot reach a
				// sibling, so a wrong kind degrades toward the narrow answer rather than the wide
				// one. Verified in schema-first-grants.test.ts.
				const scopeValue = t.endsWith("/") ? t : `${t}/`
				out.push({
					type: "grant",
					category,
					value: scopeValue,
					kind: "scope",
					quote,
					messageId,
					seq,
					...(includesSecrets ? { includesSecrets: true } : {}),
				})
				// A scope the user said includes secrets gets its own row. read_only cannot
				// match read_secret by kind group and that split is deliberate — it is what
				// stops "read this folder" from quietly unlocking the credentials in it — so
				// inclusion is honoured by recording the second grant the user actually made,
				// not by loosening the matcher.
				if (includesSecrets && category !== "read_secret") {
					out.push({ type: "grant", category: "read_secret", value: scopeValue, kind: "scope", quote, messageId, seq, includesSecrets: true })
				}
				continue
			}
			out.push({ type: "grant", category, value: t, kind: targetKind(t), quote, messageId, seq })
			// A compound permission names more than one capability: "I give you
			// permission to use sudo to write to that file" authorises the elevation
			// AS WELL AS the write. Without this the same sentence leaves no privilege
			// grant and every sudo'd follow-up re-prompts the user for what they just
			// granted. Only the method word in the verified quote earns it.
			if (category !== "privilege" && /\bsudo\b|\bsu -\b|\bas root\b|\belevat\w*/i.test(quote)) {
				out.push({ type: "grant", category: "privilege", value: t, kind: targetKind(t), quote, messageId, seq })
			}
		}
	}
	for (const r of x.revocations ?? []) {
		const quote = String(r.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		const action = String(r.action ?? "")
		// a mapped action scopes an all-forbid to its kind group; unmappable → all groups
		const mapped = mapActionToCategory(action)
		const cat = mapped ?? "*"
		const targets = (r.targets ?? []).map(String).filter((t) => t.trim().length >= 2)
		const named = targets.filter((t) => {
			const low = t.trim().toLowerCase()
			return !PRONOUN_TARGETS.has(low) && !GENERIC_KIND_TARGETS.has(low)
		})
		// A target CLASS the user's own verified words name counts as a named target, so a sentence
		// about rule files scopes to those paths instead of falling through to a category-wide row.
		// `all: true` still outranks the MODEL's target list — refusing to widen a deny on a guess is
		// the fail-safe side of the fold, and that is what it always was — but it does not outrank a
		// class read out of the sentence itself: "ANY permission files" is all-ness over that CLASS,
		// not all-ness over every category the gate knows.
		const classTargets = named.length === 0 ? ruleFileTargets(quote, mapped) : []
		// The old blanket test, kept exactly — `all: true` OR nothing named — with ONE exception: a
		// class the sentence itself named supplies targets, and then the sentence is not targetless.
		// Written this way so every other combination lands where it landed before W49b, including
		// `all: false` with only generic kind-words (`do not delete any images`), which is blanket.
		const isBlanket = classTargets.length === 0 && (r.all === true || named.length === 0)
		if (isBlanket) {
			if (cat === "*") {
				// Global "don't change anything / read-only" → session posture (not a
				// wildcard forbid row, which would match hallucinated targets and report
				// a fabricated "user forbade X") — but only when the sentence really
				// asserts a no-mutation posture. See READ_ONLY_POSTURE_RE.
				if (isReadOnlyPosture(quote, messageText)) {
					out.push({ type: "readonly-on", category: "*", value: "*", kind: "scope", quote, messageId, seq })
				} else {
					// Unmappable action, no posture assertion: keep the sentence, defuse
					// the lock. `*action*` can never equal a gate category group.
					const label = String(r.action ?? "unspecified").slice(0, 60)
					out.push({ type: "forbid", category: `*${label}*`, value: "*", kind: "scope", quote, messageId, seq })
				}
			} else {
				// mapped category with no specific target: forbid that whole category. Still exactly
				// one category — `value: "*"` means every TARGET of what the user named, never every
				// category — and this is the only path that may produce it. "no writes anywhere, ever"
				// and "chmod is not allowed on any file" are posture statements and keep their width;
				// a sentence that named a thing never reaches this line, because it has a target by now.
				out.push({ type: "forbid", category: cat, value: "*", kind: "scope", quote, messageId, seq })
			}
			continue
		}
		// Two sources of values, verified in two different ways. A target the MODEL offered must
		// appear in the user's own words or it is dropped (`targetNamedByUser`). A class path is not
		// model invention either — the phrase that summons it was verified verbatim above — so it is
		// not put through a check it could never pass: the class name is in the sentence, the paths are
		// the code's own knowledge of where its rule files live.
		const values = named.length > 0 ? named.filter((t) => targetNamedByUser(t, [messageText])) : classTargets
		const namedCategory = named.length > 0
			? namedTargetCategory(mapped, `${action} ${quote}`)
			: mapped && READ_CATEGORIES.has(mapped) ? mapped : "*"
		for (const t of values) {
			if (named.length === 0 || READ_CATEGORIES.has(namedCategory)) {
				// One row for one sentence: the read categories (task B — a negated read must not be able
				// to outrank a write, and must not arrive twice) and the class paths (the code's own list,
				// shaped once here rather than doubled below).
				const row = singleRowShape(t)
				out.push({ type: "forbid", category: namedCategory, value: row.value, kind: row.kind, quote, messageId, seq })
				continue
			}
			// named revocations apply across all categories: "don't touch
			// ~/backups" forbids deletes AND writes AND chmod there.
			out.push({ type: "forbid", category: "*", value: t, kind: targetKind(t), quote, messageId, seq })
			// AND across the subtree. A grant can be a location permission — the model marks it
			// `kind: "scope"`, and folder reads/writes also arise from the verified-quote path —
			// so a revocation that names the same location must reach everything the grant
			// reaches, or "stop, don't delete anything under ~/scratch-data" would leave the
			// earlier folder grant authorising files inside it. That is a real false allow, and
			// it is how this row was found: eval case L-02.
			//
			// Widening a FORBID is fail-safe in a way widening a grant is not: the worst case is
			// one extra prompt, never an unapproved action. A later grant naming the value still
			// lifts it by seq, exactly as the single-file revocation did.
			if (!t.endsWith("/")) {
				out.push({ type: "forbid", category: "*", value: `${t}/`, kind: "scope", quote, messageId, seq })
			}
		}
	}
	// Blanket re-enable ("ok, you can make changes now") lifts the read-only posture.
	// Conservative phrase match, and only when no specific grant target is involved
	// (a specific grant already overrides per-target via seq). Not classification —
	// a clear re-enable phrase.
	for (const g of x.grants ?? []) {
		const quote = String(g.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		const hasTarget = (g.targets ?? []).some((t) => {
			const low = String(t).trim().toLowerCase()
			return low.length >= 2 && !PRONOUN_TARGETS.has(low) && !GENERIC_KIND_TARGETS.has(low)
		})
		if (!hasTarget && RE_ENABLE_CHANGES.test(quote)) {
			out.push({ type: "readonly-off", category: "*", value: "*", kind: "scope", quote, messageId, seq })
		}
	}
	return out
}

// ---------------------------------------------------------------- (de)serialize

export type SerializedLedger = {
	v: 1
	grants: LedgerEntry[]
	forbids: LedgerEntry[]
	seen: string[]
	readOnlyOn?: { seq: number; quote: string }
	readOnlyOffSeq?: number
	/** Revocations, written only when there are any. Every reader that predates them
	 *  ignores the key, and `deserializeLedger` treats its absence as "nothing was
	 *  taken back", so this stays a v: 1 snapshot rather than a version bump. */
	revoked?: GrantRevocation[]
	/** Forbid rows the user took back, same shape and same clock rule as `revoked`, kept in
	 *  its own key space so a cancelled ban never reaches a grant. Also written only when there
	 *  are any, so an older reader sees exactly the object it did before this key existed. */
	revokedForbids?: ForbidRevocation[]
}

// ---------------------------------------------------------------- revocation

/**
 * Take back ledger grant rows and record that it happened.
 *
 * Grants only — the forbid half is `revokeLedgerForbids`. The two are deliberately not one
 * function: a lifted forbid must never touch the allow side, and their tombstone lists are
 * separate key spaces for exactly that reason.
 *
 * Like `revokeRows` on the session store, the predicate belongs to the caller —
 * deciding WHICH rows a user meant is a path question with one answer in this codebase
 * (`grant-verify`), and this function must not grow a second one. Every row removed
 * yields one revocation of its own, so revoking one file can never widen into the
 * folder grant beside it, and a revoke that matched nothing records nothing: an empty
 * revoke must not become a standing ban.
 */
export function revokeLedgerGrants(
	ledger: Ledger,
	matches: (entry: LedgerEntry) => boolean,
	opts: { quote?: string; at?: number } = {},
): GrantRevocation[] {
	const at = typeof opts.at === "number" ? opts.at : Date.now()
	const taken: GrantRevocation[] = []
	for (let i = ledger.grants.length - 1; i >= 0; i--) {
		const row = ledger.grants[i]!
		if (!matches(row)) continue
		ledger.grants.splice(i, 1)
		const revocation: GrantRevocation = { category: row.category, value: row.value, kind: row.kind, at }
		if (opts.quote) revocation.quote = opts.quote
		taken.push(revocation)
	}
	if (taken.length) ledger.revoked = foldRevocations(ledger.revoked, taken)
	return taken
}

/** Erase grant rows a revocation this ledger already holds still vetoes. Forbids are
 *  never touched: a revocation is not a forbid and cannot create one. */
export function dropRevokedGrantRows(ledger: Ledger): number {
	const split = partitionRevoked(ledger.grants, ledger.revoked)
	ledger.grants = split.kept
	return split.vetoed.length
}

/** A forbid tombstone. Structurally identical to a grant revocation — one exact
 *  `{category,value,kind}` key plus the clock it was taken on — and named apart because the
 *  list it aims at is what a reader needs to know before it applies one. */
export type ForbidRevocation = GrantRevocation

/**
 * Take back ledger FORBID rows and record that it happened, so the sentence that produced
 * them cannot put them back.
 *
 * This is the missing half of `/grants revoke`. Until now the command could remove a grant and
 * could not remove a forbid at all: the row lived in `ledger.forbids`, nothing spliced that
 * list, and even a hand-edited one came back on the next drain of the same message because the
 * tombstone gate in `applyEvent` looked only at grant keys. The only way out was
 * `/grants export`, edit the JSON by hand, `/grants import --replace` — an escape hatch that
 * asks the user to hold the machinery for a bug in it.
 *
 * A cancelled ban is not a new ban, which is why the tombstone goes in `ledger.revokedForbids`
 * and not `ledger.revoked`: the key has no type in it, so a shared list would let this command
 * delete a grant that happened to carry the same `{category,value,kind}`. Removing a forbid
 * therefore erases nothing on the allow side and records nothing there.
 *
 * Same contract as `revokeLedgerGrants`: the caller owns the predicate (which rows the user
 * meant is a path question with one answer in this codebase, `grant-verify`), one tombstone per
 * removed row so revoking one value cannot widen into the folder-shaped one beside it, and an
 * empty match records nothing — a revoke that hit nothing must not become a standing ban.
 *
 * Returns the rows it removed (with their quotes) so the caller can tell the user which
 * sentence stopped being enforced. Local-only by construction: `localRevocationKeys` ignores
 * rows tagged `imported`, so a tombstone read off a file cannot veto a sentence the user says
 * here — the same asymmetry an imported forbid already has.
 */
export function revokeLedgerForbids(
	ledger: Ledger,
	matches: (entry: LedgerEntry) => boolean,
	opts: { quote?: string; at?: number } = {},
): LedgerEntry[] {
	const at = typeof opts.at === "number" ? opts.at : Date.now()
	const taken: LedgerEntry[] = []
	const stamps: ForbidRevocation[] = []
	for (let i = ledger.forbids.length - 1; i >= 0; i--) {
		const row = ledger.forbids[i]!
		if (!matches(row)) continue
		ledger.forbids.splice(i, 1)
		const stamp: ForbidRevocation = { category: row.category, value: row.value, kind: row.kind, at }
		if (opts.quote) stamp.quote = opts.quote
		stamps.push(stamp)
		taken.push(row)
	}
	if (stamps.length) ledger.revokedForbids = foldRevocations(ledger.revokedForbids, stamps)
	return taken
}

/** Erase forbid rows a forbid revocation this ledger already holds still vetoes. Mirrors
 *  `dropRevokedGrantRows`, including its clock: a row re-earned AFTER the revocation carries a
 *  later `at` and survives, because the user is allowed to change their mind again. */
function dropRevokedForbidRows(ledger: Ledger): number {
	const split = partitionRevoked(ledger.forbids, ledger.revokedForbids)
	ledger.forbids = split.kept
	return split.vetoed.length
}

// ---------------------------------------------------------------- portability

/** Background-authority seq: anything the user says in THIS session (seq >= 1)
 *  outranks an imported row, and any local revocation dominates it. Replaying
 *  source seqs instead would compare ordinals across unrelated conversations. */
const IMPORTED_SEQ = 0

function asImported(e: LedgerEntry): LedgerEntry {
	return {
		...e,
		seq: IMPORTED_SEQ,
		// Cleared on purpose: deserializeLedger()'s keep() retains rows with no
		// messageId, which is what lets an import outlive a resume.
		messageId: "",
		origin: "imported",
		sourceSeq: e.seq,
		sourceMessageId: e.messageId || undefined,
		// `seq` is flattened because ordinals do not travel between transcripts, but the
		// row keeps its source `at`: that timestamp is the only thing a revocation can be
		// compared against across sessions, and restamping it to "now" would let any file
		// walk a grant back in over a revocation that came after it.
	}
}

function importRows(
	target: LedgerEntry[],
	rows: LedgerEntry[],
	cap: number,
): { added: number; dropped: number } {
	const seen = new Set(target.map((e) => rowIdentity(e)))
	let added = 0
	let dropped = 0
	for (const row of rows) {
		const key = rowIdentity(row)
		if (seen.has(key)) continue
		// Appended, never prepended: existing rows keep their position and the
		// LRU eviction elsewhere drops the oldest first.
		if (target.length >= cap) {
			dropped++
			continue
		}
		seen.add(key)
		target.push(row)
		added++
	}
	return { added, dropped }
}

export type ImportSummary = {
	grantsAdded: number
	forbidsAdded: number
	dropped: number
	postureImported: boolean
	/** Revocations the file added to this ledger's own list. */
	revocationsAdded: number
	/** Grant rows the file offered and a revocation made here refused at the door. */
	revokedOnArrival: number
	/** Forbid rows the file offered and a FORBID revocation made here refused at the door —
	 *  the same wall, on the other list. Reported apart because "the file was stale" and "you
	 *  cancelled a ban here and it tried to come back" are different things to see. */
	forbidsRefusedHere: number
	/** Message ids the file had already extracted and this ledger had not. Restoring them
	 *  is what stops the drain from re-extracting a conversation it was handed. */
	seenImported: number
}

/**
 * Import a grants file's ledger into `target` (plan.md Phase B2).
 *
 * Rows arrive at seq 0 with no messageId: they become background authority that
 * local statements outrank, and they survive both a rewind and the restore
 * filter. Forbids travel in the same payload, so an import cannot resurrect
 * authority the source session revoked.
 *
 * `seen` travels too. It used to be dropped here on the theory that re-extracting
 * is self-healing; measurement said otherwise. Re-extracting a conversation the file
 * just handed us is a model call per message for rows we already hold, and — once a
 * revocation is a row — re-extraction is also how a revoked grant gets another chance
 * at being re-derived. Restoring the ids makes "I already read this message" a fact
 * that survives an import instead of a fact that has to be paid for again. The cost
 * is bounded and sits on the safe side: an id from a foreign transcript can only ever
 * suppress extraction, never invent a grant, and suppression costs one prompt.
 *
 * Revocations follow the same asymmetry, in both directions:
 *  - the source's rows arrive already filtered by the source's own revocations (that
 *    happens in `deserializeLedger`, so it holds for a resumed session blob too), and
 *  - revocations made HERE refuse matching rows at the door, on the key alone: a file
 *    may only be as strong as its own clock, and a revocation made in this session is
 *    a statement made here.
 * The file's revocations are then folded in as background and do NOT reach back to
 * veto grants this session earned by itself — the same reason an imported forbid does
 * not: a stale or poisoned file must not be able to block legitimate work with only
 * `/grants clear` as the remedy. `replace` swaps rows, never revocations.
 */
export function importLedger(
	target: Ledger,
	data: unknown,
	opts: { replace?: boolean } = {},
): ImportSummary {
	const src = deserializeLedger(data)
	if (opts.replace) {
		target.grants = []
		target.forbids = []
	}
	const held = foldRevocations(target.revoked, undefined)
	const refusedHere = new Set(held.map((r) => rowIdentity(r)))
	const offered = src.grants.map(asImported)
	const allowed = offered.filter((e) => !refusedHere.has(rowIdentity(e)))
	const grants = importRows(target.grants, allowed, MAX_GRANTS)
	// The forbid side of the same wall, in its own key space: a ban this session already took back
	// does not get a second life from a file that has not heard about it. Note what this is NOT —
	// it is not a veto over anything derived HERE. The file's own tombstones were already applied
	// inside `deserializeLedger`, and a file cannot make decisions about sentences said elsewhere.
	const refusedForbidsHere = new Set(foldRevocations(target.revokedForbids, undefined).map((r) => rowIdentity(r)))
	const offeredForbids = src.forbids.map(asImported)
	const allowedForbids = offeredForbids.filter((e) => !refusedForbidsHere.has(rowIdentity(e)))
	const forbids = importRows(target.forbids, allowedForbids, MAX_FORBIDS)
	// Tagged as background on the way in: the fold keeps a revocation made HERE ahead of the
	// same one read off disk, so an import can never demote a local revoke into background
	// authority and quietly switch off the `applyEvent` guard for that key.
	target.revoked = foldRevocations(held, asBackgroundRevocations(src.revoked))
	// Message ids the source already extracted are knowledge, not authority: union them in so
	// the drain starts where the source stopped. See the doc block above for why the direction
	// is safe (a seen id can only suppress work, never authorise anything).
	let seenImported = 0
	for (const id of src.seen) {
		if (target.seen.has(id)) continue
		target.seen.add(id)
		seenImported++
	}

	const srcPosture = readOnlyActive(src)
	const hadPosture = readOnlyActive(target) != null
	let postureImported = false
	if (srcPosture && target.readOnlyOn === undefined) {
		target.readOnlyOn = { seq: IMPORTED_SEQ, quote: srcPosture.quote }
		// Only counts as imported if it is actually in force: a local
		// "you can make changes now" (higher seq) keeps it switched off.
		postureImported = !hadPosture && readOnlyActive(target) != null
	}

	return {
		grantsAdded: grants.added,
		forbidsAdded: forbids.added,
		dropped: grants.dropped + forbids.dropped,
		postureImported,
		revocationsAdded: (target.revoked?.length ?? 0) - held.length,
		revokedOnArrival: offered.length - allowed.length,
		forbidsRefusedHere: offeredForbids.length - allowedForbids.length,
		seenImported,
	}
}

export function serializeLedger(ledger: Ledger): SerializedLedger {
	const snapshot: SerializedLedger = {
		v: 1,
		grants: ledger.grants,
		forbids: ledger.forbids,
		seen: [...ledger.seen],
		readOnlyOn: ledger.readOnlyOn,
		readOnlyOffSeq: ledger.readOnlyOffSeq,
	}
	// Omitted when empty rather than written as `revoked: []`: a snapshot a human opens
	// should not carry an empty revocation list on every session that revoked nothing.
	if (ledger.revoked?.length) snapshot.revoked = ledger.revoked
	if (ledger.revokedForbids?.length) snapshot.revokedForbids = ledger.revokedForbids
	return snapshot
}

/**
 * Restore a snapshot. `validMessageIds` (current-branch membership) drops
 * entries from messages the user rewound away — a grant from an abandoned
 * branch must not survive. Unknown versions return an empty ledger (backfill
 * rebuilds deterministically).
 */
export function deserializeLedger(data: unknown, validMessageIds?: Set<string>): Ledger {
	const ledger = createLedger()
	const s = data as Partial<SerializedLedger> | undefined
	if (!s || s.v !== 1) return ledger
	const keep = (e: LedgerEntry): boolean =>
		!!e && typeof e.value === "string" && typeof e.category === "string" &&
		typeof e.seq === "number" && typeof e.quote === "string" &&
		(!validMessageIds || !e.messageId || validMessageIds.has(e.messageId))
	ledger.grants = Array.isArray(s.grants) ? s.grants.filter(keep).slice(0, MAX_GRANTS) : []
	ledger.forbids = Array.isArray(s.forbids) ? s.forbids.filter(keep).slice(0, MAX_FORBIDS) : []
	for (const id of Array.isArray(s.seen) ? s.seen : []) {
		if (typeof id === "string" && (!validMessageIds || validMessageIds.has(id))) ledger.seen.add(id)
	}
	if (s.readOnlyOn && typeof s.readOnlyOn.seq === "number" && typeof s.readOnlyOn.quote === "string") {
		ledger.readOnlyOn = { seq: s.readOnlyOn.seq, quote: s.readOnlyOn.quote }
	}
	if (typeof s.readOnlyOffSeq === "number") ledger.readOnlyOffSeq = s.readOnlyOffSeq
	// Apply-on-read: a revocation in this snapshot vetoes the rows in this snapshot,
	// including any the writer forgot to remove. Doing it here — the one door every
	// restore and every import walks through — is what makes a revocation survive a
	// round trip without every caller having to remember to ask for it.
	ledger.revoked = foldRevocations(undefined, s.revoked)
	if (ledger.revoked.length) ledger.grants = partitionRevoked(ledger.grants, ledger.revoked).kept
	// Same apply-on-read for the cancelled bans: a snapshot still carrying a forbid that one of its
	// own tombstones names is a snapshot whose writer forgot to splice, and a resume must not put
	// back a ban the user in that session had already taken back.
	ledger.revokedForbids = foldRevocations(undefined, s.revokedForbids)
	if (ledger.revokedForbids.length) dropRevokedForbidRows(ledger)
	return ledger
}
