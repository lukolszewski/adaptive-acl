/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
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
import { kubeContexts, LOCAL_MACHINE_OBJECT, tempGrantDirs } from "./risk-paths.ts"
import type { ImageRef } from "./target-grammar.ts"
import { coversByGrammar, grammarFor, namedByUserStructurally, objectStoreCovers, parseImageRef, parseVcsTarget } from "./target-grammar.ts"
import {
	DOING_VERB_EVIDENCE,
	METHOD_VERB_REQUIRED,
	NO_OBJECT_TARGET,
	canonicalPath,
	categoryDirection,
	entityMatchesTarget,
	expandHome,
	grantAnswersSegment,
	kindGroup,
	targetNamedByUser,
} from "./grant-verify.ts"
import {
	asBackgroundRevocations,
	FORBID_ANY_CATEGORY,
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
	/** The category the model named, kept when it is NOT the one the row was stored under.
	 *  The cross-check overrode it — the noun in the user's sentence outranked the verb the model
	 *  generalised from — and this is the audit trail of that override, for `/grants` and for a future
	 *  denial line. Nothing in the matcher reads it: a category the code overrode is by definition not
	 *  authority, so a row must never gain reach because of what the model guessed. */
	modelCategory?: string
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
	/** See LedgerEntry.modelCategory. Set only when it differs from `category`. */
	modelCategory?: string
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
 *  mutation cannot be lifted this way — only a blanket re-enable clears it.
 *
 *  Since the model's category is the evidence there is no verb gate here at all: reach comes from the row's
 *  own category (a delete is answered by a delete-category row), so a sentence about destroying needs no word
 *  recognised in code to lift the posture — and a wrong category costs one prompt. */
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
	return targets.every((t) =>
		ledger.grants.some(
			(g) =>
				g.seq > roSeq &&
				valueCovers(g, t, home, project, primary) &&
				grantMatchesPending(g, primary, t, home, project),
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
 * Where the direction table lives now, and why the two sets that used to sit here are gone.
 *
 * `grant-verify.ts` owns `grantDirection` / `grantAnswersSegment`, because the same question — "does a grant for
 * X answer an action of kind Y?" — is asked by three stores and by the transcript verdict, and three copies of
 * a harm taxonomy is how the four start disagreeing. The reasoning that used to be recorded here still holds and
 * is now stated once, there:
 *
 *  · you cannot edit what you cannot open, so a write grant reaches reads (secret-class reads included: an
 *    edit of a credentials file needs the read that precedes it);
 *  · you cannot remove what you may not look at either, so a delete grant reaches reads — and, through
 *    delete→write, still buys no write it did not buy before;
 *  · removing ONE file is part of editing it, so a write grant reaches `delete_outside` — never
 *    `delete_recursive`, never `delete_data`, and never the folder the row was granted over.
 *
 * What has NOT changed: `system_config` and `perm_change` are metadata or service changes rather than content
 * access, so they are reached as OBJECTS in {@link SERVICE_OBJECT_CATEGORIES}, never as a direction over paths;
 * and a READ grant buys no change of any kind.
 */

/**
 * The categories whose object is a SERVICE, HOST or CLUSTER instead of a path — and whose grant therefore
 * already contains reading that object.
 *
 * Layer 0 names the object of a non-file read (`docker ps` → the daemon, `kubectl get` → the cluster,
 * `ssh host …` → the host, `psql` → the database, `curl` → the site), so the question the user answers is
 * per object, not per command. A grant that already lets the agent drive that object — restart the daemon,
 * apply to the cluster, run on the host — plainly includes looking at it; refusing `docker ps` to someone
 * who approved `docker restart` is friction with no security content.
 *
 * `package_system` is deliberately NOT here: its object is a package or a client, and "you may install
 * ripgrep" is not "you may list every mirror". `agent_spawn` is not either — spawning is not reading.
 * A service grant whose value is `*` ("any container, anywhere") is refused below: the rule covers "the object
 * you named", and a category-wide row names none.
 */
const SERVICE_OBJECT_CATEGORIES = new Set([
	"container_mutation",
	"cluster_mutation",
	"db_mutation",
	"remote_exec",
	"network_send",
	"process_control",
	"system_config",
])

/**
 * The categories a temp-class grant may speak for.
 *
 * "You may write temporary files" is a permission over a handful of directories, so the effects it can
 * honestly carry are the ones you perform on files in a directory: read, write, delete, run. Anything else
 * — a cluster, a database, a permission change, credentials — is not a thing a scratch directory holds, and
 * a row claiming one is a model answer this file does not act on: it registers nothing and is counted, so
 * the work behind it costs its ordinary prompt.
 *
 * `read_secret` is excluded on purpose: a scratch space is where a script dumps what it read, so "temp
 * files" is never a licence to go looking for credentials, and the class asks for read + write (+ run), not for
 * the secret gate to move.
 */
const TEMP_CLASS_CATEGORIES = new Set([
	"read_only",
	"write_project",
	"write_outside",
	"write_sensitive",
	"delete_outside",
	"delete_recursive",
	"delete_data",
	"run_project_code",
])

/**
 * The classes of MACHINE a grant can name without spelling an address, the same shape as the temp-file class:
 * the model says WHICH machine it meant, code decides what that is.
 *
 * The model never names this machine in prose — "my machine", "here", "the box" are not verbatim-checkable
 * strings — so a row about it carries the class instead, exactly like `temp_files`. The class is not a target
 * and widens nothing: it supplies the object for one row of the category the model already named.
 *
 * `current_cluster` is the narrow one, and the restriction is the point: a kubeconfig with several
 * contexts has no single "my cluster" for a sentence to mean. With one context there is exactly what the user
 * meant; with several, the row registers NOTHING and the read costs its prompt, which is the "asks" this
 * class exists to ask for. A named context is not this class's business — it is an ordinary target,
 * verbatim-checked.
 */
const MACHINE_TARGET_CLASSES = new Set(["local_machine", "current_cluster"])

/**
 * What `current_cluster` means on this machine: its kubeconfig's current context, and ONLY when the file
 * holds exactly one context. Several contexts means several possible referents for one sentence, so the
 * answer is `undefined` — the row registers nothing and the read asks, which is the outcome named for an
 * ambiguous "my cluster".
 *
 * The count is the number of context ENTRIES the file declares, not the number of names we managed to read:
 * an entry whose name this scanner cannot see is still another referent, so it keeps the answer ambiguous
 * rather than narrowing the file down to the one cluster we happen to be able to name.
 *
 * Only the context names and `current-context` are ever read out of the file (see `kubeContexts`); a
 * kubeconfig holds credentials and nothing here may echo a field beyond those two.
 */
export function singleClusterContext(env?: Record<string, string | undefined>): string | undefined {
	const home = env?.HOME ?? process.env.HOME ?? ""
	if (!home) return undefined
	const { contexts, entries, current } = kubeContexts(home, env)
	if (!current) return undefined
	return entries === 1 && contexts.length === 1 ? current : undefined
}

/** Does a grant entry authorise this pending category, for this pending target?
 *
 *  Group equality as usual, PLUS a target-first widening: a grant that NAMES the
 *  exact path authorises any path-mutating category on that path. Without it an
 *  explicit per-file permission dies on the group boundary — "write to
 *  /usr/bin/foo" extracts as write_outside (fs-write) while the write itself
 *  classifies as write_sensitive (secret), because /usr/bin is a sensitive
 *  prefix, and the two never met. Scopes and wildcards are NOT widened: naming
 *  one file is not permission for a whole tree.
 *
 *  The widening never reaches a DELETE pending, and that limit is load-bearing. It fixes a
 *  group mismatch on CONTENT — the same harm, a different display category — and "you may edit this file"
 *  buying "you may destroy it" is a change of direction, not a spelling. One shape of that direction is
 *  open, and open as a RULE rather than as a spelling: a write row answers `delete_outside`
 *  (removing one file is part of editing it), never `delete_recursive`, never `delete_data`, and never the
 *  folder the row was granted over. Those refusals live in `grantAnswersSegment`, together with the rest of
 *  the direction table, so every store refuses the same three things. */
function grantMatchesPending(
	g: LedgerEntry,
	segment: string,
	target: string,
	home?: string,
	project?: string,
): boolean {
	// The directions a stored category answers at all — group equality plus the three named one-way rules
	// (delete→write, write→read, write→single-file delete) — applied WITH the target, so the two target-shaped
	// refusals (no object-less row, never the granted folder itself) happen where the target is known. This one
	// call replaces what used to be `grantAuthorises` plus the fs half of `readEntailedBy`: the same question
	// answered once, for the ledger, the session store and the transcript verdict alike.
	if (
		grantAnswersSegment({
			grant: g,
			pendingSegment: segment,
			target,
			covers: (seg) => valueCovers(g, target, home, project, seg),
			space: { home, project },
		})
	)
		return true
	if (
		g.kind === "entity" &&
		g.value !== "*" &&
		FS_MUTATION_CATEGORIES.has(g.category) &&
		FS_MUTATION_CATEGORIES.has(segment) &&
		// Privilege stays out of the naming-a-file widening. It exists to fix a group mismatch on
		// CONTENT mutation ("write to /usr/bin/foo" extracting as write_outside while the write
		// classifies as write_sensitive); it never meant "and you may chmod it".
		!PRIVILEGE_CATEGORIES.has(g.category) &&
		!PRIVILEGE_CATEGORIES.has(segment) &&
		// …and the same argument against the other direction: a named file the user may WRITE is not a
		// named file the user may DELETE. See the doc block above.
		kindGroup(segment) !== "fs-delete" &&
		valueCovers(g, target, home, project, segment)
	)
		return true
	// The OBJECT directions, which are about a service, host, cluster or daemon rather than about a path, and
	// therefore cannot live in the category table above: a grant that already drives that object plainly contains
	// looking at it. A `read_system_state` row is reached only from a grant on the same machine, never from a file
	// grant — the object, not the spelling, is what has to match.
	if (segment === "read_only" && serviceReadEntailedBy(g, target, home, project, segment)) return true
	if (segment === "read_system_state" && machineReadEntailedBy(g, target, home, project, segment)) return true
	return false
}

/**
 * The first shape of "does this grant already contain reading `target`?", narrowed to grants whose object IS a
 * service, host, cluster or daemon.
 *
 * The fs half this function used to carry (write and delete grants covering `read_only`, and the `*` rule that
 * went with them) now lives in `grantAnswersSegment` with the rest of the direction table — that direction was
 * widened to `read_secret`, which is a statement about paths and belongs with the path rules. What is left is
 * the part that is not a path at all: a grant that drives a service has the service as its object, so a read of
 * that object is not a new capability.
 *
 * A `*` value is refused here exactly as everywhere else: "any service, anywhere" names no object, so it cannot
 * be evidence about this one.
 */
function serviceReadEntailedBy(g: LedgerEntry, target: string, home?: string, project?: string, segment?: string): boolean {
	const segments = categorySegments(g.category)
	const entailed = segments.filter((c) => SERVICE_OBJECT_CATEGORIES.has(c))
	if (entailed.length === 0) return false
	if (g.value === "*") return false
	return valueCovers(g, target, home, project, segment)
}

/**
 * The second shape of the same one-way question: does a grant the user gave for some OTHER effect already
 * contain reading this machine, host or cluster?
 *
 * Narrower than {@link serviceReadEntailedBy} on purpose. A write or delete grant over a PATH is not evidence
 * about a machine — `/var/log` and "this machine" are different objects, and letting one answer the other is
 * how a folder permission quietly becomes a licence to survey the box. What does answer it is a grant whose
 * object already IS that machine, host, cluster or daemon (the service rule above, unchanged in direction), or a
 * plain read grant on the same object.
 *
 * A `*` value is refused here too: "any service, anywhere" names no object, so it cannot be evidence about
 * this one.
 */
/**
 * The categories whose object can BE a machine or a cluster, and whose grant therefore says something about
 * reading that machine's status — the service-object set above, narrowed for this one question.
 *
 * Deliberately missing, and the reason:
 *  · `network_send` — its object is an endpoint somebody sent a packet to. "You may probe `db.internal:5432`"
 *    is not permission to read that box's process table, and a host string appearing in both categories is a
 *    coincidence of spelling, not of authority;
 *  · `db_mutation` — the object is a database. A cluster's pods are not inside it in the sense that matters.
 * `read_only` is included because it is already a read of that exact object: the user said "read this", and a
 * status read of the same object is that, which is the direction the service rule already pins.
 */
const MACHINE_READ_GRANT_CATEGORIES = new Set([
	"container_mutation",
	"cluster_mutation",
	"remote_exec",
	"process_control",
	"system_config",
	"read_only",
])

function machineReadEntailedBy(g: LedgerEntry, target: string, home?: string, project?: string, segment?: string): boolean {
	if (g.value === "*") return false
	const entailed = categorySegments(g.category).filter((c) => MACHINE_READ_GRANT_CATEGORIES.has(c))
	if (entailed.length === 0) return false
	return valueCovers(g, target, home, project, segment)
}

export const MAX_GRANTS = 200
export const MAX_FORBIDS = 100

/**
 * Extraction diagnostics.
 *
 * When the model returns a category this gate cannot match — missing, `"other"`, or a value outside
 * the enum — the grant registers NOTHING: the word list that used to invent a category from the
 * display label is deleted. That is the failure mode worth counting, because a permission the user
 * actually gave is indistinguishable from one they never gave: no prompt happens, no row appears in
 * `/grants`, the work simply asks again. Surfaced by /classifier-status.
 *
 * There used to be an ordered table of English regexes below `isGrantCategory`, run over the model's
 * `action` string to invent a category. The extraction prompt defines `action` as a display label and
 * then this file made authority out of it, which is how "do not delete any images" became an
 * fs delete that could never reach the container it withdrew.
 */
export const extractionStats = {
	mapped: 0,
	/** Grant rows that registered NOTHING. Two ways to get here and both cost the same prompt: the row
	 *  had no usable category, or it named no object without asking for the whole category (so a wildcard
	 *  would have invented the authority the missing value was supposed to carry). */
	unmapped: 0,
	lastUnmapped: "",
	/** Categories that came from the model as an enum value — the schema-first path. */
	fromSchema: 0,
	/** Categories recovered by the English word list. PERMANENTLY ZERO: the table is
	 *  deleted, and the counter stays because `/classifier-status` prints it — a line that reads
	 *  "0 recovered by the English word list" is the visible proof that no endpoint is riding on it. */
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
	/** Rows whose category the code counted as a disagreement with their own targets (counted,
	 *  never applied — the model's category is what gets stored). Without this a docker push
	 *  filed under a git category, and therefore unreachable from any wording, was only
	 *  visible as a grant that never fired. */
	crossChecked: 0,
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
	extractionStats.crossChecked = 0
}

export function createLedger(): Ledger {
	return { grants: [], forbids: [], seen: new Set(), revoked: [], revokedForbids: [] }
}

// ---------------------------------------------------------------- kind groups

/** Category → matching group (§2.4) now lives in `grant-verify.ts`, because the transcript side needed the
 *  same map the ledger matches on: `verifyGrant` answers "does this sentence authorise this effect?" by
 *  comparing the kind group of every pending segment against the kind groups of the model's `effects`.
 *  Two copies of a harm taxonomy is how the two sides start disagreeing, and the import direction here
 *  (auth-ledger → grant-verify) leaves no other place to put it without a cycle. Re-exported unchanged so
 *  every existing importer of `kindGroup` keeps reading the one table. */
export { kindGroup }

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

/**
 * The object-store half of the same family, stated by CATEGORY because the two effects do not share a
 * kind group and must not borrow the fs one.
 *
 * A bucket is entered by uploading (`network_send` in layer 0 — `aws s3 cp` to a URI) and emptied by deleting
 * objects (`delete_data`). "Do not write in X" therefore has to stop overwrites AND deletes inside X, exactly
 * as the `fs-mutation` family makes a writes-forbid on a directory stop `rm` inside it. Relying on the small
 * model to list a second category for that was measured first, and it is not dependable — a row the model did
 * not emit is a hole, while a family is a rule.
 *
 * Symmetric, like `fs-mutation`: a delete-only forbid also binds an upload to the same value. That direction
 * is wider than the sentence that earned it and it costs one prompt, never an allow — the same price the fs
 * family already pays, and the reason the family is keyed by VALUE coverage everywhere it is used.
 */
const STORE_FORBID_FAMILY: ReadonlySet<string> = new Set(["network_send", "delete_data"])

function forbidCompatible(entryCategory: string, pendingCategory: string): boolean {
	// `any` is every action on the named target — it is the widest forbid the schema can express, so it
	// binds under every segment. It can never reach a grant row: grants are matched by `grantAuthorises`, and
	// `isGrantCategory` refuses the value at every door a grant row comes through.
	if (entryCategory === FORBID_ANY_CATEGORY) return true
	if (compatible(entryCategory, pendingCategory)) return true
	if (STORE_FORBID_FAMILY.has(entryCategory) && STORE_FORBID_FAMILY.has(pendingCategory)) return true
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
 * Does a stored grant authorise this pending category at all (target not considered)?
 *
 * Category-only, and therefore only used where the answer is about the SHAPE of the row rather than about
 * authority over a target — the `/grants explain` candidate scan. Everything that decides whether an action may
 * run goes through {@link grantMatchesPending}, which applies the same directions WITH the target and can
 * therefore refuse the two target-shaped cases (an object-less row, and the granted folder itself).
 *
 * The answer is the direction table and nothing else: the row's own segments, delete→write, and the
 * two directions write implies (read, single-file delete). Two bridges used to live here and both are gone:
 *
 *  - fs-write → fs-delete, conditional on a delete verb found in the row's quote. One shape of it is open —
 *    `delete_outside`, the single-file delete — as a rule about the target (a file inside what the row names)
 *    rather than about a word in a sentence.
 *  - cluster → network_send on a publish compound. A `docker push` is filed by layer 0 as
 *    `container_mutation+network_send`; the send half is reached by a row in the `net-send` group covering the
 *    target, or by the transcript call naming `network_send` in its `effects`.
 */
function grantAuthorises(g: LedgerEntry, segment: string): boolean {
	if (g.category === "*") return true
	return categoryDirection(g.category, segment) !== undefined
}

/**
 * Categories whose pending action READS, and nothing else. Two uses, both about keeping a read
 *  from standing in for a mutation: a forbid that names only these must not bind an action that
 *  mutates (`namedForbidCovers`), and a revocation whose category is one of these gets ONE shaped row
 *  instead of the entity-plus-subtree pair a mutation gets. The split is the one that keeps
 *  `read_secret` out of a folder write grant — reading a path and changing it have never been
 *  interchangeable in this file.
 *
 *  `read_system_state` belongs here on both counts: it is a read of a machine rather than a change to one,
 *  and "stop reading my processes" is one sentence about one object, not a subtree pair. It is deliberately
 *  NOT in any group with the other two — its kind group is its own name, which is what makes an approval to
 *  read a machine's state reach no file read and no credential read. */
const READ_CATEGORIES = new Set(["read_only", "read_secret", "read_system_state"])

/**
 * A compound category (`write_outside+delete_outside`, from one command that both
 * moves and removes) carries EVERY effect of the segments that produced it, but the
 * join order is composition order, not severity.
 *
 * Reading `category.split("+")[0]` therefore makes a security decision depend on
 * which segment happened to be listed first: with a write primary a gate armed by the
 * delete half was skipped entirely, so one operand order demanded a delete-shaped row
 * and the other let a plain write grant answer the delete. That fails OPEN.
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
	"read_system_state",
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

/** `"any"` — every action on the target. Declared in `session-grants.ts`, which sits below this module
 *  and refuses the value at every grant door, and re-exported here so every caller reads one name — the same
 *  way `kindGroup` travels. "Leave X alone" withdraws EVERY action on X, while "do not write in X" withdraws
 *  writes only; only forbids get the wide form, because a missed grant row costs a prompt while a missed
 *  forbid category costs an allow. */
export { FORBID_ANY_CATEGORY }

/** The enum the revocation half of the extraction schema offers: every effect word, plus `any`. */
export const REVOCATION_CATEGORY_VALUES = [...GRANT_CATEGORY_VALUES, FORBID_ANY_CATEGORY] as const

const REVOCATION_CATEGORY_SET: ReadonlySet<string> = new Set(REVOCATION_CATEGORY_VALUES)

/** Is `c` a category a revocation may name? */
export function isRevocationCategory(c: string): boolean {
	return REVOCATION_CATEGORY_SET.has(c)
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
				// Re-derived from a newer sentence, so the newer sentence's audit label wins — including
				// when it has none, for the same reason `includesSecrets` is not inherited.
				modelCategory: ev.modelCategory,
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
		modelCategory: ev.modelCategory,
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

/** First segment of a possibly-compound category — the segment a grammar is picked from. */
function primarySegment(category: string): string {
	return category.split("+")[0]?.trim() ?? category
}

/**
 * Does a stored row's value reach this pending target?
 *
 * Publish targets are answered by the grammar FIRST (docs/CLASSIFIER-SPEC.md §3), because the value the gate itself
 * writes for "every branch on this remote" — `origin/*`, the scope entity from `risk-handlers.ts`
 * — was dead under the string rule: it covered nothing, including the push that produced it. The
 * grammar is chosen by CATEGORY (`target-grammar.ts`), never by what the string looks like, so a
 * path `docs/x` cannot become a branch and prose cannot become whatever it resembles.
 *
 * `segment` is the pending category segment this row is being tested under, which is what lets one
 * compound row (`container_mutation+network_send`) be read with the image grammar on both of its
 * halves. Without it a row falls back to its own first segment, which is the same answer for every
 * row written before compound rows existed.
 *
 * `undefined` from the grammar means "no grammar for this category" or "one side is not a target
 * this grammar can read", and the row is then judged by exactly the rule it was judged by before —
 * a trailing-`/` scope prefix, then the component-run matcher. That fallback is what keeps this a
 * widening of publish targets only: fs, secret, privilege and system paths never reach it.
 */
function valueCovers(
	entry: LedgerEntry,
	target: string,
	home?: string,
	project?: string,
	segment?: string,
): boolean {
	const viaGrammar = coversByGrammar(primarySegment(segment ?? entry.category), entry.value, target)
	if (viaGrammar !== undefined) return viaGrammar
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
 * Does a FORBID row's value reach this pending target?
 *
 * The grant rule, plus one widening a ban can afford: a store named by a forbid reaches the objects inside it
 * (`archive` ↔ `s3://archive/reports.csv`), the same way the entity-plus-subtree pair makes a directory forbid
 * reach the files under it. `target-grammar.ts` owns the reading; this is the door that lets ONLY forbids
 * through it.
 *
 * How much this changes is measured, not assumed: the component matcher in `grant-verify.ts` already
 * let a bare store name hit a URI that contains it as a path component, so most of the container reach existed
 * by accident. What this adds is the rule stated where it belongs — bucket-level equality, prefix boundaries,
 * scheme independence — and a place to widen a ban that is not a side effect of a path comparison.
 *
 * Grants keep today's matching and are not passed through here. Widening a ban costs at most one prompt; a
 * grant that reaches further than the sentence that earned it costs an action the user never approved, and
 * `namedForbidCovers` uses this for the forbid scan and the plain rule for the grant that lifts it.
 */
function forbidValueCovers(
	entry: LedgerEntry,
	target: string,
	home?: string,
	project?: string,
	segment?: string,
): boolean {
	if (valueCovers(entry, target, home, project, segment)) return true
	return objectStoreCovers(entry.value, target) === true
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
 * the block a user hit over "you will not ever search in /home/u/dev" came through THIS scan
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
	// The SAME value rule the ledger rung uses, per pending segment, so a ban written in the gate's
	// own scope spelling (`origin/*`) binds every branch on origin. A compound is tested under each of
	// its segments and binds if any reading reaches it: for a forbid, guessing wide costs one extra
	// prompt, guessing narrow obeys a sentence the user actually said.
	const segments = pendingCategory === undefined ? [] : categorySegments(pendingCategory)
	const reaches = (row: LedgerEntry, value: string): boolean =>
		segments.length === 0
			? valueCovers(row, value, home, project)
			: segments.some((seg) => valueCovers(row, value, home, project, seg))
	// The forbid scan widens across a container; the grant that lifts a ban does not.
	const banReaches = (row: LedgerEntry, value: string): boolean =>
		reaches(row, value) || objectStoreCovers(row.value, value) === true
	const values = entities.filter((e) => e.kind === "target" || e.kind === "path").map((e) => e.value)
	for (const v of values) {
		let best: LedgerEntry | null = null
		for (const f of ledger.forbids) {
			if (f.value === "*") continue
			if (skipReadForbids && READ_CATEGORIES.has(f.category)) continue
			if (!banReaches(f, v)) continue
			if (!best || f.seq > best.seq) best = f
		}
		if (!best) continue
		const lifted = ledger.grants.some((g) => g.seq > best!.seq && reaches(g, v))
		if (!lifted) return { entity: v, entry: best }
	}
	return null
}

/** The distinct category segments of a possibly-compound category, in the order written. */
function categorySegments(category: string): string[] {
	return [...new Set(category.split("+").map((s) => s.trim()).filter(Boolean))]
}

/** The highest seq among the forbids that bind this target under this pending segment, or -1. */
function forbidSeqFor(
	ledger: Ledger,
	segment: string,
	target: string,
	home?: string,
	project?: string,
): number {
	return ledger.forbids
		.filter((f) => forbidCompatible(f.category, segment) && forbidValueCovers(f, target, home, project, segment))
		.reduce((m, f) => Math.max(m, f.seq), -1)
}

/** The defused revocation row a message left behind, if it left one.
 *
 *  A revocation defuses when code could not place what it named: a category outside the vocabulary, or a
 *  target that is a phrase rather than a name (see {@link placeableTarget}). A defused row reaches nothing by
 *  value and bans nothing — that is the point, it may not become a wildcard — so on its own it only
 *  says "this sentence withdrew something this file could not name".
 *
 *  OUTSIDE one message that is enough: `newerForbid` (strictly later) keeps such a row from being read as
 *  consent for an older grant. INSIDE one message it was not, and the gap was a false allow: extraction reads
 *  a message's grants and its revocations in ONE call, so both rows carry the same `seq` and a strictly-later
 *  test cannot see the withdrawal at all. One message that grants a folder and withdraws it again in words that
 *  describe it rather than name it is exactly that shape, and the grant won. Sameness of `seq`
 *  is what makes this the same sentence's business, so the fallback is bounded to one message and can never
 *  become a session-wide ban.
 *
 *  Deliberately NOT `forbidden: true` at the call site: the row names no capability, so the honest answer is
 *  "no auto-allow from this", which is what a deferral is — the gate's own model call, which
 *  reads the whole conversation, decides.
 */
function sameMessageDefusal(ledger: Ledger, seq: number): LedgerEntry | undefined {
	for (const f of ledger.forbids) if (f.seq === seq && f.category === UNKNOWN_FORBID_CATEGORY) return f
	return undefined
}

/** The newest forbid row in the ledger that postdates `seq`, whatever its category or value.
 *
 *  Strictly `>` matters: a row imported from a grants file carries `seq: 0` as background authority
 *  (see `LedgerEntry.origin`), so an imported file can never defer a live session's own grant — a
 *  stale file must not be able to switch the ledger off. Only a sentence from THIS transcript, whose
 *  seq is the message's ordinal, outranks a grant. */
function newerForbid(ledger: Ledger, seq: number): LedgerEntry | undefined {
	let newest: LedgerEntry | undefined
	for (const f of ledger.forbids) if (f.seq > seq && (!newest || f.seq > newest.seq)) newest = f
	return newest
}

/** Does the row fail the verb gate this lookup arms?
 *
 *  One gate, and it belongs to the SEGMENT: naming the entity is not approving the method, and "install"
 *  is the verb for the install segment only. The delete gate that used to sit beside it (`compoundHas`
 *  over the whole pending, answered by a destructive word in the quote) is gone — a delete is covered by a
 *  delete-category row and by nothing else, so the question "was this sentence about destroying?" is
 *  answered by the model's category rather than by a word list. See `grantAuthorises`. */
function verbGateMissing(segment: string, g: LedgerEntry): boolean {
	const needVerb = METHOD_VERB_REQUIRED.has(segment) ? DOING_VERB_EVIDENCE[segment] : undefined
	if (needVerb && !needVerb.test(g.quote)) return true
	return false
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
 * EVERY effect of the pending action needs its own row, over every target — the same rule
 * `grantsCover` already applies to session grants, and for the same reason.
 *
 * Reading `category.split("+")[0]` as "the" category made a compound's second effect free:
 * pending `vcs_local+vcs_remote` with a stored `vcs_remote feature/X` row reported "no matching
 * ledger entry", so the push re-prompted forever in a reported session, while the same shortcut in
 * the other direction once let a stored content grant stand in for a privilege change. Per
 * segment, a compound can only be covered by authority for each of its halves; a single-segment
 * pending takes exactly the path it always took.
 *
 * Per segment also means per-segment matching: each segment needs its own row, its own
 * METHOD_VERB_REQUIRED verb, and its own grammar — `valueCovers` is handed the segment so one
 * compound row is read with the same grammar on both of its halves. The delete-verb gate is gone,
 * so the only verb gate left is the one METHOD_VERB_REQUIRED arms for the segment it names: a pending that
 * destroys is answered by a delete-category row, not by a sentence that happens to contain a destructive
 * word, and which segment the gate happens to list first decides nothing either way.
 *
 * Seq precedence is unchanged: a matching forbid with a higher seq outrules the grant.
 *
 * On top of that, ANY forbid newer than the grant defers the decision — see {@link newerForbid}
 * for why the check is category-agnostic, and why it answers "not covered" rather than "forbidden".
 */
export function ledgerCovers(
	ledger: Ledger,
	category: string,
	entities: Entity[],
	home?: string,
	project?: string,
): LedgerVerdict {
	const segments = categorySegments(category)
	const named = entities.filter((e) => e.kind === "target").map((e) => e.value)
	// A targetless action's object IS its category (`su`, an interactive shell, a bare `systemctl`). It used to
	// bail here, so no row could ever answer it — not even the `{category, "*"}` row the prompt stored for
	// exactly that shape. The marker is what such a row matches, and nothing else: a row that names a value
	// cannot reach it (`valueCovers` → `entityMatchesTarget`), and a named pending never sees it.
	//
	// Only a pending with NO entities at all is targetless; one carrying a touched path or a scope has an object
	// the other layers already match on, and the marker must not stand in for it.
	const targets = named.length > 0 ? named : entities.length === 0 ? [NO_OBJECT_TARGET] : []
	const no: LedgerVerdict = { covered: false, forbidden: false, by: [], reason: "no matching ledger entry" }
	if (targets.length === 0 || segments.length === 0) return no

	const by: LedgerVerdict["by"] = []
	/** The newest revoke-style sentence that postdates a grant we would otherwise accept. Recorded
	 *  rather than returned on the spot: a later TARGET may hold a compatible forbid, and `forbidden`
	 *  is the stronger answer — answering early here would hide the row the user actually named. */
	let deferred: { seq: number; quote: string } | undefined
	for (const segment of segments) {
		// Each gate belongs to the segment that arms it, so segment ORDER can no longer decide
		// whether a check runs at all — the bug `compoundHas` was introduced to fix, now applied
		// per segment instead of to the whole pending.
		for (const t of targets) {
			const forbidSeq = forbidSeqFor(ledger, segment, t, home, project)
			const grant = ledger.grants.find((g) =>
				grantMatchesPending(g, segment, t, home, project) &&
				valueCovers(g, t, home, project, segment) &&
				g.seq > forbidSeq &&
				!verbGateMissing(segment, g),
			)
			if (!grant) {
				if (forbidSeq >= 0) {
					const f = ledger.forbids.find(
						(x) => x.seq === forbidSeq && forbidCompatible(x.category, segment) && forbidValueCovers(x, t, home, project, segment),
					)
					return { covered: false, forbidden: true, by: [], reason: `user forbade "${t}" ("${(f?.quote ?? "").slice(0, 80)}")` }
				}
				return no
			}
			// A revocation the user said AFTER this grant was earned defers the whole decision, even
			// when nothing in the ledger says the two rows are about the same thing.
			//
			// A revocation's category is the model's word now, which makes
			// `forbidCompatible` mean something it did not mean when this line was written — but it is
			// still not a proof that the sentence left this grant alone. Two cases survive the field:
			// a row this file could not place carries the defused label, which matches nothing by design,
			// and a withdrawal can name a different FAMILY than the grant it withdraws ("stop deleting
			// things" over a `container_mutation` grant). A recorded row that said `container_mutation`
			// binds directly; a row that says `other` does not, and deferring
			// is what keeps it from being read as consent.
			//
			// Deliberately NOT `forbidden: true`: that branch skips the transcript model call and prompts
			// on the row alone, which would turn every stale forbid into a refusal of every later grant —
			// the over-block this ledger exists to avoid. Deferring means "no auto-allow from this row",
			// and the gate's own model call, which reads the whole conversation, decides.
			// A defused revocation from the SAME message counts here too: same `seq`, so the strictly-later test
			// above cannot see it, and the sentence that withdrew the thing was in the same breath as the grant.
			const later = newerForbid(ledger, grant.seq) ?? sameMessageDefusal(ledger, grant.seq)
			if (later && (!deferred || later.seq > deferred.seq)) deferred = { seq: later.seq, quote: later.quote ?? "" }
			by.push({ entity: t, entry: grant })
		}
	}
	// Deferred, so nothing is stamped and nothing is promoted to a session grant: a row the gate did not
	// accept must not look freshly matched (`lastMatchedAt` feeds persistence and the recent-window fallback).
	if (deferred) {
		return {
			covered: false,
			forbidden: false,
			by: [],
			reason: `deferred: newer revocation seq ${deferred.seq} ("${deferred.quote.slice(0, 80)}")`,
		}
	}
	const now = Date.now()
	for (const m of by) m.entry.lastMatchedAt = now
	return { covered: true, forbidden: false, by, reason: `ledger: ${by.map((m) => `${m.entity}←"${m.entry.value}"`).join(", ")}` }
}

/**
 * Why the ledger answered the way it did, one line per candidate row. Pure: unlike
 * {@link ledgerCovers} it touches nothing (no `lastMatchedAt`, no promotion to a session grant), so
 * it is safe to call from a read-only command on a ledger the gate is using.
 *
 * This exists because "decided by: classifier" was the only thing a user got for a grant that was
 * sitting right there under a value that did not quite match. Every line is produced by the SAME
 * predicates the gate uses — `grantAuthorises`, `valueCovers`, the per-segment verb gate, seq
 * precedence — so the explanation cannot promise coverage the gate would not give: the verdicts here
 * are computed from the row and the pending action, never asserted.
 *
 * A candidate is any grant row that is about this pending at all: same kind group under some segment,
 * or a value that reaches some target under some segment. The second half of that test is what puts
 * `vcs_remote docker` on the page for a `container_mutation+network_send` push, which is the row the
 * user needs to see when they are told the push is not authorised.
 *
 * Reasons, in the order the gate reaches them: `group` (the row's category does not authorise any
 * segment of this pending), `value` (it authorises a segment but does not reach this target), `verb`
 * (it reaches, but the user's own words never named the method the segment requires), `forbid seq n`
 * (a ban outranks it), `deferred: newer revocation seq n` (a sentence said after this row, which this
 * file cannot place, took the decision away from it), and per segment `segment X uncovered` for the
 * effects no row reached at all.
 */
export function explainLedgerCover(
	ledger: Ledger,
	category: string,
	entities: Entity[],
	home?: string,
	project?: string,
): string[] {
	const segments = categorySegments(category)
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const lines = new Set<string>()
	if (segments.length === 0 || targets.length === 0) return []

	const label = (g: LedgerEntry): string => `row ${g.category} "${g.value}" seq ${g.seq}`
	const candidates = ledger.grants.filter(
		(g) =>
			segments.some((seg) => grantAuthorises(g, seg)) ||
			targets.some((t) => segments.some((seg) => valueCovers(g, t, home, project, seg))),
	)

	const covered = new Map<string, Set<string>>(segments.map((seg) => [seg, new Set<string>()]))
	for (const target of targets) {
		for (const g of candidates) {
			const fitting = segments.filter((seg) => grantAuthorises(g, seg))
			if (fitting.length === 0) {
				lines.add(`${label(g)}: rejected: group`)
				continue
			}
			const reaching = fitting.filter((seg) => grantMatchesPending(g, seg, target, home, project))
			if (reaching.length === 0) {
				lines.add(`${label(g)}: rejected: value`)
				continue
			}
			const spoken = reaching.filter((seg) => !verbGateMissing(seg, g))
			if (spoken.length === 0) {
				lines.add(`${label(g)}: rejected: verb`)
				continue
			}
			const blockers = spoken.map((seg) => forbidSeqFor(ledger, seg, target, home, project))
			const allowed = spoken.filter((_, i) => g.seq > blockers[i]!)
			if (allowed.length === 0) {
				lines.add(`${label(g)}: rejected: forbid seq ${Math.max(...blockers)}`)
				continue
			}
			// The same deferral `ledgerCovers` returns, worded the same way, so an explanation can never
			// promise a coverage the gate would refuse (the invariant of this whole function).
			const later = newerForbid(ledger, g.seq)
			if (later) {
				lines.add(`${label(g)}: deferred: newer revocation seq ${later.seq} ("${later.quote.slice(0, 80)}")`)
				continue
			}
			lines.add(`${label(g)}: covers ${target}`)
			for (const seg of allowed) covered.get(seg)!.add(target)
		}
	}

	for (const seg of segments) {
		const missing = targets.filter((t) => !covered.get(seg)!.has(t))
		if (missing.length > 0) lines.add(`segment ${seg} uncovered: ${missing.join(", ")}`)
	}
	return [...lines]
}

// ---------------------------------------------------------------- extraction → events

export type MessageGrantExtraction = {
	grants: Array<{
		/** Display label. Nothing here reads it (the extraction prompt says the same). */
		action?: string
		/** Enum value from GRANT_CATEGORY_VALUES — the only category a grant row can get. */
		category?: string
		/** entity = this target only; scope = everything under this location. */
		kind?: string
		/** How far the permission reaches: `named` | `category` | `everything`. */
		scope?: string
		/** A class the permission names instead of a path — `temp_files` or `none`. A grant can never
		 *  name `rule_files`: that class exists on the revocation side only, so the plugin's own allow-list
		 *  is unreachable from a permission the model was asked to read. */
		targetClass?: string
		includesSecrets?: boolean
		targets: string[]
		quote: string
	}>
	revocations: Array<{
		/** Display label, never read. */
		action?: string
		/** Enum value(s) from REVOCATION_CATEGORY_VALUES: which kinds of work were withdrawn. A list;
		 *  the single string the field used to be is still accepted, because recordings and older endpoints send
		 *  it, and it means the one-element list. */
		category?: string | string[]
		/** How far the withdrawal reaches: `named` | `category` | `everything`. */
		scope?: string
		/** A class the withdrawal names instead of a path; `rule_files` or `none`. */
		targetClass?: string
		/** The names the user withdrew work on — every one of them verified against the message. */
		targets: string[]
		/** Width on the wire that predates `scope`. NOT READ: `scope` is the one field that answers
		 *  how wide a row is, and two fields for one question is a disagreement code would have to
		 *  arbitrate. Kept on the type so recordings made against the old schema still type. */
		all?: boolean
		quote: string
	}>
}

function quoteInMessage(quote: string, message: string): boolean {
	const q = quote.replace(/\s+/g, " ").trim().toLowerCase()
	if (q.length < 3) return false
	return message.replace(/\s+/g, " ").trim().toLowerCase().includes(q)
}

function targetKind(value: string): "entity" | "scope" {
	return value.endsWith("/") ? "scope" : "entity"
}

/**
 * Can code place this value at all — that is, can it ever be compared with something the gate produces?
 *
 * The verbatim check (`targetNamedByUser`) owns the half of a target that is about the user's words: did they
 * say it. This owns the other half, which is about the value's SHAPE: is it a name. Every matcher in this tree
 * addresses a thing by `/`-separated components, so a value carrying a space is a phrase — "build artefacts",
 * "the certificates directory" — and can only ever match by the accident of `entityMatchesTarget`'s
 * noun-phrase rule (`target-grammar.ts`'s `clean()` refuses the same shape for the same reason).
 *
 * Nothing here asks what the phrase MEANS, which is the thing code must not do with a sentence: the value is not
 * interpreted, not corrected and not refused. A row whose target is unplaceable is kept exactly as the model
 * wrote it (it may still match by noun components); all this decides is whether the fold leaves the defused
 * marker row beside it, which is what stops a grant from the SAME message answering the sentence that
 * withdrew it.
 */
function placeableTarget(value: string): boolean {
	return !/\s/.test(value.trim())
}

/**
 * The three width values the extraction schema offers — the same machine tokens as `SCOPE_VALUES` in
 * `model-client.ts`, restated here because this file does not import the wire module. `named` = only
 * what the row's target list names; `category` = every target of the ONE category the row names;
 * `everything` = every kind of action at once.
 *
 * The question "how wide is this row" has exactly one answer field and this is where it is read. No
 * paraphrase of the sentence is consulted, in this function or anywhere else on this path.
 */
const EXTRACTION_SCOPES = ["named", "category", "everything"] as const
type ExtractionScope = (typeof EXTRACTION_SCOPES)[number]

/** The row's width, or `undefined` when the row did not answer. An unusable value reads as no answer,
 *  and no answer is treated as the NARROWEST width, never the widest: a row the code cannot
 *  place may cost one prompt, it may never arm a session lock. */
function extractionScope(value: unknown): ExtractionScope | undefined {
	const s = typeof value === "string" ? value.trim().toLowerCase() : ""
	return (EXTRACTION_SCOPES as readonly string[]).includes(s) ? (s as ExtractionScope) : undefined
}

/** The model's category, kept only when the enum it was offered actually contains it and the gate can
 *  match it. `"other"` is the model's own "nothing fits", so it names no capability either. */
function extractionCategory(value: unknown): string | undefined {
	const c = typeof value === "string" ? value.trim().toLowerCase() : ""
	return c !== "" && c !== "other" && isGrantCategory(c) ? c : undefined
}

/**
 * A revocation's category LIST, kept only as far as the enum it was offered contains it.
 *
 * The wire asks for a list; a row that arrives with a bare string (an endpoint ignoring the schema, a
 * recording made against the older schema) is read as the one-element list it means, so old captures still
 * fold. Values outside the revocation enum, and `"other"`, name no capability and are dropped — dropping may
 * make the row unusable (the caller then defuses it), it may never make it wider.
 *
 * A list LONGER than the schema allows is not a partial truth to keep: it is an answer that did not come from
 * this schema, so the whole list is refused and the row defuses. Keeping the first six would quietly drop a
 * category the user named, which is the one thing a forbid may not lose.
 */
function extractionCategories(value: unknown): string[] {
	const list = Array.isArray(value) ? value : typeof value === "string" ? [value] : []
	if (list.length === 0 || list.length > MAX_REVOCATION_CATEGORIES) return []
	const out: string[] = []
	for (const item of list) {
		const c = typeof item === "string" ? item.trim().toLowerCase() : ""
		if (c === "" || c === "other" || !isRevocationCategory(c)) continue
		if (!out.includes(c)) out.push(c)
	}
	return out
}

/**
 * The category of a forbid row the code could not place.
 *
 * It replaces three things at once: the `"*"` category this file used to infer from a sentence's
 * verbs, the read-only posture the same inference used to arm, and the `*action*` label it invented
 * from a display label. `kindGroup` of it is itself, so it can never equal a pending group and can
 * never produce a `forbidden` verdict — the sentence is kept in the ledger for audit and authorises
 * nothing, while `newerForbid` (which reads every forbid regardless of category) still takes the
 * auto-allow away from any older grant, which costs one model call.
 *
 * Never `"*"`, never a posture: a missing value may not become a wildcard.
 */
const UNKNOWN_FORBID_CATEGORY = "*unknown*"

/**
 * How many categories one revocation may name. The wire schema caps the list here
 * (`MAX_REVOCATION_CATEGORIES` is sent as `maxItems` by `model-client.ts`), and the ledger refuses a longer
 * answer rather than keeping a prefix of it — a forbid that quietly loses one of the categories the user named
 * is a weaker ban that looks like the sentence was obeyed.
 */
export const MAX_REVOCATION_CATEGORIES = 6

/** The one target class a revocation may name instead of a path (`targetClass` in the schema). */
const RULE_FILE_CLASS = "rule_files"

/** The paths that class names, spelled the way the gate RENDERS them — `~/…` outside the project,
 *  `./…` inside — because `canonicalPath` resolves both halves at match time against the caller's
 *  own home and project root. Hardcoding an absolute `/home/<user>` here would match nobody else.
 *  The `*` row of `permissions-loader`'s project layer lives under `.pi/projects/<id>/`, which no
 *  session can spell without the cwd, hence the project-relative form for that half. */
const RULE_FILE_PATHS = ["~/.pi/agent/adaptive-acl.json", "./.pi/projects/"]

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

// ---------------------------------------------------------------- category audit

/**
 * Count a category the row's own targets do not fit — counted only, never applied.
 *
 * The finding was an image push filed under a git category: the stored row was unreachable from
 * any wording, and nothing anywhere said so. This file may not answer that disagreement by
 * overriding the model — the model's category is what gets stored — but it may notice, because the
 * only thing code knows deterministically about a target is its own grammar: `host/repo:tag` and
 * `remote/branch` are machine syntax, not English vocabulary, and the two grammars are disjoint.
 *
 * So the check asks one shape question: do NONE of the targets parse under the grammar this category
 * uses, while SOME of them parse under the other one? Yes means "this row is filed under a category
 * whose targets look like something else" — a number worth showing in `/classifier-status`, worth
 * nothing to the matcher.
 */
function categoryDisagreesWithTargets(category: string, targets: string[]): boolean {
	const grammar = grammarFor(primarySegment(category))
	if (grammar === undefined || targets.length === 0) return false
	const parses = (value: string, want: "vcs" | "image"): boolean =>
		want === "vcs"
			? parseVcsTarget(value)?.branch !== undefined
			: parseImageRef(value)?.repo !== undefined
		const other = grammar === "vcs" ? "image" : "vcs"
		const mine = targets.some((t) => parses(t, grammar))
		const theirs = targets.some((t) => parses(t, other))
		return !mine && theirs
}

/** Split the verified quote into candidate target tokens. `:` and `@` survive: `HEAD:refs/heads/x` and
 *  `myrepo/app:1.0@sha256:…` are each ONE token. */
const TOKEN_SPLIT_RE = /[\s,;!?()\[\]{}<>"'`]+/

/** The tools a user names when they meant the command rather than a target. */
const TOOL_NAME_WORDS = new Set(["docker", "podman", "nerdctl", "git", "gh", "helm", "kubectl", "pip", "npm"])

/** Words that PARSE as a one-component ref without being names: verbs, kind-words, tools. Storing one
 *  is the dead-row bug in a new costume (`vcs_remote push` covers nothing and hides the fact that the
 *  sentence named no ref), so they are evidence for the rules below and never a value. */
const NOT_A_TARGET_NAME = new Set([
	...TOOL_NAME_WORDS,
	// Kind-words: they PARSE as a one-component ref and name nothing. Spelled out here (they used to
	// live in a separate set that also served the revocation path, where its word list is
	// gone) because this list is only ever consulted at the door of a grammar value, never as evidence
	// about a sentence.
	"image", "images", "container", "containers", "file", "files", "folder", "folders",
	"directory", "directories", "dir", "dirs", "table", "tables", "database", "databases",
	"db", "dbs", "package", "packages", "service", "services", "pod", "pods",
	"namespace", "namespaces", "volume", "volumes", "data", "backup", "backups", "dump",
	"dumps", "server", "servers", "process", "processes",
	// The vocabulary of this specific permission: `tag` was in neither older list (no one was granting
	// tags yet), and a bare kind-word parses as a repo named "tag".
	"tag", "tags", "ref", "refs", "branch", "branches", "remote", "repository", "repositories",
	"repo", "repos", "registry", "push", "publish", "upload", "release", "pull", "pr", "request",
	"head", "workflow", "job", "runner",
])

/**
 * A token that names WHERE rather than WHAT: a conventional remote or a bare host.
 *
 * `target-grammar` can read `origin` as "every branch on origin" because it has the pending target's
 * remote to compare against; here there is no pending, so a token of this shape is always the remote
 * half of a value and never a branch called `origin`.
 */
function remoteOrHostLike(token: string): boolean {
	if (token.includes("/")) return false
	return /^(?:origin|upstream)$/i.test(token) || /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?::\d+)?$/i.test(token)
}

/** A URL is a real `network_send` target that the image grammar refuses on purpose (a URL is
 *  neither a ref nor an image). Keeping the string is not a guess — it is what the fallback matcher
 *  in `valueCovers` will be compared against anyway. */
const URL_TOKEN_RE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i

function quoteTokens(text: string): string[] {
	return text
		.split(TOKEN_SPLIT_RE)
		.map((t) => t.replace(/^["'`]+/, "").replace(/[.,;:!?"'`]+$/g, ""))
		.filter(Boolean)
}

function imageSpelling(ref: ImageRef): string {
	const name = [ref.registry, ref.repo].filter((p): p is string => p !== undefined && p !== "").join("/")
	return `${name}${ref.tag ? `:${ref.tag}` : ""}${ref.digest ? `@${ref.digest}` : ""}`
}

/** Rule (i): one candidate token → the gate's own spelling, or nothing to store. */
function targetFromToken(grammar: "vcs" | "image", token: string, tokens: string[]): string | undefined {
	if (token.length < 2 || NOT_A_TARGET_NAME.has(token.toLowerCase())) return undefined
	if (grammar === "vcs") {
		if (remoteOrHostLike(token)) return undefined
		const ref = parseVcsTarget(token)
		if (!ref || ref.branch === undefined) return undefined
		// A branch named in the same breath as its remote is stored the way the gate emits it
		// (`remote/branch`), which is also the spelling that covers a `--mirror`-style target.
		const remote = ref.remote ?? tokens.find((t) => t !== token && remoteOrHostLike(t))
		return remote ? `${remote}/${ref.branch}` : ref.branch
	}
	if (URL_TOKEN_RE.test(token)) return token
	const ref = parseImageRef(token)
	// A registry alone (`ghcr.io`) names no artifact: that is rule (ii)'s answer, not this one.
	if (!ref || ref.repo === undefined) return undefined
	return imageSpelling(ref)
}

/**
 * Turn the targets of one extraction into values the matcher can actually use, or into NO row.
 *
 * Tried in order, first answer wins:
 *  (i)  a ref-shaped token in the verified quote → the parsed value, in the gate's own spelling;
 *  (ii) `scope: "category"` — the model's own "every object of that kind" — → the grammar's wildcard:
 *       `origin/*` for refs, the registry host for images, `*` when the row scoped no place at all
 *       (and NOTHING when it scoped a place this file cannot verify — `*` would be wider than the row);
 *  (iii) nothing else. Prose ("the new branch", "any branch" as a bare object under a `named` row) is
 *       NEVER stored, because a row that can never match anything is worse than no row — it shows up
 *       in `/grants` as authority the gate does not have. The verified quote still reaches the
 *       grant-model call unchanged, so the sentence is not lost, only not laundered into a value.
 *
 * Every value must also pass `namedByUserStructurally` against the message: the anti-hallucination
 * bound is that the user's own words name every component the row names (`origin/*` is storable from
 * "any branch on origin", which the older whole-token rule could never have stored).
 */
function normaliseTargets(
	category: string,
	targets: string[],
	quote: string,
	messageText: string,
	scope: ExtractionScope | undefined,
): string[] {
	const segment = primarySegment(category)
	const grammar = grammarFor(segment)
	if (grammar === undefined) return []
	const tokens = quoteTokens(quote)
	const named = (value: string): boolean => namedByUserStructurally(segment, value, messageText) === true

	// Candidates: the model's targets, plus anything in the verified quote shaped like a ref. Quote-only
	// tokens are allowed because the quote has already been matched into the message word for word, and
	// every value still has to pass the structural check below before it is stored.
	const candidates = new Set<string>()
	for (const t of targets) candidates.add(t.trim())
	for (const t of tokens) if (t.includes("/") || t.includes(":")) candidates.add(t)

	const specific: string[] = []
	for (const token of candidates) {
		const value = targetFromToken(grammar, token, tokens)
		if (value !== undefined && named(value) && !specific.includes(value)) specific.push(value)
	}
	if (specific.length > 0) return specific

	// Width comes from the field. Two English rules used to stand in for it: a quantifier three words
	// from a kind-word, and a publish verb that made the difference between a noun phrase and a
	// permission. Both are gone — `scope` answers the question, and a row that did not answer it gets no
	// wildcard.
	if (scope !== "category") return []
	// The wildcard's spelling belongs to the grammar: `origin/*` for refs; a bare registry host for
	// images, because the image grammar has no `registry/*` form and reads a registry-only row as
	// "everything in it"; and the bare `*` when the sentence named no place at all.
	const place = tokens.find(remoteOrHostLike)
	if (place !== undefined) {
		const value = grammar === "vcs" ? `${place}/*` : place
		// A place the user's own words never named is DROPPED, not widened to `*`.
		return named(value) ? [value] : []
	}
	// `*` means "every object of this kind, anywhere", so it is only honest when the ROW scoped nothing.
	// If the model's own target list names a place this file cannot verify against the message, `*` would
	// be wider than the row it was handed — a filter making a row broader than the model asked for, which
	// is exactly what a value filter may never do — so such a row registers nothing and costs one prompt instead.
	if (targets.some((t) => remoteOrHostLike(t.trim()))) return []
	return ["*"]
}

/**
 * Convert one message's extraction into ledger events.
 *
 * Every decision here comes from a structured field the model returned, plus the one bound code is
 * allowed to enforce on prose: a quote must appear verbatim in the message (`quoteInMessage`) and a
 * target must appear verbatim in it too (`targetNamedByUser`). No sentence is asked what it meant —
 * not the category, not the width, not whether a sentence re-enables changes, not whether a target is
 * a pronoun. What is left is precedence and the fail-safe choice, which is all code owns.
 *
 * What garbage costs, per path:
 *  - a grant with a missing or unusable category produces NO row → one prompt, never an allow;
 *  - a grant that names no object and did not answer `scope: "category"` produces NO row (counted): a
 *    missing value never becomes a wildcard, so "force-push it" buys nothing at all;
 *  - a revocation with a missing or unusable width produces one defused `*unknown*` row → the sentence
 *    is kept and takes the auto-allow away from every older grant, which sends the pending action to
 *    the gate's own model call. It never arms the session posture and never becomes a `"*"` category;
 *  - a target the user's words do not contain is dropped. Dropping may make a row unusable and may
 *    never widen it.
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
		const scope = extractionScope(g.scope)
		// `everything` on a grant is the user taking a stop back and nothing more — the schema prompt is
		// explicit that such a row authorises nothing further — so it lifts the posture and produces no
		// grant. The phrase list that used to decide that by reading the quote is gone: a row that did not
		// answer the width question lifts nothing, and one that answered `everything` needs no verb beside it.
		if (scope === "everything") {
			out.push({ type: "readonly-off", category: "*", value: "*", kind: "scope", quote, messageId, seq })
			continue
		}
		const category = extractionCategory(g.category)
		if (category === undefined) {
			// No category the gate can match: the endpoint ignored the enum, or answered "other". The word
			// list that used to guess one from the display label is gone, so this row registers nothing
			// and the work behind it costs its normal prompt. Counted, because a grant that silently did
			// not register is otherwise indistinguishable from a sentence the user never said.
			extractionStats.unmapped++
			extractionStats.lastUnmapped = String(g.action ?? "").slice(0, 80)
			continue
		}
		extractionStats.fromSchema++
		extractionStats.mapped++
		// A category the row's own targets do not look like is counted here and nowhere else.
		if (categoryDisagreesWithTargets(category, g.targets ?? [])) extractionStats.crossChecked++
		// Structural fields, not phrases: the model says whether this is a location and whether the
		// user's words included credentials. Absent means the narrow answer.
		const wantsScope = String(g.kind ?? "") === "scope"
		const includesSecrets = g.includesSecrets === true
		if (wantsScope) extractionStats.scopes++
		if (includesSecrets) extractionStats.secretInclusions++
		const targets = (g.targets ?? []).map(String).filter((t) => t.trim().length >= 2)
		// The TEMP-FILES class. The user's sentence contains no path — the object of "you may write
		// temporary files" is a CLASS — so there is nothing for the verbatim target check to find and the
		// check must not be what decides the row. Code owns the class → directories mapping
		// (`tempGrantDirs`), the model owns the decision that this sentence was about that class, and the
		// quote check above still applies to every row: a quote that is not in the message registers nothing.
		//
		// Garbage answers, in order: a class value outside the enum became "none" in the parser and this row
		// takes its normal target-shaped path; a class on a category that cannot live in a temp dir
		// registers nothing and is counted, which costs the one prompt it would have cost anyway; nothing
		// here can arm a session lock or allow an action the user did not name.
		if (String(g.targetClass ?? "") === "temp_files") {
			const dirs = TEMP_CLASS_CATEGORIES.has(category) ? tempGrantDirs() : []
			if (dirs.length === 0) {
				extractionStats.unmapped++
				extractionStats.lastUnmapped = String(g.action ?? "").slice(0, 80)
				continue
			}
			// One SCOPE row per temp root: reading under it arrives through write-implies-read, and a
			// second effect the user named ("and run them too") arrives as its own row, because "one row PER
			// EFFECT" is the extraction prompt's rule, not a guess this file makes.
			for (const dir of dirs) {
				out.push({ type: "grant", category, value: `${dir}/`, kind: "scope", quote, messageId, seq })
			}
			continue
		}
		// The MACHINE classes, same shape as the temp class above — code owns the mapping, the model owns
		// the decision that the sentence was about that machine, and the quote check still applies.
		// Garbage answers: a class outside the enum became `none` in the parser and the row takes its normal
		// target-shaped path; a class on a category that is not a machine read (a delete, a push, a secret)
		// registers NOTHING and is counted, costing the prompt it would have cost anyway; an ambiguous
		// "my cluster" registers nothing. None of those paths can arm a lock or allow anything.
		const machineClass = String(g.targetClass ?? "")
		if (MACHINE_TARGET_CLASSES.has(machineClass)) {
			// A class and a name in one row is a disagreement, and code may not arbitrate it by
			// picking the wider reading. The NAMED target wins and the class is dropped: the target has a verbatim
			// check behind it, and a row whose quote names `buildhost` must not quietly become a grant over THIS
			// machine, which the user never named. Dropping the class costs a prompt; taking it would have been an
			// allow nobody gave.
			const namedTargets = (g.targets ?? []).map(String).filter((t) => t.trim().length >= 2)
			if (namedTargets.length > 0) {
				for (const t of namedTargets) {
					if (!targetNamedByUser(t, [messageText])) continue
					out.push({ type: "grant", category, value: t, kind: targetKind(t), quote, messageId, seq })
				}
				continue
			}
			const object = machineClass === "local_machine"
				? LOCAL_MACHINE_OBJECT
				: singleClusterContext()
			if (category !== "read_system_state" || object === undefined) {
				extractionStats.unmapped++
				extractionStats.lastUnmapped = String(g.action ?? "").slice(0, 80)
				continue
			}
			// One ENTITY row: "this machine" is one object, not a location with things under it, and the class
			// must not read as a wildcard over the category the way a `scope` row would.
			out.push({ type: "grant", category, value: object, kind: "entity", quote, messageId, seq })
			continue
		}
		// A row that says "every object of that kind" and names no ref is answered by the grammar's own
		// wildcard, and that is the ONLY way a wildcard grant is produced any more: the quantifier regex
		// ("any branch" three words from a kind-word) and the publish-verb rule that used to stand in for
		// the width field are gone. Checked before the bare-verb path so a `category` row is answered by
		// the field rather than by whether the quote happens to contain the verb.
		const grammar = grammarFor(primarySegment(category))
		if (grammar !== undefined && scope === "category") {
			for (const value of normaliseTargets(category, targets, quote, messageText, scope)) {
				out.push({ type: "grant", category, value, kind: "entity", quote, messageId, seq })
			}
			continue
		}
		if (targets.length === 0) {
			// A row with no object in it is a wildcard only on the model's own word for it. `scope` is the
			// width field; "named" with nothing named is a MISSING VALUE, and a missing value must never
			// become `*`: "force-push it" / "drop that table" name nothing, so the row registers
			// nothing and costs the one prompt it would have cost anyway — instead of `vcs_remote *`
			// (push any ref anywhere) or `delete_data *` from three words with a pronoun object.
			// A `category` row is still honoured, but only for the categories whose whole meaning IS a verb
			// (the quote must carry it), and only for the ones with no grammar — a grammar category that
			// answered `category` was already answered by its own wildcard above, and its `*` spelling is
			// `origin/*`/registry host, not this bare form.
			const verbRe = scope === "category" ? DOING_VERB_EVIDENCE[category] : undefined
			if (verbRe !== undefined && verbRe.test(quote)) {
				out.push({ type: "grant", category, value: "*", kind: "scope", quote, messageId, seq })
				continue
			}
			// Counted, not silent: "the grant did not register" and "the user never said it" have to stay
			// distinguishable from outside, and this is the counter /classifier-status prints.
			extractionStats.unmapped++
			extractionStats.lastUnmapped = String(g.action ?? "").slice(0, 80)
			continue
		}
		// Git/image targets are TYPED. Under a grammar category the model's target strings are never
		// stored verbatim: they are normalised into the spelling the matcher reads, or the sentence
		// produces no row at all. `kind: "scope"` means nothing here either — the scope of a git
		// ref is `remote/*`, which the wildcard rule above answers from the model's `scope` field.
		if (grammar !== undefined) {
			for (const value of normaliseTargets(category, targets, quote, messageText, scope)) {
				out.push({ type: "grant", category, value, kind: "entity", quote, messageId, seq })
			}
			continue
		}
		for (const t of targets) {
			if (!targetNamedByUser(t, [messageText])) continue
			if (wantsScope) {
				// One folder permission, not one grant per file inside it. This is the model's own
				// `kind: "scope"` and now the only source of a folder grant: the "in|under|inside <path>"
				// regex that read the preposition out of the sentence is gone, so a folder the model did
				// not mark as a location registers as its own name — the narrow answer, not the wide one.
				// Note the failure direction stays fail-safe either way: a FILE path marked as a scope
				// keeps its own name and cannot reach a sibling.
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
			// One row per effect is the extraction prompt's job ("one row PER EFFECT"), so the compound a
			// sentence describes arrives as sibling rows — including the elevated-rights half. The sudo
			// regex that used to synthesise a `privilege` row from a method word inside the quote is gone:
			// reading HOW a thing was done to infer that the user authorised it is exactly the inference
			// this file no longer makes.
			out.push({ type: "grant", category, value: t, kind: targetKind(t), quote, messageId, seq })
		}
	}
	for (const r of x.revocations ?? []) {
		const quote = String(r.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		const scope = extractionScope(r.scope)
		// The kinds the sentence withdrew, as a LIST — a withdrawal can name several actions, or every
		// action, on one thing. A row that arrives with a single string is read as the one-element list it
		// means, so recordings made against the old schema fold unchanged.
		const categories = extractionCategories(r.category)
		// `any` is every action on the named thing, so no other value adds anything to a row that carries it:
		// one `any` row per target replaces the list rather than sitting beside it.
		const saysAny = categories.includes(FORBID_ANY_CATEGORY)
		// The session posture, from the field alone: `everything` is the model's answer to "nothing may
		// change". Three regexes used to second-guess that answer in both directions — arming a lock on a
		// scoping complaint ("you will not search half a tb of files in my home to find clues") and
		// declining to arm on a real one — and both directions belong to the model now. A wrong
		// `everything` is therefore the one garbage answer that can cost more than one prompt; what it
		// costs is prompts, and any later `everything` grant or `/grants revoke` ends it.
		if (scope === "everything") {
			out.push({ type: "readonly-on", category: "*", value: "*", kind: "scope", quote, messageId, seq })
			continue
		}
		const targets = (r.targets ?? []).map(String).filter((t) => t.trim().length >= 2)
		// The only judgement code makes about a target: whether the user's own words contain it. Pronouns
		// and kind-words are no longer recognised and dropped here — they ARE in the message, so they
		// pass, and a value that no real path or ref can equal costs one prompt later.
		const named = targets.filter((t) => targetNamedByUser(t, [messageText]))
		// A withdrawal whose target is a PHRASE is verbatim-correct and unplaceable: no entity the gate produces
		// will equal it, so its forbid rows reach nothing on their own. The sentence is kept as the model wrote it
		// and the defused marker is left beside it, because a grant extracted from the SAME message would
		// otherwise answer the very action the user had just withdrawn — the false allow where the grant
		// and the withdrawal came out of one message and the grant was allowed to speak for both. The marker can
		// match no category and no value, so it bans nothing, licenses nothing, and cannot outlive its message.
		for (const t of named) {
			if (placeableTarget(t)) continue
			out.push({ type: "forbid", category: UNKNOWN_FORBID_CATEGORY, value: t, kind: targetKind(t), quote, messageId, seq })
		}
		// A target CLASS is neither a name nor model invention: the sentence was verified verbatim above
		// and the paths are this code's own knowledge of where its rule files live, so they are not put
		// through a naming check they could never pass. It resolves BEFORE the category is checked because
		// the class is narrower than the wildcard: recorded, a smaller model answers
		// `{category: "other", scope: "category", targetClass: "rule_files"}` to "I do not want to use ANY
		// permission files", and an unusable category must not throw away the paths the sentence did name
		// in favour of `value: "*"`.
		const targetClass = String(r.targetClass ?? "").trim().toLowerCase()
		const values = named.length > 0 ? named : targetClass === RULE_FILE_CLASS ? RULE_FILE_PATHS : []
		// Every action withdrawn and no object named is the whole-session stop — `any` with
		// no targets, and the direction that blocks more, never less: a targetless forbid row is ignored by the
		// named-forbid scan, the posture refuses every ask/unknown mutation from the next action onward.
		//
		// Only when the MODEL named nothing. Targets the model named but the verbatim check could not find in
		// the message mean a row this file cannot place, and an unusable row costs one model call — it may not
		// arm a session lock, so that case falls through to the defused row below.
		if (saysAny && values.length === 0 && targets.length === 0) {
			out.push({ type: "readonly-on", category: "*", value: "*", kind: "scope", quote, messageId, seq })
			// A posture is a DEFAULT, not a veto: `readOnlyLiftedByGrant` lets a grant made after it authorise a
			// target, and the gate consults grants before the posture at all. So a stop the model described as
			// every-action-on-everything-of-one-kind has to leave a BAN behind too, or it ranks below a grant the
			// user gave before they spoke. Measured on one model: the same sentence filed as
			// `forbid container_mutation *` prompted, and filed as `readonly-on *` came back allow-granted — the
			// wider word, the weaker effect. The invariant for `any` with nothing named is "blocks more,
			// never less", and only this row makes it true. The width is the model's own `category` scope: at
			// `named` with nothing named the posture is already wider than anything code may write.
			if (scope === "category") {
				out.push({ type: "forbid", category: FORBID_ANY_CATEGORY, value: "*", kind: "scope", quote, messageId, seq })
			}
			continue
		}
		// The categories the rows carry: the model's list, `any` alone when the list said so, or the defused
		// label that can never equal a pending group. A defused row never answers `forbidden` —
		// `forbidCompatible` cannot match it — while `newerForbid` reads every forbid whatever its
		// category and still takes the auto-allow away from any older grant, so an unusable category costs one
		// model call and never an allow.
		const rowCategories = saysAny ? [FORBID_ANY_CATEGORY] : categories.length > 0 ? categories : [UNKNOWN_FORBID_CATEGORY]
		if (values.length === 0) {
			// Nothing to put a row on. `category` width plus a category the gate can match is the model's
			// own "every target of this one kind", and it is the only path that may produce the
			// category-wide value; `everything` was answered above, and a width the code cannot read
			// keeps the sentence defused rather than blanket. A list fans out to one category-wide
			// row per kind named, because a ban that answers only the first of them is a weaker ban than the
			// sentence the user spoke.
			const wide = scope === "category" && categories.length > 0
			for (const wideCategory of wide ? categories : [UNKNOWN_FORBID_CATEGORY]) {
				out.push({
					type: "forbid",
					category: wideCategory,
					value: "*",
					kind: "scope",
					quote,
					messageId,
					seq,
				})
			}
			continue
		}
		// A row that named a thing forbids that thing, under each category the model named. The `"*"`
		// category this file used to infer for a named target — "every category AT THIS PATH", read off
		// whether the sentence contained a mutating verb — is gone with the regex that read it: a named
		// row reaches what the model's own answer reaches, and what it does not reach goes to the gate's
		// model call instead of being guessed here. `any` is the answer the model may give when the sentence
		// withdrew all of them at once, and `forbidCompatible` makes that one row bind under every segment.
		for (const t of values) {
			for (const rowCategory of rowCategories) {
				// The shape belongs to the CATEGORY, not to the sentence: a withdrawal of two kinds is a read
				// row and a mutation row, and only the mutation half needs the subtree pair.
				const shapeOnce = named.length === 0 || READ_CATEGORIES.has(rowCategory)
				if (shapeOnce) {
					// One row for one sentence: the read categories (a negated read must not outrank a write,
					// and must not arrive twice), the class paths (the code's own list, shaped once here) and
					// nothing else that needs two rows to say one thing.
					const row = singleRowShape(t)
					out.push({ type: "forbid", category: rowCategory, value: row.value, kind: row.kind, quote, messageId, seq })
					continue
				}
				out.push({ type: "forbid", category: rowCategory, value: t, kind: targetKind(t), quote, messageId, seq })
				// AND across the subtree, because a grant can be a folder permission and a revocation naming
				// the same location has to reach everything that grant reaches, or "stop, don't delete
				// anything under ~/scratch-data" would leave the earlier folder grant authorising files inside
				// it. That is a real false allow, and it is how this row was found: eval case L-02.
				//
				// Widening a FORBID is fail-safe in a way widening a grant is not: the worst case is one extra
				// prompt, never an unapproved action. A later grant naming the value still lifts it by seq.
				if (!t.endsWith("/")) {
					out.push({ type: "forbid", category: rowCategory, value: `${t}/`, kind: "scope", quote, messageId, seq })
				}
			}
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
 * Import a grants file's ledger into `target`.
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
