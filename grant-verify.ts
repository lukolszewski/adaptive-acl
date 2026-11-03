/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Code-side verification of transcript authorisation (docs/CLASSIFIER-SPEC.md §3.3, §4.2).
 *
 * The model only *extracts* what the user allowed/forbade; nothing it says can
 * widen an approval past these checks. All matching is deterministic.
 */

import type { Entity } from "./risk-policy.ts"
import { coversByGrammar, grammarFor, parseVcsTarget } from "./target-grammar.ts"

/**
 * The value an action carries when its OBJECT is its category rather than a name somebody could say.
 *
 * `su` is "be another user", an interactive shell is "hand this terminal to a human", a bare `systemctl` is the
 * tool's own usage: the capability IS the category, so there is no noun to put in a target list. Layer 0
 * (`risk-handlers.ts`) labels those rows with this marker so that the answer a prompt stores —
 * `{category, "*"}` — can match them, and so that the prompt says what it is about.
 *
 * The marker is NOT a wildcard for a NAMED target, and the matchers keep that separation:
 *  · a stored row `{category, "*"}` matches the marker, and a named target never does;
 *  · a stored row naming a value (`pi`, `~/out/`) does not match the marker — see `entityMatchesTarget`,
 *    where a one-component target must equal a component of the entity;
 *  · the extraction door cannot produce it: a model-named target has to be a whole token the user wrote, and
 *    `targetVariants` refuses a value shorter than two characters.
 * That is what makes the row a faithful record of "the user approved a targetless action of this category":
 * it can never answer an action that names something.
 */
export const NO_OBJECT_TARGET = "*"

/** The targets an action actually names, with {@link NO_OBJECT_TARGET} dropped. */
export function namedTargetValues(entities: readonly Entity[]): string[] {
	return entities.filter((e) => e.kind === "target" && e.value !== NO_OBJECT_TARGET).map((e) => e.value)
}

export type GrantExtraction = {
	authorized: "yes" | "no"
	/** The action types the quoted sentence itself authorises, in the same vocabulary as the gate's own
	 *  categories (`GRANT_CATEGORY_VALUES`). This is the field that replaced the verb-in-quote tables: the
	 *  question "does the user's sentence cover THIS effect?" is a question about meaning, and meaning
	 *  belongs to the model, not to code reading the words. Missing or empty means the model named no effect,
	 *  which grants nothing — see the effects gate in `verifyGrant`. */
	effects?: string[]
	allowed_targets: string[]
	forbidden_targets: string[]
	quote: string
}

export type GrantVerdict = {
	granted: boolean
	reason: string
	/** Which pending entities matched which allowed target (for the log/UI). */
	matches: Array<{ entity: string; target: string }>
	/** Where the supporting quote was found. `"ledger"` means the words came from a ledger row rather
	 *  than from a message in this call — the same user sentence, remembered instead of re-sent. It
	 *  changes nothing about WHAT was granted, only where the evidence lives, and the caller uses it to
	 *  label the verdict. */
	source?: "message" | "ledger"
}

/**
 * Category → matching group (§2.4). Ledger matching compares groups, not exact categories, so a grant
 * reaches the siblings inside its own group. What a group may NOT decide is direction — that is
 * `auth-ledger.ts`'s `grantAuthorises`, because "copy to /x/" covering mkdir follows from writing content,
 * while covering chmod never did.
 *
 * Lives here rather than in the ledger because the transcript side needs the same map: the pending action's
 * segments and the model's `effects` are both categories, and "does this sentence authorise this effect?" is
 * answered by comparing their groups, not their spellings — `cluster_mutation` and `container_mutation` are
 * one kind of harm, `delete_data` and `cluster_mutation` are not. `auth-ledger.ts` re-exports it; the
 * direction of the import is auth-ledger → here, so putting the table anywhere else would close a cycle.
 */
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

/** The kind groups whose pending action READS a path's bytes. Deliberately just these two: `read_system_state`
 *  is its own group, so a permission over files can never answer a read of a machine. */
const PATH_READ_GROUPS: ReadonlySet<string> = new Set(["read_only", "secret-read"])

/** The kind groups a grant must be in to be a WRITE about the thing it names.
 *
 * Two, because the secret categories were split apart put `write_sensitive` in a group of its own: a permission
 * to edit a credentials file is still a permission to write there, and the write-implies-read direction — an
 * edit needs a read first — has to hold for exactly the files where that sentence matters most. */
const WRITE_GROUPS: ReadonlySet<string> = new Set(["fs-write", "secret-write"])

/** The groups a DELETE grant is in (destruction of content, whether a path or an object store). */
const DELETE_GROUPS: ReadonlySet<string> = new Set(["fs-delete"])

/**
 * The directions in which a stored grant answers an effect it is not filed under.
 *
 * `"own"` is the old group equality — the row's own segments, unchanged. The other three are the named
 * one-way rules, and the whole point of naming them is that "a row about X answers Y" is a statement
 * somebody made, not an accident of adjacency:
 *
 *  · `"delete-gives-write"` — destroying every byte under a scope already permits putting bytes there
 *    (the reverse is refused: a write grant buys no delete through this direction).
 *  · `"write-gives-read"` — you cannot edit what you cannot open, so a grant that lets the agent
 *    create or change content at a place lets it read there too. Secret-class paths INCLUDED, because an
 *    edit of a credentials file needs the read that precedes it; the direction is one-way, so a READ grant
 *    never buys a write and `read_system_state` is not answerable from a file at all.
 *  · `"write-gives-single-delete"` — removing ONE file is part of the same work as editing it
 *    (`rm file`, and `mv`, which is delete+write). Recursive delete, `delete_data` and the granted folder
 *    itself are refused, and refused below in {@link grantAnswersSegment} where the target is known.
 *
 * Nothing here can be reached from a read row: a permission to look at something buys no change, ever.
 */
export type GrantDirection =
	| "own"
	| "delete-gives-write"
	| "write-gives-read"
	| "write-gives-single-delete"

/** Which direction, if any, lets one stored category segment answer one pending segment. */
export function grantDirection(grantSegment: string, pendingSegment: string): GrantDirection | undefined {
	const stored = kindGroup(grantSegment)
	const pending = kindGroup(pendingSegment)
	if (stored === pending) return "own"
	if (stored === "fs-delete" && pending === "fs-write") return "delete-gives-write"
	if ((WRITE_GROUPS.has(stored) || DELETE_GROUPS.has(stored)) && PATH_READ_GROUPS.has(pending)) return "write-gives-read"
	// The single-file delete is one category, not a group: `delete_outside` is that category. `delete_recursive`
	// and `delete_data` share its group and are exactly what this direction excludes, so they are compared as
	// themselves and never inherit it.
	if (WRITE_GROUPS.has(stored) && pendingSegment === "delete_outside") return "write-gives-single-delete"
	return undefined
}

/** The strongest direction across a possibly compound grant category (`write_outside+delete_outside`). */
export function categoryDirection(grantCategory: string, pendingSegment: string): GrantDirection | undefined {
	let best: GrantDirection | undefined
	for (const seg of grantCategory.split("+").map((s) => s.trim()).filter(Boolean)) {
		const d = grantDirection(seg, pendingSegment)
		if (d === "own") return d
		if (d) best = d
	}
	return best
}

/**
 * Is this value the root of that one, once both are spelled in the same path space?
 *
 * The single-file-delete direction's one target-shaped refusal needs it: "write implies single-file delete
 * INSIDE its scope" never means deleting the scope. Both sides are canonicalised the way every other path
 * decision is (`~` → home, `./x` → the project root), so a user's absolute wording and the gate's display
 * wording cannot disagree about it.
 */
export function sameGrantRoot(value: string, target: string, space?: PathSpace): boolean {
	const strip = (v: string): string => canonicalPath(v, space).replace(/\/+$/, "").toLowerCase()
	const a = strip(value)
	const b = strip(target)
	return a.length > 0 && a === b
}

/**
 * Does a stored grant answer this pending effect, for this target?
 *
 * The ONE place the direction table is applied with a target, so the ledger, the session store and the
 * transcript verdict cannot drift apart about what a permission contains. `covers` is the caller's own value
 * matcher: each store matches values its own way (the ledger has grammars and wildcards, the session store has
 * scope prefixes), and that difference is about spelling, not about authority.
 *
 * Two refusals belong to the single-file-delete direction and live here because they are about the target
 * rather than the category:
 *  · a row that names no object (`*`) authorises no single-file delete — "write anywhere" is not a licence to
 *    remove a file somebody would have to name;
 *  · a write row never removes the folder it was granted over; a descendant is fine, the root is not.
 */
export function grantAnswersSegment(opts: {
	grant: { category: string; value: string; kind: "entity" | "scope" | string }
	pendingSegment: string
	target: string
	/** The caller's own value matcher for ONE stored segment: the ledger passes the segment it is asking about (its
	 *  value grammars are keyed by category), the session store passes the pending segment (a prompt-scoped row
	 *  matches by scope prefix either way). The direction, not the caller, decides whether the row may be asked at
	 *  all, so a store cannot widen by choosing a matcher. */
	covers: (grantSegment: string) => boolean
	space?: PathSpace
}): boolean {
	for (const seg of opts.grant.category.split("+").map((s) => s.trim()).filter(Boolean)) {
		const direction = grantDirection(seg, opts.pendingSegment)
		if (!direction) continue
		if (direction === "write-gives-single-delete") {
			if (opts.grant.value === "*") continue
			// "Never the granted folder itself" is about a FOLDER. A grant on one file is a grant on that file, and
			// removing it is the whole of that direction — refusing there would make a per-file write grant unable
			// to delete the file it names, which is the opposite of the rule.
			const folder = opts.grant.kind === "scope" || opts.grant.value.endsWith("/")
			if (folder && sameGrantRoot(opts.grant.value, opts.target, opts.space)) continue
		}
		// A delete row that names no object cannot speak for a PATH READ either: "you may delete anything"
		// says nothing about opening a particular file. A write row may ("write anywhere" is "open
		// anything"), which is the shape the write direction already accepted before it was extended to reads of
		// secret-class paths.
		if (direction === "write-gives-read" && DELETE_GROUPS.has(kindGroup(seg)) && opts.grant.value === "*") continue
		if (opts.covers(seg)) return true
	}
	return false
}

/**
 * The words that count as the user's own words naming the DOING (install it, run it elevated, hold a port
 * open) rather than only its object ("ripgrep is missing" names ripgrep).
 *
 * No entry in this table can put an effect into the model's list. Both remaining readers may only WITHHOLD:
 *  - `METHOD_VERB_REQUIRED` below, in `verifyGrant` and in `auth-ledger.ts`'s verb gate;
 *  - the targetless `scope: "category"` row in `auth-ledger.ts`'s `eventsFromExtraction`, where it is the one
 *    thing standing between a width field and a `"*"` wildcard grant.
 *
 * The `METHOD_VERB_REQUIRED` read is kept on purpose, even though it is an English read in a gate that tries
 * not to need one: measurement showed deleting it false-allows "ripgrep is missing from this box, sort that
 * out" — the model answers `authorized:"yes"` with `effects:["package_system"]` — so the sentence names the
 * package without approving the install. Until code owns that distinction this is the one surviving read of
 * English in the gate, and dropping it is a loosening, not a cleanup.
 */
export const DOING_VERB_EVIDENCE: Record<string, RegExp> = {
	vcs_remote: /\b(push|publish|pr|pull request|release)\b/i,
	vcs_discard: /\b(reset|discard|clean|throw away|revert|undo)\b/i,
	delete_recursive: /\b(delete|remove|clean|clear|wipe|rm)\b/i,
	delete_data: /\b(delete|remove|clean|clear|rm)\b/i,
	package_system: /\b(install|apt|brew|dnf|yum|pacman|upgrade|update)\b/i,
	privilege: /\b(sudo|root|elevated|admin|privileg)\b/i,
	process_control: /\b(kill|stop|restart|terminate)\b/i,
	network_listen: /\b(serve|server|listen|host|port|start)\b/i,
	system_config: /\b(restart|enable|disable|start|stop|service|daemon|systemctl|firewall|mount)\b/i,
	interactive_editor: /\b(open|edit|editor|vim|nano)\b/i,
	remote_exec: /\b(curl|wget|installer|install script|bash|\bsh\b|download|pipe)\b/i,
}

/** Categories where naming the entity is NOT the same as approving the method:
 *  the quote must also carry the action verb ("ripgrep is missing" names ripgrep
 *  but does not approve a system-wide install).
 *
 *  Kept NOT because the idea is good English parsing — it is not — but because the measured alternative is a
 *  false allow on the live classifier. Do not widen this set and do not add to it; see `DOING_VERB_EVIDENCE`
 *  above for the measurement. */
export const METHOD_VERB_REQUIRED = new Set([
	"package_system", "privilege", "remote_exec", "network_listen",
])

/** Normalise whitespace + case + strip surrounding punctuation/quotes. */
function norm(s: string): string {
	return s.trim().toLowerCase().replace(/^["'`([{]+|["'`)\]}.,;:!?]+$/g, "")
}

/** Split an entity/target into path-ish components: a/b@c:d → [a,b,c,d]. */
function components(s: string): string[] {
	return norm(s)
		.replace(/^s3:\/\//, "")
		.replace(/^[a-z]+:\/\//, "")
		.split(/[\/@:,\s]+/)
		.map((x) => x.replace(/^\.+|\.+$/g, "").trim())
		.filter(Boolean)
}

/** Variants of a target we search for in the user's own words. */
function targetVariants(t: string): string[] {
	const n = norm(t)
	const out = new Set<string>([n])
	out.add(n.replace(/^\.\//, "").replace(/\/$/, ""))
	out.add(n.replace(/^~\//, ""))
	const parts = n.split("/").filter(Boolean)
	if (parts.length > 1) out.add(parts[parts.length - 1]!)
	return [...out].filter((v) => v.length >= 2)
}

const PHRASE_STOPWORDS = new Set([
	"the", "a", "an", "in", "on", "of", "to", "my", "our", "this", "that", "and", "or",
	"dir", "directory", "folder", "file", "files", "prefix", "bucket", "image", "images",
	"branch", "table", "tables", "namespace", "pod", "pods", "container", "release",
	"repo", "repository", "package", "service", "db", "database", "whole", "entire", "only",
])

const WORD_CHAR = /[a-z0-9_-]/i

/** Does `needle` occur in `hay` as a whole token (no identifier char hugging either end)? */
function occursWholeToken(hay: string, needle: string): boolean {
	let idx = 0
	for (;;) {
		const i = hay.indexOf(needle, idx)
		if (i === -1) return false
		const before = i === 0 ? "" : hay[i - 1]!
		const after = i + needle.length >= hay.length ? "" : hay[i + needle.length]!
		const beforeOk = !before || !WORD_CHAR.test(before)
		const afterOk = !after || !(WORD_CHAR.test(after) && WORD_CHAR.test(needle[needle.length - 1]!))
		if (beforeOk && afterOk) return true
		idx = i + 1
	}
}

/** The model must not invent targets: an allowed target counts only if the user
 *  actually wrote it (whole-token, case-insensitive) in some message. */
export function targetNamedByUser(targetName: string, userMessages: string[]): boolean {
	const hays = userMessages.map((m) => m.replace(/\s+/g, " ").toLowerCase())
	return targetVariants(targetName).some((v) => hays.some((hay) => occursWholeToken(hay, v)))
}

/** Expand a leading `~`/`~/` to `home` when home is known; otherwise return as-is.
 *
 *  Why this exists: the gate renders paths outside the project home-relatively
 *  (`displayPath` → `~/dev/x`), while a user words a permission absolutely
 *  (`/home/u/dev/x`). Component-wise comparison then sees `~` against
 *  `home,u` and never matches — measured: a scope `/home/u/dev/wt/` covered
 *  the absolute entity but NOT the `~/dev/wt/…` entity the gate actually builds.
 *  Canonicalising both sides is what makes directory permissions work at all.
 *  Deliberately NOT resolved by treating `~` as a wildcard run: without home that
 *  would let `/other/dev/wt` cover `~/dev/wt`. */
export function expandHome(value: string, home?: string): string {
	if (!home) return value
	const v = value.trim()
	if (v === "~") return home
	if (v.startsWith("~/")) return `${home.replace(/\/+$/, "")}/${v.slice(2)}`
	return value
}

/** The path space a match is evaluated in. `project` must be the SAME value layer 0
 *  rendered its entities against (`risk-policy.ts` → `makeCtx`), because a target
 *  spelled `./a/b` has no meaning without it. */
export type PathSpace = { home?: string; project?: string }

/**
 * Canonicalise a path-shaped value so both sides of a comparison are spelled the same way.
 *
 * WHY THIS EXISTS. `displayPath` (`risk-paths.ts:463`) renders every in-project target
 * project-relatively (`./corpus/.pi/x`) and every home-external one home-relatively (`~/x`), and those
 * display strings are what the gate hands the grant stores as entities. A user words a permission
 * absolutely (`/home/u/dev/pm/`). `expandHome` closed the `~` half of that gap and nothing closed the
 * `./` half, so a spoken folder grant could never cover a file inside the project — the common case.
 * Measured 2026-10-14: a `delete_recursive` scope `/home/u/dev/pm` missed the entity `./.probe/tmp`
 * and covered the identical `/home/u/dev/pm/.probe/tmp`, so a correct grant read as "no approval
 * exists" and the agent asked the user for a bigger one.
 *
 * Deliberately narrow, because guessing here would widen authority:
 *  - `~` / `~/x` → home (unchanged);
 *  - `./x`, `.` , `./`, `./*` → resolved against `project`; `../x` is left alone (it points above the
 *    project root, and there is no honest way to resolve it from the project alone);
 *  - with no project known, the previous leading-`./`-strip is kept, so every existing caller behaves
 *    exactly as before;
 *  - anything else — absolute paths, bare words like `ripgrep`, `origin/main`, `s3://b/k` — is returned
 *    untouched. Resolving a bare word against the project root would invent a path the user never said.
 */
export function canonicalPath(value: string, space?: PathSpace): string {
	const trimmed = String(value ?? "").trim().replace(/^["'`]+|["'`]+$/g, "")
	if (!trimmed) return ""
	const v = expandHome(trimmed, space?.home)
	const projectRel = v === "." || v === "./" || v === "./*" || v.startsWith("./") || v.startsWith("../")
	if (!projectRel) return v
	const project = (space?.project ?? "").replace(/\/+$/, "")
	if (!project) return v.replace(/^\.\//, "")
	if (v.startsWith("../")) return v
	const rel = v === "." || v === "./" || v === "./*" ? "" : v.slice(2).replace(/^\/+/, "")
	const out = rel ? `${project}/${rel}` : `${project}/`
	return out.replace(/\/{2,}/g, "/")
}

/** Canonicalise a grant value for user-facing comparison (`/grants revoke`):
 *  trim/quote-strip, lower-case, expand `~` against `home`, and ignore a trailing
 *  separator so a directory matches whether or not it was stored as a scope.
 *  NOT used for grant matching itself — that keeps its own stricter rules. */
export function normalizeGrantValue(value: string, home?: string): string {
	let v = norm(value)
	if (!v) return ""
	v = expandHome(v, home)
	if (v.length > 1 && v.endsWith("/")) v = v.slice(0, -1)
	return v
}

/** Whole-token match between a pending entity and one user-named target.
 *  `db-backup` ≠ `db-backup-test`, `feature/x` ≠ `feature/x-prod`, `dev` ≠ `dev-logs`. */
export function entityMatchesTarget(
	entity: string,
	targetName: string,
	home?: string,
	project?: string,
): boolean {
	const space: PathSpace = { home, project }
	const ent = canonicalPath(entity, space)
	const tgt = canonicalPath(targetName, space)
	const e = norm(ent)
	const t = norm(tgt)
	if (!e || !t) return false
	if (e === t) return true
	const ec = components(ent)
	const tc = components(tgt)
	if (tc.length === 0 || ec.length === 0) return false
	// multi-component target must appear as a consecutive component run of the entity
	if (tc.length > 1) {
		for (let i = 0; i + tc.length <= ec.length; i++) {
			if (tc.every((c, j) => ec[i + j] === c)) return true
		}
		// noun-phrase target ("build dir", "dev/ prefix in the acme-data bucket"):
		// only for targets with whitespace (a phrase, not a path), and EVERY
		// content word must name a component of the entity — so "feature/x"
		// still cannot match "feature/x-prod".
		if (/\s/.test(norm(tgt))) {
			const content = tc.filter((c) => !PHRASE_STOPWORDS.has(c))
			if (content.length > 0 && content.every((c) => ec.includes(c))) return true
		}
		return false
	}
	// single-component target: match any single component of the entity
	// (namespace, image tag, table name, basename …)
	return ec.includes(tc[0]!)
}

/**
 * Which allowed target, if any, covers this pending entity — asked of every effect of a compound category.
 *
 * The grammar of the segment comes first (docs/CLASSIFIER-SPEC.md §3). A `vcs_remote` target `origin/*` is the scope spelling the
 * gate itself emits for a push, and it means "every branch on that remote except the protected names"; as
 * components it is a `*` that would have to equal a branch name, so the string rule answered "nothing" and a
 * user who answered "always" on a push was asked again next push. Only a segment with no grammar, or a pair
 * the grammar cannot read, falls through to `entityMatchesTarget` — a `false` from the grammar is an answer
 * and does not buy the old rule back, so this widens the two categories the grammar types and loosens no near-name.
 */
function allowedTargetFor(
	segments: string[],
	entity: string,
	allowed: string[],
	space?: PathSpace,
): string | undefined {
	let stringHit: string | undefined
	for (const seg of segments) {
		for (const target of allowed) {
			const verdict = coversByGrammar(seg, target, entity)
			if (verdict === true) return target
			if (
				verdict === undefined &&
				stringHit === undefined &&
				entityMatchesTarget(entity, target, space?.home, space?.project)
			) {
				stringHit = target
			}
		}
	}
	return stringHit
}

/**
 * Does a user-forbidden target reach this pending entity?
 *
 * A veto takes the UNION of the two readings, and the asymmetry against `allowedTargetFor` is deliberate. The
 * grammar's `false` on an all-branches row is a limit on AUTHORITY — "all branches on origin" is not a
 * licence for `main` — and a forbid is not authority: it is the one sentence whose job is to stop things, so
 * narrowing it is the failure mode (a coarse forbid must keep dominating everything the words could cover).
 * Hence: veto if the old string rule said yes, or the grammar says yes, or the grammar held back ONLY on the
 * protected-name limit while the row's scope does contain this branch.
 */
function forbiddenTargetFor(
	segments: string[],
	entity: string,
	forbidden: string[],
	space?: PathSpace,
): string | undefined {
	for (const seg of segments) {
		for (const target of forbidden) {
			if (entityMatchesTarget(entity, target, space?.home, space?.project)) return target
			if (coversByGrammar(seg, target, entity) === true) return target
			if (wildcardForbidReaches(seg, target, entity)) return target
		}
	}
	return undefined
}

/**
 * The one `false` a forbid may not accept: the protected-name limit on a row that sweeps a whole scope.
 *
 * "never push to origin" must still veto `origin/main`, or the typed grammar would weaken the sentence the
 * user wrote to stop exactly that. Only the protected-name reason is overridden — a row naming one branch
 * (`origin/main` vs `origin/dev`) and a row on a different remote keep their `false`, and only git refs get
 * here at all, because that limit exists only in the vcs grammar.
 */
function wildcardForbidReaches(segment: string, forbidden: string, entity: string): boolean {
	if (grammarFor(segment) !== "vcs") return false
	if (coversByGrammar(segment, forbidden, entity) !== false) return false
	const row = parseVcsTarget(forbidden)
	if (!row) return false
	const sweepsAll = row.anyRemote === true || row.anyBranch === true
	if (!sweepsAll && row.branchGlob === undefined) return false
	const pending = parseVcsTarget(entity)
	if (!pending) return false
	if (row.remote !== undefined && pending.remote !== undefined && row.remote !== pending.remote) return false
	// A pending whose branch the gate could not resolve is reached by an all-branches row (a glob cannot be
	// placed inside it, so a glob row keeps its `false` rather than guessing).
	if (pending.branch === undefined) return sweepsAll
	if (row.branchGlob !== undefined) return pending.branch.startsWith(row.branchGlob)
	return sweepsAll
}

export function verifyGrant(opts: {
	extraction: GrantExtraction
	category: string
	entities: Entity[]
	/** User messages exactly as sent to the model (for the verbatim-quote check). */
	userMessages: string[]
	/** Quotes carried by the ledger rows sent with this call (`ledger-render.ts`). Same verbatim
	 *  requirement, same normalisation — a row's quote is a user sentence the ledger kept, so it is
	 *  evidence of the SAME kind, never of a wider one. */
	ledgerQuotes?: string[]
	/** Path space for target matching. Without `project` an entity the gate rendered as `./x` cannot be
	 *  compared with a target the user worded absolutely — see `canonicalPath`. */
	space?: PathSpace
}): GrantVerdict {
	const { extraction, category, entities, userMessages } = opts
	const space = opts.space
	const no = (reason: string): GrantVerdict => ({ granted: false, reason, matches: [] })

	if (extraction.authorized !== "yes") return no("model: not authorised by the user")

	// 1. Verbatim quote check (whitespace-normalised substring of a user message). A message list that
	// is a newest-first window of a long session cannot contain a sentence the user said early on, so
	// the ledger rows sent with the call are searched too — after the messages, so a raw message always
	// wins the attribution, and with the identical comparison, so nothing is matched more loosely.
	const q = (extraction.quote ?? "").replace(/\s+/g, " ").trim().toLowerCase()
	if (q.length < 3) return no("no supporting quote from a user message")
	const appearsIn = (texts: string[] | undefined): boolean =>
		(texts ?? []).some((m) => m.replace(/\s+/g, " ").trim().toLowerCase().includes(q))
	let source: "message" | "ledger"
	if (appearsIn(userMessages)) source = "message"
	else if (appearsIn(opts.ledgerQuotes)) source = "ledger"
	else return no("quote not found verbatim in any user message")

	// 2. The model's `effects` must cover every effect of the pending action.
	//
	// This is the check that replaces the verb-in-quote tables: the replacing field landed and was measured
	// first, so the tables could go. The question "does this sentence authorise deleting,
	// as opposed to naming the thing deleted?" is a question about meaning, and meaning is the model's.
	// Coverage is by KIND GROUP, the same map the ledger matches on, so `cluster_mutation` and
	// `container_mutation` answer for each other and `delete_data` never answers for either.
	//
	// Empty or missing effects is "the model named no authorised action type" and grants NOTHING — never a
	// guess from the category, never a wildcard. What garbage costs here is always the same one
	// thing: the verdict comes back `no`, the gate prompts, and the model's transcript call has already been
	// made. A wrong-but-covered effect is no worse than the old verb table's wrong-but-matched verb, and
	// unlike the table it cannot be satisfied by a word that happens to appear in the sentence.
	// The same direction table the stores use (a sentence that authorises editing a place also
	// authorises reading there). Category-only here, because an effect list carries no value to compare; the
	// one direction that needs a target — the single-file delete — is checked after step 4, where the
	// matched targets are known.
	//
	// `delete-gives-write` is NOT applied to this side, and that asymmetry is deliberate: an EFFECT list is the
	// model's answer to "what does this sentence authorise", so a sentence that authorised only deleting does
	// not authorise copying the remains out. The ledger applies it for a different reason — a delete grant over
	// a folder really does contain writing inside it — and neither reading is the other's consequence.
	const segments = category.split("+").filter((s) => norm(s))
	const rawEffects = Array.isArray(extraction.effects) ? extraction.effects : []
	const effects = rawEffects.filter((e) => typeof e === "string" && norm(e))
	if (effects.length === 0) return no("model: the quote names no authorised action type (effects empty)")
	const directionsFor = (seg: string): GrantDirection[] =>
		effects
			.map((e) => categoryDirection(e, seg))
			.filter((d): d is GrantDirection => d !== undefined && d !== "delete-gives-write")
	const uncovered = segments.filter((seg) => directionsFor(seg).length === 0)
	if (uncovered.length > 0) {
		return no(`quote does not authorise ${uncovered.join(", ")} (effects: ${effects.join(", ")})`)
	}
	// Segments the model answered with a WRITE alone (`rm file` under "you can edit /x/"): removable, but only
	// for a named target that is not the named root itself. See the check after step 4.
	const deleteFromWriteOnly = segments.filter(
		(seg) => norm(seg) === "delete_outside" && directionsFor(seg).every((d) => d !== "own" && d !== "delete-gives-write"),
	)

	// 3. Forbidden targets veto everything they match.
	// The no-object marker is not a target: an action whose object is its category names nothing a forbid could
	// be about, and treating the marker as one would let a `*`-valued row veto every targetless action.
	const named = entities.filter((e) => e.value !== NO_OBJECT_TARGET)
	const pending = namedTargetValues(entities)
	const checked = pending.length ? pending : named.map((e) => e.value)
	const forbidden = (extraction.forbidden_targets ?? []).filter((t) => norm(t))
	if (forbidden.length > 0) {
		for (const ent of checked) {
			const hit = forbiddenTargetFor(segments, ent, forbidden, space)
			if (hit) return no(`target "${ent}" matches user-forbidden "${hit}"`)
		}
	}

	// 4. Every pending entity must be covered by an allowed target.
	// A compound category is ONE grant covering EVERY effect it names, so every effect must earn its
	// own evidence. These checks used to key off `category.split("+")[0]`, which made the verdict depend
	// on which effect mergeDecisions happened to list first: a later effect needing its method verb
	// demanded nothing, and a bare-verb effect listed first carried an unlocatable companion over the line.
	// Measured over 3845 distinct commands from real session history: 317 compound actions reach this function
	// and 19 skipped a required method verb — 12 of them `privilege` behind a lax first effect. (The same audit
	// counted 44 bare-verb accepts on the branch this replaced; the per-segment rule below is what took its
	// place.) Monotone by construction: this can only refuse more, never less.
	const allowed = (extraction.allowed_targets ?? []).filter((t) => norm(t))
	const matches: Array<{ entity: string; target: string }> = []
	if (checked.length > 0 && allowed.length > 0) {
		for (const ent of checked) {
			const hit = allowedTargetFor(segments, ent, allowed, space)
			if (!hit) return no(`target "${ent}" not named by the user (allowed: ${allowed.join(", ") || "none"})`)
			matches.push({ entity: ent, target: hit })
		}
	}

	// Target half of the single-file-delete direction: a write sentence authorises removing a FILE inside what it
	// names, never the named place itself. Without a matched target there is nothing to compare, and "the folder
	// you may edit" would quietly become "the folder you may delete" — the one reading the direction excludes, so
	// it costs a prompt instead.
	if (deleteFromWriteOnly.length > 0) {
		if (matches.length === 0) {
			return no("a write authorises no delete without a target the user named (never the granted folder itself)")
		}
		for (const m of matches) {
			if (sameGrantRoot(m.target, m.entity, space)) {
				return no(`a write authorises removing a file inside "${m.target}", not "${m.entity}" itself (never the granted root)`)
			}
		}
	}

	// 5. METHOD_VERB_REQUIRED: naming the entity is not approving the method. Kept by measurement — it is the
	// only thing between "ripgrep is missing from this box, sort that out" and `apt-get install ripgrep` (see
	// `DOING_VERB_EVIDENCE` above for why). It runs on both shapes of the verdict, which it always effectively
	// did: for a targetless action the branch this replaced asked the same four categories for the same words.
	// The wording of that refusal is unchanged from the run that measured it, so before/after comparisons stay valid.
	for (const seg of segments) {
		if (!METHOD_VERB_REQUIRED.has(seg)) continue
		const verbRe = DOING_VERB_EVIDENCE[seg]
		if (verbRe && !verbRe.test(q)) {
			return no(`user named the target but not the method (${seg}); quote lacks the action verb`)
		}
	}

	// 6. Nothing more to prove. When the sentence named no target (or the action has none), step 2 is the
	// whole evidence that it was an instruction about THIS kind of action at all — that is what the
	// bare-verb table used to claim by finding a word. `write_outside` had no entry there, so a compound
	// naming it could never be answered without a target; now the model's own effect list decides.
	if (matches.length === 0) {
		return { granted: true, reason: `user instruction covers the action (${effects.join(", ")})`, matches, source }
	}
	return { granted: true, reason: `user authorised: ${matches.map((m) => `${m.entity}←"${m.target}"`).join(", ")}`, matches, source }
}
