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

export type GrantExtraction = {
	authorized: "yes" | "no"
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

/** Categories where a bare verb ("push it", "clean the build dir") is a complete
 *  instruction, so an empty allowed_targets list with a verb-bearing quote may grant. */
export const BARE_VERB_CATEGORIES: Record<string, RegExp> = {
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
 *  but does not approve a system-wide install). */
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
 * WHY THIS EXISTS. `displayPath` (`risk-paths.ts:259`) renders every in-project target
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

	// 2. Forbidden targets veto everything they match.
	const pending = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const checked = pending.length ? pending : entities.map((e) => e.value)
	for (const ent of checked) {
		for (const f of extraction.forbidden_targets ?? []) {
			if (entityMatchesTarget(ent, f, space?.home, space?.project)) {
				return no(`target "${ent}" matches user-forbidden "${f}"`)
			}
		}
	}

	// 3. Every pending entity must be covered by an allowed target.
	// A compound category is ONE grant covering EVERY effect it names, so every effect must earn its
	// own evidence. These checks used to key off `category.split("+")[0]`, which made the verdict depend
	// on which effect mergeDecisions happened to list first: a later effect needing its method verb
	// demanded nothing, and a bare-verb effect listed first carried an unlocatable companion over the
	// line. Measured over 3845 distinct commands from real session history
	// in that sample: 317 compound actions reach this function, 19 skip a required
	// method verb (12 of them `privilege`), 44 take a bare-verb accept the later segment has not
	// earned. Monotone by construction: this can only refuse more, never less.
	const segments = category.split("+").filter((s) => norm(s))
	const allowed = (extraction.allowed_targets ?? []).filter((t) => norm(t))
	if (checked.length > 0 && allowed.length > 0) {
		const matches: Array<{ entity: string; target: string }> = []
		for (const ent of checked) {
			const hit = allowed.find((t) => entityMatchesTarget(ent, t, space?.home, space?.project))
			if (!hit) return no(`target "${ent}" not named by the user (allowed: ${allowed.join(", ") || "none"})`)
			matches.push({ entity: ent, target: hit })
		}
		for (const seg of segments) {
			if (!METHOD_VERB_REQUIRED.has(seg)) continue
			const verbRe = BARE_VERB_CATEGORIES[seg]
			if (verbRe && !verbRe.test(q)) {
				return no(`user named the target but not the method (${seg}); quote lacks the action verb`)
			}
		}
		return { granted: true, reason: `user authorised: ${matches.map((m) => `${m.entity}←"${m.target}"`).join(", ")}`, matches, source }
	}

	// 4. No named targets — bare-verb categories only, and the quote itself must carry the verb.
	if (allowed.length === 0) {
		// Every effect must be bare-verb grantable. An effect with no bare-verb form (write_outside:
		// content without a location is not an instruction) blocks the whole compound — fail-safe and
		// deliberate, not a gap to widen.
		for (const seg of segments) {
			const verbRe = BARE_VERB_CATEGORIES[seg]
			if (!verbRe) return no(`effect "${seg}" (of ${category}) requires the user to name the target`)
			if (!verbRe.test(q)) return no(`quote does not contain the action verb for "${seg}"`)
		}
		return { granted: true, reason: `user instruction covers the action ("${extraction.quote.slice(0, 60)}")`, matches: [], source }
	}

	// allowed non-empty but the action has no entities: accept only with the verb in the quote.
	for (const seg of segments) {
		const verbRe = BARE_VERB_CATEGORIES[seg]
		if (!verbRe) return no(`effect "${seg}" (of ${category}) has no bare-verb form and the action names no target`)
		if (!verbRe.test(q)) return no(`quote does not contain the action verb for "${seg}"`)
	}
	return { granted: true, reason: `user instruction covers the action`, matches: [], source }
}
