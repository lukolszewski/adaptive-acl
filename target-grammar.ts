/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Target grammars for publish targets: git refs and container images.
 *
 * A grant row stores its target as one string, and until now the only reading of
 * that string was a run of whitespace/slash components. So the value the gate itself
 * emits for "allow every branch on origin" — `origin/*`, the scope entity from
 * `risk-handlers.ts` — covered nothing, and a row could never say "any tag of
 * myrepo/app". The rule this file implements (docs/CLASSIFIER-SPEC.md §3, "publish
 * targets are matched by grammar, not by string"): pick the grammar by **category**,
 * never by the shape of the string, parse both sides of the match with it, and treat
 * an unparseable side as `undefined` so the caller falls back to the old string rule.
 *
 * Shape sniffing is what was rejected for CHOOSING a grammar, so `grammarFor` is the only dispatcher here
 * and every function below is pure: no fs, no pi, nothing else from this tree.
 *
 * This is also the one place that knows a bucket is not a directory: {@link isObjectStoreUri} and
 * the cross-space guard inside {@link coversByGrammar} sit on the single call every matcher makes, so a
 * category rename cannot make a folder row reach a cloud object.
 */

/** A git ref grant: `origin/feature/x`, `origin/*`, `refs/heads/x`, `HEAD:x`, `*`. */
export type VcsTarget = {
	remote?: string
	branch?: string
	/** Branch-name prefix from a trailing-glob row, always `/`-terminated (`feature/`). */
	branchGlob?: string
	anyBranch?: boolean
	anyRemote?: boolean
	/** The gate could not resolve the branch (`origin/(current branch)`). */
	branchUnknown?: boolean
}

/** A container image: `[registry/]repo[:tag][@digest]`, or `*`. */
export type ImageRef = {
	registry?: string
	repo?: string
	tag?: string
	digest?: string
	anyImage?: boolean
}

type TargetGrammar = "vcs" | "image"

/**
 * Mirrors `PROTECTED_BRANCH_RE` (`risk-handlers.ts:1063`) — the same list the
 * layer-0 `never` for force-pushing a protected branch uses. Kept as a copy rather than
 * an import so this module stays dependency-free; the two must stay in sync.
 */
export const PROTECTED_BRANCH_RE = /^(main|master|trunk|develop|dev|release[\/-].*|production|prod|stable)$/i

export function isProtectedBranch(branch: string): boolean {
	return PROTECTED_BRANCH_RE.test(branch)
}

/** Category segment → grammar. A Map so `constructor`/`toString` are not grammars. */
const GRAMMARS = new Map<string, TargetGrammar>([
	["vcs_remote", "vcs"],
	["vcs_force_protected", "vcs"],
	["container_mutation", "image"],
	["network_send", "image"],
])

/** One category segment — callers split compound categories on `+` themselves. */
export function grammarFor(category: string): "vcs" | "image" | undefined {
	return GRAMMARS.get(category.trim())
}

// ------------------------------------------------------------- object storage

/**
 * An object-storage URI, recognised by SHAPE (scheme, or the account-host form) and never by a tool name:
 * `gs://bucket/prefix`, `s3://bucket/key` (and the Hadoop `s3a`/`s3n` spellings), Azure blob URLs and the GCS
 * object URL. Layer 0 imports the same predicate to decide that a verb acted on DATA in a store
 * (`risk-handlers.ts`), so the two cannot drift.
 */
const OBJECT_URI_RE = /^(?:(?:gs|s3[an]?|azure-container|abfs)s?:\/\/[^/\s]+|https?:\/\/[^/\s]*(?:\.blob(?:\.core)?\.windows\.net|\.blob\.dfs\.windows\.net|storage\.googleapis\.com)[/:])[^\s]*$/i

export function isObjectStoreUri(value: string): boolean {
	return OBJECT_URI_RE.test(value.trim())
}

/**
 * The store one object-storage address points at, and how far inside it it reaches.
 *
 * `bucket` is the store; `key` is the part after it, so `s3://archive/reports/2024.csv` is the store
 * `archive` and the key `reports/2024.csv`. The Azure/GCS HTTP forms put the account in the authority and the
 * CONTAINER in the first path segment, so their store is one level later — the same reading
 * `risk-handlers.ts` uses to decide that a URI names an object rather than a store.
 */
export type ObjectStoreRef = { scheme: string; bucket: string; key?: string }

/** Bucket / container names: the DNS-ish alphabet the three big stores all accept. Machine syntax, checked
 *  against a stored VALUE (never against a sentence), and the reason a bare word like `archive` can be read
 *  as a store while `leave that folder alone` cannot. */
const BUCKET_NAME_RE = /^[a-z0-9][a-z0-9._-]{1,62}$/i

/** Read one side of an object-store match. `undefined` for anything that is not an object address. */
export function parseObjectStoreTarget(value: string): ObjectStoreRef | undefined {
	const s = value.trim()
	if (!s) return undefined
	const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s)
	if (scheme) {
		if (!isObjectStoreUri(s)) return undefined
		const rest = s.slice(s.indexOf("//") + 2)
		const segments = rest.split("/").filter((p) => p !== "")
		// `https://<account>.blob.core.windows.net/<container>/<blob>` names its store one level deeper than
		// `s3://<bucket>/<key>`; with no level left the URL names an account, which is not a store.
		const storeAt = /^https?:\/\//i.test(s) ? 1 : 0
		const bucket = segments[storeAt]
		if (bucket === undefined) return undefined
		const key = segments.slice(storeAt + 1).join("/")
		return { scheme: scheme[1]!.toLowerCase(), bucket, ...(key ? { key } : {}) }
	}
	// A store named in one word — what a user types, and what a row stores when the sentence said
	// "the archive bucket" and nothing else.
	if (s.includes("/") || s.includes(":")) return undefined
	return BUCKET_NAME_RE.test(s) ? { scheme: "", bucket: s } : undefined
}

/**
 * Does a stored row reach this object address?
 *
 * `archive` covers `s3://archive/anything`; `s3://archive/reports/` covers the keys under that prefix and
 * nothing else; a row naming a different store covers nothing here. `undefined` means "this pair is not an
 * object-store pair" — the caller keeps whatever rule it had, which is why a row about a local directory can
 * never be answered here (the cross-space guard above already refused the path/URI pair, and a plain path is
 * not an object address).
 *
 * A prefix ends at a `/`: `s3://archive/dev` does not reach `s3://archive/development/x`, the same boundary
 * rule the branch glob and the path scope use.
 */
export function objectStoreCovers(rowValue: string, pendingValue: string): boolean | undefined {
	const pending = parseObjectStoreTarget(pendingValue)
	if (!pending) return undefined
	const row = parseObjectStoreTarget(rowValue)
	if (!row) return undefined
	if (row.bucket.toLowerCase() !== pending.bucket.toLowerCase()) return false
	if (row.key === undefined) return true
	if (pending.key === undefined) return false
	const prefix = row.key.endsWith("/") ? row.key : `${row.key}/`
	return pending.key === row.key || pending.key.startsWith(prefix)
}

/** A value that says "a file on this machine": a leading `/`, `./`, `../` or `~/`. A bare word is neither a
 *  path nor a URI — people name a bucket prefix that way (`dev/`) — so it is left to the component rule. */
function isExplicitPath(value: string): boolean {
	const s = value.trim()
	return s.startsWith("/") || s.startsWith("./") || s.startsWith("../") || s.startsWith("~/") || s === "." || s === ".."
}

/**
 * A bucket and a directory are different places, and no grammar in this module can equate them.
 *
 * The bucket verbs were moved onto the effect words, and `delete_data` is now shared by a local data-file
 * delete and a bucket-object delete. Sharing the NAME must not mean sharing the target space: the component
 * matcher in `grant-verify.ts` compares `/`-separated runs, so a folder row `./backups/` would otherwise
 * "cover" `s3://acme-data/backups/x.csv` — a local approval buying a cloud delete. Every matcher consults
 * this function before its string rule, so the verdict is stated once and applies to all of them.
 *
 * Only a pair that is provably cross-space is answered: one side an object URI, the other an explicit
 * filesystem path. Anything else (`dev/` against `s3://acme-data/dev/`, which is the shape a model's own
 * `allowed_targets` really has) stays `undefined` and keeps the rule it always had.
 */
function crossSpaceVerdict(rowValue: string, pendingValue: string): boolean | undefined {
	const rowUri = isObjectStoreUri(rowValue)
	const pendingUri = isObjectStoreUri(pendingValue)
	if (rowUri === pendingUri) return undefined
	return isExplicitPath(rowUri ? pendingValue : rowValue) ? false : undefined
}

// ------------------------------------------------------------------ shared bits

/** Stands in for a `(current branch)` group so its inner space survives the prose test. */
const UNKNOWN_MARK = "\u0000"

/** Characters that may wrap a value without changing it; never `/` or `:`. */
const EDGE_PUNCT = /^[`'",;[\]{}<>]+|[`'",;[\]{}<>]+$/g

/** Trim, fold a `(…)` group to a marker, drop wrapping punctuation, reject prose. */
function clean(value: string): string | undefined {
	let s = value.trim()
	if (!s) return undefined
	if (s.includes("(") || s.includes(")")) {
		s = s.replace(/\([^()]*\)/g, UNKNOWN_MARK)
		if (/[()]/.test(s)) return undefined // unbalanced paren — not a target we can read
	}
	s = s.replace(EDGE_PUNCT, "").trim()
	if (!s) return undefined
	if (/\s/.test(s)) return undefined // whitespace means prose; prose is never parsed here
	if (s.includes("://")) return undefined // a URL is not a ref and not an image
	return s
}

function lastComponent(value: string): string {
	return value.split("/").pop() ?? value
}

/** `a/b/*` and `a/*` are the gate's own scope spellings; a star anywhere else is not. */
function trailingGlob(expr: string): string | undefined {
	if (!expr.includes("*")) return expr
	if (expr.indexOf("*") !== expr.lastIndexOf("*") || !expr.endsWith("*")) return undefined
	return expr.slice(0, -1).replace(/\/$/, "")
}

/** Whole-token, case-insensitive: no letter/digit/underscore on either side. */
function tokenHit(text: string, needle: string): boolean {
	const haystack = text.toLowerCase()
	const want = needle.toLowerCase()
	if (!want) return false
	let from = 0
	for (;;) {
		const at = haystack.indexOf(want, from)
		if (at < 0) return false
		const before = at === 0 ? "" : haystack[at - 1]!
		const after = haystack[at + want.length]
		if (!isWordChar(before) && !isWordChar(after ?? "")) return true
		from = at + 1
	}
}

function isWordChar(ch: string): boolean {
	return /[\p{L}\p{N}_]/u.test(ch)
}

/** Every alternative must be hit; each alternative list is an OR. */
function allNamed(text: string, alternatives: string[][]): boolean {
	if (alternatives.length === 0) return false
	return alternatives.every((options) => options.some((needle) => tokenHit(text, needle)))
}

// -------------------------------------------------------------------- git refs

/**
 * The conventional remote names: `origin` is what `git init` and every forge default to,
 * `upstream` the fork convention. Used to read `origin/*` as the gate wrote it when there
 * is no pending target whose remote we could compare the head against.
 */
const CONVENTIONAL_REMOTE = /^(origin|upstream)$/i

/** A head component that cannot be a branch namespace: a conventional remote or a host. */
function looksLikeRemote(component: string): boolean {
	return CONVENTIONAL_REMOTE.test(component) || component.includes(".")
}

type RefOptions = {
	/** The remote of the pending target: a bare word equal to it is a remote, not a branch. */
	pendingRemote?: string
	/** Reading the gate's own `remote/branch` form, where the head component *is* the remote. */
	headIsRemote?: boolean
}

/**
 * Turn the part after the remote into a branch, a `/`-terminated prefix or a wildcard.
 * A trailing `/` and a trailing `*` are the same row (`feature/` = everything under
 * `feature/`); a star anywhere else is a shape this grammar does not read, so the caller
 * falls back to the string rule. A glob always ends at a `/`, which keeps `release*`
 * off `releaseX`.
 */
function branchShape(expr: string): VcsTarget | undefined {
	if (!expr) return undefined
	const head = expr.endsWith("/") ? expr.slice(0, -1) : expr
	if (!expr.includes("*") && !expr.endsWith("/")) {
		if (!head.includes(UNKNOWN_MARK)) return { branch: head }
		return head === UNKNOWN_MARK ? { branchUnknown: true } : undefined
	}
	const starless = head.includes("*") ? trailingGlob(head) : head
	if (starless === undefined) return undefined
	const prefix = starless.replace(/\/$/, "")
	if (prefix === "") return { anyBranch: true }
	if (prefix.includes(UNKNOWN_MARK)) return undefined
	return { branchGlob: `${prefix}/` }
}

/**
 * Parse one side of a git-ref match. `pendingRemote` is the remote of the target being
 * decided: it is what turns the bare word `origin` (and `origin/`) into "every branch on
 * origin" instead of a branch called `origin`. A slash form whose head is that remote —
 * or is a conventional remote name, when no pending is in play — reads as `remote/branch`.
 */
function parseRef(value: string, opts: RefOptions): VcsTarget | undefined {
	const s = clean(value)
	if (!s || s.startsWith("/") || s.startsWith("~")) return undefined
	if (s === "*") return { anyRemote: true, anyBranch: true }
	const spec = s.replace(/^\++/, "") // refspec force flag: `+src:dst`
	const colon = spec.indexOf(":")
	if (colon >= 0) {
		// `<source>:<destination>` — the left side is the local ref, so what is named is the right
		// side, and the remote came from the push's argument, not from this string: a branch row.
		const dst = spec.slice(colon + 1)
		if (!dst || dst.includes(":")) return undefined
		return branchShape(dst)
	}
	if (spec.startsWith(UNKNOWN_MARK)) return undefined
	const parts = spec.split("/")
	if (parts[0] === "refs") {
		if (parts.length < 3) return undefined
		if (parts[1] === "heads") return branchShape(parts.slice(2).join("/"))
		if (parts[1] === "remotes") {
			const remote = parts[2]!
			const shape = branchShape(parts.slice(3).join("/") || "*")
			return shape ? { remote, ...shape } : undefined
		}
		return undefined // refs/tags/* and friends are not branches: let the caller fall back
	}
	const head = parts[0]!
	const emptyTail = parts.length > 1 && spec.endsWith("/")
	if (parts.length > 1 && (opts.headIsRemote || head === opts.pendingRemote || (!emptyTail && looksLikeRemote(head)))) {
		// `origin/` is the gate's own scope spelling with an empty branch part: every branch.
		const shape = branchShape(spec.slice(head.length + 1) || "*")
		return shape ? { remote: head, ...shape } : undefined
	}
	if (parts.length === 1) {
		// Reading the gate's own target form, a bare word is the `target(remote)` a `--mirror`
		// push records: a remote whose branch nobody named, not a branch called that.
		if (opts.headIsRemote) return { remote: head, branchUnknown: true }
		if (opts.pendingRemote && head === opts.pendingRemote) return { remote: head, anyBranch: true }
		return branchShape(head)
	}
	if (emptyTail) return { branch: head } // `origin/` when origin is not the pending's remote: a branch name
	return branchShape(spec)
}

export function parseVcsTarget(value: string, pendingRemote?: string): VcsTarget | undefined {
	return parseRef(value, { pendingRemote })
}

/**
 * Does the stored row cover the pending target?
 *
 * The pending side is always the gate's own `remote/branch` spelling, so its head is its
 * remote; the row is then read with that remote in hand. A wildcard row means
 * "every branch except protected", and a pending whose branch is unknown is covered by
 * `*` alone. Either side unparseable → `undefined`, so the caller keeps its old rule.
 */
export function vcsCovers(rowValue: string, pendingValue: string): boolean | undefined {
	const pending = parseRef(pendingValue, { headIsRemote: true })
	if (!pending) return undefined
	const row = parseRef(rowValue, { pendingRemote: pending.remote })
	if (!row) return undefined
	if (row.anyRemote) return true // the bare-verb `*` row: unchanged meaning, protected included
	if (pending.branch === undefined) return false // unknown or wildcard pending: only `*` reaches it
	if (row.remote !== undefined && row.remote !== pending.remote) return false
	if (row.anyBranch || row.branchGlob !== undefined || row.branchUnknown) {
		if (row.branchUnknown) return false // a row that names no branch names nothing
		if (isProtectedBranch(pending.branch)) return false
		return row.branchGlob === undefined || pending.branch.startsWith(row.branchGlob)
	}
	if (row.branch === undefined) return undefined
	return branchEq(row.branch, pending.branch)
}

/** Equal, or the row names the branch's last component (`ABC123` covers `feature/ABC123`). */
function branchEq(rowBranch: string, pendingBranch: string): boolean {
	return rowBranch === pendingBranch || lastComponent(pendingBranch) === rowBranch
}

// -------------------------------------------------------------- container images

/** A first path component that can only be a registry host. */
function looksLikeRegistry(component: string): boolean {
	return component === "localhost" || component.includes(".") || component.includes(":")
}

export function parseImageRef(value: string): ImageRef | undefined {
	const s = clean(value)
	if (!s) return undefined
	if (s.startsWith("/") || s.startsWith("~") || s.startsWith(".")) return undefined // a path, not an image
	if (s === "*") return { anyImage: true }
	if (s.includes("*")) return undefined // only `*` itself is a wildcard; no tag or repo globs
	let name = s
	let digest: string | undefined
	const at = name.indexOf("@")
	if (at >= 0) {
		digest = name.slice(at + 1)
		name = name.slice(0, at)
		if (!digest) return undefined
	}
	const tagAt = name.indexOf(":", name.lastIndexOf("/") + 1)
	let tag: string | undefined
	if (tagAt >= 0) {
		tag = name.slice(tagAt + 1)
		name = name.slice(0, tagAt)
		if (!tag) return undefined
	}
	const parts = name.split("/")
	const headIsHost = parts.length > 1 ? looksLikeRegistry(parts[0]!) : parts.length === 1 && looksLikeRegistry(parts[0]!)
	const registry = headIsHost ? parts[0]! : undefined
	const repo = registry === undefined ? name : parts.slice(1).join("/")
	const ref: ImageRef = {}
	if (registry) ref.registry = registry
	if (repo) ref.repo = repo
	if (tag) ref.tag = tag
	if (digest) ref.digest = digest
	return ref.repo || ref.registry ? ref : undefined
}

function registryEq(a: string | undefined, b: string | undefined): boolean {
	// Both absent counts as equal; a row that names a registry never matches a target that has none.
	return a === b
}

/**
 * Does the stored row cover the pending image? A row without a tag covers any tag of that
 * repo; a row that is a registry alone covers anything in that registry. `docker` parses as
 * a repo named `docker` and therefore covers nothing — the word is not a target.
 */
export function imageCovers(rowValue: string, pendingValue: string): boolean | undefined {
	const pending = parseImageRef(pendingValue)
	if (!pending) return undefined
	const row = parseImageRef(rowValue)
	if (!row) return undefined
	if (row.anyImage) return true
	if (pending.anyImage) return false
	if (row.repo === undefined) {
		if (row.registry === undefined) return undefined
		return registryEq(row.registry, pending.registry)
	}
	if (!registryEq(row.registry, pending.registry)) return false
	const bareName = !row.repo.includes("/")
	const sameRepo = row.repo === pending.repo || (bareName && lastComponent(pending.repo ?? "") === row.repo)
	if (!sameRepo) return false
	if (row.tag !== undefined && row.tag !== pending.tag) return false
	if (row.digest !== undefined && row.digest !== pending.digest) return false
	return true
}

// ------------------------------------------------------------------ dispatchers

export function coversByGrammar(category: string, rowValue: string, pendingValue: string): boolean | undefined {
	// The spaces are checked before any grammar: a bucket row can never cover a local path, whatever the
	// category's own reading of the pair would have said.
	const cross = crossSpaceVerdict(rowValue, pendingValue)
	if (cross !== undefined) return cross
	const grammar = grammarFor(category)
	if (grammar === "vcs") return vcsCovers(rowValue, pendingValue)
	if (grammar === "image") return imageCovers(rowValue, pendingValue)
	return undefined
}

/**
 * Does the user's own text name this row, structurally? Every component the parsed row
 * names must appear as a whole token; a branch may be named by its last component, which
 * is how people say it (`ABC123` for `feature/ABC123`). Wildcard rows need only the remote
 * or registry they name — the caller supplies the quantifier evidence ("any branch").
 * Tags and digests are display, not named components. `undefined` when the row has no
 * grammar here or does not parse.
 */
export function namedByUserStructurally(category: string, rowValue: string, text: string): boolean | undefined {
	const grammar = grammarFor(category)
	if (grammar === undefined) return undefined
	const named: string[][] = []
	if (grammar === "vcs") {
		const ref = parseVcsTarget(rowValue)
		if (!ref) return undefined
		if (ref.remote) named.push([ref.remote])
		if (ref.branch) named.push([ref.branch, lastComponent(ref.branch)])
		if (ref.branchGlob) {
			const prefix = ref.branchGlob.replace(/\/$/, "")
			named.push([...new Set([lastComponent(prefix), prefix])])
		}
	} else {
		const ref = parseImageRef(rowValue)
		if (!ref) return undefined
		if (ref.registry) named.push([ref.registry])
		if (ref.repo) named.push([ref.repo])
	}
	return allNamed(text, named)
}

/** One-line human description of a stored value, or `undefined` if there is nothing to say. */
export function describeTarget(category: string, value: string): string | undefined {
	const grammar = grammarFor(category)
	if (grammar === "vcs") {
		const ref = parseVcsTarget(value)
		if (!ref) return undefined
		if (ref.anyRemote) return "any branch on any remote"
		const where = ref.remote ? `on ${ref.remote}` : "on any remote"
		if (ref.branchUnknown) return ref.remote ? `the branch being pushed to ${ref.remote}` : "the branch being pushed (no remote named)"
		if (ref.anyBranch) return `all branches ${where}`
		if (ref.branchGlob) return `all branches ${where} matching ${ref.branchGlob}*`
		if (ref.branch) return ref.remote ? `${ref.remote}/${ref.branch}` : `branch ${ref.branch} ${where}`
		return undefined
	}
	if (grammar === "image") {
		const ref = parseImageRef(value)
		if (!ref) return undefined
		if (ref.anyImage) return "any image on any registry"
		const name = [ref.registry, ref.repo].filter((p) => p !== undefined).join("/")
		if (!ref.repo) return `every image in ${ref.registry}`
		if (ref.tag || ref.digest) return `${name}${ref.tag ? `:${ref.tag}` : ""}${ref.digest ? `@${ref.digest}` : ""}`
		return `any tag of ${name}`
	}
	return undefined
}
