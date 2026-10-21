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
 * Shape sniffing is what that rule exists to prevent, so `grammarFor` is the only
 * dispatcher here and every function below is pure: no fs, no pi, nothing else from
 * this tree.
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
 * Mirrors `PROTECTED_BRANCH_RE` (`risk-handlers.ts:555`) — the same list the
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
