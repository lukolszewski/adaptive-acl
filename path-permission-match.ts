/**
 * Read / Edit / Write path permission matching: globs over project-relative, `~/` and absolute
 * paths, plus the allow-always suggestions offered after a path is approved.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import path from "node:path"
import { statSync } from "node:fs"
import { homedir } from "node:os"
import { classifyPath } from "./risk-paths.ts"

function expandUserPath(p: string): string {
	const home = homedir()
	if (p === "~") return home
	if (p.startsWith("~/")) return path.join(home, p.slice(2))
	return p
}

/** Resolve a rule path pattern relative to project cwd. */
export function resolveRulePath(pattern: string, cwd: string): string {
	const p = expandUserPath(pattern.trim())
	if (p.startsWith("//")) {
		return path.resolve(p.slice(1))
	}
	if (path.isAbsolute(p)) {
		return path.resolve(p)
	}
	if (p.startsWith("./") || p.startsWith(".\\")) {
		return path.resolve(cwd, p)
	}
	if (p.startsWith("~/")) {
		return path.resolve(expandUserPath(p))
	}
	// Relative to project root (no prefix)
	return path.resolve(cwd, p)
}

function escapeRegex(s: string): string {
	return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
}

/** Compile a path glob into a regex: `**` crosses `/`, `*` does not. */
function globToRegex(globPattern: string): RegExp {
	let g = globPattern.replace(/\\/g, "/")
	g = g.replace(/\*\*/g, "\x00GLOBSTAR\x00")
	g = escapeRegex(g)
	g = g.replace(/\x00GLOBSTAR\x00/g, ".*")
	g = g.replace(/\\\*/g, "[^/]*")
	return new RegExp(`^${g}$`)
}

export function pathMatchesRulePattern(
	targetPath: string,
	rulePattern: string,
	cwd: string,
): boolean {
	if (!rulePattern || rulePattern === "*") return true

	const resolvedTarget = path.resolve(
		path.isAbsolute(expandUserPath(targetPath))
			? expandUserPath(targetPath)
			: path.resolve(cwd, targetPath),
	)

	const normalizedTarget =
		process.platform === "win32"
			? resolvedTarget.replace(/\\/g, "/")
			: resolvedTarget

	const ruleResolved = resolveRulePath(rulePattern, cwd)
	const normalizedRule =
		process.platform === "win32"
			? ruleResolved.replace(/\\/g, "/")
			: ruleResolved

	const ruleForGlob =
		rulePattern.includes("*") || rulePattern.includes("**")
			? normalizedRule
			: normalizedRule

	if (rulePattern.includes("*")) {
		// A subtree glob never reaches a secret-bearing path. "I grant this folder" means the
		// folder's ordinary contents, not the credentials sitting inside it: reaching a secret
		// has to name it exactly, which is what a non-glob rule does. Same rule as the session
		// ledger, where a folder grant unlocks secrets only on explicit inclusion wording.
		if (rulePattern.includes("**") && classifyPath(resolvedTarget, ruleContext(cwd)).isSecret) return false
		return globToRegex(ruleForGlob).test(normalizedTarget)
	}

	// Exact path or directory prefix
	if (normalizedTarget === normalizedRule) return true
	if (normalizedRule.endsWith("/")) {
		return normalizedTarget.startsWith(normalizedRule)
	}
	return (
		normalizedTarget.startsWith(normalizedRule + "/") ||
		normalizedTarget === normalizedRule
	)
}

/** The project-relative context path classification needs; here cwd doubles as project root. */
function ruleContext(cwd: string): { cwd: string; project: string; home: string } {
	return { cwd, project: cwd, home: homedir() }
}

/**
 * Is this target a folder the user means to grant as a folder?
 *
 * Trailing slash is decisive ("/x/y/"); otherwise ask the filesystem, because "/x/y" naming an
 * existing directory means the same thing. A path that does not exist yet is a FILE: an edit
 * about to create `src/a/b.ts` must not be granted as `./src/a/**`.
 */
function isDirectoryTarget(raw: string, resolved: string): boolean {
	if (raw.endsWith("/") || raw.endsWith(path.sep)) return true
	try {
		return statSync(resolved).isDirectory()
	} catch {
		return false
	}
}

export function suggestPathAllowRule(
	toolName: "Read" | "Edit" | "Write",
	targetPath: string,
	cwd: string,
): string {
	const resolved = path.isAbsolute(expandUserPath(targetPath))
		? expandUserPath(targetPath)
		: path.resolve(cwd, targetPath)

	const dir = isDirectoryTarget(targetPath, resolved)
	const rel = path.relative(cwd, resolved)
	const inProject = !rel.startsWith("..") && !path.isAbsolute(rel)
	const relPosix = rel.split(path.sep).join("/")

	// In-project: a FILE grants that file alone; a FOLDER grants that folder's own subtree — not
	// its first segment. The old form turned one approval on src/a/b.ts into Edit(./src/**), i.e. a
	// quiet grant over the whole tree, and it was chosen by "the path contains a separator", which
	// is true of almost every file.
	if (inProject) {
		return dir ? `${toolName}(./${relPosix}/**)` : `${toolName}(./${relPosix})`
	}

	// Outside the project: keep the spelling the user wrote (so `~/…` stays portable in a committed
	// file), widened to a subtree only when it really is a folder.
	if (dir) return `${toolName}(${resolved}/**)`
	if (targetPath.startsWith("~/")) {
		return `${toolName}(${targetPath})`
	}

	return `${toolName}(${targetPath})`
}

export function pathToolMatchesRuleContent(
	toolName: "Read" | "Edit" | "Write",
	targetPath: string,
	ruleContent: string | undefined,
	cwd: string,
): boolean {
	if (ruleContent === undefined) {
		return true
	}
	return pathMatchesRulePattern(targetPath, ruleContent, cwd)
}
