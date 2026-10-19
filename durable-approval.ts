/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * What an "always" click stores when authority lives in the journal instead of rule files.
 *
 * `authority.persist: "grants"` — the zero-hand-authored-file policy this workspace runs under — means the
 * click path must not write `permissions*.json`. It stores **durable grant rows** instead: the same rows the
 * prompt-derived ledger exports, so an approval earned by clicking and one earned by speaking live in one
 * place, are matched by one matcher, and are revoked by one mechanism (tombstones, W7).
 *
 * The rule that matters more than the feature: **a row may never express more than the invocation that
 * earned it.** Where no row can say exactly what was approved, the caller gets a `reason` and the click is
 * honoured once. That is the same withhold-rather-than-broaden rule the rule-file path already follows for
 * runtime variables and control flow. The reason it is absolute here: a durable row is read back for the rest
 * of the project's life with no trace of the click that produced it, so an allowance wider than the
 * invocation that earned it can never be told apart from one the user really gave.
 */
import path from "node:path";
import { homedir } from "node:os";
import { evaluateBash } from "./risk-policy.ts";
import { canonicalPath } from "./grant-verify.ts";
import type { SessionGrant } from "./session-grants.ts";

export type DurableRow = { category: string; value: string; kind: "entity" | "scope" };

const FILE_TOOLS = new Set(["read", "write", "edit"])

/**
 * Does this category carry secret material? Compound categories are `a+b`, so any segment counts. Deliberately
 * string-based and conservative: a category named `*_secret` is treated as secret-bearing even if the taxonomy
 * later grows, because the cost of guessing wrong here is a durable allowance over a keyring.
 */
function isSecretBearing(category: string): boolean {
	return category.split("+").some((seg) => seg.endsWith("_secret") || seg === "read_secret")
};

/** The targets an approval is actually about, in absolute spelling. */
export function approvalTargets(opts: {
	tool: string;
	input: Record<string, unknown>;
	cwd: string;
}): { targets: string[] } | { reason: string } {
	const { tool, input, cwd } = opts;

	if (FILE_TOOLS.has(tool)) {
		const raw = String(input.path ?? "")
		if (!raw) return { reason: "the approval carries no path" }
		return { targets: [path.isAbsolute(raw) ? raw : path.resolve(cwd, raw)] }
	}

	if (tool === "bash") {
		const command = String(input.command ?? "")
		if (!command) return { reason: "the approval carries no command" }
		let entities
		try {
			entities = evaluateBash(command, { cwd, project: cwd, home: homedir() }).entities
		} catch {
			// No verdict, no targets, so no row. Never guess a target: a wrong one here is a
			// permanent allowance for a path the user did not look at.
			return { reason: "no policy verdict for this command" }
		}
		const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
		if (targets.length === 0) return { reason: "the command names no target a row could hold" }
		return { targets }
	}

	return { reason: `${tool} approvals are not stored as rows` }
}

/**
 * Rows that exactly express this approval, or the reason they cannot.
 *
 * `folderScope` is the "Allow always (this folder)" click: one scope row over the containing directory. It is
 * offered for file tools only — a command is not a promise about a directory, so the folder click is never
 * turned into a scope row for bash even when a folder-shaped rule would exist.
 */
export function durableRowsForApproval(opts: {
	tool: string;
	input: Record<string, unknown>;
	category: string | undefined
	cwd: string;
	folderScope: boolean;
}): { rows: DurableRow[] } | { reason: string } {
	const category = opts.category
	if (!category) return { reason: "no category for this approval" }

	if (opts.folderScope && opts.tool === "bash") return { reason: "folder scope does not apply to a command" }

	const found = approvalTargets(opts)
	if ("reason" in found) return found

	if (opts.folderScope) {
		// Never widen a secret into a directory. The rule-file path withholds the folder offer on a secret-classified
		// path precisely because a `**` rule over `~/.ssh/` is the same permission as the key itself; a journal path
		// that happily stores `read_secret ~/.ssh/` would make the new store looser than the old one, which is the
		// wrong direction for a change that is supposed to be about where authority lives, not how much of it fits.
		if (isSecretBearing(category)) return { reason: "folder scope is not offered for secret-bearing categories" }
		const dirs = [...new Set(found.targets.map((t) => (t.endsWith(path.sep) ? t : path.dirname(t) + path.sep)))]
		return { rows: dirs.map((value) => ({ category, value, kind: "scope" as const })) }
	}
	return { rows: found.targets.map((value) => ({ category, value, kind: "entity" as const })) }
}

/**
 * Matcher for a deny-always click: every remembered allowance that would have covered these targets.
 *
 * Deny-always is implemented as **revocation**, not as a new row type. A durable forbid row would need its own
 * precedence rules (a forbid outranks a grant; `namedForbidCovers` only knows ledger forbids) and its own
 * restore path, and an unrestoreable deny is the worst failure mode this project has — the one that already
 * happened once when a test suite deleted a project's deny rules. Revocation uses plumbing that is proven
 * (tombstones survive import — `tombstones.test.ts` pins it), and if it ever fails the system re-prompts rather than
 * silently allowing: failing safe in the direction that costs the user a keystroke, not a secret.
 */
export function rowCoversTargets(
	targets: string[],
	space: { home?: string; project?: string } = {},
): (row: SessionGrant) => boolean {
	const want = targets.map((t) => canonicalPath(t, space).toLowerCase())
	return (row: SessionGrant): boolean => {
		const v = canonicalPath(row.value, space).toLowerCase()
		if (row.kind === "scope") return want.some((t) => t.startsWith(v) || t + path.sep === v)
		return want.includes(v)
	}
}
