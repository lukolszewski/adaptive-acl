/**
 * In-process permission bridge between an interactive pi session and headless
 * subagent sessions created *inside the same process*.
 *
 * Why this exists
 * ---------------
 * `mode-inherit.ts` / `permission-forwarding.ts` cover spawned **child
 * processes** (`PI_SUBAGENT_CHILD=1` + env vars). pi-schedule-prompt's `model:`
 * jobs are not child processes: they call `createAgentSession()` in-process with
 * `SessionManager.inMemory()`, so:
 *   - `isSubagentChildProcess()` is false → env inheritance and approval
 *     forwarding are inert;
 *   - the fresh in-memory session has no `modes` / `gate-ledger` entries, and its
 *     transcript is a single job prompt with no authorisation history to
 *     backfill → the plugin falls back to `currentMode = "ask"`,
 *     `unattendedMode = false`, an **empty grant store** and an **empty ledger**,
 *     so every directory the user approved during the session is off-limits;
 *   - `bindExtensions({})` passes no `uiContext` → `hasUI()` is false → the
 *     fail-closed branch hard-denies with no "park the step" guidance.
 *
 * Net effect before this bridge: a scheduled subagent was either completely
 * ungated (extensions not loaded at all) or denied everything outside its
 * project/global permission files.
 *
 * What is inherited
 * -----------------
 * The **whole effective authorisation state**, not just grants:
 *   - `mode` (mapped through `resolveChildMode`)
 *   - session grants (`gateGrants`)
 *   - the folded ledger (`gateLedger`) — grants **and forbids and the read-only
 *     posture**. Carrying only grants would be a privilege escalation: a parent
 *     under a blanket "don't change anything" posture, or one whose scope grant
 *     the user took back with `/grants revoke` (a ledger forbid), would otherwise
 *     hand the child rights the parent no longer has.
 *
 * Read **live, at child start** — the parent republishes on every state change.
 * A job created while the parent is `auto` and fired after it switched to
 * `bypass` runs as `bypass`; a parent that *tightens* tightens every subsequent
 * run just as immediately. Nothing is ever persisted into a job file, so a
 * one-off `bypass` cannot outlive the session that granted it.
 *
 * Contract
 * --------
 *  - The interactive session publishes `{mode, unattended, grants, ledger}` to
 *    `globalThis.__piPmBridge` on every mode / unattended / grant / revoke change.
 *  - A spawner (pi-schedule-prompt) brackets the window in which it constructs the
 *    child session by incrementing `globalThis.__piPmScheduleWindow`.
 *  - An extension instance that starts **headless** while that window is open (and
 *    the snapshot cwd matches) inherits that state and is forced unattended. It
 *    records the resolution in `globalThis.__piPmLastInheritance` (so the spawner
 *    can log the effective mode without duplicating this policy) and never
 *    publishes back, so it cannot clobber the parent's snapshot.
 *
 * Keys live on `globalThis` because the spawner and this plugin are separate
 * packages (separate module graphs) and this module may or may not be
 * re-instantiated per session. Module-level state is therefore only used for
 * intentionally process-wide values — per-session identity stays in the extension
 * factory closure.
 */

import { isInheritableMode, type InheritableMode } from "./mode-inherit.ts";
import type { SerializedLedger } from "./auth-ledger.ts";
import type { SessionGrant } from "./session-grants.ts";

/** Live snapshot of the publishing (interactive) session's gate state. */
export const PM_BRIDGE_GLOBAL = "__piPmBridge";
/** Depth counter bracketing "a headless child session is being constructed". */
export const PM_SCHEDULE_WINDOW_GLOBAL = "__piPmScheduleWindow";
/** What the most recent bridged child resolved to (for spawner logs). */
export const PM_LAST_INHERITANCE_GLOBAL = "__piPmLastInheritance";

/** Modes a headless child may run in. `ask` is deliberately absent: a child with
 *  nobody to answer its prompts cannot make progress there. */
export const CHILD_MODES = ["plan", "auto", "bypass"] as const;
export type ChildMode = (typeof CHILD_MODES)[number];

export type BridgeSnapshot = {
	mode: InheritableMode;
	unattended: boolean;
	grants: SessionGrant[];
	ledger: SerializedLedger;
	cwd: string;
	updatedAt: number;
};

export type LastInheritance = {
	mode: ChildMode;
	unattended: true;
	grants: number;
	ledgerGrants: number;
	ledgerForbids: number;
	readOnly: boolean;
	cwd: string;
	at: number;
};

type GlobalWithBridge = typeof globalThis & {
	[PM_BRIDGE_GLOBAL]?: BridgeSnapshot;
	[PM_SCHEDULE_WINDOW_GLOBAL]?: number;
	[PM_LAST_INHERITANCE_GLOBAL]?: LastInheritance;
};

function bag(): GlobalWithBridge {
	return globalThis as GlobalWithBridge;
}

/**
 * Policy: which mode a headless child runs in, given the parent's live mode.
 *
 * `bypass` and `plan` are inherited verbatim — `bypass` because the user
 * explicitly opted out of gating and the child runs as them; `plan` because "we
 * are still planning" must not be silently widened into a mutating child.
 * Everything else (`ask`, and `auto` trivially) becomes `auto`: the child needs
 * to make progress without a human, but stays inside the auto-mode gate.
 */
export function resolveChildMode(parentMode: string): ChildMode {
	if (parentMode === "bypass" || parentMode === "plan") return parentMode;
	return "auto";
}

/**
 * Publish the interactive session's live gate state for in-process children.
 * Bridged children must not call this (guarded at the call site — per-session
 * identity lives in the extension closure, not in this module).
 */
export function publishBridgeSnapshot(snap: {
	mode: string;
	unattended: boolean;
	grants: readonly SessionGrant[];
	ledger: SerializedLedger;
	cwd: string;
}): void {
	const mode: InheritableMode = isInheritableMode(snap.mode) ? snap.mode : "ask";
	bag()[PM_BRIDGE_GLOBAL] = {
		mode,
		unattended: snap.unattended,
		grants: snap.grants.map((g) => ({
			category: g.category,
			value: g.value,
			kind: g.kind,
			at: g.at,
		})),
		// Structured clone-free copy: the ledger is mutated in place by revoke and
		// by fold, and the snapshot must not alias the live arrays.
		ledger: JSON.parse(JSON.stringify(snap.ledger)) as SerializedLedger,
		cwd: snap.cwd,
		updatedAt: Date.now(),
	};
}

/** True while some spawner is constructing a headless child session. */
export function isInScheduleWindow(): boolean {
	const depth = bag()[PM_SCHEDULE_WINDOW_GLOBAL];
	return typeof depth === "number" && depth > 0;
}

export function readBridgeSnapshot(): BridgeSnapshot | undefined {
	const snap = bag()[PM_BRIDGE_GLOBAL];
	if (!snap || typeof snap !== "object") return undefined;
	if (!isInheritableMode(snap.mode)) return undefined;
	if (!Array.isArray(snap.grants)) return undefined;
	if (!snap.ledger || typeof snap.ledger !== "object" || snap.ledger.v !== 1) return undefined;
	if (typeof snap.cwd !== "string") return undefined;
	return snap;
}

/**
 * Resolve inherited state for a session that has just started. Only headless
 * sessions started inside a marked window inherit anything — an interactive
 * session always keeps its own state, so this is inert in normal `pi` usage.
 *
 * Returns undefined (keep restored/default state) when there is no bridge or the
 * cwd differs. Callers must NOT substitute `bypass` in that case.
 */
export function resolveInheritedBridgeState(opts: {
	hasUI: boolean;
	cwd: string;
}):
	| {
			mode: ChildMode;
			unattended: true;
			grants: SessionGrant[];
			ledger: SerializedLedger;
	  }
	| undefined {
	if (opts.hasUI) return undefined;
	if (!isInScheduleWindow()) return undefined;
	const snap = readBridgeSnapshot();
	if (!snap || snap.cwd !== opts.cwd) return undefined;

	const grants = snap.grants.filter(
		(g) =>
			!!g &&
			typeof g.category === "string" &&
			typeof g.value === "string" &&
			(g.kind === "entity" || g.kind === "scope"),
	);

	// Headless children are ALWAYS unattended: nobody is watching to answer a
	// prompt, so soft-deny "park this step and continue" is the only behaviour
	// that does not thrash against a dialog that can never appear.
	const inherited = {
		mode: resolveChildMode(snap.mode),
		unattended: true as const,
		grants,
		ledger: snap.ledger,
	};

	bag()[PM_LAST_INHERITANCE_GLOBAL] = {
		mode: inherited.mode,
		unattended: true,
		grants: grants.length,
		ledgerGrants: Array.isArray(snap.ledger.grants) ? snap.ledger.grants.length : 0,
		ledgerForbids: Array.isArray(snap.ledger.forbids) ? snap.ledger.forbids.length : 0,
		readOnly: !!snap.ledger.readOnlyOn && snap.ledger.readOnlyOffSeq === undefined,
		cwd: opts.cwd,
		at: Date.now(),
	};

	return inherited;
}

/** Read the most recent bridged-child resolution (spawner-side logging only). */
export function readLastInheritance(): LastInheritance | undefined {
	const last = bag()[PM_LAST_INHERITANCE_GLOBAL];
	return last && typeof last.mode === "string" ? last : undefined;
}
