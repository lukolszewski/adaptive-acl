/**
 * @lukolszewski/adaptive-acl
 *
 * Claude-Code-style permission modes for the pi coding agent.
 *
 * Four modes (Shift+Tab): ask → plan → auto → bypass → ask
 *   - ask     Manual approval for edits, outside-cwd access, mutating bash.
 *   - plan    Read-only; only plan.md may be written.
 *   - auto    Tiered auto-approve + optional built-in classifier + risk blacklist.
 *   - bypass  Full auto-approve (old auto semantics); sparse security reminders.
 */

import { Type } from "@earendil-works/pi-ai";
import {
  defineTool,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Text, truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";
import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os";
import path from "node:path";
import { initBashParser, takeBashParserWarning } from "./bash-parser.ts";
import {
  classifyToolCall,
  invalidateClassifierVerdictCache,
  readAgentsMdForClassifier,
  type ClassifierSessionContext,
} from "./classifier-client.ts";
import {
  buildClassifierUnavailableMessage,
  buildYoloRejectionMessage,
} from "./classifier-messages.ts";
import {
  getConfigPath,
  loadPermissionModesConfig,
  resolveAutoModeConfig,
  resolveClassifierConfig,
  resolveInjectionEscalation,
  resolveInjectionWarning,
  updatePermissionModesConfig,
} from "./config.ts";

import {
  buildGrantsFile,
  mergeIntoGrantsFile,
  pruneRows,
  readGrantsFile,
  summarizeGrantsFile,
  writeGrantsFile,
} from "./grants-file.ts"
import {
  restoreDangerousPermissionRules,
  stripDangerousPermissionRules,
} from "./dangerous-permissions.ts";
import {
  createDenialTrackingState,
  recordClassifierDenial,
  recordClassifierSuccess,
  shouldFallbackToPrompting,
  type DenialTrackingState,
} from "./denial-tracking.ts";
import {
  buildInjectionWarningBlock,
  scanBranchForInjectionSignals,
  TOOL_OUTPUT_INJECTION_WARNING,
} from "./injection-probe.ts";
import {
  readBranchEntries,
  readBranchMessages,
  readCustomEntryData,
  readGitBranch,
  readSessionId,
} from "./session-branch.ts";
import {
  accumulateBranchStats,
  emptyBranchStatsState,
} from "./branch-stats.ts";
import {
  addPermissionRule,
  getProjectPermissionsDir,
  loadMergedPermissionRules,
  warnIfLocalPermissionsNotGitignored,
} from "./permissions-loader.ts";
import {
  evaluateToolPermission,
  formatMergedRulesForDisplay,
  suggestAllowRuleSetForToolCall,
  suggestFolderAllowRule,
  type PermissionRule,
} from "./permissions.ts";
import {
  checkAutoRisk,
  commandReferencesSensitivePath,
  ensurePlanFile,
  extractPlanSection,
  extractTodoItems,
  filterSkillsFromPrompt,
  filterSubstantivePlanItems,
  findProjectRoot,
  formatCount,
  getPlanFilePath,
  hashPlan,
  isOutsideCwd,
  isPlanFilePath,
  isSensitivePath,
  listTrackedOutsideWrites,
  markCompletedSteps,
  popTrackedOutsideWrite,
  readPlanFile,
  resolveModePrompt,
  resolveWorkspacePath,
  restoreOutsideWrite,
  shouldSyncAssistantPlanToFile,
  trackOutsideWrite,
  writePlanFile,
  type OutsideWriteSnapshot,
  type PermissionMode,
  type PlanPhase,
  type TodoItem,
} from "./utils.ts";
// Tier 1 AND tier 2 bash verdicts now come from layer 0 (`bash-tiers.ts`) rather than utils' text tables. The old
// ladder anchored SAFE_PATTERNS on the command name, so `cat ~/.ssh/id_rsa` counted as tier-1 "safe" and plan/ask
// mode auto-approved reading a private key with no prompt — measured 2026-10-14; the walker calls
// that path read_secret and asks. utils.ts still exports the old tables (used by its own tests and by the tier
// matrix harness) but nothing on the gate path calls them any more.
import {
  classifyBashTiers as classifyTiersLayer0,
  isFallbackBash,
  isReadOnlyBash,
  isWorkflowBash,
} from "./bash-tiers.ts";
import { getAuthorityPersist, getAuthorityPersistOrigin, getProvenance } from "./config.ts";
import { adoptOrphans, planAdoption } from "./grants-adopt.ts";
import { buildAdoptChoices, confirmAdoptChoices, renderAdoptChoices } from "./adopt-confirm.ts";
import { makeAdoptedRulesLive } from "./adopt-live.ts";
import {
  approvalTargets,
  durableRowsForApproval,
  rowCoversTargets,
} from "./durable-approval.ts";
import {
  runPlanApprovalDialog,
} from "./plan-approval-dialog.ts";
import {
  classifierStats,
  resetClassifierStats,
  runGate,
  type GateResult,
} from "./gate.ts";
import {
  addGrant,
  createGrantStore,
  grantsCover,
  importSessionGrants,
  revokeRows,
  type SessionGrant,
} from "./session-grants.ts";
import {
	collectUserMessagesFromBranch,
	collectUserMessageRefs,
	type DenialWall,
	denialFamily,
	gateDenialAttribution,
	type GateDenialKnowledge,
	gateDenialMessage,
	unattendedEscalation,
	UNATTENDED_PARK_AFTER_HUMAN_DENIAL,
	// `denialWall`, not `wallFor`: when layer 0 bailed on the shape, `r.category` is the effect model's guess about
	// a command nobody parsed, and a guess must not decide which wall the denial is framed as.
	denialWall,
	gatePromptLabel,
	resolveGateEndpointWithFailure,
	syncLedger,
} from "./gate-bridge.ts";
import { copilotTokensSpent } from "./copilot-session.ts";
import {
  createLedger,
  deserializeLedger,
  extractionStats,
  importLedger,
  ledgerCovers,
  readOnlyActive,
  resetExtractionStats,
  revokeLedgerGrants,
  revokeLedgerForbids,
  serializeLedger,
} from "./auth-ledger.ts";
import { normalizeGrantValue } from "./grant-verify.ts";
import { classifyPath } from "./risk-paths.ts";
import type { ModelEndpoint } from "./model-client.ts";
import {
  createForwardingPoller,
  defaultAgentDir,
  isSubagentChildProcess,
  pollForwardedResponse,
  resolveParentSessionId,
  writeForwardedRequest,
  writeForwardedResponse,
  type ForwardedDecision,
  type ForwardedPermissionRequest,
  type ForwardingPoller,
} from "./permission-forwarding.ts";
import {
  applyInheritedModeForChild,
  publishInheritedPermissionMode,
} from "./mode-inherit.ts";
import {
  publishBridgeSnapshot,
  resolveInheritedBridgeState,
} from "./headless-bridge.ts";
import {
  ensureModelProfilesConfig,
  getActiveProfileName,
  listProfiles,
  loadModelProfiles,
  parseModelId,
  profileExists,
  resolveEffortForMode,
  resolveModelForMode,
  resolveSkillFilter,
  type ModelProfile,
  type ModelProfilesConfig,
} from "./profiles.ts";

type Mode = PermissionMode;

/** Effort / thinking levels accepted in model-profiles.json. */
const PROFILE_EFFORT_LEVELS = new Set([
  "off",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
]);

const MODE_CYCLE: Mode[] = ["ask", "plan", "auto", "bypass"];

const MODE_META: Record<Mode, { icon: string; label: string; role: string }> = {
  ask: { icon: "●", label: "Ask", role: "muted" },
  plan: { icon: "⏸", label: "Plan", role: "accent" },
  auto: { icon: "▶", label: "Auto", role: "warning" },
  bypass: { icon: "⚡", label: "Bypass", role: "error" },
};

// Tools available in plan mode (edit/write only for plan.md via tool_call gate).
const PLAN_TOOLS = ["read", "bash", "grep", "find", "ls", "edit", "write", "plan_ready"];
const PLAN_READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
const PLAN_DISABLED = new Set<string>();

type Block = { block: true; reason: string } | undefined;

/**
 * Cross-extension capability object: the single typed channel to
 * pi-claude-code-tui — globalThis.__piPermissionModes. Duck-typed on both
 * sides; version gates consumers.
 */
export interface PmCapability {
	version: number;
	active: boolean;
	mode: string;
	workingStats: string | null;
}

export default function permissionModesExtension(pi: ExtensionAPI): void {
  // ---- state -------------------------------------------------------------
  let currentMode: Mode = "ask";
  let planExecuting = false;
  let planPhase: PlanPhase = "exploring";
  let lastExtractedPlanHash = "";
  let lastPlanOfferAt = 0;
  /** Suppress agent_end re-offer after the user dismisses plan approval (Stay/Esc/Refine). */
  let suppressPlanOfferUntil = 0;
  const PLAN_OFFER_COOLDOWN_MS = 60_000;
  let needsAskReminder = false;
  let needsBypassSecurityReminder = false;
  let toolsBeforePlanMode: string[] | undefined;
  let planTodos: TodoItem[] = [];
  let projectRoot: string | null = null;
  let classifierConfig = resolveClassifierConfig(loadPermissionModesConfig());
  let autoModeConfig = resolveAutoModeConfig(loadPermissionModesConfig());
  let injectionWarningEnabled = resolveInjectionWarning(loadPermissionModesConfig());
  let injectionEscalationEnabled = resolveInjectionEscalation(loadPermissionModesConfig());

  const describeInjectionNoteState = () =>
    `injection note: ${injectionWarningEnabled ? "on" : "off"} (per-call) · escalation: ${
      injectionEscalationEnabled ? "on" : "off"
    } (on probe hit) · saved in ${getConfigPath()}`;
  let basePermissionRules: PermissionRule[] = [];
  let strippedDangerousRules: PermissionRule[] = [];
  let mergedPermissionRules: PermissionRule[] = [];
  let classifierDenialState: DenialTrackingState = createDenialTrackingState();
  const gateGrants = createGrantStore();
  let gateLedger = createLedger();
  /** Unattended mode: approval prompts soft-deny with an explanation instead
   *  of blocking on a dialog nobody will answer (overnight runs). Never-tier
   *  stays a hard deny. Toggled with /unattended, persisted with mode state. */
  let unattendedMode = false;
  /** True when THIS instance is an in-process headless child that inherited the
   *  parent's gate state via headless-bridge.ts. Such a child must never publish
   *  its own snapshot — its clamped state would clobber the parent's. */
  let bridgedAsSubagentChild = false;
  /** cwd used when publishing bridge snapshots; set once at session_start. */
  let bridgeCwd = "";
  /** Anti-loop: identical denied actions escalate instead of re-prompting the
   *  model with the same text all night. */
  const unattendedDenialCounts = new Map<string, number>();
  /** Consecutive unparseable commands — resets on any command that parses.
   *  Bounds the fix-and-retry loop so a model that keeps emitting broken shell
   *  doesn't spin forever. */
  let consecutiveUnparseable = 0;
  const UNPARSEABLE_RETRY_BUDGET = 3;
  /** Throttle: background backfill pauses while a live gate call is in flight. */
  let gateCallInFlight = false;
  let ledgerBackfillActive = false;
  let ledgerPersistTimer: ReturnType<typeof setTimeout> | undefined;
  /** Mode banner + one-shot notices for the current turn, appended as a
   *  trailing context message instead of mutating the system prompt. */
  let tailBannerText = "";
  const MAX_CLASSIFIER_FAILURES = 3;
  let forwardingPoller: ForwardingPoller | undefined;
  /** Survives poller restarts so the same inbox request is not double-prompted. */
  const forwardingClaimedIds = new Set<string>();

  function applyAutoModePermissionStrip(): void {
    if (currentMode === "auto") {
      const stripped = stripDangerousPermissionRules(basePermissionRules);
      strippedDangerousRules = stripped.stashed;
      mergedPermissionRules = stripped.active;
    } else {
      strippedDangerousRules = [];
      mergedPermissionRules = basePermissionRules;
    }
  }

  function reloadMergedPermissionRules(cwd: string): void {
    basePermissionRules = loadMergedPermissionRules(cwd);
    applyAutoModePermissionStrip();
    // Memoized verdicts may depend on the old rules — drop them.
    invalidateClassifierVerdictCache();
  }

  // ---- model-profile state -----------------------------------------------
  // activeProfile === undefined means "no profile active" — the extension
  // works as before (no auto model switching). The /model-profile command and
  // --model-profile flag set this; persistState() persists it; session_start
  // restores it and re-applies the model.
  let activeProfile: string | undefined = undefined;
  let modelProfileConfig: ModelProfilesConfig = {};

  // streaming stats (for the working-indicator readout)
  let streamStart = 0;
  let outputAtStart = 0;
  let lastTps = 0;
  let gitBranch = "";

  // ---- small helpers -----------------------------------------------------
  const isAssistant = (m: any): boolean =>
    !!m && m.role === "assistant" && Array.isArray(m.content);

  const getText = (m: any): string =>
    Array.isArray(m?.content)
      ? m.content
          .filter((c: any) => c?.type === "text")
          .map((c: any) => c.text)
          .join("\n")
      : typeof m?.content === "string"
        ? m.content
        : "";

  function persistState(): void {
    pi.appendEntry("modes", {
      currentMode,
      activeProfile,
      planPhase,
      planExecuting,
      planTodos,
      lastExtractedPlanHash,
      unattended: unattendedMode,
    });
  }

  /** Soft-denial text for unattended mode: the escalation ladder. Counting is per
   *  denial FAMILY (see denialFamily), because keying on argv resets on every
   *  rewrite and so measures stubbornness rather than progress. */
  function unattendedDenialText(
    key: string,
    opts?: { wall?: DenialWall; tier?: "allow" | "ask" | "never" },
  ): string {
    const n = (unattendedDenialCounts.get(key) ?? 0) + 1;
    if (unattendedDenialCounts.size < 200) unattendedDenialCounts.set(key, n);
    return unattendedEscalation({
      wall: opts?.wall ?? "analysis",
      tier: opts?.tier ?? "ask",
      attempt: n,
    });
  }

  type ApprovalDecision =
    | "allow"
    | "allow_always_local"
    | "allow_always_global"
    /** Forget every remembered allowance covering this target (journal-backed deny; see durable-approval.ts). */
    | "deny_always"
    | "bypass"
    | "block";

  /**
   * Single place that executes an approval decision's side effects:
   * allow-always persistence + rule reload + gitignore warning + notify,
   * outside-write tracking on EVERY allow path, compliance-inject on block.
   * The three approval flows (interactive select, ask-mode inline select,
   * forwarded-parent responder) used to duplicate this and had diverged —
   * the ask flow dropped write tracking and notifications.
   * Options narrow execution for the forwarding paths:
   * - ruleCwd: parent responder persists rules against the child's cwd
   * - persistRules:false when the other side already persisted (child poll)
   * - trackWrite:false on the parent responder (tracking is the child's job)
   */
  async function applyApprovalDecision(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    decision: ApprovalDecision,
    opts: {
      category?: string;
      ruleCwd?: string;
      persistRules?: boolean;
      trackWrite?: boolean;
      blockReason?: string;
      /** Write exactly these rules instead of deriving one from the call (folder scope). */
      rulesOverride?: string[];
      /** The "this folder" click: store one scope row instead of an entity row. */
      folderScope?: boolean;
    } = {},
  ): Promise<Block | undefined> {
    const ruleCwd = opts.ruleCwd ?? ctx.cwd;
    const persistRules = opts.persistRules !== false;
    const trackWrite = opts.trackWrite !== false;

    const trackOutsideWrite = (): void => {
      if (trackWrite && (tool === "edit" || tool === "write")) {
        trackOutsideWriteIfNeeded(ctx, tool, String(input.path ?? ""));
      }
    };

    if (decision === "allow") {
      trackOutsideWrite();
      return undefined;
    }
    if (
      decision === "allow_always_local" ||
      decision === "allow_always_global"
    ) {
      // Journal-backed authority — the zero-rule-file policy. Two conditions, deliberately: the setting must say
      // "grants" AND a layer must have actually said it. `DEFAULT_AUTHORITY_PERSIST` is "grants" so the live
      // workspace needs no file, but an unset config is not a decision to stop remembering clicks — under
      // grants, a command with no file target has no row that can express it, so making the policy
      // apply by default would silently turn "Allow always" into "allow once" for anyone who never opted in.
      if (
        getAuthorityPersist() === "grants" &&
        getAuthorityPersistOrigin() !== "default"
      ) {
        const rows = durableRowsForApproval({
          tool,
          input,
          category: opts.category,
          cwd: ruleCwd,
          folderScope: opts.folderScope === true,
        });
        if ("reason" in rows) {
          ctx.ui.notify(
            `No durable allowance stored${rows.reason ? `: ${rows.reason}` : ""}. Allowing this once.`,
            "warning",
          );
        } else {
          for (const row of rows.rows) {
            addGrant(gateGrants, row.category, row.value, row.kind, true);
          }
          writeLedgerSnapshot();
          ctx.ui.notify(
            `Remembered ${rows.rows.length} durable allowance${rows.rows.length === 1 ? "" : "s"}: ${rows.rows
              .map((r) => `${r.category} ${r.value}`)
              .join(", ")}`,
          );
        }
        trackOutsideWrite();
        return undefined;
      }
      if (persistRules) {
        // EVERY rule this approval stands for, one per command segment. A single
        // rule from the head of a compound covered one clause while coverage now
        // needs all of them, which is how "always allow" ended up not sticking.
        const set = opts.rulesOverride
          ? { rules: opts.rulesOverride, persistable: true }
          : suggestAllowRuleSetForToolCall(tool, input, ruleCwd);
        const destination =
          decision === "allow_always_local" ? "local" : "global";
        if (!set.persistable) {
          // Nothing safe to write: honour this one call, say why, and leave the
          // rules alone rather than storing something broader than the approval.
          ctx.ui.notify(
            `No always-allow rule written${set.reason ? `: ${set.reason}` : ""}. Allowing this once.`,
            "warning",
          );
        } else {
          const written: string[] = [];
          for (const rule of set.rules) {
            if (
              addPermissionRule({
                rule,
                behavior: "allow",
                destination,
                cwd: ruleCwd,
              })
            ) {
              written.push(rule);
            }
          }
          if (written.length > 0) {
            reloadMergedPermissionRules(ctx.cwd);
            if (decision === "allow_always_local") {
              warnIfLocalPermissionsNotGitignored(ruleCwd, (msg) =>
                ctx.ui.notify(msg, "warning"),
              );
            }
            // Singular phrasing kept byte-identical to the previous message so the
            // parity tests over this notification keep guarding real behaviour;
            // only a multi-rule approval reads differently.
            const label = destination === "local" ? "project local" : "global";
            ctx.ui.notify(
              written.length === 1
                ? `Added allow rule (${label}): ${written[0]}`
                : `Added ${written.length} allow rules (${label}): ${written.join(", ")}`,
            );
          }
        }
      } else {
        // Rules were persisted by the other side; just pick them up.
        reloadMergedPermissionRules(ctx.cwd);
      }
      trackOutsideWrite();
      return undefined;
    }
    if (decision === "bypass") {
      await setMode("bypass", ctx);
      trackOutsideWrite();
      return undefined;
    }
    if (decision === "deny_always") {
      // Deny-always is revocation, not a new row type: durable forbid rows would need their own precedence and
      // their own restore path, and an unrestoreable deny is the worst failure this project has already lived
      // through. Tombstones are proven (a revoked row stays revoked across import), and if this ever fails the
      // system re-prompts rather than silently allowing — the failure costs a keystroke, not a secret.
      const found = approvalTargets({ tool, input, cwd: ruleCwd });
      if ("targets" in found) {
        const gone = revokeRows(
          gateGrants,
          rowCoversTargets(found.targets, {
            home: homedir(),
            project: findProjectRoot(ruleCwd) ?? undefined,
          }),
          { quote: "denied always (clicked)" },
        );
        if (gone.length > 0) {
          writeLedgerSnapshot();
          ctx.ui.notify(
            `Revoked ${gone.length} remembered allowance${gone.length === 1 ? "" : "s"} covering ${found.targets.join(", ")}`,
            "warning",
          );
        }
      }
      return {
        block: true,
        reason:
          opts.blockReason ??
          `${tool} denied by user (always). Remembered allowances covering this target were revoked.`,
      };
    }
    return {
      block: true,
      reason: opts.blockReason ?? `${tool} blocked by user`,
    };
  }

  async function promptWithPermissionOptions(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    label: string,
    category: string,
  ): Promise<Block> {
    if (!ctx.hasUI) {
      const isChild = isSubagentChildProcess();
      const parent = resolveParentSessionId();
      // Only forward to a parent session when we're clearly a subagent child.
      // PI_SUBAGENT_PARENT_SESSION alone is not sufficient — it's often set in
      // the parent process env and inherited by unrelated processes (tests,
      // ad-hoc node calls), which would block forever waiting for a response
      // that never comes. Fail closed otherwise.
      if (!parent || !isChild) {
        return {
          block: true,
          reason:
            `${tool} not auto-approved: no UI available. ${label}.` +
            unattendedDenialText(`${tool}|${label}`),
        };
      }
      const agentDir = defaultAgentDir();
      const requesterSessionId =
        readSessionId(ctx.sessionManager) ?? "";
      const { id, challenge } = await writeForwardedRequest({
        agentDir,
        targetSessionId: parent,
        requesterSessionId,
        tool,
        label,
        category,
        cwd: ctx.cwd,
        input,
      });
      const resp = await pollForwardedResponse(agentDir, parent, id, {
        challenge,
      });
      if (!resp?.approved) {
        return {
          block: true,
          reason:
            resp?.denialReason ??
            `${tool} blocked: parent approval timed out or denied. ${label}`,
        };
      }
      if (
        resp.decision === "allow_always_local" ||
        resp.decision === "allow_always_global"
      ) {
        return applyApprovalDecision(ctx, tool, input, resp.decision, {
          persistRules: false,
        });
      }
      return applyApprovalDecision(ctx, tool, input, "allow");
    }
    if (unattendedMode) {
      return {
        block: true,
        reason: `${tool} not auto-approved: ${label}.` + unattendedDenialText(`${tool}|${label}`),
      };
    }
    // Show exactly what an always-allow would write BEFORE the choice is made, and
    // withhold the option entirely when it cannot be honoured (run-time values,
    // shell control flow): an offer that would store a rule broader than the
    // approval is worse than no offer.
    const ruleSet = suggestAllowRuleSetForToolCall(tool, input, ctx.cwd);
    // Journal-backed authority (authority.persist = "grants", explicitly chosen — see applyApprovalDecision for
    // why the origin matters) stores grant rows, not rules — so the preview has to describe rows. A prompt that
    // says "would write Bash(rm -rf /tmp/x)" while storing a grant row is a UI describing a store it is not
    // writing, and users click on that text.
    const journalBacked =
      getAuthorityPersist() === "grants" &&
      getAuthorityPersistOrigin() !== "default";
    const previewRows = journalBacked
      ? durableRowsForApproval({
          tool,
          input,
          category,
          cwd: ctx.cwd,
          folderScope: false,
        })
      : null;
    const previewFolder = journalBacked
      ? durableRowsForApproval({
          tool,
          input,
          category,
          cwd: ctx.cwd,
          folderScope: true,
        })
      : null;
    // Folder scope is offered only when suggestFolderAllowRule returns a rule that would actually
    // match later calls — it withholds the offer on a secret-classified path, where a `**` rule is
    // dead on arrival. Shown before the choice, like the rule it would write.
    const folderRule = ruleSet.persistable
      ? suggestFolderAllowRule(tool, input, ctx.cwd)
      : undefined;
    const canOfferAlways = journalBacked
      ? previewRows !== null && "rows" in previewRows
      : ruleSet.persistable;
    const canOfferFolder = journalBacked
      ? previewFolder !== null && "rows" in previewFolder
      : !!folderRule;
    const ruleNote = journalBacked
      ? canOfferAlways
        ? ` Always-allow will remember: ${previewRows && "rows" in previewRows ? previewRows.rows.map((r) => `${r.category} ${r.value}`).join(", ") : ""}` +
          (canOfferFolder && previewFolder && "rows" in previewFolder
            ? ` | folder scope: ${previewFolder.rows.map((r) => r.value).join(", ")}`
            : "")
        : ` No always-allow available${previewRows && "reason" in previewRows ? `: ${previewRows.reason}` : ""}.`
      : ruleSet.persistable
        ? ` Always-allow would write: ${ruleSet.rules.join(", ")}` +
          (folderRule ? ` | folder scope: ${folderRule}` : "")
        : ` No always-allow available${ruleSet.reason ? `: ${ruleSet.reason}` : ""}.`;
    const choice = await ctx.ui.select(`Allow ${tool}? ${label}.${ruleNote}`, [
      "Allow",
      ...(canOfferAlways
        ? [
            ...(canOfferFolder ? ["Allow always (this folder)"] : []),
            "Allow always (this project)",
            "Allow always (global)",
          ]
        : []),
      // Offered only where it has durable effect. Under rule-file authority a click here could revoke grant
      // rows while a stored rule kept allowing the call next time — an offer that overstates what it does.
      ...(journalBacked ? ["Deny always (revoke remembered allowance)"] : []),
      "Block",
    ]);
    if (choice === "Allow always (this folder)" && canOfferFolder) {
      return applyApprovalDecision(ctx, tool, input, "allow_always_local", {
        category,
        folderScope: true,
        rulesOverride: journalBacked ? undefined : folderRule ? [folderRule] : undefined,
      });
    }
    const decision: ApprovalDecision =
      choice === "Allow always (this project)"
        ? "allow_always_local"
        : choice === "Allow always (global)"
          ? "allow_always_global"
          : choice === "Deny always (revoke remembered allowance)"
            ? "deny_always"
            : choice === "Allow"
              ? "allow"
              : "block";
    return applyApprovalDecision(ctx, tool, input, decision, { category });
  }

  async function promptAutoTier3(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    reason: string,
    category: string,
  ): Promise<Block> {
    return promptWithPermissionOptions(ctx, tool, input, reason, category);
  }

  function classifierErrorMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
  }

  function logClassifierUnavailable(err: unknown, attempt: number): void {
    const debug = process.env.PERMISSION_MODES_CLASSIFIER_DEBUG === "1";
    const message = classifierErrorMessage(err);
    const line = `[permission-modes] Classifier unavailable (${attempt}/${MAX_CLASSIFIER_FAILURES}): ${message}`;
    if (debug) {
      console.warn(line);
      if (err instanceof Error && err.stack) console.debug(err.stack);
      return;
    }
    if (attempt >= MAX_CLASSIFIER_FAILURES) {
      console.warn(line);
    }
  }

  type LocalAutoTier3Decision =
    | { allow: true }
    | { allow: false; reason: string; category: string };

  function resolveLocalAutoTier3(
    tool: string,
    input: Record<string, unknown>,
    riskInput: {
      tool: string;
      command?: string;
      path?: string;
    },
    cwd: string,
  ): LocalAutoTier3Decision {
    const risk = checkAutoRisk(riskInput, cwd);
    if (risk.match) {
      return { allow: false, reason: risk.reason, category: risk.category };
    }

    const isKnownTier3 =
      tool === "bash" || tool === "edit" || tool === "write";
    if (!isKnownTier3) {
      return {
        allow: false,
        reason: `Tool "${tool}" is not auto-approved in auto mode. Enable classifier or switch to bypass.`,
        category: "unknown-tool",
      };
    }
    if (tool === "bash") {
      const cmd = String(input.command ?? "");
      if (cmd && !isFallbackBash(cmd, cwd)) {
        return {
          allow: false,
          reason: `Mutating bash in auto mode: ${cmd}`,
          category: "mutating-bash",
        };
      }
    }
    return { allow: true };
  }

  function finishAutoTier3Allow(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
  ): undefined {
    if (tool === "edit" || tool === "write") {
      trackOutsideWriteIfNeeded(ctx, tool, String(input.path ?? ""));
    }
    return undefined;
  }

  function classifierDenyBlock(tool: string, reason: string): Block {
    return { block: true, reason: buildYoloRejectionMessage(reason) };
  }

  /** Debounced snapshot of ledger + session grants into the session file.
   *  Losing one is only an optimization loss: temp-0 extraction rebuilds the
   *  ledger deterministically via backfill (proper-permission-ledger.md §2.6). */
  function writeLedgerSnapshot(): void {
    try {
      pi.appendEntry("gate-ledger", {
        v: 1,
        ledger: serializeLedger(gateLedger),
        grants: gateGrants.grants,
      });
    } catch {
      /* snapshot loss is recoverable — see above */
    }
    autoExportGrantsToFile();
  }

  /** Mirror the live ledger into the workspace journal named by `grantsAutoImport.path` on every change.
   *
   *  Manual `/grants export` **replaces** the file; this **merges**, because a workspace journal can hold rows
   *  another session wrote and overwriting them would silently delete authority somebody already gave.
   *
   *  Shares its switch with auto-import: `grantsAutoImport` now means two-way sync, not import-only. Without
   *  this, prompt answers live only in the session transcript — a crash loses them, which is the reason
   *  "grants via prompts" felt too risky to lean on. */
  function autoExportGrantsToFile(): void {
    try {
      const setting = loadPermissionModesConfig().grantsAutoImport;
      if (!setting?.enabled) return;
      // session_start sets bridgeCwd; before that there is nothing to resolve a bare name against.
      if (!bridgeCwd) return;
      const dest = resolveGrantPath(setting.path, bridgeCwd);
      // Pass the STORE, not just its rows: the revocations it carries have to travel with the grants, or a
      // revoked row that another session still holds comes back on the next union.
      const res = mergeIntoGrantsFile(dest, serializeLedger(gateLedger), gateGrants, {
        sourceCwd: bridgeCwd,
      });
      if (!res.ok) {
        // Loud on purpose: a journal we cannot write means approvals are not surviving a restart.
        console.log(`[permission-modes] grant journal NOT updated (${dest}): ${res.error}`);
      }
    } catch {
      /* persistence must never break the gate */
    }
  }

  function scheduleLedgerPersist(): void {
    // Every grant/revoke path funnels through here, and the bridge must be live
    // rather than debounced: a job firing seconds after an approval (or after
    // `/grants revoke`) has to see the current state, not a 2s-old one.
    publishBridgeState();
    if (ledgerPersistTimer) clearTimeout(ledgerPersistTimer);
    ledgerPersistTimer = setTimeout(() => {
      ledgerPersistTimer = undefined;
      writeLedgerSnapshot();
    }, 2000);
    (ledgerPersistTimer as { unref?: () => void }).unref?.();
  }

  /** The debounce timer is unref'd (must not keep pi alive), so a headless -p
   *  run can exit before it fires — flush pending snapshots at turn end. */
  function flushLedgerPersist(): void {
    if (!ledgerPersistTimer) return;
    clearTimeout(ledgerPersistTimer);
    ledgerPersistTimer = undefined;
    writeLedgerSnapshot();
  }

  /** Drain unseen user messages into the ledger in the background, newest-first.
   *  Yields to live gate calls; stops when done, on repeated failure, or when a
   *  new session starts. Restarted lazily by the next gate invocation. */
  function startLedgerBackfill(ctx: ExtensionContext, endpoint: ModelEndpoint): void {
    if (ledgerBackfillActive) return;
    ledgerBackfillActive = true;
    const debugOn = process.env.PERMISSION_MODES_CLASSIFIER_DEBUG === "1";
    const myLedger = gateLedger;
    void (async () => {
      try {
        let prevPending = Infinity;
        for (;;) {
          if (gateLedger !== myLedger) return; // session changed / cleared
          if (gateCallInFlight) {
            await new Promise((res) => setTimeout(res, 300));
            continue;
          }
          const refs = collectUserMessageRefs(readBranchEntries(ctx.sessionManager) as never);
          const sync = await syncLedger({
            refs,
            ledger: myLedger,
            endpoint,
            maxCalls: 4,
            backfillLimit: classifierConfig.ledgerBackfillLimit,
            debug: debugOn ? (l) => console.debug("[permission-modes]", l) : undefined,
          });
          if (sync.changed) scheduleLedgerPersist();
          if (sync.pending === 0) return;
          if (sync.pending >= prevPending) return; // extraction failing — retry on next gate call
          prevPending = sync.pending;
          await new Promise((res) => setTimeout(res, 150));
        }
      } catch {
        /* fail-safe: unprocessed messages fall back to the prompt path */
      } finally {
        ledgerBackfillActive = false;
      }
    })();
  }

  async function approveAutoWithGate(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
  ): Promise<Block | undefined> {
    const debugOn = process.env.PERMISSION_MODES_CLASSIFIER_DEBUG === "1";
    // The resolver knows WHY there is no endpoint; the denial text used to guess. Take the reason with the endpoint.
    const resolution = classifierConfig.enabled
      ? await resolveGateEndpointWithFailure(classifierConfig, ctx.modelRegistry as any)
      : {};
    const endpoint = resolution.endpoint;
    let branch: Array<{ type?: string; message?: { role?: string; content?: unknown } }> = [];
    try {
      branch = (ctx.sessionManager as any).getBranch?.() ?? [];
    } catch {
      // gate still runs on the pending action alone
    }
    const userMessages = collectUserMessagesFromBranch(branch);
    const ledgerOn = classifierConfig.ledger !== false;
    // One policy object for both calls: the attribution below resolves the entities the gate returned
    // against the SAME root layer 0 used, and re-deriving it anywhere else mis-resolves them.
    const gatePolicy = { cwd: ctx.cwd, project: ctx.cwd, home: homedir() };
    // What the caller still knows after the gate returns, for the denial text: whether THIS call had a
    // model endpoint, how much transcript it was given, and which ledger it consulted. Without these
    // three the rendered denial can only say `undetermined`.
    const gateKnowledge: GateDenialKnowledge = {
      policy: gatePolicy,
      endpoint: endpoint !== undefined,
      // "no endpoint" is two states with different levers: nothing configured, or a classifier that exists and
      // could not be used. The resolver knows which, so say it instead of letting the denial text guess.
      endpointFailure: resolution.failure,
      userMessages: userMessages.length,
      ledger: ledgerOn ? gateLedger : undefined,
    };
    gateCallInFlight = true;
    let r: GateResult;
    try {
      // Fold the newest unseen user messages into the ledger (≤2 calls inline,
      // typically 1: the message that started this turn). Larger backlogs —
      // resumed pre-plugin sessions, restarts without a snapshot — drain in the
      // background without blocking this tool call.
      if (endpoint && ledgerOn) {
        try {
          const sync = await syncLedger({
            refs: collectUserMessageRefs(branch as never),
            ledger: gateLedger,
            endpoint,
            maxCalls: 2,
            backfillLimit: classifierConfig.ledgerBackfillLimit,
            signal: ctx.signal,
            debug: debugOn ? (l) => console.debug("[permission-modes]", l) : undefined,
          });
          if (sync.changed) scheduleLedgerPersist();
          if (sync.pending > 0) startLedgerBackfill(ctx, endpoint);
        } catch {
          /* ledger sync must never block the gate; fallback paths cover it */
        }
      }
      try {
        r = await runGate(tool, input, {
          policy: gatePolicy,
          endpoint,
          grants: gateGrants,
          ledger: ledgerOn ? gateLedger : undefined,
          userMessages,
          signal: ctx.signal,
          debug: debugOn ? (l) => console.debug("[permission-modes]", l) : undefined,
        });
      } catch (err) {
        return promptAutoTier3(
          ctx,
          tool,
          input,
          `gate error: ${err instanceof Error ? err.message : String(err)}`,
          "gate-error",
        );
      }
    } finally {
      gateCallInFlight = false;
    }
    // Reset the fix-retry counter as soon as a command parses cleanly.
    if (!r.unparseable) consecutiveUnparseable = 0;
    if (r.outcome === "allow" || r.outcome === "allow-granted") {
      classifierDenialState = recordClassifierSuccess(classifierDenialState);
      if (r.grantedBy) {
        // runGate promoted ledger/transcript grants into the session store
        scheduleLedgerPersist();
        if (debugOn) {
          console.debug(`[permission-modes] gate allow (${r.grantedBy}): ${r.reason}`);
        }
      }
      return finishAutoTier3Allow(ctx, tool, input);
    }
    if (r.unparseable) {
      return await handleUnparseable(ctx, tool, input, r, debugOn);
    }
    return promptGateApproval(ctx, tool, input, r, gateKnowledge);
  }

  /** A malformed command (unterminated quote/heredoc/substitution) is never a
   *  user permission question — we can't classify it, so we refuse to run it and
   *  ask the model to rewrite/simplify. The model receives this as the tool
   *  result and retries on its own; the user is not prompted. A budget bounds
   *  the loop: past it, unattended parks the step and attended asks the human. */
  async function handleUnparseable(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    r: GateResult,
    debugOn: boolean,
  ): Promise<Block> {
    consecutiveUnparseable++;
    const why = r.reason || "it does not parse cleanly";
    const fix =
      `${tool} was not run: I couldn't safely analyze this command — ${why}. ` +
      `Rewrite it as simpler command(s): avoid deeply nested quoting, split multi-step ` +
      `pipelines, and put complex awk/sed/python programs in a temp script file or a ` +
      `heredoc instead of inline. Then try again.`;
    if (debugOn) {
      console.debug(
        `[permission-modes] unparseable (#${consecutiveUnparseable}): ${why}`,
      );
    }
    if (consecutiveUnparseable <= UNPARSEABLE_RETRY_BUDGET) {
      return { block: true, reason: fix };
    }
    // budget exhausted
    if (unattendedMode) {
      return {
        block: true,
        reason:
          `${fix} You have produced ${consecutiveUnparseable} unparseable commands in a row — ` +
          `stop retrying this step, park it, and continue with other work; list parked steps when the user returns.`,
      };
    }
    // attended: hand it to the human, who can see the agent is stuck
    return promptWithPermissionOptions(
      ctx,
      tool,
      input,
      `⚠️ the agent produced ${consecutiveUnparseable} commands in a row that don't parse (${why}). Last command shown below.`,
      "unparseable_command",
    );
  }

  async function promptGateApproval(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    r: GateResult,
    /** Only what the caller already knows about this call; absent = nothing, and the denial reads
     *  `undetermined` rather than guessing. */
    known?: GateDenialKnowledge,
  ): Promise<Block | undefined> {
    const label = gatePromptLabel(r);
    // Who refused, as far as this call site can actually say: `known` is what the caller observed
    // (endpoint, transcript size, which ledger the gate consulted), and a call site that has none of it
    // gets `undetermined` rather than a guess. `blockedByHuman` belongs to the Block path alone — a
    // person answered, and no policy layer outranks that.
    const whoRefused = (blockedByHuman = false) =>
      known
        ? gateDenialAttribution({ result: r, ...known, blockedByHuman })
        : blockedByHuman
          ? { decidedBy: "user" as const }
          : {};
    // A session with no UI can never answer a prompt, so it behaves as unattended
    // even when /unattended was never toggled — a fresh in-memory subagent session
    // starts with unattendedMode=false and would otherwise block on a dialog that
    // cannot appear. Never-tier still blocks; only the guidance text differs.
    if (unattendedMode || !ctx.hasUI) {
      classifierDenialState = recordClassifierDenial(classifierDenialState);
      const key = denialFamily({
        tool,
        category: r.category,
        targets: r.entities.filter((e) => e.kind === "target").map((e) => e.value),
      });
      return {
        block: true,
        reason:
          gateDenialMessage(r, { ...whoRefused(), unattended: true }) +
          unattendedDenialText(key, { wall: denialWall(r), tier: r.tier }),
      };
    }
    if (!ctx.hasUI) {
      if (r.tier === "never") {
        return { block: true, reason: gateDenialMessage(r, whoRefused()) };
      }
      return promptWithPermissionOptions(ctx, tool, input, label, r.category);
    }
    const targets = r.entities.filter((e) => e.kind === "target").map((e) => e.value);
    const scopes = r.entities.filter((e) => e.kind === "scope").map((e) => e.value);
    const sessionEntityOption = targets.length
      ? `Allow for session: ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? ", …" : ""}`
      : undefined;
    const sessionScopeOption = scopes.length
      ? `Allow for session (scope ${scopes[0]})`
      : undefined;
    const options: string[] = ["Allow"];
    const folderRule = r.tier !== "never" ? suggestFolderAllowRule(tool, input, ctx.cwd) : undefined;
    if (r.tier !== "never") {
      if (sessionEntityOption) options.push(sessionEntityOption);
      if (sessionScopeOption) options.push(sessionScopeOption);
      if (folderRule) options.push("Allow always (this folder)");
      options.push("Allow always (this project)", "Allow always (global)");
    }
    options.push("Block");
    const choice = await ctx.ui.select(`Allow ${tool}? ${label}`, options);
    if (choice === undefined || choice === "Block") {
      classifierDenialState = recordClassifierDenial(classifierDenialState);
      // The person at the dialog is the author of this refusal. Anything else in the line would send
      // the agent off to argue with a policy that a human just answered.
      return {
        block: true,
        reason: gateDenialMessage(r, whoRefused(true)),
      };
    }
    if (sessionEntityOption && choice === sessionEntityOption) {
      for (const t of targets) addGrant(gateGrants, r.category, t, "entity");
      scheduleLedgerPersist();
    } else if (sessionScopeOption && choice === sessionScopeOption) {
      for (const sc of scopes) addGrant(gateGrants, r.category, sc, "scope");
      scheduleLedgerPersist();
    } else if (choice === "Allow" && r.tier !== "never" && targets.length) {
      // a plain Allow used to remember nothing, so the identical action
      // prompted again next turn — record the entity grants too
      for (const t of targets) addGrant(gateGrants, r.category, t, "entity");
      scheduleLedgerPersist();
    } else if (choice === "Allow always (this folder)" && folderRule) {
      return applyApprovalDecision(ctx, tool, input, "allow_always_local", {
        category: r.category,
        rulesOverride: [folderRule],
      });
    } else if (choice === "Allow always (this project)") {
      return applyApprovalDecision(ctx, tool, input, "allow_always_local", { category: r.category });
    } else if (choice === "Allow always (global)") {
      return applyApprovalDecision(ctx, tool, input, "allow_always_global", { category: r.category });
    }
    classifierDenialState = recordClassifierSuccess(classifierDenialState);
    return finishAutoTier3Allow(ctx, tool, input);
  }

  async function approveAutoTier3(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
    riskInput: {
      tool: string;
      command?: string;
      path?: string;
    },
  ): Promise<Block> {
    const reviewHint = describeTier3Review(tool, input, ctx.cwd);

    if (classifierConfig.enabled) {
      for (let attempt = 1; attempt <= MAX_CLASSIFIER_FAILURES; attempt++) {
        try {
          const verdict = await classifyToolCall({
            modelRef: classifierConfig.model,
            session: collectClassifierSessionContext(ctx, reviewHint),
            pendingTool: { name: tool, input },
            registry: ctx.modelRegistry as any,
            autoMode: autoModeConfig,
            timeoutMs: classifierConfig.timeoutMs,
            jsonlTranscript: classifierConfig.jsonlTranscript,
            stage: classifierConfig.stage,
            includeAgentsMd: classifierConfig.includeAgentsMd,
            contextTokens: classifierConfig.contextTokens,
            signal: ctx.signal,
            debug: process.env.PERMISSION_MODES_CLASSIFIER_DEBUG === "1",
          });
          if (!verdict.allow) {
            classifierDenialState = recordClassifierDenial(classifierDenialState);
            if (shouldFallbackToPrompting(classifierDenialState)) {
              return promptAutoTier3(
                ctx,
                tool,
                input,
                verdict.reason || "Blocked by auto classifier (denial limit)",
                "classifier-limit",
              );
            }
            return classifierDenyBlock(
              tool,
              verdict.reason || "Blocked by auto classifier",
            );
          }
          classifierDenialState = recordClassifierSuccess(classifierDenialState);
          return finishAutoTier3Allow(ctx, tool, input);
        } catch (err) {
          if (attempt < MAX_CLASSIFIER_FAILURES) {
            if (process.env.PERMISSION_MODES_CLASSIFIER_DEBUG === "1") {
              console.debug(
                `[permission-modes] Classifier retry (${attempt}/${MAX_CLASSIFIER_FAILURES}): ${classifierErrorMessage(err)}`,
              );
            }
            continue;
          }
          logClassifierUnavailable(err, attempt);
          if (classifierConfig.failClosed !== false) {
            return classifierDenyBlock(
              tool,
              buildClassifierUnavailableMessage(tool, classifierConfig.model, {
                classifierWhy: "unavailable",
                classifierCause: classifierErrorMessage(err),
              }),
            );
          }
          break;
        }
      }
    }

    const local = resolveLocalAutoTier3(tool, input, riskInput, ctx.cwd);
    if (!local.allow) {
      return promptAutoTier3(ctx, tool, input, local.reason, local.category);
    }
    classifierDenialState = recordClassifierSuccess(classifierDenialState);
    return finishAutoTier3Allow(ctx, tool, input);
  }

  function trackOutsideWriteIfNeeded(
    ctx: ExtensionContext,
    tool: "edit" | "write",
    pathStr: string,
  ): void {
    if (!pathStr || !isOutsideCwd(pathStr, ctx.cwd)) return;
    const resolvedPath = resolveWorkspacePath(pathStr, ctx.cwd);
    let backupContent: string | null = null;
    try {
      backupContent = readFileSync(resolvedPath, "utf-8");
    } catch {
      backupContent = null;
    }
    trackOutsideWrite(ctx.cwd, {
      timestamp: new Date().toISOString(),
      originalPath: resolvedPath,
      toolName: tool,
      backupContent,
    });
    if (ctx.hasUI) {
      ctx.ui.notify(
        `📝 tracked outside-cwd ${tool}: ${shortenPath(resolvedPath)}`,
        "info",
      );
    }
  }

  function describeTier3Review(
    tool: string,
    input: Record<string, unknown>,
    cwd: string,
  ): string {
    if (tool === "bash") {
      const cmd = String(input.command ?? "");
      if (cmd && !isReadOnlyBash(cmd, cwd)) {
        return "Bash did not pass read-only allowlist; may include writes, installs, or unknown binaries.";
      }
      return "Bash requires tier-3 review.";
    }
    if (tool === "edit" || tool === "write") {
      const pathStr = String(input.path ?? "");
      if (pathStr && isOutsideCwd(pathStr, cwd)) {
        return `Write/edit outside working directory (${cwd}).`;
      }
      return "File write/edit requires tier-3 review.";
    }
    return `Tool "${tool}" is not auto-approved without classifier.`;
  }

  function collectClassifierSessionContext(
    ctx: ExtensionContext,
    reviewHint?: string,
  ): ClassifierSessionContext {
    let branch: ClassifierSessionContext["branch"] = [];
    try {
      branch = readBranchEntries(ctx.sessionManager);
    } catch {
      // classifier still runs with pending action only
    }
    const includeAgentsMd = classifierConfig.includeAgentsMd !== false;
    return {
      cwd: ctx.cwd,
      mode: currentMode,
      branch,
      reviewHint,
      agentsMd: includeAgentsMd
        ? readAgentsMdForClassifier(ctx.cwd)
        : null,
    };
  }

  // ---- tool gating -------------------------------------------------------
  function applyToolRestrictions(): void {
    if (planExecuting) {
      if (toolsBeforePlanMode !== undefined) {
        pi.setActiveTools(toolsBeforePlanMode);
        toolsBeforePlanMode = undefined;
      }
      return;
    }
    if (currentMode === "plan") {
      if (toolsBeforePlanMode === undefined)
        toolsBeforePlanMode = pi.getActiveTools();
      const kept = toolsBeforePlanMode.filter((t) => !PLAN_DISABLED.has(t));
      pi.setActiveTools([...new Set([...kept, ...PLAN_TOOLS])]);
    } else if (toolsBeforePlanMode !== undefined) {
      pi.setActiveTools(toolsBeforePlanMode);
      toolsBeforePlanMode = undefined;
    }
  }

  // ---- mode switching ----------------------------------------------------
  async function setMode(mode: Mode, ctx: ExtensionContext): Promise<void> {
    const prev = currentMode;

    if (prev === "auto" && mode !== "auto" && strippedDangerousRules.length) {
      basePermissionRules = restoreDangerousPermissionRules(
        mergedPermissionRules,
        strippedDangerousRules,
      );
      strippedDangerousRules = [];
    }

    currentMode = mode;
    needsAskReminder = mode === "ask";
    needsBypassSecurityReminder = mode === "bypass";
    planExecuting = false;

    if (mode === "auto") {
      classifierDenialState = createDenialTrackingState();
      applyAutoModePermissionStrip();
    } else if (prev === "auto") {
      applyAutoModePermissionStrip();
    }

    if (mode !== "plan") {
      planPhase = "exploring";
      lastExtractedPlanHash = "";
    }
    if (mode === "plan") {
      ensurePlanFile(ctx.cwd);
      if (prev !== "plan") planPhase = "exploring";
    }

    planTodos = [];
    if (ctx.hasUI) ctx.ui.setWidget("plan-todos", undefined);

    applyToolRestrictions();
    updateStatus(ctx);
    await applyProfileModelForMode(mode, ctx);
    persistState();
    publishInheritedPermissionMode(mode);
    publishCapability({ mode });
    publishBridgeState();
  }

  function cycleMode(ctx: ExtensionContext): void {
    const idx = MODE_CYCLE.indexOf(currentMode);
    void setMode(MODE_CYCLE[(idx + 1) % MODE_CYCLE.length], ctx);
    if (ctx.hasUI) ctx.ui.notify(`Mode: ${MODE_META[currentMode].label}`);
  }

  // ---- model profile logic ----------------------------------------------
  /**
   * Switch the active model to match the one defined in `activeProfile` for
   * the given mode. No-op when no profile is active or when the profile has
   * no mapping for the mode. All failures log a notification and keep the
   * current model — never throw, never block the user.
   */
  async function applyProfileModelForMode(
    mode: Mode,
    ctx: ExtensionContext,
  ): Promise<void> {
    // Lazy first-time activation: if nothing has been activated but a
    // config file exists on disk, try to pick up the user's `active` profile
    // (or the `default` profile) so mode switches "just work".
    if (activeProfile === undefined) {
      const cfg = loadModelProfiles();
      if (Object.keys(cfg).length === 0) return;
      const candidate = cfg.active || "default";
      if (!profileExists(cfg, candidate)) return;
      activeProfile = candidate;
      modelProfileConfig = cfg;
    }

    // Re-load lazily to pick up external edits between mode switches.
    // Then re-stamp `active` with the in-memory `activeProfile` so the
    // shared `resolveModelForMode()` helper (which reads `config.active`)
    // honors any in-memory profile switches done via `/model-profile` or
    // Alt+I — the on-disk file is NOT modified here.
    const reloaded = loadModelProfiles();
    modelProfileConfig =
      activeProfile !== undefined && reloaded.active !== activeProfile
        ? { ...reloaded, active: activeProfile }
        : reloaded;

    const modelId = resolveModelForMode(modelProfileConfig, mode);
    if (!modelId) return; // profile has no mapping for this mode — keep current model

    const parsed = parseModelId(modelId);
    if (!parsed) {
      if (ctx.hasUI)
        ctx.ui.notify(
          `Invalid model ID "${modelId}" in profile "${activeProfile}"`,
          "warning",
        );
      return;
    }

    const model = ctx.modelRegistry.find(parsed.provider, parsed.model);
    if (!model) {
      if (ctx.hasUI)
        ctx.ui.notify(`Model "${modelId}" not found in registry`, "warning");
      return;
    }

    const success = await pi.setModel(model);
    if (!success) {
      if (ctx.hasUI)
        ctx.ui.notify(`No API key available for "${modelId}"`, "warning");
      return;
    }

    const effort = resolveEffortForMode(modelProfileConfig, mode);
    if (!effort) return;
    if (!PROFILE_EFFORT_LEVELS.has(effort)) {
      if (ctx.hasUI)
        ctx.ui.notify(
          `Unknown effort "${effort}" in profile "${activeProfile}" (expected: ${[...PROFILE_EFFORT_LEVELS].join(", ")})`,
          "warning",
        );
      return;
    }
    if (typeof pi.setThinkingLevel === "function") {
      pi.setThinkingLevel(effort as any);
    }
  }

  async function setActiveProfile(
    name: string,
    ctx: ExtensionContext,
  ): Promise<void> {
    const config = loadModelProfiles();
    if (!profileExists(config, name)) {
      if (ctx.hasUI) ctx.ui.notify(`Unknown profile "${name}"`, "error");
      return;
    }
    activeProfile = name;
    modelProfileConfig = config;
    await applyProfileModelForMode(currentMode, ctx);
    updateStatus(ctx);
    persistState();
    if (ctx.hasUI) ctx.ui.notify(`Profile "${name}" activated`, "info");
  }

  // ---- UI: status, footer, plan widget, working stats --------------------
  function updateStatus(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    ctx.ui.setStatus("modes", undefined);
  }

  function shortenPath(p: string): string {
    const home = homedir();
    return p && p.startsWith(home) ? `~${p.slice(home.length)}` : p;
  }

  // A badge naming where today's authority settings came from, shown only when they were not defaulted.
  // "The wall got stricter and I do not know why" is the confusion this pre-empts; when nothing was set
  // deliberately there is nothing to say, so the footer stays clean. Values are whitelisted source ids
  // (config.ts bounds them), never free text, so nothing a config file wrote can spoof the label.
  function authorityBadge(): string {
    const parts: string[] = [];
    const origin = getAuthorityPersistOrigin();
    if (origin && origin !== "default") parts.push(`${getAuthorityPersist()}@${origin}`);
    const prov = getProvenance();
    if (prov.modeSetBy && prov.modeSetBy !== "default") parts.push(`mode:${prov.modeSetBy}`);
    if (prov.unattendedSetBy && prov.unattendedSetBy !== "default") parts.push(`unattended:${prov.unattendedSetBy}`);
    return parts.length ? `  \u2696 ${parts.join(" ")}` : "";
  }

  function installFooter(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    ctx.ui.setFooter((_tui: any, theme: any) => ({
      render(width: number): string[] {
        const m = MODE_META[currentMode];
        const cwd = shortenPath(ctx.cwd);
        const cwdText = gitBranch ? `${cwd} (${gitBranch})` : cwd;

        const ctxUsage = (ctx as any).getContextUsage?.();
        let ctxStr = "";
        if (ctxUsage && ctxUsage.tokens != null && ctxUsage.percent != null) {
          const fmtK = (n: number) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : `${Math.round(n / 1000)}k`;
          ctxStr = `${fmtK(ctxUsage.tokens)}/${fmtK(ctxUsage.contextWindow)} ${ctxUsage.percent.toFixed(1)}%`;
        }

        const md = (ctx as any).model;
        let modelStr = "";
        if (md) {
          modelStr = md.name ? String(md.name) : String(md.id ?? "");
          const thinking =
            typeof (pi as any).getThinkingLevel === "function"
              ? (pi as any).getThinkingLevel()
              : undefined;
          if (thinking) modelStr += ` • ${thinking}`;
        }
        if (activeProfile) {
          modelStr = `profile:${activeProfile} · ${modelStr}`;
        }

        const cwdW = visibleWidth(cwdText);
        const ctxW = visibleWidth(ctxStr);
        const modelW = visibleWidth(modelStr);
        const modeText = `${m.icon} ${m.label} (shift+tab)${authorityBadge()}`;
        const modeW = visibleWidth(modeText);

        // Wide: line1 = cwd(L) + context(centered) + model(R), line2 = mode
        if (cwdW + ctxW + modelW + 4 <= width) {
          const leftGap = Math.max(2, Math.floor((width - ctxW) / 2) - cwdW);
          const rightGap = width - cwdW - leftGap - ctxW - modelW;
          if (rightGap >= 12) {
            const line1 =
              theme.fg("muted", cwdText) +
              " ".repeat(leftGap) +
              theme.fg("dim", ctxStr) +
              " ".repeat(rightGap) +
              theme.fg("dim", modelStr);
            const line2 = theme.fg(m.role, modeText);
            return [line1, line2];
          }
        }

        // Narrow: line1 = cwd(L) + context(R), line2 = mode(L) + model(R)
        // Pre-truncate plain text to guarantee fit
        let cwdDisp = cwdText;
        let cwdDispW = cwdW;
        let ctxDisp = ctxStr;
        let ctxDispW = ctxW;
        if (cwdW + ctxW + 1 > width) {
          // cwd too long, truncate it
          cwdDisp = truncateToWidth(cwdText, Math.max(4, width - ctxW - 1));
          cwdDispW = visibleWidth(cwdDisp);
        }
        const gap1 = Math.max(1, width - cwdDispW - ctxDispW);
        const line1 =
          theme.fg("muted", cwdDisp) +
          " ".repeat(gap1) +
          theme.fg("dim", ctxDisp);

        let modeDisp = modeText;
        let modeDispW = modeW;
        let modelDisp = modelStr;
        let modelDispW = modelW;
        if (modeW + modelW + 1 > width) {
          modelDisp = truncateToWidth(modelStr, Math.max(4, width - modeW - 1));
          modelDispW = visibleWidth(modelDisp);
        }
        const gap2 = Math.max(1, width - modeDispW - modelDispW);
        const line2 =
          theme.fg(m.role, modeDisp) +
          " ".repeat(gap2) +
          theme.fg("dim", modelDisp);

        return [line1, line2];
      },
      invalidate() {},
    }));
  }

  function updatePlanWidget(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    if (!planTodos.length) {
      ctx.ui.setWidget("plan-todos", undefined);
      return;
    }
    const lines = planTodos.map((t) =>
      t.completed
        ? ctx.ui.theme.fg("success", "☑ ") +
          ctx.ui.theme.fg("muted", ctx.ui.theme.strikethrough(t.text))
        : `${ctx.ui.theme.fg("muted", "☐ ")}${t.text}`,
    );
    ctx.ui.setWidget("plan-todos", lines);
  }

  // Streaming chunks arrive while the branch is frozen (pi appends entries
  // on message_end), so per-chunk work is O(new entries), not O(session
  // length); a moved prefix (navigate/fork/switch) forces a full recompute
  // (property-tested in branch-stats.test.ts).
  const branchStatsState = emptyBranchStatsState();

  function computeStats(ctx: ExtensionContext): {
    input: number;
    output: number;
    cacheRead: number;
    cacheWrite: number;
    cost: number;
  } {
    try {
      return accumulateBranchStats(
        readBranchEntries(ctx.sessionManager),
        branchStatsState,
      );
    } catch {
      // Render path: keep last totals rather than throw.
      return { ...branchStatsState.accum };
    }
  }

  function workingStatsParts(ctx: ExtensionContext): string[] {
    const s = computeStats(ctx);
    const parts = [`↑${formatCount(s.input)}`, `↓${formatCount(s.output)}`];
    if (s.cacheRead) parts.push(`R${formatCount(s.cacheRead)}`);
    if (lastTps > 0) parts.push(`⚡${Math.round(lastTps)} tok/s`);
    parts.push(`$${s.cost.toFixed(3)}`);
    const usage = (ctx as any).getContextUsage?.();
    if (usage && usage.percent != null) {
      parts.push(`${Math.round(usage.percent)}% ctx`);
    }
    return parts;
  }

  function renderWorkingMessage(ctx: ExtensionContext): string {
    return `Working… (${workingStatsParts(ctx).join(" · ")})`;
  }

  // ---- Capability channel to pi-claude-code-tui --------------------------
  // One typed, versioned namespace replaces the untyped globals; the legacy
  // __pmWorkingStats key stays published for one compatibility cycle (older
  // cctui builds read it). Consumers detect via `version >= 1`.
  function publishCapability(patch: Partial<PmCapability>): void {
    const g = globalThis as Record<string, unknown>;
    const current = (g.__piPermissionModes as PmCapability | undefined) ?? {
      version: 1,
      active: true,
      mode: currentMode,
      workingStats: null,
    };
    g.__piPermissionModes = { ...current, ...patch, version: 1, active: true };
  }

  /**
   * Publish this session's live gate state so in-process headless children
   * (pi-schedule-prompt `model:` jobs) can inherit it. Carries the folded ledger
   * as well as the session grants: inheriting grants without the ledger's
   * forbids / read-only posture would hand a child rights the parent no longer
   * has. Bridged children skip this, so a child can never overwrite the parent's
   * snapshot with its own clamped state.
   */
  function publishBridgeState(): void {
    if (bridgedAsSubagentChild) return;
    publishBridgeSnapshot({
      mode: currentMode,
      unattended: unattendedMode,
      grants: gateGrants.grants,
      ledger: serializeLedger(gateLedger),
      cwd: bridgeCwd || process.cwd(),
    });
  }

  function refreshWorkingMessage(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    // Integration: when the CC-TUI extension is active, its status row owns
    // the working line — publish the stats there instead of occupying pi's
    // working-message slot (which would render a duplicate second line).
    const g = globalThis as Record<string, unknown>;
    const ccTuiActive = (g.__piCcTui as { active?: boolean } | undefined)?.active === true || g.__ccTuiActive === true;
    if (ccTuiActive) {
      const stats = workingStatsParts(ctx).join(" · ");
      publishCapability({ workingStats: stats });
      // Legacy key (one compatibility cycle for older cctui builds).
      g.__pmWorkingStats = `(${stats})`;
      return;
    }
    ctx.ui.setWorkingMessage(
      ctx.ui.theme.fg("dim", renderWorkingMessage(ctx)),
    );
  }

  async function applyConfiguredPermissionRules(
    ctx: ExtensionContext,
    tool: string,
    input: Record<string, unknown>,
  ): Promise<Block | "allow" | "passthrough"> {
    const verdict = evaluateToolPermission(
      tool,
      input,
      ctx.cwd,
      mergedPermissionRules,
    );
    if (verdict.behavior === "deny") {
      return {
        block: true,
        reason: `Denied by permission rule [${verdict.source}]: ${verdict.rule}`,
      };
    }
    if (verdict.behavior === "allow") {
      if (tool === "edit" || tool === "write") {
        trackOutsideWriteIfNeeded(ctx, tool, String(input.path ?? ""));
      }
      return "allow";
    }
    if (verdict.behavior === "ask") {
      return promptAutoTier3(
        ctx,
        tool,
        input,
        `permission rule requires approval: ${verdict.rule}`,
        "permission-ask",
      );
    }
    return "passthrough";
  }

  // ---- prompts -----------------------------------------------------------
  async function promptApproval(
    ctx: ExtensionContext,
    tool: string,
    label: string,
    input: Record<string, unknown> = {},
  ): Promise<Block> {
    return promptWithPermissionOptions(ctx, tool, input, label, "user-prompt");
  }

  // ---- commands / shortcut / flag ---------------------------------------
  for (const mode of ["ask", "plan", "auto", "bypass"] as Mode[]) {
    pi.registerCommand(mode, {
      description: `Switch to ${MODE_META[mode].label} mode`,
      handler: async (_args, ctx) => setMode(mode, ctx),
    });
  }

  const applyInjectionNoteFlags = (
    next: { note?: boolean; esc?: boolean },
    notify: (m: string, l?: "info" | "warning" | "error") => void,
  ): void => {
    const ok = updatePermissionModesConfig((cfg) => {
      if (next.note !== undefined) cfg.injectionWarning = next.note;
      if (next.esc !== undefined) cfg.injectionEscalation = next.esc;
    });
    if (!ok) {
      notify(
        `Could not write ${getConfigPath()} - it may be malformed, so nothing changed.`,
        "error",
      );
      return;
    }
    // In-memory now, file already: the next turn takes it without a reload.
    if (next.note !== undefined) injectionWarningEnabled = next.note;
    if (next.esc !== undefined) injectionEscalationEnabled = next.esc;
    notify(describeInjectionNoteState());
  };

  pi.registerCommand("injection-note", {
    description:
      "Prompt-injection warnings: standing per-call note + probe-triggered escalation (no arg = picker)",
    handler: async (args, ctx) => {
      const notify = (m: string, l: "info" | "warning" | "error" = "info") => {
        if (ctx.hasUI) ctx.ui.notify(m, l);
        else console.log(m);
      };
      const a = String(args ?? "").trim().toLowerCase();

      if (a === "" || a === "status") {
        if (!ctx.hasUI) {
          notify(
            `${describeInjectionNoteState()} · headless: /injection-note on|off|escalation=on|escalation=off`,
          );
          return;
        }
        // The picker IS the feature: change it on the fly, no file editing, no reload.
        const choice = await ctx.ui.select(
          `Injection warnings - standing note: ${injectionWarningEnabled ? "ON" : "OFF"}, escalation: ${
            injectionEscalationEnabled ? "ON" : "OFF"
          }. Change which?`,
          [
            injectionWarningEnabled ? "Standing note -> off" : "Standing note -> on",
            injectionEscalationEnabled ? "Escalation -> off" : "Escalation -> on",
            "Leave as is",
          ],
        );
        if (!choice || choice === "Leave as is" || choice === "Cancel") return;
        if (choice.startsWith("Standing note")) {
          applyInjectionNoteFlags({ note: !injectionWarningEnabled }, notify);
        } else {
          applyInjectionNoteFlags({ esc: !injectionEscalationEnabled }, notify);
        }
        return;
      }

      if (a === "on" || a === "off" || a === "toggle") {
        applyInjectionNoteFlags(
          { note: a === "toggle" ? !injectionWarningEnabled : a === "on" },
          notify,
        );
        return;
      }
      if (a === "escalation=on" || a === "escalation=off") {
        applyInjectionNoteFlags({ esc: a.endsWith("=on") }, notify);
        return;
      }
      notify(
        "Usage: /injection-note [on|off|toggle|status|escalation=on|escalation=off] - no argument opens the picker",
        "warning",
      );
    },
  });

  pi.registerCommand("msg", {
    description:
      "Predefined messages to send to the model at will (no arg = picker | list | add <name> | add-inline <name> <text> | show <name> | del <name> | send <name>)",
    handler: async (args, ctx) => {
      const notify = (m: string, l: "info" | "warning" | "error" = "info") => {
        if (ctx.hasUI) ctx.ui.notify(m, l);
        else console.log(m);
      };
      const stored = (): Record<string, string> => ({
        ...(loadPermissionModesConfig().messages ?? {}),
      });
      const writeStored = (next: Record<string, string>): boolean =>
        updatePermissionModesConfig((cfg) => {
          cfg.messages = next;
        });
      const send = async (name: string): Promise<void> => {
        const text = stored()[name];
        if (!text) {
          const known = Object.keys(stored());
          notify(
            `No stored message "${name}".${
              known.length ? ` Known: ${known.join(", ")}` : " Add one: /msg add <name>"
            }`,
            "warning",
          );
          return;
        }
        // Model-visible, arriving after the current work rather than steering mid-turn.
        await pi.sendUserMessage(text, { deliverAs: "followUp" });
        notify(`Sent "${name}" (${text.length} chars) as a follow-up.`);
      };

      const a = String(args ?? "").trim();

      if (a === "") {
        const names = Object.keys(stored());
        if (!ctx.hasUI) {
          notify(
            names.length
              ? `Stored: ${names.join(", ")} · send with /msg send <name>`
              : "No stored messages.",
          );
          return;
        }
        const choice = await ctx.ui.select(
          `Send which predefined message? (${names.length} stored)`,
          names.length ? [...names, "(cancel)"] : ["(none stored - use /msg add <name>)"],
        );
        if (!choice || choice.startsWith("(") || choice === "Cancel") return;
        await send(choice);
        return;
      }

      if (a === "list") {
        const cur = stored();
        const names = Object.keys(cur);
        notify(
          names.length
            ? names
                .map((n) => {
                  const one = String(cur[n]).replace(/\s+/g, " ").trim();
                  return `  ${n}: ${one.slice(0, 80)}${one.length > 80 ? "..." : ""}`;
                })
                .join("\n")
            : "No stored messages.",
        );
        return;
      }

      const addMatch = /^add\s+(.+)$/i.exec(a);
      if (addMatch) {
        const name = addMatch[1]!.trim();
        if (!ctx.hasUI) {
          notify('Composing needs a UI - use: /msg add-inline <name> <text>', "warning");
          return;
        }
        const text = await ctx.ui.editor(`Predefined message "${name}":`, stored()[name] ?? "");
        const body = String(text ?? "").trim();
        if (!body) {
          notify("Nothing stored (empty).", "warning");
          return;
        }
        if (!writeStored({ ...stored(), [name]: body })) {
          notify(`Could not write ${getConfigPath()}`, "error");
          return;
        }
        notify(`Stored "${name}" (${body.length} chars). Send it with /msg ${name}`);
        return;
      }

      const addInline = /^add-inline\s+(\S+)\s+([\s\S]+)$/.exec(a);
      if (addInline) {
        const name = addInline[1]!.trim();
        const body = addInline[2]!.trim();
        if (!writeStored({ ...stored(), [name]: body })) {
          notify(`Could not write ${getConfigPath()}`, "error");
          return;
        }
        notify(`Stored "${name}" (${body.length} chars). Send it with /msg ${name}`);
        return;
      }

      const delMatch = /^del\s+(.+)$/i.exec(a);
      if (delMatch) {
        const name = delMatch[1]!.trim();
        const cur = stored();
        if (!(name in cur)) {
          notify(`No stored message "${name}".`, "warning");
          return;
        }
        const rest: Record<string, string> = {};
        for (const k of Object.keys(cur)) if (k !== name) rest[k] = cur[k]!;
        if (!writeStored(rest)) {
          notify(`Could not write ${getConfigPath()}`, "error");
          return;
        }
        notify(`Deleted "${name}".`);
        return;
      }

      const showMatch = /^show\s+(.+)$/i.exec(a);
      if (showMatch) {
        const name = showMatch[1]!.trim();
        const text = stored()[name];
        notify(text ? `${name}: ${text}` : `No stored message "${name}".`, text ? "info" : "warning");
        return;
      }

      const sendMatch = /^send\s+(.+)$/i.exec(a);
      await send((sendMatch ? sendMatch[1] : a)!.trim());
    },
  });

  pi.registerCommand("unattended", {
    description:
      "Unattended mode: approval prompts soft-deny with the reason so the agent adapts (on|off, no arg = toggle)",
    handler: async (args, ctx) => {
      const a = String(args ?? "").trim().toLowerCase();
      if (a === "on") unattendedMode = true;
      else if (a === "off") unattendedMode = false;
      else unattendedMode = !unattendedMode;
      if (!unattendedMode) unattendedDenialCounts.clear();
      persistState();
      publishBridgeState();
      const msg = unattendedMode
        ? "Unattended mode ON — approval prompts will soft-deny with the reason; the agent is told to work within approved bounds or park the step. Never-tier actions stay hard-blocked."
        : "Unattended mode OFF — approval prompts are interactive again.";
      if (ctx.hasUI) ctx.ui.notify(msg, "info");
      else console.log(msg);
    },
  });

  /**
 * Default grants file lives with the PROJECT, not in a shared global path: a
 * single global file would leak one project's authority into every other project
 * that imports or auto-imports. Same directory permissions.json uses.
 */
  const defaultGrantsPath = (cwd: string): string =>
    path.join(getProjectPermissionsDir(cwd), "grants.json");

  /** `~/x` -> home, bare name -> default, relative -> against cwd. No new deps. */
  /**
   * A bare filename lands in the project's own grants directory; `~/x` and `/x` are
   * honoured verbatim so an explicit path wins; anything else with a slash resolves
   * against the project root.
   */
  const resolveGrantPath = (raw: string | undefined, cwd: string): string => {
    const v = String(raw ?? "").trim();
    if (!v) return defaultGrantsPath(cwd);
    if (v === "~") return homedir();
    if (v.startsWith("~/")) return homedir() + v.slice(1);
    if (v.startsWith("/")) return v;
    if (v.includes("/")) return `${cwd.replace(/\/$/, "")}/${v}`;
    return path.join(getProjectPermissionsDir(cwd), v);
  };

  /** Opt-in auto-import at session start: merge only, never replace. */
  const autoImportGrantsFromFile = (cwd: string): string | undefined => {
    try {
      const setting = loadPermissionModesConfig().grantsAutoImport;
      if (!setting?.enabled) return undefined;
      const path = resolveGrantPath(setting.path, cwd);
      const res = readGrantsFile(path);
      if (!res.ok) return `grants auto-import skipped: ${res.error}`;
      const l = importLedger(gateLedger, res.file.ledger);
      const g = importSessionGrants(gateGrants, pruneRows(res.file.grants).kept);
      scheduleLedgerPersist();
      return (
        `Auto-imported grants (background authority, this session's words outrank them): ` +
        `${l.grantsAdded} ledger grants, ${l.forbidsAdded} forbids, ${g.added} session grants` +
        `${l.postureImported ? " + read-only posture" : ""} from ${path}`
      );
    } catch {
      return undefined;
    }
  };

  pi.registerCommand("grants", {
    description:
      "Show grants and the authorisation ledger (clear | revoke <value> | export [path] | import <path> [--replace] [--yes] | auto on|off|path <p> | adopt | adopt confirm <id>)",
    handler: async (args, ctx) => {
      // Revoke ONE thing, by value. Deliberately not by list index: the list is
      // re-rendered from two stores (ledger + session) in an order that shifts as
      // grants are promoted, so an index-based revoke is one stale list away from
      // deleting the wrong entry. Copy a value out of /grants and it is exact.
      //
      // This is the control that replaces a path-depth ceiling: a scope grant can
      // name any directory the user actually named (including ~ or /), and one
      // command takes it back for the rest of the session.
      const adoptArgs = String(args ?? "").trim()
      if (/^adopt\b/i.test(adoptArgs)) {
        // Confirming is the ONLY route by which a widening item becomes authority, and items are named by stable id,
        // never by row number: the pending list is re-derived on every call, so a stale index would grant whatever
        // now sits in that slot rather than what the human was looking at.
        const confirmMatch = /^confirm\s+(.+)$/is.exec(adoptArgs.replace(/^adopt\s+/i, ""))
        if (confirmMatch) {
          // Split on commas ONLY. These ids contain spaces (e.g. "rule:bash(npm publish)"), so whitespace-splitting
          // would truncate every real id to its first word — a copy-paste of the printed id would then be refused as
          // unknown, and the failure would look like the item disappeared.
          const ids = confirmMatch[1]!.split(",").map((s) => s.trim()).filter(Boolean)
          const plan = planAdoption({ cwd: ctx.cwd })
          const res = confirmAdoptChoices({
            cwd: ctx.cwd,
            store: gateGrants,
            ids,
            pending: plan.pending,
            durable: true,
          })
          const cl: string[] = []
          for (const p of res.picked) {
            // `label` is what the module built for logs and pickers: AdoptChoice is a union, so printing `.value`
            // blindly shows nothing at all for a rule choice — a confirm that worked would look like it did nothing.
            const what = String((p as { label?: unknown }).label ?? (p as { rule?: unknown }).rule ?? "(item)")
            cl.push(`  + adopted: ${what}`)
          }
          // Rules written by this confirmation are re-read the same way an approval re-reads them. The claim that there was
          // no reload face and that was WRONG — reloadMergedPermissionRules has been used by the approval path all
          // along; what was missing was the per-rule answer to "is it live?", which adopt-live computes by
          // comparing the files against the policy the session was ACTUALLY running on.
          const writtenRules = res.picked
            .filter((p) => (p as { kind?: unknown }).kind === "rule")
            .map((p) => String((p as { rule?: unknown }).rule ?? ""))
            .filter(Boolean)
          if (writtenRules.length > 0) {
            const made = makeAdoptedRulesLive({ cwd: ctx.cwd, written: writtenRules, live: basePermissionRules })
            reloadMergedPermissionRules(ctx.cwd)
            for (const e of made.effects) cl.push(`    ${e.live ? "live now" : "not live"}: ${e.rule} — ${e.detail}`)
            // The files are the source of truth, so an edit made during the session arrives with this adopt. Say so
            // rather than letting the count imply the confirmation caused it.
            for (const u of made.unrequested) cl.push(`    also now in policy, not named by you: ${u}`)
            cl.push(`    ${made.summary}`)
          }
          for (const r of res.refused) cl.push(`  ! refused ${r.what}: ${r.reason}`)
          if (cl.length === 0) cl.push("Nothing confirmed.")
          const cmsg = `Adopt confirm:\n${cl.join("\n")}`
          if (ctx.hasUI) ctx.ui.notify(cmsg, "info")
          else console.log(cmsg)
          return
        }
        // Orphaned project state — an id left behind by a moved checkout — still holds rules no session reads. A lost
        // DENY rule is the worst failure mode in this codebase: nothing errors, the wall just stops refusing. So
        // tightening is safe to take quietly, while widening is authority nobody granted in this checkout and is only
        // listed for a human, never written here.
        const out = adoptOrphans({ cwd: ctx.cwd })
        const lines: string[] = []
        lines.push(
          out.apply.length === 0
            ? "Nothing tightening to adopt — no deny/ask rules found in orphaned project state."
            : `Adopted ${out.apply.length} tightening rule(s) from orphaned project state:`,
        )
        for (const c of out.apply) lines.push(`  + ${String((c as { rule?: unknown }).rule ?? "")}`)
        for (const f of out.failed) lines.push(`  ! failed ${f.rule}: ${f.error}`)
        const choices = buildAdoptChoices(out.pending, { cwd: ctx.cwd })
        lines.push(
          choices.length === 0
            ? "No widening items pending."
            : `Held for your decision, NOT written: ${choices.length} allow grant(s) from orphans.`,
        )
        for (const l of renderAdoptChoices(choices)) lines.push(`  ? ${l}`)
        if (choices.length > 0) lines.push("  Confirm one by id: /grants adopt confirm <id>")
        const msg = lines.join("\n")
        if (ctx.hasUI) ctx.ui.notify(msg, "info")
        else console.log(msg)
        return
      }
      const revMatch = /^revoke\s+(.+)$/i.exec(String(args ?? "").trim())
      if (revMatch) {
        const want = normalizeGrantValue(revMatch[1] ?? "", homedir());
        if (!want || want === "*") {
          const msg = "Usage: /grants revoke <value>  — copy a value from /grants";
          if (ctx.hasUI) ctx.ui.notify(msg, "warning");
          else console.log(msg);
          return;
        }
        // Revocation is DATA, not an absence. Before W7 these were `splice` loops, which was enough while
        // auto-export replaced the journal's ledger half — the last writer's view simply lacked the row. Now the
        // half is UNIONED so a concurrent session's addition survives, and a splice would mean revoking in this
        // session silently stops working everywhere else: the journal keeps the row, every session re-imports it.
        const matches = (v: string) => normalizeGrantValue(v, homedir()) === want;
        const taken = revokeLedgerGrants(gateLedger, (g) => matches(g.value), {
          quote: revMatch[1]!.trim(),
        }).concat(revokeRows(gateGrants, (g) => matches(g.value), { quote: revMatch[1]!.trim() }));
        // Forbids used to be revocable by NOTHING: `revokeLedgerGrants` splices `ledger.grants` only, so
        // `/grants revoke` reported success while the row that was actually blocking stayed, and the only real
        // escape was exporting the ledger and editing the JSON by hand. Same matcher, same quote, and separate
        // tombstones on purpose — `rowIdentity` has no type field, so one shared list would let "take back the
        // ban on /x" delete an ALLOW of the same key.
        const liftedForbids = revokeLedgerForbids(gateLedger, (f) => matches(f.value), {
          quote: revMatch[1]!.trim(),
        });
        const removed = taken.length;
        const lifted = liftedForbids.length;
        scheduleLedgerPersist();
        const msg =
          removed || lifted
            ? `Revoked ${removed} grant${removed === 1 ? "" : "s"}${
                lifted ? ` and lifted ${lifted} forbid${lifted === 1 ? "" : "s"}` : ""
              } for "${revMatch[1]!.trim()}" — recorded as a revocation, so an import or a re-read of the same message cannot bring it back`
            : `No session grant or forbid matches "${revMatch[1]!.trim()}" — values are listed by /grants (a forbid shows the value to copy)`;
        if (ctx.hasUI) ctx.ui.notify(msg, removed || lifted ? "info" : "warning");
        else console.log(msg);
        return;
      }
      if (String(args ?? "").trim() === "clear") {
        gateGrants.grants.length = 0;
        gateLedger = createLedger();
        scheduleLedgerPersist();
        if (ctx.hasUI) ctx.ui.notify("Session grants + ledger cleared", "info");
        else console.log("Session grants + ledger cleared");
        return;
      }
      // ---- portability: export / import / auto --------------------------
      const say = (msg: string, level: "info" | "warning" | "error" = "info") => {
        if (ctx.hasUI) ctx.ui.notify(msg, level);
        else console.log(msg);
      };
      const argStr = String(args ?? "").trim();

      const exportMatch = /^export(?:\s+(.+))?$/i.exec(argStr);
      if (exportMatch) {
        const dest = resolveGrantPath(exportMatch[1]?.trim(), ctx.cwd);
        const { file, dropped } = buildGrantsFile({
          ledger: serializeLedger(gateLedger),
          grants: gateGrants.grants,
          sourceCwd: ctx.cwd,
        });
        const ok = writeGrantsFile(dest, file);
        say(
          ok
            ? `Exported ${summarizeGrantsFile(file)} -> ${dest}${dropped ? ` (${dropped} unmatchable rows pruned)` : ""}`
            : `Could not write ${dest}`,
          ok ? "info" : "error",
        );
        return;
      }

      const importMatch = /^import(?:\s+(.+))?$/i.exec(argStr);
      if (importMatch) {
        const rest = importMatch[1]?.trim() ?? "";
        const replace = /(?:^|\s)--replace(?:\s|$)/i.test(` ${rest} `);
        const forced = /(?:^|\s)--yes(?:\s|$)/i.test(` ${rest} `);
        const srcPath = resolveGrantPath(rest.replace(/--(replace|yes)/gi, "").trim(), ctx.cwd);
        const res = readGrantsFile(srcPath);
        if (!res.ok) {
          say(`Import refused: ${res.error}`, "error");
          return;
        }
        const preview = `${summarizeGrantsFile(res.file)}${replace ? "  [REPLACE]" : ""}`;
        if (!ctx.hasUI) {
          // Fail closed: headless must never take authority from a file silently.
          if (!forced) {
            say(`Import refused without UI (would import ${preview}). Re-run with --yes.`, "warning");
            return;
          }
        } else {
          const choice = await ctx.ui.select(
            `Import grants? ${preview}`,
            replace ? ["Replace + import", "Cancel"] : ["Import (merge)", "Cancel"],
          );
          if (choice === undefined || choice === "Cancel") {
            say("Import cancelled");
            return;
          }
        }
        const l = importLedger(gateLedger, res.file.ledger, { replace });
        const g = importSessionGrants(gateGrants, pruneRows(res.file.grants).kept, { replace });
        scheduleLedgerPersist();
        const droppedTotal = l.dropped + g.dropped;
        say(
          `Imported ${l.grantsAdded} ledger grants, ${l.forbidsAdded} forbids, ${g.added} session grants` +
            `${l.postureImported ? " + read-only posture" : ""}` +
            (droppedTotal ? ` (${droppedTotal} dropped: cap reached)` : "") +
            ` from ${srcPath}. Imported rows are background authority: anything you say here outranks them.`,
        );
        return;
      }

      const autoMatch = /^auto(?:\s+(.+))?$/i.exec(argStr);
      if (autoMatch) {
        const a = (autoMatch[1] ?? "").trim();
        const pathMatch = /^path\s+(.+)$/.exec(a);
        if (a === "on" || a === "off") {
          const ok = updatePermissionModesConfig((cfg) => {
            cfg.grantsAutoImport = { ...(cfg.grantsAutoImport ?? {}), enabled: a === "on" };
          });
          say(
            ok
              ? `Grants auto-import ${a} (${getConfigPath()}) — merges at session start, never replaces`
              : `Could not write ${getConfigPath()} — it may be malformed, so nothing changed.`,
            ok ? "info" : "error",
          );
        } else if (pathMatch) {
          const dest = resolveGrantPath(pathMatch[1]?.trim(), ctx.cwd);
          const ok = updatePermissionModesConfig((cfg) => {
            cfg.grantsAutoImport = { ...(cfg.grantsAutoImport ?? {}), path: dest };
          });
          say(
            ok ? `Grants auto-import path -> ${dest}` : `Could not write ${getConfigPath()}`,
            ok ? "info" : "error",
          );
        } else {
          const cur = loadPermissionModesConfig().grantsAutoImport ?? {};
          const target = cur.path ?? defaultGrantsPath(ctx.cwd);
          say(
            `Grants auto-import: ${cur.enabled ? "on" : "off"} · path ${target} · file ${existsSync(target) ? "present" : "absent"}`,
          );
        }
        return;
      }

      const lines: string[] = [];
      lines.push("Revoke one:  /grants revoke <value>   ·   clear all:  /grants clear");
      lines.push("Move them:  /grants export [path]   ·   /grants import <path> [--replace]   ·   /grants auto on|off|path <p>");
      lines.push("");
      lines.push("Session grants (user-confirmed at prompts / promoted):");
      if (!gateGrants.grants.length) lines.push("  (none)");
      for (const g of gateGrants.grants) {
        lines.push(
          `  ${g.category}  ${g.kind === "scope" ? "scope " : ""}${g.value}${g.origin === "imported" ? "  [imported]" : ""}`,
        );
      }
      lines.push("");
      lines.push("Ledger grants (extracted from your messages):");
      if (!gateLedger.grants.length) lines.push("  (none)");
      for (const g of gateLedger.grants) {
        lines.push(
          `  ${g.category}  ${g.value}  — "${g.quote.slice(0, 90)}"${
            g.origin === "imported"
              ? `  [imported from msg ${g.sourceSeq ?? "?"}]`
              : ` (msg ${g.seq})`
          }`,
        );
      }
      lines.push("");
      // These rows are ACTIVE forbids — each one blocks. Labelling them "withdrawn/excluded" made a user
      // read the blocking row and conclude nothing was blocking them.
      lines.push("Ledger forbids (ACTIVE — these block):  revoke one with  /grants revoke <value>");
      if (!gateLedger.forbids.length) lines.push("  (none)");
      for (const f of gateLedger.forbids) {
        lines.push(
          `  ${f.category === "*" ? "(all)" : f.category}  ${f.value}  — "${f.quote.slice(0, 90)}"${
            f.origin === "imported"
              ? `  [imported from msg ${f.sourceSeq ?? "?"}]`
              : ` (msg ${f.seq})`
          }`,
        );
      }
      const ro = readOnlyActive(gateLedger);
      if (ro) {
        lines.push("");
        lines.push(`READ-ONLY MODE active — "${ro.quote.slice(0, 90)}" (msg ${ro.seq}). Mutations are blocked; project/temp work still allowed. Say "you can make changes now" to lift it.`);
      }
      lines.push("");
      lines.push(`Extracted messages: ${gateLedger.seen.size}. Use /grants clear to reset.`);
      const text = lines.join("\n");
      if (ctx.hasUI) {
        pi.sendMessage(
          {
            customType: "gate-grants-list",
            content: `**Auto-mode grants**\n\n\`\`\`\n${text}\n\`\`\``,
            display: true,
          },
          { triggerTurn: false },
        );
      } else {
        console.log(text);
      }
    },
  });

  pi.registerCommand("permissions", {
    description:
      "List merged permission rules (allow/deny/ask) from global + project config",
    handler: async (_args, ctx) => {
      reloadMergedPermissionRules(ctx.cwd);
      const text = formatMergedRulesForDisplay(mergedPermissionRules);
      if (ctx.hasUI) {
        pi.sendMessage(
          {
            customType: "permissions-list",
            content: `**Permission rules**\n\n\`\`\`\n${text}\n\`\`\``,
            display: true,
          },
          { triggerTurn: false },
        );
      } else {
        console.log(text);
      }
    },
  });

  pi.registerCommand("mode", {
    description:
      "Show or set the permission mode (ask | plan | auto | bypass)",
    handler: async (args, ctx) => {
      const arg = (args ?? "").trim();
      if (arg && (MODE_CYCLE as string[]).includes(arg)) {
        await setMode(arg as Mode, ctx);
        return;
      }
      // Accept "default" as an alias for "ask" during migration period.
      if (arg === "default") {
        await setMode("ask", ctx);
        return;
      }
      if (!ctx.hasUI) return;
      const choice = await ctx.ui.select(
        "Select mode:",
        MODE_CYCLE.map((m) => MODE_META[m].label),
      );
      const picked = MODE_CYCLE.find((m) => MODE_META[m].label === choice);
      if (picked) await setMode(picked, ctx);
    },
  });

  pi.registerCommand("plan-execute", {
    description:
      "Execute the current plan immediately (switches to auto mode with step tracking)",
    handler: async (_args, ctx) => {
      if (currentMode !== "plan" && !planExecuting) {
        ctx.ui.notify("Not in plan mode. Use /plan first.", "warning");
        return;
      }
      const planContent = readPlanFile(ctx.cwd);
      const extracted = filterSubstantivePlanItems(
        planContent ? extractTodoItems(planContent) : [],
      );
      if (!extracted.length) {
        ctx.ui.notify("No plan steps found in plan.md. Write a plan first.", "warning");
        return;
      }
      planExecuting = true;
      planPhase = "executing";
      planTodos = extracted;
      currentMode = "auto";
      applyToolRestrictions();
      updateStatus(ctx);
      updatePlanWidget(ctx);
      persistState();
      await applyProfileModelForMode("auto", ctx);
      const steps = planTodos.map((t) => `${t.step}. ${t.text}`).join("\n");
      pi.sendMessage(
        {
          customType: "modes-execute",
          content: `Execute the plan now. Steps:\n${steps}\n\nStart with step 1. After finishing each step, include a [DONE:n] tag in your reply.`,
          display: true,
        },
        { triggerTurn: true, deliverAs: "followUp" },
      );
    },
  });

  // ---- plan approval helpers ---------------------------------------------
  function markPlanOfferHandled(planContent: string): void {
    lastPlanOfferAt = Date.now();
    // Keep agent_end from immediately re-opening the same plan dialog after Stay/Esc.
    suppressPlanOfferUntil = Date.now() + PLAN_OFFER_COOLDOWN_MS;
    if (planContent) {
      lastExtractedPlanHash = hashPlan(planContent);
    }
  }

  async function promptPlanRefinement(ctx: ExtensionContext): Promise<void> {
    if (!ctx.hasUI) return;
    planPhase = "refining";
    const refinement = await ctx.ui.editor("Refine the plan:", "");
    if (refinement?.trim()) {
      pi.sendUserMessage(refinement.trim(), { deliverAs: "followUp" });
    }
  }

  function planReviewClosedToolResult() {
    return {
      content: [
        {
          type: "text" as const,
          text: "Plan review closed. Wait for the user's next message; do not continue on your own.",
        },
      ],
      terminate: true as const,
      details: {},
    };
  }

  // ---- request_user_permission (agent-initiated ask about a call the gate blocked) -------
  // The unattended denial ladder names this tool: when the gate blocks a call, the agent asks a human rather than
  // guessing. An earlier revision removed the name from the rungs until it existed; it exists now, so the rung can come
  // back honest.
  //
  // The design constraint that shaped it: the agent supplies the target as free text, so the tool must not treat
  // that text as authority. If it did, a human would be approving the agent's *description* of an action instead of
  // the action — an approval vector shaped exactly like a prompt injection. So the tool re-derives the verdict from
  // the target itself and shows the human what the interactive prompt would have shown, produced by the classifier
  // rather than by the caller. A fabricated or harmless target therefore produces no prompt to approve, and a real
  // one grants nothing the click path could not have granted: the answer goes through applyApprovalDecision, the
  // single place that turns a yes into durable authority.
  const REQUEST_PERMISSION_TOOL_NAME = "request_user_permission";

  pi.registerTool(defineTool({
    name: REQUEST_PERMISSION_TOOL_NAME,
    label: "Request user permission",
    description:
      "Ask the human about one specific call the permission gate blocked, and get allow / allow-always / deny. " +
      "Use only after a denial you cannot clear by rewriting the command. There is no timeout when nobody can be " +
      "reached: with no UI the call is denied immediately, so park it and list it in your end-of-run report.",
    parameters: Type.Object({
      tool: Type.String({
        description: 'The gated tool, e.g. "bash", "write", "edit", "read".',
      }),
      target: Type.String({
        description:
          "The exact invocation that was denied: the full command line for bash, the path for file tools. " +
          "This is re-classified by the gate, so an inaccurate value changes what the human sees — it cannot grant anything.",
      }),
      note: Type.Optional(
        Type.String({ description: "Why you need it, one or two sentences, for the human reading the prompt." }),
      ),
    }),
    executionMode: "sequential",
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const tool = String(params.tool ?? "").trim();
      const target = String(params.target ?? "").trim();
      const note = typeof params.note === "string" ? params.note.trim() : "";
      if (!tool || !target) {
        return {
          content: [{ type: "text", text: "request_user_permission needs both tool and target." }],
          details: {},
        };
      }

      // Rebuild the call and ask the policy what it thinks — never trust the caller's framing.
      const input: Record<string, unknown> =
        tool === "bash" ? { command: target } : { path: target };
      const verdict = checkAutoRisk(
        tool === "bash" ? { tool, command: target } : { tool, path: target },
        ctx.cwd,
      );
      const category = verdict.match ? verdict.category : "unknown_command";
      const reason = verdict.match
        ? verdict.reason
        : "no risk matched this call; asking anyway so a human decides";

      // No UI means nobody can answer. Deny now instead of parking a request that would only expire silently —
      // the promise of a 10-minute wait was the part of the old text that was false.
      if (!ctx.hasUI) {
        return {
          content: [
            {
              type: "text",
              text:
                `Denied: no user interface is reachable from this session, so nobody can be asked. ` +
                `Park it — list the blocked call and what you needed it for in your end-of-run report.`,
            },
          ],
          details: {},
        };
      }

      const label = (note ? note + " — " : "") + reason;
      const outcome = await promptWithPermissionOptions(ctx, tool, input, label, category);
      if (outcome?.block) {
        return {
          content: [
            {
              type: "text",
              text: `The user did not approve: ${outcome.reason ?? "denied"}. Do not retry the same call; park it and report it.`,
            },
          ],
          details: {},
        };
      }
      return {
        content: [
          {
            type: "text",
            text: `Approved by the user for ${tool}: ${target}. Proceed with that exact call.`,
          },
        ],
        details: {},
      };
    },
  }));

  // ---- plan_ready tool (model-initiated plan submission) -------------------
  const PLAN_READY_TOOL_NAME = "plan_ready";

  pi.registerTool(defineTool({
    name: PLAN_READY_TOOL_NAME,
    label: "Plan Ready",
    description:
      "Submit the completed plan to the user for approval. Only available in plan mode. The user will see the plan and choose to execute, refine, or stay in plan mode.",
    promptSnippet:
      "Call plan_ready when your plan in plan.md is complete and ready for user review.",
    promptGuidelines: [
      "Only call plan_ready when you have finished exploring and the plan file contains a concrete, numbered implementation plan.",
      "Do NOT call plan_ready if the plan still has open questions or incomplete sections.",
      "After calling plan_ready, stop and wait for the user's decision. Do not begin implementation.",
      "If the user asks to refine, update plan.md and call plan_ready again when ready.",
    ],
    parameters: Type.Object({
      summary: Type.Optional(
        Type.String({ description: "Brief one-line summary of the plan for the approval dialog." }),
      ),
    }),
    executionMode: "sequential",
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (currentMode !== "plan") {
        return {
          content: [{ type: "text", text: "plan_ready is only available in plan mode. Current mode: " + currentMode }],
          details: {},
        };
      }
      const planContent = readPlanFile(ctx.cwd);
      const extracted = filterSubstantivePlanItems(
        planContent ? extractTodoItems(planContent) : [],
      );
      if (!extracted.length) {
        return {
          content: [{ type: "text", text: "No plan steps found in plan.md. Write a numbered plan first, then call plan_ready." }],
          details: {},
        };
      }

      planTodos = extracted;
      persistState();
      updatePlanWidget(ctx);

      const summary = params.summary?.trim() || undefined;
      const stepsPreview = extracted.map((t) => `${t.step}. ${t.text}`).join("\n");

      if (!ctx.hasUI) {
        // Headless: auto-execute
        const summaryLine = summary ? `${summary}\n\n` : "";
        return {
          content: [{ type: "text", text: `Plan submitted (headless auto-execute).\n${summaryLine}${stepsPreview}` }],
          details: {},
        };
      }

      // Suppress agent_end re-offer while this dialog is open and after dismiss.
      markPlanOfferHandled(planContent ?? "");
      const choice = await runPlanApprovalDialog(ctx, {
        summary,
        planContent: planContent ?? "",
        stepCount: extracted.length,
      });
      markPlanOfferHandled(planContent ?? "");

      if (choice === "execute") {
        planExecuting = true;
        planPhase = "executing";
        currentMode = "auto";
        applyToolRestrictions();
        updateStatus(ctx);
        persistState();
        await applyProfileModelForMode("auto", ctx);
        const steps = planTodos.map((t) => `${t.step}. ${t.text}`).join("\n");
        pi.sendMessage(
          {
            customType: "modes-execute",
            content: `Execute the plan now. Steps:\n${steps}\n\nStart with step 1. After finishing each step, include a [DONE:n] tag in your reply.`,
            display: true,
          },
          { triggerTurn: true, deliverAs: "followUp" },
        );
        return {
          content: [{ type: "text", text: "Plan approved by user. Switching to execution mode." }],
          details: {},
          terminate: true,
        };
      }

      if (choice === "refine") {
        await promptPlanRefinement(ctx);
        return planReviewClosedToolResult();
      }

      // stay | cancel (Esc): one dismiss returns to the input prompt.
      return planReviewClosedToolResult();
    },
    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", "plan_ready ") + theme.fg("muted", truncateToWidth(String(args?.summary ?? ""), 60)),
        0, 0,
      );
    },
    renderResult(result, _options, theme) {
      // Selected by its discriminator, so the shape is known here; the cast records that rather than lying
      // about the union element type.
      const first = result.content?.find((c: any) => c.type === "text") as { text?: string } | undefined;
      return new Text(theme.fg("muted", truncateToWidth(String(first?.text ?? ""), 80)), 0, 0);
    },
  }));

  // ---- /model-profile command -------------------------------------------
  // Show, list, or activate a model profile from `~/.pi/agent/model-profiles.json`.
  pi.registerCommand("model-profile", {
    description:
      "Show or set model profile (named set of per-mode models from ~/.pi/agent/model-profiles.json)",
    handler: async (args, ctx) => {
      const arg = (args ?? "").trim();

      if (!arg) {
        // No args → show interactive selector
        const config = loadModelProfiles();
        const names = listProfiles(config);
        if (!names.length) {
          if (ctx.hasUI)
            ctx.ui.notify(
              "No profiles found in ~/.pi/agent/model-profiles.json",
              "warning",
            );
          return;
        }
        if (!ctx.hasUI) return;
        const choice = await ctx.ui.select("Select model profile:", names);
        if (!choice) return;
        await setActiveProfile(choice, ctx);
        return;
      }

      if (arg === "list") {
        const config = loadModelProfiles();
        const names = listProfiles(config);
        if (!names.length) {
          if (ctx.hasUI)
            ctx.ui.notify(
              "No profiles found in ~/.pi/agent/model-profiles.json",
              "info",
            );
          return;
        }
        const activeName = getActiveProfileName(config);
        const lines = names.map((n) => {
          const p = config[n] as ModelProfile;
          const mappings = ["ask", "plan", "auto", "bypass"]
            .map((m) => `${m}:${(p as any)[m] || "-"}`)
            .join(" ");
          const active = n === activeName ? " (active)" : "";
          return `${n}${active}: ${mappings}`;
        });
        pi.sendMessage(
          {
            customType: "model-profile-list",
            content: `Model profiles:\n${lines.join("\n")}`,
            display: true,
          },
          { triggerTurn: false },
        );
        return;
      }

      await setActiveProfile(arg, ctx);
    },
  });

  // ---- /outside-writes + /undo-outside-writes (NEW v1.1.3) --------------
  // Format a snapshot for display in lists/selectors.
  function formatSnapshotForDisplay(
    snap: OutsideWriteSnapshot,
    externallyModified = false,
  ): string {
    const ts = snap.timestamp.replace("T", " ").slice(0, 19);
    const action = snap.backupContent === null ? "would delete" : "would restore";
    const flag = externallyModified ? " \u26a0 externally modified" : "";
    return `${ts} \u00b7 ${snap.toolName} \u00b7 ${snap.originalPath} (${action})${flag}`;
  }

  // Detect if a file has been externally modified since its snapshot was taken.
  // Heuristic: if multiple snapshots exist for the same path, OR the current
  // file content differs from the snapshot's backupContent, the file is
  // considered externally modified.
  function isExternallyModified(
    snap: OutsideWriteSnapshot,
    allSnaps: OutsideWriteSnapshot[],
  ): boolean {
    const samePath = allSnaps.filter((s) => s.originalPath === snap.originalPath);
    if (samePath.length > 1) return true;
    try {
      const current = readFileSync(snap.originalPath, "utf-8");
      return current !== snap.backupContent;
    } catch {
      return false;
    }
  }

  pi.registerCommand("classifier-status", {
    description:
      "Show classifier config and this session's counters (eligible / called / ok / failed / no-endpoint)",
    handler: async (args, ctx) => {
      if (args.trim() === "reset") {
        resetClassifierStats();
        resetExtractionStats();
        if (ctx.hasUI) ctx.ui.notify("Classifier counters reset", "info");
        return;
      }
      const resolution = classifierConfig.enabled
        ? await resolveGateEndpointWithFailure(classifierConfig, ctx.modelRegistry as any)
        : {};
      const endpoint = resolution.endpoint;
      const s = classifierStats;
      const ex = extractionStats;
      const text = [
        `classifier: ${classifierConfig.enabled ? "enabled" : "DISABLED (default is enabled)"}`,
        `model: ${classifierConfig.model || "(none configured)"}`,
        `endpoint: ${
          endpoint
            ? "resolved"
            : resolution.failure
              ? `NOT USABLE — ${resolution.failure.detail}`
              : "none — every unknown verdict goes to the user unasked, AND natural-language grants cannot register at all: nothing parses the user's sentence into a category without a model call"
        }`,
        // The Copilot allowance used to be invisible: the cap lives in model-client.ts and the counter in
        // copilot-session.ts, so a user hitting it had no line to read.
        (classifierConfig.copilot?.budgetTokens ?? 0) > 0
          ? `copilot allowance: ${copilotTokensSpent()}/${classifierConfig.copilot?.budgetTokens} tokens${
              copilotTokensSpent() >= (classifierConfig.copilot?.budgetTokens ?? 0)
                ? " — SPENT, the classifier will refuse to send until it is raised or reset"
                : ""
            }`
          : `copilot allowance: ${copilotTokensSpent()} tokens spent, no cap set (classifier.copilot.budgetTokens)`,
        `this session: ${s.eligible} eligible, ${s.calls} called, ${s.ok} ok, ${s.failed} failed`,
        `${s.noEndpoint} eligible with no endpoint, ${s.resolveFailed} with a classifier that could not be used, ${s.grantFailed} grant-extraction failures`,
        `extracted grants: ${ex.mapped} mapped, ${ex.unmapped} whose action the category table cannot name${
          ex.lastUnmapped ? ` (last: "${ex.lastUnmapped}")` : ""
        }`,
        `categories: ${ex.fromSchema} from the model's enum, ${ex.legacyWordList} recovered by the English word list${
          ex.legacyWordList > 0 ? " — this endpoint is ignoring the schema contract" : ""
        }`,
        `shapes: ${ex.scopes} location scopes (folder permissions), ${ex.secretInclusions} explicitly including secrets`,
        ex.fromSchema === 0 && ex.legacyWordList + ex.unmapped > 0
          ? "WARNING: no grant came back with a schema category. This endpoint is not enforcing response_format json_schema, so the model cannot express folder scopes or secret inclusion - those permissions will silently fail to register. Categories are being recovered from the English action table instead."
          : "",
        ex.unmapped > 0
          ? "unmapped ones are recorded but authorise nothing — the grant did not register"
          : "",
      ]
        .filter(Boolean)
        .join("\n");
      if (ctx.hasUI) ctx.ui.notify(text, "info");
      else console.log(text);
    },
  });

  pi.registerCommand("outside-writes", {
    description:
      "List tracked outside-cwd writes from auto mode (read-only; does not undo)",
    handler: async (_args, ctx) => {
      const snaps = listTrackedOutsideWrites(ctx.cwd);
      if (!snaps.length) {
        if (ctx.hasUI) ctx.ui.notify("No tracked outside-cwd writes", "info");
        return;
      }
      const lines = snaps.map((s) => formatSnapshotForDisplay(s, isExternallyModified(s, snaps)));
      pi.sendMessage(
        {
          customType: "outside-writes-list",
          content: `Tracked outside-cwd writes (${snaps.length}):\n${lines.join("\n")}`,
          display: true,
        },
        { triggerTurn: false },
      );
    },
  });

  pi.registerCommand("undo-outside-writes", {
    description:
      "Restore files modified by auto mode outside cwd. No args = selector; 'all' = restore all; '--list' = list only",
    handler: async (args, ctx) => {
      const arg = (args ?? "").trim();

      // --list: alias for /outside-writes
      if (arg === "--list" || arg === "list") {
        const snaps = listTrackedOutsideWrites(ctx.cwd);
        if (!snaps.length) {
          if (ctx.hasUI) ctx.ui.notify("No tracked outside-cwd writes", "info");
          return;
        }
        const lines = snaps.map((s) => formatSnapshotForDisplay(s, isExternallyModified(s, snaps)));
        pi.sendMessage(
          {
            customType: "outside-writes-list",
            content: `Tracked outside-cwd writes (${snaps.length}):\n${lines.join("\n")}`,
            display: true,
          },
          { triggerTurn: false },
        );
        return;
      }

      const allSnaps = listTrackedOutsideWrites(ctx.cwd);
      if (!allSnaps.length) {
        if (ctx.hasUI)
          ctx.ui.notify("No tracked outside-cwd writes to undo", "info");
        return;
      }

      if (arg === "all") {
        // Restore all without prompting
        let restored = 0;
        let deleted = 0;
        let warned = 0;
        const externallyModifiedPaths = new Set(
          allSnaps
            .filter((s) => isExternallyModified(s, allSnaps))
            .map((s) => s.originalPath),
        );
        for (const snap of allSnaps) {
          const result = restoreOutsideWrite(snap);
          if (result.action === "restored") restored++;
          else if (result.action === "deleted") deleted++;
          if (externallyModifiedPaths.has(snap.originalPath)) warned++;
          popTrackedOutsideWrite(ctx.cwd, snap);
        }
        if (ctx.hasUI) {
          const warnMsg =
            warned > 0
              ? ` (${warned} file(s) externally modified \u2014 restored anyway)`
              : "";
          ctx.ui.notify(
            `Restored ${restored}, deleted ${deleted} tracked write(s)${warnMsg}`,
            "info",
          );
        }
        return;
      }

      // No args: interactive selector (newest first)
      if (!ctx.hasUI) {
        if (ctx.hasUI)
          ctx.ui.notify(
            "No UI available; pass 'all' or '--list' as argument",
            "warning",
          );
        return;
      }
      const ordered = [...allSnaps].reverse();
      const choice = await ctx.ui.select(
        "Restore which tracked outside-cwd write? (newest first)",
        ordered.map((s) =>
          formatSnapshotForDisplay(s, isExternallyModified(s, allSnaps)),
        ),
      );
      if (!choice) return;
      const picked = ordered.find(
        (s) =>
          formatSnapshotForDisplay(s, isExternallyModified(s, allSnaps)) === choice,
      );
      if (!picked) return;
      const wasExternal = isExternallyModified(picked, allSnaps);
      const result = restoreOutsideWrite(picked);
      popTrackedOutsideWrite(ctx.cwd, picked);
      const action = result.action === "deleted" ? "Deleted" : "Restored";
      const warnSuffix = wasExternal
        ? " (\u26a0 file was externally modified \u2014 restored from snapshot anyway)"
        : "";
      ctx.ui.notify(`${action} ${picked.originalPath}${warnSuffix}`, "info");
    },
  });


    pi.registerShortcut("shift+tab", {
    description: "Cycle mode: Ask → Plan → Auto → Bypass",
    handler: async (ctx) => cycleMode(ctx),
  });

  // Alt+T: cycle the thinking level. pi has no built-in cycle helper, and setThinkingLevel
  // clamps to the model's capabilities, so we advance to the next level the model actually
  // accepts (skipping ones it clamps away). The footer reflects the new level live.
  const THINKING_LEVELS = [
    "off",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
  ] as const;
  function cycleThinkingLevel(ctx: ExtensionContext): void {
    const get = (): string =>
      typeof (pi as any).getThinkingLevel === "function"
        ? (pi as any).getThinkingLevel()
        : "off";
    const setLevel = (pi as any).setThinkingLevel as
      | ((l: string) => void)
      | undefined;
    if (typeof setLevel !== "function") return;
    const cur = get();
    let i = THINKING_LEVELS.indexOf(cur as (typeof THINKING_LEVELS)[number]);
    if (i < 0) i = 0;
    for (let step = 1; step <= THINKING_LEVELS.length; step++) {
      const next = THINKING_LEVELS[(i + step) % THINKING_LEVELS.length];
      setLevel(next);
      const applied = get();
      if (applied !== cur) {
        if (ctx.hasUI) ctx.ui.notify(`Thinking: ${applied}`, "info");
        return;
      }
    }
    if (ctx.hasUI)
      ctx.ui.notify(
        `Thinking: ${get()} (model supports no other levels)`,
        "info",
      );
  }

  pi.registerShortcut("alt+t", {
    description:
      "Cycle thinking level (off → minimal → low → medium → high → xhigh)",
    handler: async (ctx) => cycleThinkingLevel(ctx),
  });

  // Alt+I: cycle through model profiles defined in `~/.pi/agent/model-profiles.json`.
  // Mirrors Shift+Tab's cycle-by-one behavior: starts at the profile after the
  // currently active one and wraps. Falls back to the first profile when no
  // profile is active yet. Always re-applies the model for the current mode,
  // so the UI (footer) updates immediately.
  async function cycleProfile(ctx: ExtensionContext): Promise<void> {
    const config = loadModelProfiles();
    const names = listProfiles(config);
    if (!names.length) {
      if (ctx.hasUI)
        ctx.ui.notify(
          "No profiles found in ~/.pi/agent/model-profiles.json",
          "warning",
        );
      return;
    }
    // Determine the index of the next profile. If no profile is active yet,
    // we treat the current `config.active` (or "default") as the implicit one
    // so cycling always advances.
    const currentName =
      activeProfile ?? getActiveProfileName(config) ?? names[0]!;
    let i = names.indexOf(currentName);
    if (i < 0) i = -1; // unknown current → start before the first
    const next = names[(i + 1) % names.length]!;
    await setActiveProfile(next, ctx);
  }

  pi.registerShortcut("alt+i", {
    description:
      "Cycle model profile (next profile from ~/.pi/agent/model-profiles.json)",
    handler: async (ctx) => cycleProfile(ctx),
  });

  // NB: pi has a built-in `--mode` (output mode: text/json/rpc), so the start-mode
  // flag must use a distinct name to avoid being shadowed at parse time.
  pi.registerFlag("permission-mode", {
    description:
      "Start in a permission mode: ask, plan, auto, or bypass (accepts 'default' as alias for 'ask')",
    type: "string",
    default: "ask",
  });

  pi.registerFlag("model-profile", {
    description:
      "Start with a named model profile from ~/.pi/agent/model-profiles.json",
    type: "string",
  });

  /** Simple glob-style pattern matching for autoMode.allow / soft_deny rules. */
  function matchAutoModePattern(command: string, pattern: string): boolean {
    const trimmed = command.trim();
    const p = pattern.trim();
    if (trimmed === p) return true;
    if (p.endsWith("*")) {
      const prefix = p.slice(0, -1).trim();
      return trimmed.startsWith(prefix);
    }
    return trimmed.includes(p);
  }

  function allowToolCall(): undefined {
    if (currentMode === "auto") {
      classifierDenialState = recordClassifierSuccess(classifierDenialState);
    }
    return undefined;
  }

  // ---- tool_call gate ----------------------------------------------------
  pi.on("tool_call", async (event, ctx): Promise<Block> => {
    const tool = event.toolName;
    const input = (event.input ?? {}) as Record<string, unknown>;

    // BYPASS: approve everything; still track outside-cwd writes for undo.
    // Kept ahead of the plan-file probe: bypass never reads the plan file
    // and the probe does per-call FS I/O.
    if (currentMode === "bypass") {
      if (tool === "edit" || tool === "write") {
        trackOutsideWriteIfNeeded(ctx, tool, String(input.path ?? ""));
      }
      return undefined;
    }

    const planFilePath = getPlanFilePath(ctx.cwd);

    const permResult = await applyConfiguredPermissionRules(ctx, tool, input);
    if (permResult === "allow") return allowToolCall();
    if (permResult !== "passthrough") {
      // Plan exploration: allow read-only tools even when permission rules
      // would ask, but still honor explicit deny rules.
      if (
        currentMode === "plan" &&
        PLAN_READ_TOOLS.has(tool) &&
        !String((permResult as { reason?: string }).reason ?? "").startsWith(
          "Denied by permission rule",
        )
      ) {
        return undefined;
      }
      return permResult;
    }

    // PLAN EXECUTION: use auto-mode tiered gate (classifier + blacklist).
    // planExecuting only affects prompt injection and UI; it does not bypass auto.

    // PLAN: read-only except plan.md; bash allowlist only.
    if (currentMode === "plan") {
      if (PLAN_READ_TOOLS.has(tool)) {
        return undefined;
      }
      if (tool === "edit" || tool === "write") {
        const pathStr = String(input.path ?? "");
        if (pathStr && isPlanFilePath(pathStr, ctx.cwd)) {
          return undefined;
        }
        return {
          block: true,
          reason: `Plan mode: only ${shortenPath(planFilePath)} may be edited.`,
        };
      }
      if (tool === "bash") {
        const cmd = String(input.command ?? "");
        if (!isReadOnlyBash(cmd, ctx.cwd)) {
          return {
            block: true,
            reason: `Plan mode: read-only commands only.\n  Command: ${cmd}`,
          };
        }
      }
      return undefined;
    }

    // AUTO: tiered gate with optional classifier + user prompts for risky ops
    if (currentMode === "auto") {
      if (classifierConfig.engine !== "legacy") {
        // v3 gate: deterministic policy first, then narrow model tasks.
        // User-configured autoMode rules still short-circuit ahead of it.
        if (tool === "bash") {
          const cmd = String(input.command ?? "");
          if (cmd && autoModeConfig?.allow?.length) {
            if (
              autoModeConfig.allow.some((p) => matchAutoModePattern(cmd, p)) &&
              isWorkflowBash(cmd, ctx.cwd)
            ) {
              return allowToolCall();
            }
          }
          if (cmd && autoModeConfig?.soft_deny?.length) {
            if (autoModeConfig.soft_deny.some((p) => matchAutoModePattern(cmd, p))) {
              return promptAutoTier3(ctx, tool, input, "matched autoMode.soft_deny", "auto-deny");
            }
          }
        }
        return approveAutoWithGate(ctx, tool, input);
      }
      if (tool === "read" || tool === "grep" || tool === "find" || tool === "ls") {
        const pathStr = String(input.path ?? "");
        if (pathStr && isSensitivePath(pathStr, ctx.cwd)) {
          return promptAutoTier3(
            ctx,
            tool,
            input,
            `sensitive path "${pathStr}"`,
            "sensitive-path",
          );
        }
        return allowToolCall();
      }

      if (tool === "edit" || tool === "write") {
        const pathStr = String(input.path ?? "");
        if (pathStr && isSensitivePath(pathStr, ctx.cwd)) {
          return promptAutoTier3(
            ctx,
            tool,
            input,
            `sensitive path "${pathStr}"`,
            "sensitive-path",
          );
        }
        if (!pathStr || !isOutsideCwd(pathStr, ctx.cwd)) {
          return allowToolCall();
        }
      }

      if (tool === "bash") {
        const cmd = String(input.command ?? "");
        if (cmd && commandReferencesSensitivePath(cmd)) {
          return promptAutoTier3(
            ctx,
            tool,
            input,
            `sensitive path in command: ${cmd}`,
            "sensitive-path",
          );
        }
        // Tier 1 and tier 2 both come from layer 0 now: one walker parse, one verdict, mapped onto the field
        // names this block already uses. The old shared `splitShellSegments` pass is gone from this path.
        const tier0 = cmd ? classifyTiersLayer0(cmd, ctx.cwd) : undefined;
        const tiers = tier0 ? { safe: tier0.readOnly, autoApprovable: tier0.workflow } : undefined;
        // Tier 1: read-only bash auto-approves.
        if (tiers?.safe) {
          return allowToolCall();
        }
        // Tier 1.5: autoMode.allow user rules short-circuit before classifier.
        // Guard: compound commands (&&, ||, ;) must have ALL segments safe,
        // preventing "npm install && rm -rf /" from being allowed by a "npm" rule.
        if (cmd && autoModeConfig?.allow?.length) {
          if (autoModeConfig.allow.some((p) => matchAutoModePattern(cmd, p))) {
            if (tiers?.autoApprovable) {
              return allowToolCall();
            }
            // Pattern matched but command has dangerous segments → fall through
          }
        }
        // Tier 1.5b: autoMode.soft_deny forces a prompt.
        if (cmd && autoModeConfig?.soft_deny?.length) {
          if (autoModeConfig.soft_deny.some((p) => matchAutoModePattern(cmd, p))) {
            return promptAutoTier3(ctx, tool, input, "matched autoMode.soft_deny", "auto-deny");
          }
        }
        // Tier 2: common dev workflow commands auto-approve without classifier.
        if (tiers?.autoApprovable) {
          return allowToolCall();
        }
      }

      return approveAutoTier3(ctx, tool, input, {
        tool,
        command: tool === "bash" ? String(input.command ?? "") : undefined,
        path:
          tool === "edit" || tool === "write"
            ? String(input.path ?? "")
            : undefined,
      });
    }

    // ASK: prompt on edit/write; prompt on read outside cwd; mutating bash prompts.
    if (currentMode === "ask") {
      if (tool === "read" || tool === "grep" || tool === "find" || tool === "ls") {
        const pathStr = String(input.path ?? "");
        if (pathStr && isOutsideCwd(pathStr, ctx.cwd)) {
          // Prior authorisation first. Permission rules ARE consulted above
          // (applyConfiguredPermissionRules), but NEITHER grant store was consulted on this path, so
          // approving one outside-cwd read prompted again forever - the original complaint. This is
          // also the only place write-implies-read (auth-ledger.ts:158) can bite: layer 0 answers
          // every read_only verdict with tier allow, so the gate never needs the ledger for reads.
          const pctx = { cwd: ctx.cwd, project: ctx.cwd, home: homedir() };
          const pc = classifyPath(pathStr, pctx);
          const resolved = pc.abs ?? pathStr;
          // Secrets keep their own gate. Asking the ledger for `read_only` over a credentials file
          // would let a folder grant open it, which is the asymmetry 4414553 and 1f69702 established:
          // a scope grant never reaches a secret, only a grant naming that exact path does.
          const readCategory = pc.isSecret ? "read_secret" : "read_only";
          const ents = [{ kind: "target" as const, value: resolved }];
          if (
            grantsCover(gateGrants, readCategory, ents, pctx.home, pctx.project).covered ||
            ledgerCovers(gateLedger, readCategory, ents, pctx.home, pctx.project).covered
          ) {
            return undefined;
          }
          const res = await promptApproval(
            ctx,
            tool,
            `outside cwd on "${pathStr}"`,
            input,
          );
          if (res === undefined) {
            // Remember exactly what was approved: this file, never its directory. A plain Allow used
            // to store nothing here - the same defect the gate dialog fixed at index.ts:884-900.
            addGrant(gateGrants, readCategory, resolved, "entity");
            scheduleLedgerPersist();
          }
          return res;
        }
        return undefined;
      }
      if (tool === "edit" || tool === "write") {
        const pathVal = String(input.path ?? "(unknown)");
        if (!ctx.hasUI) {
          return promptApproval(ctx, tool, `on ${pathVal}`, input);
        }
        // The bypass switch stays ask-mode-only (adjudicated
        // 2026-09-12); side effects route through the shared executor.
        // Same preview contract as the gate dialog: show the rules before they are
        // written, and withhold the offer when it cannot be honoured.
        const pathRuleSet = suggestAllowRuleSetForToolCall(tool, input, ctx.cwd);
        const pathRuleNote = pathRuleSet.persistable
          ? ` Always-allow would write: ${pathRuleSet.rules.join(", ")}`
          : ` No always-allow available${pathRuleSet.reason ? `: ${pathRuleSet.reason}` : ""}.`;
        const choice = await ctx.ui.select(`Allow ${tool} on ${pathVal}?${pathRuleNote}`, [
          "Allow",
          ...(pathRuleSet.persistable
            ? ["Allow always (this project)", "Allow always (global)"]
            : []),
          "Allow all (enable bypass)",
          "Block",
        ]);
        const decision: ApprovalDecision =
          choice === "Allow always (this project)"
            ? "allow_always_local"
            : choice === "Allow always (global)"
              ? "allow_always_global"
              : choice === "Allow all (enable bypass)"
                ? "bypass"
                : choice === "Allow"
                  ? "allow"
                  : "block";
        return applyApprovalDecision(ctx, tool, input, decision, {
          blockReason: `${tool} blocked by user on ${pathVal}`,
        });
      }
      if (tool === "bash") {
        const cmd = String(input.command ?? "");
        if (isReadOnlyBash(cmd, ctx.cwd)) return undefined;
        return promptApproval(ctx, tool, `"${cmd}"`, input);
      }
      return undefined;
    }

    return undefined;
  });

  // ---- context injection (system prompt anchor) --------------------------
  // Appends the per-turn permission-modes notice as the LAST message of every
  // LLM call (pi converts role "custom" to a user message). Transient: the
  // message is not persisted to the session, and the classifier transcript
  // builder never sees it. Keeping it at the tail preserves the KV cache for
  // the whole conversation prefix.
  pi.on("context", async (event) => {
    if (!tailBannerText) return undefined;
    const messages = [
      ...(event.messages ?? []),
      {
        role: "custom" as const,
        customType: "permission-modes-notice",
        content: `<permission-mode>\n${tailBannerText}\n</permission-mode>`,
        display: false,
        timestamp: Date.now(),
      },
    ];
    return { messages };
  });

  pi.on("before_agent_start", async (event, ctx) => {
    // Keep inherited-mode env fresh so subagents spawned this turn see the
    // parent's current mode (covers mid-session upgrades / missed setMode).
    publishInheritedPermissionMode(currentMode);
    publishCapability({ mode: currentMode });

    // Re-apply each turn so other extensions (e.g. hypa replace mode) cannot
    // permanently drop plan-mode tools like ls/grep/find from the active set.
    applyToolRestrictions();

    classifierConfig = resolveClassifierConfig(loadPermissionModesConfig());
    autoModeConfig = resolveAutoModeConfig(loadPermissionModesConfig());
    injectionWarningEnabled = resolveInjectionWarning(loadPermissionModesConfig());
    injectionEscalationEnabled = resolveInjectionEscalation(loadPermissionModesConfig());
    reloadMergedPermissionRules(ctx.cwd);

    const systemPromptBase =
      event?.systemPrompt ?? ctx?.getSystemPrompt?.() ?? "";

    let modeBlock = "";

    if (planExecuting && planTodos.length) {
      const remaining = planTodos
        .filter((t) => !t.completed)
        .map((t) => `${t.step}. ${t.text}`)
        .join("\n");
      modeBlock = `[Plan/executing] Execute steps from plan.md. Remaining:\n${remaining}\nMark progress with [DONE:n] tags.`;
      planPhase = "executing";
    } else {
      const planPath =
        currentMode === "plan" ? shortenPath(ensurePlanFile(ctx.cwd)) : undefined;
      modeBlock = resolveModePrompt({
        mode: currentMode,
        planPhase,
        planFilePath: planPath,
        needsAskReminder,
        needsBypassSecurityReminder,
      });
    }

    if (needsAskReminder) needsAskReminder = false;
    if (needsBypassSecurityReminder) needsBypassSecurityReminder = false;

    let injectionBlock = "";
    const injectionModes = currentMode === "auto" || currentMode === "bypass";
    // Standing note: a per-call attention cost, so it is the part the user can switch off.
    if (injectionWarningEnabled && injectionModes) {
      injectionBlock = TOOL_OUTPUT_INJECTION_WARNING;
    }
    // Escalation: event-driven response to a real probe signal, kept on unless
    // explicitly disabled — turning off the standing note must not disarm it.
    if (injectionEscalationEnabled && injectionModes) {
      try {
        // Real SessionEntry shape comes unwrapped from the port; the legacy
        // flat `ctx.messages` fallback predates typed access.
        const messages = readBranchMessages(ctx.sessionManager);
        const signal = scanBranchForInjectionSignals(
          messages.length > 0 ? messages : (((ctx as any).messages ?? []) as never[]),
        );
        if (signal) {
          injectionBlock = buildInjectionWarningBlock(signal);
        }
      } catch {
        // best-effort scan only
      }
    }

    const skillFilter = resolveSkillFilter(modelProfileConfig, currentMode);
    let workingPrompt = systemPromptBase;
    if (skillFilter.length !== 1 || skillFilter[0] !== "*") {
      if (workingPrompt) {
        const filtered = filterSkillsFromPrompt(workingPrompt, skillFilter);
        if (
          skillFilter.length > 0 &&
          filtered === workingPrompt &&
          workingPrompt.includes("<skill")
        ) {
          console.warn(
            `[permission-modes] Skill filter for mode "${currentMode}" was a no-op ` +
              `(${skillFilter.length} skill(s) requested: ${skillFilter.join(", ")}).`,
          );
        }
        workingPrompt = filtered;
      }
    }

    // KV-cache-friendly banner delivery (stable-prompt): the system prompt is
    // left byte-identical across turns — the mode banner, one-shot notices and
    // the injection warning are stashed here and appended by the "context"
    // handler as a trailing message on every LLM call this turn. Any change to
    // the leading system prompt invalidates the server's KV cache for the
    // entire conversation (~180k tokens re-prefilled); a trailing message
    // costs only its own tokens, which is why the banner rides at the end.
    tailBannerText = [modeBlock.trim(), injectionBlock.trim()]
      .filter(Boolean)
      .join("\n\n");

    // The only remaining head mutation is per-mode skill filtering, which is
    // a no-op unless the user configured mode-specific skills (and then only
    // changes on an actual mode switch).
    if (workingPrompt !== systemPromptBase) {
      return { systemPrompt: workingPrompt };
    }
    return undefined;
  });

  pi.on("context", async (event) => {
    const msgs = event.messages as any[];
    let lastIdx = -1;
    for (let i = 0; i < msgs.length; i++) {
      if (msgs[i]?.customType === "modes-context") lastIdx = i;
    }
    if (lastIdx === -1) return undefined;
    return {
      messages: msgs.filter(
        (m, i) => m?.customType !== "modes-context" || i === lastIdx,
      ),
    };
  });

  // ---- streaming-stat working message -----------------------------------
  pi.on("turn_start", async (_event, ctx) => {
    streamStart = Date.now();
    outputAtStart = computeStats(ctx).output;
    refreshWorkingMessage(ctx);
  });
  pi.on("before_provider_request", async (_event, ctx) =>
    refreshWorkingMessage(ctx),
  );
  pi.on("message_update", async (_event, ctx) => refreshWorkingMessage(ctx));

  // ---- turn_end: tps + plan-step tracking --------------------------------
  pi.on("turn_end", async (event, ctx) => {
    try {
      gitBranch = readGitBranch(ctx.sessionManager) ?? gitBranch;
    } catch {
      /* ignore */
    }

    const stats = computeStats(ctx);
    const elapsed = Math.max((Date.now() - streamStart) / 1000, 0.001);
    const delta = stats.output - outputAtStart;
    if (delta > 0) lastTps = delta / elapsed;
    refreshWorkingMessage(ctx);

    const msg = event.message;
    if (!isAssistant(msg)) return;
    const text = getText(msg);

    if (planExecuting && planTodos.length) {
      if (markCompletedSteps(text, planTodos) > 0) updatePlanWidget(ctx);
      persistState();
    }
  });

  // ---- agent_end: idle reset + plan complete + plan offer ----------------
  pi.on("agent_end", async (event, ctx) => {
    if (ctx.hasUI) ctx.ui.setWorkingMessage();
    flushLedgerPersist();

    // Plan execution in progress: announce completion when all steps are done.
    if (planExecuting && planTodos.length) {
      if (planTodos.every((t) => t.completed)) {
        if (ctx.hasUI) {
          pi.sendMessage(
            {
              customType: "plan-complete",
              content: "**Plan Complete!** ✓",
              display: true,
            },
            { triggerTurn: false },
          );
          ctx.ui.setWidget("plan-todos", undefined);
        }
        planExecuting = false;
        planTodos = [];
        persistState();
      }
      return;
    }

    // In plan mode: sync plan.md and offer next action (throttled).
    if (currentMode !== "plan" || !ctx.hasUI || planExecuting) return;

    const planContent = readPlanFile(ctx.cwd);
    let extracted = filterSubstantivePlanItems(
      planContent ? extractTodoItems(planContent) : [],
    );

    const lastAssistant = [...(event.messages as any[])]
      .reverse()
      .find(isAssistant);
    const assistantText = lastAssistant ? getText(lastAssistant) : "";
    const assistantPlan = assistantText
      ? filterSubstantivePlanItems(extractTodoItems(assistantText))
      : [];

    if (!extracted.length && assistantPlan.length) {
      if (shouldSyncAssistantPlanToFile(planContent)) {
        const planSection = extractPlanSection(assistantText);
        if (planSection) writePlanFile(ctx.cwd, planSection);
        extracted = assistantPlan;
      }
    } else if (assistantPlan.length) {
      if (shouldSyncAssistantPlanToFile(planContent)) {
        const assistantSection = extractPlanSection(assistantText);
        if (assistantSection) writePlanFile(ctx.cwd, assistantSection);
        extracted = assistantPlan;
      }
    }

    if (!extracted.length) return;

    // Cooldown / Stay dismiss: don't re-offer within 60s of the last offer.
    if (Date.now() - lastPlanOfferAt < PLAN_OFFER_COOLDOWN_MS) return;
    if (Date.now() < suppressPlanOfferUntil) return;

    const syncedContent = readPlanFile(ctx.cwd) ?? planContent ?? "";
    const contentHash = hashPlan(
      syncedContent || JSON.stringify(extracted),
    );
    const isFirst = !lastExtractedPlanHash;
    const changed = contentHash !== lastExtractedPlanHash;
    if (!isFirst && !changed) return;

    planTodos = extracted;
    persistState();

    // Mark before await so a concurrent agent_end cannot open a second dialog.
    markPlanOfferHandled(syncedContent || JSON.stringify(extracted));
    const choice = await runPlanApprovalDialog(ctx, {
      planContent: syncedContent,
      stepCount: extracted.length,
    });
    markPlanOfferHandled(syncedContent || JSON.stringify(extracted));

    if (choice === "execute") {
      planExecuting = true;
      planPhase = "executing";
      currentMode = "auto";
      applyToolRestrictions();
      updateStatus(ctx);
      updatePlanWidget(ctx);
      persistState();
      await applyProfileModelForMode("auto", ctx);
      const steps = planTodos.map((t) => `${t.step}. ${t.text}`).join("\n");
      pi.sendMessage(
        {
          customType: "modes-execute",
          content: `Execute the plan now. Steps:\n${steps}\n\nStart with step 1. After finishing each step, include a [DONE:n] tag in your reply.`,
          display: true,
        },
        { triggerTurn: true, deliverAs: "followUp" },
      );
    } else if (choice === "refine") {
      await promptPlanRefinement(ctx);
    }
    // stay | cancel (Esc): dialog already closed; return silently to the input prompt.
  });

  pi.on("session_compact", async (_event, ctx) => {
    if (currentMode === "bypass") {
      needsBypassSecurityReminder = true;
    }
    persistState();
  });

  // ---- session start / resume -------------------------------------------
  async function onSessionStart(
    _event: unknown,
    ctx: ExtensionContext,
  ): Promise<void> {
    // Boot the wasm bash grammar in the background: never awaited, never throws,
    // session start does not wait for it. Until it lands, the layer-0 parser
    // reports not-initialised and the gate falls back to the lexer path.
    // If it never comes up, layer 0 answers "parser-unavailable" for every bash command — a
    // dead analyzer, not a dangerous command. Silence here reads as refusals about the user's
    // own command, so announce it once, on the channel the user actually looks at.
    void initBashParser()
      .catch(() => {})
      .then(() => {
        const down = takeBashParserWarning();
        if (down && ctx.hasUI) ctx.ui.notify(down, "warning");
      });

    // Ensure the model profiles config exists (creates ~/.pi/agent if missing
    // and writes a default file with the user's default model detected from
    // settings.json). Re-runs on /reload so a user-deleted file is recreated.
    modelProfileConfig = ensureModelProfilesConfig();

    const flag = pi.getFlag("permission-mode");
    if (typeof flag === "string") {
      if ((MODE_CYCLE as string[]).includes(flag)) {
        currentMode = flag as Mode;
      } else if (flag === "default" || flag === "accept-edits") {
        currentMode = "ask";
      }
    }

    // --model-profile <name>: validate and activate the named profile.
    const profileFlag = pi.getFlag("model-profile");
    if (typeof profileFlag === "string" && profileFlag) {
      const config = loadModelProfiles();
      if (profileExists(config, profileFlag)) {
        activeProfile = profileFlag;
        modelProfileConfig = config;
      } else if (ctx.hasUI) {
        ctx.ui.notify(
          `Unknown profile "${profileFlag}". Available: ${listProfiles(config).join(", ") || "(none)"}`,
          "warning",
        );
      }
    }

    // Restore the latest persisted mode entry (overrides the flag).
    try {
      const modesData = readCustomEntryData(ctx.sessionManager, "modes");
      const last = modesData[modesData.length - 1] as
        | {
            currentMode?: string;
            planPhase?: string;
            planExecuting?: boolean;
            planTodos?: TodoItem[];
            lastExtractedPlanHash?: string;
            activeProfile?: string;
            unattended?: boolean;
          }
        | undefined;
      if (last) {
        let m = last.currentMode;
        if (m === "normal") m = "default";      // legacy (v0.x)
        if (m === "default") m = "ask";          // v1.0.0 → v2.0.0 rename
        if (m === "accept-edits") m = "ask";
        // `m` can be undefined (a state file with no recorded mode), so the type is checked before the value is
        // trusted as a mode — previously this was `currentMode = m!` behind a string[] cast, which is exactly the
        // unsound assertion that let a non-mode value into currentMode.
        if (typeof m === "string" && (MODE_CYCLE as readonly string[]).includes(m)) currentMode = m as PermissionMode;
        if (typeof last.planPhase === "string")
          planPhase = last.planPhase as PlanPhase;
        if (typeof last.planExecuting === "boolean")
          planExecuting = last.planExecuting;
        if (Array.isArray(last.planTodos))
          planTodos = last.planTodos as TodoItem[];
        if (typeof last.lastExtractedPlanHash === "string")
          lastExtractedPlanHash = last.lastExtractedPlanHash;
        if (typeof last.activeProfile === "string")
          activeProfile = last.activeProfile;
        if (typeof last.unattended === "boolean")
          unattendedMode = last.unattended;
      }
    } catch {
      /* ignore */
    }

    // Restore ledger + session grants from the newest snapshot, dropping
    // entries whose source message is not on the current branch (rewinds).
    // No/invalid snapshot → empty ledger; backfill rebuilds it deterministically.
    try {
      const snaps = readCustomEntryData(ctx.sessionManager, "gate-ledger");
      const last = snaps[snaps.length - 1] as
        | { v?: number; ledger?: unknown; grants?: unknown }
        | undefined;
      if (last?.v === 1) {
        const refs = collectUserMessageRefs(
          readBranchEntries(ctx.sessionManager) as never,
        );
        gateLedger = deserializeLedger(last.ledger, new Set(refs.map((r) => r.id)));
        if (Array.isArray(last.grants)) {
          for (const g of last.grants as SessionGrant[]) {
            if (g && typeof g.category === "string" && typeof g.value === "string") {
              addGrant(gateGrants, g.category, g.value, g.kind === "scope" ? "scope" : "entity");
            }
          }
        }
      }
      // Auto-import AFTER snapshot restore: local session state must outrank
      // imported background authority, and that order is the whole rule.
      const autoNote = autoImportGrantsFromFile(ctx.cwd);
      if (autoNote && ctx.hasUI) ctx.ui.notify(autoNote, "info");
    } catch {
      /* ignore — backfill covers it */
    }

    // Headless subagents ALWAYS inherit the parent's live mode from env when
    // set (wins over --permission-mode flag and session restore). Review
    // fan-out must not stay on ask while the parent is in bypass.
    const inherited = applyInheritedModeForChild();
    if (inherited) currentMode = inherited;

    bridgeCwd = ctx.cwd;

    // In-process headless children (pi-schedule-prompt `model:` jobs) adopt the
    // parent's live mode, session grants and folded ledger, and are forced
    // unattended. Must run BEFORE reloadMergedPermissionRules()/
    // applyToolRestrictions() below, because applyAutoModePermissionStrip() reads
    // currentMode. The hasUI check means interactive sessions never take this
    // path, so normal `pi` behaviour is untouched.
    const bridged = resolveInheritedBridgeState({ hasUI: ctx.hasUI, cwd: ctx.cwd });
    if (bridged) {
      bridgedAsSubagentChild = true;
      currentMode = bridged.mode;
      unattendedMode = true;
      needsAskReminder = false;
      // No validMessageIds filter: the child's own branch contains none of the
      // parent's message ids. The parent's in-memory ledger already dropped
      // anything from rewound branches, so copying it cannot resurrect a grant the
      // user abandoned or revoked.
      gateLedger = deserializeLedger(bridged.ledger);
      for (const g of bridged.grants) {
        addGrant(gateGrants, g.category, g.value, g.kind);
      }
    }

    // Always publish so nested / later spawns see the effective mode.
    publishInheritedPermissionMode(currentMode);
    publishCapability({ mode: currentMode });
    publishBridgeState();

    classifierConfig = resolveClassifierConfig(loadPermissionModesConfig());
    autoModeConfig = resolveAutoModeConfig(loadPermissionModesConfig());
    injectionWarningEnabled = resolveInjectionWarning(loadPermissionModesConfig());
    injectionEscalationEnabled = resolveInjectionEscalation(loadPermissionModesConfig());
    if (currentMode === "auto") {
      classifierDenialState = createDenialTrackingState();
    }
    reloadMergedPermissionRules(ctx.cwd);

    try {
      gitBranch = readGitBranch(ctx.sessionManager) ?? "";
    } catch {
      /* ignore */
    }

    // Cache the project root once per session.
    if (projectRoot === null) {
      try {
        projectRoot = findProjectRoot(ctx.cwd);
      } catch {
        projectRoot = null;
      }
    }

    applyToolRestrictions();
    if (planExecuting && planTodos.length) updatePlanWidget(ctx);
    if (currentMode === "ask") needsAskReminder = true;
    if (currentMode === "bypass") needsBypassSecurityReminder = true;
    if (ctx.hasUI) {
      installFooter(ctx);
      updateStatus(ctx);
    }

    // If a profile was activated (via flag or persisted state), apply its
    // model mapping for the current mode.
    if (activeProfile) {
      await applyProfileModelForMode(currentMode, ctx);
    }

    startPermissionForwardingPoller(ctx);
  }

  async function handleForwardedPermissionRequest(
    ctx: ExtensionContext,
    request: ForwardedPermissionRequest,
  ): Promise<void> {
    const agentDir = defaultAgentDir();
    const name = request.requesterAgentName?.trim();
    const title = name
      ? `[Subagent ${name}] ${request.message}`
      : `[Subagent] ${request.message}`;
    const sessionId = readSessionId(ctx.sessionManager);
    // Only the targeted parent session may answer; reject mismatched inbox drain.
    if (sessionId && sessionId !== request.targetSessionId) {
      forwardingClaimedIds.delete(request.id);
      return;
    }
    const responderSessionId = request.targetSessionId;

    let decision: ForwardedDecision = "block";
    let approved = false;
    let denialReason: string | undefined = `${request.tool} blocked by user`;

    // Unattended parent: deny subagent requests with the same guidance the
    // parent's own model gets — nobody is watching either session.
    if (unattendedMode) {
      await writeForwardedResponse(agentDir, request.targetSessionId, {
        id: request.id,
        challenge: request.challenge,
        approved: false,
        decision: "block",
        responderSessionId,
        respondedAt: new Date().toISOString(),
        denialReason:
          `${request.tool} not auto-approved: ${request.message}.` +
          UNATTENDED_PARK_AFTER_HUMAN_DENIAL,
      });
      return;
    }

    try {
      const choice = await ctx.ui.select(title, [
        "Allow",
        "Allow always (this project)",
        "Allow always (global)",
        "Block",
      ]);
      if (choice === "Allow") {
        decision = "allow";
        approved = true;
        denialReason = undefined;
      } else if (choice === "Allow always (this project)") {
        decision = "allow_always_local";
        approved = true;
        denialReason = undefined;
        await applyApprovalDecision(ctx, request.tool, request.input, "allow_always_local", {
          ruleCwd: request.cwd,
          trackWrite: false,
        });
      } else if (choice === "Allow always (global)") {
        decision = "allow_always_global";
        approved = true;
        denialReason = undefined;
        await applyApprovalDecision(ctx, request.tool, request.input, "allow_always_global", {
          ruleCwd: request.cwd,
          trackWrite: false,
        });
      }
    } catch {
      decision = "block";
      approved = false;
      denialReason = `${request.tool} blocked: parent approval cancelled`;
    }

    await writeForwardedResponse(agentDir, request.targetSessionId, {
      id: request.id,
      challenge: request.challenge,
      approved,
      decision,
      responderSessionId,
      respondedAt: new Date().toISOString(),
      ...(denialReason ? { denialReason } : {}),
    });
  }

  function startPermissionForwardingPoller(ctx: ExtensionContext): void {
    forwardingPoller?.stop();
    forwardingPoller = undefined;
    if (!ctx.hasUI || isSubagentChildProcess()) return;

    const agentDir = defaultAgentDir();
    forwardingPoller = createForwardingPoller({
      agentDir,
      hasUI: true,
      isChild: false,
      claimedIds: forwardingClaimedIds,
      getSessionId: () => readSessionId(ctx.sessionManager),
      onRequest: (request) => handleForwardedPermissionRequest(ctx, request),
    });
    forwardingPoller.start();
  }

  pi.on("session_start", onSessionStart);
  pi.on("session_tree", onSessionStart);
  pi.on("session_shutdown", () => {
    forwardingPoller?.stop();
    forwardingPoller = undefined;
    forwardingClaimedIds.clear();
  });
}
