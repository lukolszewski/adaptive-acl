# Changelog

## [2.8.0] - 2026-10-19

This release is a fork of pi-permission-modes 2.7.0 (MIT); this fork is licensed AGPL-3.0-or-later, and `LICENSE` carries the upstream MIT notice alongside the notices for the two tree-sitter components it now ships.

### Added
- **A deterministic gate in front of the classifier** (`classifier.engine: "gate"`, now the default): a tool call is decided in code first. `risk-policy.ts` gives every command a tier (`allow` / `ask` / `never` / `unknown`) with a category and its targets, and only what the tables cannot read reaches a model — reads, project writes, project test/lint tools and local git resolve with no model call (`risk-handlers.ts:305`, `risk-handlers.ts:383`), while recursive deletes, pushes, listeners, uploads and db/cluster mutations come back as *ask*, entity-scoped, so approving `docker rmi api:dev` never covers `payments:prod`. `"engine": "legacy"` keeps the single-shot classifier of 2.7. Spec: `docs/CLASSIFIER-SPEC.md`.
- **A real bash grammar instead of a scanner** — commands are parsed with tree-sitter-bash (`bash-parser.ts`, `wasm/tree-sitter-bash.wasm`, walked under `docs/LAYER0-WALKER-SPEC.md`) and an argument list is produced only when every word is provably literal. Anything else returns `unknown` with a named reason (`unproven_value`, `could not parse command`, `parser-unavailable`), so no decision is ever built on a guess about quoting. `web-tree-sitter` is the package's first runtime dependency and the grammar ships inside the tarball.
- **A `never` tier that nothing can clear** — disk/device writes, `authorized_keys`, `NOPASSWD: ALL` sudoers edits, force-pushes to a protected branch, fork bombs (`risk-handlers.ts:570`, `risk-policy.ts:193-197`, `risk-policy.ts:490`): no allow rule, grant or "allow always" click applies, and the denial says so in those words.
- **Session grants and an authorisation ledger** — what the user actually said is now authority. A schema-constrained call extracts grants and forbids from each user message once, code verifies the quote verbatim and the entity token whole (`db-backup` ≠ `db-backup-test`), and `auth-ledger.ts` folds them into whole-session state: a grant given at message 1 still authorises at message 300, an explicit revocation blocks even when an older grant is inside the window, and a pre-existing session is backfilled newest-first in the background. The model can only narrow a decision, never widen it.
- **`/grants`** — the live grants and ledger, printed with copyable values: `clear`, `revoke <value>` (by value, never by list index — the list re-orders as grants are promoted), `export` / `import`, `auto on|off|path <p>` for the auto-import journal, and `adopt` (below). Both stores are snapshotted into the session (`index.ts:826`, restored at `index.ts:3666`), so they survive `/reload` and resume.
- **A durable grants journal** at `<cwd>/.pi/projects/<id>/grants.json` — an "always" click stores a row there (`durable-approval.ts`) and a row may never express more than the invocation that earned it: where no row can say exactly what was approved, the click is honoured once instead of widened.
- **A read-only posture** — "don't change anything" registers as a posture rather than a rule: mutations nothing has authorised are refused with the reason, while reads and the agent's own project and `/tmp` writes continue (`gate.ts:284-290`). It is a default, not a veto — an `ask` rule, a session grant or a later "now write to /x/" all outrank it, and "you can make changes now" clears it.
- **GitHub Copilot as the classifier model** — `"model": "github-copilot/auto"` lets GitHub pick, with the extension minting its own Auto session (`copilot-session.ts`: one POST per ~55 minutes, refreshed ahead of `expires_at`, single-flight on concurrent calls, 15 s cooldown after a failure) and sending the session header only with that pick. `classifier.copilot` tunes `maxOutputTokens` (default 512 — a reasoning model spends the reserve before it answers, so too small means no answer arrives at all), `reasoningEffort`, `budgetTokens` (0 = no cap; once spent the classifier stops sending and says so rather than burning quota) and `sessionEnabled`. Every failure — 404, refused token, a model whose dialect this client cannot encode, spent allowance — reads as *classifier unavailable* with the cause named, never as a refusal.
- **Classifier endpoint and budget keys** — `classifier.baseUrl` / `modelId` point straight at an OpenAI-compatible server (llama.cpp, vLLM, litellm) instead of resolving `model` through pi's registry; `classifier.contextTokens` sizes every call to that model's window; `classifier.ledger` and `ledgerBackfillLimit` bound the ledger and how much of a session is ever re-extracted.
- **`/unattended`** — overnight work: approval prompts soft-deny with the reason so the agent adapts or parks the step, `never` stays hard-blocked, and a run that keeps hitting denials stops asking the model instead of paying for another refusal. Persisted with the mode.
- **`/classifier-status`** — config plus this session's counters (eligible / called / ok / failed / no-endpoint), the Copilot allowance spent against its cap, and how many extracted grants came back with a schema category, so an endpoint that ignores `response_format: json_schema` is visible here instead of silently failing to register folder- and secret-scoped grants.
- **`/msg`** — predefined messages stored in the config and sent on demand (`list`, `add`, `show`, `del`, `send`), delivered as a follow-up so they arrive after the current work rather than steering mid-turn. **`/injection-note`** toggles the standing auto/bypass injection note and the probe-triggered escalation independently, persisted as `injectionWarning` / `injectionEscalation`.
- **`/grants adopt`, for a checkout that moved.** `<cwd>/.pi/projects/` can hold state for an id the session no longer uses — after a rename, the old directory sits there with every rule it ever had and nothing reads it. Tightening rules (`deny` / `ask`) are copied over quietly, because they can only make a session stricter and a lost deny fails silently; every `allow` and grant row is listed as pending until a human names it (`adopt confirm <id>`, by id, never by row number) and a confirmed rule is re-read from the file so it is live in the same session (`adopt-live.ts`, `reload-policy.ts`).
- **`.pi/project.json` carries a project's id inside the tree**, so a `git worktree move`, a rename or a sibling checkout no longer orphans the rules and grants stored under the derived id. Resolution order: `.pi/project.json` → pi's `.pi/permission-modes-<id>.md` marker → `sha256(cwd)[0:8]` (`utils.ts:694-706`).
- **Project-scoped config** at `<cwd>/.pi/permission-modes.json` for `authority` and mode provenance. It deliberately holds no rules — a second rule path reachable through a project directory is one nobody audited — and it sits outside `.pi/projects/<id>/` precisely so a moved checkout carries it.

### Changed
- **"Allow always" stores a grant row instead of a rule line** (`authority.persist` now defaults to `"grants"`), which is what lets a project run with no hand-authored permission file. One key restores the 2.7 behaviour in either scope — `{ "authority": { "persist": "rules" } }` — and the footer grows a `⚖ grants@project` badge whenever an authority setting came from a layer rather than the default, so "the wall got stricter and I don't know why" has an answer.
- **Denials name who refused** (`gate-bridge.ts:521-591`): layer-0 policy, a `deny`/`ask` rule quoting its own text, a grant (revoked or absent), a ledger row with the value to pass to `/grants revoke`, the classifier (denied / unavailable / no endpoint / window too small), the denial budget, or a person. Where the caller cannot say, it prints `undetermined` rather than guessing — a confidently wrong attribution sends the reader to the wrong lever.
- **`Bash(...)` allow rules are matched against parsed argv** (`bash-rule-argv.ts`) rather than a re-split of the command text, so a `&&` chain no longer defeats an allow rule and `Bash(bash x.sh)` matches `bash x.sh arg`.
- **Classifier verdicts are structured, not read out of prose** — the extension now speaks the provider HTTP itself (`model-client.ts`) with `response_format: json_schema` (chat) or `text.format: json_schema` (responses), because free-text verdicts were where the parse failures came from. Any transport error is reported as an unavailable classifier and falls back to asking a person.
- **Broad-bash detection covers rules that name no command**: `Bash` / `Bash(*)` and any listed interpreter with an all-arguments tail are stripped on auto entry (`dangerous-permissions.ts`), while a rule that pins a subcommand (`npm run test`, `npm install lodash:*`) stays in force and `deny` / `ask` rules are never touched.
- **The mode set is unchanged** — still `ask` / `plan` / `auto` / `bypass`, still Shift+Tab, `/ask` `/plan` `/auto` `/bypass`, `/mode`, `--permission-mode`, and `PERMISSION_MODES_INHERITED_MODE` for subagent children. No mode was renamed and no config file was restructured.

### Fixed
- **A moved checkout keeps its authority.** Before this, renaming a directory silently dropped every rule the derived id held — broad allow rules and the `~/.pi` read denies alike — with nothing printed and nothing to retry. See `.pi/project.json` and `/grants adopt` above.
- **An unavailable analyzer no longer looks like a bad command.** While the grammar is loading, or if it never loads, *every* bash command is unverifiable; the old wording ("cannot verify command structure") sent the reader off to rewrite a command that was never the problem. The refusal now says the analyzer is not running in this process (`bash-parser.ts:197`) and a failed load is announced once at session start.
- **Malformed commands are refused before they are guessed at.** An unterminated quote, heredoc or `$( )` returns a *fix it and retry* message to the agent — no model call, no prompt — instead of a mis-parsed segment list, and only a small budget of repeats escalates (`gate.ts:152`).
- **An adopted rule takes effect the same session.** Writing the rule and re-reading the rules files are now one action (`adopt-live.ts`); previously the confirmation printed "adopted" while the running policy snapshot still refused the very next call.
- **Auto-mode rule stripping round-trips.** The stash restores the rule objects, their order and their source identity rather than copies, skips a rule the user re-added while auto mode ran, and leaves `deny` / `ask` rules alone however broad they are.

### Notes
- **Nothing to migrate.** The mode set did not change, so an existing `~/.pi/agent/permission-modes.json`, `permissions*.json` or `model-profiles.json` is read exactly as before and nothing rewrites it. Two *defaults* did move, and each reverts with one key: the classifier `engine` (`gate`; `"legacy"` for the 2.7 classifier) and `authority.persist` (`grants`; `"rules"` for the 2.7 rule-file behaviour).
- **One runtime dependency now** (`web-tree-sitter@0.27.1`) plus the 1.4 MB wasm grammar and its license, shipped in the package. `npm run typecheck` (`tsc --noEmit`, new `tsconfig.json`) is part of the release, and the suite is 3485 tests across 85 files.
- The two specs written for this release live in `docs/CLASSIFIER-SPEC.md` (the gate's layers, its outcomes, and the acceptance criteria each one is measured against) and `docs/LAYER0-WALKER-SPEC.md` (how a command is walked, and the reason vocabulary it returns when it refuses to classify one).

## [2.7.0] - 2026-09-12

### Changed
- **Bash risk policy adjudication (2026-09-12)** — full rationale in `docs/bash-risk-adjudication-2026-09-12.md`:
  - Auto mode now strips broad package-manager allow rules (`Bash(npm install *)`, `Bash(pnpm add:*)`, `Bash(pip install:*)`, `Bash(cargo run:*)`, …) on entry, like interpreter rules — such rules bypass the classifier and lifecycle scripts (postinstall / setup.py / build.rs) are arbitrary code runs. Narrow package-scoped rules (`Bash(npm install lodash:*)`) still survive.
  - git hook vectors (`commit`/`merge`/`rebase`/`cherry-pick`/`revert`) and worktree-loss forms (`restore`, `checkout -- <path>`) drop from tier-2 auto-approve to tier-3 classifier review; `add`/`stash`/`branch`/`switch`/`tag`/`init`/`clone`/`reset` remain tier-2.
  - `npm|pnpm|yarn|bun run <script>` tier-2 auto-approve is whitelist-gated (test/build/lint/check/typecheck/verify/coverage/unit/ci + dev/start/preview/serve/watch); deploy-like script names go to tier-3.
  - Tier-2 auto-approve reuses the classifier-offline fallback guardrails: unsafe config/exec flags (`--config`, `--require`, `-exec`, `--script-shell`, …) and outside-cwd path arguments now demote commands to tier-3 (`mv notes.txt ~/`, `mkdir /tmp/x` no longer auto-approve). Principle: the offline conservative face must never be looser than the online auto-approve face.
  - `docker run`/`docker exec` drop to tier-3 (host-mount execution vectors); `build`/`compose`/`logs`/`ps`/`images` remain tier-2.

### Changed
- **Typed capability channel to pi-claude-code-tui (plan B7)**: mode and working-stats are now published on a single versioned object `globalThis.__piPermissionModes` (`{version, active, mode, workingStats}`). The legacy untyped `__pmWorkingStats` string (with its literal-prefix contract) keeps publishing for one compatibility cycle; the cctui side reads the capability first and falls back to the legacy keys.

### Performance
- Tool-call gate: the bypass early-return now runs before the plan-file probe, and `getProjectId` caches positive marker lookups per cwd (a marker created mid-session still switches the id over). `readAgentsMdForClassifier` caches AGENTS.md/CLAUDE.md by (path, mtime) instead of re-reading on every tier-3 classifier call. No behavior change.
- Streaming stats are now incremental: usage totals accumulate over new branch entries only, instead of re-summing the whole session on every `message_update` chunk (pi freezes the branch while streaming; a moved prefix — navigate/fork/switch — forces a full recompute). Property-tested against the brute-force sum over randomized append/fork/switch sequences; ~100x cheaper per chunk on a 1000-entry session.
- The auto-mode bash tier ladder tokenizes each command once (`classifyBashTiers`): `isSafeCommand` and `isAutoApprovableBash` previously re-split the same command at every check point.
- Classifier verdicts are memoized for identical retries (60s TTL, 64-entry bound, key includes modelRef/stage/mode/cwd/autoMode rules/input); reloading permission rules drops the memo so verdicts never go stale against new rules.

### Fixed
- **Ask-mode approval flow dropped side effects (plan B2)**: the ask-mode inline approval select was a third copy of the approval logic and had diverged — "Allow", "Allow always (this project/global)", and "Allow all (enable bypass)" paths all skipped outside-cwd write tracking (no undo snapshot), allow-always paths skipped the gitignore warning and the "Added allow rule" notification, and `addPermissionRule` results went unchecked. All three approval flows (interactive select, ask-mode inline select, forwarded-parent responder) now execute decisions through a single `applyApprovalDecision` executor, so tracking/persistence/reload/notifications cannot diverge again. Option sets stay per-flow by design (the bypass switch remains ask-mode-only, CC-aligned).
- **Injection probe was dead at runtime (security, plan B1)**: `scanBranchForInjectionSignals` checked for a `"tool"` role, but pi's branch entries are wrapped as `{type:"message", message:{role:"user"|"assistant"|"toolResult"}}` — the specific-pattern warning never fired, and the test fixture used a fantasy shape that hid it. All session reads now go through a typed `session-branch.ts` port (zero `sessionManager` casts remain in index.ts); auto/bypass mode again injects the specific "Recent tool output matched a possible injection pattern" block when a recent toolResult matches an injection pattern.
- **Tier-1 read-only bypasses (security)**: `env X=1 <cmd>` and `awk` are no longer treated as read-only in plan mode (`env` executes the suffixed command and SAFE patterns only anchor the start; `awk` has `system()`/redirect execution vectors). `sed -n '…w /path'` write forms are blocked while plain `sed -n 'p'` reads stay allowed. `curl`/`wget` were added to the destructive list as defense in depth.

## [2.6.4] - 2026-09-04

### Changed
- **CC-TUI working-stats integration**: when the `pi-claude-code-tui`
  extension is active (it sets `globalThis.__ccTuiActive`), the working
  stats line (↑/↓ tokens · cache · tok/s · $ · ctx%) is published to
  `globalThis.__pmWorkingStats` for the TUI's status row instead of being
  written to pi's working-message slot — removes the duplicate "Working…"
  line between the transcript and the status bar. Without CC-TUI the
  behavior is unchanged.

## [2.6.3] - 2026-08-02

### Fixed
- **Headless ask forwarding gate**: forwarding to a parent session now requires **both** `PI_SUBAGENT_CHILD=1` and `PI_SUBAGENT_PARENT_SESSION`. Previously `PI_SUBAGENT_PARENT_SESSION` alone was enough, which hung any unrelated process that inherited the env (tests, ad-hoc node calls, non-subagent headless callers) on a 5-second poll with no responder. Headless callers that are not subagent children fall back to fail-closed (`no UI available`).

## [2.6.2] - 2026-08-02

### Fixed
- **Subagent mode inherit**: children always apply `PERMISSION_MODES_INHERITED_MODE` when set (no longer skipped when `--permission-mode` is present). Parent republishes the live mode on every `before_agent_start` so mid-session upgrades / fan-out turns see bypass correctly.
- **Headless ask forwarding gate**: forwarding to a parent session now requires **both** `PI_SUBAGENT_CHILD=1` and `PI_SUBAGENT_PARENT_SESSION`. Previously `PI_SUBAGENT_PARENT_SESSION` alone was enough, which hung any unrelated process that inherited the env (tests, ad-hoc node calls, non-subagent headless callers) on a 5-second poll with no responder. Headless callers that are not subagent children fall back to fail-closed (`no UI available`).

## [2.6.1] - 2026-08-02

### Added
- **Subagent inherits parent permission mode**: the interactive session publishes `PERMISSION_MODES_INHERITED_MODE` on mode change / session start. Headless `PI_SUBAGENT_CHILD` processes apply that mode after session restore (so parent **bypass** / **auto** / **ask** / **plan** carries into reviewers). Explicit `--permission-mode` on the child still wins. Nested children keep the value they received at spawn.

## [2.6.0] - 2026-07-31

### Added
- **Subagent ask forwarding**: when a headless child (`!ctx.hasUI`) needs approval and `PI_SUBAGENT_PARENT_SESSION` is set (pi-subagents), the ask is forwarded to the parent interactive session via a filesystem inbox under `~/.pi/agent/sessions/permission-modes-forwarding/`. Parent shows the usual Allow / Allow always / Block UI; Allow always rules are written using the **child** `cwd`. Timeout / missing parent / deny remain fail-closed. Nested subagents that target a non-UI parent still time out and deny (does not chase root). Namespace is separate from gotgenes `permission-forwarding`.

## [2.5.0] - 2026-07-30

### Added
- **Profile effort**: `ModeConfig.effort` on each mode entry in `model-profiles.json`. Switching modes applies model **and** thinking level (`off|minimal|low|medium|high|xhigh`). Explicit `effort` wins over a `:suffix` on the model string; bare `"provider/model:high"` still works. If neither is set, defaults to **`medium`**.

## [2.4.2] - 2026-07-29

### Changed
- **Near-fullscreen plan ready (92%)**: taller bottom-anchored panel with scrollable plan body and sticky option footer (Cursor / Claude Code style).

### Fixed
- **Plan-mode `2>&1` false positive**: fd-to-fd redirects no longer trip the file-redirect destructive check, so `ls … 2>&1` / `cat … 2>&1 | head` work in plan mode.

## [2.4.1] - 2026-07-29

### Fixed
- **Plan ready dialog floating mid-screen**: stop padding the dialog to the full terminal height (which pushed options upward). Use a bottom-anchored overlay (`anchor: bottom-center`, `maxHeight: 50%`) with options fixed at the bottom of the panel.
- **Stay in plan mode needing two dismisses**: after Stay/Esc/Refine, sync the plan hash and suppress `agent_end` re-offer for the cooldown window so the dialog does not immediately reopen.

[2.6.3]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.6.2...v2.6.3
[2.6.2]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.6.1...v2.6.2
[2.6.1]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.6.0...v2.6.1
[2.6.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.4.2...v2.5.0
[2.4.2]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.4.0...v2.4.1

## [2.4.0] - 2026-07-25

### Added
- **CC-aligned auto security stack**: deny-and-continue on classifier blocks, fail-closed (`classifier.failClosed`, default `true`) when classifier is unavailable, denial tracking (3 consecutive / 20 total → manual UI).
- **Classifier pipelines** (`classifier.stage`: `tool` | `single` | `fast` | `both` | `thinking`, default `tool`). `tool` uses CC-style forced `classify_result` tool call with API thinking disabled; XML stages use fast-screen + optional CoT escalation in `classifier-client.ts`.
- **`classifier-tool.ts`**: `classify_result` tool schema aligned with Claude Code auto-mode classifier.
- **Model ref stage suffix**: `provider/model@tool` (or `@single`, `@fast`, `@both`, `@thinking`) overrides `classifier.stage` for per-model pipeline selection.
- **`dangerous-permissions.ts`**: strips broad/dangerous `allow` rules (e.g. `Bash(*)`, `Bash(python:*)`) on auto mode entry; restores on exit.
- **`classifier-messages.ts`**, **`denial-tracking.ts`**, **`injection-probe.ts`**: CC-style rejection messages, denial counters, and tool-output injection warnings.
- **`classifier.includeAgentsMd`** config (default `true`); agents config cannot override deny rules in classifier prompt.
- **`parseModelRef`** supports `:thinking` / `:high` profile suffixes.

### Changed
- **Breaking: tighter auto tiers** — `curl`/`wget` removed from tier-1; `npm install`, `git fetch/pull`, arbitrary `node`/`python`, `docker pull` removed from tier-2. These now require classifier (tier-3) or manual approval.
- **Classifier block** no longer opens approval UI by default; returns structured deny-and-continue message to the agent.
- **Classifier failure** no longer fail-opens to local rules when `failClosed` is true (default).

### Migration
1. Expect more tier-3 reviews for network and package-install commands in auto mode.
2. Broad `Bash(*)` / interpreter allow rules are ignored while in auto mode (restored when leaving auto).
3. Ensure classifier model is configured and `timeoutMs` ≥ 20000 for remote providers.
4. Default classifier pipeline is `tool` (forced `classify_result`). Use `classifier.stage: "single"` for free-form JSON, or `@both` / `stage: "both"` for CC XML two-stage. Append `@tool` on `classifier.model` to force tool mode for one model without changing global config.

[2.4.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.3.0...v2.4.0

## [2.3.0] - 2026-07-25

### Added
- **`plan_ready` tool** for model-initiated plan submission in plan mode.
- **Full plan display** in the plan approval dialog.

### Changed
- Plan mode: cooldown, richer prompt, and `/plan-execute` improvements.

[2.3.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.2.0...v2.3.0

## [2.2.0] - 2026-07-25

### Added
- **Auto mode 4-tier gate** with broader auto-approve patterns and classifier hardening.

[2.2.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.1.0...v2.2.0

## [2.1.0] - 2026-07-15

### Added
- **CC-style permission rules** (`permissions.ts`, `permissions-loader.ts`, `permission-rule-parser.ts`, `shell-rule-matching.ts`, `bash-permission-match.ts`, `path-permission-match.ts`): `allow` / `deny` / `ask` lists with `Tool(specifier)` syntax aligned to Claude Code.
- **Three config scopes**: global (`~/.pi/agent/permission-modes.json`), project (`<cwd>/.pi/projects/<id>/permissions.json`), local (`permissions.local.json`).
- **`/permissions`** command to list merged rules.
- **Approval persistence**: "Allow always (this project)" and "Allow always (global)" on permission prompts.

### Changed
- **Tool gate**: configured rules run before mode gate (bypass exempt). `allow` skips mode prompts; `deny` always blocks; `ask` forces approval.
- **Auto mode**: risky ops prompt with allow-always options (replacing hard-block-only for tier-3 in recent builds).

### Notes
- Total tests: **275 passing**.
- Bash rule matching: deny/ask evaluate compound commands per segment; allow does not match compound commands (CC security model).

[2.1.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v2.0.0...v2.1.0

## [2.0.0] - 2026-07-11

### Added
- **Fourth mode: `bypass`** — full auto-approve (v1.1.6 auto semantics). Cycle is now `ask → plan → auto → bypass → ask` (Shift+Tab). Sparse security reminder on mode switch and after `session_compact`.
- **Built-in auto classifier** (`classifier-client.ts`): optional LLM review for tier-3 tool calls via `completeSimple` from `@earendil-works/pi-ai/compat` with auth from `ctx.modelRegistry.getApiKeyAndHeaders()`. Config: `~/.pi/agent/permission-modes.json` (`classifier.enabled` defaults to `false`).
- **Plan file driver**: plan content lives at `<cwd>/.pi/projects/<projectId>/plan.md`; injection is path-only. Plan mode allows `edit`/`write` on that file only.
- **System prompt anchor injection** (`<!-- permission-modes:context -->`) replaces per-turn `modes-context` messages.
- **`AUTO_RISK_PATTERNS` blacklist** as permanent auto-mode fallback when classifier is off or fails.

### Changed
- **Breaking: `auto` semantics** — tiered auto-approve (read → cwd writes → classifier/blacklist for risky ops). Old full-auto behavior is **`bypass`**.
- **Breaking: removed `/auto-depth`** and per-turn `"Continue..."` synthetic follow-ups.
- **Ask "Allow all"** now switches to **bypass** (not auto).
- **`profiles.ts`**: `bypass` mode supported in model profiles.

### Removed
- `modes-context` injection on every turn (legacy `context` dedup hook retained for old sessions).

### Notes
- Total tests: **201 passing**.
- Migration: sessions restored with `currentMode: "auto"` get the **new** auto (not full bypass). Use `/bypass` for unrestricted auto-approve.

[2.0.0]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v1.1.6...v2.0.0

## [1.1.6] - 2026-07-01

### Added
- **Adaptive footer layout**: Wide terminals show cwd (left) · context usage (center) · model/profile (right) on line 1, mode on line 2. Narrow terminals reflow to cwd + context on line 1, mode + model on line 2, with truncation to prevent overflow.
- **Context usage in footer**: Displays `tokens/contextWindow percent` via `ctx.getContextUsage()` (e.g. `42k/200k 21.0%`). Large counts use an `M` suffix (e.g. `1.0M`).

### Fixed
- **Narrow-terminal crash**: Footer layout no longer computes negative gaps when the terminal is too narrow — pre-truncates text and uses `Math.max(1, …)` for spacing.

### Changed
- **Removed colored status pill**: `ctx.ui.setStatus("modes", undefined)` — mode is shown only in the custom footer (working indicator `●` remains).
- **Mode colors**: plan uses `accent`, auto uses `warning` (swapped from v1.1.5).
- **npm scope**: Package renamed from `@aprimediet/permission-modes` to `@georgedong32/permission-modes`. Old scope remains on npm as a separate line; new installs should use `@georgedong32/permission-modes`.
- **`package.json`**: Added `repository`, `bugs`, `homepage`, and `publishConfig` metadata.

### Notes
- Total tests: **189 passing** (unchanged from v1.1.5).
- Git tag: `v1.1.6`.

[1.1.6]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v1.1.5...v1.1.6

## [1.1.5] - 2026-06-29

### Fixed
- **CRITICAL: Skill filtering was a no-op.** The `filterSkillsFromPrompt()` regex in `utils.ts` matched the Agent Skills spec format `<skill name="...">` (with the skill name as an attribute), but pi's actual `formatSkillsForPrompt()` (in `@earendil-works/pi-coding-agent/dist/core/skills.js`) emits `<skill>\n  <name>...</name>\n  <description>...</description>\n  <location>...</location>\n</skill>` (name as a child element). The regex matched **zero** of the 21 real skill blocks in this very session's system prompt — `String.prototype.replace()` returns the prompt unchanged when there are no matches, so all skills leaked through regardless of the `model-profiles.json` allowlist. The 19 unit tests for `filterSkillsFromPrompt` in `utils.test.ts` all passed because they were constructed against the wrong format. Confirmed at runtime: 21 skills in system prompt with `plan.skills = ["brainstorming","using-superpowers","writing-plans"]` → expected 3, got 21.
- **Regex updated** to match pi's actual schema: `<skill>\s*<name>([^<]+)<\/name>[\s\S]*?<\/skill>`. Same fast-paths (`["*"]`, `[]`, no `<skill>` in prompt) and same semantics — only the pattern matched against the skill blocks changed.
- **Test fixtures rewritten** in `utils.test.ts` and `index.test.ts` to use pi's actual format. Added two new tests:
  - `does NOT match the Agent Skills spec attribute format (regression guard)` — locks in that the v1.1.4 wrong format is NOT silently swallowed.
  - `matches the EXACT output of pi's formatSkillsForPrompt (integration)` — uses a verbatim copy of the schema emitted by `@earendil-works/pi-coding-agent/dist/core/skills.js` so future pi format drift is caught immediately.

### Added
- **Defensive `console.warn`** in `index.ts:before_agent_start`: if the user has a non-empty, non-`["*"]` skill filter AND the system prompt contains `<skill>` blocks AND filtering returned the prompt unchanged, log a loud warning. This is the symptom of pi changing `formatSkillsForPrompt()` without us noticing — surfaced instead of silently regressing.

### Changed
- **`utils.ts`**: doc-comment for `filterSkillsFromPrompt` updated to describe pi's actual schema (with reference to `skills.js:formatSkillsForPrompt`) instead of the Agent Skills spec attribute format.
- **`index.ts`**: `before_agent_start` now logs the defensive warning described above.

### Notes
- Total tests: **189 passing** (78 utils + 50 profiles + 61 index) — was 187 before v1.1.5.
- Manual verification on the current session: with `~/.pi/agent/model-profiles.json` `default.plan.skills = ["brainstorming","using-superpowers","writing-plans"]`, the v1.1.5 regex correctly reduces 21 → 3 `<skill>` blocks.
- This is a behavior-changing fix to a feature that was effectively missing in v1.1.4. Bumped to v1.1.5 (minor) rather than v1.1.4 patch.

[1.1.5]: https://github.com/GeorgeDong32/pi-permission-modes/compare/v1.1.4...v1.1.5

## [1.1.4] - 2026-06-29

### Added
- **Per-mode skill filtering**: Extend `~/.pi/agent/model-profiles.json` so each mode within a profile can specify a `skills` allowlist (e.g., `"skills": ["brainstorming", "writing-plans"]`). Skills not in the list are stripped from the system prompt via `before_agent_start`, saving tokens and keeping the agent focused on mode-relevant workflows.
- **`ModeConfig` type**: Profiles can now use either a string (backward compatible) or a configuration object: `{ "model": "...", "skills": [...], "tools": [...] }`.
- **`resolveModeConfig()`, `resolveSkillFilter()`, `resolveToolFilter()`** in `profiles.ts` — helpers to resolve the effective configuration for a mode, with fallback from active profile → default profile → hardcoded defaults.
- **`filterSkillsFromPrompt()`** in `utils.ts` — pure function that strips disallowed `<skill>` XML blocks from the system prompt using the Agent Skills spec format.
- **39 new tests**: 19 unit tests for config resolution, 13 unit tests for skill filtering, 7 integration tests for `before_agent_start` skill filtering.

### Changed
- **`profiles.ts`**: `ModelProfile` now accepts `string | ModeConfig` for each mode key. Added `ModeConfig` interface, `resolveModeConfig()`, `resolveSkillFilter()`, `resolveToolFilter()`, and internal `normalizeModeEntry()`.
- **`utils.ts`**: Added `filterSkillsFromPrompt()` export.
- **`index.ts`**: `before_agent_start` handler now receives `(event, ctx)`, reads the current `event.systemPrompt`, applies `filterSkillsFromPrompt()` when a non-`["*"]` skill filter is active, and returns the modified system prompt alongside the mode-context message.
- **Backward compatibility**: Existing string-only configs parse identically. No migration needed.

### Notes
- Total tests: **187 passing** (76 utils + 50 profiles + 61 index).
- Tool filtering is a **stub** in `resolveToolFilter()` (injects `read` as mandatory) — full implementation in v1.1.5.
- Skill filtering only affects system prompt injection; skills can still be invoked via `/skill:name` if needed.
- Skill filtering is config-file-only; no CLI flags for skill/tool filtering.

[1.1.4]: https://github.com/aprimediet/pi-permission-modes/compare/v1.1.3...v1.1.4

## [1.1.3] - 2026-06-29

### Added
- **Auto-mode outside-cwd write tracking**: In auto mode, `edit`/`write` calls to paths outside the working directory are now auto-approved (previously prompted), but each one is snapshotted to `<cwd>/.pi/projects/<project-id>/tmp/outside-writes/` for potential rollback. Snapshots include the pre-write file content (or `null` if the file didn't exist).
- **`/outside-writes` command**: Lists all tracked outside-cwd writes (read-only). Shows timestamp, tool, path, and what `/undo-outside-writes` would do (`would restore` vs `would delete`).
- **`/undo-outside-writes` command**: Restores one or all tracked outside-cwd writes. Modes:
  - no args — interactive selector (newest first)
  - `all` — restore all without prompting
  - `--list` (or `list`) — alias for `/outside-writes`
  - Available in all modes (not auto-only).
- **Snapshot cap at 100**: Long-running sessions auto-evict oldest snapshots (LRU) and notify via `ctx.ui.notify`.
- **21 new unit tests** in `utils.test.ts` (project ID, hash, tmp dir, snapshot lifecycle).
- **15 new integration tests** in `index.test.ts` (auto-mode tracking, undo commands, edge cases, external-modification warning).

### Changed
- **`index.ts`**: Auto-mode `tool_call` branch no longer prompts on edit/write outside cwd. Still prompts on bash destructive-outside-cwd (safety net unchanged). Tracks every outside-cwd write via `trackOutsideWrite()`. MODE_CONTEXT["auto"] updated to mention tracking. Added `formatSnapshotForDisplay()`, `isExternallyModified()`, `/outside-writes` command, and `/undo-outside-writes` command.
- **`utils.ts`**: Added 8 new exports — `OutsideWriteSnapshot`, `getProjectId`, `hashPath`, `getProjectTmpDir`, `trackOutsideWrite`, `listTrackedOutsideWrites`, `restoreOutsideWrite`, `popTrackedOutsideWrite`. Added `readFileSync`, `createHash`, `mkdirSync`, `readdirSync`, `writeFileSync`, `unlinkSync` imports. Added `MAX_TRACKED_WRITES` constant.
- **`docs/prompts/auto-mode-prompts.md`**: Updated auto-approve conditions, added write tracking section, updated decision tree.
- **`docs/PRD.md`**: Added "Outside-Cwd Write Tracking" feature and commands table.
- **`AGENTS.md`**: Updated summary, commands table, current focus, boundaries, known issues.
- **`README.md`**: Updated modes table, commands table, added outside-cwd write tracking section, bumped test count.

### Fixed
- Auto mode previously prompted on outside-cwd writes — now auto-approves (more in line with auto-mode's hands-off philosophy) while keeping a rollback safety net via snapshots.

### Notes
- Total tests: **148 passing** (60 utils + 31 profiles + 54 index integration + 3 vitest config).
- Ask/plan mode behavior unchanged.
- Bash destructive-outside-cwd prompt unchanged (still prompts).
- Snapshot dir creation failure is non-fatal: logs a warning, skips tracking, still auto-approves the write.

[1.1.3]: https://github.com/aprimediet/pi-permission-modes/compare/v1.1.2...v1.1.3

# Changelog

## [1.1.2] - 2026-06-28

### Added
- **`Alt+I` shortcut**: Cycles through model profiles defined in `~/.pi/agent/model-profiles.json`. Each press advances to the next profile (wrapping around) and re-applies the model mapping for the current mode, so the footer + status pill update immediately. Mirrors `Shift+Tab`'s cycle-by-one behavior for profiles.
- **Integration tests** — 7 new tests in `index.test.ts` for the `Alt+I` shortcut: registration, single-step advance, wrap-around from the last profile, default-profile starting point, empty-config warning, model re-application after cycling, and the "Profile activated" notification.

### Fixed
- **`applyProfileModelForMode` ignored in-memory profile switches**: `resolveModelForMode()` reads `config.active` to determine which profile to use, but `setActiveProfile()` only updated the in-memory `activeProfile` variable. After `/model-profile <name>` or `Alt+I` the wrong profile's model was applied on subsequent mode changes. Now the reload step re-stamps `active` with the in-memory `activeProfile` so profile switches always take effect. The on-disk file is NOT modified.

### Changed
- **`index.ts`**: Added `cycleProfile()` helper and `pi.registerShortcut("alt+i", ...)` registration. Hardened `applyProfileModelForMode()` to honor in-memory profile switches when reloading the config.
- **`index.test.ts`**: Fake pi stub now captures registered shortcuts in a `Map<string, Handler>` and exposes `simulateShortcut(key, ctx)` for direct invocation. (Previously a no-op stub.)
- **`package.json`**: Version bumped to `1.1.2`.
- **`README.md`**: Added `Alt+I` row to the commands/shortcuts table.

### Notes
- Total tests: **112 passing** (42 utils + 31 profiles + 39 index integration).
- `Alt+I` is a new binding — it doesn't override any built-in pi shortcut (verified against `docs/keybindings.md`).

[1.1.2]: https://github.com/aprimediet/pi-permission-modes/compare/v1.1.1...v1.1.2

## [1.1.1] - 2026-06-28

### Added
- **Per-mode model profiles**: Named profiles in `~/.pi/agent/model-profiles.json` mapping each mode (`ask` / `plan` / `auto`) to a model ID (`"provider/model"` or `"provider/model:thinking"`). When the mode changes, the extension auto-switches the model via `pi.setModel()`.
- **`/model-profile` command**: Selector (no args), direct set (`/model-profile <name>`), and list (`/model-profile list`) subcommands.
- **`--model-profile <name>` flag**: Activates a named profile on session start.
- **Thinking-level suffix**: A `":thinking"` suffix in a profile value (e.g. `"anthropic/claude-sonnet-4-5:high"`) sets the thinking level after the model switch.
- **Footer augmentation**: When a profile is active, the footer shows `profile:<name> · model/thinking` instead of plain `model/thinking`.
- **Auto-creation on missing config**: `ensureModelProfilesConfig()` is called on every `session_start` / `/reload`; if the config file is missing it's created (with the user's default model detected from `~/.pi/agent/settings.json` when available). Permissions are `0600` (user read/write only).
- **`profiles.ts`** — new pure-helper module: `loadModelProfiles`, `resolveModelForMode`, `getActiveProfileName`, `listProfiles`, `profileExists`, `parseModelId`, `ensureModelProfilesConfig`, plus mutable `setModelsPath()` for test isolation.
- **`profiles.test.ts`** — 31 new unit tests covering `parseModelId`, `resolveModelForMode`, `getActiveProfileName`, `listProfiles`, `profileExists`, `loadModelProfiles` (with tmpfile fixture), and `ensureModelProfilesConfig`.
- **Integration tests** — 9 new tests in `index.test.ts` covering: model switch on mode change, model switch on session start with `--model-profile` flag, missing-registry warning, no-API-key warning, persistence of `activeProfile`, session restore, `/model-profile list` output, `/model-profile <unknown>` notification, `/model-profile` selector.

### Changed
- **`index.ts`**: `setMode()` is now `async` and calls `applyProfileModelForMode()` after the mode change. `persistState()` now also persists `activeProfile`. `onSessionStart()` calls `ensureModelProfilesConfig()` at the top, validates `--model-profile`, restores `activeProfile` from the persisted entry, and re-applies the model at the end. `installFooter()` prepends `profile:<name> · ` to the right-side model string when a profile is active.
- **`package.json`**: Version bumped to `1.1.1`; description updated to mention per-mode model profiles.
- **`README.md`**: Added Model profiles section with example config; updated commands table with `/model-profile` and `--model-profile`; updated footer description.
- **`docs/PRD.md`**: Added per-mode model profiles as a feature; removed "Switching the AI model per mode" from non-goals (now replaced by an explicit opt-in clause); bumped version to 2.1.
- **`docs/suggestions.md`**: Added reference to `v1.1.1-suggestions.md`.
- **`AGENTS.md`**: Added `/model-profile` commands and `--model-profile` flag; updated `currentFocus` to v1.1.1; updated boundaries to clarify model-switching is opt-in via user-defined profile.

### Notes
- The model profile config file is named `model-profiles.json` (NOT `models.json`) to avoid conflict with pi's built-in `~/.pi/agent/models.json` (which is used for custom provider definitions).
- Total tests: **105 passing** (42 utils + 31 profiles + 32 index integration).

## [1.1.0] - 2026-06-28

### Added
- **3-mode redesign**: Replaced the old 4-mode system (default/plan/accept-edits/auto) with ask/plan/auto. `accept-edits` removed; `default` renamed to `ask` (backwards-compatible via `/default` alias).
- **Outside-cwd read guarding**: In ask mode, reads outside the project root now prompt for approval (matching Claude Code behavior).
- **Project-root detection**: New `findProjectRoot()` / `isInsideProject()` helpers to detect project boundaries (`.git`, `package.json`, etc.), used to relax outside-cwd prompting in auto mode when inside the project.
- **Test suite**: Initial test infrastructure with vitest — 9 utils test groups + 15 integration tests covering modes, shortcuts, commands, and edge cases.
- **Prompt documentation**: Mode-specific prompt context extracted to `docs/prompts/` (ask-mode-prompts.md, plan-mode-prompts.md, auto-mode-prompts.md).
- **Suggestions**: `docs/suggestions.md` capturing v1.2/v2.0 feature ideas.
- **Package metadata**: Added `license`, `repository`, `bugs`, `homepage`, `publishConfig` (public access), and `devDependencies` (vitest).
- **Scripts**: Added `test`, `test:watch`, `prepublishOnly`, `pack:dry` npm scripts.
- **LICENSE file**: Added MIT license.

### Changed
- **README.md**: Updated mode table, command reference, and cycle order for the new 3-mode system.
- **utils.ts**: Refactored bash allowlist and Plan: extraction helpers. Added `[DONE:n]` tracking support.
- **index.ts**: Major refactor — switched from 4-mode to 3-mode cycle, updated footer/prompt context injection, added outside-cwd guard logic.
- **"files" field**: Broadened from explicit file list to `*.ts` glob so new source files are included automatically.

### Removed
- **accept-edits mode**: Removed entirely. Equivalent behavior now provided by auto mode.
- **Inline prompt text**: Prompt content moved to separate files under `docs/prompts/` (external references).
- **Default mode**: Renamed to `ask` (with backward-compatible alias).

### Notes
- Auto-mode follow-up (auto-continue after each turn) is implemented but currently commented out — will be re-enabled when pi's auto-continue support stabilizes.

[1.1.1]: https://github.com/aprimediet/pi-permission-modes/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/aprimediet/pi-permission-modes/compare/v1.0.0...v1.1.0
