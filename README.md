# @georgedong32/permission-modes

[![npm version](https://img.shields.io/npm/v/@georgedong32/permission-modes)](https://www.npmjs.com/package/@georgedong32/permission-modes)
[![License](https://img.shields.io/npm/l/@georgedong32/permission-modes)](LICENSE)

Claude-Code-style **permission modes** for the [pi coding agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent). Four modes, cycled with **Shift+Tab**, that control how tool calls get approved. v2.0.0 adds **bypass**, a built-in **auto classifier**, **plan.md** file driver, and system-prompt anchor injection.

## Modes

| Mode | edit / write | reads outside cwd | bash | notes |
|---|---|---|---|---|
| **ask** `●` | prompt (`Allow` / `Allow all → bypass` / `Block`) | prompt | mutating commands prompt | one-line reminder on mode switch |
| **plan** `⏸` | only `plan.md` | allowed | read-only allowlist | plan file at `.pi/projects/<id>/plan.md` |
| **auto** `▶` | cwd writes auto; risky ops → classifier/blacklist | auto | tiered | optional classifier in `permission-modes.json` |
| **bypass** `⚡` | all auto-approved (tracked outside cwd) | auto | auto | security reminder on switch + compact |

**Cycle (Shift+Tab):** ask → plan → auto → bypass → ask.

When there is no interactive UI (`pi -p`, `--mode json`), anything that would prompt is **blocked** instead of silently allowed — unless the process is a **pi-subagents child** with `PI_SUBAGENT_PARENT_SESSION` set; then the ask is forwarded to the parent session UI (see below).

### Subagent permission forwarding

Headless subagent children cannot show `ctx.ui.select`. With **pi-subagents**, the root interactive session exports `PI_SUBAGENT_PARENT_SESSION`, and children inherit it (spawn also passes the direct parent session id).

When permission-modes would prompt and `!ctx.hasUI`:

1. If `PI_SUBAGENT_PARENT_SESSION` is unset → **fail-closed block** (same as before).
2. If set → write a request under  
   `~/.pi/agent/sessions/permission-modes-forwarding/sessions/<parentSessionId>/requests/`  
   and poll for a response (250ms interval, 10 minute timeout).
3. The parent session (has UI, not `PI_SUBAGENT_CHILD=1`) runs a poller that shows  
   Allow / Allow always (this project) / Allow always (global) / Block.  
   **Allow always** rules are written using the request’s **child `cwd`**, not the parent cwd.  
   (The forwarded dialog offers file-scope rules only; **Allow always (this folder)** appears in the
   interactive dialogs, not here.)
4. Timeout, cancel, or Block → child gets a block reason (never silently allowed).

**Limits:** nested subagents whose direct parent has no UI still time out and deny (this package does not rewrite the target to the root session). This inbox path is **not** shared with `@gotgenes/pi-permission-system` (`permission-forwarding/`); the two can coexist without double-handling.

### Subagent inherits parent mode

The interactive session writes `PERMISSION_MODES_INHERITED_MODE` (`ask` | `plan` | `auto` | `bypass`) into the process environment whenever the mode changes (and again on each `before_agent_start`). pi-subagents merges `process.env` into child spawns (and passes `--permission-mode` when that env is set), so headless children start in the **same mode** as the parent (e.g. parent bypass → child auto-approves; no approval popups).

### Auto-mode gate (v3, default engine)

Auto mode routes every tool call through a three-layer gate (spec: [docs/CLASSIFIER-SPEC.md](docs/CLASSIFIER-SPEC.md)):

1. **Deterministic policy** (`risk-policy.ts`) — a real shell parser plus per-verb risk
   tables decide most calls in code: reads, project writes, builds/tests, local git → **allow**;
   recursive deletes, sudo, system packages, pushes, listeners, uploads, cluster/db mutations
   → **ask** (entity-scoped); wiping protected paths, disk/device writes, reboot, firewall
   teardown, credential exfiltration, `DROP DATABASE`… → **never** (not pre-authorisable, loud
   prompt or denial). On the recorded real-session corpus ~75 % of calls resolve here with zero
   model involvement.

   The parser is tree-sitter-bash (through `web-tree-sitter`, the package's one runtime
   dependency) walked under a written specification
   ([docs/LAYER0-WALKER-SPEC.md](docs/LAYER0-WALKER-SPEC.md)): it produces an argument list only
   when every word is provably literal and refuses to classify anything else (the call comes back
   `unknown` with a named reason, never a guess; malformed input is sent back to be fixed). The
   earlier hand-written lexer survives only as an escalation-only second opinion when the walker
   refuses: it can still force a prompt, it can no longer authorise anything. The released 2.7.0
   build still runs the lexer alone — see AGENTS.md → *Branches and the live path*.
2. **Authorisation** for *ask* — permission rules, then prompt-once **session grants**
   (`{category, entity}`; approving `docker rmi api:dev` never covers `payments:prod`), then
   the **authorisation ledger** — a compact whole-session memory of what the user granted
   or withdrew, folded from a per-message extraction call (cached per message, so each
   message is read once ever). A grant given at message 1 still authorises at message 300;
   an explicit revocation blocks even if an old grant is still inside the recent window;
   pre-existing sessions are backfilled in the background, newest-first (safe while
   incomplete). Then **transcript authorisation** over the recent window as fallback: a
   small model extracts what the user allowed/forbade (`response_format: json_schema`,
   temp 0, ≤300 tokens) and code verifies it — verbatim quote, whole-token entity match
   (`db-backup` ≠ `db-backup-test`), forbidden-target veto, revocation.
   The model can only narrow a decision, never widen it. `/grants` shows (or clears) the
   session grants and the ledger; both are snapshotted into the session and survive
   stop/resume.
3. **Effect classification** for commands the tables cannot read (inline `python -c`,
   unknown binaries): same schema-constrained call, mapped back onto the tiers.

If the user says **"don't change anything" / "read-only"**, the gate enters a read-only
posture: ask/unknown *mutations* are refused (with an honest reason) while reads and the
agent's own project-folder / `/tmp` writes still proceed. It is a **default, not a veto**:
rules, session grants, and anything the user explicitly authorised are checked first, and
the posture only refuses what nothing has authorised — so a later "now write to /x/" works
even while it is active, and "you can make changes now" lifts it outright. Granting a
*folder* ("you can work in `~/dev/app`", "edits under `src/`") covers the files inside it
instead of approving one file at a time. `/grants` shows the posture and every recorded
grant with a copyable value; `/grants revoke <value>` drops one.

If a bash command is **malformed** (unterminated quote / heredoc / `$( )`), the parser
reports it instead of emitting garbage segments: the gate refuses to run it and returns
a *fix-and-simplify-and-retry* message to the agent (no user prompt, no model call) so it
rewrites the command; a small budget escalates to a prompt (attended) or a parked step
(unattended) if it keeps failing.

A parse failure is structurally impossible (`json_schema`), any transport failure falls
closed to a prompt, and verdicts are reproducible across server restarts (measured 0 flips).
Works well with a self-hosted **Qwen3.5-4B** (~2 GB VRAM, ~370 ms p50/call — see
`docs/GATE-RESULTS.md`); quality ceiling reached from 9B upward.

```json
{
  "classifier": {
    "enabled": true,
    "model": "litellm/qwen3.8-27b",
    "baseUrl": "http://127.0.0.1:8014/v1",
    "modelId": "clf-qwen35-4b",
    "timeoutMs": 15000,
    "engine": "gate"
  }
}
```

- `engine`: `"gate"` (default) or `"legacy"` (the single-shot "ask one model the whole question" classifier below).
  **Prefer `gate`.** It asks for the verdict as a forced tool call, which works on every transport and model tested
  (D24). `legacy` reads the verdict out of the model's *text*, so a model that reasons without declaring it — a LiteLLM
  alias, say, where pi has no `reasoning` flag to read — used to spend the token cap on thinking and never reach a
  verdict. It no longer has to: the text stages now send the thinking-off knob for **any** OpenAI-compatible endpoint,
  declared as reasoning or not, because that was measured rather than assumed — on such an alias, no knob gives
  **5.1 s of reasoning and no answer at all**, the knob gives **a verdict in 758 ms** (D28). What stays true is the
  failure mode: a server that accepts the field and ignores it answers with prose, and the stage then fails loudly and
  attributed (`classifier — unavailable: …`) rather than silently. If you choose `legacy`, pick a model that answers
  promptly when told not to think.
- `baseUrl`/`modelId`: direct OpenAI-compatible endpoint (needs `response_format: json_schema`
  support — llama.cpp, vLLM, litellm). Without them the endpoint is resolved from `model`
  via pi's model registry.
- **GitHub Copilot as the classifier** (leave `baseUrl` unset): `"model": "github-copilot/auto"` lets GitHub pick the
  model — the plugin mints its own Auto session, which is the mode a free plan supports. `"model":
  "github-copilot/<id>"` names one explicitly (paid plans). Copilot serves three request dialects and this classifier
  encodes the two OpenAI ones, so an `anthropic-messages` model resolves to no endpoint and the gate asks a person
  rather than guessing. `classifier.copilot` tunes the transport: `maxOutputTokens` (default 512 — a reasoning model
  spends the reserve on thinking, and too small means no answer arrives at all), `reasoningEffort` (default `"low"`),
  `budgetTokens` (0 = no cap; once spent the classifier stops sending and says so instead of burning quota),
  `sessionEnabled` (default true). Any Copilot failure reads as **classifier unavailable** with the cause named — never
  as a refusal, and never as "no endpoint configured" when one is. Wire-level measurements and the re-measurement tool
  live in the repository (`docs/COPILOT-COMPAT-MEASUREMENTS.md`, `bun tools/copilot-probe.ts`), not inside the
  installed package.
- `ledger`: `false` disables the authorisation ledger (whole-session grant memory);
  `ledgerBackfillLimit` caps how many of the newest user messages are ever extracted
  (default 400).
- Top-level `"injectionWarning": false` (next to `classifier`) disables the tool-output
  prompt-injection note injected in auto/bypass modes (both the standing reminder and the
  heuristic-triggered strong warning). Default on; the note tells the model to stay
  silent unless it actually suspects an injection.
- With the classifier disabled or unreachable the gate still runs: *allow*-tier proceeds,
  everything else prompts (UI) or is denied with the reason (headless). Fail-closed, never open.

### Legacy auto classifier (`engine: "legacy"`)

Configure `~/.pi/agent/permission-modes.json`:

```json
{
  "classifier": {
    "enabled": false,
    "engine": "legacy",
    "model": "anthropic/claude-haiku-4-5",
    "timeoutMs": 8000
  }
}
```

Uses `completeSimple` from `@earendil-works/pi-ai/compat` with credentials from pi's `modelRegistry` — all built-in provider APIs (Anthropic, OpenAI, Azure, etc.) are supported automatically.

### Permission rules (v2.1.0, CC-compatible)

Configure **allow / deny / ask** rules in Claude Code syntax (`Tool` or `Tool(specifier)`). Rules merge across scopes; evaluation order is **deny → ask → allow** (deny cannot be overridden).

| Scope | Path |
|---|---|
| Global | `~/.pi/agent/permission-modes.json` → `permissions` block |
| Project (shareable) | `<cwd>/.pi/projects/<id>/permissions.json` |
| Project local | `<cwd>/.pi/projects/<id>/permissions.local.json` (personal; add to `.gitignore`) |

Example global config:

```json
{
  "classifier": { "enabled": false },
  "permissions": {
    "allow": ["Bash(npm run test *)", "Read(~/.zshrc)"],
    "deny": ["Bash(curl *)", "Read(./.env)", "Read(./.git/**)"],
    "ask": ["Bash(npm install *)"]
  }
}
```

When a tool call would prompt, you can choose **Allow always (this project)** or **Allow always (global)** to persist an allow rule. Use `/permissions` to list the merged rule set.

**Allow always (this folder).** Where the target is a file and a subtree rule would actually match it,
the dialog also offers the containing folder — `Edit(./deploy/systemd/**)` instead of one rule per
file, so the next file in that folder needs no second approval. It is offered only where it works: a
`**` rule can never reach a secret-classified path (reaching a credential means naming it exactly), so
on those paths the option is absent rather than stored dead.

**Forcing a prompt back on.** An `ask` rule is evaluated *before* the mode gate, so it overrides what
layer 0 concludes. If you want a location that policy treats as ordinary project source to prompt
anyway — a directory of staged deploy config, say — add it to the project's rule set:

```json
{ "permissions": { "ask": ["Edit(./deploy/**)", "Write(./deploy/**)"] } }
```

This is also the way to restore strictness per project, with no separate setting to keep in sync.

## Model profiles (v1.1.1)

Define named profiles in `~/.pi/agent/model-profiles.json` mapping each mode to a **model + effort** pair. Each mode entry can be a bare model string, or a `ModeConfig` object:

```json
{
  "active": "default",
  "default": {
    "ask":  { "model": "anthropic/claude-opus-4-5", "effort": "high" },
    "plan": { "model": "anthropic/claude-opus-4-5", "effort": "xhigh" },
    "auto": { "model": "anthropic/claude-haiku-4-5", "effort": "low" },
    "bypass": { "model": "anthropic/claude-haiku-4-5", "effort": "medium" }
  },
  "fast": {
    "ask":  "anthropic/claude-haiku-4-5:low",
    "plan": "anthropic/claude-haiku-4-5:low",
    "auto": "anthropic/claude-haiku-4-5:off"
  }
}
```

- **Model ID**: `"provider/model"`, or `"provider/model:effort"` (the `:effort` suffix sets thinking after the switch).
- **`ModeConfig.effort`**: explicit field (`off` | `minimal` | `low` | `medium` | `high` | `xhigh`). Wins over a `:suffix` on the same entry. If neither is set, defaults to **`medium`**.
- When the mode changes, the extension calls `pi.setModel()` then `pi.setThinkingLevel()`. Unknown levels are skipped with a notify warning.
- The footer shows `profile:<name> · model/thinking` when a profile is active.

If the file doesn't exist on first install, the extension creates it for you (pre-filled with the user's default model from `~/.pi/agent/settings.json` when available).

**Why a separate `model-profiles.json` and not pi's built-in `models.json`?** Pi uses `~/.pi/agent/models.json` for custom provider definitions; using a different filename avoids format conflict.

## Commands, shortcut, flag

| Kind | Name | Behavior |
|---|---|---|
| Command | `/ask`, `/plan`, `/auto` | switch to that mode (`/default` also works as alias) |
| Command | `/mode [name]` | set the given mode, or pick from a list |
| Command | `/auto-depth <n>` | cap auto-mode follow-ups (`0` = unlimited; default 20) |
| Command | `/model-profile` | show selector of available profiles |
| Command | `/model-profile <name>` | activate the named profile (also `/model-profile list` to print them) |
| Shortcut | `Shift+Tab` | cycle modes |
| Shortcut | `Alt+T` | cycle thinking level (off → minimal → low → medium → high → xhigh) |
| Shortcut | `Alt+I` | cycle model profile (next profile from `~/.pi/agent/model-profiles.json`; re-applies the model for the current mode) |
| Command | `/permissions` | list merged allow/deny/ask rules |
| Command | `/grants [clear\|revoke <value>]` | show (clear / revoke) auto-mode session grants + authorisation ledger; the listing prints copyable values, and `revoke` matches the value — not a list index — because the list re-orders as grants are promoted |
| Command | `/unattended [on\|off]` | overnight mode: approval prompts soft-deny with the reason so the agent adapts or parks the step; never-tier stays hard-blocked; repeats escalate to "stop trying" (no arg = toggle; persisted with mode state) |
| Command | `/outside-writes` | list tracked outside-cwd writes (read-only) |
| Command | `/undo-outside-writes` | restore outside-cwd writes (selector, `all`, or `--list`) |
| Flag | `--permission-mode <name>` | start in a mode (accepts `ask`, `plan`, `auto`, or `default` as alias; default `ask`) |
| Flag | `--model-profile <name>` | start with a named profile activated |

> The start-mode flag is `--permission-mode` (not `--mode`) because pi already has a built-in `--mode` for output format (text/json/rpc).

### Outside-cwd write tracking (v1.1.3)

In **auto mode**, `edit` and `write` calls to paths outside the working directory are auto-approved — but each one is snapshotted to `<cwd>/.pi/projects/<project-id>/tmp/outside-writes/`. Use `/undo-outside-writes` to roll back:

- `/undo-outside-writes` — interactive selector (newest first)
- `/undo-outside-writes all` — restore all without prompting
- `/undo-outside-writes --list` — list only (alias for `/outside-writes`)
- `/outside-writes` — same as `--list`

Snapshots capture the file's pre-write content (or `null` if the file didn't exist). They persist across sessions until you undo them. The snapshot cap is 100 entries (oldest are evicted; you get a notification).

### Per-mode skill filtering (v1.1.4, fixed in v1.1.5)

When you're in **plan mode**, skills like `systematic-debugging` and `executing-plans` are irrelevant noise. Skill filtering lets you configure which skills get injected into the system prompt per mode — saving tokens and keeping the agent focused.

```json
{
  "active": "default",
  "default": {
    "ask": "anthropic/claude-sonnet-4-5",
    "plan": {
      "model": "anthropic/claude-sonnet-4-5",
      "skills": ["brainstorming", "writing-plans"]
    },
    "auto": "openai/gpt-4o"
  }
}
```

- `"skills": ["brainstorming", "writing-plans"]` — only these two skills appear in the system prompt when in plan mode.
- `"skills": ["*"]` or omitting `skills` entirely — allow all skills (default, no filtering).
- String shorthand (`"anthropic/claude-sonnet-4-5"`) still works — backward compatible.
- Skills can still be invoked manually via `/skill:name` if needed — filtering only controls which skills are pre-loaded into the agent's context.

**Resolution order:** Active profile → default profile → hardcoded defaults (`["*"]`). The `read` tool is always mandatory in tool filters (full tool filtering is planned for a future release).

### Plan mode flow

In plan mode the agent explores read-only and emits a numbered list under a `Plan:` header. On completion you choose:

- **Execute the plan** — switches to auto, restores edit/write, runs the steps; a `☐/☑` widget advances as the agent emits `[DONE:n]` tags, and you get **Plan Complete! ✓** at the end.
- **Stay in plan mode** — keep iterating.
- **Refine the plan** — opens an editor; your notes are sent back as a follow-up.

## UI

- A custom **adaptive footer** (v1.1.6): wide terminals show **cwd [git-branch] · context usage · profile/model** on line 1 and **mode** on line 2; narrow terminals reflow to two compact lines with truncation.
- **Context usage** in the footer shows `tokens/contextWindow percent` (e.g. `42k/200k 21.0%`; large counts use `M`).
- While the agent is streaming, the working indicator shows live **token / tok-s / cost / % context** stats; it reverts to the default loader when idle.
- Mode colors: ask = muted, plan = accent, auto = warning. The colored status pill was removed in v1.1.6 — mode is shown in the footer only.

Current mode, the auto-follow-up depth, and the active profile name **persist** across `/reload` and session resume.

## Install / run

```bash
# Install as a package (scoped npm name; or from a git remote / local path)
pi install npm:@georgedong32/permission-modes
pi list                                            # verify it loaded

# Or run it directly for a quick try (no install)
pi -e ./extensions/permission-modes/index.ts

# During development, hot-reload after edits
/reload
```

Auto-discovery also works: drop this folder at `~/.pi/agent/extensions/permission-modes/` (global) or `.pi/extensions/permission-modes/` (project) and pi loads `index.ts` automatically.

## Testing

```bash
npm test                # run all 189 tests (vitest)
npm run test:watch      # watch mode for development
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## Layout

```
permission-modes/             # @georgedong32/permission-modes
├── package.json              # pi manifest + npm package metadata
├── index.ts                  # main extension (default-exported factory)
├── profiles.ts               # NEW in v1.1.1: model-profile config helpers
├── profiles.test.ts          # NEW in v1.1.1: unit tests for profiles
├── utils.ts                  # bash allowlist + Plan: + [DONE:n] helpers
├── index.test.ts             # integration tests (vitest)
├── utils.test.ts             # unit tests (vitest)
├── vitest.config.ts          # vitest config
├── CHANGELOG.md              # release history
├── LICENSE                   # MIT
├── .gitignore                # excludes node_modules, lockfile, .pi/
└── docs/
    ├── PRD.md                # product requirements
    └── prompts/              # mode-specific prompt context
        ├── ask-mode-prompts.md
        ├── plan-mode-prompts.md
        └── auto-mode-prompts.md
```

Third-party deps: none. Peer dependencies (bundled by pi): `@earendil-works/pi-coding-agent`, `@earendil-works/pi-ai`, `@earendil-works/pi-tui`, `typebox`. The model is switched **only when the user opts in via `~/.pi/agent/model-profiles.json`** — without a profile config file, the model never changes and the extension behaves exactly as in v1.1.0.

## Repo tooling (dev checkout, not shipped)

`tools/cite-check.ts` and `tools/nul-scan.ts` are two controls that exist because prose and artifacts drift apart: the first fails when shipped text cites a decision record — the package ships no `docs/`, so such a pointer leads an installer nowhere — and when the packed artifact contains a `docs/` path at all (`bun tools/cite-check.ts --pack .`), the second fails when a text file grows a NUL byte, which makes every review tool treat it as binary. Both are pinned by `tools/tools.test.ts`, including their red cases. Usage and the promises each one keeps: `docs/TOOLS.md` in a dev checkout — it is deliberately not in the package, so an installed user has no tooling to document.
