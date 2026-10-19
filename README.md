# @lukolszewski/adaptive-acl

Permission modes for the [pi coding agent](https://github.com/earendil-works/pi). Four modes — **ask · plan · auto · bypass** — cycled with **Shift+Tab**, decide how every tool call gets approved. Auto mode answers most calls in code: a licensed bash grammar plus per-verb risk tables return *allow / ask / never* before any model is asked, and a model is consulted only for the call the tables cannot read (`bash-walker.ts`, `risk-policy.ts`, `bash-tiers.ts`). Approvals and undo snapshots are stored per project (`<cwd>/.pi/projects/<id>/`, `permissions-loader.ts:48`); the model a mode switches to comes from one global profile file.

A fork of upstream `pi-permission-modes` 2.7.0 — see [Origin and licence](#origin-and-licence). Installed from GitHub, not from npm.

## Install

```bash
pi install git:github.com/lukolszewski/adaptive-acl
pi list                                       # verify it loaded
```

Everything else is a modifier on that one line, and the forms are pi's own — see *Pi Packages* in pi's `README.md` and `docs/packages.md` in pi's `docs/`:

| Want | Change |
|---|---|
| A pinned tag or commit | append `@v2.8.0` to the source. A pinned ref is skipped by `pi update --extensions`; re-run with the new ref to move an existing install. |
| This project only (`.pi/git/`) | add `-l` before the source |
| Try it for one run, no install | `pi -e <source>` instead of `pi install` |
| SSH, `git@`, or HTTPS spellings | `git:git@github.com:<user>/<repo>`, `ssh://git@github.com:<user>/<repo>`, `https://github.com/<user>/<repo>` |
| Remove it | `pi remove <source>` |

Installs land in pi's own clone directory, `~/.pi/agent/git/` (`.pi/git/` with `-l`).

The one runtime dependency is `web-tree-sitter`; the grammar itself is not a dependency — it ships as `wasm/tree-sitter-bash.wasm` beside its MIT notice so no native build runs during install (`bash-parser.ts`). Pi installs git packages with `npm install --omit=dev`, which is why the dependency has to be (and is) under `dependencies`. If the grammar cannot be loaded the parser stays uninitialised, every command comes back refused with a named reason, and the gate asks a person instead of guessing (`bash-parser.ts`).

Working on it from a checkout:

```bash
pi -e ./index.ts          # load without installing
/reload                   # pi's own reload command, after an edit
npm test                  # vitest
```

pi's auto-discovery works too — its `docs/extensions.md` lists `~/.pi/agent/extensions/*/index.ts` (global) and `.pi/extensions/*/index.ts` (project-local) — so put the checkout at `~/.pi/agent/extensions/adaptive-acl/` or `.pi/extensions/adaptive-acl/` and pi loads `index.ts` from that subdirectory; run `npm install` inside it first, because the gate needs `web-tree-sitter`. Project-local locations load only once the project is trusted.

## Modes

| Mode | edit / write | read outside cwd | bash |
|---|---|---|---|
| **ask** `●` | prompt: Allow / Allow always (this project, global) / Allow all (enable bypass) / Block (`index.ts:3254`) | prompt, unless a rule or a prior grant covers it; a plain Allow remembers that exact file, never its directory, and a secret-classified path only ever accepts a grant naming that exact path (`index.ts:3214`, `index.ts:3234`) | read-only commands run free, anything else prompts |
| **plan** `⏸` | only the plan file at `.pi/projects/<id>/plan.md` | allowed | read-only commands only |
| **auto** `▶` | decided by the gate below | decided by the gate | decided by the gate |
| **bypass** `⚡` | everything, with outside-cwd writes snapshotted for undo | auto | auto |

Cycle (Shift+Tab): ask → plan → auto → bypass → ask — the order is `MODE_CYCLE` (`index.ts:238`), and the same four names are registered as commands by the loop at `index.ts:1751`. `--permission-mode <name>` picks the starting mode (`default` is accepted as `ask`, `index.ts:3000`).

Permission rules — **deny → ask → allow** — are evaluated before the mode gate for every mode except bypass, so a `deny` rule cannot be argued past and an `ask` rule can force a prompt back onto something layer 0 would allow (`index.ts:3040`, `index.ts:3049`, `permissions.ts`).

Entering auto mode removes broad bash allow rules (`Bash`, `Bash(*)`, `git:*`, `python *`, …) from the merged set for as long as the mode lasts, because such a rule short-circuits the gate before anything reasons about the command; a rule that pins a subcommand (`npm run test`, `git status`) stays in force (`dangerous-permissions.ts`).

When there is no interactive UI — pi's own `-p`/`--print` and `--mode json` — anything that would prompt is **blocked** with the reason, never silently allowed (`index.ts:602`). The one exception is `plan_ready`: with no UI it reports the plan and lets the run go on executing it (`index.ts:2584`).

### Headless and subagent sessions

- **Spawned children** (`PI_SUBAGENT_CHILD=1`): the interactive session exports `PERMISSION_MODES_INHERITED_MODE` on every mode change, so a child starts in the parent's mode (`mode-inherit.ts`). If a child would prompt and `PI_SUBAGENT_PARENT_SESSION` is set, the ask is written to a filesystem inbox under `~/.pi/agent/sessions/permission-modes-forwarding/sessions/<parentSessionId>/requests/` and polled (250 ms, 10 min timeout); the parent shows Allow / Allow always (this project) / Allow always (global) / Block — file-scope rules only, folder scope appears in the interactive dialogs and not here — and **Allow always** is written against the child's `cwd`, not the parent's. Every request carries a `challenge` kept in the child's memory and echoed back on the response, so a response that never read the matching request cannot approve. Timeout, cancel or Block → the child gets a block reason (`permission-forwarding.ts`).
- **In-process sessions** (a scheduler's `model:` job, no child process, no UI) read the parent's *whole* effective state live at child start — mode, session grants, the folded ledger including forbids and the read-only posture — so a parent that tightens tightens every later run, and nothing is persisted into a job file (`headless-bridge.ts`).
- **`/unattended [on|off]`** is the overnight switch: approval prompts soft-deny with the reason so the agent adapts or parks the step, `never`-tier stays hard-blocked, repeated denials of the same thing escalate to "stop trying". Persisted with the mode state.

## Auto-mode gate

Every auto-mode call goes through three layers. The design of each is written down in the repository: [docs/CLASSIFIER-SPEC.md](docs/CLASSIFIER-SPEC.md) and [docs/LAYER0-WALKER-SPEC.md](docs/LAYER0-WALKER-SPEC.md), and the walker's acceptance data is the `bash-walker.golden.jsonl` pinned by a test.

1. **Layer 0 — deterministic policy** (`risk-policy.ts`, `bash-tiers.ts`). `evaluateToolCall()` classifies file tools by path (`risk-paths.ts` separates project / outside / secret / device); `evaluateBash()` (`risk-policy.ts:484`) parses `bash` with tree-sitter-bash through `web-tree-sitter`, walked under a written spec: the walker returns an argument list only when every word is provably literal and otherwise returns `unknown` with a named reason (`bash-walker.ts`, `bash-walker-values.ts`). Reads, project writes, builds/tests and local git come back **allow**; recursive deletes, sudo, system packages, pushes, listeners, uploads, cluster/db mutations come back **ask** with an entity; wiping protected paths, device writes, reboot, firewall teardown, credential exfiltration, `DROP DATABASE` come back **never**, which the gate returns as `prompt-never` without ever consulting a grant: it needs a person, and the always-options are withheld on that verdict, so nothing you click makes it pre-authorisable (`gate.ts:43`, `gate.ts:240`, `index.ts:1126`). What *can* still reach a `never` call is a rule you wrote yourself — rules are evaluated before the gate and an `allow` short-circuits it (`index.ts:3049`) — which is why the broad bash rules are pulled out of auto mode (next section). Per-verb risk tables live in `risk-handlers.ts`, path classification in `risk-paths.ts`, and the whole walker is pinned by `bash-walker.golden.jsonl`.
2. **Authorisation for `ask`** — prompt-once **session grants** keyed `{category, entity}` (approving `docker rmi api:dev` never covers `payments:prod`, `session-grants.ts`), then the **authorisation ledger**: a whole-session memory of what the user granted or withdrew, folded from one verified extraction per user message, newest-first backfill that is safe while incomplete, explicit revocations that a re-extraction cannot walk back in (`gate.ts:246`, `gate.ts:261`, `auth-ledger.ts`, `ledger-render.ts`). As a last fallback, a small model extracts what the user allowed or forbade from the recent window — one `json_schema` request at `temperature: 0`, which is omitted for Copilot because that endpoint rejects the parameter (`model-client.ts:205`) — and code verifies it: verbatim quote, whole-token entity match (`db-backup` ≠ `db-backup-test`), forbidden-target veto, revocation (`model-client.ts`, `grant-verify.ts`). A model can narrow a decision, never widen it.
3. **Effect classification** for what the tables cannot read — inline `python -c`, an unknown binary — asked as one schema-constrained question and mapped back onto the tiers.

If the user says *"don't change anything"* / *"read-only"*, the gate enters a read-only posture: `ask`/`unknown` *mutations* are refused with a reason while reads, project writes and `/tmp` writes proceed. It is a default, not a veto — rules, grants and anything the user explicitly authorised are checked first, so "now write to `dist/`" still works while it is active and "you can make changes now" lifts it. A grant over a *folder* covers the files inside it instead of one approval per file (`auth-ledger.ts`, `grant-verify.ts`).

A malformed command (unterminated quote, heredoc, `$( )`) is reported rather than chopped into garbage segments: the gate refuses it and returns a *rewrite it and retry* message to the agent — no prompt, no model call — with a small budget that escalates to a prompt, or to a parked step when unattended (`risk-policy.ts:639`, `bash-ast.ts`, `index.ts:1032`).

Any classifier failure falls closed to a prompt (`gate.ts:201`) and is named for what happened — `classifier unavailable (<cause>) — it could not be asked, so there is no verdict to act on` — never as a refusal and never as a verdict (`classifier-messages.ts:67`). `/classifier-status` prints this session's counters (eligible / called / ok / failed / no-endpoint); `/classifier-status reset` clears them.

What an *ask* prompt offers: **Allow** once, **Allow for session: \<entity\>** for exactly the entities the gate named (or a scope, when the gate named one), **Allow always (this folder / this project / global)** where a rule can express the approval without widening it, and **Block**. On a `never` verdict the always-options are absent — nothing you click there makes it pre-authorisable (`index.ts:1125`).

### Classifier configuration

`~/.pi/agent/permission-modes.json` — every field and default below is `resolveClassifierConfig()` and `resolveCopilotConfig()` in `config.ts`:

```json
{
  "classifier": {
    "enabled": true,
    "engine": "gate",
    "model": "anthropic/claude-haiku-4-5",
    "timeoutMs": 15000,
    "stage": "tool",
    "failClosed": true,
    "includeAgentsMd": true,
    "jsonlTranscript": false,
    "ledger": true,
    "ledgerBackfillLimit": 400,
    "contextTokens": 4096
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | With it off the gate still runs layer 0: allow-tier proceeds, everything else prompts (UI) or is denied with the reason (headless). |
| `engine` | `"gate"` | `"gate"` = the three layers above. `"legacy"` = the single-shot "ask one model the whole question" classifier. |
| `model` | `"anthropic/claude-haiku-4-5"` | `"<provider>/<id>"`, resolved through pi's model registry and its credentials. |
| `baseUrl` / `modelId` | unset | Direct OpenAI-compatible endpoint, bypassing the registry; needs `response_format: json_schema` support. `baseUrl` outranks the Copilot block. |
| `timeoutMs` | `15000` | Per call. |
| `stage` | `"tool"` | `tool` answers as a forced `classify_result` tool call (`classifier-tool.ts`); `single`, `fast`, `both`, `thinking` are the text stages (`classifier-client.ts`). A `provider/id@stage` suffix overrides it per call. |
| `failClosed` | `true` | On the legacy engine: a classifier error denies instead of falling back to the local heuristics (`index.ts:1226`). The gate engine does not read this key — a failure there always lands as a prompt. |
| `includeAgentsMd` | `true` | Put `AGENTS.md` / `CLAUDE.md` in the classifier context. |
| `jsonlTranscript` | `false` | One JSON object per transcript block instead of `User:` / `bash cmd` lines. |
| `ledger` / `ledgerBackfillLimit` | `true` / `400` | Turn the ledger off; cap how many of the newest user messages are ever extracted. |
| `contextTokens` | `4096` | The classifier model's window; every call is sized to fit it (`context-budget.ts`). |
| `copilot` | see below | Copilot-only transport knobs. |

**GitHub Copilot as the classifier** — leave `baseUrl` unset and name a Copilot model. `"model": "github-copilot/auto"` lets GitHub pick, which is the mode a free plan supports; the extension mints its own Auto session (`POST /models/session`) because the pick is only reachable with the returned `Copilot-Session-Token`, and never sends that header with a model you named yourself. One mint is good for ~60 minutes, is refreshed 5 minutes before `expires_at`, is shared by concurrent callers, and a failure cools down for 15 s instead of retrying per tool call. `"model": "github-copilot/<id>"` names one explicitly, and the mint also reports which models GitHub offered (`copilot-session.ts`).

```json
{
  "classifier": {
    "model": "github-copilot/auto",
    "copilot": {
      "maxOutputTokens": 512,
      "reasoningEffort": "low",
      "budgetTokens": 0,
      "sessionEnabled": true
    }
  }
}
```

Copilot serves three request dialects and this classifier encodes the two OpenAI ones (`gate-bridge.ts:276`). The endpoint resolver reads pi's catalog on every call, so a model whose dialect it cannot encode resolves to no endpoint and the gate asks a person rather than guessing; when GitHub's Auto pick is one of those, the mint is repeated exactly once asking for the offered ids this client can put on the wire (`gate-bridge.ts:390`, `copilot-session.ts:303`).

`maxOutputTokens` is the answer reserve — a reasoning model spends part of it thinking before one verdict character exists, so too small is *no answer*, reported as a transport failure (default 512). `reasoningEffort` is `low` | `medium` | `high`, sent only for a model the catalog says reasons. `budgetTokens` caps what this transport may spend per process; `0` means no cap, and a spent budget stops the asking and says so rather than spending your allowance. `sessionEnabled: false` makes `github-copilot/auto` resolve to no endpoint at all, which is how you leave every Copilot request for your own chat.

Self-hosted endpoint instead:

```json
{
  "classifier": {
    "engine": "gate",
    "baseUrl": "http://127.0.0.1:8014/v1",
    "modelId": "clf-qwen35-4b",
    "contextTokens": 4096
  }
}
```

Legacy engine — one model, one question, the verdict read out of its text:

```json
{ "classifier": { "enabled": true, "engine": "legacy", "model": "anthropic/claude-haiku-4-5", "timeoutMs": 8000 } }
```

## Permission rules

Claude-Code-style `Tool` / `Tool(specifier)` rules. Scopes merge; evaluation is **deny → ask → allow**, and a `deny` cannot be overridden (`permissions.ts`, `permission-rule-parser.ts`).

| Scope | Path |
|---|---|
| Global | `~/.pi/agent/permission-modes.json` → `permissions` block |
| Project (shareable) | `<cwd>/.pi/projects/<id>/permissions.json` |
| Project local | `<cwd>/.pi/projects/<id>/permissions.local.json` — the file an "Allow always (this project)" click writes; created for you, and pi only ever *tips* you to add it to `.gitignore`, it never edits that file (`permissions-loader.ts:199`, `permissions-loader.ts:212`, called at `index.ts:524`) |

```json
{
  "permissions": {
    "allow": ["Bash(npm run test *)", "Read(~/.zshrc)"],
    "deny": ["Bash(curl *)", "Read(./.env)", "Read(./.git/**)"],
    "ask": ["Bash(npm install *)", "Edit(./deploy/**)", "Write(./deploy/**)"]
  }
}
```

The `ask` list is the way to put a prompt back on something layer 0 considers ordinary project source: an `ask` rule is evaluated before the mode gate. `/permissions` prints the merged set grouped deny / ask / allow, every rule tagged with the scope it came from — `global`, `project`, `local` (`permissions.ts:426`).

**What "Allow always" stores.** Before you click, the prompt shows exactly what would be written, and withholds the offer when it cannot be honoured (runtime variables, shell control flow) rather than storing something wider than your approval (`index.ts:650`). *This project* and *this folder* both go to the project-local `permissions.local.json` — the notification says "project local" for that reason; *global* is the only click that writes the `permissions` block above (`index.ts:498`, `permissions-loader.ts:178-190`, `index.ts:531`). Folder scope (`Edit(./deploy/systemd/**)`) is offered only where a `**` rule would actually match — never on a secret-classified path, where it would be stored dead (`index.ts:680`, `permissions.ts`).

## Grants, ledger, `/grants`

What you *said* is remembered here: rows `{category, value, kind}` extracted from your own messages, verified before they count, exported per project so the next session starts knowing them. Default file: `<cwd>/.pi/projects/<id>/grants.json` — per project, so one project's authority cannot leak into another (`index.ts:1991`, `grants-file.ts`). A click on "Allow always" writes a rule file instead, not a row here, unless a config layer explicitly chose otherwise — see [`authority.persist`](#other-config-keys) (`index.ts:461`).

```
/grants                                  list, with copyable values
/grants revoke <value>                   take one back — by value, not by list index, which re-orders
/grants clear                            drop every session grant
/grants export [path] / import <path> [--replace] [--yes]
/grants auto on|off | auto path <p>      two-way sync with a journal: merge at session start, mirror every later change back out
/grants adopt / adopt confirm <id>       take over grants orphaned by a moved or renamed checkout
```

Imported rows are background authority: what you say in this session outranks them, a headless session never takes authority from a file silently, and a revocation is stored as a row rather than a deletion so a re-extraction cannot walk a revoked grant back in (`grants-file.ts`, `grants-adopt.ts`, `index.ts:2203`). The same file backs `grantsAutoImport` in the config — `/grants auto` is how you set it without editing JSON (`index.ts:2237`), and with it on, every ledger change is *merged* into that path, not overwritten, so a second session's rows survive (`index.ts:845`):

```json
{ "grantsAutoImport": { "enabled": true, "path": "~/.pi/agent/grants.json" } }
```

## Model profiles

`~/.pi/agent/model-profiles.json` maps each mode to a model, so a cheap mode and a strong review mode are one keystroke apart. A bare string is shorthand for `{ "model": "…" }`; the object form is `ModeConfig` (`profiles.ts`):

```json
{
  "active": "default",
  "default": {
    "ask":  { "model": "anthropic/claude-opus-4-5", "effort": "high" },
    "plan": { "model": "anthropic/claude-opus-4-5", "effort": "xhigh" },
    "auto": { "model": "anthropic/claude-haiku-4-5", "effort": "low" },
    "bypass": "anthropic/claude-haiku-4-5:medium"
  },
  "review": {
    "plan": { "model": "anthropic/claude-opus-4-5", "effort": "xhigh", "skills": ["brainstorming", "writing-plans"] }
  }
}
```

| Key | Effect |
|---|---|
| `model` | `"provider/model"` or `"provider/model:effort"`. Applied with `pi.setModel()` on every mode change. |
| `effort` | `off` \| `minimal` \| `low` \| `medium` \| `high` \| `xhigh`; wins over a `:suffix`, defaults to `medium`. Applied with `pi.setThinkingLevel()`; a level the model clamps away is skipped with a warning. |
| `skills` | Skill allowlist for the mode; `["*"]` or omitted means all. Filtering strips the disallowed skills' XML blocks out of the system prompt string (`utils.ts` `filterSkillsFromPrompt`, applied at `index.ts:3379`). |
| `tools` | Tool allowlist as declared by `resolveToolFilter()`, which re-adds `read` (`profiles.ts:347`) — and which nothing in the extension calls, so `tools` has no effect on the tool list today. |

Resolution: active profile → `default` profile → defaults (`["*"]`). A mode with no entry keeps the model it is already on, and the thinking level is only touched once a model was actually set (`index.ts:1425`, `index.ts:1444`, `index.ts:1462`). One thing to know before you rely on that: the file is created for you on session start when it is missing, pre-filled from `~/.pi/agent/settings.json`'s `defaultProvider`/`defaultModel` (`profiles.ts:136-166`), and once it exists its `active` (or `default`) profile is adopted on the first mode switch without asking — so that switch sets the pre-filled model, which is not necessarily the one you had picked (`index.ts:1404-1411`). It is a separate file because pi uses `~/.pi/agent/models.json` for custom provider definitions (pi's `README.md`), and two formats in one path is a conflict.

## Other config keys

Same file, `~/.pi/agent/permission-modes.json`. Read by `config.ts`; unparseable or unreadable is `{}` plus one warning, never a throw (`loadPermissionModesConfig`). A command that changes one key re-reads the file, mutates, and replaces it through a temp file + rename; if the file cannot be parsed it writes nothing and says so, so a hand-edited file is never silently overwritten by a command handler (`updatePermissionModesConfig`, `config.ts:490`).

| Key | Default | Effect |
|---|---|---|
| `classifier` | see above | The gate's model transport. |
| `permissions` | — | Global allow/deny/ask rules. |
| `autoMode` | shipped prompt | Extra bullets merged into the classifier system prompt's three blocks: `allow`, `soft_deny`, `environment` (each `string[]`; template files `classifier-prompts/auto_mode_system_prompt.txt` + `permissions_external.txt`, merged at `classifier-prompt.ts:162`). `allow` entries can short-circuit to allow — but only for a command layer 0 already recognises as workflow bash (`index.ts:3101`, `index.ts:3106`); `soft_deny` entries force a prompt (`index.ts:3111`). |
| `grantsAutoImport` | off | `{ enabled, path }`: sync the grants journal at `path` with the live ledger — merged in at session start, mirrored back out on every change. Set by `/grants auto` (`config.ts:286`, `index.ts:845`). |
| `injectionWarning` | `true` | Standing tool-output injection note in auto/bypass. `/injection-note` toggles it live. |
| `injectionEscalation` | `true` | The stronger, probe-triggered warning when a recent tool output matches an injection pattern. Independent of the standing note, so turning that off does not disarm a real hit (`injection-probe.ts`). |
| `messages` | — | Predefined messages for `/msg`, e.g. `{"push": "Commit the current work and push the branch."}`. |
| `authority.persist` | `"grants"` | Whether an "always" click is stored as a grant row or a rule. Reserved: `config.ts` resolves and merges it, but `applyAuthorityLayers()` has no caller on the live path yet, so today a click writes rule files. Same for the project layer `<cwd>/.pi/permission-modes.json` — read by `config.ts`, not yet applied, and a `permissions` block there is ignored by design. |

## Commands, shortcuts, flags, tools

| Kind | Name | Behavior |
|---|---|---|
| Command | `/ask` `/plan` `/auto` `/bypass` | switch mode — the four names come from the loop at `index.ts:1751` |
| Command | `/mode [name]` | set the named mode (`default` → `ask`) or pick from a list |
| Command | `/plan-execute` | execute the current plan now (switches to auto with step tracking) |
| Command | `/permissions` | list the merged allow/deny/ask rules, each tagged with its scope |
| Command | `/grants …` | grants + ledger: list, `clear`, `revoke <value>`, `export`, `import`, `auto`, `adopt` |
| Command | `/unattended [on\|off]` | prompts soft-deny with the reason; `never`-tier stays hard-blocked |
| Command | `/model-profile [name\|list]` | activate a profile (selector, by name, or print them all) |
| Command | `/classifier-status [reset]` | classifier config, resolved endpoint, session counters |
| Command | `/outside-writes` | list tracked outside-cwd writes (read-only) |
| Command | `/undo-outside-writes [all\|--list]` | restore them: selector, `all`, or list only |
| Command | `/msg [list\|add\|add-inline\|show\|del\|send]` | predefined messages, no-arg opens the picker |
| Command | `/injection-note [on\|off\|toggle\|status\|escalation=on\|off]` | injection warnings; no arg opens the picker |
| Shortcut | `Shift+Tab` | cycle modes |
| Shortcut | `Alt+T` | cycle thinking level over the levels the current model actually accepts |
| Shortcut | `Alt+I` | cycle model profile, re-applying the model for the current mode |
| Flag | `--permission-mode <name>` | start in a mode: `ask` (default), `plan`, `auto`, `bypass`, or `default` |
| Flag | `--model-profile <name>` | start with a named profile active |
| Tool | `plan_ready` | the agent submits its plan for approval in plan mode |
| Tool | `request_user_permission` | the agent asks about one specific call the gate blocked — allow / allow-always / deny; with no UI it is denied immediately, so it parks the step instead of waiting |

`--permission-mode` rather than `--mode` because pi already has a built-in `--mode` for output format (text/json/rpc).

## Outside-cwd write tracking

Any auto-approved `edit`/`write` to a path outside the working directory is snapshotted to `<cwd>/.pi/projects/<project-id>/tmp/outside-writes/` before the write, with the pre-write content or `null` if the file did not exist (`utils.ts`). The snapshot list is capped at 100 with the oldest evicted and a notification; snapshots survive restarts until you undo them. `/undo-outside-writes` opens a newest-first selector, `all` restores without asking, `--list` (and `/outside-writes`) only list. A snapshot whose file was changed by someone else is flagged in the list and still restored on request, with a warning.

## Plan mode

The agent explores read-only and writes `.pi/projects/<id>/plan.md`, then calls `plan_ready`. You choose **Execute** (switches to auto, a `☐/☑` widget advances on the agent's `[DONE:n]` tags, **Plan Complete! ✓** at the end), **Stay in plan mode**, or **Refine** (opens an editor; your notes go back as a follow-up). The plan file is created on entry, and an empty or placeholder file is never reported as a plan.

## UI

The footer is the status line: line 1 shows `cwd (git-branch)`, context usage as `42k/200k 21.0%` (`M` for millions), and the model as `name • thinking-level` prefixed with `profile:<name> · ` when a profile is active; line 2 shows the mode, e.g. `⏸ Plan (shift+tab)` (ask muted, plan accent, auto warning, bypass error). Narrow terminals reflow to two truncated lines instead of dropping fields (`index.ts:1510`). While the agent streams, the working line shows live token / tok-s / cost / context figures computed incrementally over the current branch (`branch-stats.ts`). Mode, unattended flag, plan phase and active profile are written as one `modes` session entry (`index.ts:372`) and read back on `session_start` / `session_tree` (`index.ts:3624`, `index.ts:3868`), so they survive pi's own `/reload`, resume and branch switches.

## Testing

```bash
npm test                # vitest — 85 files, 3485 tests
npm run test:watch
npm run typecheck       # tsc --noEmit
npm run pack:dry        # what the package ships (64 files)
```

`bash-walker.golden.jsonl` is the walker's acceptance data — one input plus the required result per line, checked by `bash-walker-golden.test.ts`.

## Layout

```
index.ts                  the extension: hooks, mode gate, dialogs, footer, commands
risk-policy.ts            layer 0: verb -> tier tables, per-category handlers
risk-handlers.ts          per-command argument rules (rm, git, docker, kubectl, curl, …)
risk-paths.ts             path classification: project / outside / secret / device
bash-parser.ts            tree-sitter-bash init + grammar resolution from wasm/
bash-walker*.ts           the walk: values, heredocs, meaning, scan, golden harness
bash-tiers.ts             tier verdicts built on the walker's view (allow / ask / never / unknown)
shell-lexer.ts            the older hand-written lexer — runs escalation-only: its ask/never survive, its allow is demoted to unknown (risk-policy.ts:15)
classifier-client.ts      classifier transports, stages, ref parsing
model-client.ts           schema-constrained extraction + transcript authorisation
classifier-prompt.ts      the prompt, with the ruleset it must reason over
classifier-prompts/       the two prompt files the autoMode keys merge into (classifier-prompt.ts:12)
gate.ts / gate-bridge.ts  the pipeline and its endpoint resolution
auth-ledger.ts            whole-session grant/forbid memory, revocations, backfill
session-grants.ts         prompt-once {category, entity} grants + revocation rows
grants-file.ts            the on-disk journal: read, merge, prune, write
durable-approval.ts       what an "always" click may store, and when it must store nothing
grants-adopt.ts           reclaiming grants orphaned by a moved checkout
permissions*.ts           rule parsing, merging, evaluation, persistence
dangerous-permissions.ts  broad bash allow rules removed for the duration of auto mode
permission-forwarding.ts  subagent → parent ask forwarding (filesystem inbox)
headless-bridge.ts        in-process sessions inherit the parent's whole authority state
mode-inherit.ts           PERMISSION_MODES_INHERITED_MODE
profiles.ts               model profiles (~/.pi/agent/model-profiles.json)
copilot-session.ts        Copilot Auto session mint, cache, budget
config.ts                 the config file: resolvers, defaults, layered view
utils.ts                  bash tables, plan file, [DONE:n], outside-write snapshots
docs/                     the two specs cited above, plus the mode prompts
wasm/                     tree-sitter-bash.wasm + its MIT notice
```

Peer dependencies (provided by pi): `@earendil-works/pi-coding-agent`, `@earendil-works/pi-ai`, `@earendil-works/pi-tui`, `typebox`. The only runtime dependency is `web-tree-sitter`.

## Origin and licence

Forked from upstream `pi-permission-modes` 2.7.0, which is MIT; the upstream notice is kept in `LICENSE`. This fork — the layer-0 walker and its spec, the authorisation ledger and grant journal, the Copilot Auto-session transport, the unattended and headless paths — is licensed **AGPL-3.0-or-later**, as declared in `package.json`.
