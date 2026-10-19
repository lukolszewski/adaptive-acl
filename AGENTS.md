# AGENTS.md

Read this first if you are an agent asked to change this repository. It maps the tree, names the gates
you have to pass, and lists the invariants that are enforced somewhere in code and will bite you if you
change them by instinct. Every line here was checked against the files at this commit; where a line cites
`file.ts:line`, that citation is the reason the claim is true — go read it.

## What this package is

A [pi](https://www.npmjs.com/package/@earendil-works/pi-coding-agent) extension — the npm package defined
by `package.json`, whose `pi.extensions` entry (`package.json:24-26`) points at `./index.ts`. It puts a
permission gate between the coding agent's tool calls and the machine, through four named modes
(`ask → plan → auto → bypass`, cycled with Shift+Tab) that a user switches at will. The interesting part is
auto mode: it is **deterministic first**. Bash is parsed with a real grammar (`tree-sitter-bash` shipped as
a checked-in wasm) and walked under a written specification; a per-verb policy decides most calls in code;
only what the parse cannot vouch for is asked of a small safety model, and that model can narrow a decision
but never widen one. Human authority is kept separately from either: allow/deny/ask rule files, prompt-once
session grants, and an authorisation ledger folded from the conversation, all revocable. The extension also
carries the surrounding product surface — plan mode with a `plan.md` driver, outside-cwd write tracking for
undo, per-mode model profiles, subagent approval forwarding, and an adaptive footer.

## Module map

Every file matching `git ls-files '*.ts' | grep -v '\.test\.ts$'` (59 entries; the last two are test
harness, not shipped — `package.json:29-38` excludes them from the tarball).

### Entry point and pi surface

- `index.ts` — the extension. Registers the mode commands (`index.ts:1751-1756`), shortcuts, start flags,
  the `tool_call` gate, the footer, plan mode, prompts, session persistence. ~3 900 lines; everything a user
  sees is wired here, almost nothing is decided here.
- `session-branch.ts` — typed port over `ctx.sessionManager`. The only file that writes down pi's session
  entry shape (`session-branch.ts:1-8`); every session read goes through it.
- `headless-bridge.ts` — in-process bridge: an interactive session shares mode/grants/ledger with agent
  sessions created **inside the same process** (which have no UI and no session entries of their own).
- `permission-forwarding.ts` — cross-process ask forwarding: a headless child writes a request into a
  filesystem inbox, the parent session's UI answers; a challenge echoed on the response means a file nobody
  read cannot approve.
- `mode-inherit.ts` — publishes the live mode in `PERMISSION_MODES_INHERITED_MODE` so spawned children
  start in the same mode the parent is in.
- `plan-approval-dialog.ts` — the TUI component that renders `plan.md` for execute / refine / stay / cancel,
  including the terminal-height arithmetic.
- `profiles.ts` — `~/.pi/agent/model-profiles.json`: per-mode model / effort / skills / tools. Pure and
  fs-only, no pi import (`profiles.ts:9` explains why the file is not named `models.json`).
- `injection-probe.ts` — the heuristic that spots planted instructions in tool output, plus the prompt text
  injected when it fires.
- `branch-stats.ts` — incremental token/cost totals over the branch: O(new entries) per streamed chunk, with
  a full recompute whenever the branch prefix moved (`branch-stats.ts:1-10`).
- `denial-tracking.ts` — when the classifier has said no often enough that the run should stop asking it:
  a streak that an approval resets, and a total that it does not (`denial-tracking.ts:31-70`).

### Permission rules (allow / deny / ask)

- `permission-rule-parser.ts` — `Tool` / `Tool(specifier)` parsing and the escape codec that carries a
  specifier between file and memory.
- `shell-rule-matching.ts` — the three rule-body shapes (whole command, `prog:*` prefix, glob with `*`),
  compiled to fixed pieces and matched without building a regular expression.
- `bash-permission-match.ts` — the text matcher behind **deny and ask**, plus `suggestBashAllowRule*`: the
  producers that write an "always allow" specifier from a command that ran.
- `bash-audit.ts` — asks layer 0 for the legs of a command and returns the argv spellings an allow rule may
  be compared against; it re-tokenises nothing.
- `bash-rule-argv.ts` — the allow matcher: do the words a rule names sit, unchanged, at the front of these
  argv words (and, for a redirecting leg, is the file it writes the file the rule names).
- `permissions.ts` — the decision: `deny → ask → allow → passthrough` (`permissions.ts:3`), allow over argv,
  deny/ask over text, on purpose (`permissions.ts:8-17`).
- `permissions-loader.ts` — global + project rule files (`permissions.json`, `permissions.local.json`) and
  their merge/persist; owns the one derivation of where project state lives (`permissions-loader.ts:37-61`).
- `path-permission-match.ts` — Read/Edit/Write path globs over project-relative, `~/` and absolute paths,
  and the path rules offered after an approval.
- `dangerous-permissions.ts` — which allow rules hand the shell to the model (`Bash(python:*)`, `Bash(git:*)`,
  a bare `Bash`): removed on entering auto mode (`dangerous-permissions.ts:190`), put back on leaving it
  (`dangerous-permissions.ts:215`), skipping any the user re-added meanwhile.

### Layer 0 — reading bash as a tree

- `bash-parser.ts` — owns the grammar: loads `web-tree-sitter` plus the checked-in `tree-sitter-bash` wasm
  and returns a tree, or a reason there is none (`bash-parser.ts:13-33` records why the grammar is not a
  dependency; `bash-parser.ts:337-349` is the search order).
- `bash-ast.ts` — the public shape of a parse (`AstParse`, `AstCommand`) and `parseBashCommand`
  (`bash-ast.ts:87`), the entry every caller uses.
- `bash-walker.ts` — the walker proper: the spec's §2 pipeline in order, first refusal wins; the flag-write
  report that catches `sort -o /etc/x`. Holds no policy and no value rules of its own.
- `bash-walker-scan.ts` — the character scans (§10): unbalanced delimiters, control and unicode whitespace,
  constructs whose meaning differs between shells. Each scan keeps its own class because the order is
  observable.
- `bash-walker-values.ts` — everything a value can be: `NAME=` prefixes, statement assignments remembered for
  later, inert substitutions → `__CMDSUB_OUTPUT__`, inert variables → `__TRACKED_VAR__`, declaration/unset
  guards.
- `bash-walker-heredoc.ts` — here-documents: the tree-side attachment to the command that reads the body, and
  the proof-carrying masked copy the brace scan may be handed.
- `bash-walker-meaning.ts` — the §11 checks run over resolved values: is the thing in command position a
  command, can we see what it actually runs, does a wrapper's option set change what we are looking at.
- `bash-walker-golden.ts` — loads and compares `bash-walker.golden.jsonl`. Deliberately not a `*.test.ts`
  name because several suites import it; it therefore ships in the tarball (`package.json:29-38`).
- `shell-lexer.ts` — the older hand-written lexer. Still produces segments for the text tier tables and for
  the legacy engine, and its verdicts are escalation-only (`risk-policy.ts:593-602`).

### Auto-mode gate

- `risk-policy.ts` — `evaluateToolCall` (`risk-policy.ts:136`): deterministic policy over layer 0, the
  compound result is the most restrictive leg, malformed input goes to the fix-and-retry path.
- `risk-handlers.ts` — one handler per command family (`git`, `docker`, `rm`, package managers, …); anything
  unhandled comes back `unknown` and is escalated.
- `risk-paths.ts` — path classification (project / outside / sensitive / unresolvable), pure: `cwd`,
  `project` and `home` are injected so tests stay hermetic.
- `bash-tiers.ts` — the positive allowlists (read-only verbs, test runners, routine build/git verbs, the
  runner flags that turn a test into an execution vector) computed from the parse instead of from text.
- `gate.ts` — the pipeline: layer 0 → session grants → transcript authorisation → effect classification,
  returned as a `GateResult` (`gate.ts:140`). No UI, no pi imports, so it can be run end to end in a test.
- `gate-bridge.ts` — pi ↔ gate helpers: endpoint resolution including the Copilot cases, ledger sync, and
  the wording and attribution of every denial the user reads.
- `utils.ts` — the older pure helpers: text tier tables, the plan file and its numbered `Plan:` / `[DONE:n]`
  steps, project id and state directories, outside-cwd write snapshots, mode-prompt injection, skill
  filtering.

### Model calls (the safety model, when there is one)

- `config.ts` — `~/.pi/agent/permission-modes.json` and `<cwd>/.pi/permission-modes.json`: classifier,
  Copilot and authority settings, validated into defaults and cached; the resolvers are pure and the getters
  allocate nothing.
- `classifier-client.ts` — the single-shot classifier (pi-ai `completeSimple`): prompt assembly, stages, XML
  and JSON verdict formats, retries. Reachable only through the `classifier.engine: "legacy"` path
  (`config.ts:534`, wired at `index.ts:3191`).
- `classifier-prompt.ts` — assembles the system prompt out of `classifier-prompts/` with index arithmetic on
  `{{rules:*}}` / `{{include:*}}` markers; the verdict block is built here, not in the template
  (`classifier-prompt.ts:40-46`).
- `classifier-prompts/*.txt` — the auto-mode ruleset and the allow/deny/environment bullet template it pulls
  in. This is the text that decides what the model thinks "routine" means.
- `classifier-messages.ts` — the two shapes of a negative answer: a refusal carrying the model's own reason,
  and an "unreachable" notice meaning nothing was judged.
- `classifier-redact.ts` — masks credential values before text leaves the process, keeping the credential's
  name so the model still sees that one was passed.
- `classifier-tool-projection.ts` — the part of a tool input the model needs to see; `''` for tools whose
  input carries no security signal.
- `classifier-tool.ts` — the `classify_result` tool schema, for stages where the answer must arrive as a tool
  call.
- `classifier-transcript.ts` — the transcript the model sees: user messages and tool calls only, budgeted,
  redacted, oldest dropped first.
- `context-budget.ts` — token estimation and whole-item fitting; the only place that knows the window
  (`context-budget.ts:25`).
- `model-client.ts` — the narrow HTTP client that sends `response_format: json_schema` in two dialects, so a
  parse failure is structurally impossible where the server honours it.
- `copilot-session.ts` — the plugin's own GitHub Copilot Auto session: mint, cache, single-flight, allowance
  counter. It owns the token, never the request bodies.
- `message-chunks.ts` — cuts an oversize user message into whole pieces so grant extraction sees all of it;
  `chunkMessage(t).join("") === t` by construction.
- `ledger-render.ts` — renders ledger rows as the summary of the turns that no longer fit the call, so an old
  sentence in which the user granted something still authorises.

### Authority: grants, ledger, journal

- `auth-ledger.ts` — the per-session authorisation ledger, folded from per-message extraction: dedup per
  `(category, value, kind)`, cross-type precedence decided at match time by `seq`, revocations as rows, newest-first
  background backfill safe while incomplete.
- `session-grants.ts` — prompt-once grants `{category, value, kind}` and the revocation ("tombstone")
  vocabulary that every store shares, which is the only reason a merge can revoke.
- `grant-verify.ts` — code-side verification of what the model extracted: verbatim quote, whole-token entity
  match, `canonicalPath`, forbidden-target veto.
- `durable-approval.ts` — what an "always" click stores when authority lives in the journal instead of rule
  files (`authority.persist: "grants"`, the default).
- `grants-file.ts` — the one portable journal file per project (ledger rows, forbids, read-only posture,
  session grants, revocations). A merge, not a dump: several sessions write it.
- `grants-adopt.ts` — the orphan scan: state left under `<cwd>/.pi/projects/` by a directory move. Takes the
  tightening half (deny/ask) quietly; hands back everything widening as candidates.
- `adopt-confirm.ts` — the human half of that: candidate ids, selection, and writes that go through the
  modules that own the policy.
- `adopt-live.ts` — makes a confirmed rule live by re-reading the rule files, never by minting a grant.
- `reload-policy.ts` — re-reads the rule files into the policy a session is running on, keeping "absent",
  "blank" and "unreadable" three different answers (`reload-policy.ts:10-20`).

### Test harness (matched by the module-map command, not shipped)

- `vitest.config.ts` — collects `**/*.test.ts` and installs the setup file below.
- `vitest.setup.ts` — clears every `PERMISSION_MODES_*` / `PI_SUBAGENT_*` variable before **each** test file
  and awaits `initBashParser()`. Both halves matter: the plugin reads those variables at call time, and layer
  0 refuses every command as `parser-unavailable` until the grammar is loaded.

## Gates

```bash
npm install --ignore-scripts --no-audit --no-fund   # what CI does; nothing here has a build step
npx vitest run        # 85 files, 3485 tests, all green
npm run typecheck     # tsc --noEmit -p tsconfig.json — zero errors
npm run pack:dry      # 64 files, ~595 kB tarball, 2.7 MB unpacked
```

Run all four before you call a change done, and paste the real output into your result. Notes that cost an
hour each if you learn them by hand:

- **`--ignore-scripts` works** because the bash grammar is a checked-in wasm (`bash-parser.ts:13-33`), not a
  native build. Keep it that way: an `install` script in the dependency chain breaks the publish workflow,
  which installs exactly this way (`.github/workflows/test.yml`, `.github/workflows/release.yml`).
- **`npx vitest run` must be run from the repository root.** The corpora are loaded relative to the module
  that reads them (`bash-walker-golden.ts:31`, `bash-allow-layer0.test.ts:609-610`).
- **`tsconfig.json:15` includes `*.ts` and `tools/*.ts`, root level only**, with `eval` and `spike` excluded
  (neither directory exists here). A new file in a subdirectory is not typechecked by `npm run typecheck`.
- **`npm run pack:dry` counts 64** because `package.json:29-38` ships `*.ts` minus `*.test.ts`. That glob is
  why `bash-walker-golden.ts` ships and `docs/`, the `.jsonl` corpora and `testcases/` do not. If a runtime
  path starts reading a non-`.ts` file, this list has to change with it.
- The publish contract adds a **leak scan**: grep every tracked file for a fixed list of private tokens —
  developer home paths, the maintainer's account name, internal host names, scratch and vendored-tree
  directory names, corpus vocabulary — and it must print nothing. This file deliberately does not quote that
  pattern, because a file that quotes it is a file that matches it. The rule it enforces is the useful part:
  nothing in this tree quotes a personal path, a machine name, or an internal scratch directory.

### Load it while you work

```bash
pi -e ./index.ts        # from the repository root — the same entry a published install reads (package.json:24-26)
```

What you can then exercise by hand: the four mode names as commands (`index.ts:1751-1756`), plus `/mode`,
`/permissions`, `/grants`, `/plan-execute`, `/model-profile`, `/classifier-status`, `/outside-writes`,
`/undo-outside-writes`, `/unattended`, `/msg` and `/injection-note` (registered between `index.ts:1751` and
`index.ts:2819`); Shift+Tab for the mode cycle (`index.ts:2915`), Alt+T for thinking level
(`index.ts:2959`), Alt+I for profiles (`index.ts:2992`); `--permission-mode` (`index.ts:3000`) and
`--model-profile` (`index.ts:3007`) at start-up. Outside-cwd write tracking caps at 100 snapshots and evicts
the oldest (`utils.ts:19`, `utils.ts:1005-1008`) — relevant if you touch the undo path.

## Invariants

Each line names where the code enforces it. These are the things a confident, plausible patch breaks.

### Modes and the tool-call gate

- The four modes are the cycle `ask → plan → auto → bypass` (`index.ts:238`), which `/mode`
  (`index.ts:2345`) and Shift+Tab (`index.ts:2915`) step through. The per-mode commands are registered from
  their own literal array (`index.ts:1751-1756`) rather than from that constant, so a rename has to be made
  in both places or `/mode` offers a mode with no command of its own.
- The start flag is `--permission-mode` because pi owns `--mode` for output format (`index.ts:2998-3000`).
  Do not "tidy" the name.
- Configured rules evaluate **before** any mode gate, in the order deny → ask → allow → passthrough
  (`permissions.ts:3`, the loops at `permissions.ts:85` and `permissions.ts:428`). An allow short-circuits the
  gate entirely, which is exactly why broad `Bash(...)` allow rules are stripped before auto mode runs
  (`dangerous-permissions.ts:190`) and restored after it (`dangerous-permissions.ts:215`).
- Allow matches argv, deny and ask match text, and the split is load-bearing
  (`permissions.ts:8-17`, `permissions.ts:283-284`): a command layer 0 refuses to vouch for has no argv, so no
  allow rule can cover it, while `Bash(rm *)` must still stop
  `for f in *; do rm -f $f; done`, which has no argv either. Do not "unify" the two matchers.
- No UI means the session behaves as unattended: a prompt that cannot be drawn is a denial, never a pass
  (`index.ts:1093-1103`), and `never`-tier stays blocked regardless (`index.ts:1111-1115`). Every failure path
  in this package points the same way — fail closed, and say why.
- Plan mode writes only the plan file (`index.ts:3079-3082`) and runs only the read-only allowlist.
- Writes outside the project in bypass mode are **tracked, not blocked** (`utils.ts:998`
  `trackOutsideWrite`, surfaced by `/outside-writes` and `/undo-outside-writes`). Blocking them would be a
  behaviour change, not a safety fix.

### Layer 0

- Layer 0 is a parse over an explicit list of node types, not a lexer: the walker dispatches on `node.type`
  (`bash-walker.ts:211-277`) and anything it has no rule for is refused with the closest reason id — "never a
  silent pass" (`docs/LAYER0-WALKER-SPEC.md:105`). Supporting a new construct means a `case` **and** a golden
  case, never a permissive default.
- No partial answer, no guess: a refusal carries no commands and the result never contains an inferred word
  (`docs/LAYER0-WALKER-SPEC.md:37-44`). `malformed: true` means the input is broken and should be rewritten;
  `malformed: false` means valid bash the walker declines and the effect model should judge. Callers switch on
  that flag, never on the wording of a reason.
- `nodeType` is a diagnostic and nothing else (`bash-walker.ts:84-87`); no caller may branch on it and the
  golden corpus never asserts it.
- The walker holds no policy (`docs/LAYER0-WALKER-SPEC.md:525` §14.5): it does not know what a project
  directory is. Path and risk judgement lives in `risk-paths.ts` and `risk-handlers.ts`.
- The legacy lexer is escalation-only (`risk-policy.ts:593-602`): its `ask`/`never` verdicts survive, its
  `allow` verdicts are demoted to `unknown`. It can never lower a tier or authorise anything
  (`risk-policy.ts:16-17`).
- If the grammar fails to load, every bash command is refused `parser-unavailable` (`bash-parser.ts:186`) — a
  dead analyzer, never a pass. Initialisation happens at load (`index.ts:3586`) and in `vitest.setup.ts`; the
  fact a packaging bug is caught by is which wasm file was used (`bash-parser.ts:229`).

### Authority

- A grant never widens itself: a grant is `{category, value, kind}` and `grantsCover` matches that and
  nothing else (`session-grants.ts:1-5`, `session-grants.ts:368`). Approving `docker rmi api:dev` must never
  cover `payments:prod`.
- **A durable row may never express more than the invocation that earned it**
  (`durable-approval.ts:9-14`): where no row can say exactly what was approved, the click is honoured once and
  the caller is told why. A row is read back for the life of the project with no trace of the click, so a wide
  row is indistinguishable from permission.
- Importing is not declaring. Rule files are user-authored and evaluate before the mode gate; imported rows
  are background authority that anything said in the current session outranks
  (`grants-file.ts:7-10`, implemented in `importLedger`, `auth-ledger.ts:1456`).
- Adopting an orphan project's state may take its **tightening** rules (deny/ask) without asking and must
  never apply its **widening** ones — every allow rule and every journal row comes back as a candidate
  (`grants-adopt.ts:10-20`, `grants-adopt.ts:402`).
- An adopt candidate's handle is derived from what the candidate **is**: the rule text for a rule, or
  `category + scope + canonicalPath(value)` for a row (`adopt-confirm.ts:160-176`). Never an index: the list
  is re-rendered from two stores and a stale index would grant the wrong thing silently
  (`adopt-confirm.ts:14-21`). Note for anyone looking for a digest: the SHA-256 in this tree hashes a **cwd**
  for the project id (`utils.ts:839-841`) and plan text for popup throttling (`utils.ts:1226`); rule identity
  is textual and case-folded, not hashed.
- An unreadable rules file is not an empty one. `grants-adopt.ts:180` refuses to read a corrupt file, and
  `reload-policy.ts:10-20` exists because `loadMergedPermissionRules()` answers `[]` for absent, blank **and**
  unreadable. Any reload built on that read would take a half-written file as "this project keeps no deny
  rules" and take down every wall the session had.
- The project id comes from `getProjectId()` and nowhere else (`utils.ts:822`) — both rule files, the grants
  journal, the plan file and the outside-write snapshots hang off it
  (`permissions-loader.ts:37-49`). Re-deriving it (a git root, a hash taken locally) points a session at a
  state directory its rules were never written into.

### Model calls

- The classifier's system prompt **is** the auto-mode ruleset — `classifier-prompt.ts:12` loads
  `classifier-prompts/auto_mode_system_prompt.txt`, whose first line says it is the auto-mode safety check.
  The user prompt then names the live mode in its header (`classifier-client.ts:221`, filled from
  `currentMode` at `index.ts:1310`), and the classifier is only reachable from auto mode
  (`index.ts:3097-3117`, with the legacy path at `index.ts:3191`). Route another mode through this prompt and
  you hand a model a header describing one mode and rules describing another; `classifier-client.test.ts:483`
  pins the header.
- The transcript holds user messages and tool calls only. Assistant prose is excluded on purpose — the model
  being asked is the one that wrote it (`classifier-transcript.ts:1-8`).
- Redaction keeps the credential's name and masks only the value, orders specific-before-generic, and is
  idempotent (`classifier-redact.ts:3-11`). Every new rule has to keep all three; it runs on every prompt, so
  it trades recall for not hiding the command.
- **Context window: one place, and a wrong value fails silently.** The window is
  `classifier.contextTokens` (`config.ts:157-158`, defaulted at `config.ts:535`, sanitised at `config.ts:600`),
  carried onto the endpoint (`gate-bridge.ts:232`, `gate-bridge.ts:256`, `gate-bridge.ts:371`) and spent by
  `callBudget` (`context-budget.ts:77-89`). Nothing reads pi's own model window. A missing or absurd value
  falls back to 4 096 (`context-budget.ts:25`) and the transcript is then quietly shortened — items are
  dropped whole from the oldest end (`context-budget.ts:51`) — so a sizing bug reads as "the model forgot",
  not as an error. Never clip a string instead: whole items only (`context-budget.ts:15-20`).
- A truncated answer is a transport failure, never a verdict (`model-client.ts:282-287`,
  `classifier-client.ts:824-834`). The answer reserve is a different knob from the window —
  `classifier.copilot.maxOutputTokens` (`config.ts:63-67`): too small is no answer at all.
- The Copilot session token header travels **only** on the Auto pick (`model-client.ts:43-44`); measured, it
  restricts the request to the Auto models, so an explicitly named model must never carry it.
- Every model failure is rendered as "there is no verdict", never as silence or approval
  (`classifier-messages.ts:66-67`).

### pi's surface

- pi's session entry shape is written down in exactly one file (`session-branch.ts:1-8`). A private shape
  guess elsewhere once left the injection probe dead at runtime while its test, using the same guess, passed.
- Session state travels in two custom entries: `modes` (written `index.ts:373`, restored `index.ts:3624`) and
  `gate-ledger` (written `index.ts:826`, restored `index.ts:3666`). Renaming either silently discards every
  saved session's mode, grants and ledger.
- `pi.setModel()` runs only inside an explicitly configured profile: `index.ts:1404` returns when no profile
  is active, `index.ts:1444` is the only call. Profiles are opt-in and live in
  `~/.pi/agent/model-profiles.json` (`profiles.ts:9`, `profiles.ts:62`) — not `models.json`, which pi uses for
  provider definitions.
- Mode context is injected through the `<!-- permission-modes:context -->` anchor
  (`utils.ts:1163-1164`, `resolveModePrompt` at `utils.ts:1189`), not as per-turn messages. Per-mode skill
  filtering strips skill blocks from the prompt string (`utils.ts:1437`, called `index.ts:3379`, and
  `index.ts:3386` warns loudly if the strip changed nothing).

## What does not live here

This repository ships an extension and the tests that prove it. Everything else from the work that produced
it stays out, and the boundary is not a matter of taste: a file that only makes sense to whoever built the
feature is noise to the person who has to maintain it next.

- **No scratch or process artifacts.** `.gitignore` exists for this: `.pi/` (plans, reports, outside-write
  snapshots and grant files an agent writes next to the code while it works), task briefs and result notes,
  run logs, `.runs/`. They are runtime output, and some of them contain real paths from whoever's machine ran
  them.
- **No personal or machine-specific paths.** No home directories, host names, account names or local
  checkout paths — in code, comments, tests or commit messages. Tests use `mkdtemp` and injected
  `home`/`project` (`risk-paths.ts:1-4`).
- **No internal decision records, evaluation logs, or comparisons against other people's code.** If a comment
  cites a record that is not in this tree — a decision log, a TODO list, an evaluation harness, a scratch
  probe — treat it as a dead pointer and fix the comment while you are in the file. The written
  specifications that ship are
  [docs/CLASSIFIER-SPEC.md](docs/CLASSIFIER-SPEC.md) and
  [docs/LAYER0-WALKER-SPEC.md](docs/LAYER0-WALKER-SPEC.md), plus the mode prompts in `docs/prompts/`. If a
  decision needs to survive, put the reason in the code comment and cite the code, not the record.
- **No vendored third-party source**, except the one grammar blob that has to ship: `wasm/tree-sitter-bash.wasm`
  with its MIT notice (`wasm/LICENSE-tree-sitter-bash`), for the reasons in `bash-parser.ts:13-33`.
- **The behavioural contracts are in the tree.** `bash-walker.golden.jsonl` (via `bash-walker-golden.ts:31`)
  and `testcases/cases-v2.jsonl` + `testcases/cases-ledger.jsonl` (read by `bash-allow-layer0.test.ts:609-610`)
  are the accept/refuse corpus for layer 0 and the bash allow matcher. Change the behaviour and the corpus
  changes in the same commit — they are not shipped to users, they are what tells you the change is right.

## Licence and origin

The extension source is licensed MIT under [`LICENSE`](LICENSE) (`LICENSE:1-3`), which also carries the MIT
notices for the bundled tree-sitter-bash grammar (`LICENSE:26-78`); `package.json:9` currently declares
`AGPL-3.0-or-later`, which contradicts that file — reconcile the two deliberately, in a packaging change, and
never by silently editing one side. The package grew out of an earlier permission-modes extension for pi, and
several names still say so (`~/.pi/agent/permission-modes.json`, the `modes` session entry, the
`permission-modes:` prompt anchor). Those are user-visible and session-visible: renaming them orphans
existing configuration and saved state, so leave them.
