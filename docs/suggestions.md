# Permission-Modes v1.1.0 — Suggestion: Simplify to Three Modes

> **Status:** ✅ Implemented in v2.0.0 (combined with v1.2 auto-follow-up, tests, and project-root detection)
> **Supersedes:** v1.0.0's four-mode cycle (default / plan / accept-edits / auto)
> **Date:** 2026-06-28
> **Reference format:** Inspired by [codewalker's design suggestion](../codewalker/docs/claude-suggestion.md)
> **Related:** [v1.1.1-suggestions.md](../../.pi/plan/v1.1.1-suggestions.md) — per-mode model profiles (implemented in v1.1.1 / v2.1)

---

## 0. TL;DR (recommendation)

**Reduce from 4 modes to 3 modes** and sharpen each mode's permission semantics:

| v1.0.0 (current) | v1.1.0 (proposed) | What changes |
|---|---|---|
| `default` | `ask` | Renamed + refined: prompt on write/edit **AND** any access outside cwd; **don't** prompt for reads inside cwd |
| `plan` | `plan` | Refocused: explicitly block all code generation (no edit/write), **only** allow planning output in markdown |
| `accept-edits` | _(removed)_ | Merged into `ask` — no standalone "auto-approve edits" mode |
| `auto` | `auto` | Tightened: still no-ask, but **prompt on destructive actions outside the working directory** |

**Why 3 instead of 4:** The `accept-edits` mode was a narrow intermediate state between `default` and `auto` that added complexity (a whole mode, a slot in the cycle, UI state) for marginal value. Users who want "don't ask for every edit" can use `auto` with the new outside-cwd guard, or just hit "Allow all → auto" in `ask` mode. Removing it simplifies the cycle to 3 modes, which is easier to remember and navigate via Shift+Tab.

---

## 1. Current state (v1.0.0 — what exists today)

### Mode definitions

| Mode | edit / write | bash | Notes |
|---|---|---|---|
| **default** `●` | prompt (`Allow`/`Allow all→auto`/`Block`) | mutating prompts; read-only passes | — |
| **plan** `⏸` | **disabled** (stripped from tool set) | read-only allowlist only | Agent explores, emits `Plan:`, then Execute/Stay/Refine |
| **accept-edits** `✎` | **auto-approved** | mutating still prompts | The "gray area" mode |
| **auto** `▶` | auto-approved | auto-approved | Auto-continue (bounded by `/auto-depth`) |

### Key infrastructure

- `MODE_CYCLE: Mode[] = ["default", "plan", "accept-edits", "auto"]`
- `MODE_META` — icon, label, role per mode (defined as a `Record<Mode, ...>`)
- `MODE_CONTEXT` — per-mode context injected into the agent loop via `before_agent_start`
- `PLAN_TOOLS` / `PLAN_DISABLED` — plan mode's tool restrictions
- `applyToolRestrictions()` — enables/disables edit/write based on mode
- `tool_call` gate — the big `if/else` chain that decides when to block, prompt, or approve
- `Plan:` extraction + `[DONE:n]` step tracking in `utils.ts`
- UI: status pill, custom footer, plan-todos widget, working-message stats

### Pain points with v1.0.0 design

1. **`default` mode prompts too much** — it prompts for every edit/write even inside cwd, but *doesn't* prompt for reads outside cwd (reads of `/etc/passwd`, `~/.ssh/id_rsa`, etc. pass through). The "ask for every edit" is noisy; the "don't ask for any read" is underprotective.
2. **`accept-edits` is redundant** — it's a stepping stone to `auto` that users reach by clicking "Allow all → auto" anyway. Keeping it as a full mode (cycle slot, context string, status icon, switch command) adds surface area without proportional value.
3. **`plan` mode's purpose is muddy** — the current context string says "explore read-only, then produce a Plan:", but it doesn't explicitly forbid *writing code in the plan* or distinguish between "writing a plan document" vs "writing actual source files." A plan can contain code snippets, which defeats the purpose.
4. **`auto` mode has no safety net** — it trusts the agent completely. If the agent decides to `rm -rf /some/deployment/path`, it will. No boundary check.
5. **Outside-cwd awareness is missing entirely** — no mode currently distinguishes between operations *inside* the working directory vs *outside* it. This is a fundamental permission boundary that real CLIs (ssh, sudo, docker) all respect.

---

## 2. Proposed v1.1.0 — Three modes, sharper boundaries

### Mode definitions

| Mode | Icon | edit / write | outside-cwd access | read inside cwd | Destructive bash |
|---|---|---|---|---|---|
| **ask** `●` | `●` | **prompt** | **prompt** (both read & write) | **auto-approve** | prompt |
| **plan** `⏸` | `⏸` | **blocked** | **blocked** (no reads outside cwd) | allowed | blocked (read-only allowlist) |
| **auto** `▶` | `▶` | **auto-approve** | **prompt** (destructive only) | auto-approve | auto-approve inside cwd; prompt if destructive outside |

**New cycle (Shift+Tab):** `ask → plan → auto → ask`

### 2.1 `ask` mode (renamed from `default`)

**Design goal:** Be the "safe default" that protects against both unwanted mutations **and** data exfiltration, without being annoyingly noisy.

**Behavior summary:**

| Event | Behavior |
|---|---|
| `edit` / `write` (any path) | **Prompt** — user must approve each write |
| `read` inside cwd | Auto-approve |
| `read` **outside** cwd | **Prompt** — new in v1.1.0 |
| `bash` (destructive) | Prompt (same as v1.0.0) |
| `bash` (read-only inside cwd) | Auto-approve |

**Full prompt reference:** [`docs/prompts/ask-mode-prompts.md`](prompts/ask-mode-prompts.md) — includes exact dialog text, options, trigger conditions, no-UI fallback, and decision tree pseudocode.

**Key changes from v1.0.0 default:**
- Adds **outside-cwd read guarding** — if the agent tries to read `~/.ssh/id_rsa`, `/etc/shadow`, etc., the user gets a prompt. Inside cwd reads are free.
- "Allow all → auto" still offered on edit/write prompts, providing the same quick-escape to auto mode.

**Rationale:** The user's instruction says "ask for permission when pi tries to write, edit, access directory/files/anything outside cwd, don't ask permission for read." This maps to the most intuitive security boundary: **the current project directory is the trusted zone; everything outside is suspect.**

### 2.2 `plan` mode (refocused)

**Design goal:** Strictly restrict the agent to **writing plans only** (markdown text). No code generation of any kind.

**Behavior summary:**

| Event | Behavior |
|---|---|
| `edit` / `write` (any path) | **Blocked** (stripped from tool set, same as v1.0) |
| `read` (any path inside or outside cwd) | Allowed (exploration is the point) |
| `bash` (destructive) | Blocked |
| `bash` (read-only) | **Allowed** (including outside cwd) |
| Agent output containing code blocks | **No technical enforcement** (can't filter output stream), but **context injection** explicitly forbids it |

**Full prompt reference:** [`docs/prompts/plan-mode-prompts.md`](prompts/plan-mode-prompts.md) — includes new context injection wording, Plan-ready prompt, refinement editor, execution message, plan extraction/tracking, and decision tree.

**Key changes from v1.0.0 plan:**
- The `MODE_CONTEXT["plan"]` string is rewritten to **explicitly forbid code** (see prompt file for exact wording).
- Read access is expanded to include outside-cwd reads (gather context for the plan).
- Execute/Stay/Refine flow preserved.

### 2.3 `auto` mode (with outside-cwd safety net)

**Design goal:** Maximum autonomy with a hard boundary: **destructive operations outside the working directory require approval.**

**Behavior summary:**

| Event | Behavior |
|---|---|
| `edit` / `write` inside cwd | Auto-approve |
| `edit` / `write` **outside** cwd | **Prompt** |
| `read` (anywhere) | Auto-approve |
| `bash` (destructive inside cwd) | Auto-approve |
| `bash` (destructive **outside** cwd) | **Prompt** |
| `bash` (read-only) | Auto-approve |

**Full prompt reference:** [`docs/prompts/auto-mode-prompts.md`](prompts/auto-mode-prompts.md) — includes context injection, auto-approve conditions, outside-cwd edit/write prompt, outside-cwd bash prompt, and decision tree pseudocode.

**Key changes from v1.0.0 auto:**
- Adds a **destructive-outside-cwd guard** — replaces the need for `accept-edits` mode.
- Auto-continue (commented out in v1.0.0) stays commented out.

---

## 3. What to remove (accept-edits mode)

**Remove all accept-edits artifacts:**
- Entry in `MODE_CYCLE` — becomes `["ask", "plan", "auto"]`
- Entry in `MODE_META` — delete key
- Entry in `MODE_CONTEXT` — delete
- The `accept-edits` branch in the `tool_call` gate handler
- Remove from `for`-loop command registration (automatic when removed from `MODE_CYCLE`)
- Update README.md, docs/PRD.md, AGENTS.md

**Keep a `// Legacy: accept-edits removed in v1.1.0` comment** in the mode cycle area for reference, to be fully cleaned up later.

---

## 4. What to rename (`default` → `ask`)

- `"default"` → `"ask"` everywhere
- `MODE_CYCLE`: `["ask", "plan", "auto"]`
- `MODE_META` key: `"default"` → `"ask"` (icon `●` stays, or use `?`)
- `MODE_CONTEXT` key: `"default"` → `"ask"` with new semantics
- `pi.registerCommand("default", ...)` → register `/ask` as primary, optionally `/default` as alias
- All `currentMode === "default"` → `currentMode === "ask"`
- `--permission-mode` accepts both `"ask"` and `"default"` for backward compat

---

## 5. New logic: outside-cwd detection

Add to `utils.ts`:

```typescript
import path from "node:path"

export function isOutsideCwd(targetPath: string, cwd: string): boolean {
  const resolved = path.resolve(cwd, targetPath)
  const cwdAbs = path.resolve(cwd)
  return !resolved.startsWith(cwdAbs + path.sep) && resolved !== cwdAbs
}

export function commandTargetsOutsideCwd(command: string, cwd: string): boolean {
  if (/cd\s+\.\./.test(command)) return true
  const absPaths = command.match(/(?:\/[\w.\-]+)+/g)
  if (absPaths) {
    for (const p of absPaths) {
      if (isOutsideCwd(p, cwd)) return true
    }
  }
  if (/\$HOME|~/.test(command) && !command.includes('~/.pi')) return true
  if (/\.\.\/|\b\.\.\b/.test(command)) return true
  return false
}
```

Used in the `tool_call` gate:
- **`ask` mode:** before auto-approving `read`, check `isOutsideCwd` → prompt if outside
- **`auto` mode:** before auto-approving `edit`/`write` or destructive `bash`, check `isOutsideCwd` → prompt if outside

---

## 6. Plan mode code-generation guard

Already blocks `edit`/`write`. New additions:
1. Tightened context injection (see §2.2).
2. Read access expanded to outside-cwd (via modified `applyToolRestrictions()`).
3. `PLAN_DISABLED` stays `new Set(["edit", "write"])`.

---

## 7. Mode cycle & UI changes

**Cycle:** `ask → plan → auto → ask` (was `default → plan → accept-edits → auto → default`)

**Status pill:**

| Mode | Icon | Label | Role |
|---|---|---|---|
| ask | `●` or `?` | Ask | `muted` |
| plan | `⏸` | Plan | `warning` |
| auto | `▶` | Auto | `accent` |

Footer structure unchanged. Working indicator only has 3 frames.

---

## 8. Persistence & backward compatibility

Restoring from old session entries:

```typescript
let m = last.data.currentMode
if (m === "normal") m = "default"     // legacy (v0.x)
if (m === "default") m = "ask"        // v1.0.0 → v1.1.0 rename
if (m === "accept-edits") m = "ask"   // removed mode → fall back to ask
if ((MODE_CYCLE as string[]).includes(m)) currentMode = m
```

`--permission-mode` flag: accept `"ask"` and `"default"` (with deprecation warning for `"default"`).

---

## 9. Files to modify

| File | Changes |
|---|---|
| `package.json` | Bump to `1.1.0`; update description |
| `index.ts` | Major refactor: rename `default`→`ask`, remove `accept-edits`, add outside-cwd logic, rewrite `MODE_CONTEXT`, update `tool_call` gate |
| `utils.ts` | Add `isOutsideCwd()`, `commandTargetsOutsideCwd()` |
| `docs/PRD.md` | Update mode definitions, add outside-cwd semantics |
| `docs/suggestions.md` | This file — updated to reference external prompt files |
| `docs/prompts/ask-mode-prompts.md` | **NEW** — full prompt reference for Ask mode |
| `docs/prompts/plan-mode-prompts.md` | **NEW** — full prompt reference for Plan mode |
| `docs/prompts/auto-mode-prompts.md` | **NEW** — full prompt reference for Auto mode |
| `AGENTS.md` | Update mode names, cycle, invariants |
| `README.md` | Update mode table, cycle description |

---

## 10. Risks & open questions

1. **Bash heuristic false positives** — `cd ../ && ls` flagged as outside-cwd even though read-only. Acceptable tradeoff (false prompt is safe).
2. **Bash heuristic false negatives** — `npm run build` spawning a script that writes to `../` is missed. Mitigation: conservative flagging.
3. **Backward compat** — old sessions with `accept-edits`/`default` must map gracefully (§8).
4. **Zero test infra** — strongly recommend adding tests for `isOutsideCwd()`, `commandTargetsOutsideCwd()`, and the `tool_call` gate decision tree.
5. **Symlinks** — `path.resolve()` doesn't resolve symlinks. Edge case accepted for v1.1.
6. **Multi-cwd** — `--cwd /project/src` vs project root `/project`. Accept for v1.1.

---

## 11. Phasing

- **v1.1.0 (this release):** 3-mode refactor, outside-cwd detection, mode rename, accept-edits removal. Auto-continue stays commented out.
- **v1.2.0 (future):** Re-enable auto-continue; add test suite; optional "project root" detection.
