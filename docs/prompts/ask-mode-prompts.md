# Ask Mode — Prompt Reference

> **Part of the v2.0.0 implementation.** Default permission mode (replaces v1.0.0's "default" mode).
> Corresponding `index.ts` constants: `MODE_CONTEXT["ask"]`, `MODE_META["ask"]`, `tool_call` gate case `"ask"`.

---

## 1. Mode metadata

```typescript
// MODE_META["ask"]
{ icon: "●", label: "Ask", role: "muted" }
```

- **Slash commands:** `/ask` (primary), `/default` (alias for backward compat)
- **Cycle position:** `ask → plan → auto → ask`
- **Flag:** `--permission-mode ask` (also accepts `--permission-mode default` with deprecation warning)

---

## 2. System context injection (`MODE_CONTEXT["ask"]`)

Injected into the agent's context window at the start of every turn via `before_agent_start`. Displayed to the model (not the user).

```
[ASK MODE ACTIVE]
Standard mode. File edits/writes and access outside the working directory
require explicit user approval before they run. Read-only operations inside
the working directory are auto-approved.
```

**Implementation:** `pi.on("before_agent_start", ...)` returns `{ message: { customType: "modes-context", content: [above], display: false } }`. Deduplication via `context` handler keeps only the latest instance.

---

## 3. UI confirmation prompts

All prompts use `ctx.ui.select(title, options)` when `ctx.hasUI` is true.

**No-UI behavior (fail-closed, never silently allowed):**

| Condition | Action |
|---|---|
| `!ctx.hasUI` and no `PI_SUBAGENT_PARENT_SESSION` | Block with `needs approval: no UI available` |
| `!ctx.hasUI` and `PI_SUBAGENT_PARENT_SESSION` set | Forward ask to parent session UI via `permission-modes-forwarding` inbox; parent Allow / Allow always / Block; timeout or deny → block |

Local ask-mode `edit`/`write` with UI still offers the five-option dialog (including bypass). Forwarded asks use the shared four-option set only (no bypass).

### 3a. edit/write approval

| Field | Value |
|---|---|
| **Trigger** | `tool === "edit"` **or** `tool === "write"` |
| **Path check** | Any path (no outside-cwd distinction for writes — always prompt) |
| **Title** | `` `Allow ${tool} on ${path}?` `` |
| **Options** | `["Allow", "Allow all (enable auto)", "Block"]` |
| **Default** | (none — user must pick) |

**Behavior per option:**

| Choice | Action |
|---|---|
| `"Allow"` | Return `undefined` (allow the tool call) |
| `"Allow all (enable auto)"` | Call `setMode("auto", ctx)` + return `undefined` |
| `"Block"` | Return `{ block: true, reason: \`${tool} blocked by user on ${path}\` }` |

**No-UI fallback:** without parent session → `{ block: true, reason: \`${tool} blocked: no UI available to confirm.\` }` (via `promptApproval` / forwarding path: `needs approval: no UI available` or parent timeout/deny). With `PI_SUBAGENT_PARENT_SESSION`, forward to parent (four options; no bypass).

### 3b. read-outside-cwd approval (NEW in v1.1.0)

| Field | Value |
|---|---|
| **Trigger** | `tool === "read"` **AND** `isOutsideCwd(path, ctx.cwd) === true` |
| **Title** | `` `Allow read outside cwd: ${path}?` `` |
| **Options** | `["Allow", "Block"]` |

**Behavior:**

| Condition | Action |
|---|---|
| Inside cwd (`isOutsideCwd === false`) | Auto-approve (return `undefined`) |
| Outside cwd, user picks `"Allow"` | Return `undefined` |
| Outside cwd, user picks `"Block"` | Return `{ block: true, reason: \`read blocked by user on ${path} (outside cwd)\` }` |
| No UI | `{ block: true, reason: \`read blocked: no UI available to confirm.\` }` |

### 3c. destructive bash approval

Same as v1.0.0 — carried forward unchanged.

| Field | Value |
|---|---|
| **Trigger** | `tool === "bash"` **AND** `isSafeCommand(cmd) === false` |
| **Title** | `` `Allow "${cmd}"?` `` |
| **Options** | `["Allow", "Block"]` |

| Condition | Action |
|---|---|
| Safe command | Auto-approve (return `undefined`) |
| Unsafe, user picks `"Allow"` | Return `undefined` |
| Unsafe, user picks `"Block"` | Return `{ block: true, reason: \`bash blocked by user\` }` |
| No UI | `{ block: true, reason: \`bash blocked: no UI available to confirm.\` }` |

---

## 4. Decision tree (tool_call gate pseudocode)

```
if currentMode === "ask":
  if tool === "edit" || tool === "write":
    prompt 3a (edit/write approval)
  elif tool === "read":
    if isOutsideCwd(path, ctx.cwd):
      prompt 3b (read-outside-cwd approval)
    else:
      auto-approve
  elif tool === "bash":
    if isSafeCommand(cmd):
      auto-approve
    else:
      prompt 3c (destructive bash approval)
  else:
    auto-approve (other tools)
```

---

## 5. Related code locations

| What | File | Line area |
|---|---|---|
| `MODE_CONTEXT["ask"]` | `index.ts` | In the `MODE_CONTEXT` record definition |
| `MODE_META["ask"]` | `index.ts` | In the `MODE_META` record definition |
| edit/write prompt | `index.ts` | `tool_call` handler — `currentMode === "ask"` branch |
| read-outside-cwd prompt | `index.ts` | `tool_call` handler — `currentMode === "ask"` branch (NEW) |
| `isOutsideCwd()` | `utils.ts` | New helper for v1.1.0 |
