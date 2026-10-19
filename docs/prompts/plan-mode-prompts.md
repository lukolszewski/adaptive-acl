# Plan Mode — Prompt Reference

> **Part of the v2.0.0 implementation.** Refocused plan-writing mode.
> Corresponding `index.ts` constants: `MODE_CONTEXT["plan"]`, `MODE_META["plan"]`, `tool_call` gate case `"plan"`, `agent_end` handler.

---

## 1. Mode metadata

```typescript
// MODE_META["plan"]
{ icon: "⏸", label: "Plan", role: "warning" }
```

- **Slash commands:** `/plan`
- **Cycle position:** `ask → plan → auto → ask`
- **Flag:** `--permission-mode plan`

---

## 2. System context injection (`MODE_CONTEXT["plan"]`)

Injected into the agent's context window at the start of every turn. **Updated wording for v1.1.0** — explicitly forbids code generation.

```
[PLAN MODE ACTIVE]
You are in plan-writing mode. The edit and write tools are disabled and destructive
shell commands are blocked. You MAY read files and run read-only commands both inside
and outside the working directory to gather context.

Do NOT write any code. Only produce a detailed, numbered plan in markdown format
under a "Plan:" header.

Plan:
1. First step
2. Second step
...

Do not include runnable code, scripts, or implementation. Describe what would be done.
```

**Key differences from v1.0.0:**
- No longer says "read-only exploration mode" — explicitly says "plan-writing mode"
- Adds: "Do NOT write any code. Only produce a detailed, numbered plan in markdown format"
- Adds: "Do not include runnable code, scripts, or implementation"
- Read access is explicitly allowed outside cwd (so the agent can gather context)

---

## 3. Tool restrictions

### 3a. Blocked tools (`PLAN_DISABLED`)

```typescript
const PLAN_DISABLED = new Set(["edit", "write"])
```

Applied via `applyToolRestrictions()`: tools are stripped from `pi.setActiveTools()` so the model cannot even call them.

### 3b. Bash restrictions

| Condition | Action |
|---|---|
| `isSafeCommand(cmd) === true` | Allowed (return `undefined`) |
| `isSafeCommand(cmd) === false` | **Blocked** |

**Block reason message:**
```
Plan mode: read-only commands only. Use /plan to exit plan mode first.
  Command: ${cmd}
```

Read-only bash is allowed even when targeting paths outside cwd (the agent needs to inspect the environment to write a good plan).

### 3c. Read tool

Read is fully allowed — no restrictions inside or outside cwd. The agent needs full visibility to plan effectively.

---

## 4. UI prompts

### 4a. Plan-ready prompt (after agent finishes in plan mode)

| Field | Value |
|---|---|
| **Trigger** | `agent_end` event, `currentMode === "plan"`, plan extracted from last assistant message |
| **Title** | `"Plan ready — what next?"` |
| **Options** | `["Execute the plan", "Stay in plan mode", "Refine the plan"]` |
| **Source** | `agent_end` handler in `index.ts` |

**Behavior per option:**

| Option | Action |
|---|---|
| `"Execute the plan"` | Switch mode to `auto`, restore full tool access, send follow-up message with plan steps + `[DONE:n]` instructions |
| `"Stay in plan mode"` | Do nothing — agent can continue exploring/refining |
| `"Refine the plan"` | Open editor (see 4b) |

### 4b. Plan refinement editor

| Field | Value |
|---|---|
| **Trigger** | User selects "Refine the plan" |
| **Method** | `ctx.ui.editor("Refine the plan:", "")` |
| **Action on submit** | If non-empty, the content is sent as a user follow-up message |

### 4c. Plan execution follow-up message

Sent as a follow-up when user chooses "Execute the plan":

```
Execute the plan now. Steps:
1. First step
2. Second step
...

Start with step 1. After finishing each step, include a [DONE:n] tag in your reply.
```

Sent via `pi.sendMessage(..., { triggerTurn: true, deliverAs: "followUp" })`.

### 4d. Plan complete notification

Broadcast when all plan steps are marked complete (all `[DONE:n]` tags received):

```
**Plan Complete! ✓**
```

Sent via `pi.sendMessage({ customType: "plan-complete", content: ... , display: true }, { triggerTurn: false })`.

---

## 5. Decision tree (tool_call gate pseudocode)

```
if currentMode === "plan":
  if tool === "edit" || tool === "write":
    BLOCK (tools are stripped — should never reach here)
  elif tool === "bash":
    if isSafeCommand(cmd):
      auto-approve
    else:
      block with message 3b
  else:
    auto-approve (read and other tools)
```

## 6. Plan extraction & tracking

| Concern | Implementation | Location |
|---|---|---|
| Extract numbered items under `Plan:` header | `extractTodoItems(message)` | `utils.ts` |
| Track `[DONE:n]` tags | `markCompletedSteps(text, items)` | `utils.ts` |
| Detect completion | `isCompletionSignal(text)` | `utils.ts` |
| Widget display | `updatePlanWidget(ctx)` — ☐/☑ per step | `index.ts` |

---

## 7. Related code locations

| What | File | Line area |
|---|---|---|
| `MODE_CONTEXT["plan"]` | `index.ts` | `MODE_CONTEXT` record — updated wording |
| `MODE_META["plan"]` | `index.ts` | `MODE_META` record — unchanged |
| Tool restrictions | `index.ts` | `PLAN_DISABLED`, `applyToolRestrictions()` |
| bash block | `index.ts` | `tool_call` handler — `currentMode === "plan"` branch |
| Plan-ready prompt | `index.ts` | `agent_end` handler — plan mode branch |
| Refinement editor | `index.ts` | `agent_end` handler — `"Refine the plan"` choice |
| Execution message | `index.ts` | `agent_end` handler — `"Execute the plan"` choice |
| `extractTodoItems()` | `utils.ts` | — |
| `markCompletedSteps()` | `utils.ts` | — |
| `isCompletionSignal()` | `utils.ts` | — |
