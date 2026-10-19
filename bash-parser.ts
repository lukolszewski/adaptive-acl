/**
 * bash-parser.ts — a licensed bash grammar for the gate's layer 0.
 *
 * Thin, self-written wrapper around two MIT packages:
 *   `web-tree-sitter`  (wasm tree-sitter runtime, pinned 0.27.1)
 *   `tree-sitter-bash` (grammar, 0.25.1, ABI 15 — accepted by this runtime)
 *
 * This module owns exactly one job: turn a command string into a tree-sitter
 * `Tree`, or into a reason we did not get one. It has no opinion about what the
 * command *means*; the walker lives on top of the tree it hands back.
 *
 * ---------------------------------------------------------------------------
 * Where the grammar wasm comes from (decision)
 * ---------------------------------------------------------------------------
 * `tree-sitter-bash` is NOT a runtime dependency. Its npm tarball is ~20 MB
 * (native prebuilds for 6 platforms) of which we need one 1.33 MB file, and its
 * `install` script runs `node-gyp-build` — a compile step we do not want in
 * pi's `npm install` path. So the grammar ships as **one wasm blob checked in at
 * `wasm/tree-sitter-bash.wasm` next to its MIT notice
 * `wasm/LICENSE-tree-sitter-bash`**, and `wasm/` is in the package `files` list.
 *
 * Resolution order for the grammar, both rooted at `import.meta.url` so it works
 * from an installed location (`~/.pi/agent/npm/node_modules/@georgedong32/
 * permission-modes/`) and not just from a checkout with a given cwd:
 *   1. `./wasm/tree-sitter-bash.wasm` next to this file — the shipped path.
 *   2. `tree-sitter-bash/tree-sitter-bash.wasm` in the nearest `node_modules`
 *      (a dev checkout that ran `npm install --no-save tree-sitter-bash`).
 * The bytes are read with `readFileSync` and handed to `Language.load` as a
 * `Uint8Array`, so nothing depends on how emscripten's own path resolution
 * behaves under jiti.
 *
 * That first candidate is the whole contract between this file and
 * `package.json`'s `files`: `wasm/**` ships, the grammar sits beside the module.
 * Nothing else in a checkout would notice if it stopped, because every other
 * test resolves from the working tree — so `bash-parser-availability.test.ts`
 * stages the artifact the way `npm pack` would and loads the grammar from the
 * staged copy, and {@link bashParserStatus} reports which file was loaded.
 *
 * `web-tree-sitter` stays a real runtime `dependency`: pi's extension loader
 * installs it and its JS is what we import. Its own `web-tree-sitter.wasm` is
 * located explicitly through `Parser.init({ locateFile })` — the default
 * resolution happens to work in node, but it goes through emscripten's
 * `scriptDirectory` guess, which is exactly the kind of thing that breaks under
 * a transpiler. The core wasm is NOT copied; it comes from the dependency.
 *
 * ---------------------------------------------------------------------------
 * 0.27 API notes (verified against node_modules/web-tree-sitter typings and
 * measured on node 24 — do not "simplify" these without re-measuring)
 * ---------------------------------------------------------------------------
 * - The module has **no default export**: `{ Parser, Language }` are named.
 * - `Parser.init()` is a one-shot emscripten bootstrap (~10–16 ms measured,
 *   repeated calls resolve to the same module). It must precede `new Parser()`.
 * - `Language.load()` accepts a path string, a `URL` or a `Uint8Array`.
 * - `Parser#parse(src, oldTree, { progressCallback })` — the callback is called
 *   periodically *during* the parse (roughly every few hundred bytes of input;
 *   coarser on inputs the error recoverer is chewing on). Returning a truthy
 *   value cancels. The typings declare the return as `void`, so the `true` is
 *   the documented runtime contract, not a typed one. A cancelled parse returns
 *   `null` **and leaves the parser positioned mid-document**, so every cancel
 *   path here calls `reset()` before the next parse.
 * - There is no per-node hook, so the node cap can only be a **post-parse walk**
 *   (`countTreeNodes`): the tree exists by the time we can count it, so the cap
 *   rejects the tree rather than saving the parse budget. Measured cost of the
 *   JS cursor walk: ~4 ms for a 20 000-node tree, microseconds for a real
 *   command. (`Tree`'s `rootNode.descendantCount` returns the same number from
 *   native code in ~0.01 ms but cannot stop early; the cap is the point, so we
 *   walk with a cursor.)
 * - `startIndex`/`endIndex` are **JS string (UTF-16) indices**, not UTF-8 byte
 *   offsets — `src.slice(node.startIndex, node.endIndex)` is the node's text.
 *   Pinned by a test with non-ASCII content.
 * - Trees, nodes and cursors are wasm-side. A `Tree` handed back to the caller
 *   may be released with `tree.delete()`; if the caller does not, web-tree-sitter
 *   frees it through a `FinalizationRegistry` on GC.
 *
/* ---------------------------------------------------------------------------
 * Limits — and the one distinction that matters: "too slow" vs "cannot tell"
 * ---------------------------------------------------------------------------
 * Three limits stop a parse. Two of them are properties of the input and decide the same verdict on
 * every machine; one of them is a property of the machine and can never be allowed to authorise
 * anything. They are kept apart in the code (`ParseCost.stop` is `"input"` or `"wall-clock"`) and the
 * retry is taken only for the machine-shaped one.
 *
 * - `MAX_COMMAND_CHARS` 10 000 — *cannot tell*. A longer string is never handed to the parser
 *   (`too-large`). Real bash tool calls are far below this: 6 of the 11 642 distinct commands measured
 *   below exceed it, and they are refused without being parsed.
 * - `MAX_TREE_NODES` 50 000 — *cannot tell*, checked after the parse (`aborted`). With the character
 *   ceiling this is a backstop rather than a reachable limit: the densest 10 000-character command
 *   found in measurement (`a;` × 5000) yields 20 001 nodes, ~2.0 nodes/char.
 * - `PARSE_TIMEOUT_MS` 300 per call, `PARSE_ATTEMPTS` 2 — *too slow*, i.e. an environment statement.
 *   Enforced inside the progress callback: a synchronous parse cannot be interrupted from outside, so
 *   the deadline is only checked when tree-sitter calls us back, and one callback can overshoot (see
 *   the measurement below). Envelope, not per attempt: each attempt guards 150 ms and the call never
 *   exceeds 300 ms however many attempts it makes.
 *
 * Why the progress callback is *not* used as a work budget, even though it would be deterministic:
 * measured with the time guard frozen off (`spike/pi/w53-steps.ts`), a callback is not a quantum of
 * work. `a;` × 5000 takes 502 callbacks and 16 ms; `;a` × 5000 takes 302 callbacks and 700 ms. Same
 * order of callbacks, 40x the time, because the error recoverer does its work between callbacks. Real
 * input uses 0–16 callbacks (p50 0, p99 4) and the densest legal command uses 502, so any callback
 * budget low enough to catch a runaway is close enough to real input to refuse real input. The step
 * count is reported in `ParseCost` as a diagnostic and is not a limit.
 *
 * ---------------------------------------------------------------------------
 * The measurement the 300 ms comes from (`eval/parse-latency.ts`, node 24, 32 CPUs)
 * ---------------------------------------------------------------------------
 * 11 642 distinct command strings — every golden case, every curated case-file command and every
 * distinct bash command in the live session store — parsed 4 times each (46 568 parses per row). One row
 * per contention level, all from one run of the shipped code:
 *
 *   spinners   p50    p90    p95    p99    p99.9   max      over 50 ms   over 150 ms
 *   idle       0.03   0.07   0.09   0.14   0.27     1.20        0             0
 *   48         0.05   0.12   0.16   0.77   4.37    16.1         0             0
 *   96         0.05   0.12   0.17   5.42  16.0     32.9         0             0
 *   192        0.05   0.13   0.18   9.21  36.1     75.8         8             0
 *   384        0.05   0.13   0.18  37.1   84.1    121         297             0     (12x oversubscription)
 *
 * Two readings, and both matter. The work does not move with load — the same inputs take 0-16 progress
 * callbacks whatever else is running — so the entire right-hand tail is scheduling and GC, not parsing.
 * And the old 50 ms budget sat *inside* that tail: it cut off 8 real parses per 46 568 at 192 spinners
 * and 297 at 384, which is the flake, and is why a golden case could fail in a full suite and every
 * corpus count in this repo's notes drifted with the machine. No real parse in any row exceeded 150 ms,
 * so the shipped window (150 ms per attempt, 300 ms per call) decides verdicts on the input and leaves
 * the machine out of it: ~120x the measured p99 under 12x oversubscription, ~300x the idle maximum.
 *
 * Worst case a gated bash call can spend here: the walker parses the input once and the heredoc mask
 * re-parses twice (`bash-walker-heredoc.ts` maskedCopy), so <= 3 calls x 300 ms = 0.9 s — reachable only
 * by a 10 000-character pathological command on a machine >= 300x slower than measured, where real input
 * still costs 0.03 ms. A port that runs this behind a hook deadline must keep that inequality inside
 * `hook.deadlineMs` (D17: child timeout < hook.deadlineMs < host timeoutSec).
 */

import { existsSync, readFileSync } from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Language, Parser, type Tree } from "web-tree-sitter"

/** Commands longer than this are not parsed at all. */
export const MAX_COMMAND_CHARS = 10_000
/**
 * Wall-clock budget for one {@link parseBash} call, across every attempt it makes.
 *
 * 300 ms, from `eval/parse-latency.ts` over 11 642 real commands (the golden corpus, the curated case
 * files and every distinct bash command in the live session store): p50 0.03 ms, p99 0.14 ms, p99.9
 * 0.27 ms, **max 1.20 ms** on an idle machine, and **max 121 ms** with 384 CPU spinners running (12x
 * oversubscription on 32 cores). Not one parse in 46 568 went over 150 ms at any contention level
 * measured — see the table below, which is the justification for this number and not a decoration.
 */
export const PARSE_TIMEOUT_MS = 300
/**
 * Attempts one call gets. The second attempt is taken **only** when the first ended in an environment
 * abort, and it does not add to the wall-clock budget: {@link PARSE_TIMEOUT_MS} is the envelope for
 * the whole call, so each attempt guards `PARSE_TIMEOUT_MS / PARSE_ATTEMPTS` (150 ms) and the worst
 * case per call is unchanged at 300 ms.
 *
 * Why retry at all when the envelope is 320x the measured cost of real input: the observed failure was
 * a pause, not slow work — W47 measured a 322-character golden case at 7.6 ms cold, under 1 ms warm and
 * 99 ms under 48-way contention. One transient scheduling or GC pause inside a parse is enough to
 * decide a verdict under a wall-clock budget, and a pause does not repeat itself. A retry costs one
 * more window on a machine that is genuinely too slow (where it fails closed again), and buys the
 * deterministic verdict on a machine that hiccuped.
 */
export const PARSE_ATTEMPTS = 2
/** Trees bigger than this are rejected after the parse. */
export const MAX_TREE_NODES = 50_000

/** The wall-clock window one attempt guards, before the call's envelope applies. */
const ATTEMPT_WINDOW_MS = PARSE_TIMEOUT_MS / PARSE_ATTEMPTS

export type BashParseResult =
  | { tree: Tree }
  | {
      error: "not-initialised" | "too-large" | "aborted" | "parse-failed"
      detail?: string
    }

type Live = { parser: Parser; language: Language }

/**
 * The §12 id for "this process has no parser" (`docs/LAYER0-WALKER-SPEC.md` §12.3, §12.4: it describes the
 * process, never the command). `bash-walker.ts` owns the vocabulary and emits this id when `parseBash` reports
 * `not-initialised`; it is repeated here because this module is the layer *below* the walker and cannot import
 * from it. {@link PARSER_UNAVAILABLE_REASON} and the walker are pinned equal by `bash-parser-availability.test.ts`,
 * so a rename on either side is a red test rather than two vocabularies for one event.
 */
export const PARSER_UNAVAILABLE_REASON = "parser-unavailable"

/**
 * What a refusal carrying this id means, in one sentence, written for the person who is being denied.
 *
 * The wording is the deliverable, not decoration: the alternative text for an unproven command — "cannot verify
 * command structure", "rewrite as plain sequential commands without brace groups" — tells the reader their
 * command was too clever, when in fact the analyzer never looked at it. One unavailable grammar makes *every*
 * bash command unprovable (`bash-parser-availability.test.ts` pins that for a literal `cat`), so a message that
 * reads as a property of the command sends the user to rewrite a command that was never the problem.
 */
const ANALYZER_DOWN =
  "the bash analyzer is not running in this process, so no bash command can be verified — this is a fault in the analyzer, not in the command"

/** The same distinction for the two states that are not a fault, where "start the analyzer" is the fix. */
const ANALYZER_LOADING = "the bash analyzer is still loading its grammar; layer 0 is not deciding bash yet"
const ANALYZER_NOT_STARTED = "the bash analyzer was never started in this process; layer 0 is not deciding bash yet"

/** How far {@link bashParserStatus} reports a grammar path. */
export type BashParserState =
  /** Grammar loaded; `parseBash` can run synchronously and layer 0 is deciding commands. */
  | "ready"
  /** `initBashParser()` is in flight; every parse until it lands is refused {@link PARSER_UNAVAILABLE_REASON}. */
  | "initialising"
  /** Init was attempted and failed. It is not retried in this process (see {@link disposeBashParser}). */
  | "failed"
  /** Nothing has called {@link initBashParser} in this process yet. */
  | "untried"

/**
 * Whether layer 0 is actually running, as a fact a caller or a test can ask for.
 *
 * Before this existed the only signal was `parseBash` returning `not-initialised` for every command, which is
 * indistinguishable from "the command was too clever": the same eight commands measured with and without
 * `initBashParser()` differ only in the reason string, so a wasm that fails to load (a wrong path after a
 * packaging change, a different runtime, a missing file) looks like a stricter gate and is really a dead one.
 */
export type BashParserStatus = {
  state: BashParserState
  /** True only when `state === "ready"` — the one state in which a tier decision is being made. */
  available: boolean
  /** Why init failed — non-null exactly when `state === "failed"`. */
  loadError: string | null
  /** The wasm file the grammar was loaded from, once `ready` — the fact a packaging bug is caught by. */
  grammar: string | null
  /** One sentence for a human, worded for the state. Never blames the command. Empty when `available`. */
  notice: string
}

/**
 * What one {@link parseBash} call cost, for probes and `/status`. A parse can stop for two different
 * reasons and they must not be confused: the machine ran out of time (`stop: "wall-clock"`, which
 * depends on what else the CPU was doing) or the input is beyond what this module parses
 * (`stop: "input"`, which is a property of the string). `steps` is a diagnostic, not a budget —
 * see the "why the progress callback is not a budget" note in the header.
 */
export type ParseCost = {
  /** Progress callbacks observed across every attempt. */
  steps: number
  /** Wall-clock milliseconds spent, including every attempt. */
  ms: number
  /** Parses attempted: 1 normally, 2 only when the first ended in an environment abort. */
  attempts: number
  /** Why the call ended: environment, input, or null when a tree came back. */
  stop: "wall-clock" | "input" | null
}

const IDLE_COST: ParseCost = { steps: 0, ms: 0, attempts: 0, stop: "input" }

/** Non-null once init succeeded; the only signal `isBashParserReady` uses. */
let live: Live | null = null
/** Why init failed, kept for the `not-initialised` detail and for the log line. */
let initFailure: string | null = null
/** In-flight init, so concurrent callers share one bootstrap. */
let boot: Promise<void> | null = null
/** Where the grammar bytes came from; the packaged-layout path, once loaded. */
let grammarFile: string | null = null
/** Cost of the last parse; see {@link lastParseCost}. */
let lastCost: ParseCost = IDLE_COST
/** The one warning a failed init produced, until a host drains it; see {@link takeBashParserWarning}. */
let pendingWarning: string | null = null

/**
 * Say it once, loudly.
 *
 * The plugin's warning channel outside `index.ts` is `console.warn` with the `[permission-modes]` prefix —
 * `config.ts`, `profiles.ts`, `permissions-loader.ts` and `utils.ts` all use it, each firing once per distinct
 * problem — because a parse failure repeats on every tool call and a log full of one line teaches nobody
 * anything. `debugLine` is not enough here: it is gated on `PERMISSION_MODES_DEBUG`, and the whole point is that
 * the failure is invisible to a user who has no reason to set a debug variable.
 *
 * Once per failed initialization, which is what the invariant needs: init is attempted once per process (see
 * {@link initBashParser}), so a dead grammar produces exactly one line, and {@link disposeBashParser} clears the
 * flag on purpose so a host that deliberately retries and fails again is told about that too.
 */
function announceFailure(line: string): void {
  pendingWarning ??= line
  console.warn(`[permission-modes] ${line}`)
}

/**
 * The warning a failed grammar load produced, or null. Drained on read so a host that surfaces it in the UI
 * does so once per process; stderr already got the same line at the moment of failure, which is what keeps a
 * headless (no-UI) child loud rather than silent.
 */
export function takeBashParserWarning(): string | null {
  const line = pendingWarning
  pendingWarning = null
  return line
}

/**
 * Cost of the most recent {@link parseBash} in this process. Diagnostic only: no verdict reads it,
 * and it is overwritten by the next call (`parseBash` is synchronous, so nothing interleaves inside
 * one call). Read it to tell "this machine could not do the work in time" (`stop: "wall-clock"`,
 * `attempts: 2`) from "this input is not something we parse" (`stop: "input"`).
 */
export function lastParseCost(): ParseCost {
  return lastCost
}

function debugLine(text: string): void {
  if (process.env.PERMISSION_MODES_DEBUG) console.error(`[permission-modes] ${text}`)
}

function reasonOf(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}

/** Directory containing this module (works under jiti; not cwd-dependent). */
function moduleDir(): string {
  return path.dirname(fileURLToPath(import.meta.url))
}

/** Nearest `node_modules/<name>` root, resolved from this file, or null. */
function packageDir(name: string): string | null {
  try {
    const req = createRequire(import.meta.url)
    return path.dirname(req.resolve(`${name}/package.json`))
  } catch {
    // Older resolvers refuse the subpath; fall back to the bare specifier.
    try {
      const req = createRequire(import.meta.url)
      return path.dirname(path.dirname(req.resolve(name)))
    } catch {
      return null
    }
  }
}

/** Grammar wasm candidates, first hit wins. See the header decision. */
function grammarWasm(): { file: string; bytes: Uint8Array } {
  const candidates = [
    path.join(moduleDir(), "wasm", "tree-sitter-bash.wasm"),
  ]
  const dep = packageDir("tree-sitter-bash")
  if (dep) candidates.push(path.join(dep, "tree-sitter-bash.wasm"))

  for (const file of candidates) {
    if (existsSync(file)) return { file, bytes: new Uint8Array(readFileSync(file)) }
  }
  throw new Error(
    `tree-sitter-bash.wasm not found (looked in ${candidates.join(", ")})`,
  )
}

/** Core runtime wasm, from the `web-tree-sitter` dependency (never copied). */
function coreWasmOptions(): Record<string, unknown> {
  const dep = packageDir("web-tree-sitter")
  const file = dep ? path.join(dep, "web-tree-sitter.wasm") : null
  if (!file || !existsSync(file)) return {} // let emscripten try on its own
  return { locateFile: () => file }
}

async function bootstrap(): Promise<void> {
  const started = Date.now()
  try {
    await Parser.init(coreWasmOptions())
    const { file, bytes } = grammarWasm()
    const language = await Language.load(bytes)
    const parser = new Parser()
    parser.setLanguage(language)
    live = { parser, language }
    grammarFile = file
    debugLine(`bash parser ready (${Date.now() - started} ms) from ${file}`)
  } catch (err) {
    live = null
    grammarFile = null
    initFailure = reasonOf(err)
    debugLine(`bash parser unavailable: ${initFailure}`)
    // Every bash command in this session is now unverifiable, and nothing else will ever say so.
    announceFailure(
      `bash analyzer is DOWN — ${ANALYZER_DOWN} (${initFailure}). Layer 0 will report every bash command as ` +
        `"${PARSER_UNAVAILABLE_REASON}"; the grammar was looked for next to bash-parser.ts in wasm/.`,
    )
  }
}

/**
 * One-time setup. Idempotent, safe to call concurrently, never throws: on
 * failure the reason is recorded and the parser stays unavailable
 * (`parseBash` → `not-initialised`, `isBashParserReady()` → false).
 */
export async function initBashParser(): Promise<void> {
  if (live || initFailure) return
  boot ??= bootstrap().then(() => {
    boot = null
  })
  await boot
}

/** True when the grammar is loaded and `parseBash` can run synchronously. */
export function isBashParserReady(): boolean {
  return live !== null
}

/** {@link BashParserStatus.available} on its own, for callers that only branch on it. */
export function bashParserAvailable(): boolean {
  return live !== null
}

/**
 * Whether layer 0 is running, in which state, and what to tell a human about it.
 *
 * `available === false` is not one condition and must not be reported as one: `initialising` resolves itself in
 * milliseconds, `untried` means the host never booted the grammar, and `failed` means the grammar cannot be
 * loaded in this process at all. All three make every bash command come back
 * {@link PARSER_UNAVAILABLE_REASON}, which is exactly why the distinction needs a name — see the measurement in
 * `bash-parser-availability.test.ts`.
 */
export function bashParserStatus(): BashParserStatus {
  if (live) {
    return { state: "ready", available: true, loadError: null, grammar: grammarFile, notice: "" }
  }
  const state: BashParserState = initFailure ? "failed" : boot ? "initialising" : "untried"
  return {
    state,
    available: false,
    loadError: initFailure,
    grammar: null,
    notice: initFailure ? `${ANALYZER_DOWN} (${initFailure})` : boot ? ANALYZER_LOADING : ANALYZER_NOT_STARTED,
  }
}

/** Why init failed, if it did. Handy in deny messages and `/status`. */
export function bashParserInitError(): string | null {
  return initFailure
}

/**
 * Does this §12 reason describe the analyzer rather than the command?
 *
 * The distinction is load-bearing wherever a refusal turns into advice. `variable-expansion`, `loop-body`,
 * `brace-group`, `command-substitution` all mean "we looked at your command and refused it", and the fix is a
 * rewrite; `parser-unavailable` means "nothing looked at your command" and a rewrite cannot help. Collapsing
 * them is how a dead analyzer reads as a strict one.
 */
export function isAnalyzerDownReason(reason: string | null | undefined): boolean {
  return reason === PARSER_UNAVAILABLE_REASON
}

/** The sentence for {@link isAnalyzerDownReason} reasons, with the load error appended when there is one. */
export function analyzerDownNotice(): string {
  const status = bashParserStatus()
  return status.loadError ? `${ANALYZER_DOWN} (${status.loadError})` : ANALYZER_DOWN
}

/**
 * Count tree nodes with a cursor, stopping as soon as `cap` is exceeded (the
 * return value is then `cap + 1`, which is all the caller needs to know). The
 * root counts as one node; anonymous tokens count.
 *
 * Exported because a caller that keeps a tree around may want to re-check its
 * size, and because the cap itself is otherwise untestable through
 * {@link parseBash} (see the limits note in the header).
 */
export function countTreeNodes(tree: Tree, cap = Number.MAX_SAFE_INTEGER): number {
  const cursor = tree.walk()
  let seen = 0
  let childrenDone = false
  try {
    for (;;) {
      if (!childrenDone) {
        seen += 1
        if (seen > cap) return seen
        if (cursor.gotoFirstChild()) continue
      }
      childrenDone = true
      if (cursor.gotoNextSibling()) {
        childrenDone = false
        continue
      }
      let climbed = false
      while (cursor.gotoParent()) {
        if (cursor.gotoNextSibling()) {
          climbed = true
          childrenDone = false
          break
        }
      }
      if (!climbed) return seen
    }
  } finally {
    cursor.delete()
  }
}

/**
 * Parse one bash command. Synchronous — everything expensive happened in
 * {@link initBashParser}. Fails closed: before init, over the size cap, over
 * the node cap, past the time budget, or if wasm throws, the caller gets an
 * `error` and never a half-tree.
 *
 * A returned tree may contain `ERROR`/`MISSING` nodes; that is *syntactic*
 * trouble, not a parse failure. Check `tree.rootNode.hasError` — the caller
 * decides what a broken parse means.
 */
export function parseBash(command: string): BashParseResult {
  const state = live
  if (!state) {
    lastCost = IDLE_COST
    return { error: "not-initialised", detail: initFailure ?? "initBashParser() has not run" }
  }
  if (command.length > MAX_COMMAND_CHARS) {
    lastCost = IDLE_COST
    return {
      error: "too-large",
      detail: `${command.length} characters, limit ${MAX_COMMAND_CHARS}`,
    }
  }

  const began = performance.now()
  // The envelope for the whole call, across every attempt. `Date.now` is the only clock the budget
  // reads, which is what lets a test drive the cap instead of racing it.
  const envelope = Date.now() + PARSE_TIMEOUT_MS
  const counted = { steps: 0 }
  let attempts = 0

  for (;;) {
    attempts += 1
    const guard = Math.min(Date.now() + ATTEMPT_WINDOW_MS, envelope)
    let slow = false
    let tree: Tree | null = null
    let thrown: string | null = null
    try {
      tree = state.parser.parse(command, null, {
        // Return value is honoured by tree-sitter (truthy = cancel) even though
        // the typings declare the callback `void`.
        progressCallback: () => {
          counted.steps += 1
          if (Date.now() > guard) {
            slow = true
            return true
          }
          return false
        },
      })
    } catch (err) {
      thrown = reasonOf(err)
    }
    // A cancelled or thrown parse leaves the parser positioned mid-document; it must be reset before
    // anything else is parsed on it, whether the next thing is a retry or a different command.
    if (tree === null) state.parser.reset()

    const cost = (): ParseCost => ({
      steps: counted.steps,
      ms: performance.now() - began,
      attempts,
      stop: "input",
    })

    if (thrown !== null) {
      lastCost = cost()
      return { error: "parse-failed", detail: thrown }
    }

    if (tree !== null) {
      const nodes = countTreeNodes(tree, MAX_TREE_NODES)
      if (nodes > MAX_TREE_NODES) {
        tree.delete()
        // Deterministic — a property of the input, never of the load — so it is never retried.
        lastCost = cost()
        return { error: "aborted", detail: `${nodes} nodes, limit ${MAX_TREE_NODES}` }
      }
      lastCost = { ...cost(), stop: null }
      return { tree }
    }

    if (!slow) {
      lastCost = cost()
      return { error: "parse-failed", detail: "parser returned no tree" }
    }

    // The attempt ran out of its window. That is the one verdict here that says something about the
    // machine rather than the command, so it gets the call's second attempt (bounded by the same
    // envelope) before it is believed.
    if (attempts < PARSE_ATTEMPTS && Date.now() < envelope) continue
    lastCost = { ...cost(), stop: "wall-clock" }
    return {
      error: "aborted",
      detail: `over ${ATTEMPT_WINDOW_MS} ms per attempt (${PARSE_TIMEOUT_MS} ms over ${PARSE_ATTEMPTS} attempts)`,
    }
  }
}

/**
 * Release the parser and forget the init state so a later
 * {@link initBashParser} starts over. Trees already handed out are not touched
 * (they are wasm-side and stay valid until the module unloads). Intended for
 * tests and for teardown, not for the request path.
 */
export function disposeBashParser(): void {
  const state = live
  live = null
  initFailure = null
  boot = null
  grammarFile = null
  pendingWarning = null
  if (!state) return
  try {
    state.parser.delete()
  } catch {
    // Already gone: nothing to release.
  }
  // `Language` has no delete() in web-tree-sitter 0.27.1; the grammar's wasm
  // instance is reclaimed with the module.
}
