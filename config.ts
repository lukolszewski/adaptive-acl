/**
 * Permission-modes extension config (`~/.pi/agent/permission-modes.json`, plus the
 * project-scoped `<cwd>/.pi/permission-modes.json`).
 * Pure fs helpers — no pi dependency.
 *
 * Two kinds of thing live here, deliberately kept apart:
 *  - `resolve*(config)` — pure resolvers: validate + default one hand-edited object.
 *  - `applyAuthorityLayers()` / `getAuthority*()` — the cached view of all three
 *    layers, so a hot path (footer render, approval callback) reads a field instead
 *    of re-reading and re-merging files. The getters allocate nothing.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import {
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"

import type { AutoModeRules } from "./classifier-prompt.ts"
import { DEFAULT_CONTEXT_TOKENS } from "./context-budget.ts"

export type ClassifierStage = "tool" | "single" | "fast" | "both" | "thinking"

export const CLASSIFIER_STAGE_SUFFIXES: readonly ClassifierStage[] = [
	"tool",
	"single",
	"fast",
	"both",
	"thinking",
] as const

export type ClassifierEngine = "gate" | "legacy"

// ---------------------------------------------------------- GitHub Copilot transport

/** pi's provider id for GitHub Copilot. `classifier.model` is `"<provider>/<id>"`, so this is what makes a
 *  ref a Copilot ref — the same string the model registry keys its catalog on. */
export const COPILOT_PROVIDER = "github-copilot"

/** GitHub's "Auto" is not a model: it is a policy that says *GitHub* picks, and the pick can change between
 *  sessions. It is reachable only through a session token (see `copilot-session.ts`), which is why it needs a
 *  sentinel of its own rather than being one more model id someone typed. */
export const COPILOT_AUTO_MODEL_ID = "auto"
export const COPILOT_AUTO_MODEL_REF = `${COPILOT_PROVIDER}/${COPILOT_AUTO_MODEL_ID}`

/** The efforts this transport will send. Anything else is refused at resolve time rather than forwarded to an
 *  endpoint that answers `400 Unsupported parameter` — the one error class we can prevent by not typing it. */
export type CopilotReasoningEffort = "low" | "medium" | "high"

export const COPILOT_REASONING_EFFORTS: readonly CopilotReasoningEffort[] = [
	"low",
	"medium",
	"high",
] as const

/** `classifier.copilot` — the knobs that exist only because Copilot behaves differently: it rejects
 *  `temperature`, it thinks before it answers, and it picks the model for you. */
export interface CopilotClassifierConfig {
	/** The answer reserve, i.e. the call's `max_output_tokens`. A reasoning model spends part of it on thinking
	 *  before one verdict character exists (measured: 192 of 269 output tokens on a one-line classification),
	 *  so this is the number that decides whether an answer arrives at all. Default 512. Too small is not a
	 *  shorter answer, it is NO answer — reported as a transport failure, never read as a verdict. */
	maxOutputTokens: number
	/** Sent as `reasoning.effort`, and only for a model the catalog says reasons. Default `"low"`: this call
	 *  gates one tool call, it does not solve a problem. */
	reasoningEffort: CopilotReasoningEffort
	/** Tokens this transport may spend per process before it stops asking; 0 (default) means no cap. A free
	 *  Copilot plan is a small monthly allowance shared with the user's own session, so spending it on gating is
	 *  a decision the owner makes, not a default. A spent budget is a transport failure, never a refusal. */
	budgetTokens: number
	/** Turn the Auto session off entirely. With it off, `github-copilot/auto` resolves to no endpoint at all —
	 *  the gate then asks a person instead of guessing at a model — which is how you leave every Copilot request
	 *  for the user's own chat. Default true. */
	sessionEnabled: boolean
}

/** Defaults chosen so a config with no `copilot` block behaves exactly as it did before this transport existed:
 *  nothing on the OpenAI-compatible path ever reads these values. */
export const DEFAULT_COPILOT_CLASSIFIER: CopilotClassifierConfig = {
	maxOutputTokens: 512,
	reasoningEffort: "low",
	budgetTokens: 0,
	sessionEnabled: true,
}

/** Which of the two Copilot cases a `classifier.model` names: GitHub picks (`auto`, the free-plan case this was
 *  built for) or the user picks (a paid-plan case, untestable from here and correct by construction).
 *  `undefined` means the ref is not Copilot at all. */
export type CopilotModelKind = "auto" | "explicit"

/** The thinking-level suffixes `classifier-client.ts` strips from a ref. Duplicated as data on purpose: importing
 *  the parser would give config.ts a dependency on the provider stack, and config.ts being pi-free is what lets a
 *  test resolve a config file without loading it. `classifier-client.test.ts` pins this list against the parser's. */
const THINKING_SUFFIXES: readonly string[] = [
	"thinking",
	"high",
	"medium",
	"low",
	"minimal",
	"xhigh",
	"off",
] as const

/** Strip the suffixes pi's own ref parser strips (`provider/id@stage`, `provider/id:low`) so one ref means the
 *  same thing here as it does on the call path — otherwise `github-copilot/auto@tool` would read as an explicit
 *  model id and go out without the session header its model needs. */
function bareModelId(ref: string): string {
	let id = ref.trim()
	const at = id.lastIndexOf("@")
	if (at > 0 && (CLASSIFIER_STAGE_SUFFIXES as readonly string[]).includes(id.slice(at + 1).toLowerCase())) {
		id = id.slice(0, at)
	}
	const colon = id.lastIndexOf(":")
	if (colon > 0 && THINKING_SUFFIXES.includes(id.slice(colon + 1).toLowerCase())) {
		id = id.slice(0, colon)
	}
	return id
}

export function copilotModelKind(modelRef: string): CopilotModelKind | undefined {
	const ref = (modelRef ?? "").trim()
	const slash = ref.indexOf("/")
	if (slash <= 0) return undefined
	if (ref.slice(0, slash) !== COPILOT_PROVIDER) return undefined
	const id = bareModelId(ref.slice(slash + 1))
	if (!id) return undefined
	return id === COPILOT_AUTO_MODEL_ID ? "auto" : "explicit"
}

export interface ClassifierConfig {
	enabled: boolean
	model: string
	timeoutMs: number
	/** v3 deterministic-policy + narrow-model gate ("gate", default) or the single-shot "ask one model the whole question" classifier ("legacy"). */
	engine?: ClassifierEngine
	/** Direct OpenAI-compatible endpoint override (bypasses pi's model registry). */
	baseUrl?: string
	/** Model id sent to baseUrl (defaults to the id part of `model`). */
	modelId?: string
	/** One JSON object per transcript block (`{"user":…}` / `{"Bash":…}`) instead of "User:" / "bash cmd" lines. */
	jsonlTranscript?: boolean
	/** When true (default), classifier errors deny the action instead of local fallback. */
	failClosed?: boolean
	/** Classifier pipeline — see docs/prompts/auto-mode-prompts.md. Default `tool`. */
	stage?: ClassifierStage
	/** Inject AGENTS.md / CLAUDE.md into classifier context. */
	includeAgentsMd?: boolean
	/** Authorisation ledger (whole-session grant memory, gate engine only). Default true. */
	ledger?: boolean
	/** Backfill cap: only the newest N user messages are ever extracted (default 400). */
	ledgerBackfillLimit?: number
	/** The model's context window in tokens; every classifier call is sized to fit it;
	 *  default 4096 — what `clf-gate` is served with. */
	contextTokens?: number
	/** Copilot-only behaviour (answer reserve, thinking effort, allowance cap, Auto session), always filled by
	 *  {@link resolveClassifierConfig}. Read ONLY on a `github-copilot/…` endpoint — nothing on the
	 *  OpenAI-compatible path looks at this field, so its defaults cannot change today's behaviour.
	 *  `classifier.baseUrl` still outranks the whole block: an explicit endpoint means "plain OpenAI-compatible,
	 *  bypass the registry", Copilot config included. */
	copilot?: CopilotClassifierConfig
}

/**
 * Where a standing "Allow always" answer is written down.
 *
 * - `"grants"` (default): the answer becomes a durable row in the grants journal
 *   (`grants-file.ts`), which is what lets a workspace run with **zero hand-authored
 *   permission files**. Revocation is `/grants revoke <value>`.
 * - `"rules"`: the answer becomes a permission rule in a `permissions*.json` file —
 *   the behaviour up to 2.7, and what an npm install that hand-edits rule files expects.
 *
 * This selects *where an answer is remembered*, never what was decided: the gate's
 * verdict for the call being approved is already fixed when this is consulted.
 */
export type AuthorityPersist = "grants" | "rules"

export const AUTHORITY_PERSIST_VALUES: readonly AuthorityPersist[] = [
	"grants",
	"rules",
] as const

/** `"grants"` — a deliberate default flip, not an accident of this file: the live
 *  workspace must work with no permission file at all. Anyone who depended on
 *  "Allow always" writing a rule line opts back with one key
 *  (`{ "authority": { "persist": "rules" } }`). `authority-config.test.ts` asserts the
 *  default, so changing it has to fail a test and then justify a CHANGELOG line.
 */
export const DEFAULT_AUTHORITY_PERSIST: AuthorityPersist = "grants"

export interface AuthorityConfig {
	/** Journal row or rule file — see {@link AuthorityPersist}. Default `"grants"`. */
	persist?: AuthorityPersist
}

/**
 * Who caused the live mode / unattended flag, so a footer can say *why* the session
 * is unattended instead of leaving the user to guess. Values are caller-owned ids —
 * the plan names `command`, `child-bridge`, `restore`, `plan-flow` — and config does
 * NOT police the vocabulary, only that each is a short non-empty string. Absent means
 * "nobody has told us", which the footer must render as such, never as a guess.
 */
export interface ConfigProvenance {
	modeSetBy?: string
	unattendedSetBy?: string
}

export type ProvenanceKey = keyof ConfigProvenance

export const PROVENANCE_KEYS: readonly ProvenanceKey[] = [
	"modeSetBy",
	"unattendedSetBy",
] as const

/** Provenance is a source id printed in a footer, not free text: a 10 kB value from a
 *  hand-edited file is a mistake, and a truncated one would be a lie. Rejected, loudly.
 */
export const MAX_SOURCE_CHARS = 64

/** The three layers, lowest precedence first — the same order
 *  `permissions-loader.ts` merges rules in (global → project → local). `runtime` is
 *  whatever the caller decided after start-up: a start flag, a dialog answer, a
 *  restored session row. */
export type ConfigLayerName = "user" | "project" | "runtime"

const LAYER_ORDER: readonly ConfigLayerName[] = [
	"user",
	"project",
	"runtime",
] as const

/** One object per layer the caller has. A layer that omits a key *inherits* it; a layer
 *  that sets a key to an unusable value is refused and reported, never honoured and
 *  never silently replaced by the default. */
export interface ConfigLayers {
	/** `~/.pi/agent/permission-modes.json`. */
	user?: PermissionModesConfig
	/** `<cwd>/.pi/permission-modes.json`. Rules are NOT read from here — see
	 *  {@link getProjectConfigPath} for why. */
	project?: PermissionModesConfig
	/** Start flags, dialog answers, restored state — highest. */
	runtime?: PermissionModesConfig
}

export interface AuthoritySnapshot {
	persist: AuthorityPersist
	/** Which layer supplied `persist`; `"default"` when no layer named it. */
	persistOrigin: ConfigLayerName | "default"
	/** Merged provenance — frozen, so a caller cannot corrupt the cached view. */
	provenance: ConfigProvenance
	/** Every value refused while merging, in layer order. Empty in the common case.
	 *  Exposed (and warned once on apply) so a bad value is never silent. */
	diagnostics: readonly string[]
}

/** The whole config file. Most keys keep their own resolver (`resolveClassifierConfig`,
 *  `resolveAutoModeConfig`, …); the layered view in this file resolves only
 *  `authority` and the two provenance keys, and ignores everything else. */
export interface PermissionModesConfig {
	classifier?: Partial<ClassifierConfig>
	/** Extra bullets appended to the classifier system prompt: allow / soft_deny / environment. */
	autoMode?: AutoModeRules
	/** Global permission rules — one of the two rule sources (the other is
	 *  `<cwd>/.pi/projects/<id>/permissions{,.local}.json`, both via
	 *  `permissions-loader.ts`). Not read by the layered view below. */
	permissions?: {
		allow?: string[]
		deny?: string[]
		ask?: string[]
	}
	/** Inject the tool-output prompt-injection warning (auto/bypass modes).
	 *  Default true. Governs the STANDING note sent on every auto/bypass call.
	 *  The heuristic-triggered strong warning is controlled separately by
	 *  `injectionEscalation` — see `resolveInjectionWarning`. */
	injectionWarning?: boolean
	/** Raise the strong injection warning when a tool output matches an
	 *  INJECTION_PATTERN. Default true; independent of `injectionWarning`,
	 *  because it is event-driven (near-zero steady-state cost) rather than
	 *  sent on every call. */
	injectionEscalation?: boolean
	/** Import a grants file at session start (merge, never replace).
	 *  Imported rows are lowest-precedence background authority. */
	grantsAutoImport?: { enabled?: boolean; path?: string }
	/** Predefined messages the user can send to the model at will (/msg). */
	messages?: Record<string, string>
	/** Where standing authority is stored. See {@link AuthorityPersist}. */
	authority?: AuthorityConfig
	/** Provenance of the live mode — caller-written, config only stores/validates/merges.
	 *  See {@link ConfigProvenance}. */
	modeSetBy?: string
	/** Provenance of the unattended flag. See {@link ConfigProvenance}. */
	unattendedSetBy?: string
}

/** Standing per-call injection note (auto/bypass). Default true. */
export function resolveInjectionWarning(config: PermissionModesConfig): boolean {
	return config.injectionWarning ?? true
}

/** Heuristic-triggered strong warning on a real probe signal. Default true,
 *  and independent of `injectionWarning`: turning off the standing note should
 *  not disarm the response to an actual injection pattern. */
export function resolveInjectionEscalation(
	config: PermissionModesConfig,
): boolean {
	return config.injectionEscalation ?? true
}

// ------------------------------------------------- layered authority (W6 surface)

function isAuthorityPersist(value: unknown): value is AuthorityPersist {
	return (
		typeof value === "string" &&
		(AUTHORITY_PERSIST_VALUES as readonly string[]).includes(value)
	)
}

/** A value is echoed back into a diagnostic verbatim, so it has to fit in a line. */
function showValue(value: unknown): string {
	const text = typeof value === "string" ? JSON.stringify(value) : String(value)
	return text.length > 40 ? `${text.slice(0, 37)}…` : text
}

function orderedLayers(layers: ConfigLayers): Array<{
	name: ConfigLayerName
	config: PermissionModesConfig
}> {
	const out: Array<{ name: ConfigLayerName; config: PermissionModesConfig }> = []
	for (const name of LAYER_ORDER) {
		const config = layers[name]
		if (config && typeof config === "object") out.push({ name, config })
	}
	return out
}

/** A provenance value has to survive being printed in a footer: a string, non-blank,
 *  short. Anything else is refused with a reason and the lower layer's value stands.
 *  Called only for a key the layer actually set (`undefined` is inherit, handled by the
 *  caller) — an explicit `null` is not "unset", it is a value nobody can print.
 */
function readSource(
	layer: ConfigLayerName,
	key: ProvenanceKey,
	value: unknown,
	diagnostics: string[],
): string | undefined {
	if (typeof value !== "string") {
		diagnostics.push(
			`${key}=${showValue(value)} in the ${layer} config is not a string — ignored`,
		)
		return undefined
	}
	const trimmed = value.trim()
	if (!trimmed.length) {
		diagnostics.push(`${key} in the ${layer} config is blank — ignored`)
		return undefined
	}
	if (trimmed.length > MAX_SOURCE_CHARS) {
		diagnostics.push(
			`${key} in the ${layer} config is ${trimmed.length} chars (max ${MAX_SOURCE_CHARS}) — ignored`,
		)
		return undefined
	}
	return trimmed
}

/**
 * Merge the layers for the two keys this module owns — where standing authority is
 * stored, and who set the live state. Pure: no fs, no cache, no pi import, so a test
 * (or a footer) can compute the same answer the accessors will serve.
 *
 * A value that fails validation is reported in `diagnostics` and skipped: the winner is
 * then the highest *usable* value below it, or the default when nothing usable exists.
 * It is never quietly rewritten into the default as if the user had typed that.
 */
export function resolveAuthorityLayers(
	layers: ConfigLayers = {},
): AuthoritySnapshot {
	const diagnostics: string[] = []
	let persist: AuthorityPersist = DEFAULT_AUTHORITY_PERSIST
	let persistOrigin: AuthoritySnapshot["persistOrigin"] = "default"
	const provenance: ConfigProvenance = {}

	for (const { name, config } of orderedLayers(layers)) {
		const raw = config.authority?.persist
		if (raw !== undefined) {
			if (isAuthorityPersist(raw)) {
				persist = raw
				persistOrigin = name
			} else {
				diagnostics.push(
					`authority.persist=${showValue(raw)} in the ${name} config is not one of ${AUTHORITY_PERSIST_VALUES.join(" | ")} — kept "${persist}" (from ${persistOrigin})`,
				)
			}
		}

		for (const key of PROVENANCE_KEYS) {
			// `undefined` is "this layer says nothing", i.e. inherit — not a value to reject.
			const rawSource = config[key]
			if (rawSource === undefined) continue
			const value = readSource(name, key, rawSource, diagnostics)
			if (value !== undefined) provenance[key] = value
		}
	}

	return Object.freeze({
		persist,
		persistOrigin,
		provenance: Object.freeze(provenance) as ConfigProvenance,
		diagnostics: Object.freeze(diagnostics),
	})
}

let _layers: ConfigLayers = {}
let _snapshot: AuthoritySnapshot = resolveAuthorityLayers()

/** `console.warn` fires once per distinct message per process: `applyAuthorityLayers()`
 *  runs on reload and on state flips, and a typo in a hand-edited file is constant.
 *  The full list always stays readable through {@link getAuthorityDiagnostics}. */
const _warned = new Set<string>()

function publish(snapshot: AuthoritySnapshot): AuthoritySnapshot {
	for (const line of snapshot.diagnostics) {
		if (_warned.has(line)) continue
		_warned.add(line)
		console.warn(`[permission-modes] ${line}`)
	}
	_snapshot = snapshot
	return snapshot
}

/** Replace all three layers and recompute the cached view. Call it wherever
 *  `resolveClassifierConfig(loadPermissionModesConfig())` is called today; the getters
 *  below stay free because the work happens here instead of on the hot path. */
export function applyAuthorityLayers(layers: ConfigLayers): AuthoritySnapshot {
	_layers = { ...layers }
	return publish(resolveAuthorityLayers(_layers))
}

/** Replace only the runtime layer (a start flag, a dialog answer, a restored row) and
 *  recompute against the user/project layers from the last
 *  {@link applyAuthorityLayers}. This is what keeps a mode flip in `index.ts` one call
 *  instead of reloading two files. Pass `undefined` to drop the runtime layer. */
export function setRuntimeAuthority(
	runtime: PermissionModesConfig | undefined,
): AuthoritySnapshot {
	_layers = { ..._layers, runtime }
	return publish(resolveAuthorityLayers(_layers))
}

/** Where a standing "Allow always" is written — `"grants"` unless a layer said
 *  otherwise. One field read; safe in a footer. */
export function getAuthorityPersist(): AuthorityPersist {
	return _snapshot.persist
}

/** Which layer decided {@link getAuthorityPersist}, for a footer that says so. */
export function getAuthorityPersistOrigin(): AuthoritySnapshot["persistOrigin"] {
	return _snapshot.persistOrigin
}

/** The cached {@link ConfigProvenance} — frozen, spread it if you need to edit it. */
export function getProvenance(): ConfigProvenance {
	return _snapshot.provenance
}

/** Values refused during the last apply, in layer order. */
export function getAuthorityDiagnostics(): readonly string[] {
	return _snapshot.diagnostics
}

/** The whole cached view (persist + origin + provenance + diagnostics). */
export function getAuthoritySnapshot(): AuthoritySnapshot {
	return _snapshot
}

/**
 * Read-modify-write the global config JSON, preserving keys this plugin does
 * not model (the file is hand-edited, and `permissions-loader.ts` writes rules
 * into it too). Atomic via tmp + rename. Returns false on failure, never
 * throws — callers notify.
 *
 * Deliberately does NOT use `loadPermissionModesConfig()`: that swallows parse
 * errors and returns `{}`, so a corrupt-but-recoverable file would be replaced
 * wholesale. Here a parse error aborts the write and leaves the file alone.
 */
export function updatePermissionModesConfig(
	mutate: (config: PermissionModesConfig) => void,
): boolean {
	try {
		let config: PermissionModesConfig = {}
		if (existsSync(_configPath)) {
			const raw = readFileSync(_configPath, "utf-8")
			if (raw.trim()) {
				config = JSON.parse(raw) as PermissionModesConfig
			}
		}
		mutate(config)
		const dir = dirname(_configPath)
		if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
		const tmp = `${_configPath}.tmp-${process.pid}`
		writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`, "utf-8")
		renameSync(tmp, _configPath)
		return true
	} catch (err) {
		console.warn(
			`[permission-modes] Failed to write ${_configPath}:`,
			err,
		)
		return false
	}
}

let _configPath = join(homedir(), ".pi", "agent", "permission-modes.json")

export function getConfigPath(): string {
	return _configPath
}

export function setConfigPath(p: string): void {
	_configPath = p
}

const DEFAULT_CLASSIFIER: ClassifierConfig = {
	enabled: true,
	model: "anthropic/claude-haiku-4-5",
	timeoutMs: 15000,
	failClosed: true,
	stage: "tool",
	includeAgentsMd: true,
	engine: "gate",
	contextTokens: DEFAULT_CONTEXT_TOKENS,
}

/** A hand-edited config is not type-checked: anything that is not a usable positive
 *  number is ignored rather than propagated into a budget calculation. */
function positiveInt(value: unknown, fallback: number): number {
	return typeof value === "number" && Number.isFinite(value) && value > 0
		? Math.floor(value)
		: fallback
}

/** A usable non-negative whole number. `positiveInt` is the wrong check here because 0 is meaningful ("no
 *  cap"): it would read a deliberate 0 as a typo and install a cap the user never asked for. */
function nonNegativeInt(value: unknown, fallback: number): number {
	return typeof value === "number" && Number.isFinite(value) && value >= 0
		? Math.floor(value)
		: fallback
}

/** Sanity ceiling for `maxOutputTokens`. A classifier verdict is a few hundred tokens; a reserve in the millions
 *  is a typo, and an absurd `max_output_tokens` is either a 400 or an open licence to spend the user's allowance.
 *  Past the ceiling the value is ignored (this file's contract for an unusable value), not clamped — a clamped
 *  typo still reads back as something the user did not type. */
export const MAX_COPILOT_MAX_OUTPUT_TOKENS = 32_768

/** Resolve `classifier.copilot`. Same contract as every resolver in this file: a hand-edited value that cannot
 *  be used is ignored in favour of the default, never propagated into a token calculation, never rewritten
 *  into the file. */
export function resolveCopilotConfig(
	raw: Partial<CopilotClassifierConfig> | undefined,
): CopilotClassifierConfig {
	const c = raw ?? {}
	const effort = c.reasoningEffort
	const reserve = positiveInt(c.maxOutputTokens, DEFAULT_COPILOT_CLASSIFIER.maxOutputTokens)
	return {
		maxOutputTokens: reserve <= MAX_COPILOT_MAX_OUTPUT_TOKENS
			? reserve
			: DEFAULT_COPILOT_CLASSIFIER.maxOutputTokens,
		reasoningEffort: (COPILOT_REASONING_EFFORTS as readonly string[]).includes(String(effort))
			? (effort as CopilotReasoningEffort)
			: DEFAULT_COPILOT_CLASSIFIER.reasoningEffort,
		budgetTokens: nonNegativeInt(c.budgetTokens, DEFAULT_COPILOT_CLASSIFIER.budgetTokens),
		sessionEnabled: typeof c.sessionEnabled === "boolean"
			? c.sessionEnabled
			: DEFAULT_COPILOT_CLASSIFIER.sessionEnabled,
	}
}

export function resolveClassifierConfig(
	config: PermissionModesConfig,
): ClassifierConfig {
	const c = config.classifier ?? {}
	return {
		enabled: c.enabled ?? DEFAULT_CLASSIFIER.enabled,
		model: c.model ?? DEFAULT_CLASSIFIER.model,
		timeoutMs: c.timeoutMs ?? DEFAULT_CLASSIFIER.timeoutMs,
		engine: c.engine ?? DEFAULT_CLASSIFIER.engine,
		baseUrl: c.baseUrl,
		modelId: c.modelId,
		jsonlTranscript: c.jsonlTranscript ?? false,
		failClosed: c.failClosed ?? DEFAULT_CLASSIFIER.failClosed,
		stage: c.stage ?? DEFAULT_CLASSIFIER.stage,
		includeAgentsMd: c.includeAgentsMd ?? DEFAULT_CLASSIFIER.includeAgentsMd,
		ledger: c.ledger ?? true,
		ledgerBackfillLimit: c.ledgerBackfillLimit ?? 400,
		contextTokens: positiveInt(c.contextTokens, DEFAULT_CLASSIFIER.contextTokens!),
		copilot: resolveCopilotConfig(c.copilot),
	}
}

export function resolveAutoModeConfig(
	config: PermissionModesConfig,
): AutoModeRules | undefined {
	const rules = config.autoMode
	if (!rules) return undefined
	if (
		!rules.allow?.length &&
		!rules.soft_deny?.length &&
		!rules.environment?.length
	) {
		return undefined
	}
	return rules
}

/**
 * The project-scoped config file: `<cwd>/.pi/permission-modes.json`.
 *
 * Deliberately NOT under `.pi/projects/<id>/` where the rule files live: that
 * directory is named by a derived id, so a moved checkout orphans whatever was
 * written into it (the failure W5 exists for). A hand-authored config belongs at a
 * path the user can see and a `git worktree move` carries with the tree.
 *
 * **Rules are not read from this file.** Permission rules keep exactly two sources, one
 *  per scope — `~/.pi/agent/permission-modes.json.permissions` (global) and
 *  `<cwd>/.pi/projects/<id>/permissions{,.local}.json` (project), both via
 *  `permissions-loader.ts`.
 * A second rule source reachable through a project directory would be a second
 *  authority path nobody audited, so the layered view here models `authority.persist`
 *  and provenance ONLY; a `permissions` block in this file does nothing.
 */
export function getProjectConfigPath(cwd: string): string {
	return join(cwd, ".pi", "permission-modes.json")
}

/** Same contract as {@link loadPermissionModesConfig}: unreadable, unparseable or not a
 *  JSON object is `{}` plus one warning, never a throw — a broken project file must not
 *  stop a session. */
export function loadProjectPermissionModesConfig(
	cwd: string,
): PermissionModesConfig {
	const filePath = getProjectConfigPath(cwd)
	try {
		if (!existsSync(filePath)) return {}
		const raw = readFileSync(filePath, "utf-8")
		if (!raw.trim()) return {}
		const parsed = JSON.parse(raw) as unknown
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			console.warn(
				`[permission-modes] ${filePath} is not a JSON object — ignored`,
			)
			return {}
		}
		return parsed as PermissionModesConfig
	} catch (err) {
		console.warn(`[permission-modes] Failed to load ${filePath}:`, err)
		return {}
	}
}

export function loadPermissionModesConfig(): PermissionModesConfig {
	try {
		if (!existsSync(_configPath)) return {}
		const raw = readFileSync(_configPath, "utf-8")
		if (!raw.trim()) return {}
		return JSON.parse(raw) as PermissionModesConfig
	} catch (err) {
		console.warn(
			`[permission-modes] Failed to load ${_configPath}:`,
			err,
		)
		return {}
	}
}
