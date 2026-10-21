/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The layer-0 view a `Bash(...)` **allow** rule is matched against.
 *
 * `permissions.ts` used to decide "a rule covers this command" by re-splitting the command text with
 * its own scanner — stripping wrappers, redirections and `NAME=value` prefixes on the way — and then
 * comparing strings. Every one of those steps is a second, weaker opinion about a command that layer 0
 * (`bash-ast.ts` → the tree-sitter walker, `docs/LAYER0-WALKER-SPEC.md` §3) had already worked out
 * properly. This module is the seam that removes the duplicate: it asks the walker for the legs of the
 * command and hands back the argv spellings a rule may be compared against. `bash-rule-argv.ts` does
 * the comparing; nothing here re-tokenises a command string.
 *
 * ## What one leg looks like
 *
 * The walker separates assignments (`envVars`) and redirections (`redirects`) from argv, so a leg comes
 * back as the words that actually reach the program. For rule matching that leaves exactly three
 * spellings worth testing, and they are listed in one place (`legSpellings` in `permissions.ts`):
 * the argv itself, the argv with its `NAME=value` prefix spelled back in (so an exact rule written
 * before this switch keeps matching), and the argv seen through a wrapper.
 *
 * ## What refuses coverage — and why that is the point
 *
 * A rule is authority the user already gave, so the only question this module answers is whether the
 * command is one the user could have had in mind. It answers no in four cases:
 *
 *   - **the walker will not vouch for the command** (`{ kind: "unproven" }`, §12): a loop, a subshell,
 *     a command substitution. There is no trustworthy argv, so there is nothing for a rule to have
 *     authorised, and the prompt is the only channel that can widen it;
 *   - **a leg is `opaque`** (§5.10): a runtime value is wearing a literal's costume
 *     (`__CMDSUB_OUTPUT__`, `__TRACKED_VAR__`), and `Bash(cat:*)` does not mean "whatever `$HOME/x`
 *     turns out to be";
 *   - **a leg sets an environment variable that changes execution** (`LD_PRELOAD`, `NODE_OPTIONS`,
 *     `PATH`, …): the walker correctly keeps assignments out of argv, which would otherwise make a rule
 *     blind to the one prefix that changes what the command *is*;
 *   - **the command hits the never floor** (`floored` in {@link bashRuleView}, {@link hitsNeverFloor} for
 *     callers that only have the command): `rm -rf /`, `dd of=/dev/sda`, a write to
 *     `~/.ssh/authorized_keys`. A wrapper must never launder severity and neither must a rule —
 *     `sudo rm -rf /` stays `never` whoever's rule names it.
 *
 * ## What a covering rule has to name
 *
 * A rule normally covers the words it names *and whatever follows them* — that is what makes
 * `Bash(git status)` cover `git status --short`. For a command whose risk is the paths its operands name
 * (`STRICT_OPERAND_CATEGORIES`), extending a rule past its words extends it over targets: one "Allow
 * always" on `rm -rf /tmp/x` would delete a second path the user never saw. {@link bashRuleView} says
 * when that is the case (`strictOperands`) and `bash-rule-argv.ts` then requires an exact specifier to
 * name every word. `deny`/`ask` are untouched by all of this: they stay textual and broad, because a
 * denial has to keep firing when the command adds words.
 *
 * A redirect target is the other half of the same problem. `echo hi > /tmp/out.txt` and
 * `echo hi > ~/.ssh/authorized_keys` have one argv, so a rule matched on argv alone cannot tell the
 * approved write from the unapproved one. Each leg therefore carries `targets` — every redirect that
 * touches a file, in the canonical form `bash-rule-argv.ts` compares — and `permissions.ts` hands that
 * list to the matcher beside the words. A descriptor dup (`2>&1`) moves no file and is not a target;
 * a target the walker could only give as a placeholder makes the whole leg `opaque`, which is refused
 * before a rule is ever consulted.
 *
 * A refusal is not a denial: it returns the command to the gate, which still has its own tables,
 * grants, ledger and (if configured) the model. Refusing costs one prompt; guessing costs authority.
 */

import { homedir } from "node:os"
import { parseBashCommand, type AstCommand, type AstRedirect } from "./bash-ast.ts"
import {
	analyzerDownNotice,
	bashParserStatus,
	initBashParser,
	isAnalyzerDownReason,
	PARSER_UNAVAILABLE_REASON,
} from "./bash-parser.ts"
import { canonicalRedirectTarget, type RedirectTarget } from "./bash-rule-argv.ts"
import { evaluateBash, type PolicyDecision, type PolicyOptions, type Tier } from "./risk-policy.ts"

/** One simple command of the analysed input, in the spellings a rule may be tested against. */
export type BashLeg = {
	/** The leg's own source text — what the rule string gets quoted back with. */
	text: string
	/** The walker's argv: command word first, quoting resolved, assignments/redirects separated. */
	argv: string[]
	/** argv with this leg's `NAME=value` prefix spelled back in as leading words. */
	withAssignments: string[]
	/** argv seen through a wrapper in {@link COVERAGE_WRAPPERS}, null when there is none to see through. */
	inner: string[] | null
	/** Every variable this leg sets: the walker's own plus any the wrapper peel stepped over. */
	envNames: string[]
	/** Some value in this leg is only known at run time (§5.10). */
	opaque: boolean
	/**
	 * The files this leg writes or reads through a redirect, canonicalised — the other half of what an
	 * exact rule has to name. Empty when the leg touches no file: a descriptor dup (`2>&1`) moves bytes
	 * between descriptors and opens nothing, so naming it in a rule would add authority without adding
	 * harm, and `>` into a run-time-determined path never gets here at all (the leg is `opaque`).
	 */
	targets: RedirectTarget[]
}

export type BashAudit =
	| { proven: true; legs: BashLeg[] }
	| { proven: false; reason: string }

/**
 * Everything the bash **allow** path needs about one command, from one layer-0 verdict.
 *
 * This is the shape `permissions.ts` works against: {@link auditBashCommand} gives the legs, the verdict
 * gives the severity floor and whether the words a rule may extend over exist at all. Getting all three
 * from one {@link evaluateBash} call is the point — the gate runs this on every bash tool call, so a
 * second opinion about the same command would be a second parse and a second walk per call.
 */
export type BashRuleView =
	| { proven: true; floored: boolean; strictOperands: boolean; legs: BashLeg[] }
	| { proven: false; reason: string }

/** How far the wrapper peel follows a stack of them before giving up. */
const MAX_WRAPPER_HOPS = 6

/**
 * Turn one command string into the legs a rule can be matched against.
 *
 * `proven: false` is the answer for anything the walker refuses, and the §12 reason id comes back with
 * it so a caller can explain itself. As a side effect it also kicks the one-time grammar load when the
 * refusal was `parser-unavailable` — index.ts does the same at session start, but it is fire-and-forget,
 * and a rule evaluated in that startup window would otherwise be refused for the rest of the process
 * without ever triggering the load itself ({@link initBashParser} is idempotent and never throws).
 */
/**
 * Parse once, answer both questions. `auditBashCommand` and the policy verdict used to run the walker on the
 * same command independently; the second parse could report `parser-unavailable` while the first succeeded, which
 * is the same command getting two different answers on the hottest path in the extension.
 */
function auditWithParse(command: string): { audit: BashAudit; parsed: ReturnType<typeof parseBashCommand> | null } {
	const trimmed = command.trim()
	if (!trimmed) return { audit: { proven: false, reason: "empty-command" }, parsed: null }
	if (!bashParserStatus().available) {
		// Nothing has been decided about this command — the analyzer is not running. Report the process, never a
		// construct: a caller that sees `variable-expansion` here would advise a rewrite that cannot help.
		void initBashParser().catch(() => {})
		return { audit: { proven: false, reason: PARSER_UNAVAILABLE_REASON }, parsed: null }
	}
	const parsed = parseBashCommand(trimmed)
	if (parsed.kind !== "simple") return { audit: { proven: false, reason: parsed.reason }, parsed }
	if (parsed.commands.length === 0) return { audit: { proven: false, reason: "no-command" }, parsed }
	return { audit: { proven: true, legs: parsed.commands.map(toLeg) }, parsed }
}

export function auditBashCommand(command: string): BashAudit {
	return auditWithParse(command).audit
}

/**
 * The one refusal id in this file that describes the analyzer rather than the command.
 *
 * Everything else a `proven: false` answer carries — a §12 construct id from the walker, `empty-command`,
 * `no-command`, `verdict-unavailable` — is either a property of the input or a failure of one evaluation of it.
 * This one means layer 0 is not deciding anything, for any command, in this process; {@link refusalExplanation}
 * and the callers above need that split and nothing else exposes it.
 */
export function refusalIsAboutAnalyzer(reason: string): boolean {
	return isAnalyzerDownReason(reason) || reason === ANALYZER_FAULT_REASONS[0] || reason === ANALYZER_FAULT_REASONS[1]
}

/** Reasons this module produces when the evaluation itself failed — see {@link refusalIsAboutAnalyzer}. */
const ANALYZER_FAULT_REASONS = ["verdict-unavailable", "analysis-failed"] as const

/**
 * The sentence to show for a layer-0 refusal, worded for who is at fault.
 *
 * A refusal reaches a human as one of two very different statements and the id alone does not say which:
 * the analyzer examined the command and refused a construct (`brace-group`, `loop-body`, `variable-expansion`,
 * `command-substitution` — the fix is a rewrite), or the analyzer never examined it (`parser-unavailable`,
 * `verdict-unavailable` — a rewrite cannot help and the same command may pass after a reload). Text keyed on the
 * *category* collapses the two into whichever sentence was written first: `unproven_structure` is one category for
 * both, which is how a dead analyzer is reported to the user as a strict one. The same defect exists on the
 * advice side and is fixed there by deriving the advice from the construct; this is the same rule on the
 * mechanism side, and the two are complementary — this function answers "what stopped", the construct answers
 * "what to do about it".
 *
 * It returns a sentence, not a verdict: no tier, no category, nothing a decision reads.
 */
export function refusalExplanation(reason: string): string {
	if (isAnalyzerDownReason(reason)) return analyzerDownNotice()
	if ((ANALYZER_FAULT_REASONS as readonly string[]).includes(reason)) {
		return "the analyzer could not evaluate this command (the analysis itself failed) — this is a fault in the analyzer, not in the command"
	}
	return `the analyzer read this command and will not vouch for its structure (${reason}) — rewrite it as plain sequential commands`
}

function toLeg(c: AstCommand): BashLeg {
	const prefix = c.envVars.map((e) => `${e.name}=${e.value}`)
	const peeled = seeThroughWrappers(c.argv)
	return {
		text: c.text,
		argv: c.argv,
		withAssignments: prefix.length > 0 ? [...prefix, ...c.argv] : c.argv,
		inner: peeled ? peeled.argv : null,
		envNames: [...c.envVars.map((e) => e.name), ...(peeled ? peeled.envNames : [])],
		opaque: c.opaque,
		targets: fileTargetsOf(c.redirects),
	}
}

/**
 * The redirects of one leg that touch a file, as the walker reported them.
 *
 * A descriptor dup (`2>&1`, `<&0`) is excluded and it is worth saying why, because excluding it is the
 * one place this module is *not* stricter than the naive reading: it moves a stream, opens no file, and
 * the walker can already tell a dup from a write by whether the target is all digits (§7.2). Refusing
 * it would cost the offer on every `cmd 2>&1 | tail -50` and buy no authority the user did not grant.
 */
export function fileRedirects(redirects: readonly AstRedirect[]): AstRedirect[] {
	return redirects.filter((redirect) => !redirect.fdDup)
}

/** The same list in the form a rule specifier is compared against (descriptor resolved, `1>` = `>`). */
export function fileTargetsOf(redirects: readonly AstRedirect[]): RedirectTarget[] {
	return fileRedirects(redirects).map(canonicalRedirectTarget)
}

// ---------------------------------------------------------------- wrappers (§11.2, narrowed)

/**
 * The wrappers a rule may be seen through, and nothing else: the fixed set the wave-2 decision names
 * (`env`, `sudo`, `timeout`, `nice`, `nohup`, `time`). Two things are deliberately missing compared with
 * the walker's own §11.2 table — `stdbuf` (its options are all fused values, so modelling it here would
 * be a second implementation to keep in step) and `xargs`, which the text matcher used to see through
 * and this one does not: its trailing arguments arrive from a pipe at run time, which is why
 * `dangerous-permissions.ts` lists it as a broad grant.
 *
 * This is not a third opinion about severity: the severity floor is layer 0's ({@link hitsNeverFloor},
 * whose own tables peel these same wrappers and keep `never` `never` through `sudo`). What lives here is
 * only the shape of the wrapper's own arguments — how many words to step over before the command starts.
 * Anything unrecognised ends the peel with no answer at all, which costs one prompt.
 *
 * The first word that is not an option, an assignment or the wrapper's own positional IS the command —
 * which is also what §11.2 does, and it is safe because the walker would never hand us an argv whose
 * leading word is an expansion (`nice $ADJ cmd` is refused upstream as `variable-expansion`, so it never
 * reaches a rule at all).
 */
type WrapperShape = {
	/** Options with no value of their own. */
	bare?: readonly string[]
	/** Options that take a value, fused (`-uFOO`) or as the next word (`-u FOO`). */
	valued?: readonly string[]
	/** `NAME=value` words belong to the wrapper rather than to the command (`env FOO=1 ls`). */
	assignments?: boolean
	/** One positional the wrapper eats first — a duration, an adjustment. */
	leading?: { pattern: RegExp; required: boolean }
}

const COVERAGE_WRAPPERS = new Map<string, WrapperShape>([
	["env", { bare: ["--", "-i", "-0", "-S", "--ignore-environment", "--null"], valued: ["-u", "--unset"], assignments: true }],
	["sudo", {
		bare: ["--", "-n", "-E", "-P", "-S", "-l", "-v", "-k", "-b", "-a", "--non-interactive", "--reset-timestamp", "--validate"],
		valued: ["-u", "-g", "-C", "-D", "-h", "-U", "--user", "--group", "--run-as"],
	}],
	["timeout", { bare: ["--"], leading: { pattern: /^\d+(\.\d+)?[smhd]?$/, required: true } }],
	["nice", { bare: ["--"], valued: ["-n", "--adjustment"], leading: { pattern: /^[+-]?\d+$/, required: false } }],
	["nohup", { bare: ["--"] }],
	["time", { bare: ["--", "-p", "-v"], valued: ["-f", "-o"] }],
])

/** The command a wrapper hides, plus the variables the wrapper itself set. Null = not readable. */
export function seeThroughWrappers(
	argv: readonly string[],
): { argv: string[]; envNames: string[] } | null {
	let rest: readonly string[] = argv
	const envNames: string[] = []
	for (let hop = 0; hop < MAX_WRAPPER_HOPS; hop++) {
		const shape = rest.length > 0 ? shapeOf(rest[0]!) : undefined
		if (!shape) return hop === 0 ? null : { argv: [...rest], envNames }
		const stepped = stepOver(rest.slice(1), shape)
		if (!stepped) return null
		envNames.push(...stepped.envNames)
		rest = stepped.rest
	}
	return null
}

/** Wrapper lookup by command word: `sudo`, `/usr/bin/sudo` — never an inherited property name. */
function shapeOf(word: string): WrapperShape | undefined {
	return COVERAGE_WRAPPERS.get(word.slice(word.lastIndexOf("/") + 1))
}

/** Past one wrapper's own words. Null the moment an argument does not fit the shape we know. */
function stepOver(
	args: readonly string[],
	shape: WrapperShape,
): { rest: readonly string[]; envNames: string[] } | null {
	const envNames: string[] = []
	let at = 0
	let optionsDone = false
	let leadingLeft = shape.leading !== undefined
	while (at < args.length) {
		const arg = args[at]!
		if (!optionsDone && arg === "--") {
			optionsDone = true
			at += 1
			continue
		}
		if (leadingLeft && shape.leading!.pattern.test(arg)) {
			leadingLeft = false
			at += 1
			continue
		}
		const set = shape.assignments ? assignmentNameOf(arg) : null
		if (set !== null) {
			envNames.push(set)
			at += 1
			continue
		}
		if (optionsDone || !isOptionWord(arg)) break
		const option = splitOption(arg)
		if (shape.valued?.includes(option.name)) {
			at += option.inline === undefined ? 2 : 1
			continue
		}
		if (shape.bare?.includes(option.name) && option.inline === undefined) {
			at += 1
			continue
		}
		return null
	}
	// A duration that never appeared (`timeout rm -rf /`) means the command was never located.
	if (leadingLeft && shape.leading!.required) return null
	return { rest: args.slice(at), envNames }
}

/** An option word, as opposed to `-` (stdin) or the command itself. */
function isOptionWord(arg: string): boolean {
	return arg.length > 1 && arg.startsWith("-")
}

/** `-u5` → `-u` + `5`; `--user=bob` → `--user` + `bob`; `-u` alone → no inline value. */
function splitOption(word: string): { name: string; inline?: string } {
	if (word.startsWith("--")) {
		const eq = word.indexOf("=")
		return eq > 0 ? { name: word.slice(0, eq), inline: word.slice(eq + 1) } : { name: word }
	}
	return word.length > 2 ? { name: word.slice(0, 2), inline: word.slice(2) } : { name: word }
}

const ASSIGNMENT_RE = /^([A-Za-z_][A-Za-z0-9_]*)=/

/** The variable an argument sets (`FOO=1` → `FOO`), or null when it is not an assignment. */
function assignmentNameOf(arg: string): string | null {
	return ASSIGNMENT_RE.exec(arg)?.[1] ?? null
}

// ------------------------------------------------------- environment that changes execution

/**
 * Variable names whose value decides *what the command is*, not how it is coloured.
 *
 * The walker keeps `NAME=value` prefixes out of argv, and that is right for classification — but a rule
 * matched against argv alone would then never see them, and `LD_PRELOAD=/tmp/e.so git status` would be
 * covered by the innocent-looking `Bash(git status:*)`. The old text path refused that only because its
 * assignment scanner stripped a hand-picked safe list and left everything else attached to the command;
 * here the same refusal is stated as a list instead of as a side effect.
 *
 * Deliberately NOT here: `NODE_ENV`, `LANG`, `TZ`, `PYTHONUNBUFFERED`, `RUST_LOG`, `NO_COLOR` and the
 * rest of the cosmetic set the old safe list carried. Those change output, not execution, and refusing
 * them would mean every `NODE_ENV=test npm test` prompts forever — the rule an "allow always" writes for
 * that command names the command, and an env prefix the matcher cannot see would make it unhonourable.
 */
const EXECUTION_ENV_PREFIXES = ["LD_", "DYLD_", "PI_", "ADAPTIVE_ACL_"]

const EXECUTION_ENV_NAMES = new Set([
	// how a process finds its code
	"PATH", "HOME", "TMPDIR", "IFS", "GLOBIGNORE", "CDPATH",
	// shell hooks: executed by the shell that runs the command
	"BASH_ENV", "ENV", "PROMPT_COMMAND", "PS4", "SHELLOPTS", "BASHOPTS",
	// interpreter option strings that mean "load this first"
	"NODE_OPTIONS", "NODE_PATH", "DENO_RELOAD", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
	"PERL5OPT", "PERL_USE_UNSAFE_INC", "RUBYOPT", "RUBYLIB", "PHP_INI_SCAN_DIR",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
	// which compiler/wrapper a build runs
	"CC", "CXX", "RUSTC_WRAPPER", "CARGO_BUILD_WRAPPER", "MAKEFLAGS", "LDFLAGS",
	// git and friends run whatever these name
	"GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_PAGER", "GIT_EXTERNAL_DIFF",
	"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
	"PAGER", "EDITOR", "VISUAL", "BROWSER", "MANPAGER", "LESS",
])

/** True when this variable can change what the command executes, so no rule may speak for the leg. */
export function envChangesExecution(name: string): boolean {
	if (EXECUTION_ENV_NAMES.has(name)) return true
	return EXECUTION_ENV_PREFIXES.some((p) => name.startsWith(p))
}

// ------------------------------------------------- the verdict the allow path is built on

/**
 * Layer 0's verdict for the whole command, or null when the engine could not produce one.
 *
 * Asked once per command by {@link bashRuleView}. The tier tables walk the same legs, peel the same
 * wrappers (§11.2) and apply the privilege escalation that keeps `sudo rm -rf /` at `never`, so the two
 * questions the allow path has for the verdict — "is anything here floored?" and "may a rule be read
 * past the words it names?" — are both answers inside this one object. Asking them separately would
 * evaluate the same command twice on the hottest path in the extension.
 *
 * Anything thrown counts as no answer at all: a rule is not the place to guess on a broken read.
 */
function policyVerdict(command: string, cwd: string, preParsed?: PolicyOptions["preParsed"]): PolicyDecision | null {
	try {
		// `env` is the live process env, and it is the only place a virtualenv the user activated before
		// starting pi is visible: layer 0 reads VIRTUAL_ENV / CONDA_PREFIX to tell "this repo's env" from
		// "the system python" (risk-handlers.ts `pipInVenv`). Without it the same `pip install` is
		// package_system at the prompt and project env in the shell that ran it.
		// No `gitBranch`: this path has no session, and inventing a branch would put a name into the target a
		// rule is matched against that the user never said.
		return evaluateBash(command, { cwd, project: cwd, home: homedir(), env: process.env, preParsed })
	} catch {
		return null
	}
}

function verdictIsFloored(verdict: PolicyDecision): boolean {
	if (verdict.tier === "never") return true
	return verdict.segments.some((s) => s.tier === "never")
}

/**
 * The categories whose risk **is** the set of targets the command names, so that a rule naming fewer
 * targets than the call authorises deletions/writes/permission changes nobody approved.
 *
 * The test for membership is narrow: the harm is done to a *path* the operands name, and the tier is not
 * `allow` (a category the tables already wave through gains nothing from strict operands — a rule that
 * stops covering it costs a prompt and buys no decision the gate would not have made anyway). Measured
 * against the vocabulary in `risk-handlers.ts` / `risk-policy.ts`, that is:
 *
 *   - `delete_recursive`, `delete_outside`, `delete_data`, `wipe_protected`, `history_wipe` — destruction
 *     of named paths. `delete_outside` is the one that makes `mv` behave: a `mv` names a source *and* a
 *     destination, and its source row is classified here, not under a delete verb;
 *   - `device_write`, `disk_destroy` — the target is a device node (`dd of=`/`mkfs`);
 *   - `perm_change`, `perm_destroy` — `chmod`/`chown`/`setfacl` on named paths;
 *   - `vcs_discard` — which worktree, which branch, which stash is thrown away;
 *   - `persistent_access` — the authorized_keys / rc / crontab class: persistence into a named file;
 *   - `write_sensitive`, `write_outside` — overwriting a named file where the harm is *which file* it is
 *     (secret-bearing, `.git` internals, system config, anything outside the project);
 *   - `read_secret` — not on the wave-2 list, added because the same extension applies with no upside to
 *     offset it: a stored approval to read `~/.ssh/id_rsa` must not also cover the second file the call
 *     appends to the argument list, and a click on a reader always writes an exact rule (`cat`, `head`,
 *     `tail` are not subcommand-grammar tools), so equality costs nothing that prefix coverage earned;
 *   - `read_secret_remote` — the same argument, and here the generalisation is not hypothetical but
 *     the rule the producer writes today: `kubectl`, `aws`, `helm`, `vault`, `gcloud` and `az` are all on
 *     `SUBCOMMAND_GRAMMAR_TOOLS`, so "Allow always" on `kubectl get secret prod-db` writes
 *     `Bash(kubectl get:*)` and silently authorises every future `kubectl get`, which is the exact hole this
 *     closes — `get` is a benign verb and the noun is the risk. Unlike the `cluster_*` family named below,
 *     strictness here costs no offer: the harm is *which entry* was read, the entry is one of the words, and
 *     the exact rule the producer falls back to is honoured by the matcher, so the user keeps the button and
 *     loses only the coverage they never approved;
 *   - `privilege` — added for the same reason, and it closes the hole the wave-2 list would have left
 *     wide open: the tables classify a `sudo`/`doas` leg as `privilege` and never restate the inner verb
 *     (`sudo rm -rf /a /b` reports `privilege`, not `delete_recursive`), so without this name an approval
 *     for `rm -rf /tmp/x` would still cover `sudo rm -rf /tmp/x /home/u/dev/pm` — the same escalation,
 *     with root added. Nothing useful is lost: a click on a wrapped command writes an exact rule naming
 *     the wrapper (`sudo` is on the suggestion engine's `NEVER_GENERALISE`), and equality honours it.
 *
 * Deliberately **not** here, each for one of the two reasons below:
 *
 *   - `allow`-tier categories — `write_project`, `read_only`, `run_project_code`, `vcs_local`, …: covered
 *     by a rule or not, the gate lets these through without asking, so tightening them is a pure prompt
 *     cost. (What a rule does pre-empt there is the ledger's named-forbid scan — but every allow rule has
 *     always had that trade; target extension adds nothing to it.)
 *   - categories whose target is not a path the user can see in the operands — `cluster_*`, `container_*`,
 *     `db_*`, `network_*`, `package_system`, `system_config` (unit names, rules, users), `process_*`,
 *     `remote_exec`, `agent_spawn`, `interactive_editor` — and the gate's own bookkeeping states
 *     (`unproven_structure`, `unproven_value`, `unknown_*`, `unparseable_command`), which describe why the
 *     analyzer stopped rather than what the command damages. Most commands in that class are the ones
 *     whose "Allow always" writes a `tool verb:*` rule, so strict operands there would mostly delete the
 *     offer instead of narrowing it.
 */
const STRICT_OPERAND_CATEGORIES: ReadonlySet<string> = new Set([
	"delete_recursive",
	"delete_outside",
	"delete_data",
	"wipe_protected",
	"history_wipe",
	"device_write",
	"disk_destroy",
	"perm_change",
	"perm_destroy",
	"vcs_discard",
	"persistent_access",
	"privilege",
	"read_secret",
	"read_secret_remote",
	"write_sensitive",
	"write_outside",
])

/**
 * Is this verdict row target-bearing? Rows carry one category; a merged decision joins them with `+`
 * (`mergeDecisions`), so a joined row is strict as soon as one of its parts is.
 */
export function categoryHasStrictOperands(category: string): boolean {
	for (const part of category.split("+")) {
		if (STRICT_OPERAND_CATEGORIES.has(part)) return true
	}
	return false
}

/**
 * The one view the bash allow path reads: the legs a rule may be compared against, whether the command
 * hits the never floor, and whether its words may be extended by a rule at all.
 *
 * `strictOperands` is stated for the command rather than per leg, on purpose. A row of the verdict is
 * not labelled with the leg it came from — `SegmentDecision.command` is display text (`"cp to b"`,
 * `"write /tmp/out.txt"`), not a leg identity — so any per-leg split here would have to guess at
 * `evaluateBash`'s internal row order, and a wrong guess fails by *loosening* (a target-bearing leg left
 * unmarked). Reading the flag command-wide only ever tightens: the cost is that a second, innocent leg
 * of a compound has to be named exactly too, which is one extra prompt on a command the user is already
 * being asked about.
 *
 * `proven: false` covers an unproven command (with its §12 id), an empty command and a verdict the engine
 * could not produce (`verdict-unavailable` — thrown, or the grammar still loading, which
 * {@link auditBashCommand} has already kicked off for next time).
 */
export function bashRuleView(command: string, cwd: string): BashRuleView {
	const { audit, parsed } = auditWithParse(command)
	if (!audit.proven) return audit
	const verdict = policyVerdict(command, cwd, parsed ?? undefined)
	if (!verdict) return { proven: false, reason: "verdict-unavailable" }
	return {
		proven: true,
		floored: verdictIsFloored(verdict),
		strictOperands: verdict.segments.some((s) => categoryHasStrictOperands(s.category)),
		legs: audit.legs,
	}
}

/**
 * Everything the **tier ladder** needs about one command: its legs, and layer 0's severity answer.
 *
 * The ladder has three questions about a command — which simple commands is it made of, is any of them
 * floored or target-bearing, and how severe is the whole — and all three are answers inside one
 * {@link evaluateBash} verdict plus one {@link auditBashCommand}. Asking them separately would walk the same
 * input a third time on the hottest path in the extension, which is the duplication {@link bashRuleView}
 * exists to avoid on the rules side. It is a separate export rather than a wider `BashRuleView` because the
 * two callers read different things: the allow path needs the spellings a rule is compared against, the
 * ladder needs the tier and the merged category and wants neither spelling nor target list.
 *
 * `strictOperands` is the command-wide reading of {@link categoryHasStrictOperands} — the same one
 * strictness table the matcher reads, so a ladder decision and a rule decision cannot disagree about which
 * categories name their targets.
 */
export type BashTierView =
	| {
			proven: true
			/** The merged tier of the whole command (`never` outranks everything). */
			tier: Tier
			/** The merged category string of the top-tier rows (`read_only`, `delete_recursive+write_outside`). */
			category: string
			floored: boolean
			strictOperands: boolean
			legs: BashLeg[]
	  }
	| { proven: false; reason: string }

export function bashTierView(command: string, cwd: string): BashTierView {
	const { audit, parsed } = auditWithParse(command)
	if (!audit.proven) return audit
	const verdict = policyVerdict(command, cwd, parsed ?? undefined)
	if (!verdict) return { proven: false, reason: "verdict-unavailable" }
	return {
		proven: true,
		tier: verdict.tier,
		category: verdict.category,
		floored: verdictIsFloored(verdict),
		strictOperands: verdict.segments.some((s) => categoryHasStrictOperands(s.category)),
		legs: audit.legs,
	}
}

/**
 * Does layer 0 put this command in the `never` tier?
 *
 * {@link bashRuleView} carries the same answer as `floored` and is what the allow path reads; this stays
 * for callers (and tests) that only have the command. Asked once for the whole command rather than per
 * leg, because that is where the answer lives: `evaluateBash` walks the legs with the effective `cd`
 * state, peels the same wrappers (§11.2) and applies the privilege escalation that keeps `sudo rm -rf /`
 * at `never`. So "the floor is evaluated on the inner argv too" needs no extra work here — the verdict
 * layer 0 returns already is the inner one, and a wrapper or a `&&` cannot launder it.
 */
export function hitsNeverFloor(command: string, cwd: string): boolean {
	const verdict = policyVerdict(command, cwd)
	if (!verdict) return true
	return verdictIsFloored(verdict)
}
