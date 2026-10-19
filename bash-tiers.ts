/**
 * The auto-mode tier ladder, computed over layer 0.
 *
 * `utils.ts` reaches its tier verdicts through its own tokeniser: `splitShellSegments` cuts the command
 * on `;`, `&&`, `||`, `|`, `&` and newline with a hand-written quote scanner, and three tables of regexes
 * (`SAFE_PATTERNS`, `AUTO_APPROVABLE_PATTERNS`, `AUTO_FALLBACK_*`) then match *text*. Layer 0
 * (`bash-ast.ts` → the tree-sitter walker, `docs/LAYER0-WALKER-SPEC.md`) already answers the same structural
 * questions about the same command from a parse that cannot silently lose a leg: which simple commands there
 * are, the argv each one really runs, which redirects write where, and how severe the whole thing is
 * ({@link bashTierView}). Two classifiers with one answer is the rule in this repository, so this module keeps
 * what layer 0 does not express — the *positive* allowlists, which are policy about what a user is willing to
 * auto-approve rather than about what a command damages — and takes every structural judgement from the parse.
 *
 * ## What is the same and what is not
 *
 * The allowlists are the ones `utils.ts` uses today: the same read-only command names, the same run-script
 * names, the same routine build/test/git verbs, the same runner flags that turn a test command into an
 * execution vector, the same "a routine command must not name an absolute path" guardrail. What changed is
 * what they are matched against — resolved argv words instead of raw text — and that has three consequences.
 * Each is pinned by a test and reported to the supervisor rather than slipped through:
 *
 *   - **an argument is data.** `echo "rm -rf /"`, `grep -r rm src` and `git status | grep "a>b"` are read-only:
 *     the words inside a quoted argument are bytes, not commands, and the walker has already separated the
 *     redirects from the text. The text tables refused all three.
 *   - **a comment contributes nothing** (§3.1), so a comment mentioning `rm` no longer refuses a command.
 *   - **anything unproven is not safe.** A leg the walker will not vouch for (`loop-body`, `command-substitution`,
 *     `variable-expansion`, …), a leg carrying a runtime placeholder (§6), and a command analysed while the
 *     grammar is still loading are *never* auto-safe. Where the text splitter waved such a command through —
 *     `cat "$HOME/x"`, `echo $HOME` — this module costs a prompt. That is the point of the move.
 *
 * Two tables here are deliberately *narrower* than the text tables in `utils.ts`, which still carry the older
 * policy (`^\s*(make|cmake)\b`, `^\s*docker\s+(build|compose|…)`) and are unchanged by these two decisions:
 *
 *   - **compose is split by verb**: tier 2 covers the read-only compose verbs and nothing else. `up`,
 *     `down`, `build`, `restart`, `stop`, `kill`, `create`, `watch`, `cp` start containers that mount host paths
 *     and publish ports, which is not the risk class `git status` is in; `exec`/`run` are their own class
 *     (arbitrary code inside a container that mounts the repo) and inherit nothing from a wider entry.
 *   - **a task-runner target is a name the table has seen**: `make`, `cmake`, `ninja`, `bazel`, `just`,
 *     `task` use the shape `npm run <script>` always had — recognised build/test/lint verbs are tier 2,
 *     install/uninstall/deploy/publish/release verbs are not, and an unrecognised target is not either,
 *     because a Makefile is arbitrary code and tier 2 cannot promise anything about a target it has not seen.
 *
 * ## Contract
 *
 * Synchronous, and total: it never throws. A command it cannot analyse comes back "nothing is approved", with
 * a reason id. `readOnly ⊆ fallback ⊆ workflow` — the offline face is never the widest one, which is the
 * invariant `utils.ts` states as "the offline conservative face must never be looser than the online
 * auto-approve face" (adjudication ③).
 */

import { bashTierView, type BashTierView, type BashLeg } from "./bash-audit.ts"
import type { Tier } from "./risk-policy.ts"

// ------------------------------------------------------------------ the answer

/**
 * The three tier verdicts for one bash command, plus enough of layer 0's answer to explain them.
 *
 * `reason` always explains the *widest* face that was refused (`workflow`), because that is the face a caller
 * short-circuits on; `readOnlyReason` explains the narrowest one. Both are stable ids, never sentences — the
 * same discipline §12 uses — from this list:
 *
 * | id | meaning |
 * | --- | --- |
 * | `proven` | nothing refused it |
 * | a §12 id (`loop-body`, `command-substitution`, `parser-unavailable`, …) | layer 0 refused the structure |
 * | `verdict-unavailable` | layer 0 could not produce a severity answer |
 * | `floor-never` / `floor-ask` / `floor-unknown` | layer 0's tier is above `allow` (never floor included) |
 * | `no-command` | the command has no legs to classify |
 * | `runtime-value` | the leg carries a `__CMDSUB_OUTPUT__`/`__TRACKED_VAR__` placeholder (§6) |
 * | `assignment-prefix` | the leg runs with a `NAME=value` prefix, which no anchored table could see |
 * | `writes-a-file` | the leg redirects into a file |
 * | `read-only-table` / `workflow-table` / `fallback-table` | not admitted by that face's allowlist |
 * | `excluded-word` | a word the face's deny list names (`rm`, `sudo`, `--force`, …) |
 * | `runner-flag` | an argument that turns a test/build command into an execution vector |
 * | `absolute-path` | a routine command naming a path by absolute/`~`/`..` spelling |
 * | `target-bearing` | layer 0 says the command's risk *is* the targets it names |
 */
export type BashTierVerdict = {
	/** Tier 1 — read-only. What `utils.ts:isSafeCommand` answers today (plan mode, ask mode, auto tier 1). */
	readOnly: boolean
	/** Tier 2 — routine dev workflow, auto-approved with no classifier review. */
	workflow: boolean
	/** The classifier-offline face (`utils.ts:isAutoFallbackBash`); never wider than {@link workflow}. */
	fallback: boolean
	/** False when layer 0 produced no argv at all, so nothing here means anything beyond "ask". */
	proven: boolean
	/** Why `workflow` is false — `proven` when it is true. */
	reason: string
	/** Why `readOnly` is false — `proven` when it is true. */
	readOnlyReason: string
	/** layer 0's merged tier, or null when the command is unproven. */
	floor: Tier | null
	/** layer 0's merged category string (`read_only`, `delete_recursive+write_outside`, …). */
	category: string
	/** How many simple commands the command is made of (0 when unproven). */
	legs: number
}

const REFUSED = (reason: string, readOnlyReason = reason): BashTierVerdict => ({
	readOnly: false,
	workflow: false,
	fallback: false,
	proven: false,
	reason,
	readOnlyReason: readOnlyReason,
	floor: null,
	category: "",
	legs: 0,
})

/** The refusal ids a caller may see, in the order that best explains a compound command. */
const REFUSAL_PRIORITY: readonly string[] = [
	"writes-a-file", "runtime-value", "assignment-prefix", "excluded-word", "runner-flag",
	"absolute-path", "target-bearing",
]

/**
 * Tier verdicts for one command, from one layer-0 audit and one layer-0 verdict.
 *
 * `cwd` is the directory the command would run in — the same value the gate hands the policy, because the
 * severity floor is path-relative and a ladder that resolved paths against a different directory than the
 * gate does would disagree with the gate about the same command.
 */
export function classifyBashTiers(command: string, cwd: string): BashTierVerdict {
	try {
		return tiersOf(bashTierView(command, cwd))
	} catch {
		// Total by contract: an analysis that blows up is an analysis that proved nothing.
		return REFUSED("analysis-failed")
	}
}

/** The three faces as one-boolean calls, for the `utils.ts` re-export this module is written to replace. */
export function isReadOnlyBash(command: string, cwd: string): boolean {
	return classifyBashTiers(command, cwd).readOnly
}

export function isWorkflowBash(command: string, cwd: string): boolean {
	return classifyBashTiers(command, cwd).workflow
}

export function isFallbackBash(command: string, cwd: string): boolean {
	return classifyBashTiers(command, cwd).fallback
}

/** Tier verdicts from a view the caller already has, so a hot path never parses the same command twice. */
export function tiersOf(view: BashTierView): BashTierVerdict {
	if (!view.proven) return REFUSED(view.reason)
	const seen = { proven: true, floor: view.tier, category: view.category, legs: view.legs.length }
	if (view.legs.length === 0) return { ...REFUSED("no-command"), ...seen }
	if (view.tier !== "allow") {
		// layer 0 already decided this command needs a human (`never`, floored) or a model (`unknown`), or is
		// asking for a reason the tables have nothing to say about. The ladder is the narrower of the two
		// answers by construction, so an allow-tier floor is a precondition of every face.
		const id = `floor-${view.tier}`
		return { ...REFUSED(id), ...seen }
	}

	const readOnlyBlocks: string[] = []
	const workflowBlocks: string[] = []
	let fallback = true
	for (const leg of view.legs) {
		const answer = legTiers(leg, view)
		if (!answer.readOnly) readOnlyBlocks.push(answer.readOnlyReason)
		if (!answer.workflow) workflowBlocks.push(answer.workflowReason)
		if (!answer.fallback) fallback = false
	}
	// Each face is its own "every leg passes", exactly as the text ladder defines it: `npm test` fails the
	// read-only face and passes the workflow one, and a compound fails a face on its worst leg.
	const readOnly = readOnlyBlocks.length === 0
	const workflow = workflowBlocks.length === 0
	return {
		...seen,
		readOnly,
		workflow,
		// The offline face is the narrowest by construction: it needs its own table on top of the guardrails.
		fallback: workflow && fallback,
		reason: workflow ? "proven" : firstBlock(workflowBlocks) ?? "workflow-table",
		readOnlyReason: readOnly ? "proven" : firstBlock(readOnlyBlocks) ?? "read-only-table",
	}
}

/** Tier 1 and tier 2 are both "every leg must pass", so the refusal that explains a compound best wins. */
function firstBlock(blocks: string[]): string | undefined {
	for (const id of REFUSAL_PRIORITY) if (blocks.includes(id)) return id
	return blocks[0]
}

// ------------------------------------------------------------------ one leg at a time

type LegAnswer = {
	readOnly: boolean
	workflow: boolean
	fallback: boolean
	readOnlyReason: string
	workflowReason: string
}

function legTiers(leg: BashLeg, view: Extract<BashTierView, { proven: true }>): LegAnswer {
	// Structural refusals, shared by every face. Each one is a case where the text splitter and the walker
	// disagree about what the leg *is*, and the walker is the one that is never wrong about the structure.
	const structural = structuralBlock(leg)
	if (structural) {
		return { readOnly: false, workflow: false, fallback: false, readOnlyReason: structural, workflowReason: structural }
	}
	const words = leg.argv
	const readOnly = admit(words, READ_ONLY_COMMANDS, READ_ONLY_RULES) ? "proven" : "read-only-table"

	// Tier 2 admits a leg that is read-only (that is how `utils.ts` defines it: safe OR approvable) or that its
	// own workflow table admits, subject to the guardrails the fallback face has always carried.
	let workflow = "proven"
	if (readOnly === "proven") workflow = "proven"
	else {
		const guard = guardrailBlock(words, labelPrefixes(words[0]))
		if (guard) workflow = guard
		else if (!admit(words, WORKFLOW_COMMANDS, WORKFLOW_RULES)) workflow = "workflow-table"
	}
	// A command whose risk *is* the paths its operands name is not a routine command: the user has to see the
	// targets. This is the same strictness table the rule matcher reads (`categoryHasStrictOperands`, via
	// {@link bashTierView}) — there is exactly one such table in this repository, on purpose.
	if (workflow === "proven" && view.strictOperands) workflow = "target-bearing"

	let fallback = "proven"
	if (readOnly === "proven") fallback = "proven"
	else if (workflow !== "proven") fallback = workflow
	else if (!admit(words, FALLBACK_COMMANDS, FALLBACK_RULES)) fallback = "fallback-table"

	return {
		readOnly: readOnly === "proven",
		workflow: workflow === "proven",
		fallback: fallback === "proven",
		readOnlyReason: readOnly,
		workflowReason: workflow,
	}
}

/** Why this leg cannot be approved on any face, or null when its shape is classifiable. */
function structuralBlock(leg: BashLeg): string | null {
	if (leg.opaque) return "runtime-value"
	// `NAME=value` in front of a command is the one prefix every anchored table regex was blind to
	// (`env VAR=x cmd` is an execution prefix, adjudication ⑤), so the ladder still refuses it.
	if (leg.envNames.length > 0) return "assignment-prefix"
	if (leg.argv.length === 0) return "no-command"
	if (writesToAFile(leg)) return "writes-a-file"
	return null
}

/**
 * Does this leg open a file for writing through a redirect?
 *
 * Descriptor dups (`2>&1`, `<&0`) never reach here — {@link BashLeg.targets} holds only the redirects that
 * name a file, which is what makes `ls 2>&1` read-only for both engines. `>&file` (a non-digit target) is a
 * write; `<` and `<<<` move bytes in, so they are not.
 */
const WRITE_OPERATORS = new Set([">", ">>", ">|", ">&", "&>", "&>>"])

function writesToAFile(leg: BashLeg): boolean {
	return leg.targets.some((t) => WRITE_OPERATORS.has(t.op))
}

// ------------------------------------------------------------------ the allowlists

/**
 * A command the ladder admits, in the shape the tables were always describing.
 *
 * `utils.ts` writes these as anchored regexes over the command text (`^\s*git\s+(status|log|…)`); the same
 * policy over argv is a verb list plus the arguments that refuse it. Fields:
 *
 *   - `verbs` — the second word must be one of these (every entry names its verbs: an entry that omitted
 *     them meant "any arguments at all", which is what `^\s*make\b` was, and is now a {@link TaskTool});
 *   - `verbPrefix` — or starts with this prefix (`git ls-*`);
 *   - `after` — for a listed verb, the word that must follow it (`git config --get`, `node --version`);
 *   - `run` — the `run <script>` form, admitted only for these script names;
 *   - `bare` — with `verbs`: no arguments at all is admitted too (`make` beside `make test`);
 *   - `block` — refuse when this word appears anywhere in the arguments;
 *   - `blockWith` — refuse when this verb is combined with one of these words (`branch -D`);
 *   - `tool` — the arguments are a task runner's flags and targets, matched by {@link toolAdmits} instead of
 *     by a verb at a fixed position;
 *   - `check` — the last resort: a predicate over the argument words, for guards that are not word lists.
 */
type VerbRule = {
	verbs?: readonly string[]
	verbPrefix?: string
	after?: Readonly<Record<string, readonly string[]>>
	run?: readonly string[]
	bare?: boolean
	block?: readonly string[]
	blockWith?: Readonly<Record<string, readonly string[]>>
	tool?: TaskTool
	check?: (args: readonly string[]) => boolean
}

/** Tier 1 — the read-only allowlist: every argument of these is data. */
const READ_ONLY_COMMANDS: readonly string[] = [
	"bat", "cal", "cat", "date", "df", "diff", "du", "echo", "eza", "fd", "file", "free", "grep",
	"head", "htop", "id", "jq", "less", "ls", "more", "printenv", "printf", "ps", "pwd", "rg", "sort",
	"stat", "tail", "top", "tree", "type", "uname", "uniq", "uptime", "wc", "whereis", "which", "whoami",
]

/**
 * Tier 1 — the commands whose subcommand decides it.
 *
 * Deliberately missing, each for a reason recorded in `utils.ts`: bare `env` (`env VAR=x cmd` is an execution
 * prefix — and an assignment prefix is refused outright anyway), `awk` (an interpreter whose program text
 * carries `system()`), and `find` without its destructive predicates, which is why `find` lives here and not
 * in the plain list.
 */
const READ_ONLY_RULES: Readonly<Record<string, VerbRule>> = {
	git: {
		verbs: ["status", "log", "diff", "show", "branch", "remote", "config"],
		verbPrefix: "ls-",
		after: { config: ["--get"] },
		blockWith: { branch: ["-d", "-D"] },
	},
	npm: { verbs: ["list", "ls", "view", "info", "search", "outdated", "audit"] },
	yarn: { verbs: ["list", "info", "why", "audit"] },
	node: { after: { "": ["--version", "-v"] } },
	python: { after: { "": ["--version"] } },
	find: { block: ["-delete", "-exec", "-execdir", "-fexec"] },
	sed: { after: { "": ["-n"] }, block: ["-i", "--in-place"], check: (args) => !sedWritesAFile(args) },
}

/**
 * `sed -n` is read-only except for the `w` command, which writes the file named after it (`1w /path`, and the
 * `s///w path` suffix, where the `w` hugs a digit or a delimiter so no word boundary ever finds it).
 *
 * layer 0 does not model sed's program text — `sed -n '1w /tmp/x' f` arrives as `allow/write_project`, the
 * same verdict as any other write inside the project — so this guard is the ladder's own and has to stay here
 * until something upstream speaks sed. It runs over the argument words, which is where the program now is.
 */
function sedWritesAFile(args: readonly string[]): boolean {
	return args.some((word) => /(?:^|["',;/0-9}\s])w\s*["']?\s*[/~]/.test(word))
}

/**
 * Run-script names the ladder will execute on the user's behalf, shared by every face so that tier 2 can
 * never be looser than the offline face. Anything shaped like a deploy step falls through to the classifier.
 */
const RUN_SCRIPT_NAMES: readonly string[] = [
	"test", "build", "lint", "check", "typecheck", "verify", "coverage", "unit", "ci", "dev", "start",
	"preview", "serve", "watch",
]

/**
 * Target words the task-runner tables admit.
 *
 * Build/test/lint-shaped names: {@link RUN_SCRIPT_NAMES} minus the names of long-running processes (`dev`,
 * `start`, `serve`, `watch`, `preview`, `ci`) plus the make-flavoured spellings of the same idea (`all`,
 * `fmt`, `format`, `bench`). A target is arbitrary code, so tier 2 admits it for nothing but its name — which
 * is exactly why a name that is *not* here is not tier 2. `make setup`, `make bootstrap` and `task default`
 * each cost a prompt; that is the fail-closed half of the decision, and the reason this list is not simply
 * {@link RUN_SCRIPT_NAMES} reused.
 */
const BUILD_TARGETS: readonly string[] = [
	"all", "bench", "build", "check", "clean", "coverage", "fmt", "format", "lint", "test", "typecheck",
	"unit", "verify",
]

/**
 * Target and flag words that are never tier 2, whatever else the table says.
 *
 * No name here is in {@link BUILD_TARGETS}, so the list changes no verdict today. It exists so widening
 * `targets` cannot silently cover an install/deploy step, and so the tests can name the boundary in one place.
 */
const INSTALL_TARGETS: readonly string[] = ["deploy", "install", "publish", "release", "uninstall"]

/**
 * A task runner: a tool whose work is named by a *target* behind its own flags (`make -C build test`,
 * `ninja -C build`, `cmake --build build`) rather than by a subcommand at a fixed argument position.
 *
 * That difference is the whole reason this shape sits beside {@link VerbRule} instead of inside its `verbs`:
 * `args[0]` is a flag half the time, and a table that read it anyway would either refuse `make -j4 test` (a
 * dev-loop command) or accept `make -f Makefile deploy` (an install step read as a flag value). Matching is
 * therefore three steps: consume the values of the flags that have values, keep what is left as the named
 * words, and require every named word to be a target the table recognises — with "no named word at all" and
 * "a word that is really an operand" answered per tool by {@link bare} and {@link labels}.
 */
type TaskTool = {
	/** Flags that take the next word as their value, so a value is never read as a target. */
	valueFlags: readonly string[]
	/** Flags whose value is optional (`make -j`, `make -j 4`, `make -j4`): the next word is consumed only when it is a number, so `make -j test` still reads its target. */
	numericFlags?: readonly string[]
	/** The target words that are tier 2. Anything else the tool was asked for is not. */
	targets: readonly string[]
	/** Tools whose invocation *is* a flag (`cmake --build`, `just --list`): admitted when it carries no target. */
	flagVerbs?: readonly string[]
	/** Naming no target runs the tool's default target. True only where that default is documented as a build. */
	bare: boolean
	/** Words — target or flag — that are never tier 2. */
	deny: readonly string[]
	/** Prefixes whose words are operands, not names: bazel labels are neither verbs nor paths (`//pkg:target`). */
	labels?: readonly string[]
}

/** GNU make: `-C dir`, `-f file` and friends name a file; `-j` may or may not carry a value. */
const MAKE: TaskTool = {
	valueFlags: ["-C", "--directory", "-f", "--file", "--makefile", "-I", "--include-dir", "-o", "-W",
		"--assume-new", "--assume-old", "--old-file", "--eval", "--goal"],
	numericFlags: ["-j", "--jobs", "-l", "--load-average", "--max-load"],
	targets: BUILD_TARGETS,
	bare: true,
	deny: INSTALL_TARGETS,
}

/** Ninja: every flag it takes names a value, and no target means "build the default targets". */
const NINJA: TaskTool = {
	valueFlags: ["-C", "-f", "-j", "-k", "-l", "-o", "-w", "-x", "--compile-commands-dir"],
	targets: BUILD_TARGETS,
	bare: true,
	deny: INSTALL_TARGETS,
}

/**
 * CMake, whose verbs are flags. `--build` builds, `-S/-B` generate the build system for the project in the
 * working tree, and `--install` — the one people reach for by reflex — is refused: it copies into a prefix
 * outside the project, which is the harm this narrowness exists to stop. A build target named by `--target` is checked like any
 * other target, so `--target test` is a build and `--target bundle-thing` is a name nobody has vouched for.
 * A form the table has not seen (`--preset`, `--open`, `-E`, a bare in-source `cmake .`) asks.
 */
const CMAKE: TaskTool = {
	valueFlags: ["-S", "-B", "--build", "-D", "-G", "-T", "-U", "-A", "-j", "--log-level"],
	targets: BUILD_TARGETS,
	flagVerbs: ["--build", "-S", "-B", "--version", "--help"],
	bare: false,
	deny: [...INSTALL_TARGETS, "--install", "-E"],
}

/**
 * Bazel: the first named word is the command, the rest are labels. `run` is refused like `exec` — it
 * executes a built binary in the workspace — and labels are operands, so `bazel build //...` reads as a build
 * rather than as a command naming an absolute path.
 */
const BAZEL: TaskTool = {
	valueFlags: ["-j", "--jobs", "--copt", "--cxxopt", "--linkopt", "--define", "--test_arg", "--test_filter",
		"--test_output", "--output_base", "--package_path", "--repository_cache", "--distdir"],
	targets: [...BUILD_TARGETS, "aquery", "cquery", "info", "query", "version"],
	bare: false,
	deny: [...INSTALL_TARGETS, "exec", "run"],
	labels: ["//", "@@", "@", ":"],
}

/** `just` and `task` name their default recipe/task whatever the author put first, so bare is not tier 2. */
const JUST: TaskTool = {
	valueFlags: ["-f", "--justfile", "-g", "--global-justfile", "-d", "--working-directory"],
	targets: BUILD_TARGETS,
	flagVerbs: ["--list", "-l"],
	bare: false,
	deny: INSTALL_TARGETS,
}

const TASK: TaskTool = {
	valueFlags: ["--dir", "--timeout", "--data"],
	targets: BUILD_TARGETS,
	flagVerbs: ["--list"],
	bare: false,
	deny: INSTALL_TARGETS,
}

/**
 * The compose verbs tier 2 covers: they read state and print it.
 *
 * Everything else composes a running system out of images and host paths — `up`, `down`, `build`, `create`,
 * `start`, `stop`, `restart`, `kill`, `watch`, `cp`, and above all `exec`/`run`, which run arbitrary commands
 * inside a container that mounts this repo. `ls` and `events` are read-only too but are left out on purpose:
 * the decision names this list, and a verb that is not on it costs one prompt.
 */
const COMPOSE_READ: readonly string[] = ["config", "images", "logs", "port", "ps", "top", "version"]

/** Tier 2 — routine dev-workflow commands with controlled side effects, any arguments. */
const WORKFLOW_COMMANDS: readonly string[] = [
	"ava", "biome", "eslint", "jest", "mkdir", "mocha", "mv", "cp", "pytest", "prettier", "tap", "tsc",
	"touch", "vitest",
]

const WORKFLOW_RULES: Readonly<Record<string, VerbRule>> = {
	// Run scripts are whitelist-gated: a deploy-shaped name falls through to the classifier.
	npm: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	pnpm: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	yarn: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	bun: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	// Task runners: a recognised build/test/lint target, or nothing. `make install` and `make bootstrap`
	// are not tier 2 for different reasons — one is on the deny list, one was never on any list.
	make: { tool: MAKE },
	cmake: { tool: CMAKE },
	ninja: { tool: NINJA },
	bazel: { tool: BAZEL },
	just: { tool: JUST },
	task: { tool: TASK },
	cargo: { verbs: ["build", "check", "clippy", "fmt", "test"] },
	go: { verbs: ["build", "vet", "fmt", "mod", "test"] },
	// Local write operations with no hook vector (commit/merge/rebase/cherry-pick/revert) and no
	// worktree-loss form (checkout/restore); `reset --hard` is refused by name.
	git: { verbs: ["add", "stash", "branch", "switch", "tag", "init", "clone", "reset"], blockWith: { reset: ["--hard"] } },
	npx: { verbs: ["prettier", "eslint", "tsc", "esbuild", "vite", "next", "nuxt", "astro"] },
	// Compose is admitted by its subcommand, not by the word `compose`: `docker compose up` and
	// `docker compose exec web bash` inherit nothing from `docker compose ps`.
	docker: { verbs: ["build", "compose", "logs", "ps", "images"], after: { compose: COMPOSE_READ } },
}

/** The classifier-offline face: a subset of {@link WORKFLOW_RULES}, narrower on purpose. */
const FALLBACK_COMMANDS: readonly string[] = ["jest", "pytest", "vitest"]

const FALLBACK_RULES: Readonly<Record<string, VerbRule>> = {
	npm: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	pnpm: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	yarn: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	bun: { verbs: ["test"], run: RUN_SCRIPT_NAMES },
	// `make` on its own or with a test-shaped target — not `make anything`, which the tier-2 table allows.
	make: { verbs: ["test", "check", "build"], bare: true },
	cmake: { verbs: ["--build"] },
	go: { verbs: ["test"] },
	cargo: { verbs: ["test"] },
}

/**
 * Words that refuse a tier-2 command outright.
 *
 * `utils.ts` matches these over the segment text; here they are whole argv words, which is both narrower (a
 * `rm` inside a quoted message no longer refuses an innocent command) and equal where it matters (`docker rm`,
 * `git commit -m exec` still refuse). Privilege escalation and process/destruction verbs live here as well as
 * in layer 0's tables: `sudo`/`su` are `privilege`/ask and so are already refused by the floor, and keeping
 * the word costs nothing.
 */
const REFUSED_WORDS: readonly string[] = [
	"chmod", "chown", "dd", "exec", "-exec", "--exec", "kill", "killall", "pkill", "reboot", "rm",
	"shutdown", "shred", "su", "sudo", "--force", "-f",
]

/**
 * Arguments that turn a routine test/build command into an execution vector.
 *
 * These are the flags that make `npm test` / `go test` / `cargo test` run something other than the project's
 * own code: a runner, a preload, a config file, a setup module. A test command carrying one is not the
 * "routine build/test" the tier-2 table describes, and the offline face has refused them since the ladder
 * existed.
 */
const RUNNER_FLAGS: readonly string[] = [
	"-exec", "-toolexec", "--script-shell", "--node-options", "--config", "--runner", "--preload",
	"--require", "--import", "--setupFiles", "--globalSetup", "--globalTeardown",
]

/** `--target` is a build output path most of the time, and an install/deploy phase when it is not. */
const DEPLOY_TARGET_VALUES: readonly string[] = ["install", "package", "deploy"]

// ------------------------------------------------------------------ matching

/** Does this argv fit one of the table entries? (Plain names first: they are the common case.) */
function admit(argv: readonly string[], plain: readonly string[], rules: Readonly<Record<string, VerbRule>>): boolean {
	const head = argv[0]
	if (head === undefined) return false
	// Exact command words only: a path (`/usr/bin/ls`) is a different decision from a bare name, exactly as
	// the anchored `^\s*ls\b` it replaces never matched one either.
	if (plain.includes(head)) return true
	const rule = rules[head]
	return rule !== undefined && ruleFits(argv.slice(1), rule)
}

function ruleFits(args: readonly string[], rule: VerbRule): boolean {
	// A task runner's "verb" is a target behind flags, so it is matched by its own reader; the fields below
	// index `args[0]` and would read `make -j4 test` as a command whose subcommand is `-j4`.
	if (rule.tool !== undefined) return toolAdmits(args, rule.tool)
	const verb = args[0] ?? ""
	if (args.length === 0 && rule.bare) return true
	const isRunForm = rule.run !== undefined && verb === "run"
	if (rule.verbs) {
		const named =
			rule.verbs.includes(verb) ||
			isRunForm ||
			(rule.verbPrefix !== undefined && verb.startsWith(rule.verbPrefix))
		if (!named) return false
	}
	if (isRunForm && !rule.run!.includes(args[1] ?? "")) return false
	// `after` is keyed by verb, with `""` for a command that has no verb slot at all (`node --version`).
	const needs = rule.after?.[rule.verbs ? verb : ""]
	if (needs !== undefined && !needs.includes(args[rule.verbs ? 1 : 0] ?? "")) return false
	if (rule.block?.some((word) => args.includes(word))) return false
	for (const [blockedVerb, words] of Object.entries(rule.blockWith ?? {})) {
		if (verb === blockedVerb && words.some((word) => args.includes(word))) return false
	}
	if (rule.check && !rule.check(args.slice(1))) return false
	return true
}

/**
 * Does a task runner's argument list name only work the tool table recognises?
 *
 * Three answers, in this order: a denied word (`install`, `deploy`, `--install`, bazel's `run`) refuses it
 * whatever else is there; no named word at all is the tool's default target, which is tier 2 only for the two
 * tools whose default is documented as a build; and otherwise every named word must be a target on the table.
 * A target the table has never heard of is not tier 2 — that is the whole point of the shape.
 */
function toolAdmits(args: readonly string[], tool: TaskTool): boolean {
	// A denied word refuses the invocation wherever it appears — as a target, as a flag, or as the value a flag
	// swallowed — because `make -C install` and `make install` are the same shape to a reader that cannot see
	// inside the Makefile. Labels are excluded: they name a build output, not an action.
	if (args.some((word) => !isLabel(word, tool.labels) && tool.deny.includes(word))) return false
	const seen = splitArgs(args, tool)
	const names = seen.named.filter((word) => !isLabel(word, tool.labels))
	if (names.length === 0) return tool.bare || seen.flags.some((flag) => tool.flagVerbs?.includes(flag) ?? false)
	return names.every((word) => tool.targets.includes(word))
}

/**
 * Split a task runner's arguments into the flags it was given and the words it was asked to build.
 *
 * A flag's value is consumed only when the flag is known to take one, so an unknown flag that happens to
 * take a value leaves its value to be read as a target — unrecognised, and refused. Fused spellings
 * (`-j4`, `--jobs=8`) carry their value inside the word and consume nothing.
 */
function splitArgs(args: readonly string[], tool: TaskTool): { named: string[]; flags: string[] } {
	const named: string[] = []
	const flags: string[] = []
	for (let at = 0; at < args.length; at++) {
		const word = args[at]!
		if (!word.startsWith("-")) {
			named.push(word)
			continue
		}
		flags.push(word)
		if (word.includes("=") || !consumesNext(tool, word, args[at + 1])) continue
		at++
	}
	return { named, flags }
}

/**
 * Does this flag take the following word as its value?
 *
 * Two kinds. A flag like `-C`/`-f` always does. A flag like `-j` may carry its value fused (`-j4`) or separate
 * (`-j 4`) or none at all (`make -j test`, where `test` is the target), so it swallows the next word only when
 * that word is a number — which is the difference between reading `make -j 4 test` as a build and reading
 * `make -j test` as one too.
 */
function consumesNext(tool: TaskTool, flag: string, next: string | undefined): boolean {
	if (next === undefined || next.startsWith("-")) return false
	if (tool.valueFlags.includes(flag)) return true
	if (tool.numericFlags?.includes(flag) !== true) return false
	return isCount(next)
}

/** Every character a digit: how `make -j 4` is told apart from `make -j test`. */
function isCount(word: string): boolean {
	return word.length > 0 && word.split("").every((ch) => ch >= "0" && ch <= "9")
}

/** Is this word an operand of the tool rather than something it was asked to do (`bazel build //pkg:target`)? */
function isLabel(word: string, labels: readonly string[] | undefined): boolean {
	return labels !== undefined && labels.some((prefix) => word.startsWith(prefix))
}

/**
 * The operand prefixes a workflow entry treats as names-that-are-not-paths, if it has any.
 *
 * Read off the same table the match is made from, so an exemption cannot outlive the entry that needed it.
 */
function labelPrefixes(head: string | undefined): readonly string[] {
	if (head === undefined) return []
	return WORKFLOW_RULES[head]?.tool?.labels ?? []
}

/**
 * The guardrails every tier-2 face carries: deny-list words, runner flags, an absolute path in an otherwise
 * routine command, and the bare `--` that hides whatever follows it.
 *
 * `labels` exempts a tool's operand words from the path guardrail only — a bazel label is a target name that
 * happens to start with `//`. Nothing about the other two guardrails is tool-relative.
 */
function guardrailBlock(words: readonly string[], labels: readonly string[] = []): string | null {
	if (words.some((word) => REFUSED_WORDS.includes(word))) return "excluded-word"
	if (runnerFlag(words)) return "runner-flag"
	if (words.some((word) => namesAbsolutePath(word) && !isLabel(word, labels))) return "absolute-path"
	return null
}

/** Option-name matching for fused (`--config=/tmp/c`) and separate (`--config /tmp/c`) spellings. */
function runnerFlag(words: readonly string[]): boolean {
	for (let at = 0; at < words.length; at++) {
		const word = words[at]!
		if (word === "--") return true
		if (RUNNER_FLAGS.some((flag) => word === flag || word.startsWith(`${flag}=`))) return true
		if (word === "-c" && at + 1 < words.length) return true
		if (word.startsWith("-c=")) return true
		const target = optionValue(words, at, "--target")
		if (target !== null && DEPLOY_TARGET_VALUES.includes(target)) return true
	}
	return false
}

/** The value an option carries, fused (`--target=x`) or separate (`--target x`), null when it is not that option. */
function optionValue(words: readonly string[], at: number, flag: string): string | null {
	const word = words[at]!
	if (word === flag) return words[at + 1] ?? null
	return word.startsWith(`${flag}=`) ? word.slice(flag.length + 1) : null
}

/**
 * Does this word name a path by a spelling that leaves the project?
 *
 * `utils.ts` blocked tier 2 with eight regexes over the segment text; every one of them fires on a word that
 * *starts* an absolute, `~/`-rooted or `..`-relative path, or on the value side of a `name=/abs` argument.
 * Resolved argv makes the quoting cases (three of those eight) fall out for free. Note the asymmetry with
 * tier 1, which is intentional and inherited: reading a file by absolute path is read-only, so `ls -1 /tmp`
 * stays tier 1 while `mkdir /tmp/x` is not tier 2 — the guardrail is about what a routine command *writes*,
 * and layer 0 answers the same question by severity (the `target-bearing` refusal above) rather than by
 * spelling.
 */
function namesAbsolutePath(word: string): boolean {
	if (word.startsWith("/") || word.startsWith("~/")) return true
	if (word === ".." || word.startsWith("../")) return true
	const eq = word.indexOf("=")
	if (eq <= 0 || !/^[\w-]+$/.test(word.slice(0, eq))) return false
	const value = word.slice(eq + 1)
	return value.startsWith("/") || value.startsWith("~") || value === ".." || value.startsWith("../")
}
