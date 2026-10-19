import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync } from "node:fs"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it, vi } from "vitest"

/**
 * Availability, not accuracy.
 *
 * Layer 0 answers "I cannot tell" in two situations that look identical from the outside: the walker refused a
 * construct it examined (`brace-group`, `loop-body`, `variable-expansion`, `command-substitution`), and there is
 * no parser in this process at all (`parser-unavailable`). Measured over the same eight commands with and without
 * `initBashParser()`, the second case turns *every* command — including `cat` of one literal file — into
 * `unknown/unproven_structure`, while the plugin keeps appearing to work. A grammar that fails to load (wrong
 * path after a packaging change, a different runtime, a missing file) therefore reads as "my command was too
 * clever" and is really "no bash command is ever allowed again".
 *
 * So these tests do not check tier decisions — the golden corpus (`bash-walker.golden.jsonl`) holds those. They pin
 * three things: availability is observable (`bashParserStatus`), the packaged layout actually resolves the grammar
 * from the artifact rather than from this checkout, and the analyzer-down reason never borrows the wording of a
 * construct refusal.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url))
/** The manifest that decides what the artifact contains — the other half of "does the grammar resolve". */
const MANIFEST = path.join(HERE, "package.json")
const GRAMMAR_DIR = "wasm"
const GRAMMAR_SUFFIX = ".wasm"

/** A fresh copy of the adapter: it keeps init state in module scope, so every availability test needs its own. */
async function freshParser(): Promise<typeof import("./bash-parser.ts")> {
	vi.resetModules()
	return (await import("./bash-parser.ts")) as typeof import("./bash-parser.ts")
}

/** The `.wasm` files that sit next to `bash-parser.ts` — the packaged layout's only source for the grammar. */
function grammarBesideModule(): string[] {
	const dir = path.join(HERE, GRAMMAR_DIR)
	if (!existsSync(dir)) return []
	return readdirSync(dir).filter((f) => f.endsWith(GRAMMAR_SUFFIX))
}

// ------------------------------------------------------------------ the packaged layout

/**
 * Would `npm pack` ship this path, given `package.json`'s `files`?
 *
 * Deliberately narrow: it understands exactly the shapes this manifest uses — a root-anchored basename glob
 * (`*.ts`), a negation of one (`!*.test.ts`), a directory and everything under it (`wasm/**`) — and throws on any
 * other shape so that a manifest written in a grammar this test cannot reason about is a red test, not a silent
 * green one. npm always includes `package.json` regardless of the list, and that is the one special case here.
 */
function isShipped(relPath: string, patterns: string[]): boolean {
	for (const pattern of patterns) {
		if (pattern.startsWith("!")) {
			if (matchesPattern(relPath, pattern.slice(1))) return false
			continue
		}
		if (matchesPattern(relPath, pattern)) return true
	}
	return relPath === "package.json"
}

function matchesPattern(relPath: string, pattern: string): boolean {
	if (pattern.endsWith("/**")) return relPath.startsWith(pattern.slice(0, -2))
	if (pattern.includes("/")) throw new Error(`packaging test cannot reason about the pattern "${pattern}"`)
	const glob = pattern.replace(/\./g, "\\.").replace(/\*/g, ".*")
	return new RegExp(`^${glob}$`).test(path.basename(relPath))
}

/**
 * Stage the artifact in a fresh directory: copy exactly the files `files` says npm would ship, of the two the
 * grammar load needs, and nothing else. Returns the staged root plus the staged module's path.
 *
 * This is the whole point of the file: an installed plugin is `package root/bash-parser.ts` next to
 * `package root/wasm/`, with `web-tree-sitter` in a parent `node_modules`, and no checkout layout to lean on. A
 * `files` list that stops shipping `wasm/**`, a grammar renamed on disk, or a probe path that stops being derived
 * from `import.meta.url` all make the staged load fail — while every other test in this checkout keeps passing,
 * because they resolve from the working tree.
 */
async function stageArtifact(opts: { withGrammar: boolean }): Promise<{ root: string; module: string }> {
	const manifest = JSON.parse(readText(MANIFEST)) as { files?: string[] }
	const patterns = manifest.files ?? []
	const root = await mkdtemp(path.join(tmpdir(), "w90-artifact-"))
	copyFileSync(path.join(HERE, "bash-parser.ts"), path.join(root, "bash-parser.ts"))

	const grammar = grammarBesideModule()
	if (opts.withGrammar) {
		mkdirSync(path.join(root, GRAMMAR_DIR), { recursive: true })
		if (grammar.length !== 1) {
			throw new Error(
				`packaged layout cannot be staged: ${GRAMMAR_DIR}/ beside bash-parser.ts holds ${grammar.length} ` +
					`${GRAMMAR_SUFFIX} files (${grammar.join(", ") || "none"}). bash-parser.ts resolves the grammar at ` +
					`<its own directory>/${GRAMMAR_DIR}/<one file>, so that is the path the artifact must contain.`,
			)
		}
		const rel = `${GRAMMAR_DIR}/${grammar[0]}`
		if (!isShipped(rel, patterns)) {
			throw new Error(
				`the package would not ship the bash grammar: "${rel}" is not matched by package.json "files" ` +
					`(${JSON.stringify(patterns)}). The shipped plugin would load no grammar, and layer 0 would report ` +
					`every bash command as "parser-unavailable" while looking like a working plugin.`,
			)
		}
		copyFileSync(path.join(HERE, rel), path.join(root, rel))
	}
	// An install always has a node_modules for the one runtime dependency; give the staged copy the same thing.
	symlinkSync(realpathSync(path.join(HERE, "node_modules")), path.join(root, "node_modules"))
	return { root, module: path.join(root, "bash-parser.ts") }
}

function readText(file: string): string {
	return readFileSync(file, "utf8")
}

// ------------------------------------------------------------------ forced unavailable

const LITERAL_READ = "cat /tmp/x"
const CONSTRUCTS: Array<[string, string]> = [
	["variable-expansion", 'echo "X=${PI_SESSION_ID:-unset}"'],
	["brace-group", "{ git log --oneline; }"],
	["loop-body", "for f in a b; do echo $f; done"],
	["command-substitution", 'echo "$(date +%s)"'],
]

const OPTS = { cwd: "/home/user/project", project: "/home/user/project", home: "/home/user" }

/** Every layer-0 question about a command, taken while the analyzer is down. Must stay synchronous. */
function askWhileDown(audit: typeof import("./bash-audit.ts"), policy: typeof import("./risk-policy.ts"), command: string) {
	return {
		audit: audit.auditBashCommand(command),
		view: audit.bashRuleView(command, OPTS.cwd),
		tiers: audit.bashTierView(command, OPTS.cwd),
		decision: policy.evaluateToolCall("bash", { command }, OPTS),
	}
}

describe("bashParserStatus: availability is observable", () => {
	it("walks untried -> initialising -> ready, and is available only in the last", async () => {
		const mod = await freshParser()

		const before = mod.bashParserStatus()
		expect(before).toMatchObject({ state: "untried", available: false, grammar: null })
		// "not running" and "not yet started" are different problems and the notice says which.
		expect(before.notice).toContain("never started")
		expect(mod.bashParserAvailable()).toBe(false)

		const booting = mod.initBashParser()
		expect(mod.bashParserStatus().state).toBe("initialising")
		expect(mod.bashParserStatus().notice).toContain("still loading")
		await booting

		const ready = mod.bashParserStatus()
		expect(ready).toMatchObject({ state: "ready", available: true, loadError: null, notice: "" })
		expect(mod.bashParserAvailable()).toBe(true)
		expect(ready.grammar).toBe(path.join(HERE, GRAMMAR_DIR, grammarBesideModule()[0]!))
		expect(path.basename(ready.grammar!)).toBe(grammarBesideModule()[0]!)
		expect("tree" in mod.parseBash(LITERAL_READ)).toBe(true)
	})

	it("reports the state again after dispose, so a host can tell 'not running' from 'never tried'", async () => {
		const mod = await freshParser()
		await mod.initBashParser()
		expect(mod.bashParserStatus().state).toBe("ready")

		mod.disposeBashParser()
		expect(mod.bashParserStatus()).toMatchObject({ state: "untried", available: false, grammar: null })
		expect(mod.bashParserAvailable()).toBe(false)
		expect(mod.parseBash(LITERAL_READ)).toMatchObject({ error: "not-initialised" })
	})

	it("keeps the four construct ids distinct from parser-unavailable", async () => {
		const mod = await freshParser()
		await mod.initBashParser()
		expect(mod.PARSER_UNAVAILABLE_REASON).toBe("parser-unavailable")
		expect(mod.isAnalyzerDownReason(mod.PARSER_UNAVAILABLE_REASON)).toBe(true)
		for (const [id] of CONSTRUCTS) {
			expect(mod.isAnalyzerDownReason(id), id).toBe(false)
		}
		expect(mod.isAnalyzerDownReason(undefined)).toBe(false)
		expect(mod.isAnalyzerDownReason("")).toBe(false)
	})
})

describe("packaged layout: the grammar has to resolve from the artifact", () => {
	it("ships the grammar at the exact path the shipped module probes", () => {
		const manifest = JSON.parse(readText(MANIFEST)) as { files?: string[] }
		const patterns = manifest.files ?? []
		const grammar = grammarBesideModule()

		// The rule `grammarWasm()` uses: the grammar lives in wasm/ beside bash-parser.ts. If this directory is
		// gone, the shipped module has nothing to load, whatever the manifest says.
		expect(grammar.length, `bash-parser.ts must have exactly one ${GRAMMAR_SUFFIX} in ./${GRAMMAR_DIR}/ beside it`).toBe(1)
		for (const file of grammar) {
			const rel = `${GRAMMAR_DIR}/${file}`
			expect(isShipped(rel, patterns), `package.json "files" (${JSON.stringify(patterns)}) does not ship ${rel}`).toBe(true)
		}
		expect(isShipped("bash-parser.ts", patterns), 'package.json "files" does not ship bash-parser.ts').toBe(true)
	})

	it("loads and parses from a staged artifact, imported from outside this checkout", async () => {
		const staged = await stageArtifact({ withGrammar: true })
		try {
			vi.resetModules()
			const mod = (await import(staged.module)) as typeof import("./bash-parser.ts")
			await mod.initBashParser()

			const status = mod.bashParserStatus()
			expect(status.state, `grammar did not load from the staged artifact: ${status.loadError}`).toBe("ready")
			// The check that makes this a packaging test rather than a parser test: the grammar that loaded is the
			// staged copy. A probe that resolved from `process.cwd()` (the checkout, which also has a wasm/) or from the
			// importer's directory would load this checkout's file here and pass every other test in the suite while the
			// installed plugin had nothing to load — so it fails on this line instead.
			expect(status.grammar).toBe(path.join(staged.root, GRAMMAR_DIR, grammarBesideModule()[0]!))
			expect(status.grammar).not.toContain(path.basename(HERE))
			const result = mod.parseBash(LITERAL_READ)
			expect("tree" in result).toBe(true)
			if ("tree" in result) result.tree.delete()
		} finally {
			rmSync(staged.root, { recursive: true, force: true })
		}
	})

	it("says the analyzer is down, once, when the artifact has no grammar", async () => {
		const staged = await stageArtifact({ withGrammar: false })
		const warned = vi.spyOn(console, "warn").mockImplementation(() => {})
		try {
			vi.resetModules()
			const mod = (await import(staged.module)) as typeof import("./bash-parser.ts")
			await mod.initBashParser()
			await mod.initBashParser()
			mod.parseBash(LITERAL_READ)

			const status = mod.bashParserStatus()
			expect(status).toMatchObject({ state: "failed", available: false, grammar: null })
			expect(status.loadError).toContain("tree-sitter-bash.wasm not found")
			expect(status.loadError).toContain(path.join(staged.root, GRAMMAR_DIR))
			expect(status.notice).toContain("analyzer")
			// The wording a user sees must not read like a verdict on the command.
			expect(status.notice.toLowerCase()).not.toMatch(/brace|loop|expansion|substitution/)

			expect(warned.mock.calls).toHaveLength(1)
			const line = warned.mock.calls[0]!.join(" ")
			expect(line).toContain("[permission-modes]")
			expect(line).toContain("analyzer is DOWN")
			expect(mod.takeBashParserWarning()).toContain("analyzer")
			expect(mod.takeBashParserWarning()).toBeNull()
		} finally {
			warned.mockRestore()
			rmSync(staged.root, { recursive: true, force: true })
		}
	})
})

describe("blast radius: an unavailable analyzer stops deciding, for every command", () => {
	/**
	 * The hazard, pinned so nobody "fixes" it by defaulting to allow: with no parser, layer 0 cannot clear even a
	 * `cat` of one literal file. The fix is to make that observable (this file) — never to let an unanalyzed
	 * command through.
	 */
	it("turns a literal cat from allow/read_only into unknown/unproven_structure + parser-unavailable", async () => {
		const parser = await freshParser()
		const audit = (await import("./bash-audit.ts")) as typeof import("./bash-audit.ts")
		const policy = (await import("./risk-policy.ts")) as typeof import("./risk-policy.ts")

		await parser.initBashParser()
		const withParser = askWhileDown(audit, policy, LITERAL_READ)
		expect(withParser.decision.tier).toBe("allow")
		expect(withParser.decision.category).toBe("read_only")
		expect(withParser.audit.proven).toBe(true)

		// The steady state of a grammar that never loaded: disposed, so nothing is in flight and nothing is live.
		parser.disposeBashParser()
		const down = askWhileDown(audit, policy, LITERAL_READ)
		expect(down.decision.tier).toBe("unknown")
		expect(down.decision.category).toBe("unproven_structure")
		expect(down.decision.segments.some((s) => s.description.includes(parser.PARSER_UNAVAILABLE_REASON))).toBe(true)
		expect(down.audit).toEqual({ proven: false, reason: parser.PARSER_UNAVAILABLE_REASON })
		expect(down.view).toEqual({ proven: false, reason: parser.PARSER_UNAVAILABLE_REASON })
		expect(down.tiers).toEqual({ proven: false, reason: parser.PARSER_UNAVAILABLE_REASON })
	})

	it("reports every construct as parser-unavailable rather than naming a construct that was never examined", async () => {
		const parser = await freshParser()
		const audit = (await import("./bash-audit.ts")) as typeof import("./bash-audit.ts")
		const policy = (await import("./risk-policy.ts")) as typeof import("./risk-policy.ts")
		parser.disposeBashParser()

		for (const [id, command] of CONSTRUCTS) {
			const down = askWhileDown(audit, policy, command)
			expect(down.audit, id).toEqual({ proven: false, reason: parser.PARSER_UNAVAILABLE_REASON })
			expect(down.decision.tier, id).toBe("unknown")
			const text = down.decision.segments.map((s) => s.description).join(" | ")
			expect(text, id).toContain(parser.PARSER_UNAVAILABLE_REASON)
			expect(text, id).not.toContain(id)
		}
	})

	it("names the real construct for each of them once the analyzer is running", async () => {
		const parser = await freshParser()
		const audit = (await import("./bash-audit.ts")) as typeof import("./bash-audit.ts")
		await parser.initBashParser()

		for (const [id, command] of CONSTRUCTS) {
			const auditResult = audit.auditBashCommand(command)
			expect(auditResult, id).toEqual({ proven: false, reason: id })
		}
	})

	it("uses the same id for 'no parser' as the walker does", async () => {
		const parser = await freshParser()
		const walker = (await import("./bash-walker.ts")) as typeof import("./bash-walker.ts")
		parser.disposeBashParser()

		// bash-walker.ts owns the §12 vocabulary and bash-parser.ts repeats the one id it emits for a dead
		// process; this is the line that keeps the two from drifting apart.
		expect(walker.walkBash(LITERAL_READ)).toMatchObject({ kind: "unproven", reason: parser.PARSER_UNAVAILABLE_REASON })
	})
})

describe("refusal wording: who is at fault", () => {
	it("says the analyzer is down instead of blaming the command", async () => {
		const audit = (await import("./bash-audit.ts")) as typeof import("./bash-audit.ts")
		const parser = await freshParser()

		const down = audit.refusalExplanation(parser.PARSER_UNAVAILABLE_REASON)
		expect(down).toContain("analyzer")
		expect(down.toLowerCase()).not.toMatch(/brace|loop|expansion|substitution|rewrite/)
		expect(audit.refusalIsAboutAnalyzer(parser.PARSER_UNAVAILABLE_REASON)).toBe(true)
		expect(audit.refusalIsAboutAnalyzer("verdict-unavailable")).toBe(true)
		expect(audit.refusalIsAboutAnalyzer("brace-group")).toBe(false)

		const examined = audit.refusalExplanation("brace-group")
		expect(examined).toContain("brace-group")
		expect(examined).not.toBe(down)
		expect(audit.refusalExplanation("loop-body")).not.toBe(audit.refusalExplanation("variable-expansion"))
	})
})

describe("the advice a denial carries follows the cause (D54 §1 x D56)", () => {
	/**
	 * One module owns the analyzer-down sentence in `risk-policy.ts`, another owns which advice a denial prints and picks it by
	 * reading the §12 id out of the segment description. Each half passes alone, so the seam is what breaks: paraphrase
	 * the id out of the sentence and that scan finds nothing, falls back to "brace grouping, complex quoting", and an
	 * analyzer outage is explained to the user as a problem with their braces — advice that ignores its own cause, rebuilt from two correct parts.
	 * Found by a throwaway probe while merging the two branches; pinned here so it stays found.
	 */
	it("prints analyzer advice, never construct advice, when no grammar is loaded", async () => {
		const parser = await freshParser()
		const policy = (await import("./risk-policy.ts")) as typeof import("./risk-policy.ts")
		const bridge = (await import("./gate-bridge.ts")) as typeof import("./gate-bridge.ts")
		parser.disposeBashParser()
		expect(parser.bashParserStatus().available).toBe(false)
		for (const [id, command] of [...CONSTRUCTS, ["plain read", "cat /tmp/x"]]) {
			const description = policy
				.evaluateToolCall("bash", { command }, OPTS)
				.segments.map((s) => s.description)
				.join(" | ")
			expect(bridge.reportedConstruct(description), id).toBe("parser-unavailable")
			const advice = bridge.structureGuidance("parser-unavailable")
			const text = `${advice.mechanism} ${advice.fix}`
			expect(text, id).toMatch(/analyzer|grammar/)
			expect(text, id).not.toMatch(/brace|loop-body|parameter expansion|substitution/)
		}
	})

	it("names the construct it really reported once the analyzer is up", async () => {
		const parser = await freshParser()
		await parser.initBashParser()
		const policy = (await import("./risk-policy.ts")) as typeof import("./risk-policy.ts")
		const bridge = (await import("./gate-bridge.ts")) as typeof import("./gate-bridge.ts")
		expect(parser.bashParserStatus().available).toBe(true)
		const mechanisms: string[] = []
		for (const [id, command] of CONSTRUCTS) {
			const description = policy
				.evaluateToolCall("bash", { command }, OPTS)
				.segments.map((s) => s.description)
				.join(" | ")
			expect(bridge.reportedConstruct(description), id).toBe(id)
			mechanisms.push(bridge.structureGuidance(id).mechanism)
		}
		// Four different constructs must produce four different sentences, and none of them the fallback that is
		// printed when nothing was reported — which is the sentence that names braces for every bash denial.
		expect(new Set(mechanisms).size).toBe(CONSTRUCTS.length)
		expect(mechanisms).not.toContain(bridge.structureGuidance(undefined).mechanism)
	})
})
