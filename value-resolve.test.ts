/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Layer 2 (plan-runtime-values.md): the resolver. Every test here drives the real module with a fake
 * runner, so "was that command run?" is an assertion rather than an assumption — the security property
 * of this layer is *what it refuses to execute*, and a fake runner records that directly.
 *
 * The outer command's parse is built by hand through
 * `tmpl()` and injected; anything else (the inner command of a substitution) falls back to the real
 * `parseBashCommand`, wrapped with an empty slot list.
 */

import { describe, expect, it } from "vitest"
import { parseBashCommand, type AstCommand, type Slot, type TemplateCommand, type TemplateParse } from "./bash-ast.ts"
import { RESOLVE_MAX_BYTES, RESOLVE_TIMEOUT_MS, resolveCommand, type ResolveResult, type Runner } from "./value-resolve.ts"

const SPACE = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }

// --------------------------------------------------------------------------- builders

type SlotSeed = Omit<Slot, "span"> & { at: string }
type PartSeed = { text: string; argv: string[]; slots?: SlotSeed[]; extra?: Partial<AstCommand> }

/** Hand-built `TemplateParse`: spans are read off the source, exactly as the real parse reports them. */
function tmpl(command: string, parts: PartSeed[]): Extract<TemplateParse, { kind: "simple" }> {
	let cursor = 0
	const commands: TemplateCommand[] = parts.map((part) => {
		const start = command.indexOf(part.text, cursor)
		if (start < 0) throw new Error(`fixture: "${part.text}" is not in "${command}" after ${cursor}`)
		cursor = start + part.text.length
		let local = 0
		const slots: Slot[] = (part.slots ?? []).map(({ at, ...rest }) => {
			const i = part.text.indexOf(at, local)
			if (i < 0) throw new Error(`fixture: expansion "${at}" is not in "${part.text}" after ${local}`)
			local = i + at.length
			return { ...rest, span: [start + i, start + i + at.length] as [number, number] }
		})
		return {
			argv: part.argv,
			envVars: [],
			redirects: [],
			heredocs: [],
			text: part.text,
			start,
			end: start + part.text.length,
			connector: "",
			opaque: slots.length > 0,
			...part.extra,
			slots,
		}
	})
	return { kind: "simple", commands }
}

/** Injected parse: the outer command from the fixture, inner commands from the real parser. */
function parserFor(map: Record<string, TemplateParse>) {
	return (command: string): TemplateParse => {
		const hit = map[command]
		if (hit) return hit
		const real = parseBashCommand(command)
		if (real.kind !== "simple") return real
		return { kind: "simple", commands: real.commands.map((c) => ({ ...c, slots: [] })) }
	}
}

function recorder(answer: (script: string) => { ok: boolean; stdout: string } = () => ({ ok: true, stdout: "abc123\n" })) {
	const calls: string[] = []
	const opts: Array<{ cwd: string; timeoutMs: number; maxBytes: number }> = []
	const run: Runner = async (script, o) => {
		calls.push(script)
		opts.push(o)
		return answer(script)
	}
	return { calls, opts, run }
}

function resolve(command: string, commandParse: TemplateParse, env: Record<string, string | undefined>, run: Runner): Promise<ResolveResult> {
	return resolveCommand(command, { run, env, space: SPACE, parse: parserFor({ [command]: commandParse }) })
}

const varSlot = (name: string, at: string, extra: Partial<Slot> = {}): SlotSeed => ({
	argIndex: 1,
	quoted: true,
	whole: true,
	source: "var",
	name,
	at,
	...extra,
})

const subSlot = (inner: string, at: string, extra: Partial<Slot> = {}): SlotSeed => ({
	argIndex: 1,
	quoted: true,
	whole: true,
	source: "cmdsub",
	inner,
	at,
	...extra,
})

// --------------------------------------------------------------------------- substitutions

describe("value-resolve — a substitution runs only when it is a read-only command", () => {
	it("resolves `git show $(git rev-parse HEAD)` and strips the trailing newline", async () => {
		const command = `git show "$(git rev-parse HEAD)"`
		const { calls, opts, run } = recorder()
		const out = await resolve(
			command,
			tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot("git rev-parse HEAD", "$(git rev-parse HEAD)")] }]),
			{},
			run,
		)
		expect(out).toEqual({ concrete: `git show 'abc123'`, values: [{ source: "$(git rev-parse HEAD)", value: "abc123" }] })
		expect(calls).toEqual(["git rev-parse HEAD"])
		expect(opts[0]).toEqual({ cwd: SPACE.cwd, timeoutMs: RESOLVE_TIMEOUT_MS, maxBytes: RESOLVE_MAX_BYTES })
	})

	it.each([
		["mktemp", "mktemp"],
		["curl", "curl -s http://example.test/x"],
		["wget", "wget -qO- http://example.test/x"],
		["an interpreter", "python3 -c 'print(1)'"],
		["timeout", "timeout 5 cat /etc/passwd"],
	])("never runs %s", async (_label, inner) => {
		const command = `git show "$(${inner})"`
		const { calls, run } = recorder()
		const out = await resolve(
			command,
			tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
			{},
			run,
		)
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})

	it("never reads a secret file", async () => {
		const inner = "cat /home/u/.ssh/id_rsa"
		const command = `git show "$(${inner})"`
		const { calls, run } = recorder()
		const out = await resolve(
			command,
			tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
			{},
			run,
		)
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})

	it("never runs a pipeline, even one whose first verb is read-only", async () => {
		const inner = "grep x src/a.ts | sh"
		const command = `git show "$(${inner})"`
		const { calls, run } = recorder()
		const out = await resolve(
			command,
			tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
			{},
			run,
		)
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})

	it("never runs a substitution with a redirect", async () => {
		const inner = "cat src/a.ts > src/a.txt"
		const command = `git show "$(${inner})"`
		const { calls, run } = recorder()
		const out = await resolve(
			command,
			tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
			{},
			run,
		)
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})

	it("refuses a git sub-verb outside the list, and a prefixed git global flag", async () => {
		for (const inner of ["git push origin main", "git -C /tmp rev-parse HEAD", "git diff HEAD"]) {
			const command = `git show "$(${inner})"`
			const { calls, run } = recorder()
			const out = await resolve(
				command,
				tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
				{},
				run,
			)
			expect("unresolved" in out, inner).toBe(true)
			expect(calls, inner).toEqual([])
		}
	})

	it("accepts the read-only spellings of git diff/config/branch", async () => {
		for (const inner of ["git diff --name-only HEAD", "git config --get user.name", "git branch --show-current"]) {
			const command = `git show "$(${inner})"`
			const { calls, run } = recorder(() => ({ ok: true, stdout: "x\n" }))
			const out = await resolve(
				command,
				tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }]),
				{},
				run,
			)
			expect(out, inner).toEqual({ concrete: `git show 'x'`, values: [{ source: `$(${inner})`, value: "x" }] })
			expect(calls, inner).toEqual([inner])
		}
	})
})

describe("value-resolve — a substitution that does not come back cleanly is not resolved", () => {
	const inner = "git rev-parse HEAD"
	const command = `git show "$(${inner})"`
	const parse = tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot(inner, `$(${inner})`)] }])

	it("treats a non-zero exit, a cap hit and a spawn failure alike", async () => {
		const cases: Array<Runner> = [
			async () => ({ ok: false, stdout: "" }),
			async () => ({ ok: true, stdout: "x".repeat(RESOLVE_MAX_BYTES + 1) }),
			async () => {
				throw new Error("ETIMEDOUT")
			},
		]
		for (const run of cases) {
			const out = await resolve(command, parse, {}, run)
			expect("unresolved" in out).toBe(true)
		}
	})

	it("refuses a value with an internal newline but strips trailing ones", async () => {
		const many = await resolve(command, parse, {}, async () => ({ ok: true, stdout: "a\nb\n" }))
		expect("unresolved" in many).toBe(true)
		const trailing = await resolve(command, parse, {}, async () => ({ ok: true, stdout: "abc\n\n" }))
		expect(trailing).toEqual({ concrete: `git show 'abc'`, values: [{ source: `$(${inner})`, value: "abc" }] })
	})

	it("refuses an empty value", async () => {
		const out = await resolve(command, parse, {}, async () => ({ ok: true, stdout: "\n" }))
		expect("unresolved" in out).toBe(true)
	})
})

// --------------------------------------------------------------------------- variables

describe("value-resolve — variables", () => {
	it("reads a variable from the environment the shell will get", async () => {
		const command = `wc -l "$F"`
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		const { calls, run } = recorder()
		const out = await resolve(command, parse, { F: "src/a.ts" }, run)
		expect(out).toEqual({ concrete: `wc -l 'src/a.ts'`, values: [{ source: "$F", value: "src/a.ts" }] })
		expect(calls).toEqual([])
	})

	it("is unresolved when the variable is unset or empty", async () => {
		const command = `wc -l "$F"`
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		for (const env of [{}, { F: "" }]) {
			const out = await resolve(command, parse, env, recorder().run)
			expect("unresolved" in out).toBe(true)
		}
	})

	it("keeps a quoted value with a glob or a space, refuses an unquoted one", async () => {
		const quoted = `wc -l "$F"`
		const quotedParse = tmpl(quoted, [{ text: quoted, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		expect(await resolve(quoted, quotedParse, { F: "src/*.ts" }, recorder().run)).toEqual({
			concrete: `wc -l 'src/*.ts'`,
			values: [{ source: "$F", value: "src/*.ts" }],
		})

		const bare = `wc -l $F`
		const bareParse = tmpl(bare, [{ text: bare, argv: ["wc", "-l", "a b"], slots: [varSlot("F", "$F", { argIndex: 2, quoted: false })] }])
		for (const value of ["a b", "src/*.ts"]) {
			const out = await resolve(bare, bareParse, { F: value }, recorder().run)
			expect("unresolved" in out, value).toBe(true)
		}
	})

	it("keeps the literal text around a partial slot", async () => {
		const command = `echo "exit $X"`
		const parse = tmpl(command, [
			{ text: command, argv: ["echo", "exit __TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 1, whole: false })] },
		])
		const out = await resolve(command, parse, { X: "1" }, recorder().run)
		expect(out).toEqual({ concrete: `echo "exit 1"`, values: [{ source: "$X", value: "1" }] })
	})

	it("escapes a value for the quoting it lands in", async () => {
		const command = `echo "exit $X"`
		const parse = tmpl(command, [
			{ text: command, argv: ["echo", "exit __TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 1, whole: false })] },
		])
		const out = await resolve(command, parse, { X: 'a"b$c`d\\e' }, recorder().run)
		expect(out).toEqual({ concrete: 'echo "exit a\\"b\\$c\\`d\\\\e"', values: [{ source: "$X", value: 'a"b$c`d\\e' }] })
	})

	it("escapes a single quote inside the value", async () => {
		const command = `wc -l "$F"`
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		const out = await resolve(command, parse, { F: "src/it's.ts" }, recorder().run)
		expect(out).toEqual({ concrete: `wc -l 'src/it'\\''s.ts'`, values: [{ source: "$F", value: "src/it's.ts" }] })
	})

	it("refuses a name it cannot look up", async () => {
		const command = `echo "` + "${PIPESTATUS[0]}" + `"`
		const parse = tmpl(command, [
			{ text: command, argv: ["echo", "__TRACKED_VAR__"], slots: [varSlot("PIPESTATUS", "${PIPESTATUS[0]}")] },
		])
		// The shell sets `PIPESTATUS` itself; nothing in the environment can stand in for it.
		expect("unresolved" in (await resolve(command, parse, {}, recorder().run))).toBe(true)
		const special = `echo "$@"`
		const specialParse = tmpl(special, [{ text: special, argv: ["echo", "__TRACKED_VAR__"], slots: [varSlot("@", "$@")] }])
		expect("unresolved" in (await resolve(special, specialParse, { "@": "x" }, recorder().run))).toBe(true)
	})
})

// --------------------------------------------------------------------------- assignments in the same command

describe("value-resolve — a variable assigned earlier in the same command", () => {
	const command = `X=$(git rev-parse HEAD); git show "$X"`
	const parse = tmpl(command, [
		{ text: "git rev-parse HEAD", argv: ["git", "rev-parse", "HEAD"] },
		{ text: `git show "$X"`, argv: ["git", "show", "__TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 2 })] },
	])

	it("resolves it from the substitution on the right-hand side", async () => {
		const { calls, run } = recorder()
		const out = await resolve(command, parse, {}, run)
		expect(out).toEqual({ concrete: `X=$(git rev-parse HEAD); git show 'abc123'`, values: [{ source: "$X", value: "abc123" }] })
		expect(calls).toEqual(["git rev-parse HEAD"])
	})

	it("resolves a literal assignment without running anything", async () => {
		const lit = `F=src/a.ts; wc -l "$F"`
		const litParse = tmpl(lit, [
			{ text: "F=src/a.ts", argv: [], extra: { envVars: [{ name: "F", value: "src/a.ts" }] } },
			{ text: `wc -l "$F"`, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] },
		])
		const { calls, run } = recorder()
		expect(await resolve(lit, litParse, {}, run)).toEqual({
			concrete: `F=src/a.ts; wc -l 'src/a.ts'`,
			values: [{ source: "$F", value: "src/a.ts" }],
		})
		expect(calls).toEqual([])
	})

	it("does not run an assignment whose right-hand side is not read-only", async () => {
		const evil = `X=$(curl -s http://example.test/x); git show "$X"`
		const evilParse = tmpl(evil, [
			{ text: "curl -s http://example.test/x", argv: ["curl", "-s", "http://example.test/x"] },
			{ text: `git show "$X"`, argv: ["git", "show", "__TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 2 })] },
		])
		const { calls, run } = recorder()
		const out = await resolve(evil, evilParse, {}, run)
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})

	it("does not fall back to the environment when the assignment is unresolvable", async () => {
		const evil = `X=$(curl -s http://example.test/x); git show "$X"`
		const evilParse = tmpl(evil, [
			{ text: "curl -s http://example.test/x", argv: ["curl", "-s", "http://example.test/x"] },
			{ text: `git show "$X"`, argv: ["git", "show", "__TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 2 })] },
		])
		const out = await resolve(evil, evilParse, { X: "abc123" }, recorder().run)
		expect("unresolved" in out).toBe(true)
	})

	it.each([
		["a substitution", "X=$(git rev-parse HEAD)"],
		["a literal", "X=/tmp"],
	])("treats an assignment written inside a quoted here-document as data (%s)", async (_label, body) => {
		const doc = `cat > notes.txt <<'EOF'\n${body}\nEOF\ngit show "$X"`
		const docParse = tmpl(doc, [
			{ text: "cat > notes.txt <<'EOF'", argv: ["cat"], extra: { heredocs: [`${body}\n`] } },
			{ text: `git show "$X"`, argv: ["git", "show", "__TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 2 })] },
		])
		const { calls, run } = recorder()
		const out = await resolve(doc, docParse, {}, run)
		// The scan reads source text, and a here-document body is data that happens to sit in the same
		// string: `X=/tmp` in there is not an assignment, so nothing is resolved and nothing runs.
		expect("unresolved" in out).toBe(true)
		expect(calls).toEqual([])
	})
})

// --------------------------------------------------------------------------- nothing to do

describe("value-resolve — when it declines, it says so", () => {
	it("reports a command with no slots", async () => {
		const command = "ls -la"
		const out = await resolve(command, tmpl(command, [{ text: command, argv: ["ls", "-la"] }]), {}, recorder().run)
		expect("unresolved" in out).toBe(true)
	})

	it("reports an unproven template parse without throwing", async () => {
		const command = `git show "$X"`
		const out = await resolveCommand(command, {
			run: recorder().run,
			env: {},
			space: SPACE,
			parse: () => ({ kind: "unproven", reason: "variable-expansion", malformed: false }),
		})
		expect("unresolved" in out).toBe(true)
	})

	it("reports a parse that throws instead of failing the call", async () => {
		const out = await resolveCommand(`git show "$X"`, {
			run: recorder().run,
			env: {},
			space: SPACE,
			parse: () => {
				throw new Error("parseBashTemplate: not implemented yet")
			},
		})
		expect(out).toEqual({ unresolved: "template parse unavailable (parseBashTemplate: not implemented yet)" })
	})
})

describe("an assignment the shell does not keep is not used", () => {
	const space = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
	const run = async () => ({ ok: true, stdout: "abc\n" })
	const env = { X: "/" }
	for (const command of [
		'X=./build make; rm -rf "$X"', // env prefix: X is set for make alone
		'X=./build | true; rm -rf "$X"', // pipeline: a subshell
		'X=./build & rm -rf "$X"', // background: a subshell
		'false && X=./build; rm -rf "$X"', // conditional
		'export X=./build; rm -rf "$X"', // set by a builtin the scan does not follow
		'read X; rm -rf "$X"',
	]) {
		it(command, async () => {
			const r = await resolveCommand(command, { run, env, space })
			if ("concrete" in r) expect(r.concrete).not.toContain("'./build'")
			if ("concrete" in r) expect(r.concrete).not.toContain("rm -rf '/'")
		})
	}

	it("a clean statement-level assignment from a read-only substitution still resolves", async () => {
		const r = await resolveCommand('X=$(git rev-parse HEAD); git show "$X"', { run, env, space })
		expect("concrete" in r && r.concrete).toContain("git show 'abc'")
	})
})

describe("credentials are never copied into a concrete command", () => {
	const space = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
	it("does not resolve a variable named like a credential", async () => {
		const run = async () => ({ ok: true, stdout: "" })
		const r = await resolveCommand('curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com', {
			run, env: { GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" }, space,
		})
		expect("concrete" in r).toBe(false)
	})
	it("does not resolve a substitution whose output looks like a credential", async () => {
		const run = async () => ({ ok: true, stdout: "https://user:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/x/y.git\n" })
		const r = await resolveCommand('echo "$(git config --get remote.origin.url)"', { run, env: {}, space })
		expect("concrete" in r).toBe(false)
	})
})
