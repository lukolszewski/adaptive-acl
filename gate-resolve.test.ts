/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Gate ↔ resolver integration: layer 2 runs before the gate decides, and the verdict is then about the
 * command that will actually run. Two properties matter more than the happy path, so they are pinned
 * first: a command the resolver declines keeps *today's* result byte for byte, and the resolver never
 * runs anything the read-only rule refuses (the fake runner records every call).
 */

import { describe, expect, it, vi } from "vitest"
import { parseBashCommand, type AstCommand, type Slot, type TemplateCommand, type TemplateParse } from "./bash-ast.ts"
import { runGate, type GateOptions, type ResolveOutcome } from "./gate.ts"
import { RESOLVE_TIMEOUT_MS, resolveCommand, type Runner } from "./value-resolve.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }
const SPACE = { cwd: POLICY.cwd, project: POLICY.project, home: POLICY.home }

// --------------------------------------------------------------------------- fixtures

type SlotSeed = Omit<Slot, "span"> & { at: string }
type PartSeed = { text: string; argv: string[]; slots?: SlotSeed[]; extra?: Partial<AstCommand> }

/** Hand-built template parse (independent of `parseBashTemplate`), spans read off the source. */
function tmpl(command: string, parts: PartSeed[]): TemplateParse {
	let cursor = 0
	const commands: TemplateCommand[] = parts.map((part) => {
		const start = command.indexOf(part.text, cursor)
		if (start < 0) throw new Error(`fixture: "${part.text}" is not in "${command}"`)
		cursor = start + part.text.length
		let local = 0
		const slots: Slot[] = (part.slots ?? []).map(({ at, ...rest }) => {
			const i = part.text.indexOf(at, local)
			if (i < 0) throw new Error(`fixture: "${at}" is not in "${part.text}"`)
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

const varSlot = (name: string, at: string, extra: Partial<Slot> = {}): SlotSeed => ({
	argIndex: 1,
	quoted: true,
	whole: true,
	source: "var",
	name,
	at,
	...extra,
})

const subSlot = (inner: string, at: string): SlotSeed => ({ argIndex: 1, quoted: true, whole: true, source: "cmdsub", inner, at })

/** Injected parse: the command under test from the fixture, everything else from the real parser. */
function parserFor(map: Record<string, TemplateParse>) {
	return (command: string): TemplateParse => {
		const hit = map[command]
		if (hit) return hit
		const real = parseBashCommand(command)
		if (real.kind !== "simple") return real
		return { kind: "simple", commands: real.commands.map((c) => ({ ...c, slots: [] })) }
	}
}

const runner = (stdout = "abc123\n") => {
	const calls: string[] = []
	const run: Runner = async (script, opts) => {
		calls.push(`${script} @ ${opts.cwd} ${opts.timeoutMs}ms`)
		return { ok: true, stdout }
	}
	return { calls, run }
}

function gateWith(map: Record<string, TemplateParse>, env: Record<string, string | undefined>, run: Runner): GateOptions {
	return { policy: POLICY, resolve: (command) => resolveCommand(command, { run, env, space: SPACE, parse: parserFor(map) }) }
}

// --------------------------------------------------------------------------- resolved

describe("runGate — a resolved command is judged as the command that will run", () => {
	it("allows `wc -l \"$F\"` as a project read once F is filled in", async () => {
		const command = `wc -l "$F"`
		const { calls, run } = runner()
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, { F: "src/a.ts" }, run))
		expect(r.outcome).toBe("allow")
		expect(r.tier).toBe("allow")
		expect(r.category).toBe("read_only")
		expect(r.resolved).toEqual({ concrete: `wc -l 'src/a.ts'`, values: [{ source: "$F", value: "src/a.ts" }] })
		// A variable needs no runner; only a substitution does.
		expect(calls).toEqual([])
	})

	it("still asks for `wc -l \"$F\"` when F is a secret", async () => {
		const command = `wc -l "$F"`
		const { run } = runner()
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, { F: "/home/u/.ssh/id_rsa" }, run))
		expect(r.outcome).toBe("prompt")
		expect(r.tier).toBe("ask")
		expect(r.category).toBe("read_secret")
		// The prompt can say which value it was about, and which command it would really be.
		expect(r.resolved?.concrete).toBe(`wc -l '/home/u/.ssh/id_rsa'`)
		expect(r.entities.map((e) => e.value)).toContain("~/.ssh/id_rsa")
	})

	it("also treats a `~` value as the secret it is", async () => {
		const command = `wc -l "$F"`
		const { run } = runner()
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "__TRACKED_VAR__"], slots: [varSlot("F", "$F", { argIndex: 2 })] }])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, { F: "~/.ssh/id_rsa" }, run))
		expect(r.category).toBe("read_secret")
		expect(r.outcome).toBe("prompt")
	})

	it("allows `git show \"$(git rev-parse HEAD)\"` after running the read-only substitution", async () => {
		const command = `git show "$(git rev-parse HEAD)"`
		const { calls, run } = runner("abc123\n")
		const parse = tmpl(command, [
			{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot("git rev-parse HEAD", "$(git rev-parse HEAD)")] },
		])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, {}, run))
		expect(r.outcome).toBe("allow")
		expect(r.resolved).toEqual({ concrete: `git show 'abc123'`, values: [{ source: "$(git rev-parse HEAD)", value: "abc123" }] })
		expect(calls).toEqual([`git rev-parse HEAD @ ${SPACE.cwd} ${RESOLVE_TIMEOUT_MS}ms`])
	})

	it("resolves through an assignment earlier in the same command", async () => {
		const command = `X=$(git rev-parse HEAD); git show "$X"`
		const { calls, run } = runner("abc123\n")
		const parse = tmpl(command, [
			{ text: "git rev-parse HEAD", argv: ["git", "rev-parse", "HEAD"] },
			{ text: `git show "$X"`, argv: ["git", "show", "__TRACKED_VAR__"], slots: [varSlot("X", "$X", { argIndex: 2 })] },
		])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, {}, run))
		expect(r.outcome).toBe("allow")
		expect(r.resolved?.concrete).toBe(`X=$(git rev-parse HEAD); git show 'abc123'`)
		expect(calls).toHaveLength(1)
	})
})

// --------------------------------------------------------------------------- unresolved

describe("runGate — every refusal leaves the gate exactly as it was", () => {
	/** The result with no resolver at all: what any refusal must be identical to. */
	async function today(command: string) {
		return await runGate("bash", { command }, { policy: POLICY })
	}

	it("keeps today's verdict when the substitution is not read-only, and runs nothing", async () => {
		const command = `git show "$(mktemp)"`
		const { calls, run } = runner()
		const parse = tmpl(command, [{ text: command, argv: ["git", "show", "__CMDSUB_OUTPUT__"], slots: [subSlot("mktemp", "$(mktemp)")] }])
		const r = await runGate("bash", { command }, gateWith({ [command]: parse }, {}, run))
		expect(r).toEqual(await today(command))
		expect(r.resolved).toBeUndefined()
		expect(calls).toEqual([])
	})

	it("keeps today's verdict when a value would be split or globbed", async () => {
		const command = `wc -l $F`
		const { run } = runner()
		const parse = tmpl(command, [{ text: command, argv: ["wc", "-l", "$F"], slots: [varSlot("F", "$F", { argIndex: 2, quoted: false })] }])
		for (const F of ["a b", "src/*.ts"]) {
			const r = await runGate("bash", { command }, gateWith({ [command]: parse }, { F }, run))
			expect(r, F).toEqual(await today(command))
			expect(r.resolved, F).toBeUndefined()
		}
	})

	it("keeps today's verdict when the resolver throws", async () => {
		const command = `wc -l "$F"`
		const resolve = vi.fn(async (): Promise<ResolveOutcome> => {
			throw new Error("runner exploded")
		})
		const r = await runGate("bash", { command }, { policy: POLICY, resolve })
		expect(resolve).toHaveBeenCalledOnce()
		expect(r).toEqual(await today(command))
	})

	it("does not call the resolver when layer 0 already allows, or for another tool", async () => {
		const resolve = vi.fn(async (): Promise<ResolveOutcome> => ({ unresolved: "should not be asked" }))
		const allowed = await runGate("bash", { command: "ls -la" }, { policy: POLICY, resolve })
		expect(allowed.tier).toBe("allow")
		expect(resolve).not.toHaveBeenCalled()
		const read = await runGate("read", { path: "src/a.ts" }, { policy: POLICY, resolve })
		expect(read.tier).toBe("allow")
		expect(resolve).not.toHaveBeenCalled()
	})
})

describe("never stays never", () => {
	it("does not call the resolver for a command layer 0 rates never", async () => {
		const { runGate } = await import("./gate.ts")
		let called = 0
		const r = await runGate("bash", { command: 'rm -rf / "$X"' }, {
			policy: { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false },
			resolve: async () => { called++; return { unresolved: "test" } },
		} as never)
		expect(r.resolved).toBeUndefined()
		expect(called).toBe(0)
	})
})
