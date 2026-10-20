/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The config surface behind grant-backed authority: `authority.persist` plus the two
 * provenance keys a footer needs to say why the session is unattended.
 *
 * What this file is pinning, in order of how much it would hurt to get wrong:
 *
 * 1. **The default is `"grants"`, and it is asserted rather than implied.** That is a
 *    behaviour change for anyone who relied on "Allow always" appending a rule line to
 *    `permissions.json`; after it, that answer is a journal row instead. A default that
 *    moves must be written down somewhere a test fails when it slips.
 * 2. **A value nobody recognises is refused and reported, never quietly rewritten.**
 *    `positiveInt()` above may fall back silently because a bad *number* is merely
 *    unusable; a bad *storage target* is not — "keep writing rule files" versus "start
 *    writing journal rows" is exactly the kind of thing a person must be told about.
 * 3. **Precedence is per key and per layer** (user < project < runtime), matching the
 *    order `permissions-loader.ts` already merges rules in, so the two channels cannot
 *    disagree about which file wins.
 * 4. **The project layer cannot smuggle in rules.** Rules have one source each; this
 *    module models two keys and nothing else, and a test says so in case someone later
 *    "helpfully" reads a `permissions` block from the project config file.
 *
 * There is deliberately NO test for "a project config cannot loosen a user-level never":
 * `config.ts` has no never-tier notion — nothing here can produce a verdict, only choose
 * where an already-made decision is stored. Inventing one to satisfy a checklist would
 * put a fake security property in the file that pins nothing.
 */
import { beforeEach, afterEach, describe, expect, it, vi, type MockInstance } from "vitest"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
	AUTHORITY_PERSIST_VALUES,
	DEFAULT_AUTHORITY_PERSIST,
	MAX_SOURCE_CHARS,
	PROVENANCE_KEYS,
	applyAuthorityLayers,
	getAuthorityDiagnostics,
	getAuthorityPersist,
	getAuthorityPersistOrigin,
	getAuthoritySnapshot,
	getProvenance,
	getProjectConfigPath,
	loadPermissionModesConfig,
	loadProjectPermissionModesConfig,
	resolveAuthorityLayers,
	setConfigPath,
	setRuntimeAuthority,
	updatePermissionModesConfig,
	type ConfigLayers,
	type ConfigProvenance,
} from "./config.ts"

// `MockInstance`, spelled out: `ReturnType<typeof vi.spyOn>` resolves through the LAST overload of a
// generic function, which is a MockInstance whose args/returns do not line up with console.warn's — the
// assignment below is what tsc was objecting to. The default type arguments are the ones that fit.
let warn: MockInstance
let tmpDirs: string[] = []

beforeEach(() => {
	// The cached view is module state; every test starts from "no layer said anything".
	applyAuthorityLayers({})
	warn = vi.spyOn(console, "warn").mockImplementation(() => {})
	tmpDirs = []
})

afterEach(() => {
	warn.mockRestore()
	for (const dir of tmpDirs) rmSync(dir, { recursive: true, force: true })
})

function tmpProject(body?: Record<string, unknown>): string {
	const dir = mkdtempSync(join(tmpdir(), "pm-authority-"))
	tmpDirs.push(dir)
	mkdirSync(join(dir, ".pi"), { recursive: true })
	if (body) {
		writeFileSync(
			getProjectConfigPath(dir),
			JSON.stringify(body, null, 2),
			"utf-8",
		)
	}
	return dir
}

describe("authority.persist — the default", () => {
	// The one-line answer for the CHANGELOG, written as an assertion so it cannot drift.
	it("defaults to the journal, not to rule files", () => {
		expect(DEFAULT_AUTHORITY_PERSIST).toBe("grants")
		expect(resolveAuthorityLayers({}).persist).toBe("grants")
		expect(resolveAuthorityLayers({}).persistOrigin).toBe("default")
		expect(getAuthorityPersist()).toBe("grants")
	})

	it("does not keep the old rule-file behaviour as the default for compatibility", () => {
		expect(getAuthorityPersist()).not.toBe("rules")
		// ...while rule-file support stays selectable, so npm users are one line away from it.
		expect(AUTHORITY_PERSIST_VALUES).toContain("rules")
		expect(resolveAuthorityLayers({ user: { authority: { persist: "rules" } } }).persist).toBe(
			"rules",
		)
	})

	it("names exactly two targets", () => {
		expect([...AUTHORITY_PERSIST_VALUES].sort()).toEqual(["grants", "rules"])
	})
})

describe("authority.persist — validation", () => {
	it("accepts each documented target and records which layer it came from", () => {
		for (const value of AUTHORITY_PERSIST_VALUES) {
			const r = resolveAuthorityLayers({ user: { authority: { persist: value } } })
			expect(r.persist).toBe(value)
			expect(r.persistOrigin).toBe("user")
			expect(r.diagnostics).toEqual([])
		}
	})

	it("refuses a value it does not know, says so, and does not dress it up as the default", () => {
		const r = resolveAuthorityLayers({ user: { authority: { persist: "jurnal" as never } } })
		expect(r.persist).toBe("grants")
		expect(r.persistOrigin).toBe("default")
		expect(r.diagnostics).toHaveLength(1)
		expect(r.diagnostics[0]).toContain('"jurnal"')
		expect(r.diagnostics[0]).toContain("grants | rules")
		expect(r.diagnostics[0]).toContain("kept")
	})

	it("the refusal reaches the user, not just the diagnostics array", () => {
		// Distinct value: the warn dedupe is per message per process, by design.
		applyAuthorityLayers({ user: { authority: { persist: "file" as never } } })
		expect(getAuthorityDiagnostics()).toHaveLength(1)
		expect(warn).toHaveBeenCalledTimes(1)
		expect(String(warn.mock.calls[0][0])).toContain("[permission-modes]")
		expect(String(warn.mock.calls[0][0])).toContain("authority.persist")
	})

	it("a bad value never outranks a good one — it is skipped, the lower layer stands", () => {
		const r = resolveAuthorityLayers({
			user: { authority: { persist: "rules" } },
			project: { authority: { persist: "GRANTS" as never } },
		})
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("user")
		expect(r.diagnostics).toHaveLength(1)
		expect(r.diagnostics[0]).toContain("kept \"rules\" (from user)")
	})

	it("garbage in the runtime layer cannot override a project choice either", () => {
		const r = resolveAuthorityLayers({
			project: { authority: { persist: "rules" } },
			runtime: { authority: { persist: null as never } },
		})
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("project")
		expect(r.diagnostics).toHaveLength(1)
	})

	it("rejects every near-miss spelling rather than guessing what was meant", () => {
		for (const bad of ["Grants", " grants", "rule", "grant", "journal", "", true, 1, 0, null, {}, []]) {
			const r = resolveAuthorityLayers({ runtime: { authority: { persist: bad as never } } })
			expect(r.persist).toBe("grants")
			expect(r.diagnostics).toHaveLength(1)
		}
	})

	it("an explicit null is refused instead of being read as 'not set'", () => {
		// Silently treating null as absent would make `{"persist": null}` look like the
		// default the user did not choose, with no trace. It is reported either way.
		const r = resolveAuthorityLayers({ user: { authority: { persist: null as never } } })
		expect(r.diagnostics).toHaveLength(1)
		expect(r.diagnostics[0]).toContain("authority.persist=null")
	})
})

describe("precedence: user < project < runtime", () => {
	it("user config alone is honoured", () => {
		const r = resolveAuthorityLayers({ user: { authority: { persist: "rules" } } })
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("user")
	})

	it("project config overrides user config", () => {
		const r = resolveAuthorityLayers({
			user: { authority: { persist: "grants" } },
			project: { authority: { persist: "rules" } },
		})
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("project")
	})

	it("runtime flags override project config", () => {
		const r = resolveAuthorityLayers({
			user: { authority: { persist: "grants" } },
			project: { authority: { persist: "rules" } },
			runtime: { authority: { persist: "grants" } },
		})
		expect(r.persist).toBe("grants")
		expect(r.persistOrigin).toBe("runtime")
	})

	it("a layer that omits the key inherits instead of resetting it", () => {
		const r = resolveAuthorityLayers({
			user: { authority: { persist: "rules" } },
			project: {},
			runtime: {},
		})
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("user")
	})

	it("runtime works with no config file at all (a start flag with nothing on disk)", () => {
		const r = resolveAuthorityLayers({ runtime: { authority: { persist: "rules" } } })
		expect(r.persist).toBe("rules")
		expect(r.persistOrigin).toBe("runtime")
		expect(r.diagnostics).toEqual([])
	})
})

describe("provenance: modeSetBy / unattendedSetBy", () => {
	it("both keys are exported and both default to absent — absent means nobody told us", () => {
		expect([...PROVENANCE_KEYS]).toEqual(["modeSetBy", "unattendedSetBy"])
		expect(getProvenance()).toEqual({})
		expect(getProvenance().modeSetBy).toBeUndefined()
		expect(getProvenance().unattendedSetBy).toBeUndefined()
	})

	it("each key resolves independently, so a caller can attribute one without the other", () => {
		const r = resolveAuthorityLayers({
			user: { modeSetBy: "command" },
			project: { unattendedSetBy: "child-bridge" },
		})
		expect(r.provenance).toEqual({
			modeSetBy: "command",
			unattendedSetBy: "child-bridge",
		})
	})

	it("project beats user and runtime beats project, per key", () => {
		const r = resolveAuthorityLayers({
			user: { modeSetBy: "user-a", unattendedSetBy: "user-b" },
			project: { modeSetBy: "project-a" },
			runtime: { unattendedSetBy: "restore" },
		})
		expect(r.provenance).toEqual({
			modeSetBy: "project-a",
			unattendedSetBy: "restore",
		})
	})

	it("the vocabulary is the caller's: config stores any short string without judging it", () => {
		const r = resolveAuthorityLayers({ runtime: { modeSetBy: "plan-flow" } })
		expect(r.provenance.modeSetBy).toBe("plan-flow")
		expect(r.diagnostics).toEqual([])
	})

	it("trims surrounding whitespace so the footer cannot get ' command'", () => {
		expect(resolveAuthorityLayers({ runtime: { modeSetBy: "  command\n" } }).provenance.modeSetBy).toBe(
			"command",
		)
	})

	it("refuses a non-string, a blank, and an over-long value, keeping the layer below", () => {
		const cases: unknown[] = [42, true, {}, [], null, "", "   ", "x".repeat(MAX_SOURCE_CHARS + 1)]
		for (const bad of cases) {
			const r = resolveAuthorityLayers({
				user: { unattendedSetBy: "command" },
				runtime: { unattendedSetBy: bad as never },
			})
			expect(r.provenance.unattendedSetBy).toBe("command")
			expect(r.diagnostics).toHaveLength(1)
			expect(r.diagnostics[0]).toContain("unattendedSetBy")
			expect(r.diagnostics[0]).toContain("runtime")
		}
	})

	it("accepts a value exactly at the length cap", () => {
		const value = "s".repeat(MAX_SOURCE_CHARS)
		expect(resolveAuthorityLayers({ runtime: { modeSetBy: value } }).provenance.modeSetBy).toBe(
			value,
		)
	})

	it("hands out a frozen object: a caller cannot corrupt the cached view", () => {
		applyAuthorityLayers({ runtime: { modeSetBy: "command" } })
		const p = getProvenance()
		expect(Object.isFrozen(p)).toBe(true)
		expect(() => {
			;(p as ConfigProvenance).modeSetBy = "something-else"
		}).toThrow()
		expect(getProvenance().modeSetBy).toBe("command")
	})
})

describe("the cached view the hot paths read", () => {
	it("applyAuthorityLayers replaces all three layers", () => {
		applyAuthorityLayers({ user: { authority: { persist: "rules" }, modeSetBy: "command" } })
		expect(getAuthorityPersist()).toBe("rules")
		expect(getProvenance().modeSetBy).toBe("command")

		applyAuthorityLayers({})
		expect(getAuthorityPersist()).toBe("grants")
		expect(getAuthorityPersistOrigin()).toBe("default")
		expect(getProvenance()).toEqual({})
	})

	it("setRuntimeAuthority keeps the file layers and replaces only the runtime one", () => {
		applyAuthorityLayers({
			user: { authority: { persist: "rules" } },
			project: { unattendedSetBy: "child-bridge" },
		})
		expect(setRuntimeAuthority({ modeSetBy: "command" }).persist).toBe("rules")
		expect(getProvenance()).toEqual({
			unattendedSetBy: "child-bridge",
			modeSetBy: "command",
		})

		// Two flips in a row must not accumulate: the second call replaces the runtime layer.
		setRuntimeAuthority({ modeSetBy: "plan-flow" })
		expect(getProvenance().modeSetBy).toBe("plan-flow")

		setRuntimeAuthority(undefined)
		expect(getAuthorityPersist()).toBe("rules")
		expect(getProvenance()).toEqual({ unattendedSetBy: "child-bridge" })
	})

	it("diagnostics survive an apply so a footer can surface them after the warn", () => {
		const snapshot = applyAuthorityLayers({ user: { authority: { persist: "rulez" as never } } })
		expect(snapshot).toBe(getAuthoritySnapshot())
		expect(getAuthorityDiagnostics()).toEqual(snapshot.diagnostics)
		expect(getAuthorityDiagnostics()[0]).toContain("authority.persist")
	})

	it("the getters allocate nothing per call — same frozen objects every time", () => {
		applyAuthorityLayers({ user: { modeSetBy: "command" } })
		expect(getProvenance()).toBe(getProvenance())
		expect(getAuthorityDiagnostics()).toBe(getAuthorityDiagnostics())
	})
})

describe("the project config file `<cwd>/.pi/adaptive-acl.json`", () => {
	it("is resolved at a fixed path under the project, not under a derived project id", () => {
		expect(getProjectConfigPath("/home/x/proj")).toBe("/home/x/proj/.pi/adaptive-acl.json")
	})

	it("a project file selecting rule-file persistence loads and wins over the default", () => {
		const cwd = tmpProject({ authority: { persist: "rules" } })
		const project = loadProjectPermissionModesConfig(cwd)
		expect(project.authority?.persist).toBe("rules")

		// Hermetic: point the *user* layer at a file that does not exist, so this test cannot
		// be retargeted by whatever is in the real ~/.pi/agent/adaptive-acl.json.
		setConfigPath(join(cwd, "agent", "adaptive-acl.json"))
		applyAuthorityLayers({ user: loadPermissionModesConfig(), project })
		expect(getAuthorityPersist()).toBe("rules")
		expect(getAuthorityPersistOrigin()).toBe("project")
		expect(getAuthorityDiagnostics()).toEqual([])
	})

	it("a user file alone can select rule-file persistence (the npm-user escape hatch)", () => {
		const dir = tmpProject()
		const agent = join(dir, "agent", "adaptive-acl.json")
		mkdirSync(join(dir, "agent"), { recursive: true })
		writeFileSync(agent, JSON.stringify({ authority: { persist: "rules" } }), "utf-8")
		setConfigPath(agent)

		applyAuthorityLayers({ user: loadPermissionModesConfig(), project: {} })
		expect(getAuthorityPersist()).toBe("rules")
		expect(getAuthorityPersistOrigin()).toBe("user")
	})

	it("a missing file is an empty layer, not an error", () => {
		expect(loadProjectPermissionModesConfig(tmpProject())).toEqual({})
		expect(loadProjectPermissionModesConfig("/nonexistent/nope")).toEqual({})
	})

	it("an unparseable or non-object file is an empty layer plus one warning, never a throw", () => {
		const broken = tmpProject()
		writeFileSync(getProjectConfigPath(broken), '{ "authority": { persist: ', "utf-8")
		expect(loadProjectPermissionModesConfig(broken)).toEqual({})

		const array = tmpProject()
		writeFileSync(getProjectConfigPath(array), "[1,2]", "utf-8")
		expect(loadProjectPermissionModesConfig(array)).toEqual({})
		expect(warn).toHaveBeenCalledTimes(2)
	})

	it("models only its own keys — a permissions block here cannot become a rule source", () => {
		// Rules keep exactly one source each (global file + `.pi/projects/<id>/permissions*.json`,
		// both via permissions-loader.ts). A second path that could grant Bash/Edit authority
		// through a project directory nobody audited is not what this file is for.
		const cwd = tmpProject({
			permissions: { deny: ["Bash(rm -rf /*)"], allow: ["Bash(curl http://evil)"] },
		})
		const layers: ConfigLayers = { project: loadProjectPermissionModesConfig(cwd) }
		const r = resolveAuthorityLayers(layers)
		expect(r.persist).toBe("grants")
		expect(r.diagnostics).toEqual([])
		expect(Object.keys(r)).toEqual(["persist", "persistOrigin", "provenance", "diagnostics"])
		expect(r.provenance).toEqual({})
	})

	it("an unknown key in the project file is inert, not an error", () => {
		const cwd = tmpProject({ someFutureKey: { a: 1 }, authority: { persist: "rules" } })
		const project = loadProjectPermissionModesConfig(cwd)
		expect((project as Record<string, unknown>).someFutureKey).toEqual({ a: 1 })
		expect(resolveAuthorityLayers({ project }).persist).toBe("rules")
	})
})

describe("the config writer round-trips the new keys", () => {
	it("preserves authority + provenance alongside keys the plugin does not model", () => {
		const dir = mkdtempSync(join(tmpdir(), "pm-authority-write-"))
		tmpDirs.push(dir)
		const path = join(dir, "nested", "adaptive-acl.json")
		setConfigPath(path)

		expect(
			updatePermissionModesConfig((c) => {
				c.authority = { persist: "rules" }
				c.modeSetBy = "command"
			}),
		).toBe(true)

		expect(readFileSync(path, "utf-8")).toContain('"persist": "rules"')

		expect(
			updatePermissionModesConfig((c) => {
				c.injectionWarning = false
			}),
		).toBe(true)

		const back = loadPermissionModesConfig()
		expect(back.authority).toEqual({ persist: "rules" })
		expect(back.modeSetBy).toBe("command")
		expect(back.injectionWarning).toBe(false)
		expect(applyAuthorityLayers({ user: back }).persist).toBe("rules")
	})
})
