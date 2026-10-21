/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { afterAll, describe, expect, it } from "vitest"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { evaluateBash, evaluateBashLegacy, type PolicyDecision, type PolicyOptions } from "./risk-policy.ts"
import { PROTECTED_BRANCH_RE } from "./risk-handlers.ts"

/**
 * Layer 0's publish targets, pinned as the strings a grant has to be able to name.
 *
 * Every row here is about the *entity*, not the tier: a pending row whose target is
 * `origin/(current branch)` can never be covered by a stored row naming the real branch, so the user
 * approves the same push forever and `/grants` shows a row that looks like it should have worked. Same
 * failure one level down for a container publish, whose intent ("publish this artifact") is split across
 * two categories with no bridge, and for a project virtualenv the handler could see only when the caller
 * happened to pass `env`.
 */

const PROJ = "/home/dev/proj"
const HOME = "/home/dev"

const opts = (over: Partial<PolicyOptions> = {}): PolicyOptions => ({ cwd: PROJ, project: PROJ, home: HOME, fs: false, ...over })
const verdict = (cmd: string, over: Partial<PolicyOptions> = {}): PolicyDecision => evaluateBash(cmd, opts(over))

/** Entities as `kind:value` — the pair a stored grant row is compared against. */
const ents = (d: PolicyDecision): string[] => d.entities.map((e) => `${e.kind}:${e.value}`)

/**
 * The three environments every env-sensitive row is measured in.
 *   - `NO_ENV` — nothing known: probes off, nothing in env. What a caller with no information produces;
 *   - `VENV_ENV` — the user activated an env outside the tool call, so only the variable says so;
 *   - `ON_DISK` — a throwaway project that genuinely has two venv roots, probes on.
 *
 * Each states `env` explicitly instead of inheriting whichever shell the suite happened to run in — the same
 * reason vitest.setup.ts scrubs the plugin's own variables out of the environment before a file starts.
 */
const diskRoot = mkdtempSync(path.join(tmpdir(), "publish-venv-"))
for (const venv of [".venv", ".venv311"]) {
	mkdirSync(path.join(diskRoot, venv, "bin"), { recursive: true })
	writeFileSync(path.join(diskRoot, venv, "pyvenv.cfg"), "home = /usr/bin\nversion = 3.11.0\n")
}
// `looksvenv/bin/pip` with no pyvenv.cfg: the probe reads a file, it does not trust a directory name.
mkdirSync(path.join(diskRoot, "looksvenv", "bin"), { recursive: true })
afterAll(() => rmSync(diskRoot, { recursive: true, force: true }))

const NO_ENV: PolicyOptions = { cwd: PROJ, project: PROJ, home: HOME, fs: false, env: {} }
const VENV_ENV: PolicyOptions = { ...NO_ENV, env: { VIRTUAL_ENV: path.join(PROJ, ".venv") } }
const CONDA_ENV: PolicyOptions = { ...NO_ENV, env: { CONDA_PREFIX: "/home/dev/miniconda3" } }
const ON_DISK: PolicyOptions = { cwd: diskRoot, project: diskRoot, home: HOME, fs: true, env: {} }

/** tier/category, so a table row reads as one cell. */
const cell = (cmd: string, o: PolicyOptions): string => {
	const d = evaluateBash(cmd, o)
	return `${d.tier}/${d.category}`
}

describe("git push resolves the branch it writes to", () => {
	it("a bare push names the session branch", () => {
		const d = verdict("git push", { gitBranch: "feature/x" })
		expect(d.tier, d.reason).toBe("ask")
		expect(d.category).toBe("vcs_remote")
		expect(ents(d)).toContain("target:origin/feature/x")
		expect(ents(d)).toContain("scope:origin/*")
		expect(d.description).toContain("git push (current branch feature/x) to origin")
	})

	it("a bare push stays anonymous when the session has no branch", () => {
		for (const gitBranch of [undefined, "", "   "]) {
			const d = verdict("git push", { gitBranch })
			expect(ents(d), String(gitBranch)).toContain("target:origin/(current branch)")
			expect(d.tier, String(gitBranch)).toBe("ask")
		}
	})

	it("a named remote plus the session branch is still origin/<branch>", () => {
		expect(ents(verdict("git push origin", { gitBranch: "feature/x" }))).toContain("target:origin/feature/x")
		expect(ents(verdict("git push upstream", { gitBranch: "feature/x" }))).toContain("target:upstream/feature/x")
		expect(verdict("git push upstream", { gitBranch: "feature/x" }).description).toContain("to upstream")
	})

	it("each refspec spelling resolves to the remote-side name, refs/heads/ and + stripped", () => {
		for (const cmd of [
			"git push origin HEAD:feat/x",
			"git push origin local:feat/x",
			"git push origin +feat/x",
			"git push origin refs/heads/feat/x",
			"git push origin +refs/heads/feat/x",
			"git push origin feat/x",
		]) {
			const d = verdict(cmd, { gitBranch: "unrelated/branch" })
			expect(ents(d), cmd).toContain("target:origin/feat/x")
			expect(ents(d), cmd).toContain("scope:origin/*")
		}
	})

	it("a refspec outranks the session branch", () => {
		const d = verdict("git push origin main:hotfix", { gitBranch: "feature/x" })
		expect(ents(d)).toContain("target:origin/hotfix")
		expect(ents(d)).not.toContain("target:origin/feature/x")
	})

	it("the protected-branch rung sees the resolved branch", () => {
		const d = verdict("git push --force", { gitBranch: "main" })
		expect(d.tier, d.reason).toBe("never")
		expect(d.category).toBe("vcs_force_protected")
		expect(ents(d)).toContain("target:origin/main")
		expect(d.description).toContain("protected branch main")
	})

	it("a force-with-lease and a delete on the session branch hit the same floor", () => {
		expect(verdict("git push --force-with-lease", { gitBranch: "master" }).tier).toBe("never")
		expect(verdict("git push --delete", { gitBranch: "release/2.4" }).tier).toBe("never")
	})

	it("a force push of a feature branch stays an ask", () => {
		const d = verdict("git push --force", { gitBranch: "feature/x" })
		expect(d.tier).toBe("ask")
		expect(ents(d)).toContain("target:origin/feature/x")
	})

	it("exports the protected-branch table the grant grammar mirrors", () => {
		expect(PROTECTED_BRANCH_RE.test("main")).toBe(true)
		expect(PROTECTED_BRANCH_RE.test("release/2.4")).toBe(true)
		expect(PROTECTED_BRANCH_RE.test("feature/x")).toBe(false)
	})
})

describe("an artifact push is one intent with two names", () => {
	it.each(["docker", "podman", "nerdctl"])("%s push asks as container_mutation AND network_send", (bin) => {
		const d = verdict(`${bin} push myrepo/app:1.0`)
		expect(d.tier, d.reason).toBe("ask")
		expect(d.category).toBe("container_mutation+network_send")
		expect(ents(d)).toEqual(["target:myrepo/app:1.0", "scope:myrepo/app"])
		expect(d.description).toContain(`${bin} push myrepo/app:1.0`)
	})

	it("puts both rows on the same raw command", () => {
		const d = verdict("docker push myrepo/app:1.0")
		expect(d.segments.map((s) => [s.tier, s.category])).toEqual([
			["ask", "container_mutation"],
			["ask", "network_send"],
		])
		expect(new Set(d.segments.map((s) => s.command))).toEqual(new Set(["docker push myrepo/app:1.0"]))
	})

	it("scopes to the repository so one answer covers any tag of it", () => {
		expect(ents(verdict("docker push myrepo/app:2.3.4-alpine"))).toEqual(["target:myrepo/app:2.3.4-alpine", "scope:myrepo/app"])
		expect(ents(verdict("docker push myrepo/app@sha256:0123abcd"))).toEqual(["target:myrepo/app@sha256:0123abcd", "scope:myrepo/app"])
		expect(ents(verdict("docker push myrepo/app"))).toEqual(["target:myrepo/app", "scope:myrepo/app"])
	})

	it("keeps a registry port out of the tag position", () => {
		expect(ents(verdict("docker push registry.example.com:5000/app:1.0"))).toEqual([
			"target:registry.example.com:5000/app:1.0",
			"scope:registry.example.com:5000/app",
		])
	})

	it("finds the ref behind the flags", () => {
		expect(ents(verdict("docker push --all-tags myrepo/app:1.0"))).toContain("target:myrepo/app:1.0")
	})

	it("invents no target when no ref was given", () => {
		const d = verdict("docker push")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("container_mutation+network_send")
		expect(d.entities).toEqual([])
	})

	it("helm push names the oci ref, without its scheme", () => {
		const d = verdict("helm push mychart-0.1.0.tgz oci://registry.example.com/charts")
		expect(d.tier, d.reason).toBe("ask")
		expect(d.category).toBe("container_mutation+network_send")
		expect(ents(d)).toEqual(["target:registry.example.com/charts", "scope:registry.example.com/charts"])
		expect(d.description).not.toContain("oci://")
	})

	it("oras push names the ref it publishes", () => {
		const d = verdict("oras push localhost:5000/hello:v1")
		expect(d.tier, d.reason).toBe("ask")
		expect(d.category).toBe("container_mutation+network_send")
		expect(ents(d)).toEqual(["target:localhost:5000/hello:v1", "scope:localhost:5000/hello"])
	})

	it("does not invent a `gh cr push` — that is not a gh command", () => {
		const d = verdict("gh cr push myrepo/app")
		expect(d.category).not.toContain("container_mutation")
		expect(d.category).not.toBe("container_mutation+network_send")
	})

	it("leaves the container verbs that are not a publish alone", () => {
		expect(verdict("docker pull myrepo/app:1.0").tier).toBe("allow")
		expect(verdict("docker rmi app:prod").category).toBe("container_mutation")
		expect(verdict("helm uninstall web -n prod").category).toBe("cluster_mutation")
	})
})

/**
 * The pip matrix.
 *
 * A project virtualenv is the difference between "this repo's env" (allow, run_project_code) and "whatever
 * python this machine has" (ask, package_system), and layer 0 could only see it when a caller happened to
 * hand over `env` — which no production caller did. So every row is measured in three environments:
 * nothing known, the env var set, and a venv actually on disk (fs probes on). `--user` / `--system` /
 * `--break-system-packages` / an out-of-project `--target` outrank all three: those flags say the write
 * leaves the env, whatever env it was run from.
 */
describe("pip asks only when it can leave the project env", () => {
	/** command, no env, env set, venv on disk (probes on) */
	const rows: [string, string, string, string][] = [
		["pip install httpx", "ask/package_system", "allow/run_project_code", "ask/package_system"],
		["pip3 install httpx", "ask/package_system", "allow/run_project_code", "ask/package_system"],
		["python -m pip install httpx", "ask/package_system", "allow/run_project_code", "ask/package_system"],
		// uv manages the project env itself; --system is how you tell it not to.
		["uv pip install httpx", "allow/run_project_code", "allow/run_project_code", "allow/run_project_code"],
		["uv pip install --system httpx", "ask/package_system", "ask/package_system", "ask/package_system"],
		// the interpreter path is the evidence, and it has to resolve against the command's own cwd
		[".venv/bin/pip install httpx", "ask/package_system", "allow/run_project_code", "allow/run_project_code"],
		[".venv311/bin/pip install httpx", "ask/package_system", "allow/run_project_code", "allow/run_project_code"],
		[".venv/bin/python -m pip install httpx", "ask/package_system", "allow/run_project_code", "allow/run_project_code"],
		[`${diskRoot}/.venv/bin/pip install httpx`, "ask/package_system", "allow/run_project_code", "allow/run_project_code"],
		// a bin/ that is not a venv, and a venv whose probes are switched off, both stay asks
		["looksvenv/bin/pip install httpx", "ask/package_system", "allow/run_project_code", "ask/package_system"],
		// flags that say the write leaves the env, whatever env it came from
		["pip install --user httpx", "ask/package_system", "ask/package_system", "ask/package_system"],
		["pip install --break-system-packages httpx", "ask/package_system", "ask/package_system", "ask/package_system"],
		["pip install -t /opt/libs httpx", "ask/package_system", "ask/package_system", "ask/package_system"],
		["pip install -t ./vendor httpx", "ask/package_system", "allow/run_project_code", "ask/package_system"],
		// a requirements file or an editable install is the project's own setup either way
		["pip install -r requirements.txt", "allow/run_project_code", "allow/run_project_code", "allow/run_project_code"],
		["pip install -e .", "allow/run_project_code", "allow/run_project_code", "allow/run_project_code"],
		// not installs
		["pip uninstall httpx", "ask/package_system", "ask/package_system", "ask/package_system"],
		["pip list", "allow/read_only", "allow/read_only", "allow/read_only"],
	]

	it.each(rows)("%s", (cmd, noEnv, envSet, onDisk) => {
		expect(cell(cmd, NO_ENV), cmd).toBe(noEnv)
		expect(cell(cmd, VENV_ENV), cmd).toBe(envSet)
		expect(cell(cmd, ON_DISK), cmd).toBe(onDisk)
	})

	it("treats a conda env as a project env too", () => {
		expect(cell("pip install httpx", CONDA_ENV)).toBe("allow/run_project_code")
	})

	it("an empty VIRTUAL_ENV is not a virtualenv", () => {
		expect(cell("pip install httpx", { ...NO_ENV, env: { VIRTUAL_ENV: "", CONDA_PREFIX: "" } })).toBe("ask/package_system")
	})

	it("names the packages it is asking about", () => {
		const d = evaluateBash("pip install httpx rich", NO_ENV)
		expect(d.entities.map((e) => `${e.kind}:${e.value}`)).toEqual(["target:httpx", "target:rich"])
	})
})

/**
 * `source .venv/bin/activate` as a segment of its own.
 *
 * No state from one segment reaches the next, so an activate can only ever describe itself: it is project
 * code, and it says nothing about the `pip install` that follows it. What layer 0 does with it is measured
 * here rather than assumed — the walker refuses every `source` leg (§12 `evaluates-arguments-as-code`), so
 * the verdict the tables produce for the leg is visible only where the legacy rows survive: as its own
 * segment via the legacy engine, and as the `allow` row inside a compound that still has an `ask` leg.
 */
describe("an activate is its own segment", () => {
	it("sourcing an in-project activate is project code", () => {
		for (const cmd of ["source .venv/bin/activate", ". .venv/bin/activate"]) {
			const d = evaluateBashLegacy(cmd, ON_DISK)
			expect(d.segments.map((s) => [s.tier, s.category]), cmd).toEqual([["allow", "run_project_code"]])
			expect(d.segments[0]!.description, cmd).toContain(".venv/bin/activate")
		}
	})

	it("does not stretch to a script that is not in the project", () => {
		const d = evaluateBashLegacy("source /opt/other/scripts/env.sh", ON_DISK)
		expect(d.segments[0]!.tier).toBe("unknown")
		expect(d.segments[0]!.category).toBe("unknown_command")
	})

	it("refuses every source leg, so a compound built on one is the model's call", () => {
		const d = verdict("source .venv/bin/activate && .venv/bin/pip install httpx", ON_DISK)
		expect(d.tier).toBe("unknown")
		expect(d.category).toBe("unproven_structure")
		expect(d.description).toContain("evaluates-arguments-as-code")
	})

	it("an env var does not buy the compound back", () => {
		const d = verdict("source .venv/bin/activate && pip install httpx", VENV_ENV)
		expect(d.tier).toBe("unknown")
		expect(d.category).toBe("unproven_structure")
	})

	it("keeps the activate row as project code when another leg still asks", () => {
		const d = verdict("source .venv/bin/activate && pip install httpx", ON_DISK)
		expect(d.tier).toBe("ask")
		expect(d.segments.some((s) => s.tier === "allow" && s.category === "run_project_code" && s.description.includes(".venv/bin/activate")), d.description).toBe(true)
	})
})
