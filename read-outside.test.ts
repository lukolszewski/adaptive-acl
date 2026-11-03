/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * A read outside the project is an authority question, and one approval per OBJECT.
 *
 * The old rule was "reads are free except secrets". It was replaced: outside the project root, a read asks
 * until the user's stated permission covers it — through pi's own file tools, through a parsed bash read, and
 * through the effect model's answer (the last is pinned in `gate-effect-read.test.ts`). A non-file read is a
 * read too — the daemon, the cluster, the host, the journal — and the object is named so the approval is per
 * object rather than per command. The temp directories are outside for READS only; writes there are
 * untouched. And what the user already approved, in any of its directions, answers the read.
 *
 * These are layer-0 tests: none of them passes an endpoint, so a prompt here cannot be a model failure and
 * an allow cannot be a classifier guess. Where a row needs the effect model (the run case below) the fetch
 * stub carries a recorded answer.
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { applyEvent, createLedger, ledgerCovers, type Ledger } from "./auth-ledger.ts"
import { addGrant, createGrantStore } from "./session-grants.ts"
import { runGate } from "./gate.ts"
import { evaluateBash, type PolicyOptions } from "./risk-policy.ts"

const POLICY: PolicyOptions = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }

/** No endpoint on purpose: an ask must be answered by layer 0 + the ledger, and never by a model. */
async function gate(command: string, opts: { ledger?: Ledger; grants?: ReturnType<typeof createGrantStore> } = {}) {
	return runGate("bash", { command }, { policy: POLICY, ledger: opts.ledger, grants: opts.grants })
}

async function tool(name: string, input: Record<string, unknown>) {
	return runGate(name, input, { policy: POLICY })
}

/** One grant row, applied the way the ledger applies extraction output. */
function ledgerWith(rows: Array<{ category: string; value: string; kind?: "entity" | "scope"; type?: "grant" | "forbid" }>): Ledger {
	const ledger = createLedger()
	rows.forEach((row, i) =>
		applyEvent(ledger, {
			type: row.type ?? "grant",
			category: row.category,
			value: row.value,
			kind: row.kind ?? "entity",
			quote: `fixture grant ${i}`,
			messageId: `m${i}`,
			seq: i + 1,
		}),
	)
	return ledger
}

const values = (r: { entities: Array<{ value: string }> }): string[] => r.entities.map((e) => e.value)

afterEach(() => {
	vi.unstubAllGlobals()
})

describe("a read outside the project asks until the user's permission covers it", () => {
	const OUTSIDE = "cat /home/u/notes/todo.md"

	it("asks, as a read, and names the object plus its directory", async () => {
		const r = await gate(OUTSIDE)
		expect(r.outcome).toBe("prompt")
		expect(r.tier).toBe("ask")
		expect(r.category).toBe("read_only")
		expect(values(r)).toContain("~/notes/todo.md")
		expect(values(r)).toContain("/home/u/notes/")
		expect(r.reason).toContain("read outside the project")
		expect(r.modelCalls).toHaveLength(0)
	})

	it("is answered by a read grant on the directory", async () => {
		const r = await gate(OUTSIDE, { ledger: ledgerWith([{ category: "read_only", value: "/home/u/notes/", kind: "scope" }]) })
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("is answered by a WRITE grant on the file (you cannot edit what you may not open)", async () => {
		const r = await gate(OUTSIDE, { ledger: ledgerWith([{ category: "write_outside", value: "/home/u/notes/todo.md" }]) })
		expect(r.outcome).toBe("allow-granted")
	})

	it("is answered by a DELETE grant on the file (a delete grant also reads)", async () => {
		const r = await gate(OUTSIDE, { ledger: ledgerWith([{ category: "delete_recursive", value: "/home/u/notes/todo.md" }]) })
		expect(r.outcome).toBe("allow-granted")
	})

	it("is NOT answered by a grant on a different file in the same directory", async () => {
		const r = await gate(OUTSIDE, { ledger: ledgerWith([{ category: "read_only", value: "/home/u/notes/other.md" }]) })
		expect(r.outcome).toBe("prompt")
	})

	it("bows to a forbid on the object even when a grant covers it", async () => {
		const ledger = ledgerWith([
			{ category: "read_only", value: "/home/u/notes/", kind: "scope" },
			{ category: "read_only", value: "/home/u/notes/", kind: "scope", type: "forbid" },
		])
		const r = await gate(OUTSIDE, { ledger })
		expect(r.outcome).toBe("prompt")
		expect(ledgerCovers(ledger, "read_only", [{ kind: "target", value: "/home/u/notes/todo.md" }], POLICY.home).forbidden).toBe(true)
	})

	it("is answered by a session grant on the object — one approval per object, not per command", async () => {
		const grants = createGrantStore()
		addGrant(grants, "read_only", "~/notes/todo.md", "entity")
		const first = await gate(OUTSIDE, { grants })
		expect(first.outcome).toBe("allow-granted")
		expect(first.grantedBy).toBe("session-grant")
	})

	it("keeps secrets in their own category, and out of reach of a read grant on the folder", async () => {
		const key = await gate("cat ~/.ssh/id_ed25519")
		expect(key.outcome).toBe("prompt")
		expect(key.category).toBe("read_secret")
		const covered = await gate("cat ~/.ssh/id_ed25519", { ledger: ledgerWith([{ category: "read_only", value: "/home/u/.ssh/", kind: "scope" }]) })
		expect(covered.outcome).toBe("prompt")
		expect(covered.category).toBe("read_secret")
	})

	it("leaves the project subtree allowed — including the project's own .git", async () => {
		expect((await gate("cat ./README.md")).outcome).toBe("allow")
		expect((await gate("cat .git/config")).outcome).toBe("allow")
		expect((await gate("ls -la src")).outcome).toBe("allow")
	})

	it("reads the devices every pipe needs without asking", async () => {
		expect((await gate("cat /dev/null")).outcome).toBe("allow")
	})
})

describe("the temp directories are outside for reads, unchanged for writes", () => {
	it("asks for a read under /tmp", async () => {
		const r = await gate("cat /tmp/cpu_gpu.txt")
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(values(r)).toContain("/tmp/cpu_gpu.txt")
		expect(values(r)).toContain("/tmp/")
	})

	it("leaves a write under /tmp alone", async () => {
		expect((await gate("echo note > /tmp/note.txt")).outcome).toBe("allow")
	})

	it("is answered by a read grant on the temp directory", async () => {
		const r = await gate("cat /tmp/cpu_gpu.txt", { ledger: ledgerWith([{ category: "read_only", value: "/tmp/", kind: "scope" }]) })
		expect(r.outcome).toBe("allow-granted")
	})
})

describe("pi's own tools take the same rule", () => {
	it("reads outside the project ask", async () => {
		for (const name of ["read", "grep", "find", "ls", "glob"]) {
			const r = await tool(name, { path: "/home/u/notes.md" })
			expect(r.outcome, name).toBe("prompt")
			expect(r.category, name).toBe("read_only")
		}
	})

	it("reads inside the project stay free, and a call with no path is the project itself", async () => {
		expect((await tool("read", { path: "./src/app.ts" })).outcome).toBe("allow")
		expect((await tool("ls", {})).outcome).toBe("allow")
		expect((await tool("grep", { path: "./src", pattern: "x" })).outcome).toBe("allow")
	})

	it("a secret read through a tool keeps its own category", async () => {
		const r = await tool("read", { path: "/home/u/.ssh/id_ed25519" })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_secret")
	})

	it("fetching a URL is a read of the host it names (spelled as a tool)", async () => {
		const r = await tool("web_fetch", { url: "https://docs.example.com/guide#setup" })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(values(r)).toContain("docs.example.com")
	})

	it("answers the object, not the command: one approval covers the whole site", async () => {
		const ledger = ledgerWith([{ category: "read_only", value: "docs.example.com" }])
		const r = await runGate("web_fetch", { url: "https://docs.example.com/other/page" }, { policy: POLICY, ledger })
		expect(r.outcome).toBe("allow-granted")
	})
})

describe("every non-file read asks and names a stable object", () => {
	/**
	 * This table is split by what is being read. Families that answer `read_only` are reading neither a file
	 * nor a machine; the ones reading a MACHINE's own state — processes, disks, sockets, units, containers, a
	 * cluster — answer `read_system_state`, and their object is the machine or the cluster rather than the
	 * client's name or the unit's. Everything else keeps the answer it already had.
	 */
	const FAMILIES: Array<{ command: string; category: string; object: string; grant: string; grantCategory: string }> = [
		{ command: "docker ps", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "container_mutation" },
		{ command: "docker compose ps", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "container_mutation" },
		{ command: "kubectl get pods", category: "read_system_state", object: "kubectl", grant: "kubectl", grantCategory: "cluster_mutation" },
		{ command: "kubectl --context prod get pods", category: "read_system_state", object: "prod", grant: "prod", grantCategory: "cluster_mutation" },
		{ command: "helm list", category: "read_only", object: "helm", grant: "helm", grantCategory: "cluster_mutation" },
		{ command: "terraform plan", category: "read_only", object: "terraform", grant: "terraform", grantCategory: "cluster_mutation" },
		{ command: "systemctl status nginx", category: "read_system_state", object: "localhost/nginx", grant: "localhost", grantCategory: "system_config" },
		{ command: "journalctl -u nginx -n 20", category: "read_system_state", object: "localhost/nginx", grant: "localhost", grantCategory: "system_config" },
		{ command: "crontab -l", category: "read_only", object: "the user crontab", grant: "the user crontab", grantCategory: "read_only" },
		{ command: "sysctl -a", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "system_config" },
		{ command: "mount", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "system_config" },
		{ command: "uptime", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "read_only" },
		{ command: "df -h", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "read_only" },
		{ command: "ps aux", category: "read_system_state", object: "localhost", grant: "localhost", grantCategory: "read_only" },
		{ command: "curl -s https://api.example.com/health", category: "read_only", object: "api.example.com", grant: "api.example.com", grantCategory: "network_send" },
		{ command: "gh api repos/o/r", category: "read_only", object: "github.com", grant: "github.com", grantCategory: "network_send" },
		{ command: "aws s3 ls s3://bucket/", category: "read_only", object: "s3://bucket/", grant: "s3://bucket/", grantCategory: "read_only" },
		{ command: "nc -z db.internal 5432", category: "read_only", object: "db.internal", grant: "db.internal", grantCategory: "remote_exec" },
		{ command: "tmux ls", category: "read_only", object: "tmux sessions", grant: "tmux sessions", grantCategory: "read_only" },
		{ command: "ssh build-01 uptime", category: "read_system_state", object: "build-01", grant: "build-01", grantCategory: "remote_exec" },
	]

	for (const family of FAMILIES) {
		it(`${family.command} asks as a read of ${family.object}`, async () => {
			const r = await gate(family.command)
			expect(r.outcome).toBe("prompt")
			expect(r.tier).toBe("ask")
			expect(r.category).toBe(family.category)
			expect(values(r)).toContain(family.object)
			expect(r.modelCalls).toHaveLength(0)
		})

		it(`${family.command} is answered once the user has approved ${family.object}`, async () => {
			// Either the read itself was approved, or the user approved the SERVICE behind it for the object the
			// read names: both are one prompt, not one per command.
			const byRead = await gate(family.command, { ledger: ledgerWith([{ category: family.category, value: family.grant }]) })
			expect(byRead.outcome, `read grant ${family.category}:${family.grant}`).toBe("allow-granted")
			const byService = await gate(family.command, { ledger: ledgerWith([{ category: family.grantCategory, value: family.grant }]) })
			expect(byService.outcome, `service grant ${family.grantCategory}:${family.grant}`).toBe("allow-granted")
		})
	}

	it("a read of one host is not a read of another", async () => {
		const r = await gate("curl -s https://other.example.com/x", { ledger: ledgerWith([{ category: "network_send", value: "api.example.com" }]) })
		expect(r.outcome).toBe("prompt")
	})
})

describe("what stays free — a tool's own information and the shell's own state", () => {
	const FREE = [
		"node --version",
		"git --version",
		"docker --version",
		"python3 --version",
		"git --help",
		"which rg",
		"type cd",
		"command -v git",
		"pwd",
		"echo hello",
		"printf a",
		"cd /tmp",
		"true",
		"false",
		"git",
		"kubectl",
	]
	for (const command of FREE) {
		it(`${command} runs without a prompt`, async () => {
			const r = await gate(command)
			expect(r.outcome).toBe("allow")
		})
	}

	it("draws the line at a flag that is not a version request: df -h reads the filesystem", async () => {
		// `-h` means "human-readable" on df/du/ps/free, so it cannot be on the self-report list.
		expect((await gate("df -h")).outcome).toBe("prompt")
		expect((await gate("df --version")).outcome).toBe("allow")
	})

	it("draws the line at a file: echo with a redirect writes, echo with a file argument reads nothing", async () => {
		expect((await gate("echo hi > /home/u/outside.txt")).outcome).toBe("prompt")
		expect((await gate("echo $(cat /home/u/notes/todo.md)")).outcome).toBe("prompt")
	})
})

describe("running code outside the project is a run, not a write — and a run grant answers it", () => {
	/** Recorded from a model's answer for `python3 /opt/tools/clean.py`. */
	const RUN_ANSWER = { effect: "run_project_code", targets: ["/opt/tools/clean.py"], outside_project: true, confidence: "high" }
	const GRANT_NO = { authorized: "no", effects: [], allowed_targets: [], forbidden_targets: [], quote: "" }

	function stub(answer: unknown) {
		vi.stubGlobal("fetch", async (_url: string, init: Record<string, unknown>) => {
			const body = JSON.parse(String(init.body)) as { response_format?: { json_schema?: { name?: string } } }
			const payload = body.response_format?.json_schema?.name === "effect" ? answer : GRANT_NO
			const json = { choices: [{ message: { content: JSON.stringify(payload) } }] }
			return { ok: true, status: 200, json: async () => json } as unknown as Response
		})
	}

	it("asks as run_project_code on the model's own object, and not as a write", async () => {
		stub(RUN_ANSWER)
		const r = await runGate("bash", { command: "python3 /opt/tools/clean.py" }, { policy: POLICY, endpoint: { baseUrl: "http://mock", model: "mock" }, userMessages: ["clean the box up"] })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("run_project_code")
		expect(r.category).not.toBe("write_outside")
		expect(values(r)).toContain("/opt/tools/clean.py")
		expect(r.modelCalls.filter((c) => c.task === "effect")).toHaveLength(1)
	})

	it("is answered by a run grant on that target", async () => {
		stub(RUN_ANSWER)
		const r = await runGate("bash", { command: "python3 /opt/tools/clean.py" }, {
			policy: POLICY,
			endpoint: { baseUrl: "http://mock", model: "mock" },
			userMessages: ["clean the box up"],
			ledger: ledgerWith([{ category: "run_project_code", value: "/opt/tools/clean.py" }]),
		})
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("is not answered by a run grant on something else", async () => {
		stub(RUN_ANSWER)
		const r = await runGate("bash", { command: "python3 /opt/tools/clean.py" }, {
			policy: POLICY,
			endpoint: { baseUrl: "http://mock", model: "mock" },
			userMessages: ["clean the box up"],
			ledger: ledgerWith([{ category: "run_project_code", value: "/opt/tools/other.py" }]),
		})
		expect(r.outcome).toBe("prompt")
	})
})

describe("an `env` that runs no command is a read of the environment", () => {
	/**
	 * The hole this pins: `env` was peeled as a wrapper, the command inside it was the empty command, and the
	 * empty command is free — so `env | grep -i '^PI_'` printed every token in the session environment without
	 * asking. `env` with nothing left after its own options runs no program; what it prints IS the read, and it
	 * is the same read `printenv` already was.
	 */
	it("asks, as a read of the environment, in the recorded shape", async () => {
		// Only the CATEGORY moved: the environment is where a session keeps its tokens, so it is a secret read,
		// out of reach of a grant to read this machine's state. Tier, object and prompt are unchanged.
		const r = await gate("env | grep -i '^PI_'")
		expect(r.outcome).toBe("prompt")
		expect(r.tier).toBe("ask")
		expect(r.category).toBe("read_secret")
		expect(values(r)).toContain("environment variables")
		expect(r.modelCalls).toHaveLength(0)
	})

	it("asks for every spelling that runs no command", async () => {
		for (const command of ["env", "env FOO=1", "env -u PATH", "env -uPATH", "env --null", "env -i FOO=bar"]) {
			const r = await gate(command)
			expect(r.outcome, command).toBe("prompt")
			expect(values(r), command).toContain("environment variables")
		}
	})

	it("is answered by one approval of the environment, like any other object", async () => {
		const r = await gate("env", { ledger: ledgerWith([{ category: "read_secret", value: "environment variables" }]) })
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("is NOT answered by a grant to read this machine's state, nor by a plain file read grant", async () => {
		// The exclusion in that direction: a troubleshooting grant covers status reads, and the
		// environment is not a status read. Costs one prompt; buys no token out of the process.
		for (const category of ["read_system_state", "read_only"]) {
			const r = await gate("printenv", { ledger: ledgerWith([{ category, value: "environment variables" }]) })
			expect(r.outcome, category).toBe("prompt")
			expect(r.category).toBe("read_secret")
		}
	})

	it("stays a wrapper when a command follows, and then only that command is judged", async () => {
		// `env FOO=1 ls` prints nothing about the environment, so nothing about it is asked for.
		expect((await gate("env FOO=1 ls -la")).outcome).toBe("allow")
		const r = await gate("env FOO=1 cat /home/u/notes/todo.md")
		expect(r.outcome).toBe("prompt")
		expect(values(r)).toContain("~/notes/todo.md")
		expect(values(r)).not.toContain("environment variables")
	})

	it("keeps the privilege question when it is run under sudo", async () => {
		const r = await gate("sudo env FOO=1")
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("privilege")
	})

	it("does not hide the command behind an option it cannot read past", () => {
		// `-S` is not in the wrapper's vocabulary, so where the wrapped command begins is unknown. The answer
		// costs a model call: not an allow, and not a lock the user cannot get out of.
		const d = evaluateBash("env -S rm -rf /home/u/notes", POLICY)
		expect(d.tier).toBe("unknown")
		expect(d.segments[0]?.category).toBe("unknown_command")
	})
})

describe("a git command reads the repository at its own directory", () => {
	const OUTSIDE_REPO = "/home/u/work/other-repo"

	it("asks after `cd` leaves the project, and names that repository", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO}; git rev-list --count master`)
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(values(r)).toContain("~/work/other-repo")
		expect(r.reason).toContain("read outside the project")
		expect(r.modelCalls).toHaveLength(0)
	})

	it("is the same question written with -C, in either spelling", async () => {
		const spellings: Array<[string, string]> = [
			[`git -C ${OUTSIDE_REPO} status`, "~/work/other-repo"],
			[`git -C${OUTSIDE_REPO} status`, "~/work/other-repo"],
			[`git --git-dir=${OUTSIDE_REPO}/.git status`, "~/work/other-repo/.git"],
		]
		for (const [command, object] of spellings) {
			const r = await gate(command)
			expect(r.outcome, command).toBe("prompt")
			expect(values(r), command).toContain(object)
		}
	})

	it("is answered by a read grant on the repository, and one approval covers the repo's commands", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO} && git log -1`, { ledger: ledgerWith([{ category: "read_only", value: OUTSIDE_REPO }]) })
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
	})

	it("is not answered by a grant for some other repository", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO} && git log -1`, { ledger: ledgerWith([{ category: "read_only", value: "/home/u/work/second-repo" }]) })
		expect(r.outcome).toBe("prompt")
	})

	it("asks twice for a fetch outside the project, because it reads two objects", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO} && git fetch forgejo --quiet`)
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(values(r)).toContain("~/work/other-repo")
		expect(values(r)).toContain("forgejo")
	})

	it("still asks about the remote after the repository alone was approved (one object, one approval)", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO} && git fetch forgejo --quiet`, { ledger: ledgerWith([{ category: "read_only", value: OUTSIDE_REPO }]) })
		expect(r.outcome).toBe("prompt")
		expect(values(r)).toContain("forgejo")
		// The remote read is the object that is still missing, and the reason says so beside the row it covers.
		expect(r.reason).toContain("reads the remote forgejo")
	})

	it("names the host when the remote was written out as a URL", async () => {
		const r = await gate(`cd ${OUTSIDE_REPO} && git pull https://git.internal/r.git main`)
		expect(r.outcome).toBe("prompt")
		expect(values(r)).toContain("git.internal")
	})

	it("leaves the project's own repository alone, wherever the leg started", async () => {
		for (const command of ["git status", "cd /home/u/proj/sub && git log --oneline -3", "git fetch origin", "git -C /home/u/proj status"]) {
			const r = await gate(command)
			expect(r.outcome, command).toBe("allow")
			expect(r.modelCalls, command).toHaveLength(0)
		}
	})

	it("keeps the write verdicts where they were, inside and outside the project", async () => {
		const pushOutside = await gate(`cd ${OUTSIDE_REPO} && git push origin main`)
		expect(pushOutside.category).toBe("vcs_remote")
		const commitOutside = await gate(`cd ${OUTSIDE_REPO} && git add -A`)
		expect(commitOutside.outcome).toBe("allow")
		expect(commitOutside.category).toContain("vcs_local")
		const discard = await gate(`cd ${OUTSIDE_REPO} && git reset --hard`)
		expect(discard.outcome).toBe("prompt")
		expect(discard.category).toBe("vcs_discard")
	})
})
