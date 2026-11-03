/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * A status read is granted by TROUBLESHOOTING INTENT, and what one approval covers is a MACHINE or a
 * CLUSTER — not one command at a time.
 *
 * Two halves, and they are deliberately kept apart:
 *  · layer 0, which decides the category and names the object (no model, no endpoint: a prompt here cannot be
 *    a classifier failure and an allow cannot be a classifier guess);
 *  · the authorisation half, where the model's structured fields (`category`, `targetClass`, `targets`) are
 *    mapped in code to an object — the rows below are recorded model answers, because the interesting
 *    question is what a model actually returns for "go find out why", not what an idealised extraction would.
 *
 * The lines drawn, and every one of them is pinned here:
 *   - a status read of THIS machine is answered by a grant for this machine, once, whatever the command;
 *   - a grant for this machine is not a grant for `buildhost`, and a grant for `buildhost` is not one for here;
 *   - the environment is a SECRET read and a status grant never reaches it;
 *   - a file outside the project still asks on its own: a status grant buys no file read;
 *   - a tool that can also RECONFIGURE the machine keeps its own category, so "look at the networking" does
 *     not buy `ip link set eth0 down`.
 */
import { describe, expect, it } from "vitest"
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { applyEvent, createLedger, eventsFromExtraction, singleClusterContext, type Ledger } from "./auth-ledger.ts"
import { addGrant, createGrantStore } from "./session-grants.ts"
import { runGate } from "./gate.ts"
import { evaluateBash, type PolicyOptions } from "./risk-policy.ts"

const POLICY: PolicyOptions = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u", fs: false }

/** Layer 0 + the ledger, never a model: `endpoint` is deliberately never passed. */
async function gate(command: string, opts: { ledger?: Ledger; grants?: ReturnType<typeof createGrantStore> } = {}) {
	return runGate("bash", { command }, { policy: POLICY, ledger: opts.ledger, grants: opts.grants })
}

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

const LOCAL = { category: "read_system_state", value: "localhost" }
const values = (r: { entities: Array<{ value: string }> }): string[] => r.entities.map((e) => e.value)

const STATUS_FAMILIES: Array<[string, string]> = [
	["ps aux", "processes"],
	["pgrep -f node", "processes"],
	["lsof -i :8080", "processes / open files"],
	["df -h", "disk"],
	["free -m", "memory"],
	["lsblk", "block devices"],
	["uptime", "load"],
	["ss -tlnp", "network configuration"],
	["ip addr", "network configuration"],
	["nvidia-smi", "hardware"],
	["lscpu", "hardware"],
	["systemctl status nginx", "services"],
	["journalctl -u nginx -n 50", "services / the journal"],
	["docker ps", "containers"],
	["docker logs web --tail 50", "containers"],
	["docker stats --no-stream", "containers"],
	["kubectl get pods -A", "a cluster"],
	["kubectl --context prod describe pod web", "a cluster"],
]

describe("layer 0: a status read names its machine or cluster", () => {
	it.each(STATUS_FAMILIES)("%s asks as read_system_state (%s)", async (command) => {
		const r = await gate(command)
		expect(r.outcome, command).toBe("prompt")
		expect(r.category, command).toBe("read_system_state")
		expect(r.modelCalls, command).toHaveLength(0)
		expect(values(r).length, command).toBeGreaterThan(0)
	})

	it("one approval for this machine answers every local family, and is asked once", async () => {
		const ledger = ledgerWith([LOCAL])
		const local = ["ps aux", "df -h", "free -m", "ss -tlnp", "nvidia-smi", "systemctl status nginx", "journalctl -u nginx", "docker ps"]
		for (const command of local) {
			const r = await gate(command, { ledger })
			expect(r.outcome, command).toBe("allow-granted")
			expect(r.grantedBy, command).toBe("ledger")
		}
	})

	it("a session grant recorded from the prompt answers the same family (one prompt per machine)", async () => {
		const grants = createGrantStore()
		const first = await gate("df -h", { grants })
		expect(first.outcome).toBe("prompt")
		addGrant(grants, "read_system_state", "localhost", "entity")
		for (const command of ["ps aux", "free -m", "systemctl status nginx", "docker ps"]) {
			expect((await gate(command, { grants })).outcome, command).toBe("allow-granted")
		}
	})

	it("a grant for this machine does not cover a read of another machine", async () => {
		const ledger = ledgerWith([LOCAL])
		for (const command of ["ssh buildhost ps", "ssh buildhost df -h", "kubectl --context prod get pods"]) {
			const r = await gate(command, { ledger })
			expect(r.outcome, command).toBe("prompt")
			expect(r.category, command).toBe("read_system_state")
		}
	})

	it("…and the reverse: a grant for that machine or cluster does not cover this one", async () => {
		const ledger = ledgerWith([
			{ category: "read_system_state", value: "buildhost" },
			{ category: "read_system_state", value: "prod" },
		])
		for (const command of ["ps aux", "df -h", "kubectl --context staging get pods", "ssh otherbox df -h"]) {
			const r = await gate(command, { ledger })
			expect(r.outcome, command).toBe("prompt")
		}
		// …while the host and the context each answer their own read.
		expect((await gate("ssh buildhost ps", { ledger })).outcome).toBe("allow-granted")
		expect((await gate("kubectl --context prod get pods", { ledger })).outcome).toBe("allow-granted")
	})

	it("the environment is a secret read, out of reach of a status grant", async () => {
		for (const command of ["env", "printenv", "env | grep -i '^PI_'", "docker inspect web"]) {
			const r = await gate(command)
			expect(r.category, command).toBe("read_secret")
			expect(r.outcome, command).toBe("prompt")
		}
		// A grant to read this machine's state does not reach either of them…
		const statusOnly = ledgerWith([LOCAL])
		expect((await gate("printenv", { ledger: statusOnly })).outcome).toBe("prompt")
		expect((await gate("docker inspect web", { ledger: statusOnly })).outcome).toBe("prompt")
		// …while each secret-shaped read is answered by its OWN approval. `docker inspect` reports a container's
		// configuration, which lives on the machine the daemon runs on, so its object is that machine — the same
		// object as every other read of this box, and the point of the exclusion is that it takes a SECRET grant
		// to reach it, not the troubleshooting one.
		const approved = ledgerWith([{ category: "read_secret", value: "localhost" }])
		expect((await gate("docker inspect web", { ledger: approved })).outcome).toBe("allow-granted")
		expect((await gate("docker inspect web", { ledger: statusOnly })).outcome).toBe("prompt")
		expect(values(await gate("docker inspect web")).includes("localhost")).toBe(true)
		// The environment of THIS process is its own object, and approving one does not answer the other.
		const envOnly = ledgerWith([{ category: "read_secret", value: "environment variables" }])
		expect((await gate("printenv", { ledger: envOnly })).outcome).toBe("allow-granted")
		expect((await gate("docker inspect web", { ledger: envOnly })).outcome).toBe("prompt")
	})

	it("a status grant buys no read of a file outside the project", async () => {
		const ledger = ledgerWith([LOCAL])
		const r = await gate("cat /home/u/notes/todo.md", { ledger })
		expect(r.outcome).toBe("prompt")
		expect(r.category).toBe("read_only")
		expect(r.reason).toContain("read outside the project")
	})

	it("a tool that can also reconfigure the machine keeps its own category", async () => {
		const ledger = ledgerWith([LOCAL])
		// The read form is answered by the machine grant…
		expect((await gate("ip addr", { ledger })).outcome).toBe("allow-granted")
		// …and the change form is a different effect, so the same grant does not reach it.
		for (const command of ["ip link set eth0 down", "route add -net 10.0.0.0/8 gw 192.168.1.1", "arp -d 10.0.0.1"]) {
			const r = await gate(command, { ledger })
			expect(r.category, command).toBe("system_config")
			expect(r.outcome, command).toBe("prompt")
		}
	})

	it("a forbid on the object wins over the grant", async () => {
		const ledger = ledgerWith([LOCAL, { ...LOCAL, type: "forbid" }])
		const r = await gate("ps aux", { ledger })
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
	})

	it("a status grant reaches no other category, and no other category's grant reaches it", async () => {
		// `read_system_state` is its own kind group: a machine read and a file read, a write, a delete, a push
		// and a secret read stay separate permissions in both directions.
		const statusOnly = ledgerWith([LOCAL])
		for (const command of ["cat /home/u/notes/todo.md", "rm /home/u/notes/todo.md", "systemctl restart nginx", "docker rm web"]) {
			expect((await gate(command, { ledger: statusOnly })).outcome, command).toBe("prompt")
		}
		for (const category of ["write_outside", "delete_recursive", "network_send", "git_remote", "read_secret"]) {
			const other = ledgerWith([{ category, value: "localhost" }])
			expect((await gate("ps aux", { ledger: other })).outcome, category).toBe("prompt")
		}
	})

	it("the service directions that hold: a service grant naming the machine answers its status read", async () => {
		// Two directions are unchanged, and they are the ones that make one approval per object work:
		// ("a service/host/cluster grant keeps covering reading the object it names"):
		//  · a grant to control the services / containers ON this machine is a grant about this machine;
		//  · a plain read grant that names exactly this object says "read this".
		// They go ONE way: a status grant never answers a mutation (pinned above) and never answers a file read.
		for (const category of ["process_control", "container_mutation", "system_config", "read_only"]) {
			const ledger = ledgerWith([{ category, value: "localhost" }])
			expect((await gate("ps aux", { ledger })).outcome, category).toBe("allow-granted")
			expect((await gate("cat /home/u/notes/todo.md", { ledger })).outcome, category).toBe("prompt")
			expect((await gate("systemctl restart nginx", { ledger })).outcome, category).toBe("prompt")
		}
	})

	it("a cluster grant still covers reading that cluster", async () => {
		const ledger = ledgerWith([{ category: "cluster_mutation", value: "prod" }])
		expect((await gate("kubectl --context prod get pods", { ledger })).outcome).toBe("allow-granted")
		expect((await gate("kubectl --context staging get pods", { ledger })).outcome).toBe("prompt")
	})
})

describe("the command list: exactly what moved, pinned per command", () => {
	/**
	 * The blast radius, one line per command, so "which commands answer `read_system_state` now" is a
	 * fact in the repo rather than a reading of a 2 000-line dispatch table. Every row was written from the
	 * rule and then checked against the code; where they disagreed the code changed or the row did.
	 */
	const LIST: Array<[string, "ask" | "allow", string, string]> = [
		// processes, capacity, hardware, identity, network status — all THIS machine
		["ps aux", "ask", "read_system_state", "localhost"],
		["top -bn1", "ask", "read_system_state", "localhost"],
		["lsof -i :80", "ask", "read_system_state", "localhost"],
		["df -h", "ask", "read_system_state", "localhost"],
		["nvidia-smi", "ask", "read_system_state", "localhost"],
		["id", "ask", "read_system_state", "localhost"],
		["ss -tlnp", "ask", "read_system_state", "localhost"],
		// network tools in their READ form; the same binaries in a CHANGE form are a different effect
		["ip route", "ask", "read_system_state", "localhost"],
		["route -n", "ask", "read_system_state", "localhost"],
		["arp -an", "ask", "read_system_state", "localhost"],
		["ifconfig -a", "ask", "read_system_state", "localhost"],
		["ip route add default via 1.2.3.4", "ask", "system_config", ""],
		["ip link set eth0 down", "ask", "system_config", ""],
		["route add -net 10.0.0.0/8 gw 1.2.3.4", "ask", "system_config", ""],
		["arp -d 1.2.3.4", "ask", "system_config", ""],
		["ifconfig eth0 10.0.0.1", "ask", "system_config", ""],
		// kernel settings and the mount table: reading is a status read, setting is a change
		["sysctl -a", "ask", "read_system_state", "localhost"],
		["mount", "ask", "read_system_state", "localhost"],
		["sysctl net.ipv4.ip_forward=1", "ask", "system_config", ""],
		["mount /dev/sdb1 /mnt", "ask", "system_config", ""],
		// services, containers, a cluster: the object is wherever the state lives
		["systemctl list-units", "ask", "read_system_state", "localhost"],
		["journalctl -f", "ask", "read_system_state", "localhost"],
		["docker ps", "ask", "read_system_state", "localhost"],
		["docker -H tcp://box:2375 ps", "ask", "read_system_state", "box"],
		["kubectl get pods", "ask", "read_system_state", "kubectl"],
		["systemctl restart nginx", "ask", "process_control", "nginx"],
		// a status read on ANOTHER machine is that machine's, and secrets never travel with it
		["ssh build-01 uptime", "ask", "read_system_state", "build-01"],
		["docker inspect web", "ask", "read_secret", "localhost"],
		["env", "ask", "read_secret", "environment variables"],
		// untouched: a client that reports something other than a machine's own state, and reachability
		["helm list", "ask", "read_only", "helm"],
		["ping -c1 host", "ask", "read_only", "a host's reachability"],
		// unchanged from before: a file read outside the project asks, a bare tool self-report is free
		["cat /home/u/notes/todo.md", "ask", "read_only", "~/notes/todo.md"],
		["node --version", "allow", "read_only", ""],
	]

	it.each(LIST)("%s → %s %s", async (command, tier, category, object) => {
		const r = await gate(command)
		expect(r.tier, command).toBe(tier)
		expect(r.category, command).toBe(category)
		// The object is asserted only where there is an opinion about it. A CHANGE keeps the objects it had before
		// (its own operands), because only the object of a STATUS read moved, not of a mutation.
		if (object) expect(values(r), command).toContain(object)
		else if (category !== "system_config" && category !== "process_control") expect(values(r), command).toHaveLength(0)
	})

	it("a status read never becomes free, and no status read is a NEVER", async () => {
		// This moves a category, not a tier: every one of these was a prompt before and is a prompt now.
		for (const [command, tier] of LIST) {
			const r = await gate(command)
			if (r.category === "read_system_state") expect(r.tier, command).toBe("ask")
			expect(r.tier, command).not.toBe("never")
			expect(tier).toBeTruthy()
		}
	})

	it("a compound status read is answered per segment, not by the loudest one", async () => {
		// `ps && rm -rf /x` is a status read AND a destruction: the compound stays a prompt because the delete
		// segment is not covered by anything, while the status segment is answered by the machine grant.
		const ledger = ledgerWith([LOCAL])
		const r = await gate("ps aux && df -h", { ledger })
		expect(r.outcome).toBe("allow-granted")
		const mixed = await gate("df -h && rm -rf /tmp/scratch", { ledger })
		expect(mixed.outcome).toBe("prompt")
	})
})

describe("extraction: recorded model answers, mapped by code", () => {
	/** The raw payloads below, unedited. */
	const LOCAL_ANSWER = {
		grants: [{
			action: "read machine status", category: "read_system_state", kind: "entity", scope: "named",
			targetClass: "local_machine", includesSecrets: false, targets: [], quote: "look at whatever you need on the machine",
		}],
		revocations: [],
	}
	const LOCAL_MESSAGE = "nginx keeps dying on this box, go figure out why - look at whatever you need on the machine"

	const HOST_ANSWER = {
		grants: [{
			action: "read machine status", category: "read_system_state", kind: "entity", scope: "named",
			targetClass: "local_machine", includesSecrets: false, targets: ["buildhost"], quote: "you may read system state on buildhost",
		}],
		revocations: [],
	}
	const HOST_MESSAGE = "nginx keeps dying on buildhost, go figure out why - you may read system state on buildhost"

	const CLUSTER_ANSWER = {
		grants: [{
			action: "read cluster status", category: "read_system_state", kind: "entity", scope: "named",
			targetClass: "current_cluster", includesSecrets: false, targets: [], quote: "check what the pods are doing and you can look at the cluster",
		}],
		revocations: [],
	}
	const CLUSTER_MESSAGE = "my cluster is unhealthy, check what the pods are doing and you can look at the cluster"

	it("a troubleshooting sentence with no machine named becomes a grant on THIS machine", () => {
		const events = eventsFromExtraction(LOCAL_ANSWER, "m1", 1, LOCAL_MESSAGE)
		expect(events).toHaveLength(1)
		expect(events[0]).toMatchObject({ type: "grant", category: "read_system_state", value: "localhost", kind: "entity" })
	})

	it("…and it answers the local families through the ledger", async () => {
		const ledger = createLedger()
		applyEvent(ledger, eventsFromExtraction(LOCAL_ANSWER, "m1", 1, LOCAL_MESSAGE)[0]!)
		expect((await gate("df -h", { ledger })).outcome).toBe("allow-granted")
		expect((await gate("ssh buildhost df -h", { ledger })).outcome).toBe("prompt")
	})

	it("a row that names a host grants THAT host, not this machine", () => {
		// The recorded answer carries BOTH the host and `local_machine`. Code may not widen a row that names
		// something, and granting this machine from a sentence about `buildhost` would be an allow
		// nobody gave — so the named target wins and the class is dropped.
		const events = eventsFromExtraction(HOST_ANSWER, "m1", 1, HOST_MESSAGE)
		expect(events.map((e) => e.value)).toEqual(["buildhost"])
	})

	it("…and it answers `ssh buildhost …`, never a local read", async () => {
		const ledger = createLedger()
		for (const ev of eventsFromExtraction(HOST_ANSWER, "m1", 1, HOST_MESSAGE)) applyEvent(ledger, ev)
		expect((await gate("ssh buildhost ps", { ledger })).outcome).toBe("allow-granted")
		expect((await gate("ps aux", { ledger })).outcome).toBe("prompt")
		expect((await gate("ssh otherbox ps", { ledger })).outcome).toBe("prompt")
	})

	/** A kubeconfig fixture in a temp dir, with invented context names, and nothing else on disk.
	 *  Cluster discovery reads the process environment, because that is where a user's cluster pointer lives
	 *  (`KUBECONFIG`, else `$HOME/.kube/config`) — so a test that exercises it states that exception inline and
	 *  puts the previous values back, rather than leaving the rest of the file pointed at a fixture. */
	function kubeFixture(yaml: string): { env: Record<string, string>; restore: () => void } {
		const dir = mkdtempSync(join(tmpdir(), "kube-"))
		const file = join(dir, ".kube", "config")
		mkdirSync(join(dir, ".kube"), { recursive: true })
		writeFileSync(file, yaml)
		const had = { kubeconfig: process.env.KUBECONFIG, home: process.env.HOME }
		process.env.KUBECONFIG = file
		process.env.HOME = dir
		return { env: { KUBECONFIG: file, HOME: dir }, restore: () => {
			if (had.kubeconfig === undefined) delete process.env.KUBECONFIG
			else process.env.KUBECONFIG = had.kubeconfig
			if (had.home === undefined) delete process.env.HOME
			else process.env.HOME = had.home
			rmSync(dir, { recursive: true, force: true })
		} }
	}
	const ONE_CONTEXT = `apiVersion: v1\nkind: Config\ncontexts:\n- name: glint-alpha\n  context:\n    cluster: glint\n    user: glint-user\ncurrent-context: glint-alpha\nclusters:\n- name: glint-alpha\n`
	const TWO_CONTEXTS = `apiVersion: v1\nkind: Config\ncontexts:\n- name: glint-alpha\n  context:\n    cluster: glint\n    user: glint-user\n- name: glint-beta\n  context:\n    cluster: glint\n    user: glint-user\ncurrent-context: glint-alpha\n`

	it("`current_cluster` maps to the current context when the kubeconfig has exactly one", () => {
		const fx = kubeFixture(ONE_CONTEXT)
		try {
			expect(singleClusterContext(fx.env)).toBe("glint-alpha")
			const events = eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE)
			expect(events.map((e) => e.value)).toEqual(["glint-alpha"])
		} finally {
			fx.restore()
		}
	})

	it("an ambiguous \"my cluster\" registers NOTHING and costs its prompt", () => {
		const fx = kubeFixture(TWO_CONTEXTS)
		try {
			expect(singleClusterContext(fx.env)).toBeUndefined()
			expect(eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE)).toEqual([])
		} finally {
			fx.restore()
		}
	})

	/** What `kubectl config view` actually writes: the name on its OWN line, at the item's field column, with the
	 *  clusters/users lists below it — both of which also hold `- name:` items. Invented names, stand-in token. */
	const KUBECTL_ONE = [
		"apiVersion: v1",
		"kind: Config",
		"preferences: {}",
		"contexts:",
		"- context:",
		"    cluster: glint",
		"    user: glint-user",
		"  name: prod",
		"current-context: prod",
		"clusters:",
		"- cluster:",
		"    server: https://glint.invalid",
		"  name: glint",
		"users:",
		"- name: glint-user",
		"  user:",
		"    token: SUPER-SECRET-TOKEN",
	].join("\n")
	const KUBECTL_TWO = [
		"contexts:",
		"- context:",
		"    cluster: glint",
		"    user: glint-user",
		"  name: prod",
		"- context:",
		"    cluster: glint",
		"    user: reader",
		"  name: staging",
		"current-context: staging",
		"users:",
		"- name: glint-user",
		"  user:",
		"    token: SUPER-SECRET-TOKEN",
	].join("\n")

	it("the kubeconfig `kubectl` itself writes maps too — that is the file every real machine has", () => {
		// The bug this pins: kubectl writes `- context:` and puts `name:` on its own line, so a reader that only
		// understands `- name: prod` finds no context, `entries === 1` never holds, `current_cluster` never maps,
		// and "my cluster" costs a prompt on every machine in the world.
		const fx = kubeFixture(KUBECTL_ONE)
		try {
			expect(singleClusterContext(fx.env)).toBe("prod")
			const events = eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE)
			expect(events.map((e) => e.value)).toEqual(["prod"])
		} finally {
			fx.restore()
		}
	})

	it("the same layout with two contexts registers NOTHING, as the narrow reading requires", () => {
		const fx = kubeFixture(KUBECTL_TWO)
		try {
			expect(singleClusterContext(fx.env)).toBeUndefined()
			expect(eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE)).toEqual([])
		} finally {
			fx.restore()
		}
	})

	it("a `users:` list with `- name:` items is not a list of contexts", () => {
		// The count of ENTRIES is what decides, and the other two lists in a kubeconfig hold `- name:` items too:
		// counting those would call a one-context file ambiguous (so it never maps), or read a USER's name as a
		// cluster (so the ledger binds authority to an object that does not exist). KUBECTL_ONE carries four
		// `- name:` items in total, so this assertion is the difference between counting entries and counting lines.
		const fx = kubeFixture(KUBECTL_ONE)
		try {
			expect(singleClusterContext(fx.env)).toBe("prod")
			const rows = JSON.stringify(eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE))
			expect(rows).toContain("prod")
			expect(rows).not.toContain("glint-user")
		} finally {
			fx.restore()
		}
	})

	it("with no kubeconfig at all the class registers nothing either", () => {
		const fx = kubeFixture("apiVersion: v1\nkind: Config\ncontexts: []\n")
		try {
			expect(singleClusterContext(fx.env)).toBeUndefined()
			expect(eventsFromExtraction(CLUSTER_ANSWER, "m1", 1, CLUSTER_MESSAGE)).toEqual([])
		} finally {
			fx.restore()
		}
	})

	it("a kubeconfig is read for its context names only — nothing else reaches the answer", () => {
		const fx = kubeFixture(`${ONE_CONTEXT}users:\n- name: glint-user\n  user:\n    token: SUPER-SECRET-TOKEN\n`)
		try {
			const value = singleClusterContext()
			expect(value).toBe("glint-alpha")
			expect(JSON.stringify(value)).not.toContain("SUPER-SECRET-TOKEN")
		} finally {
			fx.restore()
		}
	})

	it("a machine class on a category that is not a machine read registers nothing", () => {
		// Garbage answers: wrong category, class kept from another row. The row is dropped —
		// the work costs its ordinary prompt, and no lock and no allow can come out of it.
		const fx = kubeFixture(ONE_CONTEXT)
		try {
			const swap = (category: string) => ({ grants: [{ ...CLUSTER_ANSWER.grants[0]!, category }], revocations: [] })
			for (const category of ["write_outside", "delete_recursive", "process_control", "read_secret", "other"]) {
				expect(eventsFromExtraction(swap(category), "m1", 1, "you may look at the cluster"), category).toEqual([])
			}
			const localSwap = { grants: [{ ...LOCAL_ANSWER.grants[0]!, category: "delete_recursive" }], revocations: [] }
			expect(eventsFromExtraction(localSwap, "m1", 1, LOCAL_MESSAGE)).toEqual([])
		} finally {
			fx.restore()
		}
	})

	it("a garbage targetClass is the narrow answer, never a machine-wide allow", () => {
		const junk = { grants: [{ ...LOCAL_ANSWER.grants[0]!, targetClass: "everywhere" }], revocations: [] }
		const events = eventsFromExtraction(junk, "m1", 1, LOCAL_MESSAGE)
		// The parser turned the unknown enum value into "none", so the row takes the target path — and it has
		// no targets, so it registers nothing. One prompt; nothing armed.
		expect(events).toEqual([])
	})

	it("a quote that is not in the message registers nothing, class or not", () => {
		const lie = { grants: [{ ...LOCAL_ANSWER.grants[0]!, quote: "you may read every machine in the datacentre" }], revocations: [] }
		expect(eventsFromExtraction(lie, "m1", 1, LOCAL_MESSAGE)).toEqual([])
	})
})
