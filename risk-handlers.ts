/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Per-verb deterministic classification for the auto-mode risk policy
 * (docs/CLASSIFIER-SPEC.md §2). One handler per command family; everything
 * unhandled falls out as tier "unknown" and is escalated to the model.
 *
 * Pure logic — filesystem probes go through the injected helpers so tests
 * can disable them.
 */

import path from "node:path"
import { existsSync } from "node:fs"
import { currentClusterObject, LOCAL_MACHINE_OBJECT, type PathClass, type PathContext } from "./risk-paths.ts"
import type { SimpleCommand } from "./shell-lexer.ts"
import { grammarFor, isObjectStoreUri } from "./target-grammar.ts"
import { NO_OBJECT_TARGET } from "./grant-verify.ts"
import {
	seg,
	target,
	scope,
	pathTouched,
	readPackageScript,
	hasLocalBin,
	type Entity,
	type PolicyOptions,
	type PolicyDecision,
	type SegmentDecision,
} from "./risk-policy.ts"

export type HandlerContext = {
	ctx: PathContext
	opts: PolicyOptions
	vars: Record<string, string>
	cmd: SimpleCommand
	/** argv of the command piping INTO this one (null if none). */
	pipedFrom: string[] | null
	/** argv of the command this one pipes INTO (null if none). */
	pipesTo: string[] | null
	evaluateBash: (s: string, o?: Partial<PolicyOptions>) => PolicyDecision
	decideWrite: (pc: PathClass, verb: string) => SegmentDecision
	/** The path-space answer for READING this path (risk-policy.ts `decideRead`). */
	decideRead: (pc: PathClass, verb: string) => SegmentDecision
	classify: (p: string) => PathClass
	display: (pc: PathClass) => string
}

// ---------------------------------------------------------------- helpers

/** Non-flag arguments. Handles `--` terminator. */
function positionals(argv: string[]): string[] {
	const out: string[] = []
	let noMoreFlags = false
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!
		if (!noMoreFlags && a === "--") { noMoreFlags = true; continue }
		if (!noMoreFlags && a.startsWith("-") && a !== "-") continue
		out.push(a)
	}
	return out
}

function hasFlag(argv: string[], ...flags: string[]): boolean {
	return argv.some((a) => {
		if (flags.includes(a)) return true
		// combined short flags: -rf, -fr, -Rf …
		if (/^-[A-Za-z]+$/.test(a)) {
			for (const f of flags) {
				if (/^-[A-Za-z]$/.test(f) && a.includes(f[1]!)) return true
			}
		}
		// --flag=value
		for (const f of flags) {
			if (f.startsWith("--") && a.startsWith(f + "=")) return true
		}
		return false
	})
}

function flagValue(argv: string[], ...flags: string[]): string | undefined {
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!
		for (const f of flags) {
			if (a === f) return argv[i + 1]
			if (a.startsWith(f + "=")) return a.slice(f.length + 1)
		}
	}
	return undefined
}

const rawOf = (c: SimpleCommand) => c.raw.trim()

// ---------------------------------------------------------------- command sets

/**
 * Binaries whose operands are FILES whose bytes (or metadata) they read.
 *
 * Each operand decides the verdict: inside the project free, outside it asks, secret-bearing it
 * asks as `read_secret`. With no operand the command filters its stdin and reads nothing new. This table is
 * the old `READONLY_BINS` minus the entries that were never file readers — see {@link ARG_DATA_BINS} and
 * {@link HOST_READ_OBJECTS} — so it is *not* a looser list than the one it replaces: an entry that moved out
 * moved to a table that still answers for it.
 */
const FILE_READERS = new Set([
	"ls", "dir", "vdir", "eza", "exa", "lsd", "tree", "cat", "head", "tail", "less", "more", "bat", "nl", "tac",
	"wc", "stat", "file", "du", "strings", "xxd", "hexdump", "od", "gguf-dump",
	"grep", "egrep", "fgrep", "rg", "ag", "ack", "fd", "fdfind", "zgrep", "zcat", "zless", "xzcat", "bzcat", "gunzip",
	"sort", "uniq", "cut", "column", "paste", "join", "comm", "diff", "cmp", "col", "fold", "fmt", "rev", "shuf",
	"md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum",
	"look", "man", "info", "jq", "yq",
])

/**
 * Binaries that never open the thing their argument names: the operand is data — a word, a number, a path
 * *string*. `echo`, `printf`, `basename`, `realpath`, `date`, `test` print or compute; the free list covers
 * them ("the shell's own state"), and `which`/`type`/`command -v` are named on it explicitly.
 *
 * They still pay the secret check the old table applied, so `echo ~/.ssh/id_rsa` keeps asking: a zero-loosening
 * line is measured against that table and an argument that names a credential file is
 * worth one prompt even when nothing is read.
 */
const ARG_DATA_BINS = new Set([
	"date", "cal", "expr", "seq", "bc", "true", "false", "yes", "tty", "tr",
	"basename", "dirname", "realpath", "readlink", "which", "whereis", "type", "help", "apropos", "whatis",
	"infocmp", "tput", "stty", "locale", "printf", "echo", "sleep", "wait", "sync", "test", "[", "[[", "pwd", "dirs", "fc",
	"timeout", "watch", "time", "times",
])

/**
 * Search/JSON tools whose FIRST operand is the pattern or filter, not a path (`grep RE src`, `jq '.a' f`,
 * `fd PATTERN .`). Skipping it is CLI grammar, not English: with `-e`/`-f` the pattern is in the flag, so
 * then nothing is skipped. Without this, `grep -r /etc/passwd src` would be reported as reading `/etc/passwd`
 * when it only searches for that string, and `rg -F '$(' src` would be a path.
 */
const PATTERN_FIRST_BINS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "fd", "fdfind", "zgrep", "look", "jq", "yq"])
const PATTERN_FLAGS = ["-e", "--regexp", "-f", "--file", "--from-file", "--slurpfile"]

/**
 * The reads that are not reads of a FILE and are not machine status either.
 *
 * After the two larger families are taken out, this table holds what is left: a query aimed at SOMEBODY
 * ELSE'S service (DNS, reachability, a path to a host) and a read of a system database rather than of this
 * machine's own state. The value is the object the read sees, which is what a grant has to name. `ps`, `df`,
 * `uptime`, `ip`, `ss`, `lscpu` and the rest of the status families are no longer here — they live in
 * {@link MACHINE_STATUS_BINS} and are named by the MACHINE they report on, which is the object a troubleshooting
 * grant is given.
 *
 * A read is free only under the two rules stated here: a tool's own information (`--version`, `--help`, `man`,
 * `which`/`type`/`whereis`) and the shell's own state (builtins, `pwd`, `cd`, `echo`/`printf`, `true`/`false`).
 * Reading the ENVIRONMENT is neither free nor a status read: `env`/`printenv` answer `read_secret`.
 */
const HOST_READ_OBJECTS: Record<string, string> = {
	getent: "the system account databases", ldd: "shared library resolution",
	dig: "DNS records", nslookup: "DNS records", host: "DNS records", whois: "registration data",
	ping: "a host's reachability", ping6: "a host's reachability", traceroute: "the network path", mtr: "the network path",
}

/**
 * The status families whose object is a MACHINE or a CLUSTER.
 *
 * These are the reads a person means when they say "find out why X is broken": processes, disks and memory,
 * CPU and hardware, the network configuration, what the init system and the container runtime report. They get
 * a category of their own — `read_system_state` — granted by TROUBLESHOOTING INTENT rather than by a
 * sentence naming each command, because nobody says "you may run df" when they say "go find out why the box is
 * slow". Every entry names in `what` the thing it reports on; the OBJECT is the machine, never this table.
 *
 * What is NOT here is a decision, not an oversight:
 *  · `env` / `printenv` / bare `env` / `docker inspect` — the environment is where a session keeps its tokens, so
 *    they answer `read_secret`, out of reach of a troubleshooting grant;
 *  · `dig`, `nslookup`, `host`, `whois`, `ping`, `traceroute`, `mtr` — these query somebody ELSE's machine, so
 *    their object is that service or host and they keep their own answer (`read_only`);
 *  · `getent` (every account on the box, not this user's own identity) and `ldd` (it opens the binary) likewise;
 *  · anything that CHANGES state keeps its own category — see {@link STATUS_CHANGE_WORDS}, which is what stops a
 *    grant for reading `ip` from buying `ip link set eth0 down`.
 */
const MACHINE_STATUS_BINS: Record<string, string> = {
	ps: "the process table", pgrep: "the process table", pidof: "the process table", pstree: "the process tree",
	top: "the process table", htop: "the process table", btop: "the process table",
	lsof: "which process holds which file", fuser: "which process holds a file",
	df: "filesystem usage", free: "memory usage", lsblk: "the block devices", uptime: "uptime and load",
	nproc: "the CPU count", lscpu: "CPU information", lsusb: "attached USB devices", lspci: "PCI devices",
	sensors: "sensor readings", "nvidia-smi": "GPU state", "rocm-smi": "GPU state",
	uname: "kernel and machine information", hostname: "the host name", hostnamectl: "the host name",
	id: "the current user and its groups", whoami: "the current user", groups: "the current user's groups",
	ip: "the network configuration", ifconfig: "the network configuration", ss: "the socket table",
	netstat: "the socket table", route: "the routing table", arp: "the ARP table",
}

/**
 * The argument words that turn a network-configuration tool into a CHANGE rather than a status read.
 *
 * `ip`, `route`, `arp` and `ifconfig` are read-only tools only until their next argument: `ip link set`,
 * `route add`, `arp -d` rewrite the machine. Status reads are granted by intent, so a family that can also write
 * has to answer for the writing separately — otherwise "go look at the networking" would buy the reconfiguration.
 * These are CLI grammar (the same kind of table `DOCKER_READ` and `KUBECTL_READ` are), never prose.
 */
const STATUS_CHANGE_WORDS = new Set([
	"add", "del", "delete", "change", "replace", "set", "flush", "new", "rename", "append", "preappend", "purge",
	"promisc", "down", "up", "mtu", "txqueuelen",
])

/** `arp -s` / `arp -d` and `ss -K` are the flag-shaped changes in the same family. */
const STATUS_CHANGE_FLAGS = new Set(["-s", "-d", "--set", "--delete", "-K", "-D", "-E"])

/** A read of a machine's or a cluster's own state — the `read_system_state` row. */
function statusRead(raw: string, object: string, what: string): SegmentDecision[] {
	return [seg("ask", "read_system_state", what, raw, [target(object)])]
}

/**
 * The object of a status read that is scoped to ONE named unit (`journalctl -u X`, `systemctl status X`).
 *
 * The outcome aimed for is that a `read_system_state` grant naming the service answers the read,
 * while a machine-wide read (all logs, every disk, load) keeps asking. Two things have to be true at once for
 * that, and spelling the object as `machine/unit` is what makes both true at the same time:
 *
 *  · the unit is part of the object, so a grant naming the service matches it (the component matcher asks
 *    "does any component of the entity equal the target", so `gettemp` reaches `localhost/gettemp` — the same
 *    rule that lets an image name reach `myrepo/app:1.0`);
 *  · the machine is still part of it, so the approval a user already gave for THIS machine — the object every
 *    local status read carries — keeps answering the unit-scoped reads too. Dropping the machine
 *    would have made one `systemctl status nginx` cost a fresh prompt inside a session whose user had just
 *    approved reading the box.
 *
 * And the direction this deliberately excludes stays excluded by construction: a machine-wide read keeps its object
 * `localhost`, which a service-named grant does not reach, so `journalctl` with no `-u`, `df` and `uptime` keep
 * asking (pinned in `grants-imply.test.ts`).
 */
function unitReadObject(machine: string, unit: string): string {
	const name = unit.trim()
	return name ? `${machine}/${name}` : machine
}

/** The single unit a read names, if it names exactly one.
 *
 * Exactly one, deliberately: `systemctl status a b` and `journalctl -u a -u b` read BOTH, so answering them from
 * a grant that names `a` would be reading a service the user never mentioned. Two names fall back to the machine
 * object, which is the answer such a read had before a unit could join it.
 */
function soleUnit(units: string[]): string | undefined {
	const named = [...new Set(units.map((u) => u.trim()).filter(Boolean))]
	return named.length === 1 ? named[0] : undefined
}

/** `journalctl -u name` / `--unit name` / `--unit=name`, in the order they were written. */
function journalUnits(argv: string[]): string[] {
	const units: string[] = []
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!
		if (a === "-u" || a === "--unit") {
			const next = argv[i + 1]
			if (next && !next.startsWith("-")) units.push(next)
			continue
		}
		if (a.startsWith("--unit=")) units.push(a.slice("--unit=".length))
		else if (a.startsWith("-u") && a.length > 2) units.push(a.slice(2))
	}
	return units
}

/**
 * The machine a container-runtime read is addressed to (the `docker -H` / `DOCKER_HOST` case).
 *
 * An unset address means the local socket, which is this machine; a `tcp://host:port` means that host, and the
 * scheme and port are transport — the object a user can spell is the host. An address this function cannot read
 * falls back to the local machine, the narrower answer, because that is what an unaddressed client does.
 */
function daemonMachine(argv: string[], h: HandlerContext): string {
	const written = flagValue(argv, "-H", "--host") ?? h.opts.env?.DOCKER_HOST ?? process.env.DOCKER_HOST ?? ""
	const trimmed = written.trim()
	if (!trimmed || trimmed.startsWith("unix://") || trimmed.startsWith("/")) return LOCAL_MACHINE_OBJECT
	const host = netHost(trimmed)
	return host || LOCAL_MACHINE_OBJECT
}

/** Is this command the read form of its family, or the form that changes the machine? */
function asksForAChange(bin: string, argv: string[]): boolean {
	if (argv.slice(1).some((a) => STATUS_CHANGE_WORDS.has(a) || STATUS_CHANGE_FLAGS.has(a))) return true
	// `ifconfig` has no subcommand: `ifconfig` and `ifconfig -a` report, `ifconfig eth0 10.0.0.1 netmask …`
	// assigns. Naming the interface is the change, so a second operand is the whole test — and the cost of
	// getting this direction wrong is a troubleshooting grant buying a reconfiguration, which is the one thing
	// the status-read exclusion exists to prevent.
	if (bin === "ifconfig") return positionals(argv).length >= 2
	return false
}

// verbs that read the terminal / control flow — allow
const SHELL_BUILTIN_ALLOW = new Set([
	"export", "set", "unset", "shift", "local", "declare", "typeset", "readonly",
	"alias", "unalias", "hash", "ulimit", "umask", "return", "break", "continue",
	"exit", "trap", "getopts", "read", "let", "eval-noop", "shopt", "complete", "compgen",
	"disown", "jobs", "fg", "bg", "suspend", "logout", ":", "command", "builtin", "enable",
])

/**
 * The free list: the flags that make a command a report about ITSELF, nothing else.
 *
 * Only the two long spellings, deliberately. `-h` is "human-readable" on `df`, `du`, `ps`, `free` — all of
 * which are reads that must ask — and `-V` is "version" on some tools and "verbose" on others. A free
 * answer granted by a letter that means three things is how `df -h` would stop asking.
 */
const SELF_INFO_FLAGS = new Set(["--version", "--help"])

/** A command reporting on itself is free, and it is the ONLY free non-file read besides shell state. */
function isSelfReport(argv: string[]): boolean {
	return argv.length === 2 && SELF_INFO_FLAGS.has(argv[1]!)
}

/** A read of something that is not a file — a daemon, a cluster, a registry, host state. */
function objectRead(raw: string, object: string, what: string): SegmentDecision[] {
	return [seg("ask", "read_only", what, raw, [target(object)])]
}

/**
 * The session environment, which is a SECRET read and not a status read.
 *
 * The object keeps its older spelling (`environment variables`) so a row the user approved before this was a
 * category of its own still matches; only the category moved, and it moved the strict way — a `read_only` grant
 * no longer reaches it, and neither does a grant to read this machine's state.
 */
function environmentRead(raw: string, v: string): SegmentDecision[] {
	return [seg("ask", "read_secret", `${v} — reads the session environment`, raw, [target("environment variables")])]
}

/** The free list again: the tool's own information, or the shell's own state. */
function infoRow(raw: string, what: string): SegmentDecision[] {
	return [seg("allow", "read_only", what, raw)]
}

/**
 * The object a client/daemon read is about.
 *
 * A user who means "you may look at containers" writes `docker`, not `unix:///var/run/docker.sock`: the object
 * has to be spellable by the person who grants it, because it is also the value a stored grant carries. Where
 * the client can address several targets the address wins — `--context prod` *is* "the prod cluster" — so one
 * cluster's approval does not quietly cover every other cluster the same binary can reach.
 */
function clusterObject(argv: string[], client: string): string {
	return flagValue(argv, "--context", "--kube-context") ?? client
}

/**
 * The registry an image/artifact ref is read from.
 *
 * The first path component is a host only when it is spelled like one (a dot, a colon, or `localhost`);
 * otherwise the ref is a shortcut for the vendor registry, and naming the shortcut (`nginx`) would make a
 * grant for one image look like a grant for the registry. Unnamed → the client's own default.
 */
function registryOf(ref: string, client: string): string {
	const first = (ref.split("/")[0] ?? "").trim()
	if (first && (first === "localhost" || first.includes(".") || first.includes(":"))) return first
	return DEFAULT_REGISTRY[client] ?? client
}

/** Where a bare ref (`nginx`, `redis:7`) actually comes from — the registry the client defaults to. */
const DEFAULT_REGISTRY: Record<string, string> = { docker: "docker.io", podman: "docker.io", nerdctl: "docker.io" }

/**
 * The cluster a read is addressed to, as opposed to {@link clusterObject}, which is the answer kept for
 * the clients whose reads are NOT status reads (helm, terraform): the context the command names, else the
 * kubeconfig's current context, else the client's own name. With no kubeconfig probe (unit tests, `fs: false`)
 * it is the client name, so a test never depends on which cluster the machine happens to be logged into.
 */
function clusterReadObject(argv: string[], client: string, h: HandlerContext): string {
	return currentClusterObject(flagValue(argv, "--context", "--kube-context"), client, h.ctx.home, h.opts.env, h.opts.fs)
}

/**
 * `--dry-run` splits by WHERE it runs.
 *
 * `--dry-run=server` sends the object to the API for validation, which is a read of that cluster and asks like
 * one; `--dry-run` / `--dry-run=client` renders the manifest locally and touches nothing outside the project,
 * so it stays the tool's own output. Guessing the other way either prompts for a local render or waves through
 * a server round trip.
 */
function dryRunRows(argv: string[], client: string, raw: string, what: string): SegmentDecision[] {
	const mode = flagValue(argv, "--dry-run")
	return mode === "server"
		? objectRead(raw, clusterObject(argv, client), `${what} — --dry-run=server validates against the cluster`)
		: infoRow(raw, `${what} (rendered locally)`)
}

const WRAPPERS = new Set(["timeout", "time", "nice", "ionice", "nohup", "stdbuf", "strace", "ltrace", "command", "builtin", "exec", "setsid", "unbuffer", "script", "chronic", "flock", "taskset", "numactl"])

const INTERPRETERS = new Set(["python", "python2", "python3", "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua", "Rscript", "julia", "tclsh", "osascript", "pwsh", "powershell"])

const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish"])

/** Would this sink command execute its stdin as code? */
export function sinkExecutesStdin(argv: string[]): boolean {
	const v = base(argv[0] ?? "")
	if (v === "eval" || v === "exec") return true
	const rest = argv.slice(1)
	const hasInlineCode = rest.some((a) => a === "-c" || a === "-e" || a === "--eval" || a === "-p")
	const positional = rest.filter((a) => !a.startsWith("-") || a === "-")
	if (SHELLS.has(v)) {
		// `bash` / `sh -s` with no script file executes stdin
		return !hasInlineCode && !positional.some((a) => a !== "-" && a !== "-s")
	}
	if (INTERPRETERS.has(v)) {
		// `python3` / `python3 -` with no script and no -c executes stdin
		return !hasInlineCode && (positional.length === 0 || positional.every((a) => a === "-"))
	}
	return false
}

const TEST_TOOLS = new Set(["pytest", "tox", "nox", "ruff", "black", "isort", "mypy", "flake8", "pylint", "coverage", "vitest", "jest", "mocha", "ava", "tap", "karma", "playwright", "cypress", "rspec", "phpunit", "ctest", "gotestsum", "eslint", "prettier", "biome", "tsc", "stylelint", "shellcheck", "hadolint", "yamllint", "markdownlint", "commitlint"])

const PKG_PROJECT = new Set(["npm", "pnpm", "yarn", "bun"])

/** Files whose deletion is likely irreplaceable data loss even inside the project. */
const DATA_FILE_RE = /(backup|dump|snapshot|export)[^/]*$|\.(db|sqlite3?|sql|sql\.gz|tar|tar\.(gz|bz2|xz|zst)|tgz|zip|7z|parquet|bak)$|\/(backups?|dumps?|snapshots?|archives?)\//i

const NEVER_WIPE_HISTORY_RE = /\/(\.bash_history|\.zsh_history|\.python_history|\.node_repl_history)$/

// ---------------------------------------------------------------- main entry

export function classifyVerb(argvIn: string[], h: HandlerContext): SegmentDecision[] {
	return withTargetlessObjects(classifyVerbRows(argvIn, h))
}

function classifyVerbRows(argvIn: string[], h: HandlerContext): SegmentDecision[] {
	let argv = argvIn.filter((a) => a !== "")
	if (argv.length === 0) return [seg("allow", "read_only", "empty", rawOf(h.cmd))]

	// Peel wrappers: sudo/doas handled separately (privilege), the rest transparently.
	let sudo = false
	let guard = 0
	while (argv.length > 0 && guard++ < 6) {
		const v = base(argv[0]!)
		if (v === "sudo" || v === "doas" || v === "pkexec") {
			sudo = true
			argv = argv.slice(1)
			// skip sudo flags with args
			while (argv.length && argv[0]!.startsWith("-")) {
				const f = argv[0]!
				argv = argv.slice(1)
				if (["-u", "-g", "-p", "-C", "-D", "-h", "-U"].includes(f) && argv.length) argv = argv.slice(1)
			}
			continue
		}
		if (v === "su") {
			// su [-c cmd] [user]
			const c = flagValue(argv, "-c", "--command")
			if (c) {
				const inner = h.evaluateBash(c)
				return escalateSudo(inner.segments, h)
			}
			return [seg("ask", "privilege", "switch user with su", rawOf(h.cmd))]
		}
		if (WRAPPERS.has(v)) {
			argv = argv.slice(1)
			// skip the wrapper's own leading option words (numeric or -flag [val])
			while (argv.length && (/^-/.test(argv[0]!) || /^\d+[smhd]?$/.test(argv[0]!))) {
				const f = argv[0]!
				argv = argv.slice(1)
				if (["-n", "-o", "-e", "-p", "-c"].includes(f) && v !== "timeout" && argv.length) argv = argv.slice(1)
			}
			continue
		}
		if (v === "env") {
			const inner = stepOverEnvArguments(argv.slice(1))
			// An option this table does not know means the command behind `env` cannot be located. Guessing
			// where it starts would judge some other command than the one that runs, so hand it to the model.
			if (inner === null) return [seg("unknown", "unknown_command", `run \`${rawOf(h.cmd)}\` — env option not understood`, rawOf(h.cmd))]
			// Nothing follows: `env` is not a wrapper here, it IS the command, and what it prints is the
			// session environment — the read `printenv` is (reading the environment is not shell state).
			// Peeling it away called `env | grep '^PI_'` free, which is how a token in an env var got read.
			if (inner.length === 0) break
			argv = inner
			continue
		}
		if (v === "xargs") {
			// xargs [flags] cmd … — classify the inner command; input comes from the pipe.
			argv = argv.slice(1)
			while (argv.length && argv[0]!.startsWith("-")) {
				const f = argv[0]!
				argv = argv.slice(1)
				if (["-I", "-n", "-P", "-d", "-a", "-E", "-L", "-s"].includes(f) && argv.length) argv = argv.slice(1)
			}
			if (argv.length === 0) return [seg("allow", "read_only", "xargs echo", rawOf(h.cmd))]
			// The arguments are unknown (come from stdin) — classify the verb with a glob target.
			const inner = classifyVerb([...argv, "*piped-input*"], h)
			return sudo ? escalateSudo(inner, h) : inner.map((s) => s.tier === "allow" && s.category === "read_only" ? s : { ...s, description: s.description + " (targets from piped input)" })
		}
		break
	}
	if (argv.length === 0) return [seg("allow", "read_only", "wrapper only", rawOf(h.cmd))]

	const decisions = dispatch(argv, h)
	return sudo ? escalateSudo(decisions, h) : decisions
}

function base(word: string): string {
	return path.posix.basename(word)
}

/** `NAME=value` — an argument that belongs to `env` rather than to the command it would run. */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

/**
 * `env`'s own arguments — deliberately the same vocabulary §11.2 gives the walker, because the two engines
 * disagreeing about where a wrapper ends is how a command gets judged as something else.
 */
const ENV_BARE_OPTIONS = new Set(["--", "-i", "-0", "--ignore-environment", "--null"])
const ENV_VALUE_OPTIONS = new Set(["-u", "--unset"])

/**
 * Step over `env`' own arguments and return the command it runs — the empty array when it runs none.
 *
 * `null` is a third answer and it is not the same question as "no command": the shape is one this table
 * cannot read, so where the wrapped command starts is unknown and the verdict belongs to the model. An
 * empty answer means the command ran nothing and printed the environment, which is a read.
 */
function stepOverEnvArguments(args: string[]): string[] | null {
	let i = 0
	while (i < args.length) {
		const word = args[i]!
		if (ENV_ASSIGNMENT.test(word)) {
			i += 1
			continue
		}
		if (!(word.length > 1 && word.startsWith("-"))) return args.slice(i) // the command starts here
		const long = word.startsWith("--")
		const equals = word.indexOf("=")
		const name = long ? (equals > 0 ? word.slice(0, equals) : word) : word.slice(0, 2)
		const valueWrittenWithIt = long ? equals > 0 : word.length > 2
		if (ENV_BARE_OPTIONS.has(name)) {
			// `-i=…` is not a spelling of `env` this table knows, and guessing is how an option swallows a command.
			if (valueWrittenWithIt) return null
			i += 1
			continue
		}
		if (ENV_VALUE_OPTIONS.has(name)) {
			// `-u NAME`, `-uNAME` and `--unset=NAME` all drop one variable; only the first eats the next word.
			i += valueWrittenWithIt ? 1 : 2
			continue
		}
		return null
	}
	return []
}

/** sudo wrapping: NEVER stays NEVER; everything else becomes ask/privilege (spec §2.2). */
function escalateSudo(decisions: SegmentDecision[], h: HandlerContext): SegmentDecision[] {
	return decisions.map((d) => {
		if (d.tier === "never") return d
		const ents = d.entities.length ? d.entities : [target(d.description.slice(0, 60))]
		return seg("ask", "privilege", `with sudo: ${d.description}`, rawOf(h.cmd), ents, { inlineCode: d.inlineCode })
	})
}

// ---------------------------------------------------------------- dispatch

function dispatch(argv: string[], h: HandlerContext): SegmentDecision[] {
	const v = base(argv[0]!)
	const raw = rawOf(h.cmd)

	// The free list, first because it is the cheapest answer and the one an agent hits constantly: `git
	// --version`, `docker --help`. A tool describing itself reads nothing outside the project.
	if (isSelfReport(argv)) return infoRow(raw, `${v} ${argv[1]} (the tool's own version/help)`)

	switch (v) {
		case "rm": case "unlink": return rmHandler(argv, h)
		case "rmdir": return rmdirHandler(argv, h)
		case "shred": return [neverIfSystem(argv, h, "shred", true) ?? seg("ask", "delete_recursive", `shred ${listTargets(argv, h)}`, raw, targetsOf(argv, h))]
		case "dd": return ddHandler(argv, h)
		case "mkfs": case "mkfs.ext4": case "mkfs.xfs": case "mkfs.btrfs": case "mkfs.vfat": case "fdisk": case "parted": case "wipefs": case "sfdisk": case "blkdiscard": case "mkswap":
			return [seg("never", "disk_destroy", `${v} — disk/partition operation`, raw, targetsOf(argv, h))]
		case "mv": case "cp": case "install": case "rsync": return cpMvHandler(argv, h, v)
		case "ln": return lnHandler(argv, h)
		case "mkdir": case "touch": return mkdirTouchHandler(argv, h, v)
		case "truncate": return truncateHandler(argv, h)
		case "tee": return teeHandler(argv, h)
		case "sed": return sedHandler(argv, h)
		case "awk": case "gawk": case "mawk": return awkHandler(argv, h)
		case "chmod": case "chown": case "chgrp": case "chattr": case "setfacl": return chmodHandler(argv, h, v)
		case "git": return gitHandler(argv, h)
		case "gh": case "glab": case "hub": return ghHandler(argv, h)
		case "docker": case "podman": case "nerdctl": return dockerHandler(argv, h)
		case "oras": return orasHandler(argv, h)
		case "docker-compose": return dockerComposeHandler(argv.slice(0), h, 0)
		case "kubectl": case "oc": case "k9s": return kubectlHandler(argv, h)
		case "helm": return helmHandler(argv, h)
		case "terraform": case "tofu": case "pulumi": return terraformHandler(argv, h)
		case "aws": return awsHandler(argv, h)
		case "gcloud": case "gsutil": case "az": case "doctl": case "flyctl": case "fly": case "vercel": case "netlify": case "wrangler": case "heroku": return cloudHandler(argv, h, v)
		case "apt": case "apt-get": case "aptitude": case "dnf": case "yum": case "zypper": case "pacman": case "apk": case "emerge": case "nix-env": case "snap": case "flatpak": case "brew": case "port": return sysPkgHandler(argv, h, v)
		case "npm": case "pnpm": case "yarn": case "bun": return npmHandler(argv, h, v)
		case "npx": case "bunx": case "pnpx": return npxHandler(argv, h, v)
		case "pip": case "pip2": case "pip3": return pipHandler(argv, h, v)
		case "pipx": case "uv": case "poetry": case "pdm": case "conda": case "mamba": return pyEnvHandler(argv, h, v)
		case "cargo": return cargoHandler(argv, h)
		case "go": return goHandler(argv, h)
		case "gem": case "bundle": case "composer": case "mix": case "dotnet": case "gradle": case "gradlew": case "mvn": case "sbt": case "lein": case "stack": case "cabal": case "swift": case "zig": return buildToolHandler(argv, h, v)
		case "make": case "cmake": case "ninja": case "meson": case "bazel": case "just": case "task": case "rake": return makeHandler(argv, h, v)
		case "curl": case "wget": case "http": case "https": case "httpie": case "aria2c": case "axel": return curlHandler(argv, h, v)
		case "ssh": case "mosh": return sshHandler(argv, h)
		case "scp": case "sftp": return scpHandler(argv, h)
		case "nc": case "ncat": case "netcat": case "socat": return ncHandler(argv, h, v)
		case "kill": case "pkill": case "killall": case "killall5": return killHandler(argv, h, v)
		case "systemctl": return systemctlHandler(argv, h)
		case "service": case "rc-service": return serviceControlRows(argv, h, v)
		case "journalctl": return journalctlHandler(argv, h)
		case "crontab": return crontabHandler(argv, h)
		case "iptables": case "ip6tables": case "nft": case "ufw": case "firewall-cmd": return firewallHandler(argv, h, v)
		case "reboot": case "shutdown": case "halt": case "poweroff": case "telinit": case "init":
			return [seg("never", "system_power", `${v} — machine power state`, raw)]
		case "mount": case "umount": case "swapon": case "swapoff": case "losetup": case "modprobe": case "insmod": case "rmmod": case "sysctl": case "setenforce": case "update-alternatives": case "ldconfig": case "eject":
			return sysConfigHandler(argv, h, v)
		case "useradd": case "userdel": case "usermod": case "groupadd": case "groupdel": case "passwd": case "chpasswd": case "visudo": case "adduser": case "deluser":
			return userMgmtHandler(argv, h, v)
		case "psql": case "mysql": case "mariadb": case "sqlite3": case "mongosh": case "mongo": case "redis-cli": case "clickhouse-client": case "duckdb": return dbHandler(argv, h, v)
		case "history": return historyHandler(argv, h)
		case "find": return findHandler(argv, h)
		case "tar": case "zip": case "unzip": case "gzip": case "gunzip": case "xz": case "zstd": case "7z": case "bsdtar": return archiveHandler(argv, h, v)
		case "tmux": case "screen": return tmuxHandler(argv, h)
		case "pi": case "claude": case "codex": case "aider": {
			if (argv.slice(1).every((a) => /^(--help|-h|--version|-v|--list-models|list|--list|--print-config)$/.test(a)) && argv.length <= 3) {
				return [seg("allow", "read_only", `${v} ${argv[1] ?? ""}`, raw)]
			}
			// The object of spawning an agent is the AGENT, not its prompt: one approval covers every pi
			// invocation (chained, redirected, backgrounded, nohup'd) and never covers a different program.
			return [seg("ask", "agent_spawn", `spawn coding agent: ${raw.slice(0, 120)}`, raw, [target(v)])]
		}
		case "code": case "subl": case "vim": case "vi": case "nvim": case "nano": case "emacs":
			return editorHandler(argv, h, v)
		case "eval": return [seg("unknown", "interpreter_unknown", `eval: ${argv.slice(1).join(" ").slice(0, 200)}`, raw, [], { inlineCode: argv.slice(1).join(" ") })]
		case "source": case ".": return sourceHandler(argv, h)
		case "ollama": case "llama-server": case "llama-cli": case "vllm": return [seg("ask", "network_listen", `start model server ${v}`, raw, targetsOf(argv, h))]
	}

	if (TEST_TOOLS.has(v)) return [seg("allow", "run_project_code", `${v} (project test/lint tool)`, raw)]
	if (SHELLS.has(v)) return shellHandler(argv, h, v)
	if (INTERPRETERS.has(v)) return interpreterHandler(argv, h, v)
	if (SHELL_BUILTIN_ALLOW.has(v)) return [seg("allow", "read_only", `shell builtin ${v}`, raw)]

	if (FILE_READERS.has(v)) return fileReadRows(h, v, raw, pathOperands(v, argv))
	// The status families. The object is the MACHINE, so one approval covers the family instead of the
	// command — except where the same tool can also reconfigure the machine, which is a change and keeps its
	// own category however the arguments are spelled.
	const statusWhat = MACHINE_STATUS_BINS[v]
	if (statusWhat !== undefined) {
		if (asksForAChange(v, argv)) return [seg("ask", "system_config", `${v} changes ${statusWhat}`, raw, targetsOf(argv, h))]
		return statusRead(raw, LOCAL_MACHINE_OBJECT, `${v} — reads ${statusWhat} on this machine`)
	}
	// The environment is where a session keeps its tokens, so it is a SECRET read and a troubleshooting
	// grant must never reach it. `env` reaches here only when it runs no command (as a wrapper it is peeled).
	if (v === "env" || v === "printenv") return environmentRead(raw, v)
	if (HOST_READ_OBJECTS[v] !== undefined) return objectRead(raw, HOST_READ_OBJECTS[v]!, `${v} — reads ${HOST_READ_OBJECTS[v]}`)
	if (ARG_DATA_BINS.has(v)) return argDataRows(h, v, raw, positionals(argv))

	// ./script.sh or /path/to/script inside project → run project code
	if (argv[0]!.includes("/")) {
		const pc = h.classify(argv[0]!)
		if (pc.insideProject && !pc.isGitInternal) {
			return [seg("allow", "run_project_code", `run project script ${h.display(pc)}`, raw)]
		}
		if (pc.abs && !pc.insideProject) {
			// known safe absolute binaries (e.g. /usr/bin/ls) — re-dispatch on the basename once
			const bin = base(argv[0]!)
			if (FILE_READERS.has(bin)) return fileReadRows(h, bin, raw, pathOperands(bin, argv))
			if (MACHINE_STATUS_BINS[bin] !== undefined) {
				const what = MACHINE_STATUS_BINS[bin]!
				if (asksForAChange(bin, argv)) return [seg("ask", "system_config", `${bin} changes ${what}`, raw, targetsOf(argv, h))]
				return statusRead(raw, LOCAL_MACHINE_OBJECT, `${bin} — reads ${what} on this machine`)
			}
			if (bin === "env" || bin === "printenv") return environmentRead(raw, bin)
			if (ARG_DATA_BINS.has(bin)) return argDataRows(h, bin, raw, positionals(argv))
			return [seg("unknown", "unknown_command", `run ${pc.abs}`, raw)]
		}
	}

	// function definitions `foo() {` slip through the lexer as words — allow-noop
	if (/^\w+\(\)$/.test(argv[0]!)) return [seg("allow", "read_only", "function definition", raw)]

	return [seg("unknown", "unknown_command", `run \`${raw.slice(0, 200)}\``, raw)]
}

// ---------------------------------------------------------------- handlers

/** Rows whose categories describe why the analyzer stopped rather than what the command does. */
function isBookkeepingCategory(category: string): boolean {
	return category === "unparseable_command" || category.startsWith("unknown_") || category.startsWith("unproven_")
}

/**
 * Categories whose target language ALREADY has a wildcard.
 *
 * `vcs_remote`, `container_mutation`, `network_send` and `vcs_force_protected` are read by a grammar, and in each
 * of them `*` is a word with a meaning of its own (`network_send` `*` covers any host, `container_mutation` `*`
 * any repository — see `target-grammar.ts`). Naming `*` for a command that named no destination there would not
 * record "a targetless action", it would record "every destination", so those rows keep refusing a target.
 * `publish-targets.test.ts` pins the same refusal for `docker push` with no ref.
 */
function hasTargetGrammar(category: string): boolean {
	return category.split("+").some((segment) => grammarFor(segment.trim()) !== undefined)
}

/**
 * Give every targetless ASK row the category-as-object marker (`NO_OBJECT_TARGET`, defined in `grant-verify.ts`
 * with the rules that keep it from matching a named target).
 *
 * Some actions have no noun a user could name: `su` is "be another user", an interactive shell is "hand this
 * terminal to a human", a bare `systemctl` is the tool's own usage. Their capability IS the category, so a
 * targetless ask used to be unanswerable by construction — both grant stores started with "no targets ⇒ not
 * covered", and the "always" button had no row to store. The row that answers one is `{category, "*"}`, which
 * is exactly as wide as the invocation that earned it: a missing value never becomes a wildcard, and an
 * action with no value at all is the one case where the wildcard IS the object).
 *
 * Asked only of ask-tier rows: an allow row needs no permission, and an `unknown` row's object is precisely what
 * the model is being asked to determine, so naming the category there would put a word into the effects prompt
 * that nobody said.
 */
function withTargetlessObjects(decisions: SegmentDecision[]): SegmentDecision[] {
	return decisions.map((d) => {
		if (d.tier !== "ask" || d.entities.length > 0) return d
		if (isBookkeepingCategory(d.category) || hasTargetGrammar(d.category)) return d
		return { ...d, entities: [target(NO_OBJECT_TARGET)] }
	})
}

/**
 * Editor options that run something of their own rather than open a file.
 *
 * `vim -c '!rm -rf /'` and `emacs --eval …` are not "open this file": the editor is being used as a launcher,
 * and the argv editor options are where the launched command hides. Those invocations keep the editor's own
 * category (so they still ask), with the file named when there is one.
 */
const EDITOR_EXEC_OPTIONS = new Set([
	"-c", "--cmd", "-S", "--source", "-s", "--script",
	"-e", "--eval", "--batch", "-l", "--load",
	"--command", "--execute", "--remote", "--remote-expr", "--remote-send", "--remote-tab",
])

/** Editor options whose next word is an ARGUMENT, not a file (`vim -c 'set nu' notes.md`). */
const EDITOR_VALUE_OPTIONS = new Set([
	"-c", "--cmd", "-S", "--source", "-s", "--script",
	"-e", "--eval", "-l", "--load", "-t", "--tag", "-u", "--command", "--execute",
	"--remote-expr", "--remote-send", "--remote-tab",
])

/** The file operands of an editor invocation: no option words, no option arguments, no `+cmd`/`+42`. */
function editorOperands(argv: string[]): string[] {
	const out: string[] = []
	let noMoreFlags = false
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!
		if (!noMoreFlags && a === "--") { noMoreFlags = true; continue }
		if (!noMoreFlags && a.length > 1 && a.startsWith("-")) {
			if (EDITOR_VALUE_OPTIONS.has(a) && i + 1 < argv.length) i++
			continue
		}
		if (a.startsWith("+")) continue
		out.push(a)
	}
	return out
}

/**
 * Does this editor word launch something of its own? `+42` and `+/pattern` are a line number and a search —
 * they move the cursor. `+cmd` (and every option in {@link EDITOR_EXEC_OPTIONS}) runs ex/emacs code.
 */
function editorLaunchesSomething(argv: string[]): boolean {
	return argv.slice(1).some((a) => {
		if (EDITOR_EXEC_OPTIONS.has(a)) return true
		return a.startsWith("+") && !/^\+\d+$/.test(a) && !a.startsWith("+/")
	})
}

/**
 * Opening a file in an interactive editor, decided like the WRITE to that file.
 *
 * The editor is how bytes get into a file, and the file is the whole object: classifying the operand with
 * `decideWrite` gives the row the write tier and the write target, so `vim notes.md` inside the project is the
 * project write it is, `vim ~/.ssh/config` is `write_sensitive`, and a write grant over a folder covers the
 * editor opened inside it. Before this, the row carried no target at all, so no stored grant could ever answer
 * it and the user was asked the same question every time.
 *
 * Two shapes deliberately keep the editor's own category instead:
 *  · no file operand — an empty buffer opens nothing, so there is no object to name and the row stays an ask
 *    with no target;
 *  · a command-carrying option ({@link EDITOR_EXEC_OPTIONS}, `+cmd`) — the argv then runs something of its own,
 *    which is not a write to the file.
 * Both still name the file operands, so the prompt says what is being opened.
 */
function editorHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const files = editorOperands(argv)
	if (editorLaunchesSomething(argv) || files.length === 0) {
		const named = files.slice(0, 6).map((f) => target(h.display(h.classify(f))))
		return [seg("ask", "interactive_editor", `open interactive editor ${v}`, raw, named)]
	}
	return files.slice(0, 6).map((f) => h.decideWrite(h.classify(f), "open in editor"))
}

/**
 * The file-reading binaries: every operand is put through the same path rule a parsed read uses.
 *
 * With no operand the command filters its stdin — the bytes the pipeline already produced, which the
 * upstream segment was asked about — so it reads nothing new and is free. With operands each one decides
 * for itself, and a read of two files outside the project is two objects: the user is asked about the
 * objects they were asked about, and a grant for one of them does not silently cover the other.
 */
function fileReadRows(h: HandlerContext, verb: string, raw: string, operands: string[]): SegmentDecision[] {
	if (operands.length === 0) return infoRow(raw, `${verb} (no file argument)`)
	// `command` stays the leg's own text, as every other handler leaves it: `decideRead` builds its own phrase for
	// the tool-call path, where there is no shell command to quote, and a prompt that lost the command would be
	// a prompt the user cannot read.
	return operands.slice(0, 6).map((p) => ({ ...h.decideRead(h.classify(p), verb), command: raw }))
}

/** The operands of a file reader that are actually paths: every one, except a search tool's pattern. */
function pathOperands(bin: string, argv: string[]): string[] {
	const pos = positionals(argv)
	if (pos.length === 0 || !PATTERN_FIRST_BINS.has(bin)) return pos
	if (hasFlag(argv, ...PATTERN_FLAGS)) return pos
	return pos.slice(1)
}

/** An operand that is a word, a number or a path *string* — nothing is opened, but a named credential still asks. */
function argDataRows(h: HandlerContext, verb: string, raw: string, operands: string[]): SegmentDecision[] {
	const named = operands.map((p) => h.classify(p)).find((pc) => pc.isSecret)
	if (named) return [seg("ask", "read_secret", `names secret-bearing path ${h.display(named)} (via ${verb})`, raw, [target(h.display(named))])]
	return infoRow(raw, `${verb} (arguments are data, not files)`)
}

function targetsOf(argv: string[], h: HandlerContext): Entity[] {
	return positionals(argv).slice(0, 6).map((p) => target(p))
}

function listTargets(argv: string[], h: HandlerContext): string {
	const pos = positionals(argv)
	return pos.slice(0, 4).join(" ") + (pos.length > 4 ? " …" : "")
}

function neverIfSystem(argv: string[], h: HandlerContext, verb: string, recursive: boolean): SegmentDecision | null {
	for (const p of positionals(argv)) {
		const pc = h.classify(p)
		if (pc.unresolvedRoot) return seg("ask", "delete_recursive", `${verb} on unresolved path ${p}`, rawOf(h.cmd), [target(p)])
		if (pc.isDevice) return seg("never", "device_write", `${verb} on device ${pc.abs}`, rawOf(h.cmd), [target(pc.abs!)])
		if (recursive && (pc.isNeverWipe || pc.isProjectRoot)) {
			return seg("never", "wipe_protected", `${verb} would destroy ${h.display(pc)} (protected location)`, rawOf(h.cmd), [target(h.display(pc))])
		}
		if (pc.abs && NEVER_WIPE_HISTORY_RE.test(pc.abs)) {
			return seg("never", "history_wipe", `delete shell history ${h.display(pc)}`, rawOf(h.cmd), [target(h.display(pc))])
		}
	}
	return null
}

function rmHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const recursive = hasFlag(argv, "-r", "-R", "--recursive")
	const pos = positionals(argv)
	// No operand at all: `rm` prints its usage and removes nothing, so there is no action to gate — and a row
	// could not name what it was about either.
	if (pos.length === 0) return [seg("allow", "read_only", "rm with no operand (prints usage)", raw)]
	const never = neverIfSystem(argv, h, recursive ? "recursively delete" : "delete", recursive)
	if (never) return [never]

	const out: SegmentDecision[] = []
	for (const p of pos) {
		const pc = h.classify(p)
		const disp = h.display(pc)
		if (pc.unresolvedRoot) { out.push(seg("ask", "delete_recursive", `delete unresolved path ${p}`, raw, [target(p)])); continue }
		if (pc.isSecret) { out.push(seg("ask", "write_sensitive", `delete secret-bearing file ${disp}`, raw, [target(disp)])); continue }
		if (recursive) {
			// recursive delete is ASK everywhere, including inside the project (spec §2.2)
			out.push(seg("ask", "delete_recursive", `recursively delete ${disp}`, raw, [target(disp)]))
			continue
		}
		if ((pc.insideProject && !pc.isGitInternal) || pc.isTemp) {
			if (pc.insideProject && DATA_FILE_RE.test(pc.abs ?? p)) { out.push(seg("ask", "delete_data", `delete data/backup file ${disp}`, raw, [target(disp)])); continue }
			out.push(seg("allow", "write_project", `delete file ${disp}`, raw, [pathTouched(disp)])); continue
		}
		if (pc.isGitInternal) { out.push(seg("ask", "write_sensitive", `delete inside .git: ${disp}`, raw, [target(disp)])); continue }
		out.push(seg("ask", "delete_outside", `delete ${disp} (outside project)`, raw, [target(disp), scope(path.posix.dirname(pc.abs ?? p) + "/")]))
	}
	return out
}

function rmdirHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	return positionals(argv).map((p) => {
		const pc = h.classify(p)
		if (pc.isNeverWipe || pc.isProjectRoot) return seg("never", "wipe_protected", `rmdir protected ${h.display(pc)}`, raw, [target(h.display(pc))])
		if (pc.insideProject) return seg("allow", "write_project", `rmdir ${h.display(pc)}`, raw, [pathTouched(h.display(pc))])
		return seg("ask", "delete_outside", `rmdir ${h.display(pc)}`, raw, [target(h.display(pc))])
	})
}

function ddHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const of = argv.find((a) => a.startsWith("of="))?.slice(3)
	if (!of) return [seg("ask", "delete_recursive", "dd without visible output target", raw)]
	const pc = h.classify(of)
	if (pc.isDevice) return [seg("never", "disk_destroy", `dd onto device ${pc.abs}`, raw, [target(pc.abs!)])]
	return [h.decideWrite(pc, "dd write to")]
}

function cpMvHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	let pos = positionals(argv)
	// rsync: strip host:path targets → network_send
	if (v === "rsync") {
		const remote = pos.find((p) => /^[\w.-]+@[\w.-]+:|^[\w.-]+:(?!\/\/)/.test(p) && !p.startsWith("./"))
		if (remote) {
			const sources = pos.filter((p) => p !== remote)
			const secretSrc = sources.map((p) => h.classify(p)).find((pc) => pc.isSecret || (pc.abs && pc.isNeverWipe))
			if (secretSrc) return [seg("never", "exfiltration", `rsync ${h.display(secretSrc)} to remote ${remote}`, raw, [target(remote)])]
			return [seg("ask", "network_send", `rsync to remote ${remote}`, raw, [target(remote)])]
		}
		if (hasFlag(argv, "--delete", "--delete-after", "--delete-before", "--delete-during", "--delete-excluded")) {
			const dest = pos[pos.length - 1]
			const pc = dest ? h.classify(dest) : null
			if (pc && (pc.isNeverWipe || pc.isProjectRoot)) return [seg("never", "wipe_protected", `rsync --delete into protected ${h.display(pc)}`, raw, [target(h.display(pc))])]
			return [seg("ask", "delete_recursive", `rsync --delete into ${dest}`, raw, dest ? [target(dest)] : [])]
		}
	}
	if (pos.length < 2) return [seg("ask", "write_outside", `${v} with unclear target`, raw)]
	const dest = pos[pos.length - 1]!
	const sources = pos.slice(0, -1)
	const destPc = h.classify(dest)
	const out: SegmentDecision[] = []
	// moving a protected dir away is destructive too
	if (v === "mv") {
		for (const s of sources) {
			const spc = h.classify(s)
			if (spc.isNeverWipe || spc.isProjectRoot) out.push(seg("never", "wipe_protected", `move protected ${h.display(spc)} away`, raw, [target(h.display(spc))]))
			else if (spc.isGitInternal) out.push(seg("ask", "write_sensitive", `move .git internals ${h.display(spc)}`, raw, [target(h.display(spc))]))
			else if (!spc.insideProject && spc.abs) out.push(seg("ask", "delete_outside", `move ${h.display(spc)} (outside project)`, raw, [target(h.display(spc))]))
		}
	}
	// secret source copied out of a secret location
	const secretSrc = sources.map((s) => h.classify(s)).find((pc) => pc.isSecret)
	if (secretSrc && !destPc.insideProject) out.push(seg("ask", "read_secret", `copy secret ${h.display(secretSrc)} to ${h.display(destPc)}`, raw, [target(h.display(secretSrc))]))
	else if (secretSrc && destPc.insideProject) out.push(seg("ask", "read_secret", `copy secret ${h.display(secretSrc)} into project`, raw, [target(h.display(secretSrc))]))
	out.push(h.decideWrite(destPc, `${v} to`))
	return out
}

function lnHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const pos = positionals(argv)
	const dest = pos.length >= 2 ? pos[pos.length - 1]! : pos[0]
	if (!dest) return [seg("allow", "write_project", "ln", rawOf(h.cmd))]
	return [h.decideWrite(h.classify(dest), "create link at")]
}

function mkdirTouchHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	return positionals(argv).map((p) => h.decideWrite(h.classify(p), v))
}

function truncateHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	return positionals(argv).map((p) => {
		const pc = h.classify(p)
		const d = h.decideWrite(pc, "truncate")
		// truncating a file to empty is data loss — inside project still allow (recoverable via git normally)
		return d
	})
}

function teeHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	return positionals(argv)
		.filter((p) => !reportedAsWrite(h, p))
		.map((p) => h.decideWrite(h.classify(p), hasFlag(argv, "-a", "--append") ? "append to" : "write"))
}

/**
 * Does layer 0 already report this operand as a file the command writes?
 *
 * `tee -o FILE` names its output with a flag, and the walker reports that operand on the command's
 * redirect list — the channel every write target arrives on. tee's own operand scan reads `-o`'s value
 * as an ordinary file argument too, so without this filter one file opening is described twice in the
 * prompt. Reads are not it: only a write op already reported counts, and on the lexer path — which has
 * no such report for a flag — nothing here is ever skipped, so tee still judges every operand itself.
 */
function reportedAsWrite(h: HandlerContext, operand: string): boolean {
	return h.cmd.redirects.some((r) => WRITE_REDIRECT_OPS.has(r.op) && r.target.value === operand)
}

/** Redirect operators that open their target for writing — the ones that say "this file is written". */
const WRITE_REDIRECT_OPS = new Set([">", ">>", ">|", "<>", "&>", "&>>"])

function sedHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-i", "--in-place") || argv.some((a) => /^-i(\.|$)/.test(a))) {
		return positionals(argv).filter((p) => !/^s[/#|,]|^[0-9]|^\/|^y\//.test(p) || h.classify(p).abs !== null).slice(1).map((p) => h.decideWrite(h.classify(p), "sed -i edit"))
			.filter((d, i, arr) => arr.length ? true : true) // keep list; empty → generic
			.concat([]) // no-op
			|| []
	}
	// sed w command writes files: `s/x/y/w file` or `1w file`
	const script = positionals(argv)[0] ?? ""
	const wMatch = /(?:^|[;\n])\s*(?:\d+\s*)?w\s+(\S+)|\/w\s+(\S+)$/m.exec(script)
	if (wMatch) {
		const f = wMatch[1] ?? wMatch[2]!
		return [h.decideWrite(h.classify(f), "sed write to")]
	}
	// Without `-i` sed prints the result instead of writing it, but it still READS the files it was given.
	return fileReadRows(h, "sed", raw, fileOperandsAfterScript(argv))
}

/**
 * The files a `sed`/`awk`-shaped command reads: every operand except the program.
 *
 * The program is the first operand unless it was passed with `-e`/`-f`, in which case every operand is a file.
 * This is the same grammar rule {@link pathOperands} applies to grep and jq — one shape, one helper.
 */
function fileOperandsAfterScript(argv: string[]): string[] {
	const pos = positionals(argv)
	if (pos.length === 0) return []
	if (hasFlag(argv, "-e", "--expression", "-f", "--file", "--progfile")) return pos
	return pos.slice(1)
}

function awkHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const prog = positionals(argv)[0] ?? argv.find((a) => a.includes("{")) ?? ""
	if (/\bsystem\s*\(/.test(prog)) return [seg("unknown", "interpreter_unknown", `awk with system() call`, raw, [], { inlineCode: prog.slice(0, 500) })]
	const redir = /(?:>|>>)\s*"([^"]+)"/.exec(prog)
	if (redir) return [h.decideWrite(h.classify(redir[1]!), "awk write to")]
	// Like sed: the program is data, the files after it are read.
	return fileReadRows(h, "awk", raw, fileOperandsAfterScript(argv))
}

function chmodHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const recursive = hasFlag(argv, "-R", "--recursive", "-r")
	const pos = positionals(argv)
	const mode = pos[0] ?? ""
	const files = pos.slice(1)
	const worldWritable = v === "chmod" && (/^0?[0-7]?77[67]?$/.test(mode) || /(^|,)[ao]?\+w/.test(mode) && mode.includes("o"))
	const out: SegmentDecision[] = []
	// A mode with no file (or no argument at all) is usage, not a permission change: nothing is chmodded, and
	// the row could name no target.
	if (files.length === 0) return [seg("allow", "read_only", `${v} with no file operand (prints usage)`, raw)]
	for (const f of files) {
		const pc = h.classify(f)
		const disp = h.display(pc)
		if ((pc.isNeverWipe || pc.abs === "/") && recursive) { out.push(seg("never", "perm_destroy", `${v} -R on protected ${disp}`, raw, [target(disp)])); continue }
		if (pc.insideProject && !worldWritable && !pc.isGitInternal) { out.push(seg("allow", "write_project", `${v} ${mode} ${disp}`, raw, [pathTouched(disp)])); continue }
		out.push(seg("ask", "perm_change", `${v} ${mode} ${disp}${worldWritable ? " (world-writable)" : ""}`, raw, [target(disp)]))
	}
	return out
}

// ---------------------------------------------------------------- git & forges

const GIT_READ = new Set(["status", "log", "diff", "show", "branch", "remote", "ls-files", "ls-remote", "ls-tree", "cat-file", "rev-parse", "rev-list", "describe", "blame", "shortlog", "reflog", "config", "var", "grep", "help", "version", "count-objects", "cherry", "whatchanged", "show-ref", "symbolic-ref", "name-rev", "merge-base", "diff-tree", "diff-index", "fsck", "bisect", "worktree", "notes", "stash"])
const GIT_LOCAL_WRITE = new Set(["add", "commit", "checkout", "switch", "merge", "rebase", "cherry-pick", "revert", "tag", "init", "mv", "rm", "restore", "apply", "am", "format-patch", "fetch", "pull", "submodule", "clone", "gc", "prune", "pack-refs", "maintenance", "sparse-checkout", "update-index", "commit-tree", "read-tree", "write-tree", "mktree", "checkout-index"])
/** …of those, the ones that ask a REMOTE for objects, so outside the project they are also object reads. */
const GIT_REMOTE_READ = new Set(["fetch", "pull"])
/**
 * Branches a force-push or a delete may not touch on the word of an unnamed target.
 *
 * Exported because the grant grammar in `target-grammar.ts` mirrors this table: a user who writes "never
 * force-push to main" has to land on the same set of names the prompt denied, and a second copy of the
 * regex would drift into "the prompt asked, the ledger said no".
 */
export const PROTECTED_BRANCH_RE = /^(main|master|trunk|develop|dev|release[\/-].*|production|prod|stable)$/i

/**
 * The branch a `git push` writes on the far side, from the refspec git was given.
 *
 * The name that matters is the remote side: after the colon when there is one (`HEAD:feat/x`,
 * `local:feat/x`), without the leading `+` that only means "overwrite" and without the `refs/heads/`
 * prefix git also accepts. `feat/x:` (left side only) deletes that remote branch, so when the right side
 * is empty the name is the left one.
 */
function remoteSideOf(refspec: string): string {
	const at = refspec.indexOf(":")
	const clean = (w: string) => w.replace(/^\+/, "").replace(/^refs\/heads\//, "")
	return clean(at >= 0 ? refspec.slice(at + 1) : refspec) || (at >= 0 ? clean(refspec.slice(0, at)) : "")
}

/**
 * Which branch a push writes.
 *
 * A refspec says so directly. With none, git pushes the *current* branch, and layer 0 has no shell state
 * to read — the session's own branch (`PolicyOptions.gitBranch`, from pi's git info) is the only value
 * that exists here, and `(current branch)` is what we admit we do not know. Naming it matters: the target
 * is what a stored grant is compared against, and `origin/(current branch)` is covered by nothing a user
 * could have written.
 */
function pushTargetBranch(refspec: string | undefined, sessionBranch: string | undefined): string {
	if (refspec !== undefined) return remoteSideOf(refspec)
	return typeof sessionBranch === "string" ? sessionBranch.trim() : ""
}

/**
 * The directory a `git` invocation reads its repository from, and where its subcommand begins.
 *
 * `git` finds `.git` by walking up from its working directory, so the object a git command reads is decided by
 * `-C` when one was written and otherwise by the directory the leg actually runs in — which, after a `cd`
 * earlier in the same command, is not the project (risk-policy.ts threads that directory in as the leg's cwd,
 * so `h.ctx.cwd` is it). Treating every git command as "the project repository" was the hole: after
 * `cd ~/work/other-repo`, a `git fetch` reads a repository the user never put in scope.
 *
 * The fused spellings count too (`-Cdir`, `--git-dir=dir`): an option carrying its own value still names the
 * repository. An option this set does not know is skipped without its value, which is what the previous scan
 * did, and can only move the subcommand index — never the repository.
 */
const GIT_VALUE_OPTS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix"])
/** …of those, the ones that say WHERE the repository is. */
const GIT_REPO_DIR_OPTS = new Set(["-C", "--git-dir", "--work-tree"])

function gitLayout(argv: string[]): { sub: string | undefined; rest: string[]; repoArg: string | null } {
	let repoArg: string | null = null
	let i = 1
	while (i < argv.length) {
		const word = argv[i]!
		if (!word.startsWith("-")) break
		if (word === "--") {
			i += 1
			break
		}
		const long = word.startsWith("--")
		const equals = word.indexOf("=")
		const name = long ? (equals > 0 ? word.slice(0, equals) : word) : word.slice(0, 2)
		const fused = long ? (equals > 0 ? word.slice(equals + 1) : undefined) : word.length > 2 ? word.slice(2) : undefined
		if (GIT_VALUE_OPTS.has(name)) {
			const value = fused ?? (i + 1 < argv.length ? argv[i + 1] : undefined)
			if (GIT_REPO_DIR_OPTS.has(name) && value !== undefined) repoArg = value
			// A separated value is the next word; when one is missing, nothing after it is a subcommand.
			i += fused === undefined && value !== undefined ? 2 : 1
			continue
		}
		i += 1
	}
	if (i >= argv.length) return { sub: undefined, rest: [], repoArg }
	return { sub: argv[i], rest: argv.slice(i + 1), repoArg }
}

/**
 * The remote a git command asks something of.
 *
 * Usually a NAME (`origin`, `forgejo`) whose URL lives in that repository's config — which is one of the files
 * this read is about, so reading it to get a host would be using the answer to decide whether to allow it.
 * The name as spelled is what the user typed and what a grant can be written against; when the argument is a
 * URL, written out or in scp's `user@host:path` form, the host is known and wins.
 */
function gitRemoteObject(rest: string[]): string {
	if (hasFlag(rest, "--all")) return "all remotes"
	return netHost(rest.find((a) => !a.startsWith("-")) ?? "origin")
}

function gitHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const layout = gitLayout(argv)
	const sub = layout.sub
	if (!sub) return [seg("allow", "read_only", "git", raw)]
	const rest = layout.rest
	// The repository this command reads is the one at its effective directory, so that is the object the
	// user is asked about — `./repo` when it is the project, `~/work/other-repo` when it is not.
	const repo = h.classify(layout.repoArg ?? h.ctx.cwd)
	const repoOutside = !repo.insideProject

	if (sub === "push") {
		const force = hasFlag(rest, "--force", "-f", "--force-with-lease", "--force-if-includes")
		const del = hasFlag(rest, "--delete", "-d") || rest.some((a) => a.startsWith(":"))
		const mirror = hasFlag(rest, "--mirror", "--all", "--tags")
		const pos = rest.filter((a) => !a.startsWith("-"))
		const remote = pos[0] ?? "origin"
		const refspec = pos[1]
		const branch = pushTargetBranch(refspec, h.opts.gitBranch)
		// How the prompt names it: the refspec the user typed, the branch it resolves to, or the admission.
		const shown = refspec ?? (branch ? `(current branch ${branch})` : "(current branch)")
		const named = branch || "(current branch)"
		if ((force || del) && PROTECTED_BRANCH_RE.test(branch)) {
			return [seg("never", "vcs_force_protected", `git push ${force ? "--force " : ""}${del ? "--delete " : ""}to protected branch ${branch} on ${remote}`, raw, [target(`${remote}/${branch}`)])]
		}
		if (mirror && hasFlag(rest, "--mirror")) return [seg("never", "vcs_force_protected", `git push --mirror to ${remote}`, raw, [target(remote)])]
		const kind = force ? "force-push" : del ? "delete remote branch" : "push"
		return [seg("ask", "vcs_remote", `git ${kind} ${shown} to ${remote}`, raw, [target(`${remote}/${named}`), scope(`${remote}/*`)])]
	}
	if (sub === "reset") {
		if (hasFlag(rest, "--hard")) return [seg("ask", "vcs_discard", `git reset --hard ${rest.filter((a) => !a.startsWith("-")).join(" ") || "HEAD"}`, raw, [target("worktree changes")])]
		return [seg("allow", "vcs_local", `git reset (soft/mixed)`, raw)]
	}
	if (sub === "clean") {
		if (hasFlag(rest, "-n", "--dry-run")) return [seg("allow", "read_only", "git clean --dry-run", raw)]
		if (hasFlag(rest, "-f", "--force")) {
			const wide = hasFlag(rest, "-x") || hasFlag(rest, "-d")
			return [seg("ask", "vcs_discard", `git clean -f${wide ? " (incl. dirs/ignored)" : ""} — deletes untracked files`, raw, [target("untracked files")])]
		}
		return [seg("ask", "vcs_discard", "git clean", raw)]
	}
	if (sub === "checkout" || sub === "restore") {
		// `git checkout -- .` / `git restore .` discard worktree changes
		const discardsAll = rest.includes(".") || rest.includes("--") && rest[rest.length - 1] === "." || (sub === "restore" && rest.some((a) => a === "." || a === ":/"))
		if (discardsAll && !hasFlag(rest, "-b", "-B", "--branch")) return [seg("ask", "vcs_discard", `git ${sub} — discards uncommitted changes in worktree`, raw, [target("worktree changes")])]
		return [seg("allow", "vcs_local", `git ${sub}`, raw)]
	}
	if (sub === "stash" && rest[0] && ["drop", "clear"].includes(rest[0])) {
		return [seg("ask", "vcs_discard", `git stash ${rest[0]}`, raw, [target("stash entries")])]
	}
	if (sub === "branch" && hasFlag(rest, "-D")) {
		return [seg("ask", "vcs_discard", `git branch -D ${rest.filter((a) => !a.startsWith("-")).join(" ")}`, raw, targetsOf(["branch", ...rest], h))]
	}
	if (sub === "filter-branch" || sub === "filter-repo" || sub === "replace") {
		return [seg("never", "vcs_history_rewrite", `git ${sub} — history rewrite`, raw)]
	}
	if (sub === "remote" && rest[0] && ["add", "set-url", "remove", "rm", "rename"].includes(rest[0])) {
		return [seg("ask", "vcs_remote", `git remote ${rest[0]} ${rest.slice(1).join(" ")}`, raw, [target(rest[1] ?? "")])]
	}
	if (sub === "config" && !rest.includes("--get") && !hasFlag(rest, "-l", "--list") && rest.some((a) => !a.startsWith("-"))) {
		const global = hasFlag(rest, "--global", "--system")
		if (global) return [seg("ask", "write_sensitive", `git config ${rest.join(" ").slice(0, 80)} (global)`, raw, [target("~/.gitconfig")])]
		return [seg("allow", "vcs_local", "git config (local)", raw)]
	}
	if (GIT_READ.has(sub)) {
		// A repository is a set of FILES: when the repo is inside the project the read is inside the project,
		// and when the command's effective directory is elsewhere it is an outside read. `ls-remote` is not
		// a repository read at all — it asks the remote what it has, so the remote is the object.
		if (sub === "ls-remote") {
			const remote = rest.find((a) => !a.startsWith("-")) ?? "origin"
			return objectRead(raw, remote, `git ls-remote ${remote} — reads the remote repository`)
		}
		// `git config --global --get x` reads ~/.gitconfig, not the repository: the file decides.
		if (sub === "config" && hasFlag(rest, "--global", "-g", "--global-only")) return [h.decideRead(h.classify("~/.gitconfig"), "git config --global")]
		if (sub === "config" && hasFlag(rest, "--system")) return [h.decideRead(h.classify("/etc/gitconfig"), "git config --system")]
		if (repoOutside) return [h.decideRead(repo, `git ${sub}`)]
		return infoRow(raw, `git ${sub} (the project repository)`)
	}
	if (GIT_LOCAL_WRITE.has(sub)) {
		// clone/fetch/pull touch the network but only mutate locally — allow (spec §2.1). In a repository that
		// is not the project's, `fetch`/`pull` are two reads first: the repository's objects and whatever
		// the remote answers. Every other entry keeps the category it has always had.
		if (repoOutside && GIT_REMOTE_READ.has(sub)) {
			const remote = gitRemoteObject(rest)
			return [h.decideRead(repo, `git ${sub}`), ...objectRead(raw, remote, `git ${sub} — reads the remote ${remote} of the repository at ${h.display(repo)}`)]
		}
		return [seg("allow", "vcs_local", `git ${sub}`, raw)]
	}
	return [seg("unknown", "unknown_command", `git ${sub} ${rest.join(" ").slice(0, 120)}`, raw)]
}

const GH_READ_RE = /^(list|view|status|diff|checks|download|search|api)$/
function ghHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const [_, grp, act] = argv
	// Every `gh` read is a read of the forge, and the forge is the object a user can name. `GH_HOST` is how
	// a Server/Enterprise install is spelled, so the host is read from the environment the leg actually runs
	// in — and `glab`/`hub` default to a different forge than `gh` does.
	const forge = forgeHost(base(argv[0] ?? ""), h)
	if (grp === "api") {
		const method = (flagValue(argv, "-X", "--method") ?? "GET").toUpperCase()
		if (method === "GET") return objectRead(raw, forge, `gh api GET — reads the forge API at ${forge}`)
		return [seg("ask", "network_send", `gh api ${method} ${positionals(argv.slice(1))[0] ?? ""}`, raw, targetsOf(argv.slice(1), h))]
	}
	if (grp && act && GH_READ_RE.test(act)) return objectRead(raw, forge, `gh ${grp} ${act} — reads the forge at ${forge}`)
	if (grp === "auth" && act === "status") return objectRead(raw, forge, `gh auth status — reads the forge credentials at ${forge}`)
	if (grp === "repo" && act === "clone") return [seg("allow", "vcs_local", "gh repo clone", raw)]
	if (grp && ["pr", "issue", "release", "repo", "gist", "workflow", "run", "label", "secret", "variable", "auth"].includes(grp)) {
		return [seg("ask", "vcs_remote", `gh ${grp} ${act ?? ""} — writes to the forge`, raw, [target(`${grp} ${act ?? ""}`.trim())])]
	}
	return [seg("unknown", "unknown_command", `gh ${argv.slice(1).join(" ").slice(0, 120)}`, raw)]
}

const GH_DEFAULT_HOST: Record<string, string> = { gh: "github.com", glab: "gitlab.com", hub: "github.com" }
const GH_HOST_ENV: Record<string, string> = { gh: "GH_HOST", glab: "GLAB_HOST", hub: "GH_HOST" }

/** Which forge a forge CLI talks to — its own env override, else the vendor's default. */
function forgeHost(client: string, h: HandlerContext): string {
	const fromEnv = h.opts.env?.[GH_HOST_ENV[client] ?? "GH_HOST"]?.trim()
	if (fromEnv) return fromEnv.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/\/.*$/, "")
	return GH_DEFAULT_HOST[client] ?? "github.com"
}

// ---------------------------------------------------------------- artifact publishes

/**
 * The repository part of an artifact ref — everything up to the tag or digest.
 *
 * A tag is one artifact; the repository is the thing a user means by "that image". It is the widest scope
 * this can state: the registry, the namespace and the name all stay in the value, so a scope answer widens
 * over tags of one repo and never over a second repo. A `:` before the last `/` is the registry's port, not
 * a tag separator, which is why the search starts after it.
 */
function artifactRepoOf(ref: string): string {
	const at = ref.indexOf("@")
	const noDigest = at >= 0 ? ref.slice(0, at) : ref
	const slash = noDigest.lastIndexOf("/")
	const colon = noDigest.indexOf(":", slash + 1)
	return colon >= 0 ? noDigest.slice(0, colon) : noDigest
}

/**
 * One publish, as one row: bytes leaving this machine for a registry.
 *
 * A push does not change a container or an image — it reads the artifact and uploads it. Naming it the
 * compound `container_mutation+network_send` asked the model to agree that publishing is container
 * work, and the measured models did not: they answered `network_send` for an upload and were over-blocked
 * because the pending row also demanded the container half. The effect it really is, is `network_send`:
 * on the image ref, which the image-ref grammar already reads, so one
 * `network_send myrepo/app` row covers `docker push myrepo/app:1.0` with no bridge.
 *
 * Tier unchanged (`ask`); the entities are unchanged; only the name of the effect moved.
 */
function artifactPushRows(raw: string, label: string, ref: string): SegmentDecision[] {
	if (!ref) return [seg("ask", "network_send", `${label} — no artifact ref given`, raw)]
	return [seg("ask", "network_send", `${label} ${ref} — uploads this artifact to a registry`, raw, [target(ref), scope(artifactRepoOf(ref))])]
}

// ---------------------------------------------------------------- docker & compose

const DOCKER_READ = new Set(["ps", "images", "logs", "inspect", "stats", "top", "port", "diff", "history", "version", "info", "events", "search", "manifest", "context"])
/**
 * `docker inspect` is a credential read, not a status read.
 *
 * What `inspect` prints is the container's whole configuration, and that configuration contains its
 * environment — the same bytes `printenv` prints, one layer removed. Naming it `read_system_state` would let
 * "go find out why the container restarts" read the tokens out of the container config, so it keeps the secret
 * gate whatever else a troubleshooting grant covers.
 */
function dockerReadRows(argv: string[], h: HandlerContext, sub: string, client: string, raw: string): SegmentDecision[] {
	const machine = daemonMachine(argv, h)
	if (sub === "inspect") {
		return [seg("ask", "read_secret", `${client} ${sub} — reads a container's configuration, its environment included`, raw, [target(machine)])]
	}
	if (sub === "search") {
		// A registry query, not this machine's state: somebody else's index is the object.
		return objectRead(raw, machine === LOCAL_MACHINE_OBJECT ? "the image registry" : machine, `${client} ${sub} — searches a registry`)
	}
	return statusRead(raw, machine, `${client} ${sub} — reads container state on ${machine === LOCAL_MACHINE_OBJECT ? "this machine" : machine}`)
}

function dockerHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const client = base(argv[0]!)
	let i = 1
	while (i < argv.length && argv[i]!.startsWith("-")) { const f = argv[i]!; i++; if (["-H", "--host", "-c", "--context", "--config", "-l", "--log-level"].includes(f)) i++ }
	const sub = argv[i]
	if (!sub) return statusRead(raw, daemonMachine(argv, h), `${client} — reads the ${client} daemon`)
	const rest = argv.slice(i + 1)
	if (sub === "compose") return dockerComposeHandler(argv, h, i)
	// `docker ps|images|inspect|logs|system df` are reads that must ask: they report what is running on
	// someone else's machine, and the container runtime is the object a user can name. `version` stays free —
	// that is the tool describing itself, which is the only free non-file read besides shell state.
	if (sub === "version") return infoRow(raw, `${client} version (the tool's own version)`)
	if (DOCKER_READ.has(sub)) return dockerReadRows(argv, h, sub, client, raw)
	if (sub === "build" || sub === "buildx") return [seg("allow", "run_project_code", `docker ${sub}`, raw)]
	// A pull reads somebody else's registry (and puts an image in the local store); the registry is the object.
	if (sub === "pull") return objectRead(raw, registryOf(positionals([sub, ...rest])[1] ?? "", client), `${client} pull — downloads an image from a registry`)
	// `positionals` skips the program word, and `rest` starts *after* the subcommand — so the subcommand is
	// put back in front of it rather than re-implementing the flag/`--` rules a second time.
	if (sub === "push") return artifactPushRows(raw, `${base(argv[0]!)} push`, positionals([sub, ...rest])[0] ?? "")
	if (sub === "system" && rest[0] === "prune") {
		if (hasFlag(rest, "-a", "--all") && hasFlag(rest, "--volumes")) return [seg("never", "container_wipe", "docker system prune -a --volumes — deletes ALL images and volumes", raw)]
		return [seg("ask", "container_mutation", `docker system prune${hasFlag(rest, "-a", "--all") ? " -a" : ""}`, raw, [target("unused docker data")])]
	}
	if (sub === "volume" && rest[0] === "prune") return [seg("never", "container_wipe", "docker volume prune — deletes ALL unused volumes (data loss)", raw)]
	if ((sub === "volume" || sub === "network" || sub === "container" || sub === "image") && rest[0] && ["rm", "remove", "prune"].includes(rest[0])) {
		const names = rest.slice(1).filter((a) => !a.startsWith("-"))
		return [seg("ask", "container_mutation", `docker ${sub} ${rest[0]} ${names.join(" ")}`, raw, names.map(target))]
	}
	if (sub === "rm" || sub === "rmi") {
		const names = rest.filter((a) => !a.startsWith("-"))
		return [seg("ask", "container_mutation", `docker ${sub}${hasFlag(rest, "-f", "--force") ? " -f" : ""} ${names.join(" ")}`, raw, names.map(target))]
	}
	if (sub === "stop" || sub === "restart" || sub === "kill" || sub === "pause" || sub === "unpause") {
		const names = rest.filter((a) => !a.startsWith("-"))
		return [seg("ask", "process_control", `docker ${sub} ${names.join(" ")}`, raw, names.map(target)) ]
	}
	if (sub === "run" || sub === "create") {
		const privileged = hasFlag(rest, "--privileged") || rest.some((a) => a.startsWith("--cap-add")) || rest.some((a) => a === "--pid=host" || a === "--network=host" && hasFlag(rest, "-v"))
		const mounts = rest.filter((a, idx) => (rest[idx - 1] === "-v" || rest[idx - 1] === "--volume" || rest[idx - 1] === "--mount") || a.startsWith("-v=") || a.startsWith("--volume="))
		const badMount = mounts.some((m) => {
			const hostPath = m.replace(/^(-v=|--volume=)/, "").split(":")[0] ?? ""
			if (!hostPath.startsWith("/") && !hostPath.startsWith("~") && !hostPath.startsWith("$")) return false
			const pc = h.classify(hostPath)
			return !pc.insideProject
		})
		const ports = hasFlag(rest, "-p", "--publish") || rest.some((a) => a.startsWith("-p") && /\d/.test(a))
		if (privileged) return [seg("ask", "container_privileged", `docker ${sub} --privileged/host-namespace`, raw, [target("privileged container")])]
		if (badMount) return [seg("ask", "container_mutation", `docker ${sub} with host mount outside project`, raw, mounts.map(target))]
		if (ports) return [seg("ask", "network_listen", `docker ${sub} publishing ports`, raw, mounts.map(target))]
		return [seg("allow", "run_project_code", `docker ${sub} (project-scoped)`, raw)]
	}
	if (sub === "exec" || sub === "cp" || sub === "commit" || sub === "save" || sub === "load" || sub === "import" || sub === "export" || sub === "tag" || sub === "start" || sub === "wait" || sub === "attach" || sub === "update" || sub === "rename") {
		if (sub === "exec") return [seg("allow", "run_project_code", `docker exec (existing container)`, raw)]
		return [seg("allow", "run_project_code", `docker ${sub}`, raw)]
	}
	if (sub === "login") return [seg("ask", "network_send", "docker login", raw)]
	return [seg("unknown", "unknown_command", `docker ${sub}`, raw)]
}

/**
 * `oras` — the OCI registry CLI (artifacts that are not container images).
 *
 * Only `push` is named here: it is the publish, and it gets the same two rows every other artifact push
 * gets. Everything else stays `unknown_command` exactly as it was while `oras` had no case at all — this
 * handler exists to name a target, not to authorise a grammar it has not been measured against.
 */
function orasHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	if (pos[0] === "push") return artifactPushRows(raw, "oras push", pos[1] ?? "")
	return [seg("unknown", "unknown_command", `oras ${pos[0] ?? ""}`.trim(), raw)]
}

function dockerComposeHandler(argv: string[], h: HandlerContext, i: number): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const args = argv[i] === "compose" ? argv.slice(i + 1) : argv.slice(1)
	let j = 0
	while (j < args.length && args[j]!.startsWith("-")) { const f = args[j]!; j++; if (["-f", "--file", "-p", "--project-name", "--profile", "--env-file"].includes(f)) j++ }
	const sub = args[j]
	if (!sub) return statusRead(raw, daemonMachine(argv, h), "docker compose — reads the compose services on the daemon")
	// A compose read asks the same daemon `docker ps` asks (`docker compose ps|logs` are reads of it), and
	// it is a status read of the machine that daemon runs on.
	if (["config", "ps", "logs", "top", "events", "images", "ls", "port"].includes(sub)) {
		const machine = daemonMachine(argv, h)
		return statusRead(raw, machine, `docker compose ${sub} — reads the compose services on ${machine === LOCAL_MACHINE_OBJECT ? "this machine" : machine}`)
	}
	if (sub === "version") return infoRow(raw, "docker compose version (the tool's own version)")
	if (["build", "pull", "create", "up", "start", "run", "exec", "watch", "cp"].includes(sub)) {
		// `up` starts services which may publish ports; compose files are project config → treat as project-scoped run
		return [seg("allow", "run_project_code", `docker compose ${sub}`, raw)]
	}
	if (sub === "down") {
		if (hasFlag(args.slice(j), "-v", "--volumes")) return [seg("ask", "container_mutation", "docker compose down -v — deletes volumes (data loss)", raw, [target("compose volumes")])]
		return [seg("allow", "run_project_code", "docker compose down", raw)]
	}
	if (["stop", "restart", "kill", "pause", "unpause", "rm"].includes(sub)) return [seg("allow", "run_project_code", `docker compose ${sub}`, raw)]
	return [seg("unknown", "unknown_command", `docker compose ${sub}`, raw)]
}

// ---------------------------------------------------------------- kubernetes & cloud

const KUBECTL_VALUE_FLAGS = ["-n", "--namespace", "-f", "--filename", "-o", "--output", "-l", "--selector", "-c", "--container", "--context", "--kubeconfig", "--field-selector", "--sort-by", "--template", "--from-file", "--from-literal", "--image", "--port", "--replicas", "--type", "-p", "--patch", "--timeout", "--grace-period"]
function stripValueFlags(argv: string[], valueFlags: string[]): string[] {
	const out: string[] = []
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!
		if (valueFlags.includes(a)) { i++; continue }
		if (valueFlags.some((f) => a.startsWith(f + "="))) continue
		out.push(a)
	}
	return out
}

const KUBECTL_READ = new Set(["get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version", "cluster-info", "config", "auth", "diff", "events", "wait", "proxy"])
function kubectlHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(stripValueFlags(argv, KUBECTL_VALUE_FLAGS))
	const sub = pos[0]
	if (!sub) return [seg("allow", "read_only", "kubectl", raw)]
	const ns = flagValue(argv, "-n", "--namespace") ?? (hasFlag(argv, "-A", "--all-namespaces") ? "ALL" : "default")
	if (KUBECTL_READ.has(sub)) {
		if (sub === "config" && pos[1] && !["view", "get-contexts", "current-context", "get-clusters", "get-users"].includes(pos[1])) {
			return [seg("ask", "cluster_mutation", `kubectl config ${pos[1]}`, raw, [target(pos[2] ?? pos[1])])]
		}
		// `kubectl version`/`explain` are the tool's own report; everything else in this set reads a cluster
		// (`get`/`describe`/`logs`), and the object is the CLUSTER the call is addressed to — its
		// `--context` when it names one, because that is the word a user would use to grant it.
		if (sub === "version") return infoRow(raw, `${base(argv[0]!)} version (the tool's own version)`)
		// A cluster read is a status read whose OBJECT is the cluster — `--context`
		// when the command names one, else the kubeconfig's current context — so a grant that already lets the
		// agent change something in that cluster still covers looking at it.
		return statusRead(raw, clusterReadObject(argv, base(argv[0]!), h), `${base(argv[0]!)} ${sub} — reads the cluster${sub === "config" ? " configuration" : ""} (ns ${ns})`)
	}
	if (sub === "delete") {
		const wide = hasFlag(argv, "--all", "-A", "--all-namespaces")
		const kind = pos[1] ?? ""
		if (wide || /^(namespace|ns|node|nodes|crd|customresourcedefinition)/.test(kind)) {
			return [seg("never", "cluster_wide_destroy", `kubectl delete ${kind}${wide ? " --all" : ""} (ns ${ns})`, raw, [target(`${kind}@${ns}`)])]
		}
		const names = pos.slice(2)
		return [seg("ask", "cluster_mutation", `kubectl delete ${kind} ${names.join(" ")} -n ${ns}`, raw, [...names.map((n) => target(`${kind}/${n}@${ns}`)), scope(`${kind}@${ns}`)])]
	}
	if (sub === "drain" || sub === "cordon" || sub === "uncordon" || sub === "taint") {
		if (hasFlag(argv, "--dry-run")) return dryRunRows(argv, base(argv[0]!), raw, `${base(argv[0]!)} ${sub} --dry-run`)
		return [seg("never", "cluster_wide_destroy", `kubectl ${sub} ${pos[1] ?? ""} — node-level operation`, raw, [target(pos[1] ?? "node")])]
	}
	if (["apply", "create", "patch", "replace", "edit", "scale", "rollout", "label", "annotate", "set", "expose", "autoscale", "cp"].includes(sub)) {
		if (hasFlag(argv, "--dry-run")) return dryRunRows(argv, base(argv[0]!), raw, `${base(argv[0]!)} ${sub} --dry-run`)
		return [seg("ask", "cluster_mutation", `kubectl ${sub} ${pos.slice(1, 4).join(" ")} -n ${ns}`, raw, [target(`${pos.slice(1, 3).join("/") || sub}@${ns}`), scope(`${ns}`)])]
	}
	if (sub === "exec" || sub === "attach" || sub === "debug") {
		return [seg("ask", "cluster_mutation", `kubectl ${sub} into ${pos[1] ?? "pod"} -n ${ns}`, raw, [target(`${pos[1] ?? "pod"}@${ns}`), scope(ns)])]
	}
	if (sub === "port-forward") return [seg("ask", "network_listen", `kubectl port-forward ${pos[1] ?? ""}`, raw, [target(pos[1] ?? "")])]
	if (sub === "run") return [seg("ask", "cluster_mutation", `kubectl run ${pos[1] ?? ""} -n ${ns}`, raw, [target(`${pos[1]}@${ns}`)])]
	return [seg("unknown", "unknown_command", `kubectl ${sub}`, raw)]
}

function helmHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(stripValueFlags(argv, KUBECTL_VALUE_FLAGS))
	const sub = pos[0]
	if (!sub || ["list", "ls", "status", "get", "show", "search", "repo", "template", "lint", "version", "env", "history", "inspect", "dependency", "verify"].includes(sub)) {
	if (sub === "repo" && pos[1] && ["add", "remove", "update"].includes(pos[1])) {
		// `helm repo add/update` downloads an index from somebody else's chart repository (a registry read)
		// and rewrites the local repository file outside the project. The repository is the object.
		const repo = pos.slice(2).find((p) => !p.startsWith("-")) ?? "the chart repository"
		return objectRead(raw, repo, `helm repo ${pos[1]} — reads the chart repository ${repo}`)
	}
		if (sub === "version" || sub === "env" || !sub) return infoRow(raw, `helm ${sub ?? ""} (the tool's own version/environment)`)
		// Every other verb here reads a cluster or a chart repository (`helm list|status`).
		return objectRead(raw, clusterObject(argv, "helm"), `helm ${sub} — reads the cluster charts and releases`)
	}
	const ns = flagValue(argv, "-n", "--namespace") ?? "default"
	if (sub === "push") {
		// `helm push <chart> <oci://…>` publishes a chart into an OCI registry — the same act as `docker push`,
		// and it is the destination (not the chart file) a grant has to name. The scheme is transport only.
		const dest = (pos[2] ?? "").replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
		return artifactPushRows(raw, "helm push", dest)
	}
	if (sub === "uninstall" || sub === "delete") {
		const releases = pos.slice(1)
		if (releases.length === 0) return [seg("never", "cluster_wide_destroy", "helm uninstall with no release named", raw)]
		return [seg("ask", "cluster_mutation", `helm uninstall ${releases.join(" ")} -n ${ns}`, raw, releases.map((r) => target(`${r}@${ns}`)))]
	}
	if (["install", "upgrade", "rollback", "test"].includes(sub)) {
		if (hasFlag(argv, "--dry-run")) return dryRunRows(argv, "helm", raw, `helm ${sub} --dry-run`)
		return [seg("ask", "cluster_mutation", `helm ${sub} ${pos.slice(1, 3).join(" ")} -n ${ns}`, raw, [target(`${pos[1] ?? sub}@${ns}`), scope(ns)])]
	}
	return [seg("unknown", "unknown_command", `helm ${sub}`, raw)]
}

function terraformHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const client = base(argv[0]!)
	const sub = positionals(argv)[0]
	if (!sub || ["plan", "show", "validate", "fmt", "init", "output", "state", "graph", "providers", "version", "workspace", "console", "get", "refresh", "test"].includes(sub)) {
		if (sub === "state" && positionals(argv)[1] && ["rm", "mv", "push", "replace-provider"].includes(positionals(argv)[1]!)) {
			return [seg("ask", "cluster_mutation", `terraform state ${positionals(argv)[1]}`, raw)]
		}
		// `plan`/`show`/`output`/`state` read the STATE, which lives on a backend outside this project. The object
		// is the tool's own deployment name: a terraform working directory is
		// not addressable from a sentence, the stack it manages is.
		if (sub === "version" || sub === "fmt" || sub === "validate" || !sub) return infoRow(raw, `terraform ${sub ?? ""} (the tool's own version / local files only)`)
		return objectRead(raw, client, `terraform ${sub} — reads the managed stack and its state`)
	}
	if (sub === "destroy") return [seg("never", "cluster_wide_destroy", "terraform destroy — destroys managed infrastructure", raw)]
	if (sub === "apply") {
		if (hasFlag(argv, "-destroy")) return [seg("never", "cluster_wide_destroy", "terraform apply -destroy", raw)]
		return [seg("ask", "cluster_mutation", "terraform apply", raw, [target("terraform-managed resources")])]
	}
	if (sub === "import" || sub === "taint" || sub === "untaint") return [seg("ask", "cluster_mutation", `terraform ${sub}`, raw)]
	return [seg("unknown", "unknown_command", `terraform ${sub}`, raw)]
}

const AWS_READ_RE = /^(describe|list|get|ls|head|search|lookup|query|scan|select|preview|check|validate|estimate|test|wait|help)/

/**
 * Object-storage URIs come from `target-grammar.ts` (`isObjectStoreUri`), the module every matcher already
 * asks about a target's space — one definition, so layer 0 and the matcher cannot disagree about what a URI is.
 * What a verb does to one of these is a change to DATA in a store, whichever CLI typed it, so the effect name
 * follows the URI rather than the tool (spec §2.8).
 */
function objectUris(args: string[]): string[] {
	return args.filter((a) => isObjectStoreUri(a))
}

/** The store + prefix a URI names, i.e. the widest thing a "yes" about it can honestly mean: a URI that
 *  already ends at a prefix covers that prefix; one naming a single object scopes to its parent prefix.
 *  A URI that names the store itself (`gs://bucket`) scopes to nothing wider — there is no wider prefix. */
function bucketScopeOf(uri: string): string {
	if (uri.endsWith("/")) return uri
	const cut = uri.lastIndexOf("/")
	return cut > uri.indexOf("//") + 1 ? uri.slice(0, cut + 1) : uri
}

/** `s3://bucket/key` out of the `s3api` flags, which are where an s3api call names its object. */
function s3UriFromFlags(argv: string[]): string | undefined {
	const bucket = flagValue(argv, "--bucket")
	if (!bucket) return undefined
	const key = flagValue(argv, "--key")
	return key ? `s3://${bucket}/${key}` : `s3://${bucket}`
}

/**
 * The whole-thing-gone operations, each with the effect word for its own destruction.
 *
 * These rows are tier `never`, so no grant can ever reach them and the category changes nothing about the
 * verdict — but the category is what the model is shown and what a denial is explained by, and one label for
 * eight different destructions taught the models that "destroy" is a cloud word. Deleting a database is
 * `db_destroy` (a whole database gone), issuing or revoking standing cloud credentials is
 * `privilege_persist` (standing elevated rights), and only the values that wipe a whole managed store or a
 * whole deployment keep `cluster_wide_destroy`. `cat` is omitted where the wide-destroy name is the right one.
 */
const AWS_NEVER: Array<{ svc: string; re: RegExp; why: string; cat?: string }> = [
	{ svc: "s3", re: /^rb\b/, why: "remove bucket" },
	{ svc: "s3api", re: /^delete-bucket\b/, why: "remove bucket" },
	{ svc: "ec2", re: /^terminate-instances\b/, why: "terminate instances" },
	{ svc: "rds", re: /^delete-db/, why: "delete database", cat: "db_destroy" },
	{ svc: "dynamodb", re: /^delete-table\b/, why: "delete table", cat: "db_destroy" },
	{ svc: "cloudformation", re: /^delete-stack\b/, why: "delete stack" },
	{ svc: "iam", re: /^(delete|create)-(user|access-key|role)|attach-.*policy/, why: "IAM mutation", cat: "privilege_persist" },
	{ svc: "kms", re: /^schedule-key-deletion\b/, why: "delete KMS key" },
]
function awsHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const svc = pos[0] ?? ""
	const op = pos[1] ?? ""
	if (!svc) return objectRead(raw, "aws", "aws — reads the account it is configured for")
	if (svc === "s3") {
		// `aws s3 ls` / `download` are reads. The object is the URI when the command names one (that is what a
		// user grants: "you may read that bucket"), and the service when it does not.
		if (["ls", "presign"].includes(op)) {
			const uri = pos.slice(2).find((p) => isObjectStoreUri(p)) ?? "aws s3"
			return objectRead(raw, uri, `aws s3 ${op} — reads ${uri}`)
		}
		if (op === "cp" || op === "sync" || op === "mv") {
			const rest = pos.slice(2)
			const remoteDest = rest.find((a) => a.startsWith("s3://")) && rest[rest.length - 1]?.startsWith("s3://")
			const localSrc = rest.find((a) => !a.startsWith("s3://"))
			if (remoteDest && localSrc) {
				const pc = h.classify(localSrc)
				if (pc.isSecret || pc.isNeverWipe) return [seg("never", "exfiltration", `upload ${h.display(pc)} to ${rest[rest.length - 1]}`, raw, [target(rest[rest.length - 1]!)])]
				return [seg("ask", "network_send", `aws s3 ${op} to ${rest[rest.length - 1]}`, raw, [target(rest[rest.length - 1]!)])]
			}
			// download: a read of the remote object, and the write it performs locally is decided by the
			// `outFile`-shaped rule below in the caller — here the question is only whether the store may be read.
			const srcUri = rest.find((a) => isObjectStoreUri(a)) ?? "aws s3"
			return objectRead(raw, srcUri, `aws s3 ${op} — downloads ${srcUri}`)
		}
		if (op === "rm") {
			const uri = pos[2] ?? ""
			const recursive = hasFlag(argv, "--recursive")
			if (recursive && /^s3:\/\/[^/]+\/?$/.test(uri)) return [seg("never", "cluster_wide_destroy", `aws s3 rm --recursive on whole bucket ${uri}`, raw, [target(uri)])]
			// Objects inside a bucket are DATA: removing them is delete_data whatever CLI spells it (spec §2.8),
			// the same word `rm` of a local data file uses. `cluster_mutation` is for cluster resources — a
			// bucket object is not one, and the models measured on that question all said delete_data here.
			return [seg("ask", "delete_data", `aws s3 rm${recursive ? " --recursive" : ""} ${uri}`, raw, [target(uri), scope(uri.replace(/[^/]+$/, ""))])]
		}
		if (op === "rb") return [seg("never", "cluster_wide_destroy", `aws s3 rb ${pos[2] ?? ""}`, raw, [target(pos[2] ?? "")])]
	}
	if (svc === "s3api") {
		// The same two effects as `s3 rm` / `s3 cp`, spelled as flags: removing objects is delete_data, sending
		// an object to a store is network_send. Tiers unchanged (both were the fallback's `ask`).
		const uri = s3UriFromFlags(argv)
		const ents = uri ? [target(uri), scope(bucketScopeOf(uri))] : targetsOf(argv.slice(2), h)
		if (/^delete-objects?$/.test(op)) return [seg("ask", "delete_data", `aws s3api ${op} ${uri ?? ""}`.trim(), raw, ents)]
		if (/^(put-object|upload-file|copy-object|upload-part-copy)$/.test(op)) return [seg("ask", "network_send", `aws s3api ${op} ${uri ?? ""}`.trim(), raw, ents)]
	}
	for (const n of AWS_NEVER) if (svc === n.svc && n.re.test(op)) return [seg("never", n.cat ?? "cluster_wide_destroy", `aws ${svc} ${op} — ${n.why}`, raw, targetsOf(argv.slice(2), h))]
	if (AWS_READ_RE.test(op)) {
		// A read of a cloud API is a read of that service in that account (`aws s3 ls` is a read, and the same
		// reasoning covers describe/get/list). Object = the service, or the object the call names.
		const uri = pos.slice(2).find((p) => isObjectStoreUri(p))
		return objectRead(raw, uri ?? `aws ${svc}`, `aws ${svc} ${op} — reads ${uri ?? `the ${svc} service`}`)
	}
	return [seg("ask", "cluster_mutation", `aws ${svc} ${op}`, raw, [target(`${svc}:${op}`), scope(svc)])]
}

const CLOUD_READ_RE = /^(list|describe|get|show|info|status|whoami|config|regions|zones|versions?|logs?|ls|cat|env|open|releases|domains|projects?|apps?|ps)$/

/**
 * The storage-CLI branches, decided by which end of the transfer the bucket URI sits at.
 *
 * `gsutil` / `az storage` / `aws s3api` are not cluster tools: `rm` of a prefix removes objects (data) and
 * `cp` of a local file into a store sends bytes out (a send). Before this, every verb on those CLIs was
 * `cluster_mutation`, which is the category for cluster RESOURCES — and the measured models all answered
 * the bucket verbs with the effect words instead, which is what the over-blocks were made of.
 * Whole-store removals keep the wide-destroy `never` rules below and in `AWS_NEVER`; nothing here changes a
 * tier, only which effect is named.
 */
const OBJ_DELETE_RE = /^(rm|remove|delete|del|delete-object|delete-objects|delete-blob|purge)$/
const OBJ_UPLOAD_RE = /^(cp|copy|sync|upload|upload-blob|upload-file|rsync)$/

/**
 * Does this URI name something INSIDE a store, rather than the store itself?
 * `gs://bucket/prefix` and `s3://bucket/key` put the store in the authority, so anything after it is a key.
 * The URL forms (`https://<account>.blob.core.windows.net/<container>/<blob>`, the GCS download URL) put the
 * account in the authority and the CONTAINER in the first path segment, so a store is named one level later.
 */
function uriNamesAnObject(uri: string): boolean {
	const rest = uri.slice(uri.indexOf("//") + 2)
	const segments = rest.split("/").filter((s) => s.length > 0)
	const storeLevel = /^https?:\/\//i.test(uri) ? 2 : 1
	return segments.length > storeLevel
}

function objectStorageRows(pos: string[], v: string, raw: string): SegmentDecision[] | undefined {
	// Only URIs that name an object or a prefix inside a store. A URI naming the store itself (`gs://bucket`,
	// a container URL) is a piece of provisioned infrastructure, not data in one, and stays with the generic
	// branch — creating or removing a store is not the same effect as removing what is in it.
	const uris = objectUris(pos).filter(uriNamesAnObject)
	if (uris.length === 0) return undefined
	const last = pos[pos.length - 1] ?? ""
	const verbs = pos.filter((p) => !isObjectStoreUri(p))
	if (verbs.some((p) => OBJ_DELETE_RE.test(p))) {
		const ents = uris.flatMap((u) => [target(u), scope(bucketScopeOf(u))])
		return [seg("ask", "delete_data", `${v} ${verbs.join(" ")} — removes objects in ${uris[0]}`, raw, ents)]
	}
	// The destination is the LAST argument (the storage CLIs follow `cp src dst`); a URI there means bytes are
	// leaving this machine. A URI only on the source side is a fetch into a local path — that stays what the
	// generic branch below says, because naming it a local write would change which grants reach it.
	if (isObjectStoreUri(last) && verbs.some((p) => OBJ_UPLOAD_RE.test(p))) {
		return [seg("ask", "network_send", `${v} ${verbs.join(" ")} — uploads to ${last}`, raw, [target(last), scope(bucketScopeOf(last))])]
	}
	return undefined
}

function cloudHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const joined = pos.slice(0, 3).join(" ")
	const storage = objectStorageRows(pos, v, raw)
	if (storage) return storage
	if (pos.some((p) => CLOUD_READ_RE.test(p)) && !pos.some((p) => /^(delete|destroy|rm|remove|create|deploy|set|update|scale|restart|stop)$/.test(p))) {
		// Same ruling as docker/kubectl/aws: reading a cloud account is a read of an object outside the project,
		// and the object is the CLI's account surface — the thing a user can name in one word.
		return objectRead(raw, v, `${v} ${joined} — reads the ${v} account/project`)
	}
	if (pos.some((p) => /^(delete|destroy|rm|remove)$/.test(p))) {
		if (v === "gcloud" && pos.includes("projects") || v === "az" && pos.includes("group")) {
			return [seg("never", "cluster_wide_destroy", `${v} ${joined} — deletes a whole project/resource-group`, raw, targetsOf(argv, h))]
		}
		return [seg("ask", "cluster_mutation", `${v} ${joined}`, raw, targetsOf(argv, h))]
	}
	return [seg("ask", "cluster_mutation", `${v} ${joined}`, raw, targetsOf(argv, h))]
}

// ---------------------------------------------------------------- packages

function sysPkgHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	const pkgs = pos.slice(1)
	const READ = /^(search|show|info|list|ls|depends|rdepends|policy|download|changelog|files|provides|leaves|outdated|doctor|--version|cache)$/
	if (READ.test(sub)) {
		// A package query asks the SYSTEM database and, for search/show/download, a remote mirror. The
		// object is the package manager the user would name (`apt`, `brew`), not its cache paths.
		return objectRead(raw, v, `${v} ${sub} — reads the system package database${sub === "search" || sub === "download" ? " and its remote mirror" : ""}`)
	}
	if (/^(install|add|reinstall)$/.test(sub)) {
		return [seg("ask", "package_system", `install system package(s): ${pkgs.join(" ") || "(unnamed)"} via ${v}`, raw, pkgs.map(target))]
	}
	if (/^(remove|purge|uninstall|rm|erase|del|autoremove)$/.test(sub)) {
		if (pkgs.some((p) => /^(\*|bash|coreutils|systemd|glibc|kernel|linux-image)/.test(p)) || sub === "autoremove" && hasFlag(argv, "--purge")) {
			return [seg("never", "system_destroy", `${v} ${sub} of base packages`, raw, pkgs.map(target))]
		}
		return [seg("ask", "package_system", `remove system package(s): ${pkgs.join(" ")}`, raw, pkgs.map(target))]
	}
	if (/^(update|upgrade|dist-upgrade|full-upgrade|refresh|sync)$/.test(sub)) {
		return [seg("ask", "package_system", `${v} ${sub} — system-wide package update`, raw, [target(`${v} ${sub}`)])]
	}
	return [seg("ask", "package_system", `${v} ${sub}`, raw, pkgs.map(target))]
}

const NPM_SCRIPT_SAFE_RE = /^(test|build|lint|check|typecheck|tsc|verify|coverage|unit|ci|format|fmt|dev|start|preview|serve|watch|compile|storybook|docs|clean|prepare|postinstall|e2e|test:.*|lint:.*|build:.*|check:.*|dev:.*|start:.*)$/
function npmHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	if (["publish", "unpublish", "deprecate", "owner", "access", "token", "login", "adduser", "logout"].includes(sub)) {
		return [seg("ask", "network_send", `${v} ${sub} — registry write`, raw, [target(`${v} ${sub}`)])]
	}
	if (["install", "i", "ci", "add", "update", "upgrade", "remove", "uninstall", "rm", "link", "dedupe", "prune", "rebuild", "audit"].includes(sub) || (v === "yarn" && sub === "")) {
		if (hasFlag(argv, "-g", "--global")) return [seg("ask", "package_system", `${v} global install: ${pos.slice(1).join(" ")}`, raw, pos.slice(1).map(target))]
		return [seg("allow", "run_project_code", `${v} ${sub || "install"} (project)`, raw)]
	}
	if (sub === "run" || sub === "run-script") {
		const script = pos[1] ?? ""
		const body = readPackageScript(h.ctx.project, script, h.opts.fs)
		if (body) {
			const inner = h.evaluateBash(body, { cwd: h.ctx.project })
			if (inner.tier === "allow" || inner.tier === "unknown") {
				// unknown script bodies are still project-declared; treat as project code unless a risky tier fired
				return [seg("allow", "run_project_code", `${v} run ${script}`, raw)]
			}
			return [seg(inner.tier, inner.category, `${v} run ${script} → ${inner.description}`, raw, inner.entities)]
		}
		if (NPM_SCRIPT_SAFE_RE.test(script)) return [seg("allow", "run_project_code", `${v} run ${script}`, raw)]
		return [seg("allow", "run_project_code", `${v} run ${script} (script body not readable)`, raw)]
	}
	if (["test", "t", "start", "dev", "build", "lint", "fmt", "format", "check", "typecheck", "pack", "why", "info", "view", "ls", "list", "outdated", "config", "cache", "exec", "create", "init", "version", "docs", "repo", "help", "x"].includes(sub)) {
		if (sub === "exec" || sub === "x" || sub === "create") return npxHandler(["npx", ...pos.slice(1)], h, v)
		if (sub === "config" && pos[1] === "set") return [seg("ask", "write_sensitive", `${v} config set (may touch ~/.npmrc)`, raw, [target("~/.npmrc")])]
		return [seg("allow", "run_project_code", `${v} ${sub}`, raw)]
	}
	if (v === "bun" && (sub.endsWith(".ts") || sub.endsWith(".js") || sub.endsWith(".tsx"))) {
		const pc = h.classify(sub)
		if (pc.insideProject) return [seg("allow", "run_project_code", `bun ${h.display(pc)}`, raw)]
		return [seg("unknown", "unknown_command", `bun ${sub} (outside project)`, raw)]
	}
	return [seg("unknown", "unknown_command", `${v} ${sub}`, raw)]
}

const KNOWN_NPX_TOOLS = new Set(["prettier", "eslint", "tsc", "typescript", "vitest", "jest", "mocha", "biome", "esbuild", "vite", "next", "nuxt", "astro", "webpack", "rollup", "parcel", "tsx", "ts-node", "nodemon", "concurrently", "rimraf", "npm-check-updates", "ncu", "depcheck", "madge", "tailwindcss", "postcss", "sass", "storybook", "playwright", "cypress", "husky", "lint-staged", "commitlint", "changeset", "turbo", "nx", "lerna", "serve", "http-server", "json-server", "wrangler", "shadcn", "shadcn-ui", "create-next-app", "create-vite", "degit"])
function npxHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const pkg = (pos[0] ?? "").replace(/@[\d^~latest.]+$/, "")
	if (!pkg) return [seg("unknown", "unknown_command", v, raw)]
	const bare = pkg.startsWith("@") ? pkg : pkg.split("@")[0]!
	if (["serve", "http-server", "json-server"].includes(bare)) return [seg("ask", "network_listen", `${v} ${bare} — local web server`, raw, [target(bare)])]
	if (KNOWN_NPX_TOOLS.has(bare) || hasLocalBin(h.ctx.project, bare, h.opts.fs)) {
		return [seg("allow", "run_project_code", `${v} ${bare}`, raw)]
	}
	return [seg("ask", "remote_exec", `${v} ${bare} — downloads and runs a package`, raw, [target(bare)])]
}

/** How a `pip` handler was reached, because the program word is the evidence (see {@link pipInVenv}). */
type PipInvocation = {
	/** argv[0] as the user typed it: `.venv/bin/pip`, `.venv/bin/python`, `uv`, `python`. */
	program: string
	/** Reached through `uv pip`, which provisions and uses a project env by itself. */
	uv?: boolean
}

const VENV_PROGRAM_RE = /(?:^|\/)bin\/(?:pip|python)[\w.-]*$/

/**
 * Does this pip run inside a project env — the difference between writing into this repo's env and writing
 * into whatever python the machine runs on?
 *
 * Three ways to know, and no guessing past them:
 *   - the environment says so: `VIRTUAL_ENV`, or `CONDA_PREFIX` (same shape — an env that is not the system
 *     one). This is the channel the gate has when the user activated the env outside the tool call; note it
 *     is only `CONDA_PREFIX` that means an env is active — `CONDA_EXE`/`CONDA_SHLVL` are set by an install
 *     that has never been activated, and reading those would make every conda machine look like a venv;
 *   - the program lives in one: `<root>/bin/{pip,python}*` with a `pyvenv.cfg` two levels above it. The
 *     path resolves against the leg's own cwd, so the relative spelling people actually type
 *     (`.venv/bin/pip install …`) works, and the probe is skipped when `opts.fs === false` — the same rule
 *     `hasLocalBin` follows, so a test that switches probes off gets one answer everywhere;
 *   - `uv pip` (handled by the caller): uv creates the project env by default, and `--system` is how the
 *     user says it should not.
 *
 * A `bin/` with no `pyvenv.cfg` is not a venv. A directory called `.venv` proves nothing about the
 * interpreter inside it, and an `allow` here is a write into whatever that interpreter is.
 */
export function pipInVenv(argv0: string, h: HandlerContext): boolean {
	const env = h.opts.env
	if (env?.VIRTUAL_ENV?.trim() || env?.CONDA_PREFIX?.trim()) return true
	if (!VENV_PROGRAM_RE.test(argv0)) return false
	if (h.opts.fs === false) return false
	const typed = argv0.startsWith("~/") ? path.join(h.ctx.home, argv0.slice(2)) : argv0
	const root = path.resolve(h.ctx.cwd, path.dirname(path.dirname(typed)))
	try {
		return existsSync(path.join(root, "pyvenv.cfg"))
	} catch {
		return false
	}
}

function pipHandler(argv: string[], h: HandlerContext, v: string, call: PipInvocation = { program: argv[0] ?? "" }): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	if (["list", "show", "freeze", "check", "config", "debug", "index", "inspect", "download", "cache", "hash", "help"].includes(sub)) {
		// Reading a project virtualenv is reading files inside the project; reading the interpreter the machine
		// runs on is not, and neither is `download`, which asks the package index.
		if (sub !== "download" && pipInVenv(call.program, h)) return infoRow(raw, `${v} ${sub} (the project env)`)
		return objectRead(raw, v, `${v} ${sub} — reads ${sub === "download" ? "the package index" : "the python environment packages are installed into"}`)
	}
	if (sub === "install") {
		const pkgs = pos.slice(1)
		const vcsOrUrl = pkgs.find((p) => /^(git\+|https?:\/\/|ssh:\/\/)/.test(p))
		if (vcsOrUrl) return [seg("ask", "remote_exec", `pip install from URL/VCS: ${vcsOrUrl}`, raw, [target(vcsOrUrl)])]
		const editable = hasFlag(argv, "-e", "--editable")
		const reqFile = flagValue(argv, "-r", "--requirement")
		const userOrSystem = hasFlag(argv, "--user", "--system", "--break-system-packages")
		// `--target` outside the project is a write where the env is not; inside it, the packages land in the
		// repo and the question stays the one the env answers.
		const destArg = flagValue(argv, "-t", "--target")
		const dest = destArg === undefined ? undefined : h.classify(destArg)
		if (userOrSystem || (dest !== undefined && !dest.insideProject)) {
			const why = hasFlag(argv, "--user") ? "--user" : hasFlag(argv, "--system") ? "--system" : hasFlag(argv, "--break-system-packages") ? "--break-system-packages" : `--target ${dest ? h.display(dest) : destArg}`
			return [seg("ask", "package_system", `pip install ${why}: ${pkgs.join(" ")}`, raw, pkgs.map(target))]
		}
		if (pipInVenv(call.program, h) || call.uv || editable || reqFile) return [seg("allow", "run_project_code", `pip install (project env)`, raw)]
		// bare pip with nothing saying which env: could be the system python
		return [seg("ask", "package_system", `pip install outside a virtualenv: ${pkgs.join(" ") || "(requirements)"}`, raw, pkgs.map(target))]
	}
	if (sub === "uninstall") return [seg("ask", "package_system", `pip uninstall ${pos.slice(1).join(" ")}`, raw, pos.slice(1).map(target))]
	return [seg("unknown", "unknown_command", `${v} ${sub}`, raw)]
}

/**
 * `uv pip <args…>` spoken to `pip`: drop the program word and the `pip` operand, **keep every flag**.
 *
 * The operand list is not usable here — `positionals` drops option words, and `--system` / `--target` are
 * exactly the flags that decide whether the install stays inside the project env. Rebuilding argv from the
 * words the user typed is the whole point.
 */
function asPipArgv(argv: string[]): string[] {
	const out = argv.slice(1)
	const at = out.indexOf("pip")
	if (at >= 0) out.splice(at, 1)
	return ["pip", ...out]
}

function pyEnvHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	if (v === "pipx") {
		if (["list", "runpip", "environment"].includes(sub)) return objectRead(raw, "pipx", `pipx ${sub} — reads the user-wide python env`)
		if (sub === "install" || sub === "run") return [seg("ask", "package_system", `pipx ${sub} ${pos.slice(1).join(" ")}`, raw, pos.slice(1).map(target))]
		return [seg("ask", "package_system", `pipx ${sub}`, raw)]
	}
	// uv / poetry / pdm / conda — project-env managers
	if (["sync", "lock", "run", "add", "remove", "install", "update", "build", "venv", "init", "tree", "show", "list", "env", "shell", "check", "export", "info", "search", "pip"].includes(sub)) {
		if (v === "conda" && ["install", "remove", "update"].includes(sub) && !flagValue(argv, "-n", "--name", "-p", "--prefix")) {
			return [seg("ask", "package_system", `conda ${sub} into base env`, raw, pos.slice(1).map(target))]
		}
		if (v === "uv" && sub === "pip") return pipHandler(asPipArgv(argv), h, "uv pip", { program: argv[0]!, uv: true })
		return [seg("allow", "run_project_code", `${v} ${sub} (project env)`, raw)]
	}
	if (sub === "publish") return [seg("ask", "network_send", `${v} publish`, raw)]
	if (v === "uv" && sub === "tool") return [seg("ask", "package_system", `uv tool ${pos[1] ?? ""}`, raw, pos.slice(2).map(target))]
	return [seg("unknown", "unknown_command", `${v} ${sub}`, raw)]
}

function cargoHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const sub = positionals(argv)[0] ?? ""
	if (["build", "check", "test", "clippy", "fmt", "run", "doc", "bench", "add", "remove", "update", "tree", "metadata", "vendor", "fetch", "clean", "new", "init", "search", "generate-lockfile"].includes(sub)) {
		return [seg("allow", "run_project_code", `cargo ${sub}`, raw)]
	}
	if (sub === "install") return [seg("ask", "package_system", `cargo install ${positionals(argv).slice(1).join(" ")}`, raw, positionals(argv).slice(1).map(target))]
	if (sub === "publish" || sub === "yank" || sub === "login") return [seg("ask", "network_send", `cargo ${sub}`, raw)]
	return [seg("unknown", "unknown_command", `cargo ${sub}`, raw)]
}

function goHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const sub = positionals(argv)[0] ?? ""
	if (["build", "test", "vet", "fmt", "run", "mod", "get", "list", "doc", "env", "version", "clean", "generate", "work", "tool"].includes(sub)) {
		if (sub === "env" && hasFlag(argv, "-w")) return [seg("ask", "write_sensitive", "go env -w (persistent go config)", raw)]
		if (sub === "clean" && hasFlag(argv, "-cache", "-modcache")) return [seg("ask", "delete_recursive", "go clean cache", raw, [target("go cache")])]
		return [seg("allow", "run_project_code", `go ${sub}`, raw)]
	}
	if (sub === "install") {
		const pkg = positionals(argv)[1] ?? ""
		if (pkg.includes("@") || pkg.includes("/")) return [seg("ask", "package_system", `go install ${pkg} (into GOBIN)`, raw, [target(pkg)])]
		return [seg("allow", "run_project_code", "go install (project)", raw)]
	}
	return [seg("unknown", "unknown_command", `go ${sub}`, raw)]
}

function buildToolHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const sub = positionals(argv)[0] ?? ""
	if (/^(publish|deploy|push|release|upload)/.test(sub)) return [seg("ask", "network_send", `${v} ${sub}`, raw)]
	if (v === "gem" && sub === "install") return [seg("ask", "package_system", `gem install ${positionals(argv).slice(1).join(" ")}`, raw, positionals(argv).slice(1).map(target))]
	return [seg("allow", "run_project_code", `${v} ${sub}`, raw)]
}

function makeHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const targets = positionals(argv)
	const risky = targets.find((t) => /^(deploy|publish|release|push|install|uninstall|distclean)$/.test(t))
	if (v === "make" && risky && /^(deploy|publish|push|release)$/.test(risky)) {
		return [seg("ask", "network_send", `make ${risky}`, raw, [target(risky)])]
	}
	if (v === "make" && risky === "install") {
		// make install often writes /usr/local — ask
		return [seg("ask", "package_system", "make install (may write system paths)", raw, [target("make install")])]
	}
	if (v === "cmake") {
		const installFlag = hasFlag(argv, "--install")
		if (installFlag) return [seg("ask", "package_system", "cmake --install", raw)]
		return [seg("allow", "run_project_code", "cmake", raw)]
	}
	return [seg("allow", "run_project_code", `${v} ${targets.slice(0, 3).join(" ")}`, raw)]
}

// ---------------------------------------------------------------- network

function curlHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const urls = positionals(argv).filter((p) => /^https?:\/\/|^ftp:\/\/|^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(p))
	const url = urls[0] ?? positionals(argv)[0] ?? ""
	// piped to a shell/interpreter that would EXECUTE the downloaded bytes?
	// `curl … | python3 -c "json.load(sys.stdin)"` parses data — that is fine;
	// `curl … | bash` or `curl … | python3` executes it — that asks.
	if (h.pipesTo && sinkExecutesStdin(h.pipesTo)) {
		const sink = base(h.pipesTo[0] ?? "")
		return [seg("ask", "remote_exec", `download ${url} and pipe into ${sink} (remote code execution)`, raw, [target(url)])]
	}
	const getMode = hasFlag(argv, "-G", "--get")
	const uploads = !getMode && argv.some((a) => /^(-d|--data(-\w+)?|-F|--form|-T|--upload-file|--data-binary|--data-raw|--json)$/.test(a) || a.startsWith("--data="))
	const method = (flagValue(argv, "-X", "--request") ?? "").toUpperCase()
	const outFile = flagValue(argv, "-o", "--output", "-O")
	const mutating = uploads || ["POST", "PUT", "PATCH", "DELETE"].includes(method)
	if (mutating) {
		// exfiltration check: -d @file or -T file from a secret path
		const fileRefs = argv.filter((a) => a.startsWith("@") || argv[argv.indexOf(a) - 1] === "-T" || argv[argv.indexOf(a) - 1] === "--upload-file").map((a) => a.replace(/^@/, ""))
		const secretUpload = fileRefs.map((f) => h.classify(f)).find((pc) => pc.isSecret)
		if (secretUpload) return [seg("never", "exfiltration", `upload secret ${h.display(secretUpload)} to ${url}`, raw, [target(url)])]
		// localhost mutations are routine dev work (API testing)
		if (/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/.test(url)) return [seg("allow", "run_project_code", `${v} ${method || "POST"} to localhost`, raw)]
		return [seg("ask", "network_send", `${v} ${method || "POST"} data to ${url}`, raw, [target(hostOf(url)), scope(hostOf(url))])]
	}
	if (outFile) {
		const pc = h.classify(outFile === "-O" ? path.posix.basename(url) : outFile)
		const w = h.decideWrite(pc, "download to")
		if (w.tier !== "allow") return [w]
	}
	// A `curl`/`wget` GET is a read that must ask: it fetches bytes from somebody else's machine, the same
	// class of act as reading a file outside the project. The object is the HOST, so one approval covers the
	// site rather than every path on it.
	const host = url ? netHost(url) : "the network"
	return objectRead(raw, host, `${v} GET ${url || "(no url)"} — reads ${host}`)
}

/**
 * The HOST a URL spells, with the parts a grant cannot mean stripped off.
 *
 * `hostOf` needs a scheme, and half the URLs an agent types have none (`curl localhost:8080/health`,
 * `curl example.com/api`). The authority is what a user would name — not the path, and not the port, because
 * "you may read example.com" plainly covers every port and page on it.
 */
function netHost(url: string): string {
	const authority = (url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0] ?? "").trim()
	const at = authority.lastIndexOf("@")
	const hostPort = at >= 0 ? authority.slice(at + 1) : authority
	if (hostPort.startsWith("[")) return hostPort.replace(/\].*$/, "]")
	const colon = hostPort.lastIndexOf(":")
	return colon > 0 ? hostPort.slice(0, colon) : hostPort
}

function hostOf(url: string): string {
	const m = /^[a-z]+:\/\/([^/@]*@)?([^/:?#]+)/i.exec(url)
	return m?.[2] ?? url.slice(0, 60)
}

/** ssh options that take a separate-word value (`-o BatchMode=yes`, `-i key`,
 *  `-p 22`, `-l user`…). Their values must not be mistaken for the host or the
 *  remote command. */
const SSH_VALUE_OPTS = new Set([
	"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m",
	"-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
])

/** Positionals of an ssh-family command: host first, then the remote command,
 *  skipping option values. `positionals()` drops `-o` but keeps `BatchMode=yes`. */
function sshPositionals(argv: string[]): string[] {
	const out: string[] = []
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!
		if (a === "--") { out.push(...argv.slice(i + 1)); break }
		if (a.startsWith("-") && a !== "-") {
			if (SSH_VALUE_OPTS.has(a)) i++ // skip the option's value
			continue
		}
		out.push(a)
	}
	return out
}

function sshHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-R", "-L", "-D", "-w")) {
		return [seg("ask", "network_listen", `ssh with port forwarding/tunnel`, raw, targetsOf(argv, h))]
	}
	const pos = sshPositionals(argv).filter((p) => !/^\d+$/.test(p))
	const host = pos[0] ?? ""
	const remoteCmd = pos.slice(1).join(" ")
	if (!remoteCmd) return [seg("ask", "network_send", `interactive ssh to ${host}`, raw, [target(host)])]
	// Classify the remote command and reflect its tier: a read-only remote command
	// (echo/hostname/cat…) changes nothing, so it is a remote READ — not a mutation
	// (consistent with auto-allowing `curl` GET). A mutating remote command keeps
	// network_send (gated, and blocked by the read-only posture). Entities are
	// host-scoped so a grant for the host covers repeats.
	const inner = h.evaluateBash(remoteCmd)
	if (inner.tier === "never") return [seg("never", inner.category, `on ${host}: ${inner.description}`, raw, [target(host)])]
	// Read-only ssh was already a read of the machine; what the object of such a read is, is the HOST. So the
	// inner verdict's CATEGORY survives — a status read of a remote box is still `read_system_state`, a read of a
	// remote FILE is still `read_only` — and only the object moves, because a grant for this machine must never
	// cover that host, nor the other way round.
	if (inner.tier === "allow") return objectRead(raw, host, `read-only command on ${host}: ${remoteCmd.slice(0, 80)}`)
	const READ_CATEGORIES = new Set(["read_only", "read_secret", "read_system_state"])
	if (inner.segments.length > 0 && inner.segments.every((s) => READ_CATEGORIES.has(s.category))) {
		return inner.segments.map((s) => seg(s.tier, s.category, `read-only command on ${host}: ${s.description}`, raw, [target(host), scope(host)]))
	}
	return [seg("ask", "network_send", `run on ${host}: ${remoteCmd.slice(0, 100)}`, raw, [target(host), scope(host)])]
}

function scpHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const remote = pos.filter((p) => /^[\w.-]+@[\w.-]+:|^[\w.-]+:(?!\/\/)/.test(p))
	const local = pos.filter((p) => !remote.includes(p))
	const destIsRemote = pos.length > 0 && remote.includes(pos[pos.length - 1]!)
	if (destIsRemote) {
		const secretSrc = local.map((p) => h.classify(p)).find((pc) => pc.isSecret || pc.isNeverWipe)
		if (secretSrc) return [seg("never", "exfiltration", `scp ${h.display(secretSrc)} to ${remote[remote.length - 1]}`, raw, [target(remote[remote.length - 1]!)])]
		return [seg("ask", "network_send", `scp to ${remote[remote.length - 1]}`, raw, [target(hostOf("ssh://" + remote[remote.length - 1]!))])]
	}
	// download from remote — a read of the remote host, and the local write it performs is
	// decided above when it lands outside the project.
	const dest = local[local.length - 1]
	if (dest) {
		const w = h.decideWrite(h.classify(dest), "scp download to")
		if (w.tier !== "allow") return [w]
	}
	const srcHost = hostOf("ssh://" + (remote[0] ?? ""))
	return objectRead(raw, srcHost, `scp download from ${srcHost}`)
}

function ncHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-l", "--listen") || v === "socat" && argv.some((a) => /LISTEN|BIND/i.test(a))) {
		return [seg("ask", "network_listen", `${v} listener`, raw, targetsOf(argv, h))]
	}
	if (hasFlag(argv, "-z")) {
		// A port probe asks whether something is listening on another machine.
		const probeHost = positionals(argv).find((p) => !/^\d+$/.test(p)) ?? "a host"
		return objectRead(raw, probeHost, `${v} -z port scan — reads whether ${probeHost} is listening`)
	}
	// piping data into nc = sending
	if (h.pipedFrom) return [seg("ask", "network_send", `pipe data into ${v} ${positionals(argv).join(" ")}`, raw, targetsOf(argv, h))]
	return [seg("ask", "network_send", `${v} connection to ${positionals(argv).join(" ")}`, raw, targetsOf(argv, h))]
}

// ---------------------------------------------------------------- processes & system

function killHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	if (v === "killall5") return [seg("never", "process_massacre", "killall5 — kills all processes", raw)]
	if (v === "kill") {
		// signal flags like -9 are argv entries starting with "-"; PID -1 / 1 are the danger
		const args = argv.slice(1)
		const pidArgs = args.filter((a) => !/^-(?!\d+$)/.test(a) || /^-\d+$/.test(a))
		if (args.includes("-1") && !args.some((a) => /^-s$|^--signal/.test(a) && args[args.indexOf(a) + 1] === "-1")) {
			// `-1` as a lone arg after possible -SIG flag: kill -9 -1 or kill -1
			const nonSignal = args.filter((a, i) => !(i === 0 && /^-(\d+|[A-Z]+)$/.test(a) && args.length > 1))
			if (nonSignal.includes("-1")) return [seg("never", "process_massacre", "kill -1 (all user processes)", raw)]
		}
		if (pos.includes("1")) return [seg("never", "process_massacre", "kill PID 1", raw)]
	}
	if (v === "pkill" && (hasFlag(argv, "-u") || pos.some((p) => /^\.\+?$|^\.\*$/.test(p)))) {
		return [seg("never", "process_massacre", `pkill matching too broadly: ${raw.slice(0, 80)}`, raw)]
	}
	return [seg("ask", "process_control", `${v} ${pos.join(" ")}`, raw, pos.filter((p) => !p.startsWith("-")).map(target))]
}

/**
 * The service-control verbs that act on a RUNNING unit, and the rows they produce.
 *
 * The category names the effect. Stopping or restarting a named service is what `process_control` is
 * defined as ("stops, restarts or kills named processes or services, however many are named") — the same act
 * `docker stop` and `kill` already file there. What the machine will do at BOOT (`enable`, `mask`,
 * `daemon-reload`, a unit file edit) is what `system_config` means, and that is what the rest of the verb
 * table stays on. Tiers are untouched — both branches were and are `ask`; only the name moved, so a sentence
 * the dictionary defines as process_control now reaches the row it names instead of costing a prompt.
 * `start` is in neither list on purpose: starting a unit may publish a port (whose effect is network_listen)
 * and nothing in the vocabulary calls "start a service" an effect of its own, so it stays where it was.
 */
const SERVICE_STATE_VERBS = new Set(["stop", "restart", "reload", "reload-or-restart", "try-restart", "try-reload-or-restart", "kill", "freeze", "cancel"])

/** `service nginx restart` / `rc-service nginx restart` — the verb can sit after the unit name. */
function serviceControlRows(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const verb = pos.find((p) => SERVICE_STATE_VERBS.has(p))
	if (!verb) return [seg("ask", "system_config", `service control: ${raw}`, raw, targetsOf(argv, h))]
	const units = pos.filter((p) => p !== verb && p !== v && p !== "status")
	return [seg("ask", "process_control", `${v} ${verb} ${units.join(" ")}`, raw, units.map(target))]
}

/** The `systemctl` subcommands whose operand is a UNIT — the ones whose unit joins the object.
 *
 * `list-units` / `list-timers` / `list-sockets` / `get-default` / `show-environment` are deliberately absent:
 * their arguments (a glob pattern, nothing at all) do not name the service being read, so scoping their object to
 * one would be reading the whole machine under a service's name. */
const UNIT_READ_SUBS = new Set(["status", "show", "cat", "is-active", "is-enabled", "is-failed"])

function systemctlHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const user = hasFlag(argv, "--user")
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	const units = pos.slice(1)
	if (["status", "show", "list-units", "list-unit-files", "list-timers", "list-sockets", "cat", "is-active", "is-enabled", "is-failed", "get-default", "show-environment"].includes(sub)) {
		// "What is this unit doing" is a status read of the machine the unit lives on, so the object is the
		// machine — one approval covers the whole family instead of one per unit name. What the prompt says still
		// names the unit, because a person reads the prompt, not the object.
		// When the subcommand reads ONE unit, that unit joins the object (`localhost/gettemp`), so a grant for
		// the service answers it as well as the machine grant already does. The machine-wide
		// subcommands (`list-units`, `list-timers`, …) name no unit and keep the machine object.
		const unit = UNIT_READ_SUBS.has(sub) ? soleUnit(units) : undefined
		const object = unit ? unitReadObject(LOCAL_MACHINE_OBJECT, unit) : LOCAL_MACHINE_OBJECT
		return statusRead(raw, object, `systemctl${user ? " --user" : ""} ${sub}${units.length ? ` ${units.join(" ")}` : ""} — reads unit state on this machine`)
	}
	if (["reboot", "poweroff", "halt", "suspend", "hibernate", "kexec", "hybrid-sleep", "suspend-then-hibernate", "default", "rescue", "emergency"].includes(sub)) {
		return [seg("never", "system_power", `systemctl ${sub}`, raw)]
	}
	if (["daemon-reload", "daemon-reexec"].includes(sub)) return [seg(user ? "allow" : "ask", "system_config", `systemctl${user ? " --user" : ""} ${sub}`, raw)]
	const securityUnit = units.find((u) => /firewalld|ufw|apparmor|selinux|fail2ban|auditd|nftables|iptables/.test(u))
	if (securityUnit && ["stop", "disable", "mask"].includes(sub)) {
		return [seg("never", "security_teardown", `systemctl ${sub} ${securityUnit} — disables a security service`, raw, [target(securityUnit)])]
	}
	if (SERVICE_STATE_VERBS.has(sub)) {
		return [seg("ask", "process_control", `systemctl${user ? " --user" : ""} ${sub} ${units.join(" ")}`, raw, units.map(target))]
	}
	return [seg("ask", "system_config", `systemctl${user ? " --user" : ""} ${sub} ${units.join(" ")}`, raw, units.map(target))]
}

function journalctlHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (argv.some((a) => a.startsWith("--vacuum") || a === "--rotate" || a === "--flush")) {
		return [seg("never", "history_wipe", "journalctl --vacuum/rotate — destroys system logs", raw)]
	}
	// `-u X` scopes the read to that unit, so the unit joins the object. Without `-u` the command reads the
	// whole journal, which is the machine-wide read that must keep asking.
	const unit = soleUnit(journalUnits(argv))
	const object = unit ? unitReadObject(LOCAL_MACHINE_OBJECT, unit) : LOCAL_MACHINE_OBJECT
	const scoped = unit ? ` for ${unit}` : ""
	return statusRead(raw, object, `journalctl — reads the system journal${scoped} on this machine`)
}

function crontabHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-r")) return [seg("never", "history_wipe", "crontab -r — deletes all cron jobs", raw)]
	if (hasFlag(argv, "-l")) return objectRead(raw, "the user crontab", "crontab -l — reads the scheduled jobs")
	return [seg("ask", "write_sensitive", "modify crontab (persistent scheduled execution)", raw, [target("crontab")])]
}

function firewallHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const joined = argv.join(" ")
	if (/(?:^|\s)(-F|--flush|-X|--delete-chain)(?:\s|$)/.test(joined) || (v === "nft" && /\bflush\s+ruleset\b/.test(joined))) {
		return [seg("never", "security_teardown", `${v} flush — removes firewall rules`, raw)]
	}
	if (v === "ufw" && argv.includes("disable")) return [seg("never", "security_teardown", "ufw disable", raw)]
	if (/\b-P\s+\w+\s+ACCEPT\b/.test(joined)) return [seg("never", "security_teardown", `${v} default-ACCEPT policy`, raw)]
	if (v === "ufw" && argv.includes("status") || /\b(-L|--list|list)\b/.test(joined)) return objectRead(raw, "the firewall rules", `${v} list — reads the active firewall rules`)
	return [seg("ask", "system_config", `${v} rule change: ${raw.slice(0, 100)}`, raw, [target(raw.slice(0, 60))])]
}

function sysConfigHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (v === "setenforce" && argv[1] === "0") return [seg("never", "security_teardown", "setenforce 0 — disables SELinux", raw)]
	if (v === "sysctl" && !hasFlag(argv, "-w") && !argv.some((a) => a.includes("="))) return statusRead(raw, LOCAL_MACHINE_OBJECT, "sysctl — reads kernel parameters on this machine")
	if (v === "mount" && argv.length === 1) return statusRead(raw, LOCAL_MACHINE_OBJECT, "mount — reads the mounted filesystems on this machine")
	return [seg("ask", "system_config", `${v} ${argv.slice(1, 4).join(" ")}`, raw, targetsOf(argv, h))]
}

function userMgmtHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (v === "visudo") return [seg("ask", "system_config", "edit sudoers via visudo", raw, [target("/etc/sudoers")])]
	if ((v === "usermod" && argv.some((a, i) => a === "-aG" || a === "-G")) && argv.some((a) => /sudo|wheel|admin|root|docker/.test(a))) {
		return [seg("never", "privilege_persist", `${v} adding user to privileged group`, raw, targetsOf(argv, h))]
	}
	if (v === "useradd" || v === "adduser") return [seg("ask", "system_config", `create user ${positionals(argv).join(" ")}`, raw, targetsOf(argv, h))]
	if (v === "userdel" || v === "deluser") return [seg("never", "system_destroy", `delete user account ${positionals(argv).join(" ")}`, raw, targetsOf(argv, h))]
	return [seg("ask", "system_config", `${v}`, raw, targetsOf(argv, h))]
}

// ---------------------------------------------------------------- databases

const SQL_NEVER_RE = /\bDROP\s+(DATABASE|SCHEMA)\b|\bFLUSHALL\b|\bFLUSHDB\b|dropDatabase\s*\(/i
const SQL_DELETE_NO_WHERE_RE = /\bDELETE\s+FROM\s+\S+\s*(;|$)/i
const SQL_MUTATE_RE = /\b(DROP|TRUNCATE|DELETE|ALTER|UPDATE|INSERT|CREATE|GRANT|REVOKE|VACUUM\s+FULL)\b/i
function dbHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const inline = flagValue(argv, "-c", "--command", "-e", "--execute", "--eval") ?? h.cmd.heredocs.join("\n")
	const sql = inline || ""
	if (v === "redis-cli") {
		const joined = positionals(argv).join(" ")
		if (/\bFLUSHALL\b|\bFLUSHDB\b/i.test(joined)) return [seg("never", "db_destroy", `redis ${joined.match(/FLUSH\w+/i)?.[0]}`, raw)]
		if (/\b(SET|DEL|EXPIRE|HSET|LPUSH|RPUSH|SADD|ZADD|CONFIG\s+SET|SHUTDOWN)\b/i.test(joined)) return [seg("ask", "db_mutation", `redis-cli write: ${joined.slice(0, 80)}`, raw, [target(joined.split(/\s+/)[0] ?? "")])]
		return objectRead(raw, v, "redis-cli — reads the database it connects to")
	}
	if (!sql) {
		// interactive/file input: sqlite3 file.db "SELECT..." puts SQL as positional
		const posSql = positionals(argv).find((p) => SQL_MUTATE_RE.test(p) || /select/i.test(p))
		if (posSql) return dbSqlDecision(posSql, v, h, dbReadRows(v, h, argv))
		// An embedded engine's whole state IS a file in the tree, so the file path decides, exactly as `cat` of
		// the same path would. A client/server engine has no such file: its object is the database.
		if ((v === "sqlite3" || v === "duckdb") && positionals(argv).length <= 1) {
			return [h.decideRead(h.classify(positionals(argv)[0] ?? "."), v)]
		}
		return objectRead(raw, v, `${v} — reads the database it opens`)
	}
	return dbSqlDecision(sql, v, h, dbReadRows(v, h, argv))
}

/**
 * Reading a database is a read of the DATABASE (`redis-cli`, `psql` and the like) — there is no file in the tree
 * for a grant to name. The embedded engines are the exception: an sqlite/duckdb file IS the database, so there
 * the path decides, exactly as `cat` of the same path would.
 */
function dbReadRows(v: string, h: HandlerContext, argv: string[]): SegmentDecision[] {
	if (v === "sqlite3" || v === "duckdb") {
		const file = positionals(argv)[0]
		if (file) return [h.decideRead(h.classify(file), v)]
	}
	return [objectRead(rawOf(h.cmd), v, `${v} — reads the database it opens`)[0]!]
}

function dbSqlDecision(sql: string, v: string, h: HandlerContext, readRows: SegmentDecision[]): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (SQL_NEVER_RE.test(sql)) return [seg("never", "db_destroy", `${v}: ${sql.slice(0, 80)}`, raw)]
	if (SQL_DELETE_NO_WHERE_RE.test(sql) && !/\bWHERE\b/i.test(sql)) return [seg("never", "db_destroy", `${v}: DELETE without WHERE — ${sql.slice(0, 80)}`, raw)]
	const truncates = [...sql.matchAll(/\bTRUNCATE\s+(?:TABLE\s+)?([\w".]+)/gi)].map((m) => m[1]!)
	if (truncates.length > 1) return [seg("never", "db_destroy", `${v}: TRUNCATE of ${truncates.length} tables`, raw, truncates.map(target))]
	if (SQL_MUTATE_RE.test(sql)) {
		const objs = [...sql.matchAll(/\b(?:TABLE|FROM|INTO|UPDATE)\s+([\w".]+)/gi)].map((m) => m[1]!).slice(0, 4)
		return [seg("ask", "db_mutation", `${v}: ${sql.replace(/\s+/g, " ").slice(0, 100)}`, raw, objs.map(target))]
	}
	return readRows
}

// ---------------------------------------------------------------- misc

function historyHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (argv.includes("-c") || argv.includes("-w")) return [seg("never", "history_wipe", "clear shell history", raw)]
	// `history -r FILE` reads a file; plain `history` reports this shell's recorded commands, which is host state
	// rather than the project's, so it is an object read: when unsure, it asks.
	const files = positionals(argv).filter((p) => !/^-\d+$/.test(p))
	if (files.length) return fileReadRows(h, "history", raw, files)
	return objectRead(raw, "the shell history", "history — reads the recorded shell commands")
}

function findHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const iDelete = argv.indexOf("-delete")
	const iExec = argv.findIndex((a) => a === "-exec" || a === "-execdir" || a === "-ok" || a === "-okdir")
	const roots = positionals(argv.slice(0, Math.max(1, Math.min(...[iDelete, iExec].filter((x) => x >= 0), argv.length))))
	if (iDelete >= 0) {
		const rootPcs = (roots.length ? roots : ["."]).map((r) => h.classify(r))
		const protectedRoot = rootPcs.find((pc) => pc.isNeverWipe && !pc.insideProject)
		if (protectedRoot) return [seg("never", "wipe_protected", `find -delete under protected ${h.display(protectedRoot)}`, raw, [target(h.display(protectedRoot))])]
		return [seg("ask", "delete_recursive", `find -delete under ${roots.join(" ") || "."}`, raw, (roots.length ? roots : ["."]).map(target))]
	}
	if (iExec >= 0) {
		const execArgv = argv.slice(iExec + 1, argv.findIndex((a, k) => k > iExec && (a === ";" || a === "+" || a === "\\;")) === -1 ? argv.length : argv.findIndex((a, k) => k > iExec && (a === ";" || a === "+" || a === "\\;")))
		const inner = classifyVerb(execArgv.filter((a) => a !== "{}" && a !== ";" && a !== "+"), h)
		return inner.map((d) => d.tier === "allow" ? d : { ...d, description: `find -exec: ${d.description}` })
	}
	// A search walks the trees it is given, so the ROOTS decide: `find .` is inside the project, `find ~`
	// reads the home directory. With no root, find walks the working directory, which is inside.
	if (roots.length === 0) return infoRow(raw, "find (searches the working directory)")
	return fileReadRows(h, "find", raw, roots)
}

function archiveHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	// extraction/creation writes: check -C target and output file
	const cDir = flagValue(argv, "-C", "--directory")
	if (cDir) {
		const pc = h.classify(cDir)
		if (!pc.insideProject) return [h.decideWrite(pc, `${v} extract into`)]
	}
	const outFlag = flagValue(argv, "-f", "--file", "-o")
	if (outFlag && (argv.includes("-c") || argv.some((a) => /^-\w*c/.test(a)))) {
		const pc = h.classify(outFlag)
		if (!pc.insideProject) return [h.decideWrite(pc, `${v} create archive at`)]
	}
	return [seg("allow", "write_project", `${v}`, raw)]
}

function tmuxHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const sub = positionals(argv)[0] ?? ""
	if (["ls", "list-sessions", "list-windows", "list-panes", "capture-pane", "show-options", "display-message", "has-session"].includes(sub)) {
		return objectRead(raw, "tmux sessions", `tmux ${sub} — reads the running tmux sessions`)
	}
	if (sub === "-V" || argv.includes("-V")) return infoRow(raw, `tmux ${sub} (the tool's own version)`)
	if (sub === "send-keys") {
		// arbitrary command injection into another terminal — classify the payload text
		return [seg("ask", "agent_spawn", `tmux send-keys: ${positionals(argv).slice(1).join(" ").slice(0, 80)}`, raw)]
	}
	if (["kill-server", "kill-session"].includes(sub)) return [seg("ask", "process_control", `tmux ${sub}`, raw, targetsOf(argv, h))]
	return [seg("allow", "run_project_code", `tmux ${sub}`, raw)]
}

function sourceHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const f = positionals(argv)[0]
	if (!f) return [seg("allow", "read_only", "source", raw)]
	const pc = h.classify(f)
	if (pc.insideProject || /\/(\.venv|venv|env)\/bin\/activate$/.test(pc.abs ?? "")) return [seg("allow", "run_project_code", `source ${h.display(pc)}`, raw)]
	return [seg("unknown", "unknown_command", `source ${h.display(pc)} (outside project)`, raw)]
}

function shellHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const cArg = flagValue(argv, "-c")
	if (cArg) {
		const inner = h.evaluateBash(cArg)
		return inner.segments.map((s) => ({ ...s, command: s.command || raw }))
	}
	const pos = positionals(argv)
	const script = pos.find((p) => !p.startsWith("-"))
	if (script) {
		const pc = h.classify(script)
		if (pc.insideProject) return [seg("allow", "run_project_code", `${v} ${h.display(pc)}`, raw)]
		return [seg("unknown", "unknown_command", `${v} ${script} (script outside project)`, raw)]
	}
	// bare `bash` reading stdin: if something pipes into it → remote/unknown exec
	if (h.pipedFrom) {
		const src = base(h.pipedFrom[0] ?? "")
		if (["curl", "wget", "http", "https"].includes(src)) {
			return [seg("ask", "remote_exec", `pipe ${src} output into ${v} (remote code execution)`, raw, [target(h.pipedFrom.find((a) => /https?:\/\//.test(a)) ?? src)])]
		}
		return [seg("unknown", "interpreter_unknown", `pipe ${src} output into ${v}`, raw)]
	}
	if (h.cmd.heredocs.length) {
		return [seg("unknown", "interpreter_unknown", `${v} script via heredoc`, raw, [], { inlineCode: h.cmd.heredocs.join("\n").slice(0, 2000) })]
	}
	return [seg("ask", "interactive_editor", `interactive ${v} shell`, raw)]
}

function interpreterHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const inline = flagValue(argv, "-c", "-e", "--eval", "-p")
	const code = inline ?? (argv.includes("-") || h.cmd.heredocs.length ? h.cmd.heredocs.join("\n") : undefined)
	if (code !== undefined) {
		if (isBenignInlineCode(code)) return [seg("allow", "run_project_code", `${v} inline (benign: print/version/path)`, raw)]
		return [seg("unknown", "interpreter_unknown", `${v} inline code`, raw, [], { inlineCode: code.slice(0, 2000) })]
	}
	if (hasFlag(argv, "--version", "-V", "-v") && argv.length <= 2) return [seg("allow", "read_only", `${v} --version`, raw)]
	if (v === "python" || v === "python3" ) {
		const mIdx = argv.indexOf("-m")
		if (mIdx > 0) {
			const mod = argv[mIdx + 1] ?? ""
			if (["http.server", "SimpleHTTPServer"].includes(mod)) return [seg("ask", "network_listen", `python -m http.server`, raw, [target(argv[mIdx + 2] ?? "8000")])]
			if (["pytest", "unittest", "mypy", "ruff", "black", "flake8", "pylint", "coverage", "tox", "build", "venv", "json.tool", "pip"].includes(mod)) {
				if (mod === "pip") return pipHandler(["pip", ...argv.slice(mIdx + 2)], h, "pip", { program: argv[0]! })
				return [seg("allow", "run_project_code", `python -m ${mod}`, raw)]
			}
			return [seg("unknown", "interpreter_unknown", `python -m ${mod}`, raw)]
		}
	}
	const script = positionals(argv)[0]
	if (script) {
		const pc = h.classify(script)
		if (pc.insideProject && !pc.isGitInternal) return [seg("allow", "run_project_code", `${v} ${h.display(pc)}`, raw)]
		if (pc.abs && !pc.insideProject) return [seg("unknown", "unknown_command", `${v} ${h.display(pc)} (script outside project)`, raw)]
	}
	return [seg("unknown", "interpreter_unknown", `${v} (interactive or unrecognised form)`, raw)]
}

/** Tiny whitelist of self-evidently harmless inline snippets (version prints, json parse). */
export function isBenignInlineCode(code: string): boolean {
	const c = code.trim()
	if (c.length > 300) return false
	// no imports of os/subprocess/shutil/socket/child_process/fs-write, no open() for write, no exec/system
	if (/\b(os\.(system|remove|unlink|rmdir|rename|chmod|chown)|subprocess|shutil|socket|child_process|execSync|spawnSync|fs\.(write|rm|unlink|append)|Deno\.(write|remove)|File\.(delete|write)|unlink|rimraf)\b/.test(c)) return false
	if (/\bopen\s*\([^)]*['"](w|a|r\+|wb|ab)['"]/.test(c)) return false
	if (/\brequests?\.(post|put|delete|patch)|urllib|fetch\s*\(|http\.client|axios/.test(c)) return false
	if (/\beval\s*\(|exec\s*\(|__import__/.test(c)) return false
	// looks like pure computation/printing/parsing
	return /\b(print|console\.log|json|len|version|sys\.version|platform|math|typeof|JSON\.)/i.test(c) || /^\s*['"][^'"]*['"]\s*$/.test(c)
}
