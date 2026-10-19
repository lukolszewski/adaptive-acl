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
import type { PathClass, PathContext } from "./risk-paths.ts"
import type { SimpleCommand } from "./shell-lexer.ts"
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

const READONLY_BINS = new Set([
	"ls", "dir", "vdir", "cat", "head", "tail", "less", "more", "wc", "stat", "file", "du", "df", "tree",
	"grep", "egrep", "fgrep", "rg", "ag", "ack", "fd", "fdfind", "bat", "eza", "exa", "lsd",
	"which", "whereis", "type", "printenv", "uname", "whoami", "id", "date", "cal",
	"uptime", "free", "top", "htop", "btop", "nproc", "lscpu", "lsusb", "lspci", "lsblk",
	"nvidia-smi", "rocm-smi", "sensors", "uptime", "hostname", "hostnamectl", "groups",
	"sort", "uniq", "cut", "tr", "column", "paste", "join", "comm", "diff", "cmp",
	"md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum", "basename", "dirname",
	"realpath", "readlink", "jq", "yq", "xxd", "hexdump", "od", "strings", "nl", "tac",
	"expr", "seq", "bc", "true", "false", "yes", "tty", "locale", "getent", "ldd",
	"ps", "pstree", "pgrep", "pidof", "lsof", "ss", "netstat", "ip", "ifconfig", "route", "arp",
	"dig", "nslookup", "host", "ping", "ping6", "traceroute", "mtr", "whois",
	"infocmp", "tput", "stty", "printf", "echo", "env", "look", "man", "info", "help",
	"apropos", "whatis", "zcat", "zless", "zgrep", "xzcat", "bzcat", "gunzip",
	"sleep", "wait", "sync", "test", "[", "[[", "pwd", "dirs", "history", "fc",
	"col", "fold", "fmt", "rev", "shuf", "timeout", "watch", "time", "times",
	"gguf-dump", "sqlite3", // sqlite3 handled specially below (read vs write)
])

// verbs that read the terminal / control flow — allow
const SHELL_BUILTIN_ALLOW = new Set([
	"export", "set", "unset", "shift", "local", "declare", "typeset", "readonly",
	"alias", "unalias", "hash", "ulimit", "umask", "return", "break", "continue",
	"exit", "trap", "getopts", "read", "let", "eval-noop", "shopt", "complete", "compgen",
	"disown", "jobs", "fg", "bg", "suspend", "logout", ":", "command", "builtin", "enable",
])

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
			argv = argv.slice(1)
			while (argv.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0]!) || argv[0] === "-i" || argv[0] === "-u")) {
				const f = argv[0]!
				argv = argv.slice(1)
				if (f === "-u" && argv.length) argv = argv.slice(1)
			}
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
		case "service": case "rc-service": return [seg("ask", "system_config", `service control: ${raw}`, raw, targetsOf(argv, h))]
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
			return [seg("ask", "agent_spawn", `spawn coding agent: ${raw.slice(0, 120)}`, raw)]
		}
		case "code": case "subl": case "vim": case "vi": case "nvim": case "nano": case "emacs":
			return [seg("ask", "interactive_editor", `open interactive editor ${v}`, raw)]
		case "eval": return [seg("unknown", "interpreter_unknown", `eval: ${argv.slice(1).join(" ").slice(0, 200)}`, raw, [], { inlineCode: argv.slice(1).join(" ") })]
		case "source": case ".": return sourceHandler(argv, h)
		case "ollama": case "llama-server": case "llama-cli": case "vllm": return [seg("ask", "network_listen", `start model server ${v}`, raw, targetsOf(argv, h))]
	}

	if (TEST_TOOLS.has(v)) return [seg("allow", "run_project_code", `${v} (project test/lint tool)`, raw)]
	if (SHELLS.has(v)) return shellHandler(argv, h, v)
	if (INTERPRETERS.has(v)) return interpreterHandler(argv, h, v)
	if (SHELL_BUILTIN_ALLOW.has(v)) return [seg("allow", "read_only", `shell builtin ${v}`, raw)]

	if (READONLY_BINS.has(v)) {
		// generic read-only: check file args for secrets
		const secretRead = positionals(argv).map((p) => h.classify(p)).find((pc) => pc.isSecret)
		if (secretRead) return [seg("ask", "read_secret", `read secret-bearing path ${h.display(secretRead)} via ${v}`, raw, [target(h.display(secretRead))])]
		return [seg("allow", "read_only", `${v} (read-only)`, raw)]
	}

	// ./script.sh or /path/to/script inside project → run project code
	if (argv[0]!.includes("/")) {
		const pc = h.classify(argv[0]!)
		if (pc.insideProject && !pc.isGitInternal) {
			return [seg("allow", "run_project_code", `run project script ${h.display(pc)}`, raw)]
		}
		if (pc.abs && !pc.insideProject) {
			// known safe absolute binaries (e.g. /usr/bin/ls) — re-dispatch on the basename once
			if (READONLY_BINS.has(base(argv[0]!))) return [seg("allow", "read_only", `${base(argv[0]!)} (read-only)`, raw)]
			return [seg("unknown", "unknown_command", `run ${pc.abs}`, raw)]
		}
	}

	// function definitions `foo() {` slip through the lexer as words — allow-noop
	if (/^\w+\(\)$/.test(argv[0]!)) return [seg("allow", "read_only", "function definition", raw)]

	return [seg("unknown", "unknown_command", `run \`${raw.slice(0, 200)}\``, raw)]
}

// ---------------------------------------------------------------- handlers

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
	if (pos.length === 0) return [seg("ask", "delete_recursive", "rm with no visible target", raw)]
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
	return [seg("allow", "read_only", "sed (stream edit, no -i)", raw)]
}

function awkHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const prog = positionals(argv)[0] ?? argv.find((a) => a.includes("{")) ?? ""
	if (/\bsystem\s*\(/.test(prog)) return [seg("unknown", "interpreter_unknown", `awk with system() call`, raw, [], { inlineCode: prog.slice(0, 500) })]
	const redir = /(?:>|>>)\s*"([^"]+)"/.exec(prog)
	if (redir) return [h.decideWrite(h.classify(redir[1]!), "awk write to")]
	return [seg("allow", "read_only", "awk (filter)", raw)]
}

function chmodHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const recursive = hasFlag(argv, "-R", "--recursive", "-r")
	const pos = positionals(argv)
	const mode = pos[0] ?? ""
	const files = pos.slice(1)
	const worldWritable = v === "chmod" && (/^0?[0-7]?77[67]?$/.test(mode) || /(^|,)[ao]?\+w/.test(mode) && mode.includes("o"))
	const out: SegmentDecision[] = []
	for (const f of files) {
		const pc = h.classify(f)
		const disp = h.display(pc)
		if ((pc.isNeverWipe || pc.abs === "/") && recursive) { out.push(seg("never", "perm_destroy", `${v} -R on protected ${disp}`, raw, [target(disp)])); continue }
		if (pc.insideProject && !worldWritable && !pc.isGitInternal) { out.push(seg("allow", "write_project", `${v} ${mode} ${disp}`, raw, [pathTouched(disp)])); continue }
		out.push(seg("ask", "perm_change", `${v} ${mode} ${disp}${worldWritable ? " (world-writable)" : ""}`, raw, [target(disp)]))
	}
	return out.length ? out : [seg("ask", "perm_change", raw.slice(0, 120), raw)]
}

// ---------------------------------------------------------------- git & forges

const GIT_READ = new Set(["status", "log", "diff", "show", "branch", "remote", "ls-files", "ls-remote", "ls-tree", "cat-file", "rev-parse", "rev-list", "describe", "blame", "shortlog", "reflog", "config", "var", "grep", "help", "version", "count-objects", "cherry", "whatchanged", "show-ref", "symbolic-ref", "name-rev", "merge-base", "diff-tree", "diff-index", "fsck", "bisect", "worktree", "notes", "stash"])
const GIT_LOCAL_WRITE = new Set(["add", "commit", "checkout", "switch", "merge", "rebase", "cherry-pick", "revert", "tag", "init", "mv", "rm", "restore", "apply", "am", "format-patch", "fetch", "pull", "submodule", "clone", "gc", "prune", "pack-refs", "maintenance", "sparse-checkout", "update-index", "commit-tree", "read-tree", "write-tree", "mktree", "checkout-index"])
const PROTECTED_BRANCH_RE = /^(main|master|trunk|develop|dev|release[\/-].*|production|prod|stable)$/i

function gitHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	// skip global flags: git -C dir -c a=b <sub>
	let i = 1
	let effCwd: string | null = null
	while (i < argv.length && argv[i]!.startsWith("-")) {
		const f = argv[i]!
		i++
		if ((f === "-C" || f === "-c" || f === "--git-dir" || f === "--work-tree") && i < argv.length) {
			if (f === "-C") effCwd = argv[i]!
			i++
		}
	}
	const sub = argv[i]
	if (!sub) return [seg("allow", "read_only", "git", raw)]
	const rest = argv.slice(i + 1)

	if (sub === "push") {
		const force = hasFlag(rest, "--force", "-f", "--force-with-lease", "--force-if-includes")
		const del = hasFlag(rest, "--delete", "-d") || rest.some((a) => a.startsWith(":"))
		const mirror = hasFlag(rest, "--mirror", "--all", "--tags")
		const pos = rest.filter((a) => !a.startsWith("-"))
		const remote = pos[0] ?? "origin"
		const refspec = pos[1] ?? "(current branch)"
		const branch = refspec.includes(":") ? refspec.split(":")[1]! : refspec
		if ((force || del) && PROTECTED_BRANCH_RE.test(branch)) {
			return [seg("never", "vcs_force_protected", `git push ${force ? "--force " : ""}${del ? "--delete " : ""}to protected branch ${branch} on ${remote}`, raw, [target(`${remote}/${branch}`)])]
		}
		if (mirror && hasFlag(rest, "--mirror")) return [seg("never", "vcs_force_protected", `git push --mirror to ${remote}`, raw, [target(remote)])]
		const kind = force ? "force-push" : del ? "delete remote branch" : "push"
		return [seg("ask", "vcs_remote", `git ${kind} ${refspec} to ${remote}`, raw, [target(`${remote}/${branch}`), scope(`${remote}/*`)])]
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
	if (GIT_READ.has(sub)) return [seg("allow", "read_only", `git ${sub}`, raw)]
	if (GIT_LOCAL_WRITE.has(sub)) {
		// clone/fetch/pull touch the network but only mutate locally — allow (spec §2.1)
		return [seg("allow", "vcs_local", `git ${sub}`, raw)]
	}
	return [seg("unknown", "unknown_command", `git ${sub} ${rest.join(" ").slice(0, 120)}`, raw)]
}

const GH_READ_RE = /^(list|view|status|diff|checks|download|search|api)$/
function ghHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const [_, grp, act] = argv
	if (grp === "api") {
		const method = (flagValue(argv, "-X", "--method") ?? "GET").toUpperCase()
		if (method === "GET") return [seg("allow", "read_only", `gh api GET`, raw)]
		return [seg("ask", "network_send", `gh api ${method} ${positionals(argv.slice(1))[0] ?? ""}`, raw, targetsOf(argv.slice(1), h))]
	}
	if (grp && act && GH_READ_RE.test(act)) return [seg("allow", "read_only", `gh ${grp} ${act}`, raw)]
	if (grp === "auth" && act === "status") return [seg("allow", "read_only", "gh auth status", raw)]
	if (grp === "repo" && act === "clone") return [seg("allow", "vcs_local", "gh repo clone", raw)]
	if (grp && ["pr", "issue", "release", "repo", "gist", "workflow", "run", "label", "secret", "variable", "auth"].includes(grp)) {
		return [seg("ask", "vcs_remote", `gh ${grp} ${act ?? ""} — writes to the forge`, raw, [target(`${grp} ${act ?? ""}`.trim())])]
	}
	return [seg("unknown", "unknown_command", `gh ${argv.slice(1).join(" ").slice(0, 120)}`, raw)]
}

// ---------------------------------------------------------------- docker & compose

const DOCKER_READ = new Set(["ps", "images", "logs", "inspect", "stats", "top", "port", "diff", "history", "version", "info", "events", "search", "manifest", "context"])
function dockerHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	let i = 1
	while (i < argv.length && argv[i]!.startsWith("-")) { const f = argv[i]!; i++; if (["-H", "--host", "-c", "--context", "--config", "-l", "--log-level"].includes(f)) i++ }
	const sub = argv[i]
	if (!sub) return [seg("allow", "read_only", "docker", raw)]
	const rest = argv.slice(i + 1)
	if (sub === "compose") return dockerComposeHandler(argv, h, i)
	if (DOCKER_READ.has(sub)) return [seg("allow", "read_only", `docker ${sub}`, raw)]
	if (sub === "build" || sub === "buildx") return [seg("allow", "run_project_code", `docker ${sub}`, raw)]
	if (sub === "pull") return [seg("allow", "read_only", "docker pull", raw)]
	if (sub === "push") return [seg("ask", "network_send", `docker push ${rest.filter((a) => !a.startsWith("-"))[0] ?? ""}`, raw, targetsOf(argv.slice(i), h))]
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

function dockerComposeHandler(argv: string[], h: HandlerContext, i: number): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const args = argv[i] === "compose" ? argv.slice(i + 1) : argv.slice(1)
	let j = 0
	while (j < args.length && args[j]!.startsWith("-")) { const f = args[j]!; j++; if (["-f", "--file", "-p", "--project-name", "--profile", "--env-file"].includes(f)) j++ }
	const sub = args[j]
	if (!sub) return [seg("allow", "read_only", "docker compose", raw)]
	if (["config", "ps", "logs", "top", "events", "images", "ls", "version", "port"].includes(sub)) return [seg("allow", "read_only", `docker compose ${sub}`, raw)]
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
		return [seg("allow", "read_only", `kubectl ${sub}`, raw)]
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
		if (hasFlag(argv, "--dry-run")) return [seg("allow", "read_only", `kubectl ${sub} --dry-run`, raw)]
		return [seg("never", "cluster_wide_destroy", `kubectl ${sub} ${pos[1] ?? ""} — node-level operation`, raw, [target(pos[1] ?? "node")])]
	}
	if (["apply", "create", "patch", "replace", "edit", "scale", "rollout", "label", "annotate", "set", "expose", "autoscale", "cp"].includes(sub)) {
		if (hasFlag(argv, "--dry-run")) return [seg("allow", "read_only", `kubectl ${sub} --dry-run`, raw)]
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
		if (sub === "repo" && pos[1] && ["add", "remove", "update"].includes(pos[1])) return [seg("allow", "read_only", `helm repo ${pos[1]}`, raw)]
		return [seg("allow", "read_only", `helm ${sub ?? ""}`, raw)]
	}
	const ns = flagValue(argv, "-n", "--namespace") ?? "default"
	if (sub === "uninstall" || sub === "delete") {
		const releases = pos.slice(1)
		if (releases.length === 0) return [seg("never", "cluster_wide_destroy", "helm uninstall with no release named", raw)]
		return [seg("ask", "cluster_mutation", `helm uninstall ${releases.join(" ")} -n ${ns}`, raw, releases.map((r) => target(`${r}@${ns}`)))]
	}
	if (["install", "upgrade", "rollback", "push", "test"].includes(sub)) {
		if (hasFlag(argv, "--dry-run")) return [seg("allow", "read_only", `helm ${sub} --dry-run`, raw)]
		return [seg("ask", "cluster_mutation", `helm ${sub} ${pos.slice(1, 3).join(" ")} -n ${ns}`, raw, [target(`${pos[1] ?? sub}@${ns}`), scope(ns)])]
	}
	return [seg("unknown", "unknown_command", `helm ${sub}`, raw)]
}

function terraformHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const sub = positionals(argv)[0]
	if (!sub || ["plan", "show", "validate", "fmt", "init", "output", "state", "graph", "providers", "version", "workspace", "console", "get", "refresh", "test"].includes(sub)) {
		if (sub === "state" && positionals(argv)[1] && ["rm", "mv", "push", "replace-provider"].includes(positionals(argv)[1]!)) {
			return [seg("ask", "cluster_mutation", `terraform state ${positionals(argv)[1]}`, raw)]
		}
		return [seg("allow", "read_only", `terraform ${sub ?? ""}`, raw)]
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
const AWS_NEVER: Array<{ svc: string; re: RegExp; why: string }> = [
	{ svc: "s3", re: /^rb\b/, why: "remove bucket" },
	{ svc: "s3api", re: /^delete-bucket\b/, why: "remove bucket" },
	{ svc: "ec2", re: /^terminate-instances\b/, why: "terminate instances" },
	{ svc: "rds", re: /^delete-db/, why: "delete database" },
	{ svc: "dynamodb", re: /^delete-table\b/, why: "delete table" },
	{ svc: "cloudformation", re: /^delete-stack\b/, why: "delete stack" },
	{ svc: "iam", re: /^(delete|create)-(user|access-key|role)|attach-.*policy/, why: "IAM mutation" },
	{ svc: "kms", re: /^schedule-key-deletion\b/, why: "delete KMS key" },
]
function awsHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const svc = pos[0] ?? ""
	const op = pos[1] ?? ""
	if (!svc) return [seg("allow", "read_only", "aws", raw)]
	if (svc === "s3") {
		if (["ls", "presign"].includes(op)) return [seg("allow", "read_only", `aws s3 ${op}`, raw)]
		if (op === "cp" || op === "sync" || op === "mv") {
			const rest = pos.slice(2)
			const remoteDest = rest.find((a) => a.startsWith("s3://")) && rest[rest.length - 1]?.startsWith("s3://")
			const localSrc = rest.find((a) => !a.startsWith("s3://"))
			if (remoteDest && localSrc) {
				const pc = h.classify(localSrc)
				if (pc.isSecret || pc.isNeverWipe) return [seg("never", "exfiltration", `upload ${h.display(pc)} to ${rest[rest.length - 1]}`, raw, [target(rest[rest.length - 1]!)])]
				return [seg("ask", "network_send", `aws s3 ${op} to ${rest[rest.length - 1]}`, raw, [target(rest[rest.length - 1]!)])]
			}
			// download
			return [seg("allow", "read_only", `aws s3 ${op} (download)`, raw)]
		}
		if (op === "rm") {
			const uri = pos[2] ?? ""
			const recursive = hasFlag(argv, "--recursive")
			if (recursive && /^s3:\/\/[^/]+\/?$/.test(uri)) return [seg("never", "cluster_wide_destroy", `aws s3 rm --recursive on whole bucket ${uri}`, raw, [target(uri)])]
			return [seg("ask", "cluster_mutation", `aws s3 rm${recursive ? " --recursive" : ""} ${uri}`, raw, [target(uri), scope(uri.replace(/[^/]+$/, ""))])]
		}
		if (op === "rb") return [seg("never", "cluster_wide_destroy", `aws s3 rb ${pos[2] ?? ""}`, raw, [target(pos[2] ?? "")])]
	}
	for (const n of AWS_NEVER) if (svc === n.svc && n.re.test(op)) return [seg("never", "cluster_wide_destroy", `aws ${svc} ${op} — ${n.why}`, raw, targetsOf(argv.slice(2), h))]
	if (AWS_READ_RE.test(op)) return [seg("allow", "read_only", `aws ${svc} ${op}`, raw)]
	return [seg("ask", "cluster_mutation", `aws ${svc} ${op}`, raw, [target(`${svc}:${op}`), scope(svc)])]
}

const CLOUD_READ_RE = /^(list|describe|get|show|info|status|whoami|config|regions|zones|versions?|logs?|ls|cat|env|open|releases|domains|projects?|apps?|ps)$/
function cloudHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const joined = pos.slice(0, 3).join(" ")
	if (pos.some((p) => CLOUD_READ_RE.test(p)) && !pos.some((p) => /^(delete|destroy|rm|remove|create|deploy|set|update|scale|restart|stop)$/.test(p))) {
		return [seg("allow", "read_only", `${v} ${joined}`, raw)]
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
	if (READ.test(sub)) return [seg("allow", "read_only", `${v} ${sub}`, raw)]
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

function pipHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	if (["list", "show", "freeze", "check", "config", "debug", "index", "inspect", "download", "cache", "hash", "help"].includes(sub)) return [seg("allow", "read_only", `${v} ${sub}`, raw)]
	if (sub === "install") {
		const pkgs = pos.slice(1)
		const vcsOrUrl = pkgs.find((p) => /^(git\+|https?:\/\/|ssh:\/\/)/.test(p))
		if (vcsOrUrl) return [seg("ask", "remote_exec", `pip install from URL/VCS: ${vcsOrUrl}`, raw, [target(vcsOrUrl)])]
		const inVenv = Boolean(h.opts.env?.VIRTUAL_ENV) || argv[0]!.includes("/.venv/") || argv[0]!.includes("/venv/")
		const editable = hasFlag(argv, "-e", "--editable")
		const reqFile = flagValue(argv, "-r", "--requirement")
		const userOrSystem = hasFlag(argv, "--user", "--system", "--break-system-packages")
		if (userOrSystem) return [seg("ask", "package_system", `pip install ${hasFlag(argv, "--user") ? "--user" : "--system"}: ${pkgs.join(" ")}`, raw, pkgs.map(target))]
		if (inVenv || editable || reqFile) return [seg("allow", "run_project_code", `pip install (project env)`, raw)]
		// bare pip install with no venv — could be system python
		return [seg("ask", "package_system", `pip install outside a virtualenv: ${pkgs.join(" ") || "(requirements)"}`, raw, pkgs.map(target))]
	}
	if (sub === "uninstall") return [seg("ask", "package_system", `pip uninstall ${pos.slice(1).join(" ")}`, raw, pos.slice(1).map(target))]
	return [seg("unknown", "unknown_command", `${v} ${sub}`, raw)]
}

function pyEnvHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	if (v === "pipx") {
		if (["list", "runpip", "environment"].includes(sub)) return [seg("allow", "read_only", `pipx ${sub}`, raw)]
		if (sub === "install" || sub === "run") return [seg("ask", "package_system", `pipx ${sub} ${pos.slice(1).join(" ")}`, raw, pos.slice(1).map(target))]
		return [seg("ask", "package_system", `pipx ${sub}`, raw)]
	}
	// uv / poetry / pdm / conda — project-env managers
	if (["sync", "lock", "run", "add", "remove", "install", "update", "build", "venv", "init", "tree", "show", "list", "env", "shell", "check", "export", "info", "search", "pip"].includes(sub)) {
		if (v === "conda" && ["install", "remove", "update"].includes(sub) && !flagValue(argv, "-n", "--name", "-p", "--prefix")) {
			return [seg("ask", "package_system", `conda ${sub} into base env`, raw, pos.slice(1).map(target))]
		}
		if (v === "uv" && sub === "pip") return pipHandler(["pip", ...pos.slice(1)], h, "uv pip")
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
	return [seg("allow", "read_only", `${v} GET ${url}`.trim(), raw)]
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
	if (inner.tier === "allow") return [seg("allow", "read_only", `read-only command on ${host}: ${remoteCmd.slice(0, 80)}`, raw, [target(host)])]
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
	// download from remote
	const dest = local[local.length - 1]
	if (dest) {
		const w = h.decideWrite(h.classify(dest), "scp download to")
		if (w.tier !== "allow") return [w]
	}
	return [seg("allow", "read_only", "scp download", raw)]
}

function ncHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-l", "--listen") || v === "socat" && argv.some((a) => /LISTEN|BIND/i.test(a))) {
		return [seg("ask", "network_listen", `${v} listener`, raw, targetsOf(argv, h))]
	}
	if (hasFlag(argv, "-z")) return [seg("allow", "read_only", `${v} -z port scan`, raw)]
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

function systemctlHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	const user = hasFlag(argv, "--user")
	const pos = positionals(argv)
	const sub = pos[0] ?? ""
	const units = pos.slice(1)
	if (["status", "show", "list-units", "list-unit-files", "list-timers", "list-sockets", "cat", "is-active", "is-enabled", "is-failed", "get-default", "show-environment"].includes(sub)) {
		return [seg("allow", "read_only", `systemctl ${sub}`, raw)]
	}
	if (["reboot", "poweroff", "halt", "suspend", "hibernate", "kexec", "hybrid-sleep", "suspend-then-hibernate", "default", "rescue", "emergency"].includes(sub)) {
		return [seg("never", "system_power", `systemctl ${sub}`, raw)]
	}
	if (["daemon-reload", "daemon-reexec"].includes(sub)) return [seg(user ? "allow" : "ask", "system_config", `systemctl${user ? " --user" : ""} ${sub}`, raw)]
	const securityUnit = units.find((u) => /firewalld|ufw|apparmor|selinux|fail2ban|auditd|nftables|iptables/.test(u))
	if (securityUnit && ["stop", "disable", "mask"].includes(sub)) {
		return [seg("never", "security_teardown", `systemctl ${sub} ${securityUnit} — disables a security service`, raw, [target(securityUnit)])]
	}
	return [seg("ask", "system_config", `systemctl${user ? " --user" : ""} ${sub} ${units.join(" ")}`, raw, units.map(target))]
}

function journalctlHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (argv.some((a) => a.startsWith("--vacuum") || a === "--rotate" || a === "--flush")) {
		return [seg("never", "history_wipe", "journalctl --vacuum/rotate — destroys system logs", raw)]
	}
	return [seg("allow", "read_only", "journalctl (read)", raw)]
}

function crontabHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (hasFlag(argv, "-r")) return [seg("never", "history_wipe", "crontab -r — deletes all cron jobs", raw)]
	if (hasFlag(argv, "-l")) return [seg("allow", "read_only", "crontab -l", raw)]
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
	if (v === "ufw" && argv.includes("status") || /\b(-L|--list|list)\b/.test(joined)) return [seg("allow", "read_only", `${v} list`, raw)]
	return [seg("ask", "system_config", `${v} rule change: ${raw.slice(0, 100)}`, raw, [target(raw.slice(0, 60))])]
}

function sysConfigHandler(argv: string[], h: HandlerContext, v: string): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (v === "setenforce" && argv[1] === "0") return [seg("never", "security_teardown", "setenforce 0 — disables SELinux", raw)]
	if (v === "sysctl" && !hasFlag(argv, "-w") && !argv.some((a) => a.includes("="))) return [seg("allow", "read_only", "sysctl (read)", raw)]
	if (v === "mount" && argv.length === 1) return [seg("allow", "read_only", "mount (list)", raw)]
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
		return [seg("allow", "read_only", "redis-cli (read)", raw)]
	}
	if (!sql) {
		// interactive/file input: sqlite3 file.db "SELECT..." puts SQL as positional
		const posSql = positionals(argv).find((p) => SQL_MUTATE_RE.test(p) || /select/i.test(p))
		if (posSql) return dbSqlDecision(posSql, v, h)
		if (v === "sqlite3" && positionals(argv).length <= 1) return [seg("allow", "read_only", `${v} (interactive/read)`, raw)]
		return [seg("allow", "read_only", `${v} (no inline SQL visible)`, raw)]
	}
	return dbSqlDecision(sql, v, h)
}

function dbSqlDecision(sql: string, v: string, h: HandlerContext): SegmentDecision[] {
	const raw = rawOf(h.cmd)
	if (SQL_NEVER_RE.test(sql)) return [seg("never", "db_destroy", `${v}: ${sql.slice(0, 80)}`, raw)]
	if (SQL_DELETE_NO_WHERE_RE.test(sql) && !/\bWHERE\b/i.test(sql)) return [seg("never", "db_destroy", `${v}: DELETE without WHERE — ${sql.slice(0, 80)}`, raw)]
	const truncates = [...sql.matchAll(/\bTRUNCATE\s+(?:TABLE\s+)?([\w".]+)/gi)].map((m) => m[1]!)
	if (truncates.length > 1) return [seg("never", "db_destroy", `${v}: TRUNCATE of ${truncates.length} tables`, raw, truncates.map(target))]
	if (SQL_MUTATE_RE.test(sql)) {
		const objs = [...sql.matchAll(/\b(?:TABLE|FROM|INTO|UPDATE)\s+([\w".]+)/gi)].map((m) => m[1]!).slice(0, 4)
		return [seg("ask", "db_mutation", `${v}: ${sql.replace(/\s+/g, " ").slice(0, 100)}`, raw, objs.map(target))]
	}
	return [seg("allow", "read_only", `${v} query (read)`, raw)]
}

// ---------------------------------------------------------------- misc

function historyHandler(argv: string[], h: HandlerContext): SegmentDecision[] {
	if (argv.includes("-c") || argv.includes("-w")) return [seg("never", "history_wipe", "clear shell history", rawOf(h.cmd))]
	return [seg("allow", "read_only", "history", rawOf(h.cmd))]
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
	return [seg("allow", "read_only", "find (search)", raw)]
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
	if (["ls", "list-sessions", "list-windows", "list-panes", "capture-pane", "show-options", "display-message", "has-session", "-V"].includes(sub) || argv.includes("-V")) {
		return [seg("allow", "read_only", `tmux ${sub}`, raw)]
	}
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
				if (mod === "pip") return pipHandler(["pip", ...argv.slice(mIdx + 2)], h, "pip")
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
