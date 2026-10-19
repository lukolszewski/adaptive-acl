/**
 * Path classification for the auto-mode risk policy (docs/CLASSIFIER-SPEC.md §2.3, §2.5).
 * Pure functions; `home` and `project` are injected so tests are hermetic.
 */

import path from "node:path"

export type PathContext = {
	/** Effective working directory for relative paths. */
	cwd: string
	/** Project root (the pi session cwd). Writes inside are ALLOW. */
	project: string
	home: string
}

export type PathClass = {
	/** Absolute, normalised path; `null` when it cannot be resolved (unexpanded variable). */
	abs: string | null
	/** Raw token as written. */
	raw: string
	insideProject: boolean
	/** Equals the project root itself (or `.`, `./`, `*`). */
	isProjectRoot: boolean
	/** Wiping this path is NEVER-tier (root, home, system dirs, project parents…). */
	isNeverWipe: boolean
	/** Secret-bearing file (§2.5). */
	isSecret: boolean
	/** Sensitive config (shell profiles, ssh, cron, systemd, /etc…) — writes are ASK write_sensitive. */
	isSensitiveConfig: boolean
	/** Looks like machine config by path shape but sits inside the project: staged source, not the
	 *  live file. Writes are ALLOW. See `isSensitiveConfig` for the difference that matters. */
	stagedConfig: boolean
	/** Inside a temp location (/tmp, /var/tmp, /dev/shm, $TMPDIR) — writes are routine. */
	isTemp: boolean
	/** Inside the project's .git directory. */
	isGitInternal: boolean
	/** Block device or special device. */
	isDevice: boolean
	/** Starts with an unexpanded variable or contains a glob at the root position. */
	unresolvedRoot: boolean
	/** Path contains an unexpanded `$var` somewhere after a known prefix. */
	hasExpansion: boolean
}

const SYSTEM_ROOTS = [
	"/", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/var",
	"/boot", "/opt", "/srv", "/dev", "/proc", "/sys", "/root", "/home", "/mnt", "/media",
	"/run", "/snap", "/nix", "/System", "/Library", "/Applications", "/Users", "/private", "/tmp", "/var/tmp", "/dev/shm",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/share", "/var/lib", "/var/log",
	"/etc/ssh", "/etc/systemd", "/var/lib/docker",
]

const HOME_NEVER_SUBDIRS = [
	".ssh", ".gnupg", ".config", ".local", ".cache", "Documents", "Desktop", "Pictures",
	"Videos", "Music", "Downloads", "Library", "Dropbox", "OneDrive", ".aws", ".kube",
	".docker", ".password-store", ".mozilla", ".thunderbird", "dev", "src", "projects",
	"work", "repos", "code",
]

/**
 * Filenames that mean "this holds a credential" — one reviewed line each, not one long alternation.
 *
 * A regex alternation cannot express "a credential *here*, not everywhere", and that limitation is
 * what put two ordinary source filenames in here: `config\.json` (written for `~/.docker/config.json`,
 * and thereafter flagging every `config.json` in every project on disk) and `hosts\.yml` (an Ansible
 * inventory name, so `inventory/hosts.yml` read as secret-bearing). Both are gone; the home locations
 * they were reaching for are already covered by `SECRET_DIRS_UNDER_HOME`. Anything added here should
 * say which location it was really about, and whether that location is already covered. Names that
 * are not on this list are still recognised by word shape — see `credentialNameWord` below.
 */
const SECRET_NAME_RULES: ReadonlyArray<{ id: string; re: RegExp }> = [
	{ id: "openssh_key", re: /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i },
	{ id: "key_material_ext", re: /.*\.(pem|key|p12|pfx|jks|keystore)$/i },
	{ id: "credentials", re: /^credentials(\..*)?$/i },
	{ id: "dotenv", re: /^\.env(\..*)?$/i },
	{ id: "client_auth_files", re: /^(\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\.my\.cnf|\.htpasswd)$/i },
	{ id: "auth_json", re: /^auth\.json$/i }, // Composer credentials store
	{ id: "secrets_file", re: /^secrets?(\..*)?\.(json|ya?ml|toml|env)$/i },
	{ id: "token_file", re: /^tokens?(\..*)?$/i },
	{ id: "dot_secret_ext", re: /.*\.secret$/i },
	{ id: "unix_auth_db", re: /^(shadow|sudoers(\..*)?)$/i },
	{ id: "kubeconfig", re: /^kubeconfig$/i },
	{ id: "gcp_service_account", re: /^service-account.*\.json$/i },
]

/** The reviewed list: one line per name, each written for a place it was really seen. */
function listedCredentialFilename(basename: string): boolean {
	return SECRET_NAME_RULES.some((r) => r.re.test(basename))
}

export function isCredentialFilename(basename: string): boolean {
	return listedCredentialFilename(basename) || declaresCredentialName(basename)
}

/* ------------------------------------------------------------------ secret-bearing *names* (D18)
 *
 * The table above is a list of specific names. It cannot answer the general question — "a file whose
 * NAME ALONE declares it holds credentials" — because that declaration is a property of the last
 * word of the name, not of one fixed spelling: `pass`, `client_secret.json`, `aws_secret_access_key`,
 * `passwords.list.bak` all declare it, and none of them is a line anybody would think to add.
 *
 * So this is word recognition, not pattern matching, and its whole design is the noise rule:
 *
 *   - a word counts only as a WHOLE word of the name (`passctl`, `mypasswd`, `tokenizer`, `compass`
 *     are ordinary files), never as a substring;
 *   - code and prose are not credential stores, so a file whose extension says `ts`/`py`/`go`/`md`
 *     is never secret by name — `src/password.ts` and `docs/secrets.md` stay readable, and that
 *     single guard is what keeps this feature usable. Data extensions (json/yaml/toml/env/txt/csv)
 *     deliberately stay out of that exemption: a data file named `secrets` is the case this exists
 *     for;
 *   - `key` is too generic to fire on its own (`sort_key`, `monkey`, `key`), so it counts only
 *     behind a qualifier that is itself known to name a credential;
 *   - the token has to *address* a file. Read-only binaries take their pattern from the same slot as
 *     their files, so `grep -r password src/` reaches the path classifier with the bare word
 *     `password`, and a rule that prompts there prompts on the word, not on a file;
 *   - one word means something else where the OS keeps it — see `UNIX_USER_DB_PATHS`.
 *
 * Being secret-bearing costs one prompt, not a floor: the category is the existing `read_secret`, so
 * a human approval or a prompt-derived grant covers the file (`docs/TODO.md`, decision D18).
 */

/** Words that mean "the bytes in this file are credentials" when they end a file name. */
const CREDENTIAL_NAME_WORDS: ReadonlySet<string> = new Set([
	"pass", "passwd", "passphrase", "passphrases", "password", "passwords",
	"credential", "credentials", "secret", "secrets", "token", "tokens",
	"apikey", "htpasswd",
])

/** `key` names a credential only behind one of these: `api_key`, `access_key`, `signing_key`. */
const KEY_QUALIFIERS: ReadonlySet<string> = new Set([
	"api", "access", "auth", "private", "secret", "security", "encryption", "signing", "session", "master",
])

/** Extensions that say *code or documentation about* credentials, not a credential store. */
const CODE_OR_DOC_EXTS: ReadonlySet<string> = new Set([
	"ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "vue", "svelte", "astro",
	"py", "pyi", "rb", "php", "go", "rs", "java", "kt", "kts", "scala", "swift", "dart", "zig", "nim",
	"c", "h", "cc", "cpp", "cxx", "hh", "hpp", "m", "mm", "cs", "fs", "vb", "ex", "exs", "erl", "hs",
	"clj", "cljs", "lua", "r", "jl", "v", "cr", "odin",
	"sh", "bash", "zsh", "fish", "ksh", "ps1", "psm1", "bat", "cmd", "pl", "pm", "tcl", "awk",
	"md", "markdown", "mdx", "rst", "adoc", "org", "tex", "norg",
])

/** Trailing extensions that wrap a name instead of describing it: `secrets.tar.gz`, `pass.txt.bak`. */
const WRAPPER_EXTS: ReadonlySet<string> = new Set([
	"tar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "zip", "gzip", "7z", "rar",
	"bak", "old", "orig", "save", "saving", "backup", "copy", "tmp", "temp", "swp", "sublime-workspace",
])

/**
 * Where the word `passwd` is the machine's user database rather than a claim about credentials.
 *
 * The hashes are not here — they are in `/etc/shadow`, which the reviewed table has called secret by
 * name for years — and the file is world-readable by design, so reading it is ordinary debugging
 * (and `index.test.ts` pins that a read of `/etc/passwd` auto-approves). Everywhere else the same
 * word is a leak: a `passwd` committed into a repo, or dumped in `/tmp`, is exactly the file this
 * rule exists for. A location exemption for one word, not a general location rule: D18 says a
 * credential-declaring name is secret-bearing wherever it sits, and that still holds for every other
 * word here.
 */
const UNIX_USER_DB_PATHS: ReadonlySet<string> = new Set(["/etc/passwd", "/etc/passwd-", "/private/etc/passwd", "/etc/master.passwd"])

/** Drop a trailing editor `~` and then every wrapping extension, innermost last. */
function unwrapName(name: string): string {
	let n = name.replace(/~+$/, "")
	for (;;) {
		const at = n.lastIndexOf(".")
		if (at <= 0) return n
		if (!WRAPPER_EXTS.has(n.slice(at + 1))) return n
		n = n.slice(0, at)
	}
}

/** The credential word this file name ends with, or `null`. See the block comment above. */
function credentialNameWord(rawName: string): string | null {
	const name = rawName.trim().toLowerCase()
	if (!name) return null
	const unwrapped = unwrapName(name)
	const dot = unwrapped.lastIndexOf(".")
	// `dot <= 0` keeps a leading dot (`.env`, `.htpasswd`) part of the name, not an extension.
	const stem = dot <= 0 ? unwrapped : unwrapped.slice(0, dot)
	const ext = dot <= 0 ? "" : unwrapped.slice(dot + 1)
	if (ext && CODE_OR_DOC_EXTS.has(ext)) return null
	const words = stem.split(/[^a-z0-9]+/).filter((w) => w.length > 0)
	if (words.length === 0) return null
	const last = words[words.length - 1]!
	if (CREDENTIAL_NAME_WORDS.has(last)) return last
	if (last === "key" && words.length > 1 && KEY_QUALIFIERS.has(words[words.length - 2]!)) return "key"
	return null
}

/**
 * Does this token address a file, or is it a bare word a command was handed?
 *
 * A directory part (`./pass`, `config/secrets`) or an extension (`pass.txt`) means a file is being
 * addressed. A lone `password` does not: `grep -r password src/` and `cat password` are the same
 * string, and the read-only-binary handler classifies every positional it is given as a path
 * (risk-handlers.ts), so guessing here would prompt on searches for the word. The miss is one
 * uncovered spelling of an extensionless root-level file; the false positive is every grep.
 */
function addressesAFile(raw: string, basename: string): boolean {
	return raw.includes("/") || /\.[^./]+$/.test(basename)
}

/** The reviewed name-shape answer for a basename: which credential word the name ends with. */
function declaresCredentialName(basename: string): boolean {
	return credentialNameWord(basename) !== null
}

/** Directory names whose contents are machine config *wherever they live outside a project*. */
const CONFIG_DIR_SEGMENT_RE = /\/(crontab|cron\.d|cron\.daily|cron\.hourly|systemd|init\.d|rc\.d|profile\.d|ld\.so\.conf\.d|sudoers\.d)\b/

const SECRET_EXAMPLE_RE = /\.(example|sample|template|dist|schema)$/i

/** Files under a secret directory that hold no credential: this plugin's own config (modes, rules,
 *  classifier endpoint — provider keys live in the agent's models/settings files, not here). */
const NON_SECRET_UNDER_HOME = new Set([".pi/agent/permission-modes.json"])

const SECRET_DIRS_UNDER_HOME = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh", ".config/gcloud", ".azure", ".password-store", ".pi/agent", ".claude", ".config/pi", ".vault-token"]

const SENSITIVE_HOME_FILES = new Set([
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
	".config/fish/config.fish", ".cshrc", ".tcshrc", ".kshrc", ".xinitrc", ".xprofile", ".Xresources", ".xsession",
	".gitconfig", ".gitignore_global", ".ssh/config", ".ssh/authorized_keys", ".ssh/known_hosts", ".inputrc",
	".tmux.conf", ".vimrc", ".config/nvim/init.lua", ".config/nvim/init.vim", ".npmrc", ".yarnrc", ".cargo/config.toml",
	".docker/config.json", ".kube/config", ".aws/config", ".config/systemd", ".config/autostart", ".bash_history",
	".zsh_history", ".python_history", ".node_repl_history", ".lesshst",
])

const SENSITIVE_SYSTEM_PREFIXES = [
	"/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/var/lib", "/var/spool/cron", "/var/log",
	"/Library", "/System", "/private/etc", "/root", "/snap",
]

const DEVICE_RE = /^\/dev\/(sd[a-z]+\d*|nvme\d+n\d+(p\d+)?|mmcblk\d+(p\d+)?|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|loop\d+|dm-\d+|md\d+|mapper\/.+|disk\d+.*|rdisk\d+.*|mem|kmem|port|zero|random|urandom|tty\S*|fd\d+)$/

export function expandTilde(p: string, home: string): string {
	if (p === "~") return home
	if (p.startsWith("~/")) return path.join(home, p.slice(2))
	if (p === "$HOME" || p === "${HOME}") return home
	if (p.startsWith("$HOME/")) return path.join(home, p.slice(6))
	if (p.startsWith("${HOME}/")) return path.join(home, p.slice(8))
	return p
}

function normalize(abs: string): string {
	const n = path.posix.normalize(abs)
	return n.length > 1 ? n.replace(/\/+$/, "") : n
}

/** Does `abs` equal `root` or live under it? */
export function isUnder(abs: string, root: string): boolean {
	const a = normalize(abs)
	const r = normalize(root)
	return a === r || a.startsWith(r === "/" ? "/" : r + "/")
}

function homeRelative(abs: string, home: string): string | null {
	const h = normalize(home)
	const a = normalize(abs)
	if (a === h) return ""
	if (a.startsWith(h + "/")) return a.slice(h.length + 1)
	return null
}

export function classifyPath(rawIn: string, ctx: PathContext): PathClass {
	const raw = rawIn
	let p = raw.trim()
	// strip surrounding quotes left by tools that pass strings through
	p = p.replace(/^["']|["']$/g, "")
	const base: PathClass = {
		abs: null, raw, insideProject: false, isProjectRoot: false, isNeverWipe: false, isSecret: false, isTemp: false,
		isSensitiveConfig: false, stagedConfig: false, isGitInternal: false, isDevice: false, unresolvedRoot: false, hasExpansion: false,
	}
	if (!p) return base

	// Unexpanded variable/command substitution at the root of the path.
	const expansionAtRoot = /^\$(?!HOME\b|\{HOME\})|^`/.test(p)
	const globAtRoot = /^[*?]/.test(p) || p === "./*" || p === "*" || p === ".*"
	if (expansionAtRoot) {
		base.unresolvedRoot = true
		base.hasExpansion = true
		// `$X/...` — could be anything, including `/`. Callers treat as unresolved.
		return base
	}
	if (/\$[A-Za-z_{(]|`/.test(p)) base.hasExpansion = true

	p = expandTilde(p, ctx.home)
	if (globAtRoot) {
		// `*` / `./*` — the current directory's contents.
		base.abs = normalize(ctx.cwd)
	} else {
		// Drop a trailing glob component for classification ("./build/*" → ./build)
		const globIdx = p.search(/[*?[]/)
		let head = globIdx === -1 ? p : p.slice(0, globIdx)
		if (globIdx !== -1) {
			const lastSlash = head.lastIndexOf("/")
			head = lastSlash === -1 ? "." : head.slice(0, lastSlash) || "/"
		}
		base.abs = normalize(path.isAbsolute(head) ? head : path.resolve(ctx.cwd, head))
	}
	const abs = base.abs
	const project = normalize(ctx.project)
	const home = normalize(ctx.home)

	base.insideProject = isUnder(abs, project)
	base.isTemp = ["/tmp", "/var/tmp", "/dev/shm"].some((t) => abs !== t && isUnder(abs, t))
	base.isProjectRoot = abs === project || (globAtRoot && normalize(ctx.cwd) === project)
	base.isGitInternal = base.insideProject && (abs === path.posix.join(project, ".git") || abs.startsWith(path.posix.join(project, ".git") + "/"))
	base.isDevice = DEVICE_RE.test(abs) && abs !== "/dev/null"

	const basename = path.posix.basename(abs)
	const hrel = homeRelative(abs, home)

	// Secret-bearing?
	const exampleFile = SECRET_EXAMPLE_RE.test(basename)
	if (listedCredentialFilename(basename) && !exampleFile) base.isSecret = true
	// D18: a name that declares credentials is secret-bearing wherever it sits, including here in the
	// project. Added *beside* the reviewed table, never in place of it, and only where the token is a
	// file reference rather than a bare word the command is searching for.
	const shapeWord = credentialNameWord(basename)
	const userDb = shapeWord === "passwd" && UNIX_USER_DB_PATHS.has(abs)
	if (!base.isSecret && !exampleFile && shapeWord !== null && !userDb && addressesAFile(p, basename)) base.isSecret = true
	if (hrel !== null) {
		for (const d of SECRET_DIRS_UNDER_HOME) {
			if (hrel === d || hrel.startsWith(d + "/")) {
				// known_hosts / config under ~/.ssh are sensitive config, not secrets
				if (d === ".ssh" && (basename === "known_hosts" || basename === "config")) break
				if (NON_SECRET_UNDER_HOME.has(hrel)) break
				base.isSecret = true
			}
		}
	}
	if (abs === "/etc/shadow" || abs === "/etc/gshadow" || abs.startsWith("/etc/sudoers")) base.isSecret = true

	// Sensitive config?
	if (hrel !== null) {
		if (SENSITIVE_HOME_FILES.has(hrel)) base.isSensitiveConfig = true
		for (const d of [".ssh", ".config/systemd", ".config/autostart", ".config/fish", ".gnupg", ".aws", ".kube", ".docker", ".pi", ".claude", ".config/gh", "Library/LaunchAgents"]) {
			if (hrel === d || hrel.startsWith(d + "/")) base.isSensitiveConfig = true
		}
	}
	// "Sensitive config" is a statement about the MACHINE, not about a filename: the harm is that some
	// other process reads this file and it takes effect. A repository's own copy is inert staged source.
	// `deploy/systemd/pw-build.timer` becomes a live unit only when a later step installs it, and that
	// step is gated in its own right (`system_config`, `network_send`, `vcs_remote`) — so the check moves
	// to where the harm actually is rather than loosening it. An in-project match is therefore recorded
	// as `stagedConfig` (ALLOW) and stays `isSensitiveConfig` (ASK) only where the file really is live:
	// outside the project, or inside one whose root is itself a config location.
	const looksLikeConfigLocation = SENSITIVE_SYSTEM_PREFIXES.some((pre) => isUnder(abs, pre)) || CONFIG_DIR_SEGMENT_RE.test(abs)
	if (looksLikeConfigLocation) {
		if (base.insideProject && !projectIsLiveConfig(project, home)) base.stagedConfig = true
		else base.isSensitiveConfig = true
	}

	// NEVER-wipe?
	const never = new Set(SYSTEM_ROOTS.map(normalize))
	if (never.has(abs)) base.isNeverWipe = true
	if (abs === home) base.isNeverWipe = true
	if (hrel !== null && hrel !== "") {
		const first = hrel.split("/")[0]!
		if (HOME_NEVER_SUBDIRS.includes(first) && !hrel.includes("/")) base.isNeverWipe = true
	}
	// Any ancestor of the project (including the project root itself) is never wiped.
	if (isUnder(project, abs)) base.isNeverWipe = true
	// Top-level home entries that are directories holding other projects are covered above;
	// wiping the parent of a project is always the project's parent chain → covered by isUnder.
	return base
}

/**
 * Is the project root itself a live config location? A dotfiles repo opened at `~/.config`, or an
 * infra repo opened at `/etc/nginx`, holds files that take effect exactly where they sit — the
 * project-relative downgrade in `classifyPath` must not apply there, or "it's in the project" would
 * become a blanket bypass. Without this guard the fix would be wrong for precisely the repos whose
 * whole job is editing machine config.
 */
export function projectIsLiveConfig(project: string, home: string): boolean {
	if (SENSITIVE_SYSTEM_PREFIXES.some((pre) => isUnder(project, pre))) return true
	const hrel = homeRelative(project, normalize(home))
	if (hrel === null) return false
	if (hrel === "") return true // the project *is* the home directory
	return (hrel.split("/")[0] ?? "").startsWith(".") // ~/.ssh, ~/.config, ~/.aws …
}

/** Human-readable short form for prompts/entities. */
export function displayPath(pc: PathClass, ctx: PathContext): string {
	if (!pc.abs) return pc.raw
	if (pc.raw === "." || pc.raw === "./" || pc.raw === "*" || pc.raw === "./*") return pc.raw
	const rel = path.posix.relative(normalize(ctx.project), pc.abs)
	if (pc.insideProject) return rel === "" ? "." : `./${rel}`
	const hrel = homeRelative(pc.abs, ctx.home)
	if (hrel !== null) return hrel === "" ? "~" : `~/${hrel}`
	return pc.abs
}
