/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Bare secret-bearing filenames.
 *
 * A file whose NAME ALONE declares it holds credentials — `pass`, `passphrase`, `secrets`,
 * `api_key`, `.env.local` — is secret-bearing wherever it sits, so reading it is `ask` under the
 * category `~/.ssh/id_rsa` already uses. No new category, no new tier, and deliberately not the
 * never floor: reading your own project's credential file is ordinary work that one approval, or a
 * grant derived from the user's own words, can cover.
 *
 * The half that decides whether this feature survives a real project is the noise rule: a file that
 * merely *talks about* or *handles* credentials is not one. `src/password.ts`, `docs/secrets.md`,
 * `lib/tokenizer.py` and `grep -r password src/` all stay readable, and a rule that flagged them
 * would get itself switched off — so every positive here has its negative twin in the same block.
 * The twins are the specification; the word lists in `risk-paths.ts` are the implementation.
 */

import { describe, expect, it } from "vitest"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, delimiter } from "node:path"
import { classifyPath, isCredentialFilename, kubeContexts, type PathContext } from "./risk-paths.ts"
import { evaluateBash, type PolicyOptions } from "./risk-policy.ts"
import { addGrant, createGrantStore, grantsCover } from "./session-grants.ts"

const CTX: PathContext = { cwd: "/home/dev/site", project: "/home/dev/site", home: "/home/dev" }
const OPTS: PolicyOptions = { ...CTX, fs: false }

const cls = (p: string) => classifyPath(p, CTX)
const read = (p: string) => evaluateBash(`cat ${p}`, OPTS)

/**
 * What "secret-bearing" has to buy, and nothing more: an `ask` in the existing `read_secret`
 * category, naming the file so the approval and the grant both have something to bind to.
 */
function expectSecret(p: string) {
	expect(cls(p).isSecret, p).toBe(true)
	const d = read(p)
	expect(d.tier, p).toBe("ask")
	expect(d.category, p).toBe("read_secret")
	expect(d.entities.filter((e) => e.kind === "target").map((e) => e.value), p).toHaveLength(1)
}

/** What an ordinary file has to keep: no secret flag, and a read the gate waves through. */
function expectOrdinary(p: string) {
	expect(cls(p).isSecret, p).toBe(false)
	expect(read(p).tier, p).toBe("allow")
}

/** Each pair: the file whose name is the secret, and the neighbour that only mentions it. */
const PAIRS: Array<[secret: string, ordinary: string]> = [
	["./pass", "./passctl"],
	["./passphrase", "./passage.md"],
	["./passwd", "./scripts/mypasswd.sh"],
	["./password", "./src/password.ts"],
	["./passwords", "./passwords.md"],
	["./secret", "./docs/password-policy.md"],
	["./secrets", "./docs/secrets.md"],
	["./credential", "./credential_store.py"],
	["./apikey", "./token_bucket.json"],
	["./api_key", "./sort_key.json"],
	["./htpasswd", "./key_cache.json"],
	["./.secrets", "./node_modules/key/index.js"],
]

describe("a name that is the credential is secret-bearing in the project", () => {
	for (const [secret, ordinary] of PAIRS) {
		it(`${secret} asks; ${ordinary} does not`, () => {
			expectSecret(secret)
			expectOrdinary(ordinary)
		})
	}

	it("fires on the name, not on a location — the project root included", () => {
		// The reviewed table in risk-paths.ts reaches for home directories; a repo's own `pass` was
		// never on it, which is the gap this closes.
		expect(isCredentialFilename("pass")).toBe(true)
		expect(cls("./pass").insideProject).toBe(true)
		expectSecret("./config/passwords")
		expectOrdinary("./src/pass/index.ts")
	})

	it("keeps working outside the project without moving anything into the never floor", () => {
		expectSecret("/srv/data/pass")
		expectSecret("/tmp/pass")
		expectSecret("./secrets/api.key")
		// An ordinary file outside the project is no longer free — it asks as a
		// read. What this test still protects is that the SECRET rule stays a category and never a floor: same
		// tier, different name, and `rm -rf /` is still the only never here.
		const ordinary = read("/tmp/notes.txt")
		expect(ordinary.tier).toBe("ask")
		expect(ordinary.category).toBe("read_only")
		// Deleting a secret asks (write_sensitive, as before); it is not a wipe of a protected root.
		for (const p of ["./pass", "./secrets"]) {
			const d = evaluateBash(`rm -rf ${p}`, OPTS)
			expect(d.tier, p).toBe("ask")
			expect(d.category, p).toBe("write_sensitive")
		}
		expect(evaluateBash("rm -rf /", OPTS).tier).toBe("never")
	})
})

describe("except where the word is the machine's own database", () => {
	it("reads /etc/passwd the way it always has — except it now asks", () => {
		// The hashes are in /etc/shadow (secret by name for years) and this file is world-readable by design, so
		// the point of this test is that `/etc/passwd` is NOT secret-bearing. The tier for everything
		// outside the project changed: an outside read is a prompt (`read_only`), which is why `index.test.ts`
		// now expects a prompt for it in auto mode too. Nothing here loosened: `isSecret` stays false for this
		// one word here.
		for (const p of ["/etc/passwd", "/etc/passwd-", "/private/etc/passwd", "/etc/master.passwd"]) {
			expect(cls(p).isSecret, p).toBe(false)
			const d = read(p)
			expect(d.tier, p).toBe("ask")
			expect(d.category, p).toBe("read_only")
		}
		expect(cls("/etc/shadow").isSecret).toBe(true)
	})

	it("still asks for the same word anywhere it is not the system database", () => {
		for (const p of ["./passwd", "/tmp/passwd", "./backup/etc/passwd"]) expectSecret(p)
	})
})

describe("recognition is by whole word, never by substring", () => {
	it("does not fire because a name happens to contain the letters", () => {
		for (const p of [
			"./passctl", "./passage.md", "./passgen.py", "./src/bypass.js", "./compass.json",
			"./keyboard.json", "./scripts/mypasswd.sh", "./token-bucket.go", "./passage/index.ts",
		]) expectOrdinary(p)
	})

	it("does fire when the word is the whole last word of the name", () => {
		for (const p of ["./pass", "./src/pass", "./archive/pass", "./notes/pass.txt"]) expectSecret(p)
	})

	it("treats separators — not just the empty string — as word boundaries", () => {
		expectSecret("./config/client_secret.json")
		expectSecret("./access_token.json")
		expectSecret("./aws_secret_access_key.txt")
		// The words in front of the credential word are irrelevant; the one at the end is decisive.
		expectOrdinary("./token_bucket.json")
		expectOrdinary("./password-policy.json")
	})
})

describe("code and documentation are not credential stores", () => {
	it("exempts source and prose by extension, whatever the name says", () => {
		for (const p of [
			"./src/password.ts", "./lib/tokenizer.py", "./docs/secrets.md", "./passwords.md",
			"./pass.go", "./tools/passgen.py", "./cmd/secrets/main.go", "./password-policy.md",
		]) expectOrdinary(p)
	})

	it("does not exempt the data extensions, which is the case the rule exists for", () => {
		for (const p of ["./pass.txt", "./passwords.txt", "./config/credentials.json", "./secrets.env"]) expectSecret(p)
	})
})

describe("`key` counts only behind a qualifier that names a credential", () => {
	it("fires on the qualified forms", () => {
		for (const p of ["./api_key", "./api-key", "./apikey", "./access_key.json", "./secret_key", "./signing_key"]) expectSecret(p)
	})

	it("stays off the generic ones, where `key` is not a credential", () => {
		for (const p of ["./key", "./sort_key.json", "./key_cache.json", "./keyboard.json", "./cache-key.txt"]) expectOrdinary(p)
	})
})

describe("a wrapping extension does not hide the name", () => {
	it("sees through archives and backups", () => {
		for (const p of ["./secrets.tar.gz", "./password.list.bak", "./pass.txt~", "./credentials.zip"]) expectSecret(p)
	})

	it("does not invent a secret in an ordinary archive", () => {
		for (const p of ["./notes.tar.gz", "./build.zip", "./notes.bak"]) expectOrdinary(p)
	})
})

describe("examples and templates hold no credential", () => {
	it("keeps the exemption the reviewed table already had", () => {
		for (const p of ["./.env.example", "./credentials.sample", "./secrets.template", "./password.dist"]) {
			expect(cls(p).isSecret, p).toBe(false)
			expect(read(p).tier, p).toBe("allow")
		}
	})

	it("still says the NAME declares a credential — it is the file that does not", () => {
		// Same split the table has always had: `isCredentialFilename` is about the name, `isSecret`
		// is about this file. `.env.example` has been on that side of the line from the start.
		expect(isCredentialFilename(".env.example")).toBe(true)
		expect(isCredentialFilename("credentials.sample")).toBe(true)
		expect(cls("./credentials.sample").isSecret).toBe(false)
		expect(cls("./credentials").isSecret).toBe(true)
	})
})

describe("searching for the word is not reading the file", () => {
	it("leaves grep and its pattern alone", () => {
		for (const c of ["grep -r password src/", "grep -rl secret .", "grep -rn password-policy src/", "grep -c apikey README.md"]) {
			const d = evaluateBash(c, OPTS)
			expect(d.tier, c).toBe("allow")
			expect(d.category, c).not.toBe("read_secret")
		}
	})

	it("is not the source of the pattern noise the reviewed table once had", () => {
		// `tokens?` and `credentials` are on the table, and the table never looked at whether the token it matched
		// was a file. It no longer does, because the argument is not one: a search tool's first operand is the
		// PATTERN (risk-handlers.ts `PATTERN_FIRST_BINS`), so the word is data and only the paths after it are
		// reads. Pinned as the opposite assertion, so the noise cannot come back without a test noticing.
		for (const c of ["grep -c token README.md", "grep -c credentials src/app.ts", "grep -rn credentials src/"]) {
			expect(evaluateBash(c, OPTS).category, c).not.toBe("read_secret")
		}
	})

	it("asks about the same name once something addresses it as a file", () => {
		// The one thing this trade costs: a bare, extensionless, directory-less token is ambiguous
		// between "the file" and "the word" — and the read-only-binary handler hands every positional
		// to the path classifier (risk-handlers.ts). Pinned so the miss is a decision, not an accident.
		expect(cls("password").isSecret).toBe(false)
		expect(cls("password").abs).not.toBeNull()
		expectSecret("./password")
	})
})

describe("an approval that names the file covers it", () => {
	it("is covered by a read_secret grant for that file, and by nothing broader by default", () => {
		const d = read("./pass")
		const named = createGrantStore()
		expect(grantsCover(named, d.category, d.entities, CTX.home, CTX.project).covered).toBe(false)
		addGrant(named, "read_secret", "./pass", "entity")
		expect(grantsCover(named, d.category, d.entities, CTX.home, CTX.project).covered).toBe(true)

		const other = createGrantStore()
		addGrant(other, "read_secret", "./other", "entity")
		expect(grantsCover(other, d.category, d.entities, CTX.home, CTX.project).covered).toBe(false)
	})
})

describe("the reviewed table is untouched", () => {
	it("still recognises the names it was written for, and still ignores the ones it dropped", () => {
		for (const n of [".env", ".env.local", ".env.production", "id_ed25519", "server.pem", "app.key", "tokens.json", "credentials.json", "kubeconfig", "shadow"]) {
			expect(isCredentialFilename(n), n).toBe(true)
		}
		// Dropped on purpose (they were written for one home location and flagged every project on
		// disk); the word-shape rule must not quietly put them back.
		for (const n of ["config.json", "hosts.yml", "index.ts", "main.rs", "notes.txt", "keys.md", "vault.txt"]) {
			expect(isCredentialFilename(n), n).toBe(false)
		}
		expectOrdinary("./config.json")
		expectOrdinary("./inventory/hosts.yml")
		expectOrdinary("./vault.txt")
	})
})

describe("provider CLI credential directories under home", () => {
	// Each entry is a directory one specific tool keeps a live key in; the negative twin on the same line
	// is the neighbour that merely shares its prefix, which a substring match would have swallowed.
	const LOCATIONS: Array<[secret: string, neighbour: string]> = [
		["~/.config/vastai/config.json", "~/.config/vastai/README.md"],
		["~/.config/rclone/rclone.conf", "~/.config/rclone/remotes/s3.conf"],
		["~/.config/op/config", "~/.config/op/item-cache.json"],
		["~/.config/doctl/config.yaml", "~/.config/doctl/context.json"],
		["~/.config/hcloud/config.toml", "~/.config/hcloud/active-context"],
		["~/.terraform.d/credentials.tfrc.json", "~/.terraform.d/requirements.tf"],
		["~/.cache/huggingface/token", "~/.cache/huggingface/hub/models--x/config.json"],
	]

	it("marks the location, not just the file whose name says credential", () => {
		for (const [secret, neighbour] of LOCATIONS) {
			// Both are inside the secret directory, so the location — not the filename — is what decides.
			expect(cls(secret).isSecret, secret).toBe(true)
			expect(cls(neighbour).isSecret, neighbour).toBe(true)
		}
	})

	it("reads them as read_secret, the category that already exists", () => {
		for (const [secret] of LOCATIONS) expectSecret(secret)
	})

	it("stops at the directory boundary — a shared prefix is not membership", () => {
		// `.config/op` must not reach `.config/openstatus`; `.cache/huggingface` must not reach
		// `.cache/huggingface-x`. Component comparison is the whole rule, so these stay ordinary.
		for (const p of ["~/.config/openstatus/config", "~/.config/doctlx/config.yaml", "~/.config/rclone-browser/profile", "~/.cache/huggingface-x/hub/config.json", "~/.config/gh-cli/config", "~/.terraform.d-x/plugin-cache/state.json"]) {
			expect(cls(p).isSecret, p).toBe(false)
		}
	})

	it("is a tightening: nothing the old list already covered changed, and the same paths read freely under a different home", () => {
		// Same table, another machine: `~` resolves through the injected context, so a session whose home is
		// not `/home/dev` sees these as ordinary files outside that home (they are not under `home` at all).
		const elsewhere = classifyPath("/srv/home/u/.config/rclone/rclone.conf", CTX)
		expect(elsewhere.isSecret).toBe(false)
		// …and the file the plugin itself owns is still not a secret even though `.pi/agent` is on the list.
		expect(cls("~/.pi/agent/adaptive-acl.json").isSecret).toBe(false)
	})
})

/**
 * The kubeconfig probe behind the `current_cluster` object (see `kubeContexts`).
 *
 * This is the one place that decides whether "my cluster" means anything on a given machine, and the file it
 * reads is written by a tool, not by us — so every layout below is copied from what a real `kubectl config view`
 * / hand-maintained kubeconfig looks like, with invented names and a stand-in token. Two properties are pinned
 * together: the COUNT of context entries (a one-context file must map, an ambiguous one must not) and the fact
 * that a kubeconfig also holds credentials, so no value but a context name may ever come out of it.
 */
describe("reading the kubeconfig for its contexts", () => {
	/** A kubeconfig in a temp dir: the probe then reads a file this test wrote, never the developer's cluster. */
	function kubeFile(text: string): { env: Record<string, string>; clean: () => void } {
		const dir = mkdtempSync(join(tmpdir(), "kubeconfig-"))
		const file = join(dir, "config")
		writeFileSync(file, text)
		return { env: { KUBECONFIG: file, HOME: dir }, clean: () => rmSync(dir, { recursive: true, force: true }) }
	}
	/** `kubectl config view` writes the name on its OWN line, at the item's field column, two past the dash. */
	const KUBECTL_STYLE = [
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
		"    token: STAND-IN-TOKEN",
	].join("\n")
	const KUBECTL_STYLE_TWO = [
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
	].join("\n")
	/** The layout a hand-edited file uses: the name on the dash line itself. */
	const NAME_ON_THE_DASH = ["contexts:", "- name: glint-alpha", "  context:", "    cluster: glint", "    user: glint-user", "current-context: glint-alpha"].join("\n")
	/** Some tools indent the whole list, so the dash is not at column 0 and the item's fields sit further in. */
	const INDENTED_LIST = ["contexts:", "  - context:", "      cluster: glint", "    name: alpha", "  - context:", "      cluster: glint", "    name: beta", "current-context: alpha"].join("\n")

	it("counts the entries kubectl's own layout declares", () => {
		const fx = kubeFile(KUBECTL_STYLE)
		try {
			expect(kubeContexts(fx.env.HOME, fx.env)).toEqual({ contexts: ["prod"], entries: 1, current: "prod" })
		} finally {
			fx.clean()
		}
	})

	it("counts them in the layouts kubectl does NOT write, the same way", () => {
		// One rule, not one branch per style: an item, and its name wherever that item carries it.
		for (const [layout, expected] of [[NAME_ON_THE_DASH, ["glint-alpha"]], [INDENTED_LIST, ["alpha", "beta"]]] as Array<[string, string[]]>) {
			const fx = kubeFile(layout)
			try {
				expect(kubeContexts(fx.env.HOME, fx.env).contexts, layout).toEqual(expected)
				expect(kubeContexts(fx.env.HOME, fx.env).entries, layout).toBe(expected.length)
			} finally {
				fx.clean()
			}
		}
	})

	it("keeps the count at the contexts section — the `clusters:` and `users:` lists also hold `- name:` items", () => {
		// Those two lists are the reason the section boundary matters: KUBECTL_STYLE holds four `- name:` items in
		// total, so counting lines instead of entries would call this file ambiguous and "my cluster" would
		// never map — or, in a file with no contexts at all, would invent a referent from a USER's name.
		const fx = kubeFile(KUBECTL_STYLE)
		try {
			expect(kubeContexts(fx.env.HOME, fx.env).entries).toBe(1)
			expect(kubeContexts(fx.env.HOME, fx.env).contexts).toEqual(["prod"])
		} finally {
			fx.clean()
		}
		for (const layout of ["users:\n- name: only-a-user\n", "clusters:\n- name: only-a-cluster\n", "contexts: []\nusers:\n- name: u1\n- name: u2\n"]) {
			const fx2 = kubeFile(layout)
			try {
				expect(kubeContexts(fx2.env.HOME, fx2.env), layout).toEqual({ contexts: [], entries: 0 })
			} finally {
				fx2.clean()
			}
		}
	})

	it("takes the name from the entry's own line, not from the map nested inside it", () => {
		// `name` inside `context:` belongs to that map; reading it would put a cluster or user name in the ledger
		// as if it were the context, which is a different object than the one the user agreed to.
		const fx = kubeFile(["contexts:", "- context:", "    name: INNER-VALUE", "    cluster: glint", "  name: prod", "current-context: prod"].join("\n"))
		try {
			const found = kubeContexts(fx.env.HOME, fx.env)
			expect(found).toEqual({ contexts: ["prod"], entries: 1, current: "prod" })
			expect(JSON.stringify(found)).not.toContain("INNER-VALUE")
		} finally {
			fx.clean()
		}
	})

	it("answers names and the current context, and nothing else the file holds", () => {
		// A kubeconfig is a credential store. Whatever the layout, no token, certificate or server address may
		// reach the caller — the ledger row, the prompt and the log all print what this returns.
		const fx = kubeFile(`${KUBECTL_STYLE_TWO}\nusers:\n- name: glint-user\n  user:\n    token: STAND-IN-TOKEN\n    client-certificate-data: Zm9vYmFyCg==\nclusters:\n- cluster:\n    server: https://glint.invalid\n  name: glint\n`)
		try {
			const found = JSON.stringify(kubeContexts(fx.env.HOME, fx.env))
			expect(found).toContain("prod")
			expect(found).toContain("staging")
			for (const secret of ["STAND-IN-TOKEN", "Zm9vYmFyCg==", "glint.invalid", "certificate"]) {
				expect(found, secret).not.toContain(secret)
			}
		} finally {
			fx.clean()
		}
	})

	it("a KUBECONFIG that names several files adds their entries together", () => {
		// `$KUBECONFIG` is a list, and kubectl merges the files in order. Two files with one context each are TWO
		// referents, so "my cluster" is ambiguous even though no single file looks ambiguous — the narrow answer.
		const dir = mkdtempSync(join(tmpdir(), "kubeconfig-"))
		const a = join(dir, "a")
		const b = join(dir, "b")
		writeFileSync(a, "contexts:\n- name: glint-alpha\ncurrent-context: glint-alpha\n")
		writeFileSync(b, "contexts:\n- name: glint-beta\n")
		try {
			expect(kubeContexts(dir, { KUBECONFIG: `${a}${delimiter}${b}` })).toEqual({ contexts: ["glint-alpha", "glint-beta"], entries: 2, current: "glint-alpha" })
			// …and the first file's current-context wins, the way kubectl reads them.
			expect(kubeContexts(dir, { KUBECONFIG: `${b}${delimiter}${a}` }).current).toBe("glint-alpha")
		} finally {
			rmSync(dir, { recursive: true, force: true })
		}
	})

	it("stays ambiguous when an entry has no readable name, and when the file is not there", () => {
		// An entry we cannot name is still another cluster the sentence could mean, so it must not narrow the file
		// down to the one entry we happen to read — and every failure mode answers "nothing", which costs a prompt.
		const unnamed = kubeFile(["contexts:", "- context:", "    cluster: glint", "current-context: glint"].join("\n"))
		try {
			expect(kubeContexts(unnamed.env.HOME, unnamed.env)).toEqual({ contexts: [], entries: 1, current: "glint" })
		} finally {
			unnamed.clean()
		}
		const empty = kubeFile("apiVersion: v1\nkind: Config\ncontexts: []\ncurrent-context: \"\"\n")
		try {
			expect(kubeContexts(empty.env.HOME, empty.env)).toEqual({ contexts: [], entries: 0 })
		} finally {
			empty.clean()
		}
		expect(kubeContexts("/nonexistent-home", { KUBECONFIG: "/nonexistent-home/config" })).toEqual({ contexts: [], entries: 0 })
		// The `fs: false` switch: a unit test never reads the machine's real kubeconfig.
		expect(kubeContexts("/home/dev", { KUBECONFIG: "/dev/null" }, false)).toEqual({ contexts: [], entries: 0 })
	})
})
