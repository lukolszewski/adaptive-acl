/**
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
import { classifyPath, isCredentialFilename, type PathContext } from "./risk-paths.ts"
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
		expect(read("/tmp/notes.txt").tier).toBe("allow")
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
	it("reads /etc/passwd the way it always has", () => {
		// The hashes are in /etc/shadow (secret by name for years) and this file is world-readable by
		// design; index.test.ts pins that a read of it auto-approves in auto mode. Nothing loosened:
		// `/etc/passwd` was never secret here, and the exemption is this one word at this one path.
		for (const p of ["/etc/passwd", "/etc/passwd-", "/private/etc/passwd", "/etc/master.passwd"]) {
			expect(cls(p).isSecret, p).toBe(false)
			expect(read(p).tier, p).toBe("allow")
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

	it("is not the source of the pattern noise the reviewed table already had", () => {
		// `tokens?` and `credentials` are on the table, and the table has never looked at whether the
		// token it matched was a file. Measured identical before and after the word-shape rule — pinned
		// so the two are not confused, and so fixing it is a decision about the table, not a regression
		// report against this file.
		for (const c of ["grep -c token README.md", "grep -c credentials src/app.ts", "grep -rn credentials src/"]) {
			expect(evaluateBash(c, OPTS).category, c).toBe("read_secret")
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
