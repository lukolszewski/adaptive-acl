import { describe, expect, it } from "vitest"

import { redactForClassifier } from "./classifier-redact.ts"

/**
 * Synthetic strings only — every "secret" here was invented for this file. Assertions look at the
 * mask, at what survived beside it, and (for the negative cases) at the text coming back byte
 * identical, so a regression shows up as the class it belongs to instead of as a diff in one long
 * string. Long blobs are joined from short pieces, so nothing here reads like a key that existed.
 */

const r = (text: string): string => redactForClassifier(text, Number.POSITIVE_INFINITY)

const BLOB = ["aB3d", "E6fG", "9hI2", "kL5m", "N8oP", "qR7s"].join("")
const PASS = ["Sup3r", "Passw0rd"].join("")

/** Masked, and the name that owns the secret is still there. */
const masked = (text: string, keeps: string[]): void => {
	const out = r(text)
	expect(out).toContain("[REDACTED]")
	for (const keep of keeps) expect(out).toContain(keep)
}

/** Byte-identical: an ordinary command must come back exactly as it went in. */
const untouched = (text: string): void => {
	expect(r(text)).toBe(text)
}

describe("redactForClassifier - credential-shaped tokens", () => {
	it("masks openai-style keys and keeps the prefix", () => {
		masked(`OPENAI_KEY=sk-${BLOB}`, ["OPENAI_KEY=", "sk-[REDACTED]"])
	})

	it("masks huggingface tokens", () => {
		masked(`hf_${BLOB}`, ["hf_", "[REDACTED]"])
		const out = r(`huggingface-cli login --token hf_${BLOB}`)
		expect(out).toContain("[REDACTED]")
		expect(out).not.toContain(BLOB)
		// a short `hf_` run is a filename or a stem, not a token
		untouched("ls hf_models")
	})

	it("masks github tokens of every prefix and keeps the prefix", () => {
		for (const prefix of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) {
			masked(`gh auth token ${prefix}${BLOB}`, [prefix, "[REDACTED]"])
		}
		masked(`token github_pat_11FAKE${BLOB}`, ["github_pat_", "[REDACTED]"])
		// behind `export` the env rule owns the whole value, so the prefix goes with it
		expect(r(`export GITHUB_TOKEN=github_p…BLOB}`)).toBe("export GITHUB_TOKEN=[REDACTED]")
		untouched("grep -r 'gh_' src/")
	})

	it("masks google api keys", () => {
		masked(`curl 'https://maps.test/x?key=AIzaSy-${BLOB}1'`, ["AIza", "[REDACTED]"])
		untouched("echo AIzaShort")
	})

	it("masks ssh key material but keeps the type and the comment", () => {
		const base64 = ["AAAAC3NzaC1l", "ZDI1NTE5AAAA", "IFakeBlobForTests0"].join("")
		const out = r(`cat id_ed25519.pub # ssh-ed25519 ${base64} deploy@laptop`)
		expect(out).toContain("ssh-ed25519")
		expect(out).toContain("deploy@laptop")
		expect(out).toContain("[REDACTED]")
		expect(out).not.toContain(base64)
		untouched("ssh-keygen -t ed25519 -C me@example.com")
	})

	it("masks a private key body and keeps the armour lines", () => {
		const body = ["cmFuZG9tYm9keWxpbmVvbmVGb3J0ZXN0aW5n", "YW5vdGhlckxpbmUyRm9yVGVzdGluZw=="].join("\n")
		const key = ["-----BEGIN OPENSSH PRIVATE KEY-----", body, "-----END OPENSSH PRIVATE KEY-----"].join("\n")
		const out = r(key)
		expect(out).toContain("-----BEGIN OPENSSH PRIVATE KEY-----")
		expect(out).toContain("-----END OPENSSH PRIVATE KEY-----")
		expect(out).not.toContain("cmFuZG9tYm9keWxpbmVvbmVGb3J0ZXN0aW5n")
		expect(out.match(/\[REDACTED\]/g)).toHaveLength(1)
		untouched("grep -n 'BEGIN' ssh-keygen.1")
	})
})

describe("redactForClassifier - assignments", () => {
	it("masks key=value whose key names a secret, keeping the key", () => {
		masked(`DB_PASSWORD=${PASS}`, ["DB_PASSWORD=", "[REDACTED]"])
		masked("client_secret: aBcDeFgHiJkL", ["client_secret", "[REDACTED]"])
		masked("aws_access_key_id=AKIAIOSFODNN7FAKE1", ["aws_access_key", "[REDACTED]"])
		masked(`{"db_password": "${PASS}"}`, ["db_password", "[REDACTED]"])
	})

	it("masks env-style *_TOKEN / *_SECRET / *_KEY / *_PASSWORD names", () => {
		for (const name of ["APP_TOKEN", "APP_SECRET", "SIGNING_KEY", "ADMIN_PASSWORD"]) {
			masked(`${name}=v4lu3-Str1ng`, [name, "[REDACTED]"])
		}
	})

	it("masks export and env assignments", () => {
		masked(`export GH_TOKEN=${BLOB}`, ["export GH_TOKEN=", "[REDACTED]"])
		masked(`env STRIPE_SECRET_KEY=${BLOB} node server.js`, ["env STRIPE_SECRET_KEY=", "node server.js"])
	})

	it("masks a password in a URL query", () => {
		const out = r(`curl 'https://api.test/q?user=acct&x=1&password=${PASS}'`)
		expect(out).toContain("password=[REDACTED]")
		expect(out).not.toContain(PASS)
		expect(out).toContain("user=acct")
		expect(out).toContain("x=1")
	})

	it("leaves a name that only mentions a credential alone", () => {
		untouched("cat token.txt")
		untouched("./deploy --token-file ./secrets/token.file")
		untouched("-- token_count: 42")
		untouched("author_name: Jordan Doe")
		untouched("sed -i 's/authentication/verification/' app.js")
	})

	it("leaves a value that is a path, a number or filler alone", () => {
		untouched("token_path=/etc/app/tokens")
		untouched("key_file: ./keys/deploy")
		untouched("x_key = 100//3")
		untouched("cache_key: 12345")
		untouched("echo '===== secret sauce ====='")
	})

	it("leaves an expansion and a null-ish value alone", () => {
		untouched("Authorization=$HEADER")
		untouched("db_password: ${VAULT_REF}")
		untouched("db_password = null")
	})
})

describe("redactForClassifier - flags and headers", () => {
	it("masks long flags with a secret value", () => {
		masked("mysqladmin --password= rootpw", ["--password=", "[REDACTED]"])
		masked("vault login -method=token token=abc123XYZ", ["token=", "[REDACTED]"])
		masked("curl --api-key aB3dE6fG9h https://api.test", ["--api-key", "[REDACTED]"])
	})

	it("masks -p only behind a client that reads a password there", () => {
		masked(`mysql -h db.internal -u root -p${PASS}`, ["mysql", "-p", "[REDACTED]"])
		masked("mariadb -u app -p 'An0therPass'", ["mariadb", "-p", "[REDACTED]"])
	})

	it("does not mask -p when it is a port", () => {
		untouched("docker run -p 8080:80 -d nginx")
		untouched("kubectl port-forward svc/web 8080:8080")
		untouched("ssh -p 2222 deploy@host.example")
		untouched("nc -p 31337 -l")
		untouched("psql -h db.internal -p 5432 -U app")
	})

	it("masks auth header values, including a scheme in front of them", () => {
		const basic = "dXNlcjpwYXNzd29yZA=="
		masked(`curl -H "Authorization: Basic ${basic}"`, ["Authorization", "[REDACTED]"])
		expect(r(`curl -H "Authorization: Basic ${basic}"`)).not.toContain(basic)
		masked('curl -H "X-Api-Key: aB3dE6fG9hI2" https://api.test', ["X-Api-Key", "[REDACTED]"])
		masked("Proxy-Authorization: NTLM GARBAGEBLOBHERE", ["Proxy-Authorization", "[REDACTED]"])
		expect(r("Proxy-Authorization: NTLM GARBAGEBLOBHERE")).not.toContain("GARBAGEBLOBHERE")
	})

	it("masks a url password and keeps the user and the host", () => {
		const out = r(`git clone https://ci-bot:${PASS}@git.test/team/app.git`)
		expect(out).toContain("https://ci-bot:[REDACTED]@git.test")
		expect(out).not.toContain(PASS)
	})

	it("keeps a url that carries a user but no password", () => {
		untouched("git clone ssh://git@git.test/team/app.git")
		untouched("psql postgres://app@db.internal:5432/maindb")
	})
})

describe("redactForClassifier - ordinary text and repeatability", () => {
	const ORDINARY = [
		"cd /home/dev/projects/web-app && npm test",
		"git status && git diff --stat HEAD~1",
		"grep -rn 'password' src/ --include=*.ts",
		"ls -la /var/log | tail -20",
		"python3 -c \"import json; print(json.dumps({'tokens': 12}))\"",
		"docker compose up -d --build",
		"cat README.md | head -40",
		'jq ".args[0]" payload.json',
		"export PATH=$PATH:/opt/tools/bin",
		"for f in *.png; do convert $f out/$f.jpg; done",
	]

	it("does not change ordinary commands", () => {
		for (const text of ORDINARY) expect(r(text)).toBe(text)
	})

	it("is idempotent over every shape it handles", () => {
		const CASES = [
			...ORDINARY,
			`export DB_PASSWORD=${PASS}`,
			"api_key: aB3dE6fG9h",
			`{"token": "${PASS}", "model": "x"}`,
			`curl -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" https://api.test`,
			`git clone https://ci-bot:${PASS}@git.test/team/app.git`,
			`mysql -u root -p${PASS} -e 'select 1'`,
			"cat id.pub # ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake0 deploy@laptop",
			"-----BEGIN PRIVATE KEY-----\ncmFuZG9tYm9keQ==\n-----END PRIVATE KEY-----",
			`key=hf_${BLOB} token=ghp_${BLOB}`,
			"Bearer abc.def.ghi",
		]
		for (const text of CASES) {
			const once = r(text)
			expect(r(once)).toBe(once)
		}
	})

	it("does not stack masks when run twice", () => {
		const text = `DB_PASSWORD=${PASS} api_key: aB3dE6fG9h file`
		const once = r(text)
		expect((once.match(/\[REDACTED\]/g) ?? []).length).toBe(2)
		expect(r(once).match(/\[REDACTED\]/g)).toHaveLength(2)
	})

	it("still redacts bearer tokens (pinned by classifier-client tests)", () => {
		expect(r("Bearer abc.def.ghi")).toContain("Bearer [REDACTED]")
	})

	it("truncation still keeps the tail", () => {
		const redacted = redactForClassifier(`${"a".repeat(5000)}; rm -rf /`)
		expect(redacted).toContain("rm -rf")
		expect(redacted).toContain("...[truncated]...")
	})
})
