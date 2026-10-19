/**
 * Redact likely secrets before text leaves for a classifier provider (transcript, AGENTS.md, tool
 * projection). Every rule keeps the credential's *name* — key, flag, header, token prefix, armour
 * line — and masks only its value, so the classifier still sees that a credential was passed while
 * the credential itself does not.
 *
 * Two properties hold for the whole set and every rule is written to keep them:
 *  - specific before generic: a value recognised by its own shape (`sk-…`, a PEM armour) is masked
 *    before the rules that recognise it by the name beside it, so the informative mask wins;
 *  - idempotent: every value position refuses a value that already begins with the mask, so
 *    running the set twice cannot change its output.
 *
 * Precision over recall, because this runs on every prompt: a name has to *be* a credential word
 * (or end in one) rather than merely contain one, and a value that is a path, a number or a run of
 * punctuation is left alone. `token_file=…`, `author_name: …` and `x_key = 100//3` name things
 * about a credential; masking their values hides the command without protecting anything.
 */

const MASK = "[REDACTED]"

/**
 * A value that is not a credential: an earlier mask (including one a more specific rule left behind
 * a `sk-`/`hf_` prefix in front of), a shell expansion (`$T`, `${T}`) or a null-ish word. Masking
 * those only hides the shape of the command, so it buys nothing.
 */
const REAL_VALUE = String.raw`(?!\[|\$\{?)(?![^\s]*\[REDACTED\])(?!(?:true|false|null|none|nil|undefined|empty)\b)`

/** Auth schemes that sit in front of the value in an `Authorization:` header. */
const AUTH_SCHEME = String.raw`basic|bearer|token|digest|ntlm|negotiate`

/**
 * A value that is a path, a number or a run of filler (`-----`, `=====`) is data about the key,
 * not a secret. Used where the key alone does not already prove the value is a credential.
 */
const NOT_A_CREDENTIAL_VALUE = String.raw`(?![~./])(?!\d+(?:[\s,;'"}\]]|[/.]|$))(?![=\-*_~#]{4,})`

/** The words that make a name credential-bearing. `auth` deliberately will not absorb `author`. */
const SECRET_ROOT = String.raw`passw(?:or)?d|passwd|pwd|secret|token|credential|auth(?:orization|isation)?`

/**
 * A name that *ends* in a credential word (`DB_PASSWORD`, `access_token`, `API_KEY`,
 * `http.password`) or in `_KEY_ID` (which is the credential's own identifier), singular or plural.
 * The end anchor is the precision: `token_file`, `auth_url` and `keyboard` name a thing about a
 * credential, not one.
 */
const SECRET_NAME = String.raw`[A-Za-z0-9_.-]*(?:${SECRET_ROOT}|api[_-]?key|[A-Za-z0-9.-]*[_-]key)(?:[_-]id)?s?(?![A-Za-z0-9_-])`

/** Name, then its separator, then an optional opening quote — all of it kept in the output. */
const ASSIGN = String.raw`${SECRET_NAME}["']?[ \t]*[:=][ \t]*["']?`

/** Clients for which `-p` is a password. For `psql`, `ssh`, `docker -p` and friends it is a port. */
const P_IS_PASSWORD = String.raw`mysql|mariadb|mysqladmin|mysqldump`

/** One ordered substitution. `to` echoes the captured name so it survives its own value. */
interface Rule {
	/** What it matches, and the audit class that measures it. */
	readonly note: string
	readonly re: RegExp
	readonly to: string
}

const RULES: readonly Rule[] = [
	{
		// token-openai — `sk-…` keys; the prefix survives so the provider is still recognisable.
		note: "openai-style sk- key",
		re: /\bsk-[a-zA-Z0-9_-]{16,}\b/g,
		to: `sk-${MASK}`,
	},
	{
		// bearer-token — `Bearer <value>`, alone or behind an `Authorization:` header.
		note: "bearer scheme value",
		re: /\bBearer\s+[A-Za-z0-9._-]+\b/gi,
		to: `Bearer ${MASK}`,
	},
	{
		// key-value (JSON) — `"token": "…"`, `"api_key": "…"`, `"password": "…"`.
		note: "json string value under a secret key",
		re: /"((?:api[_-]?key|token|password))"\s*:\s*"[^"]*"/gi,
		to: `"$1":"${MASK}"`,
	},
	{
		// key-value (JSON) — the same three keys with a non-string value.
		note: "json non-string value under a secret key",
		re: /"((?:api[_-]?key|token|password))"\s*:\s*(?!")[^,\s}\]]+/gi,
		to: `"$1":"${MASK}"`,
	},
	{
		// key-value — the same three keys at any separator, unquoted.
		note: "bare api_key/token/password assignment",
		re: /\b(api[_-]?key|token|password)\s*[:=]\s*\S+/gi,
		to: `$1=${MASK}`,
	},
	{
		// pem-block — mask the body of an armour, keep both armour lines.
		note: "private key armour body",
		re: /(-{5}BEGIN[A-Z0-9 ]{0,40}-{5})([\s\S]*?)(-{5}END[A-Z0-9 ]{0,40}-{5})/g,
		to: `$1\n${MASK}\n$3`,
	},
	{
		// ssh-public-key — `ssh-ed25519 AAAA… comment`: mask the base64, keep type and comment.
		note: "ssh public key material",
		re: /\b(ssh-(?:rsa|ed25519|dss|ecdsa(?:-sha2-nistp\d+)?))([ \t]+)(?!\[)[A-Za-z0-9+/]{16,}={0,2}/g,
		to: `$1$2${MASK}`,
	},
	{
		// token-huggingface — `hf_…`.
		note: "huggingface token",
		re: /\b(hf_)[A-Za-z0-9]{20,}/g,
		to: `$1${MASK}`,
	},
	{
		// token-github — `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`.
		note: "github token",
		re: /\b(gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}/g,
		to: `$1${MASK}`,
	},
	{
		// token-google — `AIza…`; a real key is AIza + 35, a shorter run is still a keyed blob.
		note: "google api key",
		re: /\b(AIza)[0-9A-Za-z_-]{20,}/g,
		to: `$1${MASK}`,
	},
	{
		// auth-header — `Authorization: …`, `Proxy-Authorization: …`, `X-Api-Key: …`, and the
		// `curl -H "Authorization: …"` form, auth scheme included. The two guards keep this rule off
		// a value the bearer rule above has already masked.
		note: "http auth header value",
		re: new RegExp(
			String.raw`\b(authorization|proxy-authorization|x-api-key|x-auth-token|www-authenticate)` +
				String.raw`[ \t]*[:=][ \t]*["']?[ \t]*(?!\[|\$\{?)(?!(?:${AUTH_SCHEME})[ \t]*\[)` +
				String.raw`(?:(?:${AUTH_SCHEME})[ \t]+)?(?!\[|\$\{?)[^\s,;'"}]+`,
			"gi",
		),
		to: `$1=${MASK}`,
	},
	{
		// url-userinfo — `scheme://user:pass@host`: mask the password only, keep user and host.
		note: "url password",
		re: /\b([a-z][a-z0-9+.-]{1,12}:\/\/[^\s/@:]*:)(?!\[)[^\s/@,;'"`]{1,}@/gi,
		to: `$1${MASK}@`,
	},
	{
		// env-export — `export NAME=…` and `env NAME=… cmd` when NAME names a secret. No value
		// guard here: a variable whose name is `*_TOKEN` holds a credential whatever it is set to.
		note: "exported secret variable",
		re: new RegExp(
			String.raw`\b((?:export|env)[ \t]+[A-Za-z0-9_]*(?:${SECRET_NAME})[ \t]*=[ \t]*)${REAL_VALUE}[^\s;|&'"]+`,
			"gi",
		),
		to: `$1${MASK}`,
	},
	{
		// cli-flag-value — `--password v`, `--password=v`, `--token v`, `--api-key v`. A flag whose
		// name merely mentions a credential (`--token-file`) is not one.
		note: "long cli flag with a secret value",
		re: new RegExp(
			String.raw`(--(?:[a-z0-9]+-)*(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential|private[_-]?key|auth|authorization))([ \t=]+)${REAL_VALUE}(?!--)[^\s;|&]+`,
			"gi",
		),
		to: `$1$2${MASK}`,
	},
	{
		// cli-short-p — `-p<value>` / `-p <value>` behind a client that reads a password there.
		note: "short -p password flag",
		re: new RegExp(
			String.raw`\b((?:${P_IS_PASSWORD})\b[^\n]*?[ \t]-p)([ \t]*)(?!\[|\$)(?!--)[^\s;|&]+`,
			"gi",
		),
		to: `$1$2${MASK}`,
	},
	{
		// key-value — any `NAME=value`, `name: value` or `?name=value` whose NAME names a secret and
		// whose value is not a path, a number or filler.
		note: "assignment to a secret-named key",
		re: new RegExp(
			String.raw`(?<![A-Za-z0-9_-])(${ASSIGN})${REAL_VALUE}${NOT_A_CREDENTIAL_VALUE}[^\s,;&'"}\]]{4,}`,
			"gi",
		),
		to: `$1${MASK}`,
	},
]

/** Apply every rule in order. Each is one scan, so ordinary text costs a pass per rule. */
function maskAll(text: string): string {
	let out = text
	for (const rule of RULES) out = out.replace(rule.re, rule.to)
	return out
}

/** Keep the head and the tail of an over-long context, dropping the middle. */
function clamp(redacted: string, limit: number): string {
	if (!Number.isFinite(limit) || redacted.length <= limit) return redacted
	const tailLen = Math.min(1000, Math.floor(limit / 3))
	const headLen = limit - tailLen - 15
	return (
		redacted.slice(0, headLen) +
		"\n...[truncated]...\n" +
		redacted.slice(-tailLen)
	)
}

export function redactForClassifier(text: string, limit = 4000): string {
	return clamp(maskAll(text), limit)
}
