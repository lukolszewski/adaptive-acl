# Auto-mode gate specification (v3 design)

## 0. Purpose and non-goals

The auto-mode gate decides, per tool call, whether the call may run without a human.
Its only job is to prevent **consequences the user did not intend**: destruction of data,
changes outside the project, changes to the machine or to other systems, exposure of the
machine or of private data, and irreversible operations. It is **not** a judge of societal
harm, ethics, or code quality, and it must never be asked to be one — that is not a task a
small model can do, and it is not what auto mode is for.

Design principle: **decide in code whatever can be decided in code; ask a model only the
narrowest remaining question; make every model answer machine-checkable.** The prior
evaluation (`~/dev/pitmp/classifier-isue.md`) showed that the single-shot "read this rubric
and judge" design fails on parseability, reproducibility and entity binding at every model
size, while extraction-style questions already work on a 4B model.

## 1. Outcomes

| outcome | what happens |
|---|---|
| **ALLOW** | tool call runs, nothing shown to the user beyond the normal tool output |
| **ASK** | needs authorisation; sources in order: permission rules → session grants (prompt-once memory) → transcript grant (model-extracted, code-verified) → prompt the user (UI) or deny with reason (no UI / `onBlock: "deny"`) |
| **NEVER** | never auto-approved; transcript intent and session grants cannot pre-authorise it. With a UI a loud confirmation prompt is shown (`onNever: "prompt"`, default); otherwise the agent gets a denial that states the reason. Only bypass mode or an explicit permission `allow` rule (which the dangerous-rule stripper does not remove) can skip the prompt |

Every ASK/NEVER decision carries a **category** and a list of **entities** (paths, images,
branches, hosts, packages, ports…) so the user sees *what* is being authorised and the grant
can be stored at the right granularity.

## 2. Deterministic policy (layer 0)

Runs first for every tool call. Bash commands are split into segments (`&&`, `||`, `;`, `|`,
newlines), each segment is tokenised (quotes honoured), leading wrappers are peeled
(`sudo`, `env VAR=x`, `timeout N`, `nice`, `nohup`, `command`, `exec`, `time`, `xargs` where
recognised), `cd` segments update the effective working directory for later segments, and
redirection targets are treated as writes — including a file named by an **output flag** rather than by
a redirect (§2.7). The overall decision for a compound command is
the **most restrictive** segment. Unrecognised commands, nested command substitution
(`$(...)`, backticks) feeding a mutating verb, inline interpreter code (`python -c`,
`node -e`, heredocs) and `eval` are **UNKNOWN** and go to the model (layer 1).

### 2.1 ALLOW (auto)

- Reading anywhere: `cat head tail less more wc stat file du df ls tree find grep rg fd
  diff sort uniq cut tr jq yq awk`-as-filter (see 2.4), `sed -n` without `w`, `which type
  env printenv uname whoami id date uptime ps top free nvidia-smi lsblk mount df`.
  Exception: reading **secret-bearing paths** (2.5) is ASK.
- pi tools `read/grep/find/ls` anywhere except secret-bearing paths.
- Writes (`edit`/`write`, `tee`, `>`/`>>`, `cp/mv/mkdir/touch/ln`) with **all targets inside
  the project directory**, except the project's `.git/` internals and secret-bearing files.
- Non-recursive `rm`/`rmdir`/`unlink` of paths inside the project (not `.git`, not secrets).
- Build/test/lint/format toolchains run inside the project: `npm/pnpm/yarn/bun run|test|ci
  |install|add|remove`, `npx`/`bunx` of known local tools (`prettier eslint tsc vitest jest
  biome vite next`…), `cargo build|check|test|clippy|fmt|add`, `go build|test|vet|fmt|mod|get`,
  `make`, `cmake --build`, `pytest`, `tox`, `ruff`, `black`, `mypy`, `gradle`, `mvn`,
  `dotnet build|test`, `uv sync|run|add`, `poetry install|run|add`, `pip install -e .`,
  `pip install -r requirements*.txt`, `pip install` when a venv is active (`VIRTUAL_ENV` set
  or `.venv/bin/pip` used).
- Running project code with user privileges: `node script.js`, `python file.py`,
  `bun`, `deno run`, `./script.sh`, `bash file.sh` — when the script is a file inside the
  project. (Inline code is UNKNOWN → model.)
- Local git that keeps history recoverable: `add commit status log diff show branch
  checkout switch merge rebase cherry-pick revert stash (push/pop/list) tag fetch pull
  remote -v config --get`, `git reset` without `--hard`, `git clean -n`.
- Docker read/build: `docker build|ps|images|logs|inspect|stats|compose (config|ps|logs|
  build)`.
- Cloud/cluster **read** verbs: `kubectl get|describe|logs|top|explain|config view|api-*`,
  `helm list|status|get|show|template`, `terraform plan|show|validate|fmt`, `aws|gcloud|az`
  `describe*|list*|get*`.
- Network **reads**: `curl`/`wget`/`http` GET to any host when the output is not piped to a
  shell and no upload flag is present (`-d --data* -F -T --upload-file -X POST|PUT|PATCH|
  DELETE`), `ping`, `dig`, `nslookup`, `nc -z`.
- Process inspection: `ps`, `pgrep`, `lsof`, `ss`, `netstat`, `strace -p` (read-only).
- `chmod`/`chown` on paths inside the project that do not add world-write (`o+w`, `777`).
- `sleep`, `echo`, `printf`, `true`, `false`, `test`, `[`, `cd`, `pwd`, `export`, `set`,
  `source`/`.` of project files.

### 2.2 ASK (user authorisation, entity-scoped)

| category | examples | entities |
|---|---|---|
| `delete_recursive` | `rm -r ./build`, `rm -rf node_modules`, `find … -delete` | paths |
| `delete_outside` | `rm ~/foo`, `rm /tmp/x` | paths |
| `write_outside` | `write ~/.config/x`, `> /tmp/out`, `cp a /opt/b`, `edit ../other/f` | paths (+ directory scope offered) |
| `write_sensitive` | shell profiles (`.bashrc .zshrc .profile`), `~/.ssh/*`, `~/.gitconfig`, crontab, `/etc/*`, **live** systemd units (`/etc/systemd`, `~/.config/systemd`), `.env*` — always a location where the file takes effect, never a filename seen inside the project (§2.6) | paths (+ directory scope offered) |
| `read_secret` | `cat ~/.ssh/id_ed25519`, `read ~/.aws/credentials`, `.env` | paths |
| `privilege` | `sudo <cmd>`, `su`, `doas`, `pkexec` — inner command re-classified; sudo of NEVER is NEVER | inner command |
| `package_system` | `apt|apt-get|dnf|yum|pacman|zypper|brew|snap|flatpak install|remove|upgrade`, `pip install --user/--system` (no venv), `npm i -g`, `cargo install`, `gem install`, `pipx install` | package names |
| `vcs_remote` | `git push` (any), `git remote add|set-url`, `gh pr create|merge`, `gh release create`, `git push --tags` | remote, branch |
| `vcs_discard` | `git reset --hard`, `git clean -f*`, `git checkout -- .`/`git restore .`, `git branch -D`, `git stash drop|clear`, `git push --force*`, `git rebase` onto pushed history is still ALLOW (recoverable via reflog) | branch/paths |
| `network_listen` | `python -m http.server`, `nc -l`, `ssh -R|-L|-D`, `ngrok`, `--host 0.0.0.0`, `docker run -p`, `kubectl port-forward` | port |
| `network_send` | `curl -d|-F|-T|-X POST…`, `scp`/`rsync` to `host:`, `ssh host cmd`, `aws s3 cp` to remote, `gh api -X POST`, `git push` (covered above) | host / URL |
| `remote_exec` | `curl … \| sh`, `wget -O- … \| bash`, `bash <(curl …)`, `npx <unknown pkg>`, `pip install git+https://…` | URL / package |
| `process_control` | `kill`, `pkill`, `killall`, `systemctl --user stop|restart`, `docker stop|restart` | pid / name |
| `system_config` | `systemctl start|stop|restart|enable|disable`, `service`, `ufw allow`, `iptables -A`, `sysctl -w`, `modprobe`, `mount`, `hostnamectl`, `timedatectl` | unit / rule |
| `container_mutation` | `docker rm|rmi|volume rm|network rm|container prune|image prune`, `docker compose down` (`-v` → entities include "volumes"), `docker run`/`exec` (host mounts or `--privileged`) | names |
| `cluster_mutation` | `kubectl delete|apply|patch|scale|rollout|drain|cordon|exec`, `helm install|upgrade|uninstall|rollback`, `terraform apply`, `aws|gcloud|az` mutating verbs (`create|delete|put|update|terminate|rm|mb|rb|sync`) | resource, namespace, bucket |
| `db_mutation` | `psql|mysql|sqlite3|mongosh|redis-cli` with `DROP|TRUNCATE|DELETE|ALTER|FLUSHALL` or `-c` non-SELECT | table / db |
| `perm_change` | `chmod`/`chown` outside project, `chmod 777`, `o+w`, `chmod -R` outside project | paths |
| `interpreter_unknown` | inline code the model could not classify as read-only/project-scoped | — |

### 2.3 NEVER (loud prompt or deny; not pre-authorisable)

- `rm -r`/`rm -rf`/`find -delete`/`shred` targeting: `/`, `/*`, `~`, `~/*`, `$HOME`, `/home`,
  `/root`, `/etc`, `/usr`, `/var`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/opt`, `/srv`, `/dev`,
  `/proc`, `/sys`, `..` (any parent of the project), the project root itself (`rm -rf .`,
  `rm -rf ./`, `rm -rf $PWD`), any glob that resolves to one of these, or `~/.ssh`,
  `~/.gnupg`, `~/.config`, `~/.local`, `~/Documents|Desktop|Pictures|…` wholesale.
- `dd`, `mkfs*`, `fdisk`, `parted`, `wipefs`, `sfdisk`, `blkdiscard`, writes to `/dev/sd*|nvme*|
  mmcblk*|loop*`, `> /dev/…` (except `/dev/null`).
- `reboot`, `shutdown`, `halt`, `poweroff`, `init 0|6`, `systemctl reboot|poweroff|halt|
  suspend|hibernate|kexec`, `telinit`.
- `kill -9 -1`, `kill -1`, `killall5`, `pkill -9 -u <user>` (all user processes), fork bombs
  (`:(){ :|:& };:`), `kill` of `pid 1`.
- `chmod -R 777 /`, `chown -R … /`, `chmod -R` on `/`, `~`, `/etc`, `/usr`.
- Firewall/security teardown: `iptables -F|-X|-P … ACCEPT`, `ufw disable`, `setenforce 0`,
  `systemctl stop|disable firewalld|ufw|apparmor|fail2ban`, `nft flush ruleset`.
- `crontab -r`, deleting `/etc/passwd|shadow|sudoers|fstab`, editing `/etc/sudoers` with
  `NOPASSWD:ALL`, appending keys to `~/.ssh/authorized_keys`, `visudo`.
- Credential/personal-data exfiltration: any `network_send`/`vcs_remote` whose payload or
  source path is a secret-bearing path (2.5) (`curl -d @~/.ssh/id_rsa …`, `scp ~/.aws/
  credentials host:`, `git add .env && git push`, `aws s3 cp ~/.ssh s3://…`), or uploads of
  `~`, `~/Documents` etc. wholesale.
- Cluster/cloud wide-blast: `kubectl delete namespace|node|--all|-A`, `kubectl drain`
  without `--dry-run`, `helm uninstall` with `--all`/no release, `terraform destroy`,
  `aws s3 rb --force`, `aws ec2 terminate-instances`, `gcloud projects delete`,
  `az group delete`, `docker system prune -a --volumes`, `docker volume prune`.
- `git push --force`/`--force-with-lease`/`--delete` to `main|master|trunk|develop|release*`
  or `git push --mirror`; `git filter-branch`/`git filter-repo` on shared history.
- `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE` on more than one table, `FLUSHALL`, `mongo
  dropDatabase()`, `DELETE FROM x` without `WHERE`.
- `history -c`, `shred`/`rm` of shell history, log wipes under `/var/log`, `journalctl
  --vacuum*` (covering tracks).
- Package-manager wide removal: `apt purge|remove` of `*`, `sudo apt autoremove --purge`
  of base packages, `pip uninstall -y -r <all>`, `npm cache clean --force` is ASK (harmless).

### 2.4 UNKNOWN → model (layer 1)

Reached only when layer 0 cannot classify: unknown binaries, interpreters with inline code
(`python -c`, `python - <<EOF`, `node -e`, `perl -e`, `ruby -e`, `bash -c`, `sh -c`, `eval`,
`awk` with `system(`/`>`), `xargs` with an unrecognised verb, `find -exec <unknown>`, `make`
targets named `deploy|publish|release|clean-all`, scripts outside the project, `npm run
<script>` whose script body (from `package.json`) contains a NEVER/ASK pattern, or docker
`run`/`exec`. The model receives the raw command (and the inline code if any) and answers a
closed-vocabulary **effect classification**; the effect maps back onto 2.1–2.3.

UNKNOWN is distinct from **UNPARSEABLE**. A command whose structure the parser cannot
establish cleanly — it reaches end-of-input still inside a quote, heredoc, or `$( )`
substitution, or contains control characters — is malformed; its segment list would be
fabricated from the unparsed
remainder (the failure that produced phantom "commands" from an awk `printf` body in
one real session). The line does not move when layer 0 becomes an AST parse: a command that
*parses* but contains nodes the security walker will not vouch for is **UNKNOWN**
(`unproven_structure`) and still goes to the effect model — only genuinely malformed input
takes the fix-and-retry path. Such a command is **not** sent to the effect model and **not**
turned into a user prompt. It is refused, and the agent is asked to rewrite/simplify
and retry (§5). This is fail-closed (an unparseable command can no longer degrade into
an allow via phantom segments) and is a security improvement, not just UX.

### 2.5 Secret-bearing paths

`~/.ssh/**` (except `known_hosts`, `config`), `~/.aws/**`, `~/.gnupg/**`, `~/.kube/config`,
`~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`,
`~/.config/gh/hosts.yml`, `~/.pi/agent/auth.json`, `~/.claude/**` credentials,
`**/.env`, `**/.env.*` (not `.env.example|.env.sample|.env.template`), `**/id_rsa*`,
`**/id_ed25519*`, `**/*.pem`, `**/*.key`, `**/credentials*`, `**/secrets*.{json,yaml,yml}`,
`**/token*`, `/etc/shadow`, `/etc/sudoers*`, keychains.

### 2.6 Live config vs staged copies

`write_sensitive` is a statement about the **machine**, not about a filename. The harm is that some
other process reads the file and the change takes effect: a systemd unit in `/etc/systemd/system`, a
unit in `~/.config/systemd/user`, a line in `~/.bashrc`, a row in `crontab`. So sensitivity is decided
by *where the file is read from*, and a path shape that matches inside the project does not qualify.

A repository's own copy is staged source. `deploy/systemd/pw-build.timer` is inert text until an
install step copies it into place and enables it — and that step is classified in its own right
(`system_config` for `systemctl enable`, `network_send` for the `scp`/`rsync` that carries it,
`vcs_remote` for a push). Classifying the staged copy as sensitive does not prevent the harm; it
interrupts the user while the harm is still several steps away, and it does so on every file in the
folder. `risk-paths.ts` therefore records an in-project match as `stagedConfig` (ALLOW) and keeps
`isSensitiveConfig` (ASK) for matches outside the project.

Two limits, both load-bearing:

- **A project root that *is* machine config keeps full strictness.** `projectIsLiveConfig()` is true
  when the project sits under a sensitive system prefix or under a home dot-directory — a dotfiles repo
  opened at `~/.config`, an infra repo opened at `/etc/nginx`. Without it, "it's in the project" would
  be a blanket bypass for exactly the repos whose job is editing machine config.
- **Secrets are not config-shaped and are not covered by this section.** `.env`, key material and
  credential files stay secret-bearing wherever they sit, including in the project (§2.5): their harm
  is in the bytes, not in an activation step, and a staged copy of a private key is still a private key.
  `.git` internals likewise stay ASK — writing them mutates real repo state, not a staged copy.

Filenames alone carry no location information, which is why `config.json` and `hosts.yml` sat in the
secret list for a while: each was written for one home location (`~/.docker/config.json`, an Ansible
inventory) and thereafter flagged that filename in every project on disk. The name list in
`risk-paths.ts` is a table with one reviewed line per name for that reason.

### 2.7 A write named by a flag is a write target

A command can open a file for writing without a redirect: `sort -o /etc/x` truncates `/etc/x` exactly
as `sort > /etc/x` does. Nothing in the syntax tree says so — the flag is an ordinary word and its
operand an ordinary argument — so a layer that only understands `>` calls the command read-only and the
ladder runs the write unasked. Layer 0 therefore reports the operand as a **write target of that
segment**, on the same channel a redirect target arrives on, and everything downstream reads one list:

| tool | flag | spellings read | operator |
|---|---|---|---|
| `sort` | `-o` | `-o F`, `-oF`, `-bo F` (a cluster) | `>` truncate |
| `uniq` | `--output` | `--output=F`, `--output F` | `>` |
| `patch` | `-o` | `-o F`, `-oF` | `>` |
| `tee` | `-o`, `--output` | `-o F`, `-oF`, `--output=F`, `--output F` | `>` — the flag exists precisely to mean "truncate instead of append" |
| `git` with `diff`, `show` or `log` | `--output` | `--output=F`, `--output F` | `>` |

Four properties hold because the target is reported once, in layer 0, instead of special-cased per
category:

- **the tier tables decide the verdict.** An in-project target is ALLOW (`write_project`), a target
  outside is ASK (`write_outside`), and the secret / live-config / device / `authorized_keys` rules of
  §2.2–§2.3 and §2.5–§2.6 apply unchanged: `sort -o ~/.ssh/authorized_keys` is NEVER for the same reason
  `cat x > ~/.ssh/authorized_keys` is.
- **strict-operand matching applies for free (§3).** `sort -i /tmp/a -o /etc/x` is target-bearing, so an
  allow rule must name every word it ran; one "Allow always" on one file cannot authorise the next.
- **target coverage applies for free.** A specifier that does not name the file does not cover the call,
  exactly as with `>`, and the "Allow always" offer spells the target so the rule it writes is honoured.
- **an unlisted tool reports nothing.** `-o` means something else in most of the tools it could be given
  to (`ssh -o BatchMode=yes`, `grep -o`, `git -O <orderfile>`), so the table stays short and every entry
  is a reviewed claim about one tool's option grammar. A tool that is not listed keeps exactly the verdict
  it had before this section existed — never a wrong one.

The operator records how the file is opened, so `>` and `>>` stay different writes and the descriptor is
part of a target's identity: stderr stays plumbing, and a rule for a stdout write never covers a stderr
one. A runtime-determined operand (`sort -o "$(pwd)/x"`) is reported as written, carrying its
placeholder; such a command is already `opaque`, and an opaque command's arguments are never read as
literals (`unproven_value`).

## 3. Authorisation for ASK (layer 1b)

An ASK decision is authorised when **any** of the following holds, checked in order:

1. **Permission rule** — an existing configured `allow` rule matches (dangerous broad rules
   are still stripped on auto entry).
2. **Session grant** — the user answered an earlier prompt with *Allow* / *Allow for this
   session* (or *Allow always*) and the stored grant `{category, entity or entity-scope}`
   covers the pending entities. Grants are exact entities or directory/namespace prefixes
   chosen by the user in the prompt; they are never widened automatically. A grant that
   names a **path** authorises any *path-mutating* category on that exact path
   (target-first matching): "apply that fix to /x/y.py" authorises writing `/x/y.py` even
   though the extraction mapped the action to a different fs-write category than the
   pending one (e.g. the path lives under `/usr`, which layer 0 calls
   `write_sensitive`). Scopes and wildcards are **not** widened by this rule, deletes
   still require a delete verb, and read categories are excluded so a read grant can
   never authorise a write. Ledger and transcript grants (below) are promoted here on
   first use so repeats are free.
 2b. **Read-only posture** — a blanket "you are not allowed to change anything" /
    "read-only" instruction sets a session posture (not a per-target forbid). While
    active, any ask/unknown action that is a *change* (everything except plain reads)
    is refused with an honest reason quoting the user; allow-tier project-folder and
    /tmp work still proceeds (the project is excluded by default). The posture is a
    **default, not a veto**: rules, session grants and the ledger (items 1, 2, 3) are
    evaluated first, and the posture only refuses what nothing has authorised — so a
    later explicit permission on a target supersedes it for any path-mutating category
    on that path, with no kind-group requirement. A blanket "you can make changes now"
    clears it. **Arming is by exclusion, not by phrase**: a `no`-prefixed assertion arms
    unless the text is demonstrably about reading/searching/inspecting with no mutating or
    running verb anywhere in it; ambiguity arms, because an allowlist of "read-only"
    phrasings is fail-open and a false read-only claim is worse than an extra prompt. A
    blanket revocation that grants nothing ("revert that change") does **not** arm the
    posture — it records an inert `*action*` forbid (see item 3). This replaces an earlier
    wildcard forbid that matched hallucinated targets and mis-reported "user forbade
    «entity»".
3. **Authorisation ledger** — pure code lookup against the per-session ledger of grants
   and forbids folded from per-message extraction (task 4.3); this is the whole-session
   memory, so authorisation is not a function of scroll position. All pending target
   entities must be covered by grant entries of a **compatible kind group** (creating,
   copying, moving, writing and chmod at a user-designated location are one group;
   deletes additionally require a delete verb in the grant's quote; package installs,
   sudo, remote exec and listeners require their method verb — same regexes as §3.3),
   each grant's `seq` must be above any matching forbid's, and near-name rejection from
   §3.3 applies unchanged. A matching **forbid** short-circuits to the prompt — the
   recent-window fallback must not overrule an explicit revocation. Growth control:
   entries are deduped per `(category, value, kind)` keeping the highest seq; caps
   (200 grants / 100 forbids) evict least-recently-matched grants first; eviction's
   failure mode is one extra prompt, never a false allow. Matching **normalises the home
   directory**: the gate renders outside-project paths as `~/dev/x/…` while users grant
   `/home/u/dev/x/…`, so `~` and the absolute form are canonicalised on both sides
   (unrelated sibling directories still do not match — this widens equality, not reach). The same
   canonicalisation covers the **project-relative** rendering, which is how every in-project target
   arrives: `displayPath` emits `./corpus/x.ts`, so a grant worded `/home/u/dev/pm/` reaches it only if the
   matcher resolves `./…` against the project root first (`canonicalPath`, fed by `policyProject` — the
   exact root layer 0 used, never a re-derived one). With only the `~` half done, the ledger silently misses
   every in-project target while still covering `~/…` ones, and the denial reads as "no approval exists"
   rather than "the two spellings were never compared" — the live failure of 2026-10-14, where a correctly
   extracted `delete_recursive` scope covered nothing inside the project. Anything the matcher cannot place
   (a bare word like `ripgrep`, a `..`-relative path, `./x` with no known project) is left unresolved: that
   costs one extra prompt and can never widen authority.
   Grants are revocable by value (`/grants revoke <value>`), never by list index: the
   listing merges two stores and re-orders as grants are promoted, so an index-based
   revoke is one stale listing away from deleting the wrong entry.
4. **Transcript grant (recent-window fallback)** — the model is asked one narrow question over **user messages
   only** (assistant text and tool results are never shown): *did the user explicitly ask
   for or approve this specific action on these specific targets, and has that not been
   withdrawn later?* The answer is structured (JSON schema enforced) and contains:
   `authorized` (yes/no), `allowed_targets[]`, `forbidden_targets[]`, `quote` (verbatim
   user text). Code then verifies:
   - the quote occurs verbatim (whitespace-normalised) in a user message;
   - every pending entity matches an `allowed_targets` entry **as a whole token** (case-
     insensitive; `db-backup` ≠ `db-backup-test`, `feature/x` ≠ `feature/x-prod`,
     `dev/` ≠ `dev-logs/`, `staging` ≠ `prod`); basename and last-path-component matches
     are accepted for paths;
   - no pending entity matches a `forbidden_targets` entry;
   - if the pending action has entities and `allowed_targets` is empty, the grant is
     accepted only for categories where a bare verb is a complete instruction
     (`vcs_remote` "push it", `delete_recursive` "clean the build dir" names `build`…) and
     the quote contains the category's verb — otherwise it is rejected.
   Any verification failure → not authorised (prompt). The model can therefore only
   *narrow* what the code would allow, never widen it.
5. Otherwise: prompt (UI) with options *Allow once · Allow for session (this entity) ·
   Allow for session (scope) · Allow always (rule) · Block*; without a UI: deny with the
   category, entities and a one-line reason so the agent can ask the user in text.
   Every allow answer (including plain *Allow*) records a session grant for the pending
   entities, so an identical action does not re-prompt.

Prompt-once memory is keyed by `{category, entity}`; a `delete_recursive` grant for
`./build` does not cover `./dist`, and a `write_outside` grant for `~/dev/other/` covers
files under it only if the user chose the scope option.

## 4. Model tasks (layer 1)

All tasks use `temperature 0` — **except a GitHub Copilot endpoint, where `temperature` is measured to be
refused** (`400 Unsupported parameter`) and is therefore never sent — `response_format: json_schema` on the
chat dialect / `text.format: json_schema` on the responses dialect (llama.cpp / vLLM / OpenAI and, measured,
Copilot's Auto path all accept it), thinking disabled where the server honours a knob, a hard output-token
cap, and a system prompt under 600 tokens. Any transport or schema failure → the deterministic fallback
(`ASK`, prompt; a failed ledger extraction leaves the message queued for retry). **A truncated answer is a
transport failure, never a short verdict** — on a reasoning model the cap can be entirely spent on thinking
and return empty text (§4.0).

### 4.0 Transport and classifier configuration

One block in `~/.pi/agent/permission-modes.json` under `classifier` decides which transport every layer-1
question uses (resolved by `resolveClassifierConfig` in `config.ts`; the project-scoped
`<cwd>/.pi/permission-modes.json` covers `authority.persist` and provenance only — classifier settings are
not read from there). Three cases are supported; which one is live is decided by `classifier.baseUrl` and
`classifier.model` alone.

**Keys that exist** (nothing else may be invented; defaults in parentheses): `enabled` (true), `model`
(`"anthropic/claude-haiku-4-5"`, `"<provider>/<id>"`), `engine` (`"gate"` | `"legacy"`), `timeoutMs` (15000),
`contextTokens` (4096), `failClosed` (true), `stage`, `includeAgentsMd`, `ledger`, `ledgerBackfillLimit`,
`jsonlTranscript`, `baseUrl`, `modelId`, and the Copilot-only block `copilot` (below).

| case | config | behaviour |
|---|---|---|
| **A — own OpenAI-compatible endpoint** | `classifier.baseUrl` (+ optional `modelId`) | Unchanged behaviour, and it outranks everything else: plain OpenAI-compatible POST to `{baseUrl}/chat/completions` with `response_format: json_schema` and `temperature: 0`, bypassing pi's registry **and the whole `copilot` block**, whatever `model` says. Needs a server that honours `json_schema` (llama.cpp, vLLM, litellm). |
| **B — Copilot Auto** (`github-picks`) | `"model": "github-copilot/auto"`, no `baseUrl` | The sentinel names a policy, not a model: the plugin mints **its own Auto session** (`POST {baseUrl}/models/session` with `X-GitHub-Api-Version: 2026-08-01`, cached and refreshed before `expires_at`, single-flight, 15 s failure cooldown — `copilot-session.ts`). The pick is only addressable with `Copilot-Session-Token`, so that header travels on every call; the wire dialect is the **pick's** catalog `api` (`openai-completions` → `/chat/completions`, `openai-responses` → `/responses`; an `anthropic-messages` pick has no encoder → resolves to no endpoint → the posture below). Because the pick is the plugin's own, host-model churn mid-session cannot silently change the classifier's model. || **C — explicit Copilot model** | `"model": "github-copilot/<id>"`, no `baseUrl` | The user's pick, dialect taken from the catalog `api` for that id. The session header is **never attached** — measured, it narrows the request to the Auto picks (`400 Requested model not available for session`). Correct by construction; untested on a free plan (see `docs/COPILOT-COMPAT-MEASUREMENTS.md` §6). `github-copilot/<id>@stage` / `:effort` suffixes are stripped before resolution, like every other ref. |

`classifier.copilot` — knobs that exist only because Copilot behaves differently (resolved by
`resolveCopilotConfig`; an unusable hand-edited value is ignored in favour of the default, never
propagated; read **only** on a `github-copilot/…` endpoint, so case A is untouched by them):

| key | default | meaning |
|---|---|---|
| `maxOutputTokens` | 512 | The **answer reserve** (`max_output_tokens` / `max_tokens`). A reasoning pick spends part of it thinking before any verdict exists (measured: 192 of 269 output tokens on a one-line classification; at a 120 cap the answer arrives EMPTY), so too small is not a shorter answer but no answer — reported as a transport failure. Values above 32 768 are treated as typos and ignored. |
| `reasoningEffort` | `"low"` | Sent as `reasoning.effort`, and only for a model the catalog marks as reasoning. Anything outside `low|medium|high` is refused at resolve time rather than forwarded to an endpoint that answers `400 Unsupported parameter`. |
| `budgetTokens` | 0 (= no cap) | Tokens this process may spend on Copilot before it stops asking — a free-plan allowance is shared with the user's own chat. A spent budget is a transport failure, never a refusal, and the denial text names it. |
| `sessionEnabled` | true | `false` turns the Auto session off: `github-copilot/auto` then resolves to **no endpoint at all** and the gate asks a person — how you leave every Copilot request for the user's own chat. |

**What the mint asks Auto for (D57, 2026-10-17).** Copilot serves three request dialects and this client encodes
two, so **GitHub's Auto pick may be one we cannot put on the wire** — that possibility is a fact about Auto, not a
bug, and no request shape makes it impossible. `auto_mode.model_hints` was measured to close the gap as far as the
wire allows (`docs/COPILOT-COMPAT-MEASUREMENTS.md` §2b): the field filters the offered pool **by model id**
(`["gpt-5-mini"]` → pool `[gpt-5-mini]`, pick `gpt-5-mini`), it does **not** accept dialect names — a dialect name
is answered like any unmatched hint, `200` with `available_models: []` and `selected_model: ""`. So the mint asks
the measured control question first (`model_hints: ["auto"]`), and only when the resolver reports a pick whose
catalog `api` it cannot encode does it ask **once** more with `model_hints` set to the ids GitHub itself offered in
`available_models` whose dialect we do encode. Two rules hold that property: an id is never named in source (the
catalog churns within hours — D55), and an empty hint list is never sent, because the one thing measured about a
hint that matches nothing is that it costs you the pool.

Whatever the retry achieves, an unspeakable pick stays exactly what W88 made it: **an unavailable classifier naming
its cause** (`gate-bridge.ts`'s `auto-pick-unnamed` / `auto-pick-unspeakable`, rendered by
`classifierUnavailableReason` / `buildClassifierUnavailableMessage` in `classifier-messages.ts` — call those, do not
restate their text here or in a denial), which asks in a terminal and declines unattended. Never a silent fallback,
never a refusal, never "no endpoint configured" when an endpoint exists.

**Failure posture (owner's ruling, 2026-10-16).** Layer 0 decides whatever it can decide in code. Where it
cannot and the classifier is unreachable: **interactive sessions ask the user; unattended runs decline with
the reason naming that the classifier was not available** — the existing catch in `index.ts` falls back to
the tier-3 prompt, which is a prompt in a terminal and a decline in a headless run. Every Copilot-specific
failure must therefore reach that catch as a transport failure and never be parsed as a verdict: 404-with-
an-empty-body (missing version header), `model_not_supported` (missing session token), `Unsupported
parameter` (a forbidden field), a spent `budgetTokens`, a truncated answer, and a dialect with no encoder.
A classifier that cannot reach its model is an unavailable classifier, not one that votes "no".

### 4.1 Effect classification (for UNKNOWN)

Input: the command text (≤ 1500 chars), the effective cwd, the project root.
Output: `{"effect": <enum of 2.1–2.3 categories + "read_only" + "write_project" + "run_project_code">, "targets": string[], "outside_project": boolean, "confidence": "high"|"medium"|"low"}`.
Mapping: `read_only|write_project|run_project_code` with `outside_project=false` and
confidence ≠ low → ALLOW; any ASK category → ASK with `targets` as entities; any NEVER
category → NEVER; `low` confidence → ASK (`interpreter_unknown`).

### 4.2 Transcript authorisation (for ASK)

Input: the last ≤ 12 user messages (≤ 6 000 chars, most recent last, oldest truncated
first), the pending action rendered in plain words by layer 0 ("recursively delete
directory ./build (rm -rf ./build)"), its category and entities.
Output: `{"authorized": "yes"|"no", "allowed_targets": string[], "forbidden_targets": string[], "quote": string}`.
The code verification in §3.3 is mandatory; a `yes` alone never allows anything.

### 4.3 Per-message grant extraction (for the ledger)

Input: ONE user message (≤ 4 000 chars), nothing else — so there is no pending action to
echo from, and requiring extracted names to appear verbatim in the message is sound.
Output: `{"grants": [{action, targets[], quote}], "revocations": [{targets[], all, quote}]}`
(schema-capped: ≤ 8 items each, ≤ 16 targets). Code verifies each item (verbatim quote in
the message, targets whole-token present, pronouns dropped), maps `action` to a gate
category via a small keyword table (unmappable actions are stored inert — they match
nothing and only the §4.2 fallback can use them), and folds the result into the ledger.
Run lazily on gate invocations: ≤ 2 calls inline (typically 1 — the message that started
the turn); larger backlogs (sessions predating the plugin, restarts without a snapshot)
drain via background backfill, **newest-first**, capped at the newest 400 user messages.
Newest-first makes a *partially* backfilled ledger safe: every grant present already has
all later messages processed, so nothing later-revoked can be allowed. The ledger and
session grants are snapshotted into the session (debounced) and restored on resume,
dropping entries whose source message is no longer on the branch; with no snapshot,
temp-0 extraction rebuilds the same ledger from scratch.

## 5. Observability and safety rails

- Every decision is logged (`PERMISSION_MODES_CLASSIFIER_DEBUG=1`) with layer, category,
  entities, model latency and, for model answers, the raw JSON and the verification result.
- Denials tell the agent the category and entities so it can ask the user precisely.
- A per-session budget: after 3 consecutive model failures the gate falls back to prompting
  for all ASK/UNKNOWN decisions (fail-closed, never fail-open).
- Verdict memo: identical `(command, cwd, user-message hash)` within 60 s returns the
  cached decision.
- Reproducibility: with `temperature 0` and schema-constrained 1–30 token outputs, the
  measured cross-restart flip rate must be reported by the eval, not assumed.

## 6. Acceptance criteria (measured by `eval/`)

| metric | target |
|---|---|
| NEVER cases auto-approved | 0 (hard requirement, layer 0 only, no model involved) |
| false-allow on ASK cases without authorisation | ≤ 2 % |
| over-block on ALLOW cases | ≤ 10 % |
| transcript-authorised ASK cases correctly allowed | ≥ 80 % (residual is a prompt, not a failure) |
| ledger-recall on long-session grants (authorisation outside the §4.2 window) | ≥ 80 % |
| parse/transport failures | 0 % with json_schema; a failure is a prompt |
| p50 latency for a model call on the target hardware | ≤ 500 ms |
| verdict flip across two server restarts | 0 on layer-0 cases; reported for model cases |
