# Auto-mode gate specification (v3 design)

## 0. Purpose and non-goals

The auto-mode gate decides, per tool call, whether the call may run without a human.
Its only job is to prevent **consequences the user did not intend**: destruction of data,
changes outside the project, changes to the machine or to other systems, exposure of the
machine or of private data, and irreversible operations. It is **not** a judge of societal
harm, ethics, or code quality, and it must never be asked to be one — that is not a task a
small model can do, and it is not what auto mode is for.

Design principle: **decide in code whatever can be decided in code; ask a model only the
narrowest remaining question; make every model answer machine-checkable.** It follows from what the
alternative was measured to do. Asking one small model to read a rubric and return a verdict fails on
all three counts — the answer is not reliably parseable, is not reproducible across restarts, and
does not bind to the entities named in the conversation, at every model size tried. The same sizes
answer *extraction* questions reliably on a 4B model: "quote the sentence in which the user named
this target" has a checkable answer, and the check can be done in code afterwards.

## 1. Outcomes

| outcome | what happens |
|---|---|
| **ALLOW** | tool call runs, nothing shown to the user beyond the normal tool output |
| **ASK** | needs authorisation, and is authorised if any of these holds, evaluated in this order: configured permission rules (which run before any mode gate), session grants (prompt-once memory), the authorisation ledger, then — only if nothing authorised it — the read-only posture, then the transcript grant (model-extracted, code-verified). Whatever is left goes to the person: a prompt where there is a UI, a denial carrying the category, the entities and a one-line reason where there is not. A session with no UI behaves as unattended, so a prompt that cannot be drawn is a denial and never a pass |
| **NEVER** | never auto-approved, and not pre-authorisable: the gate stops here, before session grants and the ledger are consulted, so nothing the user said earlier can settle it. With a UI the prompt is narrowed to *Allow* and *Block* — no session-entity, no scope, no "Allow always", and a plain Allow records no grant (§3 item 5) — so it interrupts once per call instead of remembering; without a UI it is a denial that states the reason. Only bypass mode or an explicit permission `allow` rule (which the dangerous-rule stripper does not remove) gets past it |

Every ASK/NEVER decision carries a **category** and a list of **entities** (paths, images,
branches, hosts, packages, ports…) so the user sees *what* is being authorised and the grant
can be stored at the right granularity.

## 2. Deterministic policy (layer 0)

Runs first for every tool call, in code, with no model in the loop.

Bash is not split on text. The whole input is parsed with `tree-sitter-bash` and walked under
[docs/LAYER0-WALKER-SPEC.md](LAYER0-WALKER-SPEC.md), which either proves a literal argument list for
every simple command in the input or refuses the input as a whole with one reason id and the
`malformed` flag that says whether to ask for a simpler command (§2.4). Each simple command the parse
proves is then classified by the handler for its command family (`risk-handlers.ts`); a `cd` updates
the effective working directory for the commands after it; redirection targets are treated as writes
— including a file named by an **output flag** rather than by a redirect (§2.7); and the verdict for a
compound input is the **most restrictive** command in it. There is exactly one parser: the older
hand-written lexer (`shell-lexer.ts`) still runs, but only where the parse refused, and only to
escalate — its `ask` and `never` verdicts survive, its `allow` verdicts come back as `unknown`
(`risk-policy.ts`). It can never lower a tier and never authorise a command.

Wrappers are not transparent, and the two layers peel different lists. For its meaning checks the parse
steps over `env`, `nice`, `stdbuf`, `timeout`, `nohup` and `time` — and only for those checks, so the
reported command words stay what was written (LAYER0 §11.2); a wrapper in a form the parse does not
recognise is refused, not judged as itself. The handler then peels its own list to reach the verb it
classifies (`WRAPPERS` in `risk-handlers.ts`: `timeout`, `time`, `nice`, `ionice`, `nohup`, `stdbuf`,
`strace`, `ltrace`, `command`, `builtin`, `exec`, `setsid`, `unbuffer`, `script`, `chronic`, `flock`,
`taskset`, `numactl`). Neither list ever hides `sudo`/`doas`/`pkexec` or `xargs`: the first family is its
own category (`privilege`, §2.2) whose inner command is classified beside it, with NEVER surviving the
wrap, and `xargs` has its argument command classified in its own right.

Unrecognised commands, nested command substitution
(`$(...)`, backticks) feeding a mutating verb, inline interpreter code (`python -c`,
`node -e`, heredocs) and `eval` are **UNKNOWN** and go to the model (layer 1).

### 2.1 ALLOW (auto)

The families below are what the handlers classify as `allow`; the exact word lists live with the code
and are the authority — `READONLY_BINS` and the per-family handlers in `risk-handlers.ts`, the write
and path rules in `risk-paths.ts`. A command no handler claims is not "allowed by omission": it comes
back `unknown` and goes to §2.4.

- Reading **inside the project** (its `.git` included): `cat head tail less more wc stat file du ls tree find
  grep rg fd diff sort uniq cut tr jq yq awk`-as-filter (see 2.4), `sed -n` without `w`, and pi tools
  `read/grep/find/ls`. Reads outside the project and non-file reads ask (2.9). Secret-bearing paths are ASK (2.5).
- A tool's own information and shell state (2.9): `--version`, `--help`, `which`/`type`/`command -v`.
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
- Local git **in the project repository** (2.9) that keeps history recoverable: `add commit status log diff show branch
  checkout switch merge rebase cherry-pick revert stash (push/pop/list) tag fetch pull
  remote -v config --get`, `git reset` without `--hard`, `git clean -n`.
- Docker build in the project: `docker build`, `docker compose build`. Docker, cluster, cloud, network and
  process **reads** below are non-file reads: they ask, naming their object (2.9).
- (ASK, 2.9) Cloud/cluster **read** verbs: `kubectl get|describe|logs|top|explain|config view|api-*`,
  `helm list|status|get|show|template`, `terraform plan|show|validate|fmt`, `aws|gcloud|az`
  `describe*|list*|get*`.
- (ASK, 2.9) Network **reads**: `curl`/`wget`/`http` GET to any host when the output is not piped to a
  shell and no upload flag is present (`-d --data* -F -T --upload-file -X POST|PUT|PATCH|
  DELETE`), `ping`, `dig`, `nslookup`, `nc -z`.
- (ASK, 2.9) Process inspection: `ps`, `pgrep`, `lsof`, `ss`, `netstat`, `strace -p` (read-only).
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
| `package_system` | `apt|apt-get|dnf|yum|pacman|zypper|brew|snap|flatpak install|remove|upgrade`, `pip install --user/--system` outside a virtualenv (inside one — `VIRTUAL_ENV`/`CONDA_PREFIX` set, `.venv/bin/pip`, `uv pip` into a venv — it is project-local; `source .venv/bin/activate` is classified on its own), `npm i -g`, `cargo install`, `gem install`, `pipx install` | package names |
| `vcs_remote` | `git push` (any), `git remote add|set-url`, `gh pr create|merge`, `gh release create`, `git push --tags` | `remote/branch` as the gate spells it — a bare `git push` names the session's own branch, never a guess; scope `remote/*` |
| `vcs_discard` | `git reset --hard`, `git clean -f*`, `git checkout -- .`/`git restore .`, `git branch -D`, `git stash drop|clear`, `git push --force*`, `git rebase` onto pushed history is still ALLOW (recoverable via reflog) | branch/paths |
| `network_listen` | `python -m http.server`, `nc -l`, `ssh -R|-L|-D`, `ngrok`, `--host 0.0.0.0`, `docker run -p`, `kubectl port-forward` | port |
| `network_send` | `curl -d|-F|-T|-X POST…`, `scp`/`rsync` to `host:`, `ssh host cmd`, `aws s3 cp` to remote, `gh api -X POST`, `git push` (covered above); `docker|podman|nerdctl|helm|oras push <ref>` — **one row, `network_send`** (a push sends bytes and mutates no container); an upload into an object store (`gsutil/az … cp` with the URI last) | host / URL; for an artifact push the image/chart ref, scope `registry/repo` (any tag) |
| `remote_exec` | `curl … \| sh`, `wget -O- … \| bash`, `bash <(curl …)`, `npx <unknown pkg>`, `pip install git+https://…` | URL / package |
| `process_control` | `kill`, `pkill`, `killall`, `systemctl stop\|restart\|reload\|kill`, `service nginx restart`, `docker stop\|restart` — a RUNNING thing the command names, however many it names | pid / name / unit |
| `system_config` | what the machine will do at BOOT or how it is set up: `systemctl start\|enable\|disable\|mask\|daemon-reload`, `service` (verbs that are not stop/restart), `ufw allow`, `iptables -A`, `sysctl -w`, `modprobe`, `mount`, `hostnamectl`, `timedatectl` | unit / rule |
| `container_mutation` | `docker rm|rmi|volume rm|network rm|container prune|image prune`, `docker compose down` (`-v` → entities include "volumes"), `docker run`/`exec` (host mounts or `--privileged`) — the containers and images **on this machine** | names; image ref |
| `cluster_mutation` | `kubectl delete|apply|patch|scale|rollout|drain|cordon|exec`, `helm install|upgrade|uninstall|rollback`, `terraform apply`, and the `aws|gcloud|az` fallback for a mutating API verb on a service with no handler — a cluster or cloud **resource**, never an object inside a store | resource, namespace |
| `delete_data` | objects **inside** a store: `aws s3 rm` of an object/prefix, `aws s3api delete-object(s)`, `gsutil rm -r gs://bucket/prefix`, `az storage … delete`, plus local backups/dumps/archives (`rm ./backups/db-backup`) | the URI or path, + the store/prefix as scope |
| `db_mutation` | `psql|mysql|sqlite3|mongosh|redis-cli` with `DROP TABLE|TRUNCATE|DELETE|ALTER|UPDATE|INSERT` or `-c` non-SELECT — one table's worth; a whole database or schema gone is `db_destroy` (§2.3) | table / db |
| `perm_change` | `chmod`/`chown` outside project, `chmod 777`, `o+w`, `chmod -R` outside project | paths |
| `interpreter_unknown` | inline code the model could not classify as read-only/project-scoped | — |

### 2.3 NEVER (Allow once at a prompt, or deny; not pre-authorisable)

The path half of this is one table in `risk-paths.ts`, not a paraphrase: `SYSTEM_ROOTS` for whole
systems, `HOME_NEVER_SUBDIRS` for the first level of a home directory, and one rule — a path is
never-wipe if it *is* one of those, if it is the user's home, or if the project lives under it
(`isUnder(project, abs)`), which is what makes every ancestor of the project and the project root
itself unwipeable.

- `rm -r`/`rm -rf`/`find -delete`/`shred` targeting a system root: `/`, `/bin`, `/sbin`, `/lib*`,
  `/usr`, `/etc`, `/var`, `/boot`, `/opt`, `/srv`, `/dev`, `/proc`, `/sys`, `/root`, `/home`, `/mnt`,
  `/media`, `/run`, `/snap`, `/nix`, the macOS trees (`/System`, `/Library`, `/Applications`,
  `/Users`, `/private`), and the deep ones that are always worth more than their parent
  (`/usr/local`, `/usr/{bin,sbin,lib,share}`, `/var/lib`, `/var/log`, `/etc/ssh`, `/etc/systemd`,
  `/var/lib/docker`). The temp roots (`/tmp`, `/var/tmp`, `/dev/shm`) are on the list as
  *directories*: their contents are ordinary `delete_outside` targets, the directory itself is not.
- …or the home directory itself, or a first-level entry of it that holds a person's work or their
  credentials: `.ssh`, `.gnupg`, `.config`, `.local`, `.cache`, `Library`, `Documents`, `Desktop`,
  `Pictures`, `Videos`, `Music`, `Downloads`, `Dropbox`, `OneDrive`, `.aws`, `.kube`, `.docker`,
  `.password-store`, `.mozilla`, `.thunderbird`, `dev`, `src`, `projects`, `work`, `repos`, `code`.
  Only as a whole entry — `rm -rf ~/Documents/one-project` is a `delete_outside`, `rm -rf ~/Documents`
  is NEVER — because the second one deletes the things that were not this project.
- …or the project root itself (`rm -rf .`, `rm -rf ./`, `rm -rf $PWD`) or any parent of it.
  A glob is judged by the directory it names, not by the shell's expansion: a trailing glob component
  is dropped and the remainder classifies (`rm -rf ./build/*` is about `./build`), a glob at the root
  of a path (`*`, `./*`) is the current directory, and `$HOME` / `${HOME}` are expanded first.
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
  source path is a secret-bearing path (§2.5) (`curl -d @~/.ssh/id_rsa …`, `scp ~/.aws/
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

UNKNOWN is distinct from **UNPARSEABLE**, and the two take different roads.

A command whose structure the parse cannot establish — the input ends inside a quote, a heredoc or a
`$( )` substitution, or it carries a control character — is `malformed`, and any segment list for it
would have to be fabricated from the unparsed remainder. That is not a cosmetic cost: a fabricated
segment list is how an awk `printf` body once came back as two confident "commands" and was judged as
if they were. So a malformed command is **not** sent to the effect model and **not** put to the user as
a permission question — there is no command there to authorise. It is refused with no model call, and
the agent is told to rewrite it: split the pipeline, avoid deeply nested quoting, put a complex
awk/sed/python program in a file or a heredoc instead of inline. The retries are bounded; after 3
malformed commands in a row an unattended run is told to park the step and list it later, and an
attended session hands the stuck agent to the human, who can see what is happening.

A command that *does* parse but uses structure the walker will not vouch for — a loop, a brace group, a
command substitution, a variable with no known value — is the other case: valid bash, refused for what
it uses, `malformed: false`. That is **UNKNOWN** (`unproven_structure`) and it *does* go to the effect
model, because nothing is broken and a model can reason about the intent. The line between the two is
drawn by the parse's own flag and never by the wording of a reason, and the older text engine running
beside it can only make such a command more expensive to approve, never cheaper (§2).

A third refusal is neither case. With no grammar loaded in the process, every bash command is refused
`parser-unavailable`: that is the plugin's own fault rather than the command's, so the denial says the
analyzer is down instead of advising a rewrite, and it stops everything rather than passing anything.
The reason id stays in the text the agent reads, because the advice attached to a denial is chosen from
it — paraphrase it away and the caller has to guess whether to blame the command or the runtime.

### 2.5 Secret-bearing paths

Being secret-bearing costs one prompt and sets no floor: the category is `read_secret`, so an approval
or a grant covers the file like any other ASK. What counts is decided in `risk-paths.ts` by three
mechanisms, and a name list alone cannot cover the last one.

1. **A directory under the home directory**: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`,
   `.config/gh`, `.config/gcloud`, `.azure`, `.password-store`, `.config/pi`, `.vault-token`,
   `.claude`, and `.pi/agent` — this plugin's own state directory, treated as one whole because
   whatever the agent is handed lands beside its settings. Its own `adaptive-acl.json` is exempt:
   it holds modes, rules and the classifier endpoint, and provider keys live in the agent's own
   settings files, not there.
   Two exemptions inside `~/.ssh`: `known_hosts` and `config` are sensitive *config* (§2.6), not
   secrets — reading them is routine and blocking it teaches the user that the wall is noise.
2. **A reviewed file name, one line each** (`SECRET_NAME_RULES`): OpenSSH private keys
   (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`, `.pub` included), key material by extension
   (`.pem .key .p12 .pfx .jks .keystore`, and `.secret`), `credentials*`, `.env` and `.env.*`, the
   client auth files (`.npmrc .pypirc .netrc .git-credentials .pgpass .my.cnf .htpasswd`),
   `auth.json`, `secrets?.{json,yaml,yml,toml,env}`, `token(s)*`, `shadow` and `sudoers*`,
   `kubeconfig`, `service-account*.json`. A name ending `.example`, `.sample`, `.template`, `.dist`
   or `.schema` is a template and is not secret by name. `/etc/shadow`, `/etc/gshadow` and anything
   under `/etc/sudoers` are secret wherever they are found.
3. **A name whose last word declares what it holds** — `pass`, `passwd`, `passphrase`, `password`,
   `credential(s)`, `secret(s)`, `token(s)`, `apikey`, `htpasswd`. This is word recognition, not
   pattern matching, and its whole design is not being noisy: the word must be a whole word of the
   name (`passctl`, `mypasswd`, `tokenizer`, `compass` are ordinary files); a file whose extension
   says code or prose is never secret by name, so `src/password.ts` and `docs/secrets.md` stay
   readable, while data extensions (json/yaml/toml/env/txt/csv) stay in play because a data file
   named `secrets` is exactly what this is for; `key` counts only behind a qualifier that is itself
   known to name a credential (`sort_key` and `monkey` do not); the token has to *address* a file, so
   the bare word in `grep -r password src/` is a search term, not a target; and one word means
   something else where the OS keeps it — `/etc/passwd` is the user database, not a credential store.

Secrets are not config-shaped, so §2.6's staged-copy rule does not reach them: a `.env`, a key or a
credential file is secret-bearing inside the project too, because the harm is in the bytes and not in
an activation step, and a staged copy of a private key is still a private key.

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

Three details of the read, because each one is a way for the table to be wrong about a real command:
a wrapper is stepped over first, so `timeout 5 sort -o /etc/x` still reports the write; a bare `--`
ends the option scan, so a word after it is a filename and not a flag operand; and the `git` rule fires
only when one of `diff`, `show`, `log` appears among the words the invocation names, anywhere before the
flags, because `--output` belongs to the diff options (`git -c core.pager=cat diff --output=f` is still
`git diff`). LAYER0 §7.7 is the walker-side half of this section.

### 2.8 The category names the effect, not the tool family

A category answers *what is changed, destroyed, sent or run* — never which program did it. Deleting objects
under a bucket prefix is `delete_data` whether the CLI is `aws s3`, `gsutil`, `az storage`, `rclone` or `mc`;
sending an artifact to a registry is `network_send` whether it is a `curl -T`, an `scp` or a `docker push`;
stopping a service is `process_control` whether the word after it is `kill` or `systemctl`.

One module holds those definitions — `category-meanings.ts`, one line per `GRANT_CATEGORY_VALUES` entry plus
the lines where the neighbours divide — and all three model calls render **that** text: the gate's grant call
the slice for its own pending type, the effect classifier one line per value it may answer, the per-message
extraction the whole table. A definition is not restated inside a prompt, because a restatement is a second
thing that has to stay true. The boundaries the models were measured getting wrong are stated explicitly there:
`delete_data` vs `cluster_mutation` (a bucket object is data; a cluster category is for resources),
`network_send` vs `container_mutation` (a push mutates no container), `network_send` vs `exfiltration` (what
leaves must be secret material), `vcs_remote` vs `vcs_force_protected` (the branch decides, not the force),
`db_mutation` vs `db_destroy` (one table vs a whole database), `process_control` vs `process_massacre`
(named vs indiscriminate), `delete_recursive` vs `wipe_protected` (pointed-at vs never-wipeable).

Two rules the split follows, both load-bearing:

- **A tier never moves with a rename.** These are names: a category change may only rename what was already
  `ask` / `never` / `allow`, so a mis-named row costs one prompt and can never become an approval. The
  whole-store `never` rules stayed `never` (`aws s3 rb`, whole-bucket `--recursive rm`, `kubectl delete ns`);
  the ones whose destruction is not a store got their own word (`aws rds delete-db` is `db_destroy`,
  `aws iam …` is `privilege_persist`).
- **Renaming moves reach, so it moves it in one direction only.** A row reaches its own kind group
  (`grant-verify.ts`), so `systemctl stop x` leaving `system_config` for `process_control` means a
  `system_config` grant no longer covers it and a `process_control` grant does — never both, and never a wider
  category. A rename that would let a file-write grant authorise a `kubectl config use-context`, or a
  piped-installer grant authorise `ssh host cmd`, was rejected for that reason and kept as it was.

### 2.9 Reads outside the project need permission

Reads outside the project ask. `decideRead` is the single answer for a path: secret → read_secret;
/dev/null, /dev/stdout, /dev/stderr → allow; unresolvable path → ask naming the raw text; device → ask; inside
the project root (its .git included) → allow; otherwise → ask `read_only`, target = the object, scope offered =
its directory. The same rule covers pi's read/grep/find/ls/glob tools, `< file` redirects, and the effect
model's read verdict (`readEffectTier`).

Non-file reads ask too and must name a stable object: the daemon, the cluster(+context), the host, the
unit, the journal, the crontab, the database, the object store, the URL host, and the remote a git command asks. `env` written with no command after it and `printenv` are
`read_secret` (2.9b) — reading the environment is not shell state. A git command is judged against the repository at its EFFECTIVE directory (`-C`, `--git-dir`,
`--work-tree`, or the directory the leg runs in after a `cd`), never against "the project" by assumption:
outside the project that is a read of that repository, and `fetch`/`pull` there also read the remote.

Free only: a tool's own information (`--version`, `--help`, `which`/`type`/`command -v`, a bare usage print)
and shell state (`pwd`, `echo`/`printf` with no file, builtins, `cd`, `true`/`false`); `-h` is not a
self-report flag. /tmp, /var/tmp and $TMPDIR are outside for READS; writes there are unchanged.

Coverage: a read_only grant on X covers reads under X; a WRITE or DELETE grant on X covers reading X
(one-way, per segment, `*` refused on delete and service rows); a grant naming a service, host or cluster
covers reading that object; a forbid on the object still wins; read_secret is reachable from none of them.
Running code outside the project is run_project_code, not a write. A temp-file permission is structured,
never inferred from prose: `targetClass:"temp_files"` on a grant row maps in code to /tmp, /var/tmp and $TMPDIR.

### 2.9b A status read is granted by machine

A read whose OBJECT is a machine or a cluster — its processes, disks, memory, hardware, identity, sockets,
routing, kernel settings, mount table, services, journal, containers, cluster workloads — is
`read_system_state`, tier ask. Layer 0 answers it for the families it knows (MACHINE_STATUS_BINS: ps, pgrep,
pidof, pstree, top, htop, btop, lsof, fuser, df, free, lsblk, uptime, nproc, lscpu, lsusb, lspci, sensors,
nvidia-smi, rocm-smi, uname, hostname, hostnamectl, id, whoami, groups, ip, ifconfig, ss, netstat, route, arp;
systemctl's status verbs; journalctl; `sysctl` with no assignment; bare `mount`; the container-runtime read
verbs; kubectl's read verbs) and for the inner command of `ssh <host> …`.

The object is the machine, never the client or the unit: `localhost` here; the daemon host for a container
runtime (`-H`/`--host`, else $DOCKER_HOST, else local — `unix://` and bare paths are local); the context for
kubectl (`--context`, else the kubeconfig's current context, else the client's name); the ssh host for a remote
status read. One approval answers the family on that object, which is the point of the ruling.

Never `read_system_state`: `env` / `printenv` / bare-env and `docker inspect` are `read_secret` (a session keeps
its tokens in the environment, and an inspect prints a container's configuration, its environment included);
clients that report something other than a machine's state (helm, terraform, aws, gh, curl GET, dig, nslookup,
host, whois, ping, traceroute, mtr, getent, ldd, crontab -l, tmux ls) stay `read_only`; a status tool in a
CHANGE form (`ip link set`, `route add`, `arp -d`, `ifconfig IF ADDR`, `sysctl k=v`, `mount DEV POINT`) is
`system_config`.

Coverage: `read_system_state` is its own kind group and covers only itself. The direction of §2.9's coverage is kept through
MACHINE_READ_GRANT_CATEGORIES — container_mutation, cluster_mutation, remote_exec, process_control,
system_config, read_only — narrowed from SERVICE_OBJECT_CATEGORIES by dropping network_send and db_mutation: an
endpoint somebody sent a packet to, and a database, are not a machine whose state you may read. `*` is refused,
a forbid still wins, a temp-file permission never reaches it, and the read-only posture treats it as a read
because it changes nothing.

Extraction: prose that grants troubleshooting latitude without naming a machine is a `read_system_state` grant
with `targetClass:"local_machine"`; one about the cluster the user is pointed at now uses `"current_cluster"`.
Code maps the classes — local to `localhost`, current_cluster to the kubeconfig's current context ONLY when that
file declares exactly one context ENTRY — and registers NOTHING when the category is not `read_system_state` or
the cluster is ambiguous, so an ambiguous "my cluster" costs its prompt instead of arming a wildcard. Ambiguity is
the count of entries under `contexts:`, not the count of names the reader could parse: an entry it cannot name is
still another referent. A row that names a target keeps the name and loses the class. `kubeContexts` reads
`current-context` and context NAMES and nothing else — one slot per list item, the name read from whichever line
carries it at that item's own field column, whether that is the dash line (`- name: prod`, hand-written) or its
own line under `- context:` (what kubectl writes) — and it stops at the next top-level key, so the `clusters:` and
`users:` lists cannot contribute their `- name:` items. A kubeconfig also holds tokens, and none of that may reach
a ledger row, a prompt or a log.

## 3. Authorisation for ASK

The items keep the subsection numbers the rest of this document and the code comments use, which are
**not** the order they run in. The code evaluates them **1 → 2 → 3 → 2b → 4** (grants, ledger, then the
posture, then the model), because the posture has to be outrankable by a permission given later — see
item 2b's "default, not a veto". Item 4 is what the number **§3.3** means: it holds the entity matcher
that items 2 and 3 also call, and `grant-verify.ts` and §4.2 both cite it by that number, so renumbering
this section without carrying the alias would orphan those references.

One thing happens before any of this: a **named forbid** in the ledger also binds an ALLOW-tier verdict.
"do not delete X" downgrades an allow into an ASK so the pipeline below decides it, with the forbidden
path promoted to a target so the prompt can offer the session options on it. An explicit revocation is
never outranked by a table that finds nothing wrong.

`gate.ts` names these steps after the pipeline rather than after this document: **layer 1a** is item 2,
**layer 1b** is item 4, **layer 1c** is the effect classification of §4.1 (which runs on UNKNOWN, before
this section is reached at all). The ledger of item 3 and the posture of item 2b have no layer letter.

1. **Permission rule** — an existing configured `allow` rule matches (dangerous broad rules
   are still stripped on auto entry).
2. **Session grant** — the user answered an earlier prompt with *Allow*, `Allow for session: <the
   pending targets>`, `Allow for session (scope …)`, or an *Allow always* answer — which stores the
   same row marked durable, so it is remembered past this session too: in the project's grants journal
   by default, or in a rule file when `authority.persist` is `"rules"` (item 5) — and the stored grant
   `{category, entity or entity-scope}` covers the pending entities.
   Grants are exact entities or directory/namespace prefixes
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
   and forbids folded from per-message extraction (§4.3); this is the whole-session
   memory, so authorisation is not a function of scroll position. All pending target
   entities must be covered by grant entries of a **compatible kind group** (creating,
   copying, moving, writing and chmod at a user-designated location are one group;
   deletes additionally require a delete verb in the grant's quote; package installs,
   sudo, remote exec and listeners require their method verb — the same verb tables item 4
   uses, `BARE_VERB_CATEGORIES` / `METHOD_VERB_REQUIRED` in `grant-verify.ts`),
   each grant's `seq` must be above any matching forbid's, and the whole-token (near-name)
   rejection stated in item 4 applies unchanged. A matching **forbid** short-circuits to the prompt — the
   recent-window fallback must not overrule an explicit revocation. Growth control:
   entries are deduped per `(category, value, kind)` keeping the highest seq; caps
   (200 grants / 100 forbids) evict least-recently-matched grants first; eviction's
   failure mode is one extra prompt, never a false allow. Matching **normalises the path
   spelling**, because the gate and the user do not write paths the same way: the gate renders an
   outside-project target as `~/…` and an in-project one as `./…` (`displayPath`), while a user grants
   the absolute form they typed. Both halves are canonicalised before comparison
   (`canonicalPath`, fed by `policyProject` — the exact root layer 0 used, never a re-derived one), so
   `~` and its absolute form are one path and `./src/a.ts` and `<project>/src/a.ts` are one path.
   Unrelated siblings still do not match: this widens *equality*, never reach. The project-relative half
   is not decoration — it is how every in-project target arrives — and doing only the `~` half produces
   a ledger that silently misses every in-project grant while still covering `~/…` ones, so the denial
   reads as "no approval exists" when the truth is "the two spellings were never compared". A correctly
   extracted scope that covers nothing inside the project is that bug, and it looks like a user who
   never granted anything.
   Anything the matcher cannot place (a bare word like `ripgrep`, a `..`-relative path, `./x` with no
   known project) is left unresolved: that costs one extra prompt and can never widen authority.
   Grants are revocable by value (`/grants revoke <value>`), never by list index: the
   listing merges two stores and re-orders as grants are promoted, so an index-based
   revoke is one stale listing away from deleting the wrong entry.
 3b. **Publish targets are matched by grammar, not by string** (items 2 and 3 alike).
    Targets stay strings, but for the categories whose targets have a shape —
    `vcs_remote` / `vcs_force_protected` (git refs) and `container_mutation` /
    `network_send` (image and chart refs) — `target-grammar.ts` is asked first and the
    string rule only runs where the grammar has no answer. Git refs form a lattice:
    `*` ⊃ `origin` = `origin/*` ⊃ `origin/feature/*` ⊃ `origin/feature/x`, with refspec spellings
    (`HEAD:x`, `+x`) read on the remote side.
    A wildcard row (`origin/*`, `origin`) never reaches a **protected branch** (`main`,
    `master`, `trunk`, `develop`, `dev`, `release/*`, `production`, `prod`, `stable`): pushing
    one needs a sentence that names it. Image refs match by registry, repository
    and tag: a row without a tag covers every tag of that repository, a tagged row covers
    that tag only, and a different registry never matches. Matching is applied to **every
    segment** of a compound category, so `container_mutation+network_send` needs a row
    that covers the image under each effect. A publish is a single
    `network_send` segment, so no bridge between `container_mutation` and `network_send` exists — "push
    the image" is one act and one effect. Extraction stores no prose for these categories — a
    value the grammar cannot read is dropped at extraction and pruned on import — and
    keeps the model's own category beside the deterministic one (`modelCategory`) so the
    listing can say what the model thought. The grammar only ever **widens inside these
    four categories**; fs, secret, privilege and system-config matching is untouched.
    Forbids are never narrowed by it: a revocation fires when the string rule, the
    grammar, or the wildcard's plain scope reaches the target, so "never push to origin"
    still vetoes `origin/main`. A denial that found a row of the right kind but the wrong
    target names it as a *near miss* with the sentence that would have covered it,
    and `/grants explain <command>` prints the same per-row verdicts on demand.
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
5. Otherwise: prompt. With a UI the options are the ones the person sees — *Allow*,
   `Allow for session: <the pending targets>`, `Allow for session (scope <scope>)`, and for a
   file tool also *Allow always (this folder)*, plus *Allow always (this project)* and *Allow
   always (global)*, and *Block*. On a NEVER verdict every "for session" and "always" option is
   withheld (only *Allow* and *Block* are offered, §1). Without a UI: deny with the category,
   entities and a one-line reason so the agent can ask the user in text.
   Every allow answer (including plain *Allow*, and excepting a NEVER verdict, which remembers
   nothing) records a session grant for the pending entities, so an identical action does not
   re-prompt. An *Allow always* answer additionally records a **durable** row, and `authority.persist`
   decides where it lives: `"grants"` (the default) writes it to the project's grants journal, which is
   what lets a project run with no hand-authored permission file at all; `"rules"` writes a permission
   rule instead. Either way the row may never say more than the invocation that earned it — where no
   row can express exactly what was approved, the click is honoured once and the user is told why,
   because a durable row is read back for the life of the project with no trace of the click that
   produced it, and a wider row is indistinguishable from permission.

Prompt-once memory is keyed by `{category, entity}`; a `delete_recursive` grant for
`./build` does not cover `./dist`, and a `write_outside` grant for `~/dev/other/` covers
files under it only if the user chose the scope option.

## 4. Model tasks (layer 1)

All tasks use `temperature 0` — **except a GitHub Copilot endpoint, where `temperature` is measured to be
refused** (`400 Unsupported parameter`) and is therefore never sent — `response_format: json_schema` on the
chat dialect / `text.format: json_schema` on the responses dialect (llama.cpp / vLLM / OpenAI and, measured,
Copilot's Auto path all accept it), thinking disabled where the server honours a knob, and a hard output-token
cap. Any transport or schema failure → the deterministic fallback
(`ASK`, prompt; a failed ledger extraction leaves the message queued for retry). **A truncated answer is a
transport failure, never a short verdict** — on a reasoning model the cap can be entirely spent on thinking
and return empty text (§4.0).

Each task carries its own short system prompt — `GRANT_SYSTEM_PROMPT`, `EFFECT_SYSTEM_PROMPT`,
`MESSAGE_GRANT_SYSTEM_PROMPT` in `model-client.ts` — and nothing in this design puts a number on how long
one may be. Size is handled by arithmetic, not by a rule of thumb: the call subtracts the fixed part's
measured cost from the endpoint's context window and lets the variable part fill what is left, whole items
only (§4.2, `callBudget` in `context-budget.ts`, `grantCallFixedChars` measuring the grant prompt by
rendering it). A prompt that is too big for the configured window is therefore not a violated budget but a
window too small, and it is reported as one.

One system prompt is not in that family and must not be confused with it: the auto-mode ruleset prompt —
some 9 kB of policy prose (roughly 2 200–2 800 tokens depending on the estimator), assembled by
`classifier-prompt.ts` out of `classifier-prompts/auto_mode_system_prompt.txt` and
`classifier-prompts/permissions_external.txt`. Three bullet blocks — allow, deny, environment — can each
be replaced wholesale by the user's configured rules, and a block left unset keeps the bullets shipped in
the template. The verdict block is **not** in either template: `classifier-prompt.ts` composes it and
splices it in, so the shape of the answer is code the tests can read rather than text a template can
silently contradict. Splicing is index arithmetic over the `{{rules:…}}` / `{{include:…}}` markers, no
regular expression touches the templates, and a marker that cannot be resolved is dropped rather than
sent, so a template that loses its include never leaks `{{include:verdict}}` to a model.
That prompt belongs to the **legacy** single-shot engine
(`classifier.engine: "legacy"`, `classifier-client.ts`), the one this document's §0 rejects; it is reachable
only when that key is set. Nothing on the gate path sends it, and the arithmetic shows why it cannot fit:
at that size the system prompt alone is more than half of the default 4 096-token window
(`classifier.contextTokens`, §4.0), before any transcript or answer reserve — and the transcript is the
evidence these tasks exist to read.

### 4.0 Transport and classifier configuration

One block in `~/.pi/agent/adaptive-acl.json` under `classifier` decides which transport every layer-1
question uses (resolved by `resolveClassifierConfig` in `config.ts`; the project-scoped
`<cwd>/.pi/adaptive-acl.json` covers `authority.persist` and provenance only — classifier settings are
not read from there). Three cases are supported; which one is live is decided by `classifier.baseUrl` and
`classifier.model` alone.

**Keys that exist** (nothing else may be invented; defaults in parentheses): `enabled` (true), `model`
(`"anthropic/claude-haiku-4-5"`, `"<provider>/<id>"`), `engine` (`"gate"` | `"legacy"`), `timeoutMs` (15000),
`contextTokens` (4096), `failClosed` (true), `stage`, `includeAgentsMd`, `ledger`, `ledgerBackfillLimit`,
`jsonlTranscript`, `baseUrl`, `modelId`, `maxOutputTokens`, `extraRequestFields` (both below), and the
Copilot-only block `copilot` (below).

| case | config | behaviour |
|---|---|---|
| **A — own OpenAI-compatible endpoint** | `classifier.baseUrl` (+ optional `modelId`) | Unchanged behaviour, and it outranks everything else: plain OpenAI-compatible POST to `{baseUrl}/chat/completions` with `response_format: json_schema` and `temperature: 0`, bypassing pi's registry **and the whole `copilot` block**, whatever `model` says. Needs a server that honours `json_schema` (llama.cpp, vLLM, litellm). |
| **B — Copilot Auto** | `"model": "github-copilot/auto"`, no `baseUrl` | The sentinel names a policy, not a model: the plugin mints **its own Auto session** (`POST {baseUrl}/models/session` with `X-GitHub-Api-Version: 2026-08-01`, cached and refreshed before `expires_at`, single-flight, 15 s failure cooldown — `copilot-session.ts`). The pick is only addressable with `Copilot-Session-Token`, so that header travels on every call; the wire dialect is the **pick's** catalog `api` (`openai-completions` → `/chat/completions`, `openai-responses` → `/responses`; an `anthropic-messages` pick has no encoder → resolves to no endpoint → the posture below). Because the pick is the plugin's own, host-model churn mid-session cannot silently change the classifier's model. |
| **C — explicit Copilot model** | `"model": "github-copilot/<id>"`, no `baseUrl` | The user's pick, dialect taken from the catalog `api` for that id. The session header is **never attached** — measured, it narrows the request to the Auto picks (`400 Requested model not available for session`). Correct by construction; nothing in this repository exercises it against a live free-plan account. `github-copilot/<id>@stage` / `:effort` suffixes are stripped before resolution, like every other ref. |

`classifier.copilot` — knobs that exist only because Copilot behaves differently (resolved by
`resolveCopilotConfig`; an unusable hand-edited value is ignored in favour of the default, never
propagated; read **only** on a `github-copilot/…` endpoint, so case A is untouched by them):

| key | default | meaning |
|---|---|---|
| `maxOutputTokens` | 512 | The **answer reserve** (`max_output_tokens` / `max_tokens`). A reasoning pick spends part of it thinking before any verdict exists (measured: 192 of 269 output tokens on a one-line classification; at a 120 cap the answer arrives EMPTY), so too small is not a shorter answer but no answer — reported as a transport failure. Values above 32 768 are treated as typos and ignored. |
| `reasoningEffort` | `"low"` | Sent as `reasoning.effort`, and only for a model the catalog marks as reasoning. Anything outside `low|medium|high` is refused at resolve time rather than forwarded to an endpoint that answers `400 Unsupported parameter`. |
| `budgetTokens` | 0 (= no cap) | Tokens this process may spend on Copilot before it stops asking — a free-plan allowance is shared with the user's own chat. A spent budget is a transport failure, never a refusal, and the denial text names it. |
| `sessionEnabled` | true | `false` turns the Auto session off: `github-copilot/auto` then resolves to **no endpoint at all** and the gate asks a person — how you leave every Copilot request for the user's own chat. |

**Answer limit and extra request fields.** Two keys apply to every endpoint, cases A–C alike, and
to both engines:

- `classifier.maxOutputTokens` — a **floor** on every call's answer reserve (`max_tokens` / `max_output_tokens`):
  the effective reserve is `max(call's own reserve, maxOutputTokens)`, and on Copilot `copilot.maxOutputTokens`
  still applies as before (`answerReserveTokens` in `model-client.ts`; `classifierAnswerReserveTokens` in
  `classifier-client.ts`). The built-in reserves are 300 (grant call), 400 (extraction), 512 (legacy stages).
  Every window budget subtracts the effective reserve, never the constant, so a raised limit narrows the prompt
  instead of overflowing the window. Valid values are whole numbers from 1 to 32 768 that are smaller than
  `contextTokens`.
- `classifier.extraRequestFields` — an object merged into the request body **after** the client builds it, on all
  three dialects (`request-fields.ts` `mergeRequestFields`; the legacy engine applies it through pi-ai's
  `onPayload`). Objects merge key by key; `null` removes a key. The top-level keys `model`, `messages`, `input`,
  `system`, `response_format`, `text`, `output_config`, `stream`, `max_tokens` and `max_output_tokens` are refused:
  the output schema is what makes a parse failure impossible, and the limit has its own key. Default `{}`.

The client sends **no** thinking-off field of its own. It used to add `chat_template_kwargs: {enable_thinking:
false}` to every non-Copilot request; which field a server understands (`reasoning_effort`, `reasoning.effort`,
`chat_template_kwargs`, nothing) is a fact about that server, so it is configuration. An invalid value in either
key is dropped and reported (`ClassifierConfig.problems`, shown by `/classifier-status` and once at session start),
never clamped or silently replaced. With `ADAPTIVE_ACL_CLASSIFIER_DEBUG=1` each gate request logs its URL,
dialect, effective limit and extra field **names** (never values), and each reply its status, finish reason,
token usage (reasoning tokens included when reported) and the first 300 characters.

**What the mint asks Auto for.** Copilot serves three request dialects and this client encodes
two, so **GitHub's Auto pick may be one we cannot put on the wire** — that possibility is a fact about Auto, not a
bug, and no request shape makes it impossible. `auto_mode.model_hints` was measured to close the gap as far as the
wire allows: the field filters the offered pool **by model id**
(`["gpt-5-mini"]` → pool `[gpt-5-mini]`, pick `gpt-5-mini`), it does **not** accept dialect names — a dialect name
is answered like any unmatched hint, `200` with `available_models: []` and `selected_model: ""`. So the mint asks
the measured control question first (`model_hints: ["auto"]`), and only when the resolver reports a pick whose
catalog `api` it cannot encode does it ask **once** more with `model_hints` set to the ids GitHub itself offered in
`available_models` whose dialect we do encode. Two rules hold that property: an id is never named in source (the
catalog churns within hours), and an empty hint list is never sent, because the one thing measured about a
hint that matches nothing is that it costs you the pool.

Whatever the retry achieves, an unspeakable pick stays exactly what the retry did not change: **an unavailable classifier naming
its cause** (`gate-bridge.ts`'s `auto-pick-unnamed` / `auto-pick-unspeakable`, rendered by
`classifierUnavailableReason` / `buildClassifierUnavailableMessage` in `classifier-messages.ts` — call those, do not
restate their text here or in a denial), which asks in a terminal and declines unattended. Never a silent fallback,
never a refusal, never "no endpoint configured" when an endpoint exists.

**Failure posture.** Layer 0 decides whatever it can decide in code. Where it
cannot and the classifier is unreachable: **interactive sessions ask the user; unattended runs decline with
the reason naming that the classifier was not available** — the existing catch in `index.ts` falls back to
the tier-3 prompt, which is a prompt in a terminal and a decline in a headless run. Every Copilot-specific
failure must therefore reach that catch as a transport failure and never be parsed as a verdict: 404-with-
an-empty-body (missing version header), `model_not_supported` (missing session token), `Unsupported
parameter` (a forbidden field), a spent `budgetTokens`, a truncated answer, and a dialect with no encoder.
A classifier that cannot reach its model is an unavailable classifier, not one that votes "no".

**The extraction piece width is sized on measured tokens.** The per-message grant extraction (§4.3)
must fit its fixed prompt, one whole piece of the user's message, and an answer reserve into one context
window. The sizing uses two per-call constants measured against the served endpoint's own
`usage.prompt_tokens` — one for the fixed prompt text, one for the message piece — because the two halves
are different text and tokenise differently; the global `CHARS_PER_TOKEN` estimate in `context-budget.ts`
is tuned for path- and code-heavy transcripts and overstates this prompt by a third. Two measured properties
of the endpoint shape the arithmetic: the `response_format` schema is **not** counted in `prompt_tokens` (it
becomes a decoding grammar, not prompt text), and the server's window check compares `prompt_tokens` alone
against the window — `max_tokens` is not part of its check. The answer reserve is therefore our own budget,
not the server's error margin, and it must still be paid: an answer cut off mid-JSON is a transport failure,
not a verdict. On the default 4096-token window this leaves pieces of a few thousand characters (about 3 200
at the time of writing); smaller windows shrink smoothly toward a 384-
character floor, and a window that cannot pay for prompt plus floor gets a call that fails — the message
stays unseen and the action costs one prompt, never a silent allow. When a piece still outgrows the server's
count (code-dense content tokenises denser than prose), the extraction splits that piece in half and re-reads
it, merging rows in message order: an estimation error there costs extra model calls, never a lost message.

### 4.1 Effect classification (for UNKNOWN)

Input: the command text (≤ 1500 chars), the effective cwd, the project root.
Output: `{"effect": <enum of 2.1–2.3 categories + "read_only" + "write_project" + "run_project_code">, "targets": string[], "outside_project": boolean, "confidence": "high"|"medium"|"low"}`.
Mapping: `read_only|write_project|run_project_code` with `outside_project=false` and
confidence ≠ low → ALLOW; any ASK category → ASK with `targets` as entities; any NEVER
category → NEVER; `low` confidence → ASK (`interpreter_unknown`).

### 4.2 Transcript authorisation (for ASK)

Input: the pending action rendered in plain words by layer 0 ("recursively delete
directory ./build (rm -rf ./build)"), its category and entities, and as much of the recent
conversation as this model's window holds. There is no fixed message count and no character cap —
the sizes that used to sit here were measured in a unit the server does not use, and the request
they produced was rejected outright:

- at most the newest **60** user messages are candidates (`MAX_USER_MSGS`, `gate.ts`);
- the room they get is the endpoint's `classifier.contextTokens` minus the call's fixed part, measured
  by rendering the real prompt, minus the answer reserve (§4.0);
- that room is filled **whole, newest-first, stopping at the first message that does not fit**
  (`fitNewestFirst`, `context-budget.ts`). So what the model sees is a contiguous suffix of the
  conversation: never half a sentence — clipping "…and never touch prod" mid-line invents evidence
  that reads like the approval it was cutting off — and never a gap an older message jumped over;
- if the newest message alone does not fit, the call is **not made** and the action prompts. Asking
  for a verdict from no evidence is not a no, it is a question that was not asked.

A 4 096-token window holds a handful of messages, so authorisation would otherwise be a function of
scroll position — the grant was said twenty turns ago and is gone. It is not gone: that sentence
already sits in the ledger as a row (§3 item 3), and the rows are sent in the same call as the summary
of the turns that no longer fit. Rows are fitted against 40 % of a budget measured without them
(`LEDGER_SHARE`), then the fixed part is re-measured with them, so any share the rows could not spend
returns to the raw messages and no block size is hard-coded. A row is one line, oldest first, in a
layout the model is asked to read and the verifier does not parse:

```
#<seq> <kind>[ imported] <category> <entity|scope>=<value> — "<the user's own words>"
```

`kind` is `grant`, `forbid` or `posture`, padded to a fixed column so the categories line up; a row
imported from the project's journal says `imported`, sorts first and carries `seq 0`, because it is
background authority that anything said on this branch outranks (§3); every run of whitespace is
collapsed, so a pasted multi-line message cannot break the layout; values go out **absolute**, because
`~` means nothing to a model that has never seen this machine; and the quote is clipped at 120
characters **in the rendered line only** — the row keeps the full verbatim quote, which is what the
verifier must still find. Rows are dropped whole, oldest first, for the same reason messages are.

Output: `{"authorized": "yes"|"no", "allowed_targets": string[], "forbidden_targets": string[], "quote": string}`.
The code verification of §3 item 4 is mandatory; a `yes` alone never allows anything.

### 4.3 Per-message grant extraction (for the ledger)

Input: ONE user message, cut to pieces no wider than the endpoint's own window can pay for
(`extractionChunkChars`, §4.0) — so there is no pending action to
echo from, and requiring extracted names to appear verbatim in the message is sound.
Output: `{"grants": [{action, targets[], quote}], "revocations": [{targets[], all, quote}]}`
(schema-capped: ≤ 8 items each, ≤ 16 targets). Code verifies each item (verbatim quote in
the message, targets whole-token present, pronouns dropped), takes the model's own `category` for every row —
`action` is a display label and decides nothing — and folds the result into the ledger.
Run lazily on gate invocations: ≤ 2 calls inline (typically 1 — the message that started
the turn); larger backlogs (sessions predating the plugin, restarts without a snapshot)
drain via background backfill, **newest-first**, capped at the newest 400 user messages.
Newest-first makes a *partially* backfilled ledger safe: every grant present already has
all later messages processed, so nothing later-revoked can be allowed. The ledger and
session grants are snapshotted into the session (debounced) and restored on resume,
dropping entries whose source message is no longer on the branch; with no snapshot,
temp-0 extraction rebuilds the same ledger from scratch.

### 4.3b Withdrawals: category lists, `any`, container reach

**Revocation category is a list.** A revocation row's `category` is a non-empty list of 1–6 values from the revocation
vocabulary (the grant vocabulary plus `any`). A grant row's `category` stays exactly one value. Meaning comes from the
model: the model decides which kinds a sentence withdrew, and code only applies what the row says — no code reads the
sentence. A list longer than the bound is refused whole (the row is defused: no auto-allow from it, one prompt),
never truncated, because a silently narrowed ban reads as obedience.

**`any` — every action on the thing.** `any` is a revocation-only value meaning every action on the named target and
on everything inside it (objects in a bucket, files under a directory, resources in a namespace), reads included.
"Leave X alone" / "do not touch X" is `any`; "do not write in X" is the write kinds (and, as for files, deletes and
overwrites inside X, not reads); "don't write or delete in X" is exactly those two. The asymmetry is deliberate: a
missed grant category costs one prompt, a missed forbid category costs an allow, so widening is granted to forbids
only. Every door a grant row comes through refuses `any` — the extraction parser, `asGrantRow`, `addGrant`, the fold —
and the schema never offers it on the grant side.

**`any` with nothing named is the whole-session stop, and a stop is not the same thing as a ban.** A revocation row
naming `any` and no target the verbatim check accepts sets the read-only posture ("stop doing things") — the same
outcome the scope-`everything` vocabulary produces. It also leaves a `forbid any *` row behind whenever the model's own
width is `category`, because a posture is a DEFAULT: the gate consults grants before it, and `readOnlyLiftedByGrant`
lifts it for a target a later grant covers, while a ban is not lifted that way. At width `named` no `*` row is written:
the width is the model's claim, not code's.

**A withdrawal whose target is a phrase is defused, and defusal is a deferral — not a veto.** A target the user wrote
verbatim but that names no placeable thing ("build artefacts", "the certificates directory") cannot equal anything the
gate produces, so its forbid rows reach nothing on their own. The sentence is kept exactly as the model wrote it, and
a `*unknown*` marker row is left beside it. Within its own message the marker means "no auto-allow": a grant extracted
from the same message — same `seq` — can no longer answer the action the user withdrew in the same breath (case
`L-18` in `testcases/cases-ledger.jsonl`: a message that granted a folder and withdrew it again in words describing it, where the grant won).
Outside that message the marker is inert: it names no capability, so it bans nothing, licenses nothing, and cannot
outlive its own message or arm a session lock. The gate's own model call, which reads the conversation, decides
the prompt.

**Container reach is for forbids only.** A forbid on a container reaches what is inside it: a bucket name matches its
object-store URIs in any scheme the target grammar knows (`archive` ↔ `s3://archive/…`), a prefix ends at a `/`
(`s3://archive/dev` does not reach `s3://archive/development/x`), and a directory reaches files under it. Grants keep
today's exact matching; if that costs an unnecessary prompt, that is the cost to pay, not the rule to widen.

**Store forbid family.** A forbid on `network_send` is also a forbid on `delete_data` and the reverse
(`STORE_FORBID_FAMILY`), because exfiltration needs an upload and a purge needs a delete — the same argument the
`fs-mutation` family already makes for files. `forbidCompatible` also treats `any` as matching every category on
either side. Forbids stay deliberately coarse where grants are narrow: a revocation must dominate everything the
sentence could plausibly have covered.

**Bucket deletion is `cluster_wide_destroy` at tier `never`, not `delete_data`.** Deleting a whole bucket
(`aws s3 rb`, `aws s3 rm --recursive s3://bucket/`) is what layer 0 already says it is; "delete objects inside it" is
`delete_data`; "leave the bucket alone" is `any`.

**What the wire asks for, and why.** The schema asks for the array; a bare string is still honoured by the parser,
which is where tolerance costs nothing. Measured over 233 real messages, `anyOf: [string, array]` scored *worse*
than the array alone, and the models measured returned only one-element lists anyway, so the wider grammar
bought nothing.

### 4.3c What a grant implies

A grant answers more than the category it was filed under, but only in the three directions named here. The
directions live in `grant-verify.ts` (`grantDirection`, `grantAnswersSegment`, `categoryDirection`) and the
ledger (`auth-ledger.ts`), the session store (`session-grants.ts`) and the transcript verdict
(`grant-verify.ts:verifyGrant`) all ask the same function, so they cannot drift apart about what a permission
contains.

- **Write implies read, inside the row's own scope.** A row that permits creating or changing content at a
  place also permits reading there: you cannot edit what you cannot open. Secret-class paths are **included**
  (an edit of a credentials file needs the read that precedes it), which is why `read_secret` is reachable from
  `fs-write`/`secret-write` and, through delete→write, from `fs-delete`. The direction is one-way: a **read
  grant buys no change of any kind**, and a read of a machine (`read_system_state`) is never answered by a grant
  over files.
- **Write implies the single-file delete.** Removing ONE file is part of editing it (`rm file`, and `mv`,
  which is delete+write). Three things stay refused: `delete_recursive`, `delete_data`, and deleting the folder
  the row was granted over ("write inside /x/" is not "delete /x"). A row that names no object (`*`) authorises
  no delete at all. A delete grant still covers writes inside it (unchanged), and therefore reads. A write grant on the temp roots therefore also opens a secret-class file there: credentials are recognised only by name shape, so there is no reliable way to single them out.
- **The task in hand approves the reads it obviously needs.** The transcript grant call may answer
  `authorized: "yes"` for a `read_only` or `read_system_state` action on the strength of a message that asks for
  the task, with `allowed_targets` empty (a task implies the read, not a name). It never implies `read_secret`, it
  is never authority for a change (write, delete, install, restart, push, permission change), and a task-implied
  read loses to a forbid. The judged part is the model's; code supplies only the two allowed read categories, the
  `authorized` check, the verbatim quote and the forbid veto.
- **A service-named status grant covers that service.** `read_system_state` grants naming a unit answer
  reads scoped to it: `journalctl -u X` / `--unit X` and the unit-scoped `systemctl` subcommands (`status`,
  `show`, `cat`, `is-active`, `is-enabled`, `is-failed`) put the unit in the object (`localhost/X`), so a
  `nginx` grant matches while a machine-wide read (`journalctl` with no `-u`, `df`, `uptime`,
  `systemctl list-units`) keeps the bare machine object and keeps asking. A machine grant still answers the
  unit-scoped read (§2.9b still holds), and two units in one read name neither service.
- **Garbage.** Every direction is applied to a category string and a target only. An unknown category, an empty
  effect list, an `authorized: "no"` row that still names effects, a pronoun target, an object-less row or a
  value that is not a path all fall through to the next layer: one prompt, or one more model call. None of them
  can widen a row, and none of them can produce an allow on its own.

Measured against real session history and the `testcases/` suites on three models: no new false allows, and the
reads these rules were written for stopped prompting.

## 5. Observability and safety rails

- Every decision can be logged: `ADAPTIVE_ACL_CLASSIFIER_DEBUG=1` turns on the gate, ledger and
  classifier lines (layer, category, entities, model latency, and for a model answer the raw JSON and
  the verification result); `ADAPTIVE_ACL_DEBUG=1` covers the parser's own lines.
- Denials tell the agent the category and entities so it can ask the user precisely, and an
  unavailable classifier is named as one (`/classifier-status` distinguishes disabled, no endpoint
  resolved, and endpoint present but failing — three states that look identical to the user).
- **Transport failure on the legacy path**: a classifier call is attempted up to 3 times
  (`MAX_CLASSIFIER_FAILURES`); if every attempt fails the call is **denied** with a message naming the
  transport error, unless `classifier.failClosed` has been set to `false`, in which case the
  deterministic local answer decides. No failure path ends in an approval.
- **Denial budget** (`denial-tracking.ts`, also the legacy path): 3 refusals in a row with no allowance
  between them, or 20 refusals across the run, and the model stops being asked and the call prompts the
  person instead. It counts refusals, not failures, and the two counters are deliberately different:
  an approval resets the streak (evidence the agent is off that one door) and never the total
  (refusals scattered over a run still add up, and no healthy run reaches twenty).
  The gate path needs neither counter for a transport failure — an unanswerable call prompts, or
  declines when there is no UI, on the spot (§4.0's failure posture).
- **Verdict memo (legacy path, `classifier-client.ts`)**: an identical call — same model ref, stage,
  mode, cwd, tool name and serialised input, same configured auto-mode rules and same rules-file
  generation — is answered from cache for 60 s, bounded at 64 entries. Reloading the permission rules
  drops the whole cache, because a verdict computed under the old rules must not outlive them.
- **Reproducibility is a claim to be measured, not a property to be asserted.** `temperature 0` and a
  schema-constrained answer of a few tokens make the same input answer the same way in practice, but
  "across two server restarts" is exactly where a small model has been seen to flip, so any figure for
  a flip rate has to ship with the measurement that produced it. This repository pins behaviour with
  the corpora below and claims no number of its own.

## 6. Acceptance criteria

These are the targets the design was held to, recorded because they say what the design is trying to
buy and in what proportions. What this repository can show you is narrower, and the difference matters
to anyone who wants to check a line:

- **Pass/fail, in the tree.** Layer 0's accepts and refuses are pinned line by line by
  `bash-walker.golden.jsonl` (LAYER0 §15); the allow-rule suggestion engine is pinned over the curated
  corpora `testcases/cases-v2.jsonl` and `testcases/cases-ledger.jsonl` by the invariant "an offer that
  is made is an offer that covers the command that earned it"; and the categories, path rules, grant
  matching and transports above are pinned by the suites `npx vitest run` executes. A regression in a
  NEVER case fails one of these, which is the only honest way the first line below is enforced.
- **Not in the tree.** Anything that needs a labelled corpus, a live endpoint or a clock: the
  percentages, the latency, and the restart-to-restart flip rate. A prompt corpus shipped with the
  package would be a fixture nobody could audit and a benchmark someone else's bill, so none ships, and
  no number in this table is measurable from inside this checkout. Treat them as the contract, not as a
  result this package reports.

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
