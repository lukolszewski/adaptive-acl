import { beforeAll, describe, expect, it } from "vitest"
import { classifyBashTiers, isFallbackBash, isReadOnlyBash, isWorkflowBash } from "./bash-tiers.ts"
import { categoryHasStrictOperands, hitsNeverFloor } from "./bash-audit.ts"
import { initBashParser } from "./bash-parser.ts"

/**
 * The tier ladder over layer 0, pinned case by case.
 *
 * The table is the specification: each row states the three faces (`readOnly` / `workflow` / `fallback` as
 * `T`/`f`) and the property the row exists to hold. Rows are grouped by the axis that decides them — the
 * allowlist, the compound rule, quoting, what the walker refuses, the guardrails — because those are the
 * places where this ladder could silently drift from the text ladder it replaces.
 *
 * A synthetic cwd is used on purpose: `/home/user/project` has no `package.json`, so `npm run <script>` is
 * classified the way it is for any user who has not declared the script, and nothing here reads the tree the
 * tests run in.
 */

const cwd = "/home/user/project"

beforeAll(async () => {
	await initBashParser()
})

const letters = (command: string): string => {
	const tiers = classifyBashTiers(command, cwd)
	return [tiers.readOnly, tiers.workflow, tiers.fallback].map((v) => (v ? "T" : "f")).join("")
}

const tiersOf = (command: string) => classifyBashTiers(command, cwd)

/** command, expected faces (read-only / workflow / fallback), the property the row pins */
type Row = [string, string, string]

describe("tier 1 — the read-only allowlist", () => {
	const rows: Row[] = [
		["cat notes.md", "TTT", "plain read-only"],
		["head -50 log", "TTT", "plain read-only"],
		["tail -f log", "TTT", "plain read-only"],
		["grep -rn TODO src", "TTT", "plain read-only"],
		["ls -la", "TTT", "plain read-only"],
		["pwd", "TTT", "plain read-only"],
		["echo hi", "TTT", "plain read-only"],
		["wc -l f", "TTT", "plain read-only"],
		["jq . package.json", "TTT", "plain read-only"],
		["rg TODO", "TTT", "plain read-only"],
		["printenv HOME", "TTT", "plain read-only"],
		["git status --short", "TTT", "git subcommand in the list"],
		["git log --oneline -5", "TTT", "git subcommand in the list"],
		["git diff HEAD~1", "TTT", "git subcommand in the list"],
		["git ls-files src", "TTT", "git ls-* prefix"],
		["git remote -v", "TTT", "git subcommand in the list"],
		["git config --get user.email", "TTT", "git config only with --get"],
		["npm ls --depth=0", "TTT", "npm read-only subcommand"],
		["npm view react version", "TTT", "npm read-only subcommand"],
		["yarn info left-pad", "TTT", "yarn read-only subcommand"],
		["node --version", "TTT", "node only with --version"],
		["python --version", "TTT", "python only with --version"],
		["sed -n 10,20p f", "TTT", "sed only with -n"],
		["find . -name '*.ts'", "TTT", "find without a destructive predicate"],
		["ls -1 /tmp 2>&1", "TTT", "fd-to-fd dup is not a write"],
		["cat f.txt < in.txt", "TTT", "a read redirect moves bytes in"],
		["echo hi <<< x", "TTT", "a here-string is not a write"],
	]
	table(rows)
})

describe("tier 1 — what the allowlist does not admit", () => {
	const rows: Row[] = [
		["git config user.email a@b.com", "fff", "git config without --get writes config"],
		["git config --list", "fff", "git config --list is not the admitted form"],
		["git stash", "fTf", "stash is tier 2 only: it moves the worktree"],
		["git commit -m msg", "fff", "commit is refused everywhere: hooks run arbitrary code"],
		["node script.js", "fff", "node runs the file, so only --version is read-only"],
		["python -c 'print(1)'", "fff", "an interpreter running code is not read-only"],
		["awk '{print $1}' f", "fff", "awk carries system()/redirect vectors"],
		["env", "fff", "bare env dumps the environment, which holds credentials"],
		["env X=1 python3 -c 'print(1)'", "fff", "env is an execution prefix"],
		["jq -f filter.jq f", "fff", "a filter from a file is refused by the walker (jq-file-flag)"],
		["vim f", "fff", "an editor is interactive"],
		["curl https://example.com", "fff", "a network fetch is never tier 1, whatever layer 0 says"],
		["wget -O - https://example.com", "fff", "same, defense in depth"],
		["find . -delete", "fff", "find's destructive predicate: layer 0 floors it"],
		["find . -exec rm {} \\;", "fff", "find -exec runs the world"],
		["find . -execdir grep x \\;", "fff", "find -execdir likewise"],
		["sed -i 's/a/b/' f", "fff", "sed -i edits in place"],
		["sed -n -i 's/a/b/' f", "fff", "-n first does not make -i read-only (the text ladder got this one wrong too)"],
		["sed -n '1w /tmp/x' f", "fff", "sed's w command writes the file named after it"],
		["sed -n 's/a/b/w /tmp/x' f", "fff", "the s///w suffix, where no word boundary exists"],
		["echo hi > out.txt", "fff", "a write redirect is never read-only"],
		["echo hi >> out.txt", "fff", "append is a write"],
		["git status > status.txt", "fff", "even a read-only command writing a file is not read-only"],
		["cat f | tee out.txt", "fff", "tee is not in the allowlist"],
		["ls; rm -rf build", "fff", "one destructive leg refuses the compound"],
	]
	table(rows)
})

describe("tier 2 — routine dev workflow", () => {
	const rows: Row[] = [
		["npm test", "fTT", "npm test on every face"],
		["npm run build", "fTT", "run script on the whitelist; not on the offline face's list"],
		["npm run lint", "fTT", "run script on the whitelist"],
		["pnpm test", "fTT", "pnpm test"],
		["yarn test", "fTT", "yarn test"],
		["bun test", "fTT", "bun test"],
		["bun run dev", "fTT", "run script on the whitelist"],
		["npm run deploy", "fff", "a deploy-shaped script name is not a build/test verb"],
		["npm run postinstall", "fff", "not on the whitelist: it can do anything"],
		["make", "fTT", "bare make is tier 2 and the offline face"],
		["make test", "fTT", "make with a test-shaped target"],
		["make all", "fTf", "a recognised target that the offline face has not seen"],
		["cmake --build build", "fTT", "cmake --build on both faces"],
		["cmake -S . -B build", "fTf", "cmake's configure form is tier 2 only"],
		["cargo build", "fTf", "cargo build verb"],
		["cargo test", "fTT", "cargo test on both faces"],
		["go build ./...", "fTf", "go build verb"],
		["go test ./...", "fTT", "go test on both faces"],
		["git add .", "fTf", "local git write with no hook vector"],
		["git switch main", "fTf", "local git worktree op"],
		["git stash", "fTf", "stash is tier 2, not read-only"],
		["git reset", "fTf", "plain reset is tier 2"],
		["git reset --hard", "fff", "--hard discards work: refused by name"],
		["git clean -fd", "fff", "clean discards untracked files"],
		["git push", "fff", "push is refused everywhere (layer 0: vcs_remote/ask)"],
		["git checkout main", "fff", "checkout can lose the worktree"],
		["mkdir -p src/components", "fTf", "mkdir inside the project"],
		["touch notes.md", "fTf", "touch inside the project"],
		["cp a.txt b.txt", "fTf", "cp inside the project"],
		["mv a.txt b.txt", "fTf", "mv inside the project"],
		["npx prettier --check .", "fTf", "npx with a pinned tool"],
		["npx some-unknown-tool", "fff", "npx of an unknown package downloads and runs code"],
		["eslint . --fix", "fTf", "a pinned linter"],
		["tsc --noEmit", "fTf", "type checker"],
		["vitest run", "fTT", "a pinned test runner"],
		["pytest -q", "fTT", "a pinned test runner"],
		["mocha", "fTf", "a pinned test runner, tier 2 only"],
		["docker build .", "fTf", "docker build has no host-mount vector"],
		["docker ps", "fTf", "docker read verbs"],
		["docker compose ps", "fTf", "a read-only compose verb stays tier 2 (D1)"],
		["docker run -v /:/host ubuntu", "fff", "docker run/exec are never tier 2 (host-mount execution)"],
		["npm install", "fff", "install is not a workflow verb: it pulls code from the network"],
		["pip install requests", "fff", "system package install is ask at layer 0"],
	]
	table(rows)
})

describe("tier 2 — compose is split by verb (D1)", () => {
	const rows: Row[] = [
		["docker compose ps", "fTf", "the read-only verbs stay: these are the ones run ten times an hour"],
		["docker compose ps -a", "fTf", "a flag after the subcommand does not change the verb"],
		["docker compose logs --tail 50 web", "fTf", "logs reads state"],
		["docker compose config", "fTf", "config renders the file it already has"],
		["docker compose top", "fTf", "top reads state"],
		["docker compose images", "fTf", "images reads state"],
		["docker compose port web 8080", "fTf", "port reads state"],
		["docker compose version", "fTf", "version reads state"],
		["docker compose up", "fff", "up starts containers that mount host paths and publish ports: tier 3"],
		["docker compose up -d", "fff", "detached is the same container"],
		["docker compose down", "fff", "down stops and removes them"],
		["docker compose build", "fff", "builds an image from repo code: layer 0 calls it run_project_code"],
		["docker compose create", "fff", "create is a state change"],
		["docker compose stop", "fff", "stop is a state change"],
		["docker compose restart", "fff", "restart is a state change"],
		["docker compose watch", "fff", "watch runs services on file changes"],
		["docker compose cp a web:/tmp/a", "fff", "cp moves bytes into a container"],
		["docker compose run web pytest", "fff", "run is arbitrary code in a container that mounts the repo"],
		["docker compose exec web bash", "fff", "exec likewise — it inherits nothing from the compose entry"],
		["docker compose --profile extra up", "fff", "a global flag in front does not hide the verb from the refusal"],
		["docker compose", "fff", "no verb at all is not the read-only form"],
		["docker compose ls", "fff", "read-only, but not one of the verbs the decision names: fail closed"],
		["docker compose events", "fff", "same — see RESULT.md, this one costs a prompt"],
	]
	table(rows)
	it("refuses run/exec from the table, not only from the guardrail", () => {
		// `exec` is also a refused word, so the guardrail would catch it on its own; the split is about the entry, so
		// what has to be pinned is that the table itself is what says no to `run`.
		expect(tiersOf("docker compose run web pytest").reason).toBe("workflow-table")
		expect(tiersOf("docker compose exec web bash").workflow).toBe(false)
	})
	it("keeps the read-only compose verbs out of tier 1", () => {
		// They read container state, not the filesystem: the read-only face is about arguments being data, and
		// `docker` is not a command whose every argument can be trusted to be inert.
		expect(tiersOf("docker compose ps").readOnly).toBe(false)
		expect(tiersOf("docker compose ps").fallback).toBe(false)
	})
})

describe("tier 2 — a task runner names a target the table has seen (D2)", () => {
	const rows: Row[] = [
		// make: the recognised verbs stay, the install verbs and every unseen name do not.
		["make build", "fTT", "build is on the table"],
		["make check", "fTT", "check is on the table, and on the offline face"],
		["make clean", "fTf", "clean is on the table"],
		["make lint", "fTf", "lint is on the table"],
		["make fmt", "fTf", "fmt is on the table"],
		["make -j4 test", "fTf", "a fused flag does not hide the target"],
		["make -j 4 test", "fTf", "an optional numeric flag consumes its value only when it is a number"],
		["make -C build test", "fTf", "-C consumes its directory, so `test` is still the target"],
		["make -j4 -C build test", "fTf", "two flags, one target"],
		["make -B", "fTf", "flags only: the default target, which for make is a build"],
		["make build test", "fTT", "several targets, every one of them recognised"],
		["make build docs", "fff", "one unrecognised target refuses the whole invocation"],
		["make -C build install", "fff", "an install target behind -C is still an install target"],
		["make -o install", "fff", "a denied word cannot hide by being the value of a flag"],
		["make install", "fff", "install: layer 0 already floors it, and the table refuses it too"],
		["make uninstall", "fff", "the deny list is the ladder's own: layer 0 calls this run_project_code"],
		["make deploy", "fff", "deploy is not a build verb"],
		["make publish", "fff", "publish is not a build verb"],
		["make release", "fff", "release is not a build verb"],
		["make bootstrap", "fff", "an unrecognised target asks: a Makefile is arbitrary code"],
		["make setup", "fff", "the fail-closed half of the decision, and the expensive one"],
		["make test ARGS=-v", "fff", "an inline assignment changes what the target does, so it is not a target"],
		// cmake: verbs are flags, and `--install` is the one everybody reaches for.
		["cmake --build build -j 8", "fTT", "the -j value is not mistaken for a target"],
		["cmake --fresh -S . -B build", "fTf", "a boolean flag does not swallow -S"],
		["cmake --build build --target test", "fTT", "a recognised --target is still a build"],
		["cmake --build build --target docs", "fff", "an unrecognised --target is not"],
		["cmake --install .", "fff", "copies into a prefix outside the project"],
		["cmake --install build --prefix /usr/local", "fff", "same, in the spelling that says it out loud"],
		["cmake .", "fff", "in-source configure names no form the table knows"],
		["cmake --preset gcc", "fff", "a preset name is a name nobody has vouched for"],
		["cmake -E copy a.txt b.txt", "fff", "cmake's shell mode is not a build"],
		["cmake --version", "fTf", "version is tier 2 only"],
		// ninja, just, task, bazel: new to tier 2, and only for the verbs on the table.
		["ninja", "fTf", "bare ninja builds the default targets, which is documented, unlike a default recipe"],
		["ninja -C build", "fTf", "-C consumes its directory"],
		["ninja -C build test", "fTf", "a recognised target behind two flags"],
		["ninja -C build -j 8 all", "fTf", "three flags, one target"],
		["ninja install", "fff", "ninja's install target is an install step"],
		["just build", "fTf", "just's recognised recipes"],
		["just test", "fTf", "test is on the table"],
		["just --list", "fTf", "listing recipes reads the justfile"],
		["just", "fff", "bare just runs the first recipe, a name the ladder cannot see"],
		["just install", "fff", "install is on the deny list here too"],
		["task build", "fTf", "task's recognised tasks"],
		["task test", "fTf", "test is on the table"],
		["task --list", "fTf", "listing tasks reads the Taskfile"],
		["task default", "fff", "the default task is whatever the Taskfile says it is"],
		["task deploy", "fff", "deploy is not a build verb"],
		["bazel build //...", "fTf", "a bazel label is an operand, not an absolute path"],
		["bazel test //...", "fTf", "test is on the table"],
		["bazel test //pkg --test_output=errors", "fTf", "a fused flag with a value"],
		["bazel test :unit", "fTf", "a package-relative label is an operand too"],
		["bazel build //pkg:target --define=x=1", "fTf", "a define is data for the build"],
		["bazel clean", "fTf", "clean is on the table"],
		["bazel coverage //...", "fTf", "coverage is on the table"],
		["bazel query //...", "fTf", "bazel's read verbs are its own addition to the list"],
		["bazel run //cmd/server", "fff", "run executes a built binary in the workspace, so it goes the way of exec"],
	]
	table(rows)
	it("says that the target table is what refused", () => {
		expect(tiersOf("make bootstrap").reason).toBe("workflow-table")
		expect(tiersOf("cmake --install .").reason).toBe("floor-ask")
		expect(tiersOf("cmake .").reason).toBe("workflow-table")
	})
	it("keeps a task runner out of tier 1 and off the offline face", () => {
		// Adding a tool to tier 2 must not widen the other two faces: the offline face still knows only the
		// make/cmake forms it has always known.
		expect(tiersOf("bazel test //...").readOnly).toBe(false)
		expect(tiersOf("bazel test //...").fallback).toBe(false)
		expect(tiersOf("just test").fallback).toBe(false)
		expect(tiersOf("make test").fallback).toBe(true)
	})
})

describe("the compound rule: every leg must pass", () => {
	const rows: Row[] = [
		["ls && echo ok", "TTT", "&& chain of read-only legs"],
		["ls; echo ok", "TTT", "; chain"],
		["ls || echo missing", "TTT", "|| chain"],
		["ls | head -5", "TTT", "pipeline"],
		["ls -1 | grep x | wc -l", "TTT", "three-stage pipeline"],
		["ls & echo ok", "TTT", "backgrounded leg"],
		["ls\ngit status", "TTT", "newline-separated statements"],
		["ls && rm -rf /tmp/x", "fff", "one && is not enough: every leg must pass"],
		["ls; python -c \"open('/tmp/x','w').write('x')\"", "fff", "second leg runs code"],
		["echo hi > out.txt", "fff", "a redirect is attributed to its own leg, not lost"],
		["npm test && git push", "fff", "a workflow leg plus a refused leg refuses"],
		["git status && docker compose up", "fff", "a compose leg refuses the compound: D1 reaches compound commands"],
		["make test && make install", "fff", "one recognised target and one install step is an install step"],
		["git status && echo done | head -5", "TTT", "mixed connectors, all read-only"],
	]
	table(rows)
})

describe("quoting: an argument is data, not a command", () => {
	const rows: Row[] = [
		["echo 'a;rm -rf /'", "TTT", "a dangerous string is a string"],
		["echo \"rm -rf /\"", "TTT", "same in double quotes"],
		["rg -F '$(' src", "TTT", "a substitution marker inside a literal pattern"],
		["echo 'literal ` text'", "TTT", "a backtick inside single quotes"],
		["git status | grep \"a>b\"", "TTT", "a > inside a quoted argument is not a redirect"],
		["printf '%s;rm' x", "TTT", "a format string is data"],
		["echo 'one;two'", "TTT", "one leg, not two: the splitter cannot cut inside quotes any more"],
	]
	table(rows)
	it("counts one leg where the text splitter saw two", () => {
		const one = tiersOf("echo 'one;two'")
		expect(one.legs).toBe(1)
		expect(one.floor).toBe("allow")
		expect(one.category).toBe("read_only")
	})
})

describe("what layer 0 refuses is never auto-safe", () => {
	const rows: Row[] = [
		["echo $(whoami)", "fff", "command substitution — §12 command-substitution"],
		["cat <(ls)", "fff", "process substitution"],
		["grep x <(ls)", "fff", "process substitution as an argument"],
		["echo `ls`", "fff", "backtick substitution"],
		["echo $HOME", "fff", "a variable the walker has no literal value for"],
		["echo ${HOME}", "fff", "same in braces"],
		["for f in *; do echo $f; done", "fff", "loop body — iteration is a run-time fact"],
		["if test -f x; then ls; fi", "fff", "conditional body"],
		["case x in y) ls;; esac", "fff", "case statement"],
		["{ ls; }", "fff", "brace group"],
		["f() { ls; }; f", "fff", "function definition"],
		["cd /tmp && ls", "fff", "cd is not on the allowlist on any face"],
		["(cd /tmp && ls)", "fff", "the subshell's legs are still legs, and cd is still refused"],
		["cat <<EOF\nrm -rf x\nEOF", "fff", "an unquoted heredoc delimiter is expanded by the shell"],
		["cat \"$HOME/x\"", "fff", "a runtime placeholder makes the leg opaque (unproven_value)"],
		["cat 'unterminated", "fff", "a command that does not parse proves nothing"],
	]
	table(rows)
	it("reports the §12 id rather than a guess", () => {
		expect(tiersOf("echo $(whoami)").reason).toBe("command-substitution")
		expect(tiersOf("for f in *; do echo $f; done").reason).toBe("loop-body")
		expect(tiersOf("echo `ls`").reason).toBe("command-substitution")
		expect(tiersOf("cat 'unterminated").reason).toBe("unterminated-quote")
	})
	it("marks an unproven command unproven, so no caller reads the booleans as evidence", () => {
		expect(tiersOf("echo `ls`").proven).toBe(false)
		expect(tiersOf("echo `ls`").floor).toBeNull()
	})
})

describe("severity: the floor outranks the table", () => {
	const rows: Row[] = [
		["rm -rf /", "fff", "never floor"],
		["dd if=/dev/zero of=/dev/sda", "fff", "device write is floored"],
		["rm -rf build", "fff", "delete_recursive is ask: a table match cannot outrank it"],
		["chmod 600 f", "fff", "chmod is refused by the table and by the floor"],
		["sudo ls", "fff", "privilege escalation is ask, and `sudo` is a refused word"],
		["time npm test", "fff", "time is not on the allowlist, so a wrapped command is refused"],
		["nice -n 5 npm test", "fff", "same for nice"],
		["nohup npm test", "fff", "same for nohup"],
		["timeout 10 npm test", "fff", "same for timeout"],
		["FOO=1 npm test", "fff", "an assignment prefix is invisible to argv and refused outright"],
		["env FOO=1 ls", "fff", "env's assignment is remembered as an env name"],
		["sudo ls -la", "fff", "privilege is never laundered by a wrapper"],
		["cat ~/.ssh/id_rsa", "fff", "reading a secret is ask, whatever `cat` looks like"],
		["cat .env", "fff", "same for a project .env"],
		["grep TOKEN ~/.bashrc", "fff", "a secret read through grep is still a secret read"],
	]
	table(rows)
	it("names the floor it refused on", () => {
		expect(tiersOf("rm -rf /").reason).toBe("floor-never")
		expect(tiersOf("rm -rf build").reason).toBe("floor-ask")
		expect(tiersOf("cat \"$HOME/x\"").reason).toBe("floor-unknown")
		expect(tiersOf("cat ~/.ssh/id_rsa").readOnlyReason).toBe("floor-ask")
		expect(tiersOf("cat ~/.ssh/id_rsa").category).toBe("read_secret")
	})
})

describe("the guardrails a routine command carries", () => {
	const rows: Row[] = [
		["mkdir -p build && rm -rf cache", "fff", "rm in any leg refuses the compound"],
		["touch f --force", "fff", "--force is refused on the workflow face"],
		["cp x -f y", "fff", "-f likewise"],
		["npm run build -- --config /tmp/c.js", "fff", "a runner config is an execution vector"],
		["npm test -c /tmp/x.js", "fff", "-c with a value likewise"],
		["go test -exec /tmp/x", "fff", "go's -exec runs a binary"],
		["vitest --globalSetup /tmp/g.ts", "fff", "a global setup module is code"],
		["npm test -- --watch", "fff", "a bare -- hides whatever follows it"],
		["cargo build --target=install", "fff", "--target naming a deploy phase"],
		["mkdir /tmp/x", "fff", "a routine command naming an absolute path is not routine"],
		["mkdir ~/x", "fff", "same for ~"],
		["mkdir ../x", "fff", "same for .."],
		["mkdir --path=/tmp/x", "fff", "and for the fused --flag=/abs spelling"],
		["cp a b --target-directory=/tmp", "fff", "and for an absolute option value"],
		["mkdir \"../x\"", "fff", "quoting does not move the path inside the project"],
		["touch ./notes.md", "fTf", "a project-relative path is fine"],
		["ls -la /etc", "TTT", "tier 1 has no absolute-path guardrail: reading is reading"],
	]
	table(rows)
	it("says which guardrail refused", () => {
		expect(tiersOf("mkdir /tmp/x").reason).toBe("absolute-path")
		expect(tiersOf("npm test -- --watch").reason).toBe("runner-flag")
		expect(tiersOf("touch f --force").reason).toBe("excluded-word")
		expect(tiersOf("git commit -m x").reason).toBe("workflow-table")
	})
})

describe("the offline face is never the widest one", () => {
	it("keeps readOnly ⊆ fallback ⊆ workflow on every sample", () => {
		const samples = [
			"ls", "npm test", "npm run build", "make all", "cmake -S . -B b", "git add .", "mkdir x",
			"cat f", "sed -n 1,2p f", "docker compose up", "mocha", "echo hi > out.txt", "npm install",
			"git push", "ls && git status", "sudo ls", "echo $(ls)", "mkdir /tmp/x", "vitest --globalSetup /tmp/g",
			// The compose/task-runner tables, so the containment claim covers the tables this change added rather than only
			// the ones it inherited.
			"docker compose ps", "docker compose exec web bash", "make", "make -j4 test", "make bootstrap",
			"cmake --build .", "cmake --install .", "ninja", "ninja -C build test", "just", "just build",
			"task build", "bazel build //...", "bazel run //cmd/server",
		]
		for (const command of samples) {
			const tiers = tiersOf(command)
			// The read-only face is inside the offline face, which is inside the workflow face: every one of
			// them is "the face above it, plus more refusals", and `utils.ts` says the offline face must never
			// be looser than the online one.
			if (tiers.readOnly) expect(tiers.fallback, command).toBe(true)
			if (tiers.fallback) expect(tiers.workflow, command).toBe(true)
		}
	})
	it("agrees with the single-boolean helpers", () => {
		for (const command of ["ls", "npm run build", "mkdir /tmp/x", "rm -rf build"]) {
			const tiers = tiersOf(command)
			expect(isReadOnlyBash(command, cwd)).toBe(tiers.readOnly)
			expect(isWorkflowBash(command, cwd)).toBe(tiers.workflow)
			expect(isFallbackBash(command, cwd)).toBe(tiers.fallback)
		}
	})
})

describe("the strictness table is the one in bash-audit.ts", () => {
	it("reuses categoryHasStrictOperands instead of a copy of its own", () => {
		// The ladder's `target-bearing` refusal is a belt: every category on the strictness table is ask or
		// never at layer 0 today, so the allow-tier floor already refuses the command before the belt is
		// reached. It exists so that a future allow-tier target-bearing category cannot slip through the
		// ladder while the rule matcher still refuses it. This test is the reason that claim is checkable:
		// if someone adds an allow-tier category to the table, the belt starts firing and this is the test
		// that says why.
		expect(tiersOf("rm -rf build").reason).toBe("floor-ask")
		expect(categoryHasStrictOperands("delete_recursive")).toBe(true)
		expect(categoryHasStrictOperands("write_project+read_only")).toBe(false)
	})
})

describe("the function is total", () => {
	const junk = ["", "   ", "\n", ";;;", "ls; ", "echo '", "echo $((", "echo ${", "`", "\\"]
		.concat(["\x07ls", "\x00ls", "a".repeat(9000), "[[ -f x ]]", "cd", "-", ">", "> f"])
	for (const command of junk) {
		it(`does not throw on ${JSON.stringify(command.slice(0, 12))}`, () => {
			expect(() => classifyBashTiers(command, cwd)).not.toThrow()
			const tiers = classifyBashTiers(command, cwd)
			expect(typeof tiers.reason).toBe("string")
			expect(tiers.legs).toBeGreaterThanOrEqual(0)
		})
	}
	it("refuses an empty command like the text ladder does", () => {
		const tiers = tiersOf("")
		expect(tiers.readOnly).toBe(false)
		expect(tiers.reason).toBe("empty-command")
	})
})

/** One `it` per row, so a failure names the command rather than the table index. */
function table(rows: Row[]): void {
	for (const [command, expected, why] of rows) {
		it(`${expected}  ${command.replace(/\n/g, "\\n")} — ${why}`, () => {
			expect(letters(command)).toBe(expected)
		})
	}
}

describe("a remote secret read is floored by layer 0, not by a table here (D16)", () => {
	/**
	 * This ladder never learned the name of a cloud CLI, and it must not: `kubectl get secret prod-db` is
	 * refused here because layer 0's floor moved to `ask`, which is the same route every other refusal takes.
	 * The rows below are the proof that the ladder has no private opinion about these CLIs — the ordinary
	 * verb on the same binary is still floored at `allow`.
	 */
	it("refuses the secret read through the floor, with the reason id that says so", () => {
		for (const command of [
			"kubectl get secret prod-db -o jsonpath={.data.password}",
			"aws secretsmanager get-secret-value --secret-id prod/db",
			"helm get values prod-release",
		]) {
			const tiers = tiersOf(command)
			expect([tiers.readOnly, tiers.workflow, tiers.fallback], command).toEqual([false, false, false])
			expect(tiers.proven, command).toBe(true)
			expect(tiers.floor, command).toBe("ask")
			expect(tiers.reason, command).toBe("floor-ask")
			expect(tiers.category, command).toBe("read_secret_remote")
			// …and it is the floor, not this file's allowlist, that refused it: no table here names these tools.
			expect(tiers.readOnlyReason, command).not.toBe("read-only-table")
		}
	})
	it("still treats the same verbs on an ordinary noun as un-floored", () => {
		for (const command of ["kubectl get pods", "kubectl describe deployment web", "helm list", "aws ssm get-parameter --name /app/config"]) {
			expect(tiersOf(command).floor, command).toBe("allow")
		}
	})
	it("is not the never floor, because one approval is allowed to cover it", () => {
		// The never floor is reserved for what is never legitimate in an agent session. Reading your own
		// staging secret is not that, so nothing here may reach the floor the exfiltration rows reach.
		expect(hitsNeverFloor("kubectl get secret prod-db", cwd)).toBe(false)
		expect(hitsNeverFloor("aws secretsmanager get-secret-value --secret-id prod/db", cwd)).toBe(false)
	})
})
