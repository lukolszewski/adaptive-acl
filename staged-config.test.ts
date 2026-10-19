/**
 * Staged config vs live config, and the approvals that follow from the difference.
 *
 * Reported against a real project: writing `deploy/systemd/pw-build.timer` prompted as
 * "write sensitive config", four files in that folder cost four prompts, and each "allow always"
 * stored one exact file rule so the next file asked again. The cause was a path-shape check applied
 * to the whole raw path with no project gate, so a repository's own inert copy of a unit file was
 * classed with the live unit that reads it.
 *
 * The property that matters is not "systemd is allowed" — it is that sensitivity tracks the machine.
 * Every test below that loosens something in-project is paired with one that keeps the same shape
 * asking where it would actually take effect.
 */

import { describe, expect, it } from "vitest"
import { classifyPath, isCredentialFilename, projectIsLiveConfig, type PathContext } from "./risk-paths.ts"
import { evaluateBash, evaluateToolCall } from "./risk-policy.ts"
import { suggestFolderAllowRule } from "./permissions.ts"
import { pathMatchesRulePattern } from "./path-permission-match.ts"

const PROJ = "/home/dev/personal-site"
const CTX: PathContext = { cwd: PROJ, project: PROJ, home: "/home/dev" }
const OPTS = { cwd: PROJ, project: PROJ, home: "/home/dev", fs: false }

const cls = (p: string, ctx: PathContext = CTX) => classifyPath(p, ctx)
const verdict = (tool: string, input: Record<string, unknown>) => evaluateToolCall(tool, input, OPTS)

describe("staged config is not live config", () => {
	it("classifies a unit file staged inside the project as staged, not sensitive", () => {
		for (const p of ["deploy/systemd/pw-build.timer", "deploy/systemd/pw-build.service", "ops/init.d/svc", "docs/cron.d/nightly", "build/profile.d/x.sh"]) {
			const pc = cls(p)
			expect(pc.insideProject, p).toBe(true)
			expect(pc.stagedConfig, p).toBe(true)
			expect(pc.isSensitiveConfig, p).toBe(false)
		}
	})

	it("allows the writes the report was about", () => {
		for (const p of ["deploy/systemd/pw-build.timer", "deploy/systemd/pw-receiver.service", "deploy/systemd/pw-build.path"]) {
			const d = verdict("edit", { path: p, new_string: "x" })
			expect(d.tier, p).toBe("allow")
			expect(d.segments[0]!.category, p).toBe("write_project")
		}
		expect(verdict("write", { path: "deploy/systemd/x.service", content: "[Unit]" }).tier).toBe("allow")
	})

	it("allows bash writes into the same folder, not just the edit tool", () => {
		expect(evaluateBash("cp build/pw-build.timer deploy/systemd/pw-build.timer", OPTS).tier).toBe("allow")
		expect(evaluateBash("cat > deploy/systemd/x.service <<'EOF'\n[Unit]\nEOF", OPTS).tier).toBe("allow")
	})

	it("still asks for the live unit the staged copy is installed into", () => {
		for (const p of ["/etc/systemd/system/x.service", "/etc/cron.d/nightly", "/etc/init.d/svc", "/usr/lib/systemd/x"]) {
			expect(cls(p).isSensitiveConfig, p).toBe(true)
			expect(cls(p).stagedConfig, p).toBe(false)
			const d = verdict("edit", { path: p, new_string: "x" })
			expect(d.tier, p).toBe("ask")
			expect(d.segments[0]!.category, p).toBe("write_sensitive")
		}
		// ~/.config/systemd/user is reached by the home-directory rule, untouched by this change
		expect(cls("~/.config/systemd/user/x.service").isSensitiveConfig).toBe(true)
		expect(verdict("edit", { path: "~/.config/systemd/user/x.service", new_string: "x" }).tier).toBe("ask")
	})

	it("does not treat a project root that IS machine config as staged", () => {
		expect(projectIsLiveConfig("/etc/nginx", "/home/dev")).toBe(true)
		expect(projectIsLiveConfig("/home/dev/.config/dotfiles", "/home/dev")).toBe(true)
		expect(projectIsLiveConfig("/home/dev", "/home/dev")).toBe(true)
		expect(projectIsLiveConfig(PROJ, "/home/dev")).toBe(false)
		expect(projectIsLiveConfig("/srv/www/site", "/home/dev")).toBe(false)

		// A dotfiles / infra repo opened at the live location keeps full strictness: "it is in the
		// project" must not become a blanket bypass for the repos whose job is editing config.
		const live: PathContext = { cwd: "/etc/nginx", project: "/etc/nginx", home: "/home/dev" }
		expect(cls("sites-enabled/cron.d/x", live).isSensitiveConfig).toBe(true)
		expect(cls("sites-enabled/cron.d/x", live).stagedConfig).toBe(false)
		expect(evaluateToolCall("edit", { path: "sites-enabled/cron.d/x", new_string: "y" }, { ...OPTS, cwd: "/etc/nginx", project: "/etc/nginx" }).tier).toBe("ask")
	})

	it("leaves .git internals asking — those mutate real repo state, not a staged copy", () => {
		expect(cls(".git/hooks/pre-commit").isGitInternal).toBe(true)
		expect(verdict("edit", { path: ".git/hooks/pre-commit", new_string: "x" }).segments[0]!.category).toBe("write_sensitive")
	})
})

describe("credential filenames are a reviewed table, not one long regex", () => {
	it("no longer reads ordinary project source as secret-bearing", () => {
		// Both were written for one home location and then flagged that filename everywhere on disk:
		// `config.json` for ~/.docker/config.json, `hosts.yml` for an Ansible inventory.
		expect(isCredentialFilename("config.json")).toBe(false)
		expect(isCredentialFilename("hosts.yml")).toBe(false)
		expect(verdict("edit", { path: "config.json", new_string: "{}" }).tier).toBe("allow")
		expect(verdict("edit", { path: "site/config.json", new_string: "{}" }).tier).toBe("allow")
		expect(verdict("read", { path: "config.json" }).tier).toBe("allow")
	})

	it("keeps the names that really do carry a credential, in-project included", () => {
		for (const n of [".env", ".env.local", "id_ed25519", "app.key", "server.pem", "tokens.json", "secrets.yaml", "credentials.json", "auth.json", "kubeconfig", "service-account-x.json", "app.secret"]) {
			expect(isCredentialFilename(n), n).toBe(true)
		}
		// A repo's .env holds real credentials: still asked, still secret-shaped.
		expect(verdict("write", { path: ".env", content: "A=1" }).segments[0]!.category).toBe("write_sensitive")
		expect(verdict("read", { path: ".env" }).segments[0]!.category).toBe("read_secret")
	})

	it("keeps the example/template exemption and the directory-based rules", () => {
		expect(isCredentialFilename(".env.example")).toBe(true)
		expect(cls(".env.example").isSecret).toBe(false)
		expect(cls(".env.local").isSecret).toBe(true)
		// The location that motivated dropping bare config.json is still covered, by directory.
		expect(cls("~/.docker/config.json", { ...CTX, cwd: "/home/dev" }).isSecret).toBe(true)
		expect(cls("~/.aws/credentials", { ...CTX, cwd: "/home/dev" }).isSecret).toBe(true)
		// …and this plugin's own config under a secret directory stays non-secret.
		expect(cls("~/.pi/agent/permission-modes.json", { ...CTX, cwd: "/home/dev" }).isSecret).toBe(false)
	})
})

describe("one approval covers the folder, not one file", () => {
	it("offers a scope entity so the dialog can grant the directory", () => {
		const d = verdict("edit", { path: "/etc/systemd/system/x.service", new_string: "x" })
		const scopes = d.segments.flatMap((s) => s.entities.filter((e) => e.kind === "scope").map((e) => e.value))
		expect(scopes).toContain("/etc/systemd/system/")
	})

	it("does not offer a folder scope for a secret, where a ** rule could never match", () => {
		const d = verdict("write", { path: ".env", content: "A=1" })
		expect(d.segments.flatMap((s) => s.entities.filter((e) => e.kind === "scope"))).toHaveLength(0)
	})

	it("suggests a folder rule that actually matches the sibling files", () => {
		const rule = suggestFolderAllowRule("edit", { path: "deploy/systemd/pw-build.timer" }, PROJ)
		expect(rule).toBe("Edit(./deploy/systemd/**)")
		// The whole point: the next file in the folder needs no second approval.
		expect(pathMatchesRulePattern("deploy/systemd/pw-receiver.service", "./deploy/systemd/**", PROJ)).toBe(true)
		expect(pathMatchesRulePattern("deploy/other/x.sh", "./deploy/systemd/**", PROJ)).toBe(false)
	})

	it("withholds the offer where the rule would be dead on arrival", () => {
		// A ** rule never matches a secret-classified path, so offering the folder would store a rule
		// that silently does nothing.
		expect(suggestFolderAllowRule("edit", { path: ".env" }, PROJ)).toBeUndefined()
		expect(suggestFolderAllowRule("read", { path: "id_ed25519" }, PROJ)).toBeUndefined()
		// No folder for a bare name at the filesystem root, and folder scope is a path-tool idea.
		expect(suggestFolderAllowRule("edit", { path: "/x" }, PROJ)).toBeUndefined()
		expect(suggestFolderAllowRule("bash", { command: "cat > deploy/systemd/x" }, PROJ)).toBeUndefined()
		expect(suggestFolderAllowRule("edit", {}, PROJ)).toBeUndefined()
	})

	it("still suggests the exact file for the plain per-file approval", () => {
		// The two offers must not be confused: one names the file, the other the folder.
		const folder = suggestFolderAllowRule("edit", { path: "deploy/systemd/pw-build.timer" }, PROJ)
		expect(folder).not.toBe("Edit(./deploy/systemd/pw-build.timer)")
	})
})
