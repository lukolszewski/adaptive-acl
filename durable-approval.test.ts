/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 */

import { describe, expect, it } from "vitest";
import { approvalTargets, durableRowsForApproval, rowCoversTargets } from "./durable-approval.ts";
import type { SessionGrant } from "./session-grants.ts";

/**
 * The click path's durable authority. These pins exist because the alternative is a remembered allowance whose
 * breadth nobody checked: every case here is about the row NOT being wider than the invocation that earned it.
 */
describe("durable rows from an always-allow click", () => {
	it("a file approval stores exactly the file it was about", () => {
		const r = durableRowsForApproval({
			tool: "write",
			input: { path: "src/a.ts" },
			category: "write_project",
			cwd: "/home/dev/proj",
			folderScope: false,
		});
		expect(r).toEqual({ rows: [{ category: "write_project", value: "/home/dev/proj/src/a.ts", kind: "entity" }] });
	});

	it("the folder click stores one scope row over the containing directory, not the file", () => {
		const r = durableRowsForApproval({
			tool: "edit",
			input: { path: "/home/dev/proj/src/a.ts" },
			category: "write_outside",
			cwd: "/home/dev/proj",
			folderScope: true,
		});
		expect(r).toEqual({ rows: [{ category: "write_outside", value: "/home/dev/proj/src/", kind: "scope" }] });
	});

	it("a command stores a row per target it names, never a command-shaped wildcard", () => {
		const r = durableRowsForApproval({
			tool: "bash",
			input: { command: "rm -rf /tmp/alpha /tmp/beta" },
			category: "delete_recursive",
			cwd: "/home/dev/proj",
			folderScope: false,
		});
		expect("rows" in r && r.rows.length).toBe(2);
		const values = "rows" in r ? r.rows.map((x) => x.value).sort() : [];
		expect(values).toEqual(["/tmp/alpha", "/tmp/beta"]);
		expect("rows" in r && r.rows.every((x) => x.kind === "entity")).toBe(true);
	});

	it("a command with no target gets no row, because nothing can express it narrowly", () => {
		const r = durableRowsForApproval({
			tool: "bash",
			input: { command: "npm test" },
			category: "run_scripts",
			cwd: "/home/dev/proj",
			folderScope: false,
		});
		expect("reason" in r).toBe(true);
	});

	it("folder scope is never turned into a scope row for a command", () => {
		const r = durableRowsForApproval({
			tool: "bash",
			input: { command: "rm -rf /tmp/alpha" },
			category: "delete_recursive",
			cwd: "/home/dev/proj",
			folderScope: true,
		});
		expect(r).toEqual({ reason: "folder scope does not apply to a command" });
	});

	it("folder scope is refused for a secret-bearing category — a directory is never the right size of that yes", () => {
		const r = durableRowsForApproval({
			tool: "read",
			input: { path: "/home/dev/.ssh/id_rsa" },
			category: "read_secret",
			cwd: "/home/dev/proj",
			folderScope: true,
		});
		expect(r).toEqual({ reason: "folder scope is not offered for secret-bearing categories" });
	});

	it("compound categories count as secret-bearing on any segment", () => {
		const nonSecret = durableRowsForApproval({
			tool: "write",
			input: { path: "/home/dev/.ssh/config" },
			category: "write_outside+perm_change",
			cwd: "/home/dev/proj",
			folderScope: true,
		});
		expect("rows" in nonSecret ? nonSecret.rows.length : 0).toBeGreaterThan(0);
		expect(
			durableRowsForApproval({
				tool: "read",
				input: { path: "/home/dev/.env" },
				category: "read_secret+read_dotenv",
				cwd: "/home/dev/proj",
				folderScope: true,
			}),
		).toEqual({ reason: "folder scope is not offered for secret-bearing categories" });
	});

	it("no category means no row — a row without a category authorises every category", () => {
		expect(
			durableRowsForApproval({
				tool: "write",
				input: { path: "/tmp/x" },
				category: undefined,
				cwd: "/tmp",
				folderScope: false,
			}),
		).toEqual({ reason: "no category for this approval" });
	});

	it("an approval with no path and no command is refused, not guessed", () => {
		expect(approvalTargets({ tool: "write", input: {}, cwd: "/tmp" })).toEqual({
			reason: "the approval carries no path",
		});
		const unsupported = approvalTargets({ tool: "grep", input: { pattern: "x" }, cwd: "/tmp" });
		expect("reason" in unsupported ? unsupported.reason : "").toContain("grep");
	});
});

describe("deny-always revokes exactly the allowances that would have covered the target", () => {
	const row = (value: string, kind: "entity" | "scope"): SessionGrant => ({
		category: "write_outside",
		value,
		kind,
		at: 1,
	});

	it("matches the entity itself", () => {
		expect(rowCoversTargets(["/tmp/x"])(row("/tmp/x", "entity"))).toBe(true);
		expect(rowCoversTargets(["/tmp/x"])(row("/tmp/y", "entity"))).toBe(false);
	});

	it("a scope row matches everything inside it", () => {
		expect(rowCoversTargets(["/tmp/dir/x"])(row("/tmp/dir/", "scope"))).toBe(true);
		expect(rowCoversTargets(["/other/x"])(row("/tmp/dir/", "scope"))).toBe(false);
	});

	it("a home-relative row cannot dodge a revocation of the same file", () => {
		const space = { home: "/home/dev" };
		expect(rowCoversTargets(["/home/dev/.ssh/id_rsa"], space)(row("~/.ssh/id_rsa", "entity"))).toBe(true);
	});
});
