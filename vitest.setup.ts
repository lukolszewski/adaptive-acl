/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Per-file environment baseline.
 *
 * The plugin's own state channel is `process.env`: the interactive session
 * publishes its live mode there (index.ts -> publishInheritedPermissionMode) and
 * headless children are flagged with PI_SUBAGENT_CHILD. Both are read at call
 * time, not import time, so a value inherited from the surrounding shell changes
 * gate behaviour in whichever direction the value points — a test that expects a
 * prompt gets an auto-approve instead.
 *
 * That makes the suite dependent on where it was run from, which is worse than a
 * plain failure: from a shell that has run pi one test fails, and from inside a
 * pi-subagents child fifty do, with no hint that the cause is the environment.
 * `setupFiles` runs before every test file, so each file starts from a known
 * baseline and states its own exceptions explicitly. Snapshot-and-restore inside
 * a test file is not a substitute — it restores whatever contamination was
 * present at import, which is the bug that made these tests order- and
 * shell-dependent in the first place.
 *
 * Scoped to this plugin's own prefixes. Ambient variables (HOME, PATH, CI,
 * proxies, provider keys) are left alone — some are legitimately read by the
 * code under test, and none of them are ours to normalise.
 */

const INHERITED_PREFIXES = ["PERMISSION_MODES_", "PI_SUBAGENT_"];

for (const key of Object.keys(process.env)) {
	if (INHERITED_PREFIXES.some((prefix) => key.startsWith(prefix))) {
		delete process.env[key];
	}
}

// Layer 0 parses with tree-sitter-bash, whose grammar is loaded once per process (index.ts does it
// at load time). Without this every parse in the suite would be refused `parser-unavailable`.
const { initBashParser } = await import("./bash-parser.ts");
await initBashParser();

// This file has no imports of its own besides the dynamic one above, so without this it is not a module and
// top-level `await` is a syntax error (TS1375) — tsc rejects it even though vitest/bun run it fine.
export {};
