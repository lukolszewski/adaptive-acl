/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["**/*.test.ts"],
		// Baseline PERMISSION_MODES_* / PI_SUBAGENT_* before every file: these are the
		// plugin's live state channel and are read at call time, so an inherited shell
		// value silently retargets the gate. See vitest.setup.ts.
		setupFiles: ["./vitest.setup.ts"],
	},
});