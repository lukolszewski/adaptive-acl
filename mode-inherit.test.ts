/**
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	applyInheritedModeForChild,
	PERMISSION_MODES_INHERITED_MODE_ENV,
	publishInheritedPermissionMode,
	resolveInheritedPermissionMode,
} from "./mode-inherit.ts";
import { SUBAGENT_CHILD_ENV } from "./permission-forwarding.ts";

describe("mode-inherit", () => {
	const prevMode = process.env[PERMISSION_MODES_INHERITED_MODE_ENV];
	const prevChild = process.env[SUBAGENT_CHILD_ENV];

	// Establish the baseline every test here assumes. Without it the starting state comes
	// from the ambient environment — and any shell that has ever run pi has this var set,
	// because the extension publishes the live mode into process.env. afterEach then
	// faithfully restores that tainted value instead of clearing it, so a test asserting
	// "nothing is published" only passes on a clean shell. Snapshot/restore stays for the
	// outer env; it is not a substitute for a per-test baseline.
	beforeEach(() => {
		delete process.env[PERMISSION_MODES_INHERITED_MODE_ENV];
		delete process.env[SUBAGENT_CHILD_ENV];
	});

	afterEach(() => {
		if (prevMode === undefined)
			delete process.env[PERMISSION_MODES_INHERITED_MODE_ENV];
		else process.env[PERMISSION_MODES_INHERITED_MODE_ENV] = prevMode;
		if (prevChild === undefined) delete process.env[SUBAGENT_CHILD_ENV];
		else process.env[SUBAGENT_CHILD_ENV] = prevChild;
	});

	it("publishInheritedPermissionMode sets env on parent", () => {
		delete process.env[SUBAGENT_CHILD_ENV];
		publishInheritedPermissionMode("bypass");
		expect(process.env[PERMISSION_MODES_INHERITED_MODE_ENV]).toBe("bypass");
		expect(resolveInheritedPermissionMode()).toBe("bypass");
	});

	it("publishInheritedPermissionMode is no-op in child", () => {
		process.env[SUBAGENT_CHILD_ENV] = "1";
		process.env[PERMISSION_MODES_INHERITED_MODE_ENV] = "ask";
		publishInheritedPermissionMode("bypass");
		expect(process.env[PERMISSION_MODES_INHERITED_MODE_ENV]).toBe("ask");
	});

	it("publishes nothing for invalid modes", () => {
		publishInheritedPermissionMode("yolo");
		expect(resolveInheritedPermissionMode()).toBeUndefined();
	});

	it("does not clobber a valid mode with an invalid one", () => {
		// The safety property the single combined test above assumed away: a bad mode
		// string must never overwrite the mode that children actually inherit.
		process.env[PERMISSION_MODES_INHERITED_MODE_ENV] = "auto";
		publishInheritedPermissionMode("yolo");
		expect(process.env[PERMISSION_MODES_INHERITED_MODE_ENV]).toBe("auto");
		expect(resolveInheritedPermissionMode()).toBe("auto");
	});

	it("applyInheritedModeForChild returns mode for any child when env is set", () => {
		delete process.env[SUBAGENT_CHILD_ENV];
		process.env[PERMISSION_MODES_INHERITED_MODE_ENV] = "bypass";
		expect(applyInheritedModeForChild()).toBeUndefined();

		process.env[SUBAGENT_CHILD_ENV] = "1";
		expect(applyInheritedModeForChild({ flagSet: true, currentMode: "ask" })).toBe(
			"bypass",
		);
		expect(applyInheritedModeForChild()).toBe("bypass");
	});
});
