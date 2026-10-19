import { beforeEach, describe, expect, it } from "vitest";

import {
	PM_BRIDGE_GLOBAL,
	PM_LAST_INHERITANCE_GLOBAL,
	PM_SCHEDULE_WINDOW_GLOBAL,
	publishBridgeSnapshot,
	readBridgeSnapshot,
	resolveChildMode,
	resolveInheritedBridgeState,
} from "./headless-bridge.ts";
import type { SerializedLedger } from "./auth-ledger.ts";

const CWD = "/home/me/proj";

function ledger(over: Partial<SerializedLedger> = {}): SerializedLedger {
	return {
		v: 1,
		grants: [
			// A LedgerEntry row, spelled the way `auth-ledger.ts` declares it: `value` IS the target (there is
			// no `targets` field — that shape belongs to the model's extraction payload, `{action, targets,
			// quote}`), and `messageId` is required, which a row of this shape must carry.
			{
				category: "write",
				value: "~/proj/src/",
				kind: "scope",
				seq: 3,
				messageId: "m-3",
				quote: "you may edit src",
			},
		],
		forbids: [],
		seen: [],
		...over,
	};
}

function publish(mode: string, extra: Record<string, unknown> = {}) {
	publishBridgeSnapshot({
		mode,
		unattended: false,
		grants: [{ category: "write", value: "~/proj/src/", kind: "scope", at: 1 }],
		ledger: ledger(),
		cwd: CWD,
		...extra,
	});
}

function window(depth: number | undefined) {
	(globalThis as Record<string, unknown>)[PM_SCHEDULE_WINDOW_GLOBAL] = depth;
}

beforeEach(() => {
	const g = globalThis as Record<string, unknown>;
	delete g[PM_BRIDGE_GLOBAL];
	delete g[PM_SCHEDULE_WINDOW_GLOBAL];
	delete g[PM_LAST_INHERITANCE_GLOBAL];
});

describe("resolveChildMode", () => {
	it("inherits bypass and plan verbatim", () => {
		expect(resolveChildMode("bypass")).toBe("bypass");
		expect(resolveChildMode("plan")).toBe("plan");
	});

	it("maps ask and auto to auto (a child can never answer a prompt)", () => {
		expect(resolveChildMode("ask")).toBe("auto");
		expect(resolveChildMode("auto")).toBe("auto");
	});

	it("maps unknown garbage to auto, never to bypass", () => {
		expect(resolveChildMode("nonsense")).toBe("auto");
		expect(resolveChildMode("")).toBe("auto");
	});
});

describe("resolveInheritedBridgeState", () => {
	it("returns nothing for interactive sessions even with a live bridge", () => {
		publish("auto");
		window(1);
		expect(resolveInheritedBridgeState({ hasUI: true, cwd: CWD })).toBeUndefined();
	});

	it("returns nothing outside a spawner window", () => {
		publish("auto");
		window(undefined);
		expect(resolveInheritedBridgeState({ hasUI: false, cwd: CWD })).toBeUndefined();
		window(0);
		expect(resolveInheritedBridgeState({ hasUI: false, cwd: CWD })).toBeUndefined();
	});

	it("returns nothing when the cwd does not match", () => {
		publish("auto");
		window(1);
		expect(
			resolveInheritedBridgeState({ hasUI: false, cwd: "/home/me/other" }),
		).toBeUndefined();
	});

	it("inherits the parent's mode mapping, forces unattended, and carries grants + ledger", () => {
		publish("ask");
		window(1);
		const got = resolveInheritedBridgeState({ hasUI: false, cwd: CWD });
		expect(got?.mode).toBe("auto");
		expect(got?.unattended).toBe(true);
		expect(got?.grants).toHaveLength(1);
		// forbids / read-only posture ride along in the ledger — dropping them
		// would be a privilege escalation
		expect(got?.ledger.grants).toHaveLength(1);
	});

	it("inherits bypass verbatim when the parent is in bypass", () => {
		publish("bypass");
		window(1);
		expect(resolveInheritedBridgeState({ hasUI: false, cwd: CWD })?.mode).toBe("bypass");
	});

	it("carries a read-only posture through to the child", () => {
		publish("auto", { ledger: ledger({ readOnlyOn: { seq: 9, quote: "change nothing" } }) });
		window(1);
		const got = resolveInheritedBridgeState({ hasUI: false, cwd: CWD });
		expect(got?.ledger.readOnlyOn?.seq).toBe(9);
		const last = (globalThis as Record<string, any>)[PM_LAST_INHERITANCE_GLOBAL];
		expect(last.readOnly).toBe(true);
	});

	it("rejects a malformed snapshot rather than falling back to permissive defaults", () => {
		window(1);
		(globalThis as Record<string, unknown>)[PM_BRIDGE_GLOBAL] = { mode: "bypass" };
		expect(resolveInheritedBridgeState({ hasUI: false, cwd: CWD })).toBeUndefined();
		expect(readBridgeSnapshot()).toBeUndefined();
	});

	it("records what the child resolved to, for spawner-side logging", () => {
		publish("plan");
		window(1);
		resolveInheritedBridgeState({ hasUI: false, cwd: CWD });
		const last = (globalThis as Record<string, any>)[PM_LAST_INHERITANCE_GLOBAL];
		expect(last.mode).toBe("plan");
		expect(last.unattended).toBe(true);
		expect(last.grants).toBe(1);
		expect(last.ledgerGrants).toBe(1);
		expect(last.ledgerForbids).toBe(0);
	});
});

describe("publishBridgeSnapshot", () => {
	it("does not alias the live ledger arrays", () => {
		const l = ledger();
		publishBridgeSnapshot({
			mode: "auto",
			unattended: false,
			grants: [],
			ledger: l,
			cwd: CWD,
		});
		l.grants.push({
			category: "write",
			value: "~/elsewhere/",
			kind: "scope",
			seq: 99,
			messageId: "m-99",
			quote: "later mutation",
		});
		expect(readBridgeSnapshot()?.ledger.grants).toHaveLength(1);
	});

	it("clamps an unknown mode to ask so a corrupt publish cannot smuggle bypass", () => {
		publishBridgeSnapshot({
			mode: "bypas",
			unattended: false,
			grants: [],
			ledger: ledger(),
			cwd: CWD,
		});
		expect(readBridgeSnapshot()?.mode).toBe("ask");
	});
});
