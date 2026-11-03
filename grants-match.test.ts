/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Grants that can actually match.
 *
 * The three layer shapes this file pins are the ones where the user answered "always" and the gate asked
 * again anyway, because the row it stored could never answer the next call:
 *
 *   - a command whose "acts on" was EMPTY (an agent CLI, an editor, a bare `su`) — the stores bail on an
 *     empty target list, so no row could ever cover it. Agents now name the program, editors name the
 *     file they open (decided like a write to it), and an action whose object IS its category carries the
 *     `*` marker.
 *   - a delete approval the user clicked did not answer a write inside it, while the same sentence spoken
 *     did (the session store's direction list was missing `delete-gives-write`).
 *
 * Every "it matches" assertion has a control that must NOT match: a row for `pi` does not cover `claude`, the
 * `*` marker never answers a named target, and a delete-kind row still refuses the other delete kinds.
 */
import { describe, expect, it } from "vitest"
import { evaluateBash } from "./risk-policy.ts"
import { addGrant, createGrantStore, grantsCover } from "./session-grants.ts"
import { applyEvent, createLedger, ledgerCovers } from "./auth-ledger.ts"
import { NO_OBJECT_TARGET, verifyGrant } from "./grant-verify.ts"

const CWD = "/home/u/proj"
const HOME = "/home/u"
const POLICY = { cwd: CWD, project: CWD, home: HOME, fs: false }

function verdict(command: string) {
	return evaluateBash(command, POLICY)
}

function covered(command: string, rows: Array<{ category: string; value: string; kind?: "entity" | "scope" }>) {
	const d = verdict(command)
	const store = createGrantStore()
	for (const row of rows) addGrant(store, row.category, row.value, row.kind ?? "entity")
	return { category: d.category, entities: d.entities, ...grantsCover(store, d.category, d.entities, HOME, CWD) }
}

function ledgerCovered(command: string, rows: Array<{ category: string; value: string; kind?: "entity" | "scope" }>) {
	const d = verdict(command)
	const ledger = createLedger()
	rows.forEach((row, i) =>
		applyEvent(ledger, {
			type: "grant",
			category: row.category,
			value: row.value,
			kind: row.kind ?? "entity",
			// A grant's `seq` is the message ordinal it was earned at, and `ledgerCovers` needs it to compare
			// against a forbid: a row without one loses to every ban, which is not what this fixture means.
			quote: `fixture ${i} — go ahead and su to root`,
			messageId: `m${i}`,
			seq: i + 1,
		}),
	)
	return { category: d.category, ...ledgerCovers(ledger, d.category, d.entities, HOME, CWD) }
}

const targetValues = (command: string) =>
	verdict(command).entities.filter((e) => e.kind === "target").map((e) => e.value)

describe("an agent CLI's object is the program, not its prompt", () => {
	it("names the program it spawns", () => {
		expect(targetValues("pi -p hi")).toEqual(["pi"])
		expect(targetValues("claude --print x")).toEqual(["claude"])
		// a nohup'd, backgrounded, redirected spawn is still the same leg, and still `pi`
		expect(targetValues("nohup pi -p hi > log.txt 2>&1 &")).toEqual(["pi"])
		expect(targetValues("cd folder && nohup pi -p hi > log.txt 2>&1 &")).toEqual(["pi"])
	})

	it("a row for `pi` answers every pi call, chained and nohup'd included", () => {
		const rows = [{ category: "agent_spawn", value: "pi" }]
		expect(covered("pi -p hi", rows).covered).toBe(true)
		expect(covered("cd folder && nohup pi -p hi > log.txt 2>&1 &", rows).covered).toBe(true)
	})

	it("…and never a different coding agent", () => {
		const rows = [{ category: "agent_spawn", value: "pi" }]
		expect(covered("claude --print x", rows).covered).toBe(false)
		expect(covered("codex exec x", rows).covered).toBe(false)
	})

	it("the ledger answers the same way, so the spoken grant reaches the nohup'd leg too", () => {
		const rows = [{ category: "agent_spawn", value: "pi" }]
		expect(ledgerCovered("cd folder && nohup pi -p hi > log.txt 2>&1 &", rows).covered).toBe(true)
		expect(ledgerCovered("claude --print x", rows).covered).toBe(false)
	})
})

describe("an editor is the write to the file it opens", () => {
	it("in the project it is the project write it is, with the file as the object", () => {
		const d = verdict("vim notes.md")
		expect(d.tier).toBe("allow")
		expect(d.category).toBe("write_project")
		expect(d.entities.map((e) => e.value)).toContain("./notes.md")
	})

	it("outside the project it asks, and a folder write grant covers it", () => {
		const d = verdict("vim ~/elsewhere/out/notes.md")
		expect(d.category).toBe("write_outside")
		const cover = covered("vim ~/elsewhere/out/notes.md", [{ category: "write_outside", value: `${HOME}/elsewhere/out/`, kind: "scope" }])
		expect(cover.covered).toBe(true)
	})

	it("a secret file is a secret write, not a free editor", () => {
		expect(verdict("vim ~/.ssh/config").category).toBe("write_sensitive")
	})

	it("an editor told to RUN something keeps the editor category, so it still asks", () => {
		// `-c '!cmd'` / `+cmd` are a launcher, not "open this file": the write classification would have made
		// this an allow inside the project.
		for (const command of ["vim -c '!rm -rf /' notes.md", 'vim +"!rm -rf /" notes.md', "emacs --eval '(shell-command \"rm -rf /\")' notes.md"]) {
			const d = verdict(command)
			expect(d.tier).toBe("ask")
			expect(d.category).toBe("interactive_editor")
			expect(d.entities.map((e) => e.value)).toContain("./notes.md")
		}
		// the control: a cursor move is not a launch
		expect(verdict("vim +42 notes.md").tier).toBe("allow")
		expect(verdict("vim +/needle notes.md").tier).toBe("allow")
	})

	it("no file operand keeps today's behaviour: an ask with nothing to name", () => {
		const d = verdict("vim")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("interactive_editor")
		expect(d.entities.map((e) => e.value)).toEqual([NO_OBJECT_TARGET])
	})
})

describe("a command with no operand at all does nothing", () => {
	it("bare rm and chmod print usage, so they are allowed", () => {
		for (const command of ["rm", "rm -rf", "chmod", "chmod 755", "chown", "chgrp -R"]) {
			const d = verdict(command)
			expect(d.tier, command).toBe("allow")
			expect(d.category, command).toBe("read_only")
		}
	})

	it("the guard: an operand is still gated exactly as before", () => {
		expect(verdict("rm -rf /tmp/x").category).toBe("delete_recursive")
		expect(verdict("chmod 777 /srv/x").category).toBe("perm_change")
	})
})

describe("an action whose object IS its category carries the no-object marker", () => {
	it("the marker is what a targetless ask names", () => {
		expect(targetValues("su")).toEqual([NO_OBJECT_TARGET])
		expect(targetValues("sh")).toEqual([NO_OBJECT_TARGET])
		expect(targetValues("systemctl")).toEqual([NO_OBJECT_TARGET])
	})

	it("a prompt row of that category answers it — the click is no longer forgotten", () => {
		expect(covered("su", [{ category: "privilege", value: NO_OBJECT_TARGET }]).covered).toBe(true)
		expect(covered("sh", [{ category: "interactive_editor", value: NO_OBJECT_TARGET }]).covered).toBe(true)
		// `privilege` is one of the categories whose words must name the method, so the fixture says "su".
		expect(ledgerCovered("su", [{ category: "privilege", value: NO_OBJECT_TARGET }]).covered).toBe(true)
	})

	it("…and a row that names something does not", () => {
		// "you may use vim" is not "you may hand the terminal to any shell"
		expect(covered("sh", [{ category: "interactive_editor", value: "vim" }]).covered).toBe(false)
	})

	it("the marker never answers a NAMED action (the direction the whole rule must not widen)", () => {
		expect(covered("vim -c x ./notes.md", [{ category: "interactive_editor", value: NO_OBJECT_TARGET }]).covered).toBe(false)
		expect(covered("pi -p hi", [{ category: "agent_spawn", value: NO_OBJECT_TARGET }]).covered).toBe(false)
	})

	it("a category whose target language already has a wildcard gets no marker", () => {
		// In the send/image grammar `*` means "any destination", so naming it for a command that named none would
		// record an authority nobody gave (`publish-targets.test.ts` pins the same refusal for `docker push`).
		expect(verdict("docker push").entities).toEqual([])
		expect(verdict("git push").entities.map((e) => e.value)).not.toContain(NO_OBJECT_TARGET)
	})

	it("…and the transcript path covers the pi leg from the user's own words", () => {
		// "you can run pi" against `cd folder && nohup pi … > log.txt 2>&1 &`: the pi leg is the ask, and the
		// agent name is what the sentence names. The other legs are judged as usual (`cd` free, the redirect a
		// project write), which is why the merged entity list holds only `pi`.
		const entities = verdict("cd folder && nohup pi -p hi > log.txt 2>&1 &").entities
		expect(entities.map((e) => e.value)).toEqual(["pi"])
		const v = verifyGrant({
			extraction: {
				authorized: "yes",
				effects: ["agent_spawn"],
				allowed_targets: ["pi"],
				forbidden_targets: [],
				quote: "you can run pi",
			},
			category: "agent_spawn",
			entities,
			userMessages: ["you can run pi"],
			space: { home: HOME, project: CWD },
		})
		expect(v.granted).toBe(true)
		// the control: a different agent is not the one the sentence named
		const claude = verifyGrant({
			extraction: { authorized: "yes", effects: ["agent_spawn"], allowed_targets: ["pi"], forbidden_targets: [], quote: "you can run pi" },
			category: "agent_spawn",
			entities: verdict("claude --print x").entities,
			userMessages: ["you can run pi"],
			space: { home: HOME, project: CWD },
		})
		expect(claude.granted).toBe(false)
	})

	it("the transcript path is unchanged: the marker is not a target the user must have written", () => {
		// Before this change a targetless ask carried no entities at all, so `verifyGrant` had no target to check and
		// the model's effects decided. The marker must not turn that into "the user has to have said `*`".
		const v = verifyGrant({
			extraction: {
				authorized: "yes",
				effects: ["privilege"],
				allowed_targets: [],
				forbidden_targets: [],
				quote: "go ahead and su to root for this",
			},
			category: "privilege",
			entities: [{ kind: "target", value: NO_OBJECT_TARGET }],
			userMessages: ["go ahead and su to root for this"],
		})
		expect(v.granted).toBe(true)
		expect(v.matches).toEqual([])
	})

	it("…and the marker cannot be used to smuggle a forbid", () => {
		const v = verifyGrant({
			extraction: {
				authorized: "yes",
				effects: ["interactive_editor"],
				allowed_targets: [],
				forbidden_targets: [NO_OBJECT_TARGET],
				quote: "you can open the editor",
			},
			category: "interactive_editor",
			entities: [{ kind: "target", value: NO_OBJECT_TARGET }],
			userMessages: ["you can open the editor"],
		})
		expect(v.granted).toBe(true)
	})
})

describe("a clicked delete permission contains the write inside it, like the spoken one", () => {
	const OUT = `${HOME}/elsewhere/out/`

	it("the session store now applies `delete-gives-write`", () => {
		const rows = [{ category: "delete_outside", value: OUT, kind: "scope" as const }]
		expect(covered(`cp ./x ${OUT}y`, rows).covered).toBe(true)
		// the control: the same row does not answer a write OUTSIDE its scope
		expect(covered(`cp ./x ${HOME}/elsewhere/other/y`, rows).covered).toBe(false)
	})

	it("…which is what the ledger already did, so the two stores agree", () => {
		const rows = [{ category: "delete_outside", value: OUT, kind: "scope" as const }]
		expect(ledgerCovered(`cp ./x ${OUT}y`, rows).covered).toBe(true)
		expect(covered(`cp ./x ${OUT}y`, rows).covered).toBe(ledgerCovered(`cp ./x ${OUT}y`, rows).covered)
	})

	it("category-exact refusals between the delete kinds stay", () => {
		// the whole reason the session store keeps an exact-category rule: a `delete_data` approval is not a
		// licence to remove the tree, and a `delete_recursive` one is not a licence to delete a data file.
		expect(covered("rm -rf /tmp/build", [{ category: "delete_data", value: "/tmp/build" }]).covered).toBe(false)
		expect(covered("rm ~/notes.db", [{ category: "delete_recursive", value: "~/notes.db" }]).covered).toBe(false)
	})

	it("a write row still answers the single-file delete it contains", () => {
		const rows = [{ category: "write_outside", value: OUT, kind: "scope" as const }]
		expect(covered(`rm ${OUT}y`, rows).covered).toBe(true)
	})
})
