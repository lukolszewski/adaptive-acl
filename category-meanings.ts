/**
 * One dictionary for the effect vocabulary: every grant category, two lengths, in one file.
 *
 * WHY THIS FILE EXISTS. Measuring the bigger models showed most over-blocks were not model errors: the model
 * named the effect correctly and OUR vocabulary disagreed with it — an s3 object deletion it called
 * `delete_data` was refused because layer 0 had filed the same command `cluster_mutation`; a force-push to a
 * feature branch was answered `vcs_force_protected` because that is the only value with "force" in its name,
 * and no prompt said what either vcs value means. A bare enum teaches a model to pick by word-shape. The fix
 * is not code that re-reads the model's answer — a structured field is the model's verdict and code overrides
 * it only to narrow (see `readEffectTier` in model-client.ts); it is telling every caller what each word
 * means, in the same words, from one table.
 *
 * THREE CALLS READ THIS TABLE, each at the price its own window can pay:
 *   - the gate's grant call takes the slice it needs — the pending action type's line and the boundaries that
 *     name it (`meaningLinesFor`), because that call is sized to a 4 096-token window and its fixed text is
 *     paid for out of the user messages that fit beside it;
 *   - the effect classifier takes one full line per value it may answer (`EFFECT_ENUM`), plus the boundaries;
 *   - the per-message extraction call takes the SHORT form of every value (`"short"`), plus the boundaries,
 *     because choosing a category from a sentence is its whole job and it cannot rule out a value it has
 *     never seen defined — while the whole dictionary in full does not fit beside a 4 000-character message
 *     piece in that window (measured against the server's own `usage.prompt_tokens`).
 * They cannot drift, because both lengths are projections of one table: each value carries its full `meaning`
 * and its short `gloss` side by side, and a value with one and not the other fails `model-client.test.ts`.
 *
 * What a line states is the EFFECT — what is changed, destroyed, sent, run — never the tool that did it and
 * never an example sentence: a prompt may not carry a sentence lifted from a test corpus, so there are no
 * examples here at all, only definitions and the lines where neighbours divide.
 */

import { GRANT_CATEGORY_VALUES } from "./auth-ledger.ts"

/**
 * One value, two lengths.
 *
 * `meaning` is what a caller that has room reads; `gloss` is the same distinction in the fewest words that
 * still separate it from its neighbours — written to stand alone next to the value name, so it drops the
 * examples and the second clauses, never the dividing property. Where a pair is the thing models get wrong,
 * the divider lives in `CATEGORY_BOUNDARIES` and the gloss says enough for the pair line to be understood.
 */
type Entry = { gloss: string; meaning: string }

const DICTIONARY: Record<string, Entry> = {
	read_only: { gloss: "reads, changes nothing", meaning: "reads or inspects a file, a page, a repository — changes nothing" },
	read_secret: { gloss: "reads keys/tokens/credentials/.env", meaning: "reads secret material — keys, tokens, credentials, .env, a session's environment" },
	read_system_state: {
		gloss: "reads a machine's own status (procs, services, disks)",
		meaning: "reads what a machine or cluster reports about itself — processes, services, containers, disks, memory, network configuration, hardware — changes nothing, and its object is the machine or cluster, never a file",
	},
	write_project: {
		gloss: "creates/edits files in the project or temp",
		meaning: "creates or edits files inside the project, or in temp locations",
	},
	write_outside: { gloss: "creates/edits files outside the project", meaning: "creates or edits files on this machine outside the project" },
	write_sensitive: {
		gloss: "writes a program's own config location",
		meaning: "writes where a program reads its own config: /etc, systemd, cron, shell rc, ssh, git --global",
	},
	delete_outside: { gloss: "removes files outside the project", meaning: "removes files living outside the project directory" },
	delete_recursive: { gloss: "removes a directory tree", meaning: "removes a directory tree on this machine" },
	delete_data: {
		gloss: "removes items INSIDE a store, not the store",
		meaning: "removes things INSIDE a store — objects under a bucket prefix, rows, backup files — never the store itself",
	},
	wipe_protected: {
		gloss: "wipes a place that must never be wiped",
		meaning: "destroys a place that must never be wiped: /, home, system directories, the whole project",
	},
	history_wipe: {
		gloss: "destroys shell history, logs, every job",
		meaning: "destroys recorded history in one blow: shell history, system logs, every scheduled job",
	},
	device_write: { gloss: "writes a raw device node", meaning: "writes onto a raw device node (/dev/sda), not a file" },
	disk_destroy: { gloss: "formats or overwrites a disk", meaning: "formats or overwrites a disk or partition" },
	system_config: {
		gloss: "machine setup: services, firewall, users",
		meaning: "changes how the machine is set up: services enabled, firewall rules, mounts, sysctl, users",
	},
	system_power: { gloss: "reboots or powers off the machine", meaning: "changes the machine's power state: reboot, shutdown, power off" },
	system_destroy: {
		gloss: "removes what the machine needs to run",
		meaning: "removes what the machine needs to run: base packages, a user account, a whole project/resource group",
	},
	perm_change: { gloss: "chmod/chown a path", meaning: "changes who may read or write a path (chmod, chown)" },
	perm_destroy: {
		gloss: "destroys permissions of a protected place",
		meaning: "recursively destroys the permission set of a protected location",
	},
	persistent_access: {
		gloss: "leaves a standing way back in",
		meaning: "leaves a standing way back in: authorized_keys, a shell rc entry, a crontab entry",
	},
	privilege: { gloss: "runs elevated (sudo/root)", meaning: "runs with elevated rights (sudo/root) — the elevation itself, whatever it runs" },
	privilege_persist: {
		gloss: "standing elevated rights: sudoers, group",
		meaning: "grants standing elevated rights: a privileged group, a sudoers entry",
	},
	security_teardown: {
		gloss: "disables a security service or its rules",
		meaning: "disables a security service or removes its rules: firewall off, SELinux off",
	},
	process_control: {
		gloss: "stops/restarts/kills processes, however many",
		meaning: "stops, restarts or kills named processes or services, however many are named",
	},
	process_massacre: { gloss: "kills everything matching a pattern, or PID 1", meaning: "kills indiscriminately — a pattern matching everything, or PID 1" },
	package_system: {
		gloss: "installs/removes software machine-wide",
		meaning: "installs/removes/updates software machine-wide or globally, outside a project's env",
	},
	remote_exec: { gloss: "fetches code over the net and runs it", meaning: "fetches code over the network and runs it (a piped installer, a package from a URL)" },
	network_listen: { gloss: "opens a listening port", meaning: "opens a port or socket that accepts connections" },
	network_send: {
		gloss: "sends data out: upload, POST, push an image",
		meaning: "sends data out to an address: upload, POST, scp/rsync to a host, pushing an image to a registry",
	},
	exfiltration: { gloss: "sends SECRET material off the machine", meaning: "sends SECRET material off the machine — what leaves is a credential, not ordinary data" },
	vcs_remote: { gloss: "writes to a git remote: any push", meaning: "writes to a git remote: any push, including a force-push to an ordinary (non-protected) branch" },
	vcs_local: { gloss: "git work that cannot leave this machine", meaning: "git work that cannot leave this machine: commit, local branch, soft reset, config --local" },
	vcs_discard: { gloss: "throws away uncommitted local work", meaning: "throws away uncommitted or untracked local work, or a local branch/stash" },
	vcs_force_protected: {
		gloss: "force/mirror push to a PROTECTED branch (main, develop, release/*)",
		meaning: "force, delete or mirror push to a PROTECTED branch — main, master, trunk, develop, dev, release/*, production, prod, stable (a mirror push rewrites all of them); forcing an ORDINARY branch is vcs_remote, not this",
	},
	vcs_history_rewrite: {
		gloss: "rewrites published commit history",
		meaning: "rewrites published commit history, so the remote's history no longer matches this one",
	},
	cluster_mutation: {
		gloss: "changes a cluster or cloud resource",
		meaning: "changes a cluster or cloud RESOURCE — a pod, deployment, release, node, instance",
	},
	cluster_wide_destroy: {
		gloss: "destroys a whole store or all of a cluster",
		meaning: "destroys a whole managed store or all of a cluster at once: a namespace deleted, a whole bucket wiped",
	},
	container_mutation: {
		gloss: "changes containers/images on THIS machine",
		meaning: "changes containers/images/volumes on THIS machine: removed, pruned, created, reconfigured",
	},
	container_privileged: {
		gloss: "starts a container with host-level power",
		meaning: "starts a container with host-level power (--privileged, host namespace, added capabilities)",
	},
	container_wipe: { gloss: "destroys a machine's container setup", meaning: "destroys a machine's whole container setup at once: every image and volume" },
	db_mutation: {
		gloss: "changes rows or one table (DROP TABLE in)",
		meaning: "changes rows or one table — insert, update, a delete with a condition, DROP TABLE, ALTER; one table, never the whole database",
	},
	db_destroy: {
		gloss: "removes a whole database or schema",
		meaning: "removes a whole database or schema, or everything in it at once: DROP DATABASE, FLUSHALL, truncating every table",
	},
	run_project_code: {
		gloss: "runs this project's own code",
		meaning: "runs this project's own code, scripts, tests or builds, with the user's own rights",
	},
	agent_spawn: { gloss: "starts another agent or automation", meaning: "starts another agent or automation that acts on its own from here" },
	interactive_editor: { gloss: "opens an interactive editor or prompt", meaning: "opens an interactive editor or prompt that waits for a human to type" },
	other: { gloss: "nothing above fits", meaning: "nothing above fits what this action does" },
}

const view = (entries: Record<string, Entry>, key: keyof Entry): Record<string, string> =>
	Object.fromEntries(Object.entries(entries).map(([name, entry]) => [name, entry[key]]))

/** The full definition of each value — what a call with room in its window reads. */
export const CATEGORY_MEANINGS: Record<string, string> = view(DICTIONARY, "meaning")

/** The same definition in the fewest words that still divide it from its neighbours — what the extraction
 *  call reads, because its window is shared with the message piece it has to read whole. */
export const CATEGORY_GLOSSES: Record<string, string> = view(DICTIONARY, "gloss")

/**
 * Where the neighbours divide, stated as pairs because that is where the models actually go wrong. Each line
 * names the value it separates from, which is what lets a caller pick the ones that concern its own category.
 */
export const CATEGORY_BOUNDARIES: Array<{ values: string[]; line: string }> = [
	{
		values: ["delete_data", "cluster_mutation", "cluster_wide_destroy"],
		line: "objects inside a bucket, table or backup folder are delete_data whatever CLI typed it; cluster_mutation is for cluster RESOURCES; cluster_wide_destroy is the store itself gone whole — a stop put on a whole store still covers the items inside it",
	},
	{
		values: ["network_send", "container_mutation", "container_wipe"],
		line: "pushing an image or chart sends bytes to a registry — network_send; it mutates no container; container_wipe is a machine's whole container setup",
	},
	{
		values: ["network_send", "exfiltration"],
		line: "ordinary data going out is network_send; exfiltration is only when what leaves is secret material",
	},
	{
		values: ["vcs_remote", "vcs_force_protected"],
		line: "every push is vcs_remote; vcs_force_protected is a force/delete/mirror push to a PROTECTED branch only — the branch decides, not the force",
	},
	{
		values: ["db_mutation", "db_destroy"],
		line: "one table or its rows, DROP TABLE included, is db_mutation; db_destroy is a whole database or schema gone",
	},
	{
		values: ["read_only", "read_system_state", "read_secret"],
		line: "read_system_state is what a machine or cluster says about itself when asked, read_only is a file or a page that lives somewhere, and read_secret is secret material — the environment a session runs with is read_secret even though `env` looks like a status command",
	},
	{
		values: ["read_system_state", "system_config", "process_control"],
		line: "looking at a service's state is read_system_state; stopping it, enabling it or reconfiguring the machine that hosts it is not a read at all — it is process_control or system_config, whatever the sentence called it",
	},
	{
		values: ["process_control", "process_massacre"],
		line: "process_control names what it stops, however many that is; process_massacre is the sweep that names nothing",
	},
	{
		values: ["delete_recursive", "wipe_protected"],
		line: "delete_recursive removes a tree the user pointed at; wipe_protected is a location that must never be wiped",
	},
	{
		values: ["network_listen", "run_project_code"],
		line: "starting something that accepts connections is network_listen even when what it starts is this project's own code - the port is the effect that reaches further",
	},
]

/** Which of the two lengths a caller wants. `"full"` is the definition, `"short"` is the same divider in a
 *  few words; the words are the point of the dictionary, so the only difference is how much room it pays with. */
export type DictionaryLength = "full" | "short"

/** The values this dictionary covers, in enum order — the same order the schema's enum is sent in. */
export function categoryMeaningLines(values: readonly string[] = GRANT_CATEGORY_VALUES, length: DictionaryLength = "full"): string[] {
	const table = length === "short" ? CATEGORY_GLOSSES : CATEGORY_MEANINGS
	return values.map((c) => `- ${c}: ${table[c] ?? "no meaning recorded"}`)
}

/** Every boundary that names one of these values, as one clause; empty string when none does. */
export function boundaryLinesFor(values: readonly string[]): string {
	const want = new Set(values)
	return CATEGORY_BOUNDARIES.filter((b) => b.values.some((v) => want.has(v))).map((b) => b.line).join("; ")
}

/**
 * The slice one call needs, already shaped as prompt lines: what the pending action type means, then the
 * boundary that separates it from the neighbour models confuse it with. Used by the gate's grant call, whose
 * window is shared with the user messages it has to read — the whole dictionary does not fit beside them
 * — and the call only ever has to judge the type it was given.
 */
export function meaningLinesFor(category: string): string[] {
	const segments = category.split("+").map((s) => s.trim()).filter(Boolean)
	// A gate-internal category (`unproven_structure`, `unknown_command`) is not in the dictionary — it says why
	// the analyzer stopped, not what the action does. Say nothing rather than print a placeholder into a prompt.
	const known = segments.filter((s) => CATEGORY_MEANINGS[s] !== undefined)
	const out = known.map((s) => `${segments.length > 1 ? `What ${s} means: ` : "What that means: "}${CATEGORY_MEANINGS[s]}`)
	const boundary = boundaryLinesFor(segments)
	if (out.length > 0 && boundary) out.push(`Not to be confused with: ${boundary}.`)
	return out
}

/** The boundary block: one line per pair, prefixed once so the lines themselves stay reusable. */
export function boundaryBlock(): string {
	return `Where the neighbours divide:\n${CATEGORY_BOUNDARIES.map((b) => `- ${b.line}`).join("\n")}`
}

/** The dictionary as one block, optionally with the boundary lines under it, in the requested length. */
export function categoryMeaningBlock(
	values: readonly string[] = GRANT_CATEGORY_VALUES,
	withBoundaries = false,
	length: DictionaryLength = "full",
): string {
	const body = categoryMeaningLines(values, length).join("\n")
	if (!withBoundaries) return body
	return `${body}\n${boundaryBlock()}`
}
