/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * The verb rules of the cloud and cluster CLIs (`gcloud`, `aws`, `az`, `doctl`, `fly`, `vercel`,
 * `netlify`, `wrangler`, `heroku`), and what category each answer turns into.
 *
 * Two failures are being pinned here, and they pull in opposite directions:
 *
 *  · a READ reported as a change. `gcloud logging read` and `compute instances get-serial-port-output` were
 *    `cluster_mutation` because the old rule was one regex of read nouns and everything else fell through to
 *    "mutation" — so the live read grants that existed could not reach them, and `gcloud auth
 *    print-access-token` was reported as a change to a cluster rather than as reading a credential.
 *  · a read reported as the wrong KIND of read. `gcloud compute instances list` is not a read of a file
 *    outside the project; it is the account reporting on itself, which is the `read_system_state` family
 *   . The OBJECT is unchanged (`gcloud`, `aws ec2`, the cluster name) on purpose: that is the word
 *    an existing grant already spells.
 *
 * The tables below are the report's commands verbatim, plus the rows the change must NOT move: stored data
 * (buckets, registries) stays `read_only`, a whole-project delete stays `never`, and an unknown verb is
 * `unknown` — escalated to the effect model — rather than guessed into a mutation.
 */

import { describe, expect, it } from "vitest"
import { evaluateBash, type PolicyDecision, type PolicyOptions } from "./risk-policy.ts"

const OPTS: PolicyOptions = { cwd: "/home/dev/proj", project: "/home/dev/proj", home: "/home/dev", fs: false }

const decide = (cmd: string) => evaluateBash(cmd, OPTS)
const objects = (d: PolicyDecision) => d.entities.filter((e) => e.kind === "target").map((e) => e.value)

/** The read categories a grant can answer; used to say "this is NOT one of them" where that is the point. */
const READ_CATEGORIES = ["read_only", "read_secret", "read_secret_remote", "read_system_state"]

describe("cloud reads are reads of the account's own state", () => {
	const READS = [
		// The five from the report, all `read_only` on `gcloud` before this change.
		"gcloud compute instances list",
		"gcloud projects list",
		"gcloud run services describe web",
		"gcloud iam service-accounts list",
		"gcloud auth list",
		// …and the verbs the old read list did not know, which fell through to `cluster_mutation`.
		"gcloud logging read --limit=10",
		"gcloud compute instances get-serial-port-output vm1",
		"gcloud compute instances get-iam-policy vm1",
	]

	it.each(READS)("%s", (command) => {
		const d = decide(command)
		expect(d.tier, command).toBe("ask")
		expect(d.category, command).toBe("read_system_state")
		// The object is the CLI's account surface, exactly what the `read_only` row named before, so every
		// grant a user already approved for `gcloud` still answers this row.
		expect(objects(d), command).toEqual(["gcloud"])
	})

	it("the same rule reaches every CLI that shares the grammar", () => {
		// One vocabulary, not one per vendor: the first positional group names the product and the verb is
		// the last word, whatever the product is called.
		const rows: Array<[string, string]> = [
			["az vm list", "az"],
			["az group list", "az"],
			["doctl compute droplet list", "doctl"],
			["fly status", "fly"],
			["vercel ls", "vercel"],
			["heroku apps", "heroku"],
			["netlify sites:list", "netlify"], // the colon spelling of a verb
			["gcloud beta run services describe web", "gcloud"],
		]
		for (const [command, object] of rows) {
			const d = decide(command)
			expect(d.tier, command).toBe("ask")
			expect(d.category, command).toBe("read_system_state")
			expect(objects(d), command).toEqual([object])
		}
	})
})

describe("a credential is read as a credential", () => {
	it("gcloud auth print-access-token is a secret read, not a cluster change", () => {
		// The report's third bug: this was `cluster_mutation`, so the prompt said the agent was about to
		// change a cluster when what it does is hand over a live access token.
		const d = decide("gcloud auth print-access-token")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("read_secret")
		expect(objects(d)).toEqual(["gcloud credentials"])
	})

	it("keeps the stored-secret rows", () => {
		// The generic rule must not replace the entry-naming rows: those say WHICH secret, which is what a
		// grant is written against. `aws secretsmanager get-secret-value` is the report's example.
		const rows: Array<[string, string]> = [
			["aws secretsmanager get-secret-value --secret-id prod/db", "aws-secret:prod/db"],
			["gcloud secrets versions access latest --secret=prod-db", "gcloud-secret:prod-db"],
			["az keyvault secret show --vault-name kv --name db-pass", "keyvault-secret:db-pass@kv"],
		]
		for (const [command, entity] of rows) {
			const d = decide(command)
			expect(d.tier, command).toBe("ask")
			expect(d.category, command).toBe("read_secret_remote")
			expect(objects(d), command).toContain(entity)
		}
	})

	it("does not turn a destruction into a read of the noun it destroys", () => {
		// Precedence, mutation before secret:
		// a secret word refines a READ, so `get-secret-value` is a secret read — but a verb that destroys the
		// same noun is a change, and calling it a read would be the original bug in the other direction.
		for (const command of ["aws secretsmanager delete-secret --secret-id x", "gcloud secrets versions destroy 3"]) {
			const d = decide(command)
			expect(d.tier, command).toBe("ask")
			expect(d.category, command).toBe("cluster_mutation")
			expect(READ_CATEGORIES, command).not.toContain(d.category)
		}
	})
})

describe("the two named exceptions write this machine, not the account", () => {
	it.each([
		["gcloud container clusters get-credentials prod", "gcloud"],
		["az aks get-credentials -n prod -g acme", "az"],
	])("%s writes the local kubeconfig", (command) => {
		// Not a read at all: it writes `~/.kube/config`, which every later `kubectl` reads. The category is the
		// one the code already uses for a write to a program's config location, and the object is the file.
		const d = decide(command)
		expect(d.tier, command).toBe("ask")
		expect(d.category, command).toBe("system_config")
		expect(objects(d), command).toEqual(["~/.kube/config"])
	})

	it("gcloud config set is a mutation of the CLI's own configuration", () => {
		const d = decide("gcloud config set project acme-prod")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("system_config")
		expect(objects(d)).toEqual(["gcloud config"])
		// …and `auth login` is the same act under a word no verb table would call a read.
		const login = decide("gcloud auth login")
		expect(login.category).toBe("system_config")
		expect(login.tier).toBe("ask")
	})
})

describe("a change keeps the answer a change had", () => {
	it("a resource is still a cluster mutation", () => {
		const d = decide("gcloud compute instances delete vm1")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("cluster_mutation")
		for (const command of ["az vm create -n x -g acme", "wrangler deploy", "aws ec2 stop-instances --instance-ids i-1"]) {
			expect(decide(command).category, command).toBe("cluster_mutation")
		}
	})

	it("wholesale destruction is still never", () => {
		for (const command of ["gcloud projects delete my-proj", "az group delete -n acme", "aws ec2 terminate-instances --instance-ids i-123"]) {
			expect(decide(command).tier, command).toBe("never")
		}
	})
})

describe("an unrecognised verb is escalated, not guessed", () => {
	it.each(["gcloud foo frobnicate", "aws foo frobnicate", "az foo frobnicate"])("%s", (command) => {
		// The failure this replaces: every unlisted verb used to be `cluster_mutation`, which stated a change
		// the command does not make. `unknown` hands the question to the effect model — the same shape every
		// other handler returns for a verb it does not know (no entities, category `unknown_command`).
		const d = decide(command)
		expect(d.tier, command).toBe("unknown")
		expect(d.category, command).toBe("unknown_command")
		expect(d.entities, command).toEqual([])
	})
})

describe("stored data is not the account reporting on itself", () => {
	it.each([
		["aws s3 ls", "aws s3"],
		["aws s3 ls s3://acme-data/dev/", "s3://acme-data/dev/"],
		["aws s3api list-buckets", "aws s3api"],
		["gsutil ls gs://acme-backup", "gsutil"],
		["gsutil cat gs://acme-backup/exports/x.csv", "gsutil"],
		["az storage blob list --container-name exports", "az"],
		["gcloud artifacts docker images list us-docker.pkg.dev/p/r/i", "gcloud"],
		["doctl registry repository list-v2", "doctl"],
	])("%s stays read_only", (command, object) => {
		// Stored data is excluded: a bucket, a registry and an object store hold bytes somebody put there, so a
		// troubleshooting grant must not reach them; the object is what it was.
		const d = decide(command)
		expect(d.tier, command).toBe("ask")
		expect(d.category, command).toBe("read_only")
		expect(objects(d), command).toContain(object)
	})

	it("helm cluster reads are read_system_state, like kubectl; a chart repository stays read_only", () => {
		const d = decide("helm list")
		expect(d.tier).toBe("ask")
		expect(d.category).toBe("read_system_state")
		expect(objects(d)).toEqual(["helm"])
	})

	it("kms decrypt is a secret read: it returns plaintext", () => {
		for (const command of ["gcloud kms decrypt --key k --ciphertext-file c --plaintext-file -", "aws kms decrypt --ciphertext-blob fileb://c"]) {
			const d = decide(command)
			expect(d.tier, command).toBe("ask")
			expect(d.category, command).toBe("read_secret")
		}
	})
})

describe("the aws and az tables", () => {
	it.each([
		// op → the answer the verb rules give it
		["aws ec2 describe-instances", "read_system_state", "aws ec2"],
		["aws ssm get-parameter --name /app/config", "read_system_state", "aws ssm"],
		["aws s3api list-buckets", "read_only", "aws s3api"],
		["aws secretsmanager get-secret-value --secret-id prod/db", "read_secret_remote", "aws-secret:prod/db"],
		["aws ec2 terminate-instances --instance-ids i-123", "cluster_wide_destroy", ""],
		["az vm list", "read_system_state", "az"],
		["az group list", "read_system_state", "az"],
		["az group delete -n acme", "cluster_wide_destroy", ""],
		["az keyvault secret show --vault-name kv --name db-pass", "read_secret_remote", "keyvault-secret:db-pass@kv"],
	])("%s → %s", (command, category, object) => {
		const d = decide(command)
		expect(d.tier, command).toBe(category === "cluster_wide_destroy" ? "never" : "ask")
		expect(d.category, command).toBe(category)
		if (object) expect(objects(d), command).toContain(object)
	})

	it("a global option's value is not the service word", () => {
		// `positionals()` drops an option and keeps its value, so `aws --endpoint-url URL s3 cp …` used to read
		// `URL` as the service and `s3` as the verb — the only shape
		// that lost tier once the verb rules replaced the old 'everything else is a mutation' fallback.
		const listed = decide("aws --endpoint-url https://s3.example.com s3 ls s3://acme-data/dev/")
		expect(listed.tier).toBe("ask")
		expect(listed.category).toBe("read_only")
		expect(objects(listed)).toEqual(["s3://acme-data/dev/"])
		const copied = decide("aws --endpoint-url https://s3.example.com s3 cp s3://acme-data/dev/x.csv ./x.csv")
		expect(copied.category).toBe("read_only")
		// …and the same for the global options that come before a service read.
		const described = decide("aws --region eu-west-1 --output json ec2 describe-instances")
		expect(described.category).toBe("read_system_state")
		expect(objects(described)).toEqual(["aws ec2"])
	})

	it("a hyphenated op is read by its segments, not as one unknown word", () => {
		// `describe-instances` is `describe`, `get-secret-value` is a `get` around the noun `secret`, and
		// `list-buckets` is a `list` — the aws spelling of the same verbs gcloud writes as separate words.
		expect(decide("aws ec2 describe-instances").category).toBe("read_system_state")
		expect(decide("aws ec2 describe-instances").tier).toBe("ask")
		expect(decide("aws secretsmanager get-secret-value --secret-id x").category).toContain("read_secret")
		expect(decide("aws s3api list-buckets").category).toBe("read_only")
	})
})
