/**
 * Copyright © 2026 Łukasz Olszewski
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE.
 *
 * Layer-0 bash parsing: the public shape of what the walker (`bash-walker.ts`) produces, and
 * the view of it the verb handlers still consume.
 *
 * `parseBashCommand` parses with tree-sitter-bash and walks the tree under
 * `docs/LAYER0-WALKER-SPEC.md`: every construct is either proven to a literal argv or the whole
 * input is refused with one stable reason id (§12). Nothing in between — a command is never
 * emitted with a part of it missing.
 *
 * The result carries the structure the tier tables need:
 *
 *   - **heredoc bodies**, attached to the command that reads them, so an interpreter fed by
 *     stdin is classified on its program text (§8);
 *   - the **connector** (`;`, `&&`, `||`, `|`, `|&`, `&`, newline) in front of each simple
 *     command, which the verb handlers use for `pipedFrom`/`pipesTo`;
 *   - `opaque`: a value that is only known at runtime but is harmless to the parse — the output
 *     of a proven inert substitution, or a variable from the inert list (§5.10) — appears in argv
 *     as `__CMDSUB_OUTPUT__` / `__TRACKED_VAR__`. Those are runtime values wearing the costume of
 *     a literal (`cat "$HOME/x"` arrives as `cat __TRACKED_VAR__/x`, which would classify as a
 *     project-relative path), so any command carrying one is flagged and the policy refuses to
 *     treat its arguments as literals (`unproven_value`);
 *   - `malformed`: distinguishes "this command is broken, ask the model to fix it" (unterminated
 *     quote, control characters, over-long input) from "this command uses shell features we refuse
 *     to analyse" (loops, `$VAR`, function definitions). The first goes to the fix-and-retry path,
 *     the second to the effect model.
 *
 * Safety note: `start`/`end`/`connector` are attribution used for prompt hints and pipe context
 * only — nothing may depend on them for a verdict. Heredoc attribution is the exception and is
 * checked by the walker: a body it cannot attribute refuses the whole input
 * (`heredoc-unattributed`) rather than silently dropping code an interpreter would read.
 */

import type { SimpleCommand, Word } from "./shell-lexer.ts"
import { walkBash } from "./bash-walker.ts"

/** Substituted into argv when a value is only known at runtime (§5.10, §6). */
export const CMDSUB_PLACEHOLDER = "__CMDSUB_OUTPUT__"
export const TRACKED_VAR_PLACEHOLDER = "__TRACKED_VAR__"

function hasPlaceholder(v: string): boolean {
	return v.includes(CMDSUB_PLACEHOLDER) || v.includes(TRACKED_VAR_PLACEHOLDER)
}

export type AstRedirect = {
	/** `>`, `>>`, `<`, `<<<`, `>&`, `<&`, `>|`, `&>`, `&>>`. */
	op: string
	target: string
	fd?: number
	/** `>&2` / `<&0` — a file-descriptor dup, not a file. */
	fdDup: boolean
}

export type AstCommand = {
	argv: string[]
	envVars: Array<{ name: string; value: string }>
	redirects: AstRedirect[]
	/** Quoted-delimiter heredoc bodies attached to this command, in source order. */
	heredocs: string[]
	/** Source span of the command (`source.slice(start, end) === text`, §13). */
	text: string
	start: number
	end: number
	/** Operator in front of this command: "", ";", "&&", "||", "|", "|&", "&", "\n". */
	connector: string
	/** Some argument/redirect/env value is a runtime placeholder, not a literal. */
	opaque: boolean
}

export type AstParse =
	| { kind: "simple"; commands: AstCommand[] }
	| {
			kind: "unproven"
			/** A stable id from the §12 vocabulary, never a sentence. */
			reason: string
			nodeType?: string
			/** The command is malformed (fix-and-retry) rather than merely feature-rich. */
			malformed: boolean
	  }

/**
 * Parse a bash command string into per-simple-command argv with the structure the tables need.
 * Fail-closed: anything the walker will not vouch for comes back as `{ kind: "unproven" }`; the
 * caller decides between "ask the model to fix it" (`malformed`) and "let the effect model judge
 * it" (everything else). The grammar must have been loaded once per process with
 * `initBashParser()` (bash-parser.ts); until then every parse is refused `parser-unavailable`.
 */
export function parseBashCommand(command: string): AstParse {
	return walkBash(command)
}

/**
 * A run-time value in an ARGUMENT position, kept as a slot instead of refused (template parse only).
 *
 * `parseBashCommand` keeps refusing these; the template parse exists for the three callers that judge a
 * command with its values filled in or tested: the resolver, the allow matcher and the "Allow always" writer.
 */
export type Slot = {
	/** Index into `argv` of the word that holds the slot. */
	argIndex: number
	/** `"$X"` (true) vs `$X` (false): an unquoted value is split on whitespace and glob-expanded by bash. */
	quoted: boolean
	/** The slot is the entire word, not part of it (`"$X"` vs `"exit $X"`). */
	whole: boolean
	source: "var" | "cmdsub"
	/** Variable name, for `var` (`PIPESTATUS` for `${PIPESTATUS[0]}`). */
	name?: string
	/** The substitution's own source text, for `cmdsub` (`git rev-parse HEAD` for `$(git rev-parse HEAD)`). */
	inner?: string
	/** Source offsets of the whole expansion, `command.slice(span[0], span[1])` (e.g. `"$X"` → `$X`). */
	span: [number, number]
}

/** A walked command whose argv may hold slots; each slot's word carries the walker's placeholder text. */
export type TemplateCommand = AstCommand & { slots: Slot[] }

export type TemplateParse = { kind: "simple"; commands: TemplateCommand[] } | Extract<AstParse, { kind: "unproven" }>

/**
 * The same walk as {@link parseBashCommand}, except a variable or an accepted substitution in an argument
 * position becomes a {@link Slot} instead of a refusal. Command position, redirect targets, execution-changing
 * env prefixes and the arguments of anything that runs its arguments as code stay refused.
 *
 * The placeholders of §5.10/§6.1 stay in `argv` where the slot is, exactly as in a plain parse, so
 * `opaque` means the same thing in both — a slot says *which* word holds the run-time value and where it
 * was written, and nothing else. Each command's `slots` are in the order their words were emitted.
 *
 * A refusal here is the same refusal the plain walk gives, with one addition: a substitution's own
 * commands are walked (and emitted first, §6.2) even where the outer value became a slot, so a refusal
 * inside the substitution refuses the template as a whole.
 */
export function parseBashTemplate(command: string): TemplateParse {
	return walkBash(command, "template")
}

/** Word wrapper for the argv values (quoting has already been resolved by the walker). */
function word(value: string): Word {
	return { value, raw: value, quoted: false, hasExpansion: value.includes("$") || value.includes("`") }
}

/**
 * View of a walked command in the shape `risk-handlers.ts` still expects (the old lexer's
 * `SimpleCommand`). Only `raw` and `heredocs` are read by the handlers today; the rest
 * is filled so that anything touching it sees a consistent object.
 */
export function toLegacyCommand(c: AstCommand): SimpleCommand {
	return {
		argv: c.argv.map(word),
		assignments: c.envVars.map((e) => ({ name: e.name, value: e.value, hasExpansion: hasPlaceholder(e.value) })),
		redirects: c.redirects.map((r) => ({ op: r.op, fd: r.fd, target: word(r.target) })),
		heredocs: c.heredocs,
		connector: c.connector,
		substitutions: [],
		raw: c.text,
	}
}
