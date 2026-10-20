/**
 * What the model is told when auto mode says no.
 *
 * Two shapes of text live here, plus the one clause they share. A *refusal* carries the classifier's own reason
 * and is recognisable later by its fixed lead-in, so callers can tell a refusal apart from ordinary
 * assistant prose. An *unreachable* notice is the degenerate refusal: the safety model could
 * not be asked at all, so nothing was judged either way. {@link classifierUnavailableReason} is the short form of
 * the second shape, for a gate reason line that has no room for a paragraph.
 *
 * Both shapes name their author. That is cheap here and nowhere else: inside this module the
 * decider is known by construction — a refusal IS the model's verdict, an unreachable notice IS
 * the model being unusable — while every other denial site has to be told by its caller.
 *
 * The advice that follows a refusal is exported separately because other call sites may want
 * to repeat it without repeating the refusal itself.
 *
 * Modified for @lukolszewski/adaptive-acl (2026); upstream pi-permission-modes remains
 * MIT-licensed — see LICENSE.
 */

import { attributionLine, type DenialContext } from "./gate-bridge.ts"

/** Fixed lead-in of every refusal. The classifier's reason is appended immediately after it. */
export const AUTO_MODE_REJECTION_PREFIX =
	"The auto-mode safety check turned this action down. Why: "

/**
 * Reusable advice for what to do after a refusal: an honest detour is fine, a sneaky one is
 * not, and when no honest detour exists the decision belongs to the user.
 */
export const DENIAL_WORKAROUND_GUIDANCE =
	"A detour is allowed: if another tool gets you to the same result and is the ordinary way " +
	"to ask for it, use it — browsing a folder with the ls tool after a shell `find` was refused, " +
	"or pulling one value out with the grep tool instead of a pipeline. What is not allowed is " +
	"smuggling the refused action through: repackaging it inside `bash -c`, a script file, a heredoc " +
	"or a test runner, or re-issuing it with cosmetic edits that mean exactly the same thing, are " +
	"all bad-faith bypasses. And if the request truly cannot be finished without the blocked " +
	"capability, do not force it — pause, tell the user what you meant to run and what you needed it " +
	"for, name what stood in the way, and wait for their call."

/** Where a human can grant this class of action up front, in the syntax this plugin parses. */
const PERMISSION_RULE_HINT =
	"When the user wants this class of action to go through unattended, they can grant it as a " +
	"permission rule instead: `Bash(<command prefix>:*)` for shell calls, `Read(<path>)` or " +
	"`Edit(<path>)` for file tools. Global rules live in ~/.pi/agent/adaptive-acl.json, " +
	"per-project rules in the project's .pi/projects/<id>/permissions.json."

/** Prompt to harvest rule suggestions once the current request is otherwise wrapped up. */
const RULE_SUGGESTION_CLOSER =
	"Near the end of your turn, tell the user which rules you would need added so these calls " +
	"stop being blocked, and let them choose."

export function isClassifierDenial(content: string): boolean {
	// Prefix test only: whatever follows the lead-in is the classifier's own free text.
	const lead = AUTO_MODE_REJECTION_PREFIX
	return content.slice(0, lead.length) === lead
}

/**
 * The short form: one clause for "there was no verdict, because the classifier could not be asked".
 *
 * This is the wording every failure of that kind shares — a Copilot Auto session that would not mint, a pick in a
 * dialect we cannot encode, `model_not_supported`, a 404 for a request that lost its version header,
 * `Unsupported parameter`, a spent token allowance, an answer cut off by its own cap. None of them is a refusal:
 * nothing was judged. Naming the cause is what makes the sentence actionable, because the causes want different
 * fixes and a bare "unavailable" sends the reader to none of them.
 */
export function classifierUnavailableReason(cause?: string): string {
	const specific = (cause ?? "").replace(/\s+/g, " ").trim()
	return `classifier unavailable${specific ? ` (${specific})` : ""} — it could not be asked, so there is no verdict to act on`
}

export function buildYoloRejectionMessage(reason: string, ctx?: DenialContext): string {
	const independentWork =
		"Anything else on your list that does not need this action is untouched — go ahead with it."
	return [
		`${AUTO_MODE_REJECTION_PREFIX}${reason}.`,
		attributionLine({ ctx: { ...ctx, decidedBy: "classifier", classifierWhy: ctx?.classifierWhy ?? "denied" } }),
		independentWork,
		DENIAL_WORKAROUND_GUIDANCE,
		PERMISSION_RULE_HINT,
		RULE_SUGGESTION_CLOSER,
		humanPresentClause(ctx),
	]
		.filter((part) => part && part !== "")
		.join(" ")
}

/** Only said when a person is actually watching: a refusal the model issued can be overruled by
 *  the human who owns the session, and the way to do that is a mode or a rule, never a workaround. */
function humanPresentClause(ctx?: DenialContext): string {
	if (!ctx?.humanPresent) return ""
	return (
		"A human is watching this session, so this decision is theirs to make explicitly — switching to " +
		"/mode ask, or adding a permission rule that names this target, is the honest route; their silence is not approval."
	)
}

export function buildClassifierUnavailableMessage(
	toolName: string,
	classifierModel: string,
	ctx?: DenialContext,
): string {
	// The cause comes from whoever caught the failure — the transport's own error text, or the reason the endpoint
	// could not be resolved. Without it this says only "did not answer", which is the sentence a user reads when
	// they have a Copilot login to re-authenticate, an allowance that is spent, or a model GitHub will not serve,
	// and cannot tell which.
	const cause = (ctx?.classifierCause ?? "").replace(/\s+/g, " ").trim()
	const reachability =
		`The safety classifier ${classifierModel} did not answer${cause ? ` (${cause})` : ""}, so auto mode has no verdict on ` +
		`${toolName} and will not substitute a guess for one.`
	const attribution = attributionLine({
		ctx: { ...ctx, decidedBy: "classifier", classifierWhy: ctx?.classifierWhy ?? "unavailable" },
	})
	const retry = "Wait a moment, then make the same call again."
	const fallback =
		"If it stays out of reach, set this step aside, make progress on the parts of the request " +
		"that do not need it, and come back to it later."
	const readOnly =
		"Read-only steps — opening files, searching the tree, listing directories — never consult " +
		"the classifier, so carry on with those as usual."
	return [reachability, attribution, retry, fallback, readOnly, humanPresentClause(ctx)]
		.filter((part) => part && part !== "")
		.join(" ")
}
