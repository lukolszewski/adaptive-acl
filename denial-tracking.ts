/**
 * Denial tracking — decides when the classifier has said "no" often enough that the run should
 * stop asking it and go back to the user.
 *
 * Two limits are watched, because they describe two different failures:
 *
 *   `maxConsecutive` — a short burst of refusals with no allowance in between means the agent is
 *     pushing on one specific door. This is a streak: a single allowed call ends it and the budget
 *     starts over, which is right, because an approval is evidence the agent is no longer stuck.
 *   `maxTotal` — refusals scattered across a whole run add up even when each was followed by an
 *     approval. Progress is being made, just too slowly to keep paying for a model call, and no
 *     healthy run reaches twenty. An allowance does not touch this one, so once it is reached it
 *     stays reached.
 *
 * The state is a pair of ordinals rather than two running counters. `denials` counts every refusal
 * ever recorded; `clearedAt` remembers what that count was the last time a call was allowed. The
 * streak is the distance between the two, so "an allowance resets the streak without reducing the
 * total" is a property of the representation instead of a rule two fields have to agree on. A
 * consequence worth knowing: the numbers in the state are ordinals of the refusal history, not
 * "denials remaining", and neither updater writes to its argument — `index.ts` reassigns the
 * result either way, and `recordClassifierSuccess` hands back the very object it was given when
 * there is no streak to break.
 */

/** The two caps, stated first so the rules read before the thing they measure. */
export const DENIAL_LIMITS = {
	maxConsecutive: 3,
	maxTotal: 20,
} as const

export type DenialTrackingState = {
	/** Refusals recorded in this run so far. Monotonic: no event lowers it. */
	readonly denials: number
	/** The value `denials` had the last time a call was allowed — the base of the live streak. */
	readonly clearedAt: number
}

/** Nothing has happened yet, so the streak is measured from zero. */
export function createDenialTrackingState(): DenialTrackingState {
	return { denials: 0, clearedAt: 0 }
}

/** Refusals piled up since the last allowance. Zero means the last call went through. */
export function denialStreak(state: DenialTrackingState): number {
	return state.denials - state.clearedAt
}

/**
 * Stop asking the classifier and prompt the user: either the live streak has reached
 * `maxConsecutive`, or `maxTotal` refusals have accumulated across the run. The first condition
 * releases as soon as something is allowed; the second never does.
 */
export function shouldFallbackToPrompting(state: DenialTrackingState): boolean {
	const stuckOnOneCall = denialStreak(state) >= DENIAL_LIMITS.maxConsecutive
	const outOfBudget = state.denials >= DENIAL_LIMITS.maxTotal
	return stuckOnOneCall || outOfBudget
}

/** One more refusal. Only the tally moves; the base of the streak is left where it was. */
export function recordClassifierDenial(state: DenialTrackingState): DenialTrackingState {
	const tally = state.denials + 1
	return { denials: tally, clearedAt: state.clearedAt }
}

/**
 * One allowed call: the streak is over. The tally is left exactly where it was, because an
 * approval cannot un-denial a refusal — a run that keeps tripping the limit keeps climbing toward
 * `maxTotal` no matter how many approvals it collects in between.
 */
export function recordClassifierSuccess(state: DenialTrackingState): DenialTrackingState {
	if (denialStreak(state) === 0) return state
	return { denials: state.denials, clearedAt: state.denials }
}
