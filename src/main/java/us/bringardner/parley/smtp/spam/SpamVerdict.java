package us.bringardner.parley.smtp.spam;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * What a filter found. The score and the {@link #isSpam() spam} flag are always there; the
 * {@link #getAction() action} is what the filter itself would do, if it has an opinion (the
 * server's thresholds can override it, see {@link Spam}).
 */
public final class SpamVerdict {

	/** What to do with a message, from the mildest to the harshest. */
	public enum Action {
		/** Deliver it. */
		ACCEPT,
		/** Deliver it to the Junk mailbox. */
		QUARANTINE,
		/** Refuse it for now (451): the sender may try again. */
		DEFER,
		/** Refuse it (550). */
		REJECT
	}

	private final double score;
	private final double requiredScore;
	private final boolean spam;
	private final Action action;
	private final List<String> symbols;

	/**
	 * @param score the filter's score; higher is spammier
	 * @param requiredScore the score at which the filter calls a message spam (0 if it has none)
	 * @param spam whether the filter calls the message spam
	 * @param action what the filter would do, or null if it leaves that to the server
	 * @param symbols the rules that matched (may be empty)
	 */
	public SpamVerdict(double score, double requiredScore, boolean spam, Action action, List<String> symbols) {
		this.score = score;
		this.requiredScore = requiredScore;
		this.spam = spam;
		this.action = action;
		this.symbols = Collections.unmodifiableList(new ArrayList<>(symbols));
	}

	/** A message nobody checked: score 0, not spam. */
	public static SpamVerdict clean() {
		return new SpamVerdict(0, 0, false, Action.ACCEPT, Collections.emptyList());
	}

	public double getScore() {
		return score;
	}

	public double getRequiredScore() {
		return requiredScore;
	}

	public boolean isSpam() {
		return spam;
	}

	/** What the filter would do, or null. */
	public Action getAction() {
		return action;
	}

	public List<String> getSymbols() {
		return symbols;
	}
}
