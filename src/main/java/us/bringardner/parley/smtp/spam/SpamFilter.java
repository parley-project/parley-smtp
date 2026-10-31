package us.bringardner.parley.smtp.spam;

import java.io.IOException;

/**
 * A connection to one spam scanner, made by its {@link SpamProvider} from the queue's settings. The
 * SMTP server asks it about a message after the message has been received and before it is accepted;
 * the filter says what it found and the server decides what to do with the answer (see {@link Spam}).
 * <p>
 * It may be called by many sessions at once and must be thread safe. Any exception from
 * {@link #check} (a scanner that is down or slow) means "no answer": the server accepts the message
 * unscored, so a filter never loses mail.
 */
public interface SpamFilter {

	/** The id of this filter (its provider's id), for headers and logs. */
	String id();

	/**
	 * Score a message.
	 *
	 * @throws IOException if the scanner can't be reached or gave no usable answer
	 */
	SpamVerdict check(SpamRequest request) throws IOException;

	/**
	 * Teach the scanner that a message is spam or ham (not spam), if its provider has
	 * {@link SpamProvider.Feature#LEARN}.
	 *
	 * @throws UnsupportedOperationException if it can't learn
	 * @throws IOException if the scanner can't be reached or refused
	 */
	default void learn(SpamRequest request, boolean spam) throws IOException {
		throw new UnsupportedOperationException(id() + " can't learn");
	}

	/**
	 * Ask the scanner whether it is there: a provider with {@link SpamProvider.Feature#STATUS} answers
	 * from the scanner itself. An unreachable scanner is a status that is down, not an exception.
	 */
	default SpamStatus status() {
		return SpamStatus.up(null, "");
	}

	/** Release what the filter holds (connections...); it is not used again. */
	default void close() {
	}
}
