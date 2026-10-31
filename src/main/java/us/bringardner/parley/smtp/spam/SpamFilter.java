package us.bringardner.parley.smtp.spam;

import java.io.IOException;

/**
 * A spam filter the SMTP server asks about a message after it has been received and before it is
 * accepted. An implementation sends the message to a scanner (or scores it itself) and says what it
 * found; the server decides what to do with the answer (see {@link Spam}).
 * <p>
 * An implementation is made by its {@link SpamFilterFactory} from the settings of the queue, may be
 * called by many sessions at once, and must be thread safe. Any exception (a scanner that is down or
 * slow) means "no answer": the server accepts the message unscored, so a filter never loses mail.
 * To plug in another scanner, implement the two interfaces and list the factory in
 * {@code META-INF/services/us.bringardner.parley.smtp.spam.SpamFilterFactory} (or call
 * {@link SpamFilters#register}).
 */
public interface SpamFilter {

	/** The id of this filter (its factory's id), for headers and logs. */
	String id();

	/**
	 * Score a message.
	 *
	 * @throws IOException if the scanner can't be reached or gave no usable answer
	 */
	SpamVerdict check(SpamRequest request) throws IOException;

	/** Release what the filter holds (connections...); it is not used again. */
	default void close() {
	}
}
