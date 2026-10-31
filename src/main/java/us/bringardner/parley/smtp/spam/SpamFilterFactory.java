package us.bringardner.parley.smtp.spam;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Makes a {@link SpamFilter} of one kind. Found through {@link java.util.ServiceLoader} or
 * {@link SpamFilters#register}; the id is what the {@code spam.provider} setting and a domain's
 * override name.
 */
public interface SpamFilterFactory {

	/** The id (lower case letters and digits): the value of {@code spam.provider} and the prefix of {@code spam.<id>.*}. */
	String id();

	/** A name for people (the web administration). */
	String label();

	/** The settings the filter has, without the {@code spam.<id>.} prefix; the web administration offers them. */
	default List<SpamOption> options() {
		return Collections.emptyList();
	}

	/**
	 * Make a filter.
	 *
	 * @param settings the filter's settings (the {@link #options()} keys, without prefix, that are set)
	 *        and {@code timeoutMillis}, the longest the filter should take
	 * @throws IllegalArgumentException if a setting is wrong
	 */
	SpamFilter create(Map<String, String> settings);
}
