package us.bringardner.parley.smtp.spam;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import us.bringardner.parley.files.ConnectionSetting;
import us.bringardner.parley.files.ConnectionSettings;

/**
 * A kind of spam scanner the mail servers can use: what it is called, what it can do, which settings
 * it needs, and how to make a {@link SpamFilter} that talks to it. The servers and the web
 * administration know no scanner by name: they ask {@link SpamProviders} which providers exist, show
 * their {@link #getSettings()} and make filters with {@link #create}.
 * <p>
 * A provider is found as FileSourceFactory's are: list the class in
 * {@code META-INF/services/us.bringardner.parley.smtp.spam.SpamProvider} in a jar on the class path or
 * in a plugin folder (parley-core's {@code Plugins}). It needs a public constructor without
 * arguments, must hold no state (the same instance serves every caller) and must be thread safe.
 * <p>
 * The settings are kept in the queue's properties as {@code spam.<id>.<key>}; the engine adds
 * {@value #TIMEOUT_MILLIS} (the longest a call may take) to what {@link #create} gets.
 */
public interface SpamProvider {

	/** What a provider can do beyond scoring a message. */
	enum Feature {
		/** Scores a message: {@link SpamFilter#check}. Every provider can. */
		CHECK,
		/** Learns that a message is spam or ham: {@link SpamFilter#learn}. */
		LEARN,
		/** Says whether the scanner is reachable, and its version: {@link SpamFilter#status}. */
		STATUS
	}

	/** The setting the engine adds to those of the provider: the longest a call may take, in milliseconds. */
	String TIMEOUT_MILLIS = "timeoutMillis";

	/** The id (lower case letters and digits): the value of {@code spam.provider} and the prefix of {@code spam.<id>.*}. */
	String getId();

	/** A name for people (the web administration's list). */
	String getTitle();

	/** What the scanner is and what it needs, in a sentence or two (shown beside the list). */
	default String getDescription() {
		return "";
	}

	/** What this provider can do; {@link Feature#CHECK} is always in it. */
	default Set<Feature> getFeatures() {
		return EnumSet.of(Feature.CHECK);
	}

	/**
	 * The settings the provider has, in the order a form shows them (without the {@code spam.<id>.}
	 * prefix). The same description FileSource connections use, so a form that shows one shows the other.
	 */
	default List<ConnectionSetting> getSettings() {
		return Collections.emptyList();
	}

	/** What is wrong with these settings (one message per problem), empty if nothing: checked against {@link #getSettings()}. */
	default List<String> validate(Map<String, String> settings) {
		Properties p = new Properties();
		settings.forEach((k, v) -> {
			if (v != null) {
				p.setProperty(k, v);
			}
		});
		return ConnectionSettings.validate(getSettings(), p);
	}

	/**
	 * Make a filter.
	 *
	 * @param settings the provider's settings that are set (keys without the prefix), and {@link #TIMEOUT_MILLIS}
	 * @throws IllegalArgumentException if a setting is wrong
	 */
	SpamFilter create(Map<String, String> settings);
}
