package us.bringardner.parley.smtp.spam;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The kinds of spam filter that can be chosen: the built-in ones (none, rspamd, spamassassin), those
 * listed in {@code META-INF/services/us.bringardner.parley.smtp.spam.SpamFilterFactory} and those
 * given to {@link #register}.
 */
public final class SpamFilters {

	private static final Map<String, SpamFilterFactory> FACTORIES = new ConcurrentHashMap<>();
	private static volatile boolean loaded;

	private SpamFilters() {
	}

	private static void load() {
		if (loaded) {
			return;
		}
		synchronized (FACTORIES) {
			if (loaded) {
				return;
			}
			for (SpamFilterFactory f : new SpamFilterFactory[] { new NullSpamFilter.Factory(), new RspamdSpamFilter.Factory(),
					new SpamAssassinSpamFilter.Factory() }) {
				FACTORIES.put(f.id(), f);
			}
			try {
				for (SpamFilterFactory f : ServiceLoader.load(SpamFilterFactory.class)) {
					FACTORIES.putIfAbsent(f.id().toLowerCase(Locale.ROOT), f);
				}
			} catch (java.util.ServiceConfigurationError e) {
				// a broken plug-in doesn't take the built-in filters away
			}
			loaded = true;
		}
	}

	/** Add (or replace) a kind of filter. */
	public static void register(SpamFilterFactory factory) {
		load();
		String id = factory.id();
		if (id == null || !id.matches("[a-z0-9]+")) {
			throw new IllegalArgumentException("A spam filter id is lower case letters and digits: " + id);
		}
		FACTORIES.put(id, factory);
	}

	/** The factory with the id, or null. */
	public static SpamFilterFactory factory(String id) {
		load();
		return id == null ? null : FACTORIES.get(id.trim().toLowerCase(Locale.ROOT));
	}

	/** The ids of all the kinds, "none" first and the others in alphabetical order. */
	public static List<String> ids() {
		load();
		List<String> ret = new ArrayList<>(FACTORIES.keySet());
		java.util.Collections.sort(ret);
		ret.remove(NullSpamFilter.ID);
		ret.add(0, NullSpamFilter.ID);
		return ret;
	}

	/** All the factories, in the order of {@link #ids()}. */
	public static List<SpamFilterFactory> factories() {
		List<SpamFilterFactory> ret = new ArrayList<>();
		for (String id : ids()) {
			ret.add(FACTORIES.get(id));
		}
		return ret;
	}
}
