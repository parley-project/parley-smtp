package us.bringardner.parley.smtp.spam;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.parley.plugin.Plugins;

/**
 * The spam providers that exist, found at run time as FileSourceFactory's are: the classes listed in
 * {@code META-INF/services/us.bringardner.parley.smtp.spam.SpamProvider} of the jars on the class
 * path (this module lists its own three there) and of the plugin folders (parley-core's
 * {@link Plugins}), and those given to {@link #register}. Nothing else knows a provider by name.
 */
public final class SpamProviders {

	/** id to provider, in the order found; built when first needed and again after plugins are loaded. */
	private static volatile Map<String, SpamProvider> found;
	private static final Map<String, SpamProvider> REGISTERED = new ConcurrentHashMap<>();
	private static volatile boolean listening;

	private SpamProviders() {
	}

	private static Map<String, SpamProvider> found() {
		Map<String, SpamProvider> ret = found;
		if (ret == null) {
			synchronized (SpamProviders.class) {
				ret = found;
				if (ret == null) {
					if (!listening) {
						listening = true;
						Plugins.onLoad(() -> found = null);
					}
					ret = new LinkedHashMap<>();
					for (SpamProvider p : Plugins.providers(SpamProvider.class, e -> {
						// a plug-in that can't be loaded doesn't take the others away
						System.err.println("A spam provider cannot be loaded: " + e);
					})) {
						String id = p.getId() == null ? "" : p.getId().trim().toLowerCase(Locale.ROOT);
						if (id.matches("[a-z0-9]+")) {
							ret.putIfAbsent(id, p);
						}
					}
					found = ret = Collections.unmodifiableMap(ret);
				}
			}
		}
		return ret;
	}

	/** Add (or replace) a provider that isn't listed in a services file (a test, or a program that builds its own). */
	public static void register(SpamProvider provider) {
		String id = provider.getId();
		if (id == null || !id.matches("[a-z0-9]+")) {
			throw new IllegalArgumentException("A spam provider id is lower case letters and digits: " + id);
		}
		REGISTERED.put(id, provider);
	}

	/** Forget the providers given to {@link #register}. */
	public static void unregister(String id) {
		REGISTERED.remove(id);
	}

	/** The provider with the id, or null. */
	public static SpamProvider get(String id) {
		if (id == null) {
			return null;
		}
		String k = id.trim().toLowerCase(Locale.ROOT);
		SpamProvider p = REGISTERED.get(k);
		return p != null ? p : found().get(k);
	}

	/** All the providers: "none" first, then by title. */
	public static List<SpamProvider> all() {
		Map<String, SpamProvider> m = new LinkedHashMap<>(found());
		m.putAll(REGISTERED);
		List<SpamProvider> ret = new ArrayList<>(m.values());
		ret.sort((a, b) -> {
			if (a.getId().equals(NullSpamFilter.ID) != b.getId().equals(NullSpamFilter.ID)) {
				return a.getId().equals(NullSpamFilter.ID) ? -1 : 1;
			}
			return a.getTitle().compareToIgnoreCase(b.getTitle());
		});
		return ret;
	}

	/** The ids of all the providers, in the order of {@link #all()}. */
	public static List<String> ids() {
		List<String> ret = new ArrayList<>();
		for (SpamProvider p : all()) {
			ret.add(p.getId());
		}
		return ret;
	}

	/**
	 * Ask a provider's scanner whether it is there, with these settings (what a form has, saved or
	 * not): a status that is down says why, including a setting that is wrong.
	 */
	public static SpamStatus test(String id, Map<String, String> settings, int timeoutMillis) {
		SpamProvider p = get(id);
		if (p == null) {
			return SpamStatus.down("There is no spam provider '" + id + "'");
		}
		List<String> problems = p.validate(settings);
		if (!problems.isEmpty()) {
			return SpamStatus.down(String.join("; ", problems));
		}
		Map<String, String> s = new LinkedHashMap<>(settings);
		s.put(SpamProvider.TIMEOUT_MILLIS, String.valueOf(timeoutMillis));
		SpamFilter f = null;
		try {
			f = p.create(s);
			return f.status();
		} catch (RuntimeException e) {
			return SpamStatus.down(e.getMessage() == null ? e.toString() : e.getMessage());
		} finally {
			if (f != null) {
				f.close();
			}
		}
	}
}
