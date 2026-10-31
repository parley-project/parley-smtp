package us.bringardner.parley.smtp.spam;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Function;

import us.bringardner.parley.files.ConnectionSetting;

import us.bringardner.parley.smtp.spam.SpamVerdict.Action;

/**
 * The spam settings of an SMTP server and the check it makes with them. It is the one place that
 * knows which {@link SpamFilter} applies to which recipient; the filters only score. Which providers
 * exist is not known here: {@link SpamProviders} finds them.
 * <p>
 * Settings of the SMTP server (in its settings under its prefix, {@code parley.mail.smtp.spam.*}; only the
 * server that receives mail from other servers checks for spam):
 * <ul>
 * <li>{@code enabled} (default false) and {@code provider} (a provider id, default
 * {@value NullSpamFilter#ID}): the provider for every domain without an override;</li>
 * <li>{@code rejectScore}, {@code quarantineScore}: when set, the score decides (reject,
 * Junk, or accept below both) and the filter's own action is ignored; when neither is set the
 * filter's action decides, or Junk for a message it calls spam if it has no action;</li>
 * <li>{@code maxSize} (bytes, default 2 MB; larger messages are not checked),
 * {@code timeoutMillis} (default 5000);</li>
 * <li>{@code <id>.<key>}: the settings of each provider (see {@link SpamProvider#getSettings()}).</li>
 * </ul>
 * The overrides by recipient domain are the queue's ({@code spam.domains} in its {@code queue.properties},
 * {@code example.com:off,other.org:rspamd}: {@code off}, or the id of the provider to use there, even
 * when spam checking is off for the rest), since domains belong to the queue.
 * <p>
 * A message for recipients with different filters is checked once per filter, each with its own
 * recipients, and the mildest outcome wins (the message can't be refused for some recipients and
 * accepted for others), so a domain that isn't checked keeps the mail of the others from being refused.
 * A filter that fails or is slow never stops mail: the message is accepted unscored.
 */
public final class Spam {

	/** The override that turns checking off for a domain. */
	public static final String OFF = "off";

	/** What the server does with a message. */
	public static final class Outcome {
		/** No filter applied. */
		public static final Outcome NONE = new Outcome(Action.ACCEPT, "", null, 0, null);

		public final Action action;
		/** Header fields to add (each ends with CRLF), or "". */
		public final String headers;
		/** The reply text when the message is refused, or null. */
		public final String text;
		public final double score;
		/** The id of the filter that scored highest, or null. */
		public final String provider;

		Outcome(Action action, String headers, String text, double score, String provider) {
			this.action = action;
			this.headers = headers;
			this.text = text;
			this.score = score;
			this.provider = provider;
		}
	}

	private volatile boolean enabled;
	private volatile String provider = NullSpamFilter.ID;
	private volatile Double rejectScore;
	private volatile Double quarantineScore;
	private volatile long maxSize = 2 * 1024 * 1024;
	private volatile int timeoutMillis = 5000;
	private volatile Map<String, Map<String, String>> options = Collections.emptyMap();
	private final Map<String, SpamFilter> filters = new ConcurrentHashMap<>();
	private volatile BiConsumer<String, Throwable> log = (m, e) -> {
	};

	// ------------------------------------------------------------------ settings

	/**
	 * Read the settings (blank values are not set).
	 *
	 * @param setting a setting of the server by its name after {@code spam.} ("enabled", "rspamd.url"), or null
	 * @throws IllegalArgumentException if a number is wrong, the provider is not known, or its settings are wrong
	 */
	public void configure(Function<String, String> setting) {
		boolean en = Boolean.parseBoolean(get(setting, "enabled", "false"));
		String prov = get(setting, "provider", NullSpamFilter.ID).toLowerCase(Locale.ROOT);
		Double reject = number(setting, "rejectScore");
		Double quarantine = number(setting, "quarantineScore");
		long max = Long.parseLong(get(setting, "maxSize", "2097152"));
		int timeout = Integer.parseInt(get(setting, "timeoutMillis", "5000"));
		Map<String, Map<String, String>> o = new LinkedHashMap<>();
		for (SpamProvider p : SpamProviders.all()) {
			Map<String, String> m = new LinkedHashMap<>();
			for (ConnectionSetting cs : p.getSettings()) {
				String v = setting.apply(p.getId() + "." + cs.key());
				if (v != null && !v.trim().isEmpty()) {
					m.put(cs.key(), v.trim());
				}
			}
			o.put(p.getId(), m);
		}
		SpamProvider chosen = SpamProviders.get(prov);
		if (chosen == null) {
			throw new IllegalArgumentException("spam.provider '" + prov + "' is not a spam provider (" + SpamProviders.ids() + ")");
		}
		List<String> problems = chosen.validate(o.get(chosen.getId()));
		if (!problems.isEmpty()) {
			throw new IllegalArgumentException("spam." + prov + ": " + String.join("; ", problems));
		}
		enabled = en;
		provider = prov;
		rejectScore = reject;
		quarantineScore = quarantine;
		maxSize = max;
		timeoutMillis = timeout;
		options = o;
		closeFilters();
	}

	private static String get(Function<String, String> q, String key, String def) {
		String v = q.apply(key);
		return v == null || v.trim().isEmpty() ? def : v.trim();
	}

	private static Double number(Function<String, String> q, String key) {
		String v = get(q, key, null);
		return v == null ? null : Double.valueOf(v);
	}

	/** {@code a.com:off,b.org:rspamd} as a map of lower case domain to "off" or a filter id. */
	public static Map<String, String> parseDomains(String text) {
		Map<String, String> ret = new LinkedHashMap<>();
		for (String entry : text.split(",")) {
			String e = entry.trim();
			if (e.isEmpty()) {
				continue;
			}
			int colon = e.lastIndexOf(':');
			if (colon <= 0 || colon == e.length() - 1) {
				throw new IllegalArgumentException("spam.domains entry '" + e + "' isn't domain:filter");
			}
			ret.put(e.substring(0, colon).trim().toLowerCase(Locale.ROOT), e.substring(colon + 1).trim().toLowerCase(Locale.ROOT));
		}
		return ret;
	}

	/** Called with a message (and the exception, if any) when a filter fails; default: nothing. */
	public void setLog(BiConsumer<String, Throwable> log) {
		this.log = log;
	}

	private void closeFilters() {
		List<SpamFilter> old = new ArrayList<>(filters.values());
		filters.clear();
		for (SpamFilter f : old) {
			try {
				f.close();
			} catch (RuntimeException e) {
				// ignore
			}
		}
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/** The id of the filter used where a domain has no override. */
	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider.trim().toLowerCase(Locale.ROOT);
	}

	/** Messages at or above this score are refused (null: not used). */
	public void setRejectScore(Double score) {
		this.rejectScore = score;
	}

	/** Messages at or above this score go to Junk (null: not used). */
	public void setQuarantineScore(Double score) {
		this.quarantineScore = score;
	}

	public void setMaxSize(long maxSize) {
		this.maxSize = maxSize;
	}

	/** The settings of a filter, as {@link SpamProvider#create} gets them (without the timeout). */
	public void setOptions(String id, Map<String, String> settings) {
		Map<String, Map<String, String>> o = new LinkedHashMap<>(options);
		o.put(id, new LinkedHashMap<>(settings));
		options = o;
		closeFilters();
	}

	// ------------------------------------------------------------------ the check

	/**
	 * The provider id that applies to mail for a domain, or {@value NullSpamFilter#ID}.
	 *
	 * @param domains the overrides ({@link #parseDomains})
	 */
	public String providerFor(String domain, Map<String, String> domains) {
		String o = domains.get(domain.toLowerCase(Locale.ROOT));
		if (o != null) {
			return o.equals(OFF) ? NullSpamFilter.ID : o;
		}
		return enabled ? provider : NullSpamFilter.ID;
	}

	/** True if any mail can be checked: spam checking is on, or some domain turns a filter on. */
	public boolean isActive(Map<String, String> domains) {
		if (enabled && !NullSpamFilter.ID.equals(provider)) {
			return true;
		}
		for (String o : domains.values()) {
			if (!o.equals(OFF) && !o.equals(NullSpamFilter.ID)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check a message. Never throws: a filter that fails counts as accepting the message.
	 *
	 * @param domains the queue's overrides by recipient domain ({@link #parseDomains})
	 * @return what to do with it (never null)
	 */
	public Outcome check(SpamRequest request, Map<String, String> domains) {
		Map<String, List<String>> groups = new LinkedHashMap<>();
		boolean unchecked = false;
		for (String rcpt : request.getRecipients()) {
			String id = providerFor(rcpt.substring(rcpt.lastIndexOf('@') + 1), domains);
			if (id.equals(NullSpamFilter.ID)) {
				unchecked = true;
			} else {
				groups.computeIfAbsent(id, k -> new ArrayList<>()).add(rcpt);
			}
		}
		if (groups.isEmpty()) {
			return Outcome.NONE;
		}
		if (request.getSize() > maxSize) {
			return Outcome.NONE;
		}
		Action combined = unchecked ? Action.ACCEPT : null;
		SpamVerdict top = null;
		String topId = null;
		for (Map.Entry<String, List<String>> g : groups.entrySet()) {
			SpamVerdict v;
			try {
				v = filter(g.getKey()).check(g.getValue().size() == request.getRecipients().size() ? request
						: request.forRecipients(g.getValue()));
			} catch (IOException | RuntimeException e) {
				log.accept("Spam filter " + g.getKey() + " failed for " + request.getQueueId() + "; accepting the message unscored: " + e, e);
				combined = Action.ACCEPT;
				continue;
			}
			Action a = decide(v);
			if (combined == null || a.ordinal() < combined.ordinal()) {
				combined = a;
			}
			if (top == null || v.getScore() > top.getScore()) {
				top = v;
				topId = g.getKey();
			}
		}
		if (top == null) {
			return Outcome.NONE;
		}
		String text = null;
		if (combined == Action.REJECT) {
			text = "Message rejected as spam";
		} else if (combined == Action.DEFER) {
			text = "Message temporarily deferred, try again later";
		}
		return new Outcome(combined, headers(top, topId, top.isSpam() || decide(top) != Action.ACCEPT), text, top.getScore(), topId);
	}

	/** What to do about a verdict: the thresholds if any are set, else the filter's action, else Junk for spam. */
	Action decide(SpamVerdict v) {
		Double reject = rejectScore;
		Double quarantine = quarantineScore;
		if (reject != null || quarantine != null) {
			if (reject != null && v.getScore() >= reject) {
				return Action.REJECT;
			}
			if (quarantine != null && v.getScore() >= quarantine) {
				return Action.QUARANTINE;
			}
			return Action.ACCEPT;
		}
		if (v.getAction() != null) {
			return v.getAction();
		}
		return v.isSpam() ? Action.QUARANTINE : Action.ACCEPT;
	}

	/** The filter of the provider with the id, made on first use (to learn, or ask its status). */
	public SpamFilter getFilter(String id) throws IOException {
		return filter(id);
	}

	private SpamFilter filter(String id) throws IOException {
		SpamFilter f = filters.get(id);
		if (f != null) {
			return f;
		}
		SpamProvider factory = SpamProviders.get(id);
		if (factory == null) {
			throw new IOException("Unknown spam provider '" + id + "'");
		}
		Map<String, String> settings = new LinkedHashMap<>(options.getOrDefault(id, Collections.emptyMap()));
		settings.put(SpamProvider.TIMEOUT_MILLIS, String.valueOf(timeoutMillis));
		f = factory.create(settings);
		SpamFilter prior = filters.putIfAbsent(id, f);
		if (prior != null) {
			f.close();
			return prior;
		}
		return f;
	}

	/** The X-Spam-* fields for a message; those the sender put in are dropped by the caller. */
	private static String headers(SpamVerdict v, String id, boolean flag) {
		StringBuilder sb = new StringBuilder();
		sb.append("X-Spam-Flag: ").append(flag ? "YES" : "NO").append("\r\n");
		sb.append("X-Spam-Score: ").append(num(v.getScore())).append("\r\n");
		sb.append("X-Spam-Status: ").append(flag ? "Yes" : "No").append(", score=").append(num(v.getScore()));
		if (v.getRequiredScore() > 0) {
			sb.append(" required=").append(num(v.getRequiredScore()));
		}
		StringBuilder tests = new StringBuilder();
		for (String s : v.getSymbols()) {
			if (s.matches("[A-Za-z0-9_.\\-]{1,64}") && tests.length() < 400) {
				tests.append(tests.length() == 0 ? "" : ",").append(s);
			}
		}
		if (tests.length() > 0) {
			sb.append(" tests=").append(tests);
		}
		sb.append("\r\n");
		sb.append("X-Spam-Checker: ").append(id).append("\r\n");
		return sb.toString();
	}

	private static String num(double d) {
		return String.format(Locale.ROOT, "%.2f", d);
	}

	/** True for a header field the server writes, which a sender's own copy must not stand in for. */
	public static boolean isSpamHeader(String fieldName) {
		return fieldName.equalsIgnoreCase("X-Spam-Flag") || fieldName.equalsIgnoreCase("X-Spam-Score")
				|| fieldName.equalsIgnoreCase("X-Spam-Status") || fieldName.equalsIgnoreCase("X-Spam-Checker");
	}
}
