package us.bringardner.parley.smtp.spam;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import us.bringardner.parley.files.ConnectionSetting;

/**
 * Rspamd (rspamd.com) over its HTTP API: the message is posted to {@code <url>/checkv2} with the
 * session in the request headers (IP, Helo, From, Rcpt, User, Queue-Id), and the JSON answer gives
 * the score, the required score, rspamd's action and the rules that matched.
 * <p>
 * Rspamd's actions map to ours: "reject" to REJECT, "soft reject" and "greylist" to DEFER,
 * "add header" and "rewrite subject" to QUARANTINE (Junk), "no action" to ACCEPT.
 */
public final class RspamdSpamFilter implements SpamFilter {

	public static final String ID = "rspamd";
	static final String DEFAULT_URL = "http://127.0.0.1:11333";
	static final String DEFAULT_CONTROLLER_URL = "http://127.0.0.1:11334";
	private static final int MAX_ANSWER = 1024 * 1024;

	/** The provider of this filter, listed in META-INF/services. */
	public static final class Provider implements SpamProvider {
		@Override
		public String getId() {
			return ID;
		}

		@Override
		public String getTitle() {
			return "Rspamd";
		}

		@Override
		public String getDescription() {
			return "rspamd.com: a fast scanner with its own rules, reputation and learning. Install the rspamd package on a machine the "
					+ "mail server can reach; it answers over HTTP, by default on 127.0.0.1:11333.";
		}

		@Override
		public Set<Feature> getFeatures() {
			return EnumSet.of(Feature.CHECK, Feature.LEARN, Feature.STATUS);
		}

		@Override
		public List<ConnectionSetting> getSettings() {
			return Arrays.asList(
					ConnectionSetting.text("url", "Rspamd URL").withDefault(DEFAULT_URL)
							.withDescription("The base URL of rspamd's normal worker (the controller port 11334 is not it)."),
					ConnectionSetting.secret("password", "Rspamd password")
							.withDescription("The password header rspamd expects from the normal worker, if it requires one (usually none)."),
					ConnectionSetting.text("controllerUrl", "Controller URL").withDefault(DEFAULT_CONTROLLER_URL).asAdvanced()
							.withDescription("Rspamd's controller, which learns spam and ham."),
					ConnectionSetting.secret("controllerPassword", "Controller password").asAdvanced()
							.withDescription("The controller's (enable) password, needed to learn."));
		}

		@Override
		public List<String> validate(Map<String, String> settings) {
			List<String> ret = new ArrayList<>(SpamProvider.super.validate(settings));
			for (String k : new String[] { "url", "controllerUrl" }) {
				String v = settings.get(k);
				if (v != null && !v.trim().isEmpty() && !v.trim().startsWith("http://") && !v.trim().startsWith("https://")) {
					ret.add("The rspamd " + (k.equals("url") ? "URL" : "controller URL") + " must start with http:// or https://: " + v);
				}
			}
			return ret;
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			List<String> problems = validate(settings);
			if (!problems.isEmpty()) {
				throw new IllegalArgumentException(String.join("; ", problems));
			}
			int timeout = Integer.parseInt(settings.getOrDefault(TIMEOUT_MILLIS, "5000").trim());
			return new RspamdSpamFilter(base(settings.get("url"), DEFAULT_URL), settings.get("password"),
					base(settings.get("controllerUrl"), DEFAULT_CONTROLLER_URL), settings.get("controllerPassword"), timeout);
		}

		private static String base(String v, String def) {
			String url = v == null || v.trim().isEmpty() ? def : v.trim();
			while (url.endsWith("/")) {
				url = url.substring(0, url.length() - 1);
			}
			return url;
		}
	}

	private final String url;
	private final String password;
	private final String controllerUrl;
	private final String controllerPassword;
	private final int timeout;

	RspamdSpamFilter(String url, String password, String controllerUrl, String controllerPassword, int timeoutMillis) {
		this.url = url;
		this.password = password == null || password.isEmpty() ? null : password;
		this.controllerUrl = controllerUrl;
		this.controllerPassword = controllerPassword == null || controllerPassword.isEmpty() ? null : controllerPassword;
		this.timeout = timeoutMillis;
	}

	@Override
	public String id() {
		return ID;
	}

	@Override
	public SpamVerdict check(SpamRequest r) throws IOException {
		HttpURLConnection c = (HttpURLConnection) new URL(url + "/checkv2").openConnection();
		try {
			c.setConnectTimeout(timeout);
			c.setReadTimeout(timeout);
			c.setRequestMethod("POST");
			c.setDoOutput(true);
			c.setFixedLengthStreamingMode(r.getSize());
			if (r.getClientAddress() != null) {
				c.setRequestProperty("IP", r.getClientAddress().getHostAddress());
			}
			header(c, "Helo", r.getHelo());
			c.setRequestProperty("From", r.getSender());
			for (String rcpt : r.getRecipients()) {
				c.addRequestProperty("Rcpt", header(rcpt));
			}
			header(c, "User", r.getUser());
			header(c, "Queue-Id", r.getQueueId());
			header(c, "Hostname", r.getHostname());
			header(c, "Password", password);
			try (InputStream in = r.openMessage(); OutputStream out = c.getOutputStream()) {
				byte[] buf = new byte[8192];
				int n;
				while ((n = in.read(buf)) > 0) {
					out.write(buf, 0, n);
				}
			}
			int code = c.getResponseCode();
			if (code != 200) {
				throw new IOException("rspamd answered " + code + " " + c.getResponseMessage());
			}
			return parse(read(c.getInputStream()));
		} finally {
			c.disconnect();
		}
	}

	@Override
	public void learn(SpamRequest r, boolean spam) throws IOException {
		HttpURLConnection c = (HttpURLConnection) new URL(controllerUrl + (spam ? "/learnspam" : "/learnham")).openConnection();
		try {
			c.setConnectTimeout(timeout);
			c.setReadTimeout(timeout);
			c.setRequestMethod("POST");
			c.setDoOutput(true);
			c.setFixedLengthStreamingMode(r.getSize());
			header(c, "Password", controllerPassword);
			try (InputStream in = r.openMessage(); OutputStream out = c.getOutputStream()) {
				in.transferTo(out);
			}
			int code = c.getResponseCode();
			if (code != 200) {
				throw new IOException("rspamd's controller answered " + code + " " + c.getResponseMessage());
			}
		} finally {
			c.disconnect();
		}
	}

	@Override
	public SpamStatus status() {
		HttpURLConnection c = null;
		try {
			c = (HttpURLConnection) new URL(url + "/ping").openConnection();
			c.setConnectTimeout(timeout);
			c.setReadTimeout(timeout);
			int code = c.getResponseCode();
			if (code != 200) {
				return SpamStatus.down("rspamd answered " + code + " " + c.getResponseMessage() + " at " + url);
			}
			String server = c.getHeaderField("Server");
			String version = server != null && server.toLowerCase(Locale.ROOT).startsWith("rspamd/") ? server.substring(7) : "";
			return SpamStatus.up(version, "rspamd answers at " + url);
		} catch (IOException e) {
			return SpamStatus.down("Can't reach rspamd at " + url + ": " + e.getMessage());
		} finally {
			if (c != null) {
				c.disconnect();
			}
		}
	}

	private static void header(HttpURLConnection c, String name, String value) {
		if (value != null && !value.isEmpty()) {
			c.setRequestProperty(name, header(value));
		}
	}

	/** A value that is safe in a header line. */
	private static String header(String v) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < v.length(); i++) {
			char ch = v.charAt(i);
			sb.append(ch < 32 || ch > 126 ? '?' : ch);
		}
		return sb.toString();
	}

	private static String read(InputStream in) throws IOException {
		try (InputStream i = in) {
			java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int n;
			while ((n = i.read(buf)) > 0) {
				b.write(buf, 0, n);
				if (b.size() > MAX_ANSWER) {
					throw new IOException("rspamd's answer is too long");
				}
			}
			return new String(b.toByteArray(), StandardCharsets.UTF_8);
		}
	}

	/** The verdict in rspamd's JSON answer. */
	@SuppressWarnings("unchecked")
	static SpamVerdict parse(String json) throws IOException {
		Object o = Json.parse(json);
		if (!(o instanceof Map)) {
			throw new IOException("rspamd's answer isn't a JSON object");
		}
		Map<String, Object> m = (Map<String, Object>) o;
		if (!(m.get("score") instanceof Double)) {
			throw new IOException("rspamd's answer has no score");
		}
		double score = (Double) m.get("score");
		double required = m.get("required_score") instanceof Double ? (Double) m.get("required_score") : 0;
		String action = String.valueOf(m.get("action")).toLowerCase(Locale.ROOT);
		SpamVerdict.Action a;
		switch (action) {
		case "reject":
			a = SpamVerdict.Action.REJECT;
			break;
		case "soft reject":
		case "greylist":
			a = SpamVerdict.Action.DEFER;
			break;
		case "add header":
		case "rewrite subject":
			a = SpamVerdict.Action.QUARANTINE;
			break;
		case "no action":
			a = SpamVerdict.Action.ACCEPT;
			break;
		default:
			throw new IOException("rspamd gave the unknown action '" + action + "'");
		}
		List<String> symbols = new ArrayList<>();
		if (m.get("symbols") instanceof Map) {
			symbols.addAll(((Map<String, Object>) m.get("symbols")).keySet());
		}
		return new SpamVerdict(score, required, a != SpamVerdict.Action.ACCEPT, a, symbols);
	}
}
