package us.bringardner.parley.smtp.spam;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
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
 * Apache SpamAssassin through {@code spamd} (the SPAMC/SPAMD protocol on TCP, default port 783):
 * the SYMBOLS command sends the message and returns "Spam: True ; 7.5 / 5.0" (spam or not, the
 * score and the threshold) and the names of the rules that matched.
 * <p>
 * spamd has no opinion about what to do, so the verdict has no action: the server's thresholds
 * (or its default, Junk for spam) decide.
 */
public final class SpamAssassinSpamFilter implements SpamFilter {

	public static final String ID = "spamassassin";
	private static final int MAX_ANSWER = 1024 * 1024;

	/** The provider of this filter, listed in META-INF/services. */
	public static final class Provider implements SpamProvider {
		@Override
		public String getId() {
			return ID;
		}

		@Override
		public String getTitle() {
			return "SpamAssassin (spamd)";
		}

		@Override
		public String getDescription() {
			return "Apache SpamAssassin through its spamd daemon (SPAMC protocol, TCP port 783). spamd has no login, so let it listen on "
					+ "localhost only. Learning needs spamd started with --allow-tell.";
		}

		@Override
		public Set<Feature> getFeatures() {
			return EnumSet.of(Feature.CHECK, Feature.LEARN, Feature.STATUS);
		}

		@Override
		public List<ConnectionSetting> getSettings() {
			return Arrays.asList(
					ConnectionSetting.text("host", "spamd host").withDefault("127.0.0.1").withDescription("Where spamd listens."),
					ConnectionSetting.integer("port", "spamd port", 1L, 65535L).withDefault("783").withDescription("spamd's TCP port."),
					ConnectionSetting.text("user", "spamd user").asAdvanced()
							.withDescription("The user spamd applies the preferences of (blank: spamd's default)."));
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			List<String> problems = validate(settings);
			if (!problems.isEmpty()) {
				throw new IllegalArgumentException(String.join("; ", problems));
			}
			int port = Integer.parseInt(settings.getOrDefault("port", "783").trim());
			int timeout = Integer.parseInt(settings.getOrDefault(TIMEOUT_MILLIS, "5000").trim());
			return new SpamAssassinSpamFilter(settings.getOrDefault("host", "127.0.0.1").trim(), port,
					settings.get("user"), timeout);
		}
	}

	private final String host;
	private final int port;
	private final String user;
	private final int timeout;

	SpamAssassinSpamFilter(String host, int port, String user, int timeoutMillis) {
		this.host = host;
		this.port = port;
		this.user = user == null || user.trim().isEmpty() ? null : user.trim();
		this.timeout = timeoutMillis;
	}

	@Override
	public String id() {
		return ID;
	}

	@Override
	public SpamVerdict check(SpamRequest r) throws IOException {
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress(host, port), timeout);
			s.setSoTimeout(timeout);
			OutputStream out = s.getOutputStream();
			StringBuilder head = new StringBuilder("SYMBOLS SPAMC/1.5\r\nContent-length: ").append(r.getSize()).append("\r\n");
			if (user != null) {
				head.append("User: ").append(user.replaceAll("[\\r\\n]", "")).append("\r\n");
			}
			head.append("\r\n");
			out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
			try (InputStream in = r.openMessage()) {
				byte[] buf = new byte[8192];
				int n;
				while ((n = in.read(buf)) > 0) {
					out.write(buf, 0, n);
				}
			}
			out.flush();
			s.shutdownOutput();
			ByteArrayOutputStream all = new ByteArrayOutputStream();
			try (InputStream in = new BufferedInputStream(s.getInputStream())) {
				byte[] buf = new byte[8192];
				int n;
				while ((n = in.read(buf)) > 0) {
					all.write(buf, 0, n);
					if (all.size() > MAX_ANSWER) {
						throw new IOException("spamd's answer is too long");
					}
				}
			}
			return parse(new String(all.toByteArray(), StandardCharsets.UTF_8));
		}
	}

	@Override
	public void learn(SpamRequest r, boolean spam) throws IOException {
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress(host, port), timeout);
			s.setSoTimeout(timeout);
			OutputStream out = s.getOutputStream();
			StringBuilder head = new StringBuilder("TELL SPAMC/1.5\r\nContent-length: ").append(r.getSize())
					.append("\r\nMessage-class: ").append(spam ? "spam" : "ham").append("\r\nSet: local\r\n");
			if (user != null) {
				head.append("User: ").append(user.replaceAll("[\\r\\n]", "")).append("\r\n");
			}
			head.append("\r\n");
			out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
			try (InputStream in = r.openMessage()) {
				in.transferTo(out);
			}
			out.flush();
			s.shutdownOutput();
			String first = new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine();
			if (first == null || !first.startsWith("SPAMD/") || !first.split(" ", 3)[1].equals("0")) {
				throw new IOException("spamd refused to learn: " + first);
			}
		}
	}

	@Override
	public SpamStatus status() {
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress(host, port), timeout);
			s.setSoTimeout(timeout);
			s.getOutputStream().write("PING SPAMC/1.5\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			s.getOutputStream().flush();
			s.shutdownOutput();
			String first = new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine();
			if (first != null && first.startsWith("SPAMD/") && first.toUpperCase(Locale.ROOT).contains("PONG")) {
				return SpamStatus.up(first.split(" ", 2)[0].substring(6), "spamd answers at " + host + ":" + port);
			}
			return SpamStatus.down("Not a spamd answer at " + host + ":" + port + ": " + first);
		} catch (IOException e) {
			return SpamStatus.down("Can't reach spamd at " + host + ":" + port + ": " + e.getMessage());
		}
	}

	/** The verdict in spamd's answer to SYMBOLS. */
	static SpamVerdict parse(String answer) throws IOException {
		String[] lines = answer.split("\r?\n", -1);
		if (lines.length == 0 || !lines[0].startsWith("SPAMD/")) {
			throw new IOException("Not a spamd answer: " + (lines.length == 0 ? "" : lines[0]));
		}
		String[] status = lines[0].split(" ", 3);
		if (status.length < 2 || !status[1].equals("0")) {
			throw new IOException("spamd answered " + lines[0]);
		}
		boolean spam = false;
		double score = 0;
		double threshold = 0;
		boolean found = false;
		int i = 1;
		for (; i < lines.length && !lines[i].isEmpty(); i++) {
			String l = lines[i];
			if (l.toLowerCase(Locale.ROOT).startsWith("spam:")) {
				// Spam: True ; 7.5 / 5.0
				String[] p = l.substring(5).split(";");
				if (p.length != 2) {
					throw new IOException("Unreadable spamd Spam header: " + l);
				}
				spam = p[0].trim().equalsIgnoreCase("true") || p[0].trim().equalsIgnoreCase("yes");
				String[] st = p[1].split("/");
				try {
					score = Double.parseDouble(st[0].trim());
					threshold = st.length > 1 ? Double.parseDouble(st[1].trim()) : 0;
				} catch (NumberFormatException e) {
					throw new IOException("Unreadable spamd Spam header: " + l);
				}
				found = true;
			}
		}
		if (!found) {
			throw new IOException("spamd's answer has no Spam header");
		}
		List<String> symbols = new ArrayList<>();
		StringBuilder body = new StringBuilder();
		for (i++; i < lines.length; i++) {
			body.append(lines[i]);
		}
		for (String sym : body.toString().split(",")) {
			if (!sym.trim().isEmpty()) {
				symbols.add(sym.trim());
			}
		}
		return new SpamVerdict(score, threshold, spam, null, symbols);
	}
}
