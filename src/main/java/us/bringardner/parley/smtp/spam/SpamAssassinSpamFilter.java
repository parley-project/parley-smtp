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
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

	public static final class Factory implements SpamFilterFactory {
		@Override
		public String id() {
			return ID;
		}

		@Override
		public String label() {
			return "SpamAssassin (spamd)";
		}

		@Override
		public List<SpamOption> options() {
			return Arrays.asList(
					new SpamOption("host", "spamd host", SpamOption.Type.TEXT, "127.0.0.1", "Where spamd listens."),
					new SpamOption("port", "spamd port", SpamOption.Type.NUMBER, "783", "spamd's TCP port."),
					new SpamOption("user", "spamd user", SpamOption.Type.TEXT, null,
							"The user spamd applies the preferences of (blank: spamd's default)."));
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			int port = Integer.parseInt(settings.getOrDefault("port", "783").trim());
			int timeout = Integer.parseInt(settings.getOrDefault("timeoutMillis", "5000").trim());
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
