package us.bringardner.parley.smtp.queue;

import us.bringardner.parley.io.IoUtils;
import us.bringardner.parley.mail.Sasl;
import us.bringardner.parley.mail.SaslPrep;
import us.bringardner.parley.net.capability.CapabilitySet;
import us.bringardner.parley.net.sasl.ISaslClient;
import us.bringardner.parley.net.sasl.SaslClients;
import us.bringardner.parley.net.sasl.SaslEncoding;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import us.bringardner.parley.core.util.TlsSockets;
import us.bringardner.parley.core.util.TrustAllCertificates;
import us.bringardner.parley.smtp.SmtpInput;
import us.bringardner.parley.smtp.SmtpStreams;

/**
 * The client side of SMTP, used by the queue to hand mail to other servers:
 * EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA or BDAT, QUIT.
 */
public class SmtpClient implements Closeable {

	private static final Pattern ENHANCED = Pattern.compile("^([245]\\.\\d{1,3}\\.\\d{1,3})\\b");

	/** A server reply: code and text lines. */
	public static final class Reply {
		public final int code;
		public final List<String> lines;

		Reply(int code, List<String> lines) {
			this.code = code;
			this.lines = lines;
		}

		public boolean isPositive() {
			return code >= 200 && code < 400;
		}

		public boolean isTransient() {
			return code >= 400 && code < 500;
		}

		/** The enhanced status code of the reply (RFC 2034), or null. */
		public String enhanced() {
			Matcher m = ENHANCED.matcher(lines.isEmpty() ? "" : lines.get(0));
			return m.find() ? m.group(1) : null;
		}

		/** "550 5.1.1 text" (multi-line replies joined). */
		@Override
		public String toString() {
			return code + " " + String.join(" ", lines);
		}
	}

	private final String host;
	private final int readTimeout;
	private Socket socket;
	private SmtpInput in;
	private OutputStream out;
	private boolean tls;
	private final Map<String, String> extensions = new LinkedHashMap<>();
	private CapabilitySet capabilities = new CapabilitySet();
	private boolean esmtp;

	public SmtpClient(String host, int port, int connectTimeout, int readTimeout) throws IOException {
		this(host, null, port, connectTimeout, readTimeout);
	}

	/**
	 * Connect to {@code address} (or, if null, to {@code host} looked up by the
	 * JDK); {@code host} is still the name used for TLS.
	 */
	public SmtpClient(String host, java.net.InetAddress address, int port, int connectTimeout, int readTimeout)
			throws IOException {
		this.host = host;
		this.readTimeout = readTimeout;
		socket = new Socket();
		socket.connect(address != null ? new InetSocketAddress(address, port) : new InetSocketAddress(host, port),
				connectTimeout);
		socket.setSoTimeout(readTimeout);
		streams();
	}

	private void streams() throws IOException {
		in = new SmtpInput(socket.getInputStream());
		out = IoUtils.buffered(socket.getOutputStream());
	}

	public String getHost() {
		return host;
	}

	public boolean isTls() {
		return tls;
	}

	/** Extensions from the last EHLO, by upper-case keyword, with their parameters. */
	public Map<String, String> getExtensions() {
		return extensions;
	}

	/**
	 * The extensions from the last EHLO with their parameters, as a {@link CapabilitySet}:
	 * {@code getCapabilities().has("AUTH", "PLAIN")}.
	 */
	public CapabilitySet getCapabilities() {
		return capabilities;
	}

	public boolean supports(String extension) {
		return extensions.containsKey(extension.toUpperCase(Locale.ROOT));
	}

	/** Read one reply (all its lines). */
	public Reply readReply() throws IOException {
		List<String> lines = new ArrayList<>();
		int code = -1;
		while (true) {
			byte[] b = in.readLine(64 * 1024);
			if (b == null) {
				throw new IOException("Connection closed by " + host);
			}
			String line = new String(b, StandardCharsets.UTF_8);
			if (line.length() < 3) {
				throw new IOException("Invalid reply from " + host + ": " + line);
			}
			int c;
			try {
				c = Integer.parseInt(line.substring(0, 3));
			} catch (NumberFormatException e) {
				throw new IOException("Invalid reply from " + host + ": " + line);
			}
			if (code >= 0 && c != code) {
				throw new IOException("Inconsistent multi-line reply from " + host);
			}
			code = c;
			lines.add(line.length() > 4 ? line.substring(4) : "");
			if (line.length() == 3 || line.charAt(3) == ' ') {
				return new Reply(code, lines);
			}
		}
	}

	public void send(String command) throws IOException {
		out.write((command + "\r\n").getBytes(StandardCharsets.UTF_8));
		out.flush();
	}

	public Reply command(String command) throws IOException {
		send(command);
		return readReply();
	}

	/** EHLO, falling back to HELO; records the extensions. */
	public Reply hello(String name) throws IOException {
		Reply r = command("EHLO " + name);
		extensions.clear();
		capabilities = new CapabilitySet();
		if (r.code == 250) {
			esmtp = true;
			// the first line greets; the others are extensions
			capabilities = CapabilitySet.parseLines(r.lines.subList(1, r.lines.size()));
			for (int i = 1; i < r.lines.size(); i++) {
				String l = r.lines.get(i).trim();
				int sp = l.indexOf(' ');
				extensions.put((sp < 0 ? l : l.substring(0, sp)).toUpperCase(Locale.ROOT), sp < 0 ? "" : l.substring(sp + 1));
			}
			return r;
		}
		esmtp = false;
		return command("HELO " + name);
	}

	public boolean isEsmtp() {
		return esmtp;
	}

	/**
	 * STARTTLS (RFC 3207). With {@code verify}, the server's certificate must be
	 * valid for the host; otherwise any certificate is accepted (opportunistic TLS).
	 */
	public Reply startTls(boolean verify) throws IOException {
		Reply r = command("STARTTLS");
		if (r.code != 220) {
			return r;
		}
		try {
			//  Opportunistic TLS (verify false) accepts any certificate, see TrustAllCertificates
			SSLContext ctx = verify ? SSLContext.getDefault() : TrustAllCertificates.sslContext("TLS");
			//  SNI for a host name (not an address) and, with verify, the host name check
			SSLSocket ssl = TlsSockets.layer(ctx, socket, host, true, verify, true);
			ssl.setSoTimeout(readTimeout);
			ssl.startHandshake();
			socket = ssl;
			tls = true;
			streams();
		} catch (IOException e) {
			throw e;
		} catch (Exception e) {
			throw new IOException("TLS failed with " + host + ": " + e.getMessage(), e);
		}
		return r;
	}

	/** AUTH PLAIN (RFC 4954, RFC 4616). */
	public Reply authPlain(String user, String password) throws IOException {
		return command("AUTH PLAIN " + Sasl.encodePlain(user, password));
	}

	/** Most challenges answered before giving up on a server that never finishes. */
	private static final int MAX_AUTH_ROUNDS = 8;

	/**
	 * AUTH with a SASL mechanism (RFC 4954): the initial response goes with the command, and each
	 * 334 reply is a challenge for the mechanism. Returns the final reply (235 on success).
	 * <p>
	 * A mechanism that checks the server (SCRAM) must be complete when the server says 235;
	 * if it isn't, the server accepted the login without proving it knows the password, and an
	 * IOException is thrown.
	 */
	public Reply authenticate(ISaslClient sasl) throws IOException {
		String cmd = "AUTH " + sasl.getName();
		if (sasl.hasInitialResponse()) {
			byte[] ir = sasl.initialResponse();
			cmd += " " + (ir.length == 0 ? "=" : SaslEncoding.encode(ir));
		}
		Reply r = command(cmd);
		for (int round = 0; r.code == 334; round++) {
			IOException failure = null;
			byte[] response = null;
			if (round >= MAX_AUTH_ROUNDS) {
				failure = new IOException(host + " sent too many AUTH challenges");
			} else {
				try {
					response = sasl.evaluateChallenge(SaslEncoding.decode(r.lines.isEmpty() ? "" : r.lines.get(0)));
				} catch (IllegalArgumentException e) {
					failure = new IOException("Invalid AUTH challenge from " + host);
				} catch (IOException e) {
					failure = e;
				}
			}
			if (failure != null) {
				command("*"); // cancel; the server answers 501
				throw failure;
			}
			r = command(SaslEncoding.encode(response));
		}
		if (r.code == 235 && !sasl.isComplete()) {
			throw new IOException(host + " accepted the login without completing " + sasl.getName());
		}
		return r;
	}

	/**
	 * The mechanism to log in with: the first of {@code preferred} that the server offered in
	 * its AUTH extension and that {@link SaslClients} can make. User name and password are
	 * prepared with SASLprep (RFC 4013), which servers apply to what they store; text that can't
	 * be prepared isn't used.
	 *
	 * @return a client for {@link #authenticate(ISaslClient)}, or null if there is no match
	 */
	public ISaslClient chooseSasl(String user, String password, List<String> preferred) {
		String u = SaslPrep.prepare(user, false);
		String p = SaslPrep.prepare(password, false);
		if (u == null || p == null) {
			return null;
		}
		return SaslClients.choose(capabilities.getParams("AUTH"), preferred, u, p);
	}

	/** DATA content (dot-stuffed, ending with "."); returns the final reply. */
	public Reply data(InputStream content) throws IOException {
		Reply r = command("DATA");
		if (r.code != 354) {
			return r;
		}
		SmtpStreams.DotStuffingOutputStream dot = new SmtpStreams.DotStuffingOutputStream(out);
		content.transferTo(dot);
		dot.finish();
		return readReply();
	}

	/** BDAT n LAST with the whole content (CHUNKING, RFC 3030). */
	public Reply bdat(InputStream content, long size) throws IOException {
		out.write(("BDAT " + size + " LAST\r\n").getBytes(StandardCharsets.US_ASCII));
		byte[] buf = new byte[64 * 1024];
		long left = size;
		while (left > 0) {
			int n = content.read(buf, 0, (int) Math.min(buf.length, left));
			if (n < 0) {
				throw new IOException("The content is shorter than its size");
			}
			out.write(buf, 0, n);
			left -= n;
		}
		out.flush();
		return readReply();
	}

	/** QUIT, ignoring errors. */
	public void quit() {
		try {
			command("QUIT");
		} catch (IOException e) {
			// closing anyway
		}
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}
}
