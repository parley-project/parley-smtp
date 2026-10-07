package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/**
 * AUTH mechanism [initial-response] (RFC 4954) with PLAIN (RFC 4616) and LOGIN.
 * "*" cancels; "=" is an empty initial response.
 */
public class Auth extends BaseCommand {

	private static final long serialVersionUID = 1L;

	private static final String USERNAME = Base64.getEncoder().encodeToString("Username:".getBytes(StandardCharsets.US_ASCII));
	private static final String PASSWORD = Base64.getEncoder().encodeToString("Password:".getBytes(StandardCharsets.US_ASCII));

	public Auth() {
		super("AUTH");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!p.isEsmtp()) {
			p.error(BAD_SEQUENCE, "5.5.1", "Send EHLO first");
			return;
		}
		if (p.isAuthenticated()) {
			p.error(BAD_SEQUENCE, "5.5.1", "Already authenticated");
			return;
		}
		if (p.getTransaction() != null) {
			p.error(BAD_SEQUENCE, "5.5.1", "AUTH not allowed during a mail transaction");
			return;
		}
		if (p.getSmtpServer().isRequireTls() && !p.isTls()) {
			p.error(ENCRYPTION_REQUIRED, "5.7.11", "Encryption required for requested authentication mechanism");
			return;
		}
		String[] a = args.trim().split(" +");
		String mechanism = a[0].toUpperCase(Locale.ROOT);
		String initial = a.length > 1 ? a[1] : null;
		if (mechanism.equals("PLAIN")) {
			String response = initial != null ? initial : challenge(p, "");
			if (response == null) {
				return;
			}
			byte[] decoded = decode(p, response);
			if (decoded == null) {
				return;
			}
			String[] parts = new String(decoded, StandardCharsets.UTF_8).split("\u0000", -1);
			if (parts.length != 3 || (!parts[0].isEmpty() && !parts[0].equals(parts[1]))) {
				p.authFailed();
				return;
			}
			result(p, parts[1], parts[2]);
		} else if (mechanism.equals("LOGIN")) {
			String user = initial != null ? initial : challenge(p, USERNAME);
			if (user == null) {
				return;
			}
			byte[] u = decode(p, user);
			if (u == null) {
				return;
			}
			String pass = challenge(p, PASSWORD);
			if (pass == null) {
				return;
			}
			byte[] pw = decode(p, pass);
			if (pw == null) {
				return;
			}
			result(p, new String(u, StandardCharsets.UTF_8), new String(pw, StandardCharsets.UTF_8));
		} else {
			p.error(PARAMETER_NOT_IMPLEMENTED, "5.5.4", "Unrecognized authentication type");
		}
	}

	/** Send "334 challenge" and read the response; null if cancelled or the connection closed. */
	private static String challenge(SmtpRequestProcessor p, String challenge) throws IOException {
		p.reply(AUTH_CONTINUE + " " + challenge);
		String r = p.readLine();
		if (r == null) {
			p.close();
			return null;
		}
		r = r.trim();
		if (r.equals("*")) {
			p.error(PARAMETER_ERROR, "5.0.0", "Authentication cancelled");
			return null;
		}
		return r;
	}

	private static byte[] decode(SmtpRequestProcessor p, String b64) throws IOException {
		if (b64.equals("=")) {
			return new byte[0];
		}
		try {
			return Base64.getDecoder().decode(b64);
		} catch (IllegalArgumentException e) {
			p.error(PARAMETER_ERROR, "5.5.2", "Invalid base64 data");
			return null;
		}
	}

	private static void result(SmtpRequestProcessor p, String user, String password) throws IOException {
		if (p.login(user, password)) {
			p.reply(AUTH_SUCCEEDED, "2.7.0", "Authentication successful");
		} else {
			p.authFailed();
		}
	}
}
