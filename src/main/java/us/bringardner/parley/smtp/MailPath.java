package us.bringardner.parley.smtp;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A reverse-path or forward-path with its ESMTP parameters, as in
 * {@code MAIL FROM:<user@example.com> SIZE=1000 BODY=8BITMIME}
 * (RFC 5321 section 4.1.2). A null reverse-path ({@code <>}) has no address.
 */
public final class MailPath {

	private final MailAddress address;
	private final Map<String, String> parameters;

	private MailPath(MailAddress address, Map<String, String> parameters) {
		this.address = address;
		this.parameters = parameters;
	}

	/** The address, or null for the null reverse-path {@code <>}. */
	public MailAddress getAddress() {
		return address;
	}

	/** Parameters by upper-case keyword; a parameter without a value maps to "". */
	public Map<String, String> getParameters() {
		return parameters;
	}

	/**
	 * Parse the argument of MAIL FROM: or RCPT TO:, starting at the path.
	 *
	 * @param allowNull accept {@code <>} (MAIL only)
	 * @param utf8      accept UTF-8 (SMTPUTF8 announced, or for RCPT, given with MAIL)
	 * @param lenient   accept a path without angle brackets (some old clients send that)
	 * @throws IllegalArgumentException if the syntax is invalid
	 */
	public static MailPath parse(String text, boolean allowNull, boolean utf8, boolean lenient) {
		String s = text.trim();
		String pathText;
		String rest;
		if (s.startsWith("<")) {
			int end = findClose(s);
			if (end < 0) {
				throw new IllegalArgumentException("Missing >");
			}
			pathText = s.substring(1, end);
			rest = s.substring(end + 1);
			if (!rest.isEmpty() && rest.charAt(0) != ' ') {
				throw new IllegalArgumentException("Expected a space after the path");
			}
		} else if (lenient) {
			int sp = s.indexOf(' ');
			pathText = sp < 0 ? s : s.substring(0, sp);
			rest = sp < 0 ? "" : s.substring(sp);
		} else {
			throw new IllegalArgumentException("The path must be in angle brackets");
		}
		// a source route (A-d-l) is ignored (RFC 5321 section 4.1.1.3)
		if (pathText.startsWith("@")) {
			int colon = pathText.indexOf(':');
			if (colon < 0) {
				throw new IllegalArgumentException("Invalid source route");
			}
			pathText = pathText.substring(colon + 1);
		}
		MailAddress address = null;
		if (pathText.isEmpty()) {
			if (!allowNull) {
				throw new IllegalArgumentException("A null path isn't allowed here");
			}
		} else {
			address = MailAddress.parse(pathText, utf8);
		}
		return new MailPath(address, parseParameters(rest, utf8));
	}

	private static int findClose(String s) {
		boolean quoted = false;
		for (int i = 1; i < s.length(); i++) {
			char c = s.charAt(i);
			if (quoted && c == '\\') {
				i++;
			} else if (c == '"') {
				quoted = !quoted;
			} else if (!quoted && c == '>') {
				return i;
			}
		}
		return -1;
	}

	/** Parse "KEY=value KEY2" (esmtp-param, RFC 5321 section 4.1.2). */
	public static Map<String, String> parseParameters(String text, boolean utf8) {
		Map<String, String> ret = new LinkedHashMap<>();
		for (String p : text.trim().split(" +")) {
			if (p.isEmpty()) {
				continue;
			}
			int eq = p.indexOf('=');
			String key = (eq < 0 ? p : p.substring(0, eq)).toUpperCase(Locale.ROOT);
			String value = eq < 0 ? "" : p.substring(eq + 1);
			if (!key.matches("[A-Z0-9][A-Z0-9-]*")) {
				throw new IllegalArgumentException("Invalid parameter keyword");
			}
			if (eq >= 0 && value.isEmpty()) {
				throw new IllegalArgumentException("Empty parameter value");
			}
			for (int i = 0; i < value.length(); i++) {
				char c = value.charAt(i);
				if (c == '=' || c < 33 || c == 127 || (c >= 0x80 && !utf8)) {
					throw new IllegalArgumentException("Invalid parameter value");
				}
			}
			if (ret.containsKey(key)) {
				throw new IllegalArgumentException("Duplicate parameter " + key);
			}
			ret.put(key, value);
		}
		return ret;
	}

	/** Decode an xtext value (RFC 3461 section 4): "+XX" is a hex-encoded octet. */
	public static String decodeXtext(String s) {
		java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '+') {
				if (i + 3 > s.length()) {
					throw new IllegalArgumentException("Invalid xtext");
				}
				try {
					bytes.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Invalid xtext");
				}
				i += 2;
			} else {
				byte[] b = String.valueOf(c).getBytes(java.nio.charset.StandardCharsets.UTF_8);
				bytes.write(b, 0, b.length);
			}
		}
		return new String(bytes.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
	}

	/** Encode as xtext: "+", "=" and characters outside 33..126 become "+XX". */
	public static String encodeXtext(String s) {
		StringBuilder sb = new StringBuilder();
		for (byte b : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
			int c = b & 0xff;
			if (c < 33 || c > 126 || c == '+' || c == '=') {
				sb.append('+').append(String.format("%02X", c));
			} else {
				sb.append((char) c);
			}
		}
		return sb.toString();
	}
}
