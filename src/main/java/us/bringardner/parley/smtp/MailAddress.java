package us.bringardner.parley.smtp;

import java.io.Serializable;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Locale;

/**
 * An SMTP mailbox (RFC 5321 section 4.1.2): local-part "@" domain, where the
 * domain may be an address literal such as {@code [192.0.2.1]}. With SMTPUTF8
 * (RFC 6531) both parts may contain UTF-8.
 * <p>
 * The local part is case-sensitive (only the receiving host may interpret it);
 * the domain is not.
 */
public final class MailAddress implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final String ATEXT_SPECIALS = "!#$%&'*+-/=?^_`{|}~";
	public static final int MAX_LOCAL_PART = 64;
	public static final int MAX_DOMAIN = 255;

	private final String localPart;
	private final String domain;

	public MailAddress(String localPart, String domain) {
		this.localPart = localPart;
		this.domain = domain;
	}

	public String getLocalPart() {
		return localPart;
	}

	public String getDomain() {
		return domain;
	}

	/** True if the domain is an address literal ({@code [192.0.2.1]}, {@code [IPv6:...]}). */
	public boolean isAddressLiteral() {
		return domain.startsWith("[");
	}

	/** True if the address has no characters outside ASCII. */
	public boolean isAscii() {
		return isAscii(localPart) && isAscii(domain);
	}

	/** True if only the local part needs SMTPUTF8 (a non-ASCII domain can be sent as A-labels). */
	public boolean needsSmtpUtf8() {
		return !isAscii(localPart);
	}

	/** The domain in lower case with IDN A-labels (for DNS and for comparison). */
	public String getAsciiDomain() {
		if (isAddressLiteral()) {
			return domain.toLowerCase(Locale.ROOT);
		}
		try {
			return IDN.toASCII(Normalizer.normalize(domain, Normalizer.Form.NFC), IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
		} catch (IllegalArgumentException e) {
			return domain.toLowerCase(Locale.ROOT);
		}
	}

	/** The address with an A-label domain (for servers without SMTPUTF8). */
	public MailAddress toAsciiDomain() {
		return new MailAddress(localPart, getAsciiDomain());
	}

	static boolean isAscii(String s) {
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) >= 0x80) {
				return false;
			}
		}
		return true;
	}

	/** local@domain, with the local part quoted if it isn't a dot-string. */
	@Override
	public String toString() {
		return (isDotString(localPart) ? localPart : quote(localPart)) + "@" + domain;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof MailAddress)) {
			return false;
		}
		MailAddress a = (MailAddress) o;
		return localPart.equals(a.localPart) && getAsciiDomain().equals(a.getAsciiDomain());
	}

	@Override
	public int hashCode() {
		return localPart.hashCode() * 31 + getAsciiDomain().hashCode();
	}

	// ------------------------------------------------------------------ parsing

	/**
	 * Parse a mailbox such as {@code user@example.com} or {@code "a b"@[192.0.2.1]}.
	 *
	 * @param utf8 allow UTF-8 (SMTPUTF8)
	 * @throws IllegalArgumentException if it isn't a valid mailbox
	 */
	public static MailAddress parse(String text, boolean utf8) {
		if (!utf8 && !isAscii(text)) {
			throw new IllegalArgumentException("Non-ASCII address without SMTPUTF8");
		}
		int at;
		String local;
		if (text.startsWith("\"")) {
			int i = 1;
			StringBuilder sb = new StringBuilder();
			boolean closed = false;
			while (i < text.length()) {
				char c = text.charAt(i++);
				if (c == '\\') {
					if (i >= text.length()) {
						break;
					}
					char q = text.charAt(i++);
					if (q < 32 || q > 126) {
						throw new IllegalArgumentException("Invalid quoted pair");
					}
					sb.append(q);
				} else if (c == '"') {
					closed = true;
					break;
				} else if (c < 32 || c == 127) {
					throw new IllegalArgumentException("Control character in local part");
				} else {
					sb.append(c);
				}
			}
			if (!closed || i >= text.length() || text.charAt(i) != '@') {
				throw new IllegalArgumentException("Invalid quoted local part");
			}
			local = sb.toString();
			at = i;
		} else {
			at = text.lastIndexOf('@');
			if (at <= 0) {
				throw new IllegalArgumentException("Missing local part or @");
			}
			local = text.substring(0, at);
			if (!isDotString(local)) {
				throw new IllegalArgumentException("Invalid local part");
			}
		}
		String domain = text.substring(at + 1);
		if (!isDomain(domain) && !isAddressLiteral(domain)) {
			throw new IllegalArgumentException("Invalid domain");
		}
		if (local.getBytes(StandardCharsets.UTF_8).length > MAX_LOCAL_PART * 4
				|| domain.getBytes(StandardCharsets.UTF_8).length > MAX_DOMAIN) {
			throw new IllegalArgumentException("Address too long");
		}
		return new MailAddress(local, domain);
	}

	private static boolean isAtext(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
				|| ATEXT_SPECIALS.indexOf(c) >= 0;
	}

	static boolean isDotString(String s) {
		if (s.isEmpty() || s.startsWith(".") || s.endsWith(".") || s.contains("..")) {
			return false;
		}
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c != '.' && !isAtext(c)) {
				return false;
			}
		}
		return true;
	}

	private static String quote(String s) {
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '"' || c == '\\') {
				sb.append('\\');
			}
			sb.append(c);
		}
		return sb.append('"').toString();
	}

	/** A domain name: labels of letters, digits and hyphens (or UTF-8 U-labels). */
	public static boolean isDomain(String d) {
		if (d.isEmpty() || d.length() > MAX_DOMAIN || d.startsWith(".") || d.endsWith(".") || d.contains("..")) {
			return false;
		}
		for (String label : d.split("\\.")) {
			if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
				return false;
			}
			for (int i = 0; i < label.length(); i++) {
				char c = label.charAt(i);
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c >= 0x80)) {
					return false;
				}
			}
		}
		return true;
	}

	/** An address literal: [IPv4], [IPv6:...] or [tag:content]. */
	public static boolean isAddressLiteral(String d) {
		if (d.length() < 3 || !d.startsWith("[") || !d.endsWith("]")) {
			return false;
		}
		String inner = d.substring(1, d.length() - 1);
		if (inner.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
			for (String p : inner.split("\\.")) {
				if (Integer.parseInt(p) > 255) {
					return false;
				}
			}
			return true;
		}
		if (inner.regionMatches(true, 0, "IPv6:", 0, 5)) {
			return inner.substring(5).matches("[0-9A-Fa-f:.]+");
		}
		int colon = inner.indexOf(':');
		return colon > 0 && inner.substring(0, colon).matches("[A-Za-z0-9-]*[A-Za-z0-9]")
				&& inner.substring(colon + 1).chars().allMatch(c -> c >= 33 && c <= 126 && c != '[' && c != ']' && c != '\\');
	}
}
