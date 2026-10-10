package us.bringardner.parley.smtp.dkim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The header fields of a message, read byte for byte so they can be hashed
 * exactly as received (RFC 6376 section 3.4). Each field keeps its raw text,
 * continuation lines and terminating CRLF included, as ISO-8859-1 characters
 * (one char per byte, so UTF-8 header bytes survive unchanged).
 */
public final class HeaderFields {

	/** Header blocks larger than this are refused (the body is never held in memory). */
	public static final int MAX_HEADER_BYTES = 1024 * 1024;

	/** One header field. */
	public static final class Field {
		private final String name;
		private final String raw;

		Field(String name, String raw) {
			this.name = name;
			this.raw = raw;
		}

		/** The field name as written (no trailing white space). */
		public String getName() {
			return name;
		}

		/** The whole field: name, colon, value, continuation lines and line end. */
		public String getRaw() {
			return raw;
		}

		/** The value: after the colon, unfolded, trimmed (decoded as UTF-8). */
		public String getValue() {
			String v = raw.substring(raw.indexOf(':') + 1).replace("\r", "").replace("\n", "");
			return new String(v.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8).trim();
		}

		public boolean is(String fieldName) {
			return name.equalsIgnoreCase(fieldName);
		}

		@Override
		public String toString() {
			return raw.trim();
		}
	}

	private final List<Field> fields;
	private final boolean hasBody;
	private final long headerLength;

	private HeaderFields(List<Field> fields, boolean hasBody, long headerLength) {
		this.fields = Collections.unmodifiableList(fields);
		this.hasBody = hasBody;
		this.headerLength = headerLength;
	}

	public List<Field> getFields() {
		return fields;
	}

	/** True if a blank line ended the header (there may be a body after it). */
	public boolean hasBody() {
		return hasBody;
	}

	/** Bytes read: the header fields plus the blank line. */
	public long getHeaderLength() {
		return headerLength;
	}

	/** The first field with this name, or null. */
	public Field get(String name) {
		for (Field f : fields) {
			if (f.is(name)) {
				return f;
			}
		}
		return null;
	}

	/** All fields with this name, top to bottom. */
	public List<Field> getAll(String name) {
		List<Field> ret = new ArrayList<>();
		for (Field f : fields) {
			if (f.is(name)) {
				ret.add(f);
			}
		}
		return ret;
	}

	/**
	 * Read the header of a message. The stream is left at the first byte of
	 * the body; it should be buffered, as it is read one byte at a time.
	 *
	 * @throws IOException if the header is larger than {@link #MAX_HEADER_BYTES}
	 */
	public static HeaderFields read(InputStream in) throws IOException {
		List<Field> fields = new ArrayList<>();
		//  a line at a time, in an array that grows: ByteArrayOutputStream.write(int) is synchronized
		byte[] line = new byte[256];
		StringBuilder field = null;
		long total = 0;
		boolean hasBody = false;
		while (true) {
			int len = 0;
			int b;
			while ((b = in.read()) >= 0) {
				if (len == line.length) {
					line = Arrays.copyOf(line, len * 2);
				}
				line[len++] = (byte) b;
				if (++total > MAX_HEADER_BYTES) {
					throw new IOException("The message header is larger than " + MAX_HEADER_BYTES + " bytes");
				}
				if (b == '\n') {
					break;
				}
			}
			if (len == 0) {
				break; // end of the message
			}
			String text = new String(line, 0, len, StandardCharsets.ISO_8859_1);
			if (text.equals("\r\n") || text.equals("\n")) {
				hasBody = true;
				break;
			}
			char first = text.charAt(0);
			if ((first == ' ' || first == '\t') && field != null) {
				field.append(text);
			} else {
				add(fields, field);
				field = new StringBuilder(text);
			}
			if (b < 0) {
				break;
			}
		}
		add(fields, field);
		return new HeaderFields(fields, hasBody, total);
	}

	private static void add(List<Field> fields, StringBuilder field) {
		if (field == null) {
			return;
		}
		String raw = field.toString();
		int colon = raw.indexOf(':');
		if (colon <= 0) {
			return; // not a header field (e.g. an mbox "From " line); ignored
		}
		String name = raw.substring(0, colon);
		int end = name.length();
		while (end > 0 && (name.charAt(end - 1) == ' ' || name.charAt(end - 1) == '\t')) {
			end--;
		}
		fields.add(new Field(name.substring(0, end), raw));
	}

	/**
	 * The domain of the first address in a From (or other address) field, in
	 * lower case A-labels, or null if none is found.
	 */
	public static String addressDomain(String value) {
		if (value == null) {
			return null;
		}
		String v = stripComments(value);
		String addr;
		int lt = indexOutsideQuotes(v, '<');
		if (lt >= 0) {
			int gt = v.indexOf('>', lt);
			addr = gt > lt ? v.substring(lt + 1, gt) : v.substring(lt + 1);
		} else {
			int comma = indexOutsideQuotes(v, ',');
			addr = comma >= 0 ? v.substring(0, comma) : v;
			int colon = addr.indexOf(':'); // a group: "name: a@b;"
			if (colon >= 0) {
				addr = addr.substring(colon + 1);
			}
		}
		int at = addr.lastIndexOf('@');
		if (at < 0) {
			return null;
		}
		String domain = addr.substring(at + 1).trim();
		int stop = 0;
		while (stop < domain.length() && " \t>,;)".indexOf(domain.charAt(stop)) < 0) {
			stop++;
		}
		domain = domain.substring(0, stop);
		while (domain.endsWith(".")) {
			domain = domain.substring(0, domain.length() - 1);
		}
		if (domain.isEmpty()) {
			return null;
		}
		try {
			return java.net.IDN.toASCII(domain, java.net.IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
		} catch (IllegalArgumentException e) {
			return domain.toLowerCase(Locale.ROOT);
		}
	}

	private static int indexOutsideQuotes(String s, char ch) {
		boolean quoted = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (quoted && c == '\\') {
				i++;
			} else if (c == '"') {
				quoted = !quoted;
			} else if (!quoted && c == ch) {
				return i;
			}
		}
		return -1;
	}

	/** Remove (comments) outside quoted strings. */
	public static String stripComments(String s) {
		StringBuilder sb = new StringBuilder(s.length());
		int depth = 0;
		boolean quoted = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '\\' && i + 1 < s.length() && (quoted || depth > 0)) {
				if (depth == 0) {
					sb.append(c).append(s.charAt(i + 1));
				}
				i++;
			} else if (quoted) {
				sb.append(c);
				if (c == '"') {
					quoted = false;
				}
			} else if (c == '(') {
				depth++;
			} else if (c == ')' && depth > 0) {
				depth--;
			} else if (depth == 0) {
				if (c == '"') {
					quoted = true;
				}
				sb.append(c);
			}
		}
		return sb.toString();
	}
}
