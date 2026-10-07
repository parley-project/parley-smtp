package us.bringardner.parley.smtp.dkim;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** A DKIM tag=value list (RFC 6376 section 3.2). */
final class TagList {

	private TagList() {
	}

	/**
	 * The tags in order; values have surrounding white space removed.
	 *
	 * @throws DkimException (permerror) on a syntax error or a duplicate tag
	 */
	static Map<String, String> parse(String text) throws DkimException {
		Map<String, String> ret = new LinkedHashMap<>();
		String unfolded = text.replace("\r", "").replace("\n", "");
		String[] parts = unfolded.split(";", -1);
		for (int i = 0; i < parts.length; i++) {
			String part = parts[i];
			if (part.trim().isEmpty()) {
				if (i == parts.length - 1) {
					continue; // a trailing ';' is allowed (RFC 6376 section 3.2)
				}
				throw DkimException.perm("empty tag in the tag list");
			}
			int eq = part.indexOf('=');
			if (eq < 0) {
				throw DkimException.perm("tag without a value: " + abbreviate(part.trim()));
			}
			String name = part.substring(0, eq).trim();
			if (!name.matches("[A-Za-z][A-Za-z0-9_]*")) {
				throw DkimException.perm("invalid tag name " + abbreviate(name));
			}
			if (ret.put(name, part.substring(eq + 1).trim()) != null) {
				throw DkimException.perm("duplicate tag " + name);
			}
		}
		return ret;
	}

	/** A base64 value (b=, bh=, p=): white space inside it is ignored. */
	static byte[] base64(String value, String tag) throws DkimException {
		try {
			return Base64.getDecoder().decode(value.replaceAll("[ \\t\\r\\n]", ""));
		} catch (IllegalArgumentException e) {
			throw DkimException.perm("invalid base64 in " + tag + "=");
		}
	}

	static String abbreviate(String s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length() && sb.length() < 40; i++) {
			char c = s.charAt(i);
			sb.append(c < 32 || c > 126 ? '?' : c);
		}
		return sb.toString();
	}
}
