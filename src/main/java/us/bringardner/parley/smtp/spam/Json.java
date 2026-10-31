package us.bringardner.parley.smtp.spam;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader for scanner answers: objects become {@code Map<String, Object>}, arrays
 * {@code List<Object>}, numbers {@code Double}, plus String, Boolean and null.
 */
final class Json {

	private final String s;
	private int pos;

	private Json(String s) {
		this.s = s;
	}

	static Object parse(String text) throws IOException {
		Json j = new Json(text);
		Object ret = j.value(0);
		j.skip();
		if (j.pos != j.s.length()) {
			throw j.error("unexpected text after the value");
		}
		return ret;
	}

	private IOException error(String why) {
		return new IOException("Bad JSON at " + pos + ": " + why);
	}

	private void skip() {
		while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
			pos++;
		}
	}

	private Object value(int depth) throws IOException {
		if (depth > 50) {
			throw error("nested too deeply");
		}
		skip();
		if (pos >= s.length()) {
			throw error("unexpected end");
		}
		char c = s.charAt(pos);
		switch (c) {
		case '{': {
			pos++;
			Map<String, Object> m = new LinkedHashMap<>();
			skip();
			if (peek('}')) {
				return m;
			}
			do {
				skip();
				String k = string();
				skip();
				expect(':');
				m.put(k, value(depth + 1));
				skip();
			} while (peek(','));
			expect('}');
			return m;
		}
		case '[': {
			pos++;
			List<Object> l = new ArrayList<>();
			skip();
			if (peek(']')) {
				return l;
			}
			do {
				l.add(value(depth + 1));
				skip();
			} while (peek(','));
			expect(']');
			return l;
		}
		case '"':
			return string();
		default:
			if (s.startsWith("true", pos)) {
				pos += 4;
				return Boolean.TRUE;
			}
			if (s.startsWith("false", pos)) {
				pos += 5;
				return Boolean.FALSE;
			}
			if (s.startsWith("null", pos)) {
				pos += 4;
				return null;
			}
			int start = pos;
			while (pos < s.length() && "+-0123456789.eE".indexOf(s.charAt(pos)) >= 0) {
				pos++;
			}
			if (start == pos) {
				throw error("unexpected '" + c + "'");
			}
			try {
				return Double.valueOf(s.substring(start, pos));
			} catch (NumberFormatException e) {
				throw error("bad number");
			}
		}
	}

	/** Consume the character if it is next. */
	private boolean peek(char c) {
		if (pos < s.length() && s.charAt(pos) == c) {
			pos++;
			return true;
		}
		return false;
	}

	private void expect(char c) throws IOException {
		if (!peek(c)) {
			throw error("expected '" + c + "'");
		}
	}

	private String string() throws IOException {
		expect('"');
		StringBuilder sb = new StringBuilder();
		while (pos < s.length()) {
			char c = s.charAt(pos++);
			if (c == '"') {
				return sb.toString();
			}
			if (c != '\\') {
				sb.append(c);
				continue;
			}
			if (pos >= s.length()) {
				break;
			}
			char e = s.charAt(pos++);
			switch (e) {
			case 'n':
				sb.append('\n');
				break;
			case 't':
				sb.append('\t');
				break;
			case 'r':
				sb.append('\r');
				break;
			case 'b':
				sb.append('\b');
				break;
			case 'f':
				sb.append('\f');
				break;
			case 'u':
				if (pos + 4 > s.length()) {
					throw error("bad \\u escape");
				}
				try {
					sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
				} catch (NumberFormatException ex) {
					throw error("bad \\u escape");
				}
				pos += 4;
				break;
			default:
				sb.append(e); // \" \\ \/
			}
		}
		throw error("unterminated string");
	}
}
