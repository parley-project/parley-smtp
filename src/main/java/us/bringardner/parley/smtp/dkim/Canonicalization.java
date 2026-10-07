package us.bringardner.parley.smtp.dkim;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Locale;

/** The "simple" and "relaxed" canonicalization algorithms (RFC 6376 section 3.4). */
public enum Canonicalization {

	SIMPLE, RELAXED;

	public String keyword() {
		return name().toLowerCase(Locale.ROOT);
	}

	static Canonicalization parse(String s) throws DkimException {
		switch (s.trim().toLowerCase(Locale.ROOT)) {
		case "simple":
			return SIMPLE;
		case "relaxed":
			return RELAXED;
		default:
			throw DkimException.perm("unknown canonicalization " + s);
		}
	}

	/**
	 * A header field in this canonical form, ending with CRLF (section 3.4.1
	 * and 3.4.2). {@code raw} is the field as {@link HeaderFields} reads it.
	 */
	public String header(String raw) {
		if (this == SIMPLE) {
			return raw;
		}
		int colon = raw.indexOf(':');
		String name = raw.substring(0, colon).replaceAll("[ \\t]+$", "").toLowerCase(Locale.ROOT);
		String value = raw.substring(colon + 1).replace("\r\n", "").replace("\r", "").replace("\n", "");
		value = value.replaceAll("[ \\t]+", " ").trim();
		return name + ":" + value + "\r\n";
	}

	/**
	 * A stream that canonicalizes the body written to it and hashes the
	 * result (section 3.4.3 and 3.4.4).
	 *
	 * @param limit hash only this many octets of the canonical body (the l= tag), or -1
	 */
	public BodyHasher bodyHasher(MessageDigest md, long limit) {
		return new BodyHasher(this == RELAXED, md, limit);
	}

	/**
	 * Canonicalizes a body as it is written, so a body of any size can be
	 * hashed without holding it in memory. Line ends are CRLF; trailing empty
	 * lines are dropped, and a missing CRLF on the last line is added.
	 */
	public static final class BodyHasher extends OutputStream {
		private final boolean relaxed;
		private final MessageDigest md;
		private final long limit;
		private final byte[] buf = new byte[8192];
		private int used;
		private long emitted;
		private int pendingEmptyLines;
		private boolean prevCr;
		private boolean lineHasContent;
		private boolean pendingSpace;
		private byte[] digest;

		BodyHasher(boolean relaxed, MessageDigest md, long limit) {
			this.relaxed = relaxed;
			this.md = md;
			this.limit = limit;
		}

		@Override
		public void write(int b) {
			b &= 0xff;
			if (prevCr) {
				prevCr = false;
				if (b == '\n') {
					endLine();
					return;
				}
				content('\r');
			}
			if (b == '\r') {
				prevCr = true;
				return;
			}
			content(b);
		}

		@Override
		public void write(byte[] b, int off, int len) {
			for (int i = off; i < off + len; i++) {
				write(b[i]);
			}
		}

		private void content(int b) {
			if (relaxed && (b == ' ' || b == '\t')) {
				pendingSpace = true; // written only if more content follows on the line
				return;
			}
			if (!lineHasContent) {
				while (pendingEmptyLines > 0) {
					emit('\r');
					emit('\n');
					pendingEmptyLines--;
				}
				lineHasContent = true;
			}
			if (pendingSpace) {
				emit(' ');
				pendingSpace = false;
			}
			emit(b);
		}

		private void endLine() {
			pendingSpace = false;
			if (lineHasContent) {
				emit('\r');
				emit('\n');
				lineHasContent = false;
			} else {
				pendingEmptyLines++;
			}
		}

		private void emit(int b) {
			if (limit < 0 || emitted < limit) {
				buf[used++] = (byte) b;
				if (used == buf.length) {
					md.update(buf, 0, used);
					used = 0;
				}
			}
			emitted++;
		}

		/** End the body: the hash of the canonical body (later calls return the same). */
		public byte[] finish() {
			if (digest == null) {
				if (prevCr) {
					prevCr = false;
					content('\r');
				}
				pendingSpace = false;
				if (lineHasContent) {
					emit('\r');
					emit('\n');
					lineHasContent = false;
				}
				if (!relaxed && emitted == 0) {
					emit('\r'); // an empty body is one CRLF in simple
					emit('\n');
				}
				md.update(buf, 0, used);
				used = 0;
				digest = md.digest();
			}
			return digest;
		}

		@Override
		public void close() {
			finish();
		}

		/** Length of the whole canonical body (not limited by l=). */
		public long getCanonicalLength() {
			return emitted;
		}
	}
}
