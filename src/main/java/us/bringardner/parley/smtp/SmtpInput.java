package us.bringardner.parley.smtp;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Reads one side of an SMTP connection: command and reply lines, BDAT chunks,
 * and DATA content up to the end-of-data line. Used by the server and by the
 * outbound client.
 */
public final class SmtpInput {

	/** A line longer than the limit; the rest of the line has been discarded. */
	public static final class LineTooLongException extends IOException {
		private static final long serialVersionUID = 1L;

		LineTooLongException(int max) {
			super("Line longer than " + max + " bytes");
		}
	}

	/** The result of reading DATA content. */
	public static final class DataResult {
		/** Octets of content (after removing dot-stuffing). */
		public long size;
		/** True if the content was larger than allowed; the rest was read and discarded. */
		public boolean tooLarge;
	}

	private final InputStream in;
	private final byte[] buf = new byte[64 * 1024];
	private int pos;
	private int len;
	private final ByteArrayOutputStream partial = new ByteArrayOutputStream();
	private boolean discarding;
	private volatile BooleanSupplier keepWaiting;
	private volatile long lastReceived = System.currentTimeMillis();

	public SmtpInput(InputStream in) {
		this.in = in;
	}

	/** Asked after a socket timeout: true to keep waiting, false to throw the timeout. */
	public void setKeepWaiting(BooleanSupplier keepWaiting) {
		this.keepWaiting = keepWaiting;
	}

	public long getLastReceived() {
		return lastReceived;
	}

	private boolean fill() throws IOException {
		if (pos < len) {
			return true;
		}
		int n;
		while (true) {
			try {
				n = in.read(buf, 0, buf.length);
				break;
			} catch (SocketTimeoutException e) {
				BooleanSupplier k = keepWaiting;
				if (k == null || !k.getAsBoolean()) {
					throw e;
				}
			}
		}
		if (n <= 0) {
			return false;
		}
		lastReceived = System.currentTimeMillis();
		pos = 0;
		len = n;
		return true;
	}

	/**
	 * A line without its CRLF (a bare LF also ends it), or null at end of stream.
	 *
	 * @throws LineTooLongException for a line longer than {@code max}
	 */
	public byte[] readLine(int max) throws IOException {
		while (true) {
			if (!fill()) {
				if (partial.size() > 0) {
					byte[] rest = partial.toByteArray();
					partial.reset();
					return rest;
				}
				return null;
			}
			int i = pos;
			while (i < len && buf[i] != '\n') {
				i++;
			}
			if (!discarding) {
				partial.write(buf, pos, i - pos);
			}
			boolean found = i < len;
			pos = found ? i + 1 : len;
			if (!discarding && partial.size() > max) {
				discarding = true;
				partial.reset();
			}
			if (found) {
				if (discarding) {
					discarding = false;
					throw new LineTooLongException(max);
				}
				byte[] line = partial.toByteArray();
				partial.reset();
				int n = line.length;
				if (n > 0 && line[n - 1] == '\r') {
					n--;
				}
				return n == line.length ? line : java.util.Arrays.copyOf(line, n);
			}
		}
	}

	/** Copy exactly {@code n} bytes to {@code out} (null discards them). */
	public void readFully(long n, OutputStream out) throws IOException {
		while (n > 0) {
			if (!fill()) {
				throw new EOFException("Connection closed in a BDAT chunk");
			}
			int c = (int) Math.min(n, len - pos);
			if (out != null) {
				out.write(buf, pos, c);
			}
			pos += c;
			n -= c;
		}
	}

	/**
	 * Read DATA content up to the end-of-data line, removing dot-stuffing
	 * (RFC 5321 section 4.5.2). Only CRLF "." CRLF ends the data: a "." after a
	 * bare LF is content, which defeats "SMTP smuggling".
	 *
	 * @param max the largest size accepted; more is read and discarded
	 */
	public DataResult readData(OutputStream out, long max) throws IOException {
		DataResult r = new DataResult();
		boolean lineStart = true; // the DATA command's CRLF precedes the content
		boolean prevCr = false;
		int state = 0; // 0 normal, 1 "." at line start, 2 "." CR at line start
		while (true) {
			if (!fill()) {
				throw new EOFException("Connection closed in DATA");
			}
			while (pos < len) {
				int b = buf[pos++] & 0xff;
				if (state == 1) {
					if (b == '\r') {
						state = 2;
						continue;
					}
					// ".x": the dot was stuffing
					state = 0;
				} else if (state == 2) {
					if (b == '\n') {
						return r;
					}
					// ".\r" followed by something else: the dot was stuffing, the CR is content
					state = 0;
					write(r, out, max, '\r');
					prevCr = true;
				} else if (lineStart && b == '.') {
					state = 1;
					lineStart = false;
					continue;
				}
				write(r, out, max, b);
				lineStart = prevCr && b == '\n';
				prevCr = b == '\r';
			}
		}
	}

	private static void write(DataResult r, OutputStream out, long max, int b) throws IOException {
		r.size++;
		if (r.size > max) {
			r.tooLarge = true;
		} else if (out != null) {
			out.write(b);
		}
	}

	/** True if bytes have been received but not read yet (for PIPELINING). */
	public boolean hasBuffered() {
		return pos < len || partial.size() > 0;
	}

	/** Forget anything received but not read (after STARTTLS, RFC 3207). */
	public void discardBuffered() {
		pos = len = 0;
		partial.reset();
		discarding = false;
	}
}
