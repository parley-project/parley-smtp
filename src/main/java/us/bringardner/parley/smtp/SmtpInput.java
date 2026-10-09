package us.bringardner.parley.smtp;

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import us.bringardner.parley.io.BufferedLineInput;

/**
 * Reads one side of an SMTP connection: command and reply lines, BDAT chunks,
 * and DATA content up to the end-of-data line. Used by the server and by the
 * outbound client.
 */
public final class SmtpInput extends BufferedLineInput {

	/** The result of reading DATA content. */
	public static final class DataResult {
		/** Octets of content (after removing dot-stuffing). */
		public long size;
		/** True if the content was larger than allowed; the rest was read and discarded. */
		public boolean tooLarge;
	}

	public SmtpInput(InputStream in) {
		super(in, "Connection closed in a BDAT chunk", true);
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
}
