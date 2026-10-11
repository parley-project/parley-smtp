package us.bringardner.parley.smtp;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/** Output streams for SMTP content. */
public final class SmtpStreams {

	private SmtpStreams() {
	}

	/** Turns bare LF and bare CR into CRLF. */
	public static final class CrlfOutputStream extends FilterOutputStream {
		private boolean pendingCr;

		public CrlfOutputStream(OutputStream out) {
			super(out);
		}

		@Override
		public void write(int b) throws IOException {
			if (pendingCr) {
				pendingCr = false;
				out.write('\r');
				out.write('\n');
				if (b == '\n') {
					return;
				}
			}
			if (b == '\r') {
				pendingCr = true;
			} else if (b == '\n') {
				out.write('\r');
				out.write('\n');
			} else {
				out.write(b);
			}
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			for (int i = off; i < off + len; i++) {
				write(b[i]);
			}
		}

		/** End the content: a final bare CR becomes CRLF. The stream is flushed, not closed. */
		public void finish() throws IOException {
			if (pendingCr) {
				pendingCr = false;
				out.write('\r');
				out.write('\n');
			}
			out.flush();
		}

		@Override
		public void close() throws IOException {
			finish();
			super.close();
		}
	}

	/**
	 * DATA content for sending (RFC 5321 section 4.5.2): line ends become CRLF (a bare CR too), a
	 * "." starting a line is doubled, and {@link #finish()} ends the content with CRLF "." CRLF.
	 * This is {@link us.bringardner.parley.io.DotStuffingOutputStream} with bare CR normalized;
	 * unlike that class, closing only flushes, because the caller decides when the data ends and
	 * the stream under it is the connection.
	 */
	public static final class DotStuffingOutputStream extends us.bringardner.parley.io.DotStuffingOutputStream {

		public DotStuffingOutputStream(OutputStream out) {
			super(out, true);
		}

		@Override
		public void close() throws IOException {
			flush();
		}
	}
}
