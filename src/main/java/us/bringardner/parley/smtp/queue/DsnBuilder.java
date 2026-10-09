package us.bringardner.parley.smtp.queue;

import us.bringardner.parley.io.IoUtils;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.mail.Rfc2822Date;
import us.bringardner.parley.smtp.SmtpStreams;

/**
 * Delivery status notifications (RFC 3464, RFC 3461): a multipart/report with
 * a human-readable part, a message/delivery-status part (message/global-delivery-status
 * when addresses need UTF-8, RFC 6533) and the returned message or its headers.
 */
public final class DsnBuilder {

	/** Why the notification is sent. */
	public enum Kind {
		FAILURE("failed", "Undelivered Mail Returned to Sender"),
		DELAY("delayed", "Delayed Mail (still being retried)"),
		SUCCESS("delivered", "Successful Mail Delivery Report");

		final String action;
		final String subject;

		Kind(String action, String subject) {
			this.action = action;
			this.subject = subject;
		}
	}

	private static final SecureRandom RANDOM = new SecureRandom();

	/** The result of writing a DSN. */
	public static final class Written {
		public boolean utf8;
		public boolean eightBit;
		public long size;
	}

	private DsnBuilder() {
	}

	/**
	 * Write a DSN about some recipients of {@code entry}.
	 *
	 * @param actions the Action for each recipient ("failed", "delayed", "delivered", "relayed", "expanded")
	 */
	public static Written write(FileSource dest, DeliveryConfig config, QueueEntry entry, FileSource content, Kind kind,
			List<QueuedRecipient> rcpts, List<String> actions, long willRetryUntil) throws IOException {
		Written w = new Written();
		boolean utf8 = entry.from != null && !entry.from.isAscii();
		for (QueuedRecipient r : rcpts) {
			utf8 |= !r.address.isAscii() || (r.orcpt != null && !isAscii(r.orcpt));
		}
		w.utf8 = utf8 || entry.smtpUtf8;
		String host = config.getHostname();
		String boundary = Long.toHexString(System.currentTimeMillis()) + "." + Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE)
				+ "/" + host;
		String now = new Rfc2822Date().toString();
		StringBuilder h = new StringBuilder();
		h.append("From: Mail Delivery System <MAILER-DAEMON@").append(host).append(">\r\n");
		h.append("To: ").append(entry.from == null ? "<>" : "<" + entry.from + ">").append("\r\n");
		h.append("Subject: ").append(kind.subject).append("\r\n");
		h.append("Date: ").append(now).append("\r\n");
		h.append("Message-ID: <").append(Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE)).append(".dsn@").append(host)
				.append(">\r\n");
		h.append("Auto-Submitted: auto-replied\r\n");
		h.append("MIME-Version: 1.0\r\n");
		h.append("Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"").append(boundary)
				.append("\"\r\n\r\n");
		h.append("This is a MIME-encapsulated message.\r\n\r\n");

		// human-readable part
		h.append("--").append(boundary).append("\r\n");
		h.append("Content-Description: Notification\r\n");
		h.append("Content-Type: text/plain; charset=utf-8\r\n");
		h.append("Content-Transfer-Encoding: 8bit\r\n\r\n");
		h.append("This is the mail system at host ").append(host).append(".\r\n\r\n");
		switch (kind) {
		case FAILURE:
			h.append("I'm sorry to have to inform you that your message could not\r\n")
					.append("be delivered to one or more recipients.\r\n\r\n");
			break;
		case DELAY:
			h.append("Your message could not be delivered yet. The mail system will keep\r\n")
					.append("trying until ").append(new Rfc2822Date(willRetryUntil)).append(".\r\n\r\n");
			break;
		default:
			h.append("Your message was successfully delivered to the destination(s) listed below.\r\n\r\n");
		}
		for (int i = 0; i < rcpts.size(); i++) {
			QueuedRecipient r = rcpts.get(i);
			h.append("<").append(r.address).append(">: ").append(actions.get(i));
			if (r.lastResult != null && !r.lastResult.isEmpty() && !actions.get(i).equals("delivered")
					&& !actions.get(i).equals("relayed") && !actions.get(i).equals("expanded")) {
				h.append("\r\n    ").append(r.lastResult);
			}
			h.append("\r\n");
		}
		h.append("\r\n");

		// machine-readable part
		h.append("--").append(boundary).append("\r\n");
		h.append("Content-Description: Delivery report\r\n");
		h.append("Content-Type: ").append(utf8 ? "message/global-delivery-status" : "message/delivery-status").append("\r\n");
		if (utf8) {
			h.append("Content-Transfer-Encoding: 8bit\r\n");
		}
		h.append("\r\n");
		h.append("Reporting-MTA: dns; ").append(host).append("\r\n");
		if (entry.envid != null) {
			h.append("Original-Envelope-Id: ").append(entry.envid).append("\r\n");
		}
		h.append("Arrival-Date: ").append(new Rfc2822Date(entry.created)).append("\r\n");
		for (int i = 0; i < rcpts.size(); i++) {
			QueuedRecipient r = rcpts.get(i);
			String action = actions.get(i);
			h.append("\r\n");
			h.append("Final-Recipient: ").append(r.address.isAscii() ? "rfc822; " : "utf-8; ").append(r.address).append("\r\n");
			if (r.orcpt != null) {
				h.append("Original-Recipient: ").append(r.orcpt.indexOf(';') > 0 ? r.orcpt : "rfc822; " + r.orcpt).append("\r\n");
			}
			h.append("Action: ").append(action).append("\r\n");
			String status = r.lastStatus == null || r.lastStatus.isEmpty()
					? (kind == Kind.FAILURE ? "5.0.0" : kind == Kind.DELAY ? "4.0.0" : "2.0.0")
					: r.lastStatus;
			if (action.equals("delivered") || action.equals("relayed") || action.equals("expanded")) {
				status = "2.0.0";
			}
			h.append("Status: ").append(status).append("\r\n");
			if (r.remoteMta != null) {
				h.append("Remote-MTA: ").append(r.remoteMta).append("\r\n");
			}
			String diag = diagnostic(r);
			if (diag != null && !action.equals("delivered") && !action.equals("relayed")) {
				h.append("Diagnostic-Code: ").append(diag).append("\r\n");
			}
			h.append("Last-Attempt-Date: ").append(now).append("\r\n");
			if (kind == Kind.DELAY) {
				h.append("Will-Retry-Until: ").append(new Rfc2822Date(willRetryUntil)).append("\r\n");
			}
		}
		h.append("\r\n");

		// the returned message: headers, or the whole message for a failure if asked for (or small)
		boolean full = kind == Kind.FAILURE && !"HDRS".equalsIgnoreCase(entry.ret)
				&& ("FULL".equalsIgnoreCase(entry.ret) || entry.size <= config.getMaxReturnSize())
				&& entry.body != QueueEntry.Body.BINARY;
		boolean returnedUtf8 = entry.smtpUtf8;
		h.append("--").append(boundary).append("\r\n");
		if (full) {
			h.append("Content-Description: Undelivered Message\r\n");
			h.append("Content-Type: ").append(returnedUtf8 ? "message/global" : "message/rfc822").append("\r\n");
		} else {
			h.append("Content-Description: Message Headers\r\n");
			h.append("Content-Type: ").append(returnedUtf8 ? "message/global-headers" : "text/rfc822-headers").append("\r\n");
		}
		if (entry.body != QueueEntry.Body.SEVEN_BIT || returnedUtf8) {
			h.append("Content-Transfer-Encoding: 8bit\r\n");
		}
		h.append("\r\n");

		try (OutputStream raw = IoUtils.buffered(dest.getOutputStream())) {
			CountingOutputStream count = new CountingOutputStream(raw);
			count.write(h.toString().getBytes(StandardCharsets.UTF_8));
			SmtpStreams.CrlfOutputStream out = new SmtpStreams.CrlfOutputStream(count);
			try (InputStream in = IoUtils.buffered(content.getInputStream())) {
				if (full) {
					in.transferTo(out);
				} else {
					copyHeaders(in, out);
				}
			}
			out.finish();
			// end with CRLF before the closing boundary
			count.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII));
			count.flush();
			w.size = count.count;
		}
		w.eightBit = true; // the text part is 8bit UTF-8
		return w;
	}

	private static String diagnostic(QueuedRecipient r) {
		String last = r.lastResult == null ? "" : r.lastResult;
		int i = last.indexOf("smtp; ");
		if (i >= 0) {
			return last.substring(i);
		}
		return last.isEmpty() ? null : "x-local; " + last;
	}

	/** Copy the header block (up to the blank line). */
	private static void copyHeaders(InputStream in, OutputStream out) throws IOException {
		int prev = -1;
		int prev2 = -1;
		int b;
		long n = 0;
		while ((b = in.read()) >= 0 && n < 1024 * 1024) {
			if (b == '\n' && (prev == '\n' || (prev == '\r' && prev2 == '\n'))) {
				break;
			}
			out.write(b);
			prev2 = prev;
			prev = b;
			n++;
		}
	}

	private static boolean isAscii(String s) {
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) >= 0x80) {
				return false;
			}
		}
		return true;
	}

	private static final class CountingOutputStream extends java.io.FilterOutputStream {
		long count;

		CountingOutputStream(OutputStream out) {
			super(out);
		}

		@Override
		public void write(int b) throws IOException {
			out.write(b);
			count++;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			out.write(b, off, len);
			count += len;
		}
	}
}
