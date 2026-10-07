package us.bringardner.parley.smtp.dmarc;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import us.bringardner.parley.mail.Rfc2822Date;

/** The messages that carry DMARC reports (RFC 7489 sections 7.2.1.1 and 7.3, RFC 6591). */
final class ReportMail {

	private static final SecureRandom RANDOM = new SecureRandom();

	private ReportMail() {
	}

	static String boundary() {
		return "=_parley_" + Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE) + Long.toHexString(System.nanoTime());
	}

	private static StringBuilder headers(String from, List<String> to, String subject, String host) {
		StringBuilder m = new StringBuilder();
		m.append("Date: ").append(new Rfc2822Date()).append("\r\n");
		m.append("Message-ID: <").append(Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE)).append('.')
				.append(Long.toHexString(System.currentTimeMillis())).append("@").append(host).append(">\r\n");
		m.append("From: ").append(from).append("\r\n");
		m.append("To: ").append(String.join(", ", to)).append("\r\n");
		m.append("Subject: ").append(clean(subject)).append("\r\n");
		m.append("Auto-Submitted: auto-generated\r\n");
		m.append("MIME-Version: 1.0\r\n");
		return m;
	}

	/** An aggregate report: a text part and the gzipped XML as an attachment. */
	static byte[] aggregate(String from, List<String> to, String host, String orgName, String domain, String reportId,
			String fileName, byte[] gz, long begin, long end) {
		String b = boundary();
		StringBuilder m = headers(from, to, "Report Domain: " + domain + " Submitter: " + orgName + " Report-ID: <" + reportId + ">",
				host);
		m.append("Content-Type: multipart/mixed; boundary=\"").append(b).append("\"\r\n\r\n");
		m.append("This is a DMARC aggregate report (RFC 7489) in MIME format.\r\n\r\n");
		m.append("--").append(b).append("\r\n");
		m.append("Content-Type: text/plain; charset=us-ascii\r\n\r\n");
		m.append("DMARC aggregate report for ").append(domain).append(" from ").append(orgName).append(".\r\n");
		m.append("Report-ID: ").append(reportId).append("\r\n");
		m.append("Period: ").append(begin).append(" to ").append(end).append(" (seconds since 1970, UTC)\r\n\r\n");
		m.append("--").append(b).append("\r\n");
		m.append("Content-Type: application/gzip; name=\"").append(fileName).append("\"\r\n");
		m.append("Content-Disposition: attachment; filename=\"").append(fileName).append("\"\r\n");
		m.append("Content-Transfer-Encoding: base64\r\n\r\n");
		m.append(Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(gz)).append("\r\n");
		m.append("--").append(b).append("--\r\n");
		return m.toString().getBytes(StandardCharsets.US_ASCII);
	}

	/**
	 * A failure report in the Abuse Reporting Format (RFC 5965, RFC 6591):
	 * a text part, a message/feedback-report part and the message's header.
	 *
	 * @param feedback the fields of the message/feedback-report part, each ending with CRLF
	 * @param header   the reported message's header fields (raw bytes)
	 */
	static byte[] failure(String from, List<String> to, String host, String domain, String text, String feedback, byte[] header) {
		String b = boundary();
		StringBuilder m = headers(from, to, "DMARC failure report for " + domain, host);
		m.append("Content-Type: multipart/report; report-type=feedback-report; boundary=\"").append(b).append("\"\r\n\r\n");
		m.append("This is an authentication failure report (RFC 6591) in MIME format.\r\n\r\n");
		m.append("--").append(b).append("\r\n");
		m.append("Content-Type: text/plain; charset=us-ascii\r\n\r\n");
		m.append(clean(text)).append("\r\n\r\n");
		m.append("--").append(b).append("\r\n");
		m.append("Content-Type: message/feedback-report\r\n\r\n");
		m.append(feedback).append("\r\n");
		m.append("--").append(b).append("\r\n");
		m.append("Content-Type: text/rfc822-headers\r\n\r\n");
		byte[] head = m.toString().getBytes(StandardCharsets.US_ASCII);
		byte[] tail = ("\r\n--" + b + "--\r\n").getBytes(StandardCharsets.US_ASCII);
		byte[] ret = new byte[head.length + header.length + tail.length];
		System.arraycopy(head, 0, ret, 0, head.length);
		System.arraycopy(header, 0, ret, head.length, header.length);
		System.arraycopy(tail, 0, ret, head.length + header.length, tail.length);
		return ret;
	}

	/** Printable ASCII only (header and text values come from the reported message). */
	static String clean(String s) {
		StringBuilder sb = new StringBuilder();
		String v = s == null ? "" : s;
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			sb.append((c < 32 && c != '\r' && c != '\n' && c != '\t') || c > 126 ? '?' : c);
		}
		return sb.toString().replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
	}
}
