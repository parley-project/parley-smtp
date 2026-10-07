package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.smtp.MailPath;
import us.bringardner.parley.smtp.queue.QueueEntry;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;
import us.bringardner.parley.smtp.server.SmtpServer;
import us.bringardner.parley.smtp.spf.SpfResult;

/**
 * MAIL FROM:&lt;reverse-path&gt; [parameters] (RFC 5321 section 4.1.1.2), with
 * SIZE (RFC 1870), BODY (RFC 6152, RFC 3030), SMTPUTF8 (RFC 6531), RET and
 * ENVID (RFC 3461) and AUTH (RFC 4954).
 */
public class Mail extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Mail() {
		super("MAIL");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!checkHello(p)) {
			return;
		}
		if (p.getTransaction() != null) {
			p.error(BAD_SEQUENCE, "5.5.1", "Nested MAIL command");
			return;
		}
		SmtpServer s = p.getSmtpServer();
		if (s.isSubmission() && s.isRequireTls() && !p.isTls()) {
			p.error(AUTH_REQUIRED, "5.7.0", "Must issue a STARTTLS command first");
			return;
		}
		if (s.isSubmission() && !p.isAuthenticated()) {
			p.error(AUTH_REQUIRED, "5.7.0", "Authentication required");
			return;
		}
		if (!args.regionMatches(true, 0, "FROM:", 0, 5)) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: MAIL FROM:<address>");
			return;
		}
		String rest = args.substring(5);
		// SMTPUTF8 changes how the address is parsed, so look for it first
		boolean utf8 = false;
		int close = rest.lastIndexOf('>');
		if (close >= 0) {
			for (String param : rest.substring(close + 1).trim().split(" +")) {
				utf8 |= param.equalsIgnoreCase("SMTPUTF8");
			}
		}
		MailPath path;
		try {
			path = MailPath.parse(rest, true, utf8, true);
		} catch (IllegalArgumentException e) {
			if (!utf8 && !isAscii(rest)) {
				p.error(MAILBOX_NAME_NOT_ALLOWED, "5.6.7", "Non-ASCII address requires SMTPUTF8");
			} else {
				p.error(PARAMETER_ERROR, "5.1.7", "Bad sender address syntax: " + e.getMessage());
			}
			return;
		}
		Map<String, String> params = path.getParameters();
		if (!params.isEmpty() && !p.isEsmtp()) {
			p.error(PARAMETERS_NOT_RECOGNIZED, "5.5.4", "Parameters need EHLO");
			return;
		}
		SmtpRequestProcessor.Transaction t = new SmtpRequestProcessor.Transaction();
		t.from = path.getAddress();
		t.smtpUtf8 = utf8;
		for (Map.Entry<String, String> e : params.entrySet()) {
			String v = e.getValue();
			switch (e.getKey()) {
			case "SIZE":
				try {
					t.declaredSize = Long.parseLong(v);
				} catch (NumberFormatException ex) {
					p.error(PARAMETER_ERROR, "5.5.4", "Invalid SIZE");
					return;
				}
				if (t.declaredSize > s.getMaxMessageSize()) {
					p.error(EXCEEDED_STORAGE, "5.3.4", "Message size exceeds fixed maximum message size");
					return;
				}
				break;
			case "BODY":
				try {
					t.body = QueueEntry.Body.parse(v);
				} catch (IllegalArgumentException ex) {
					p.error(PARAMETER_ERROR, "5.5.4", "Invalid BODY");
					return;
				}
				break;
			case "SMTPUTF8":
				if (!v.isEmpty()) {
					p.error(PARAMETER_ERROR, "5.5.4", "SMTPUTF8 takes no value");
					return;
				}
				break;
			case "RET":
				String ret = v.toUpperCase(Locale.ROOT);
				if (!ret.equals("FULL") && !ret.equals("HDRS")) {
					p.error(PARAMETER_ERROR, "5.5.4", "Invalid RET");
					return;
				}
				t.ret = ret;
				break;
			case "ENVID":
				t.envid = MailPath.decodeXtext(v);
				if (t.envid.length() > 100) {
					p.error(PARAMETER_ERROR, "5.5.4", "ENVID too long");
					return;
				}
				break;
			case "AUTH":
				break; // RFC 4954 section 5: accepted, not passed on
			default:
				p.error(PARAMETERS_NOT_RECOGNIZED, "5.5.4", "Unsupported parameter " + e.getKey());
				return;
			}
		}
		t.spf = p.checkSpf(t.from);
		if (t.spf != null && t.spf.getResult() == SpfResult.Result.FAIL && p.getQueue().getConfig().getSpf().isRejectFail()) {
			// RFC 7208 section 8.4, RFC 7372
			p.error(MAILBOX_UNAVAILABLE, "5.7.23", "SPF validation failed: " + explanation(t.spf.getExplanation()));
			return;
		}
		p.setTransaction(t);
		p.reply(OK, "2.1.0", "Ok");
	}

	/** The domain's explanation, made safe for a reply line (printable ASCII, at most 200 characters). */
	static String explanation(String text) {
		StringBuilder sb = new StringBuilder();
		String t = text == null ? "" : text;
		for (int i = 0; i < t.length() && sb.length() < 200; i++) {
			char c = t.charAt(i);
			sb.append(c < 32 || c > 126 ? '?' : c);
		}
		return sb.toString();
	}

	static boolean isAscii(String s) {
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) >= 0x80) {
				return false;
			}
		}
		return true;
	}
}
