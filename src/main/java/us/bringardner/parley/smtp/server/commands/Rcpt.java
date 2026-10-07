package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.MailPath;
import us.bringardner.parley.smtp.queue.LocalDelivery;
import us.bringardner.parley.smtp.queue.QueuedRecipient;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * RCPT TO:&lt;forward-path&gt; [NOTIFY=...] [ORCPT=...] (RFC 5321 section
 * 4.1.1.3, RFC 3461). Local recipients must exist; other domains need relay
 * rights (AUTH or a trusted network), so the server is never an open relay.
 */
public class Rcpt extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Rcpt() {
		super("RCPT");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		SmtpRequestProcessor.Transaction t = p.getTransaction();
		if (t == null) {
			p.error(BAD_SEQUENCE, "5.5.1", "Need MAIL command");
			return;
		}
		if (t.bdatUsed) {
			p.error(BAD_SEQUENCE, "5.5.1", "RCPT after BDAT");
			return;
		}
		if (!args.regionMatches(true, 0, "TO:", 0, 3)) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: RCPT TO:<address>");
			return;
		}
		SmtpServer s = p.getSmtpServer();
		if (t.recipients.size() >= s.getMaxRecipients()) {
			p.reply(INSUFFICIENT_STORAGE, "4.5.3", "Too many recipients");
			return;
		}
		String rest = args.substring(3).trim();
		MailPath path;
		if (rest.regionMatches(true, 0, "<postmaster>", 0, 12)) {
			// RFC 5321 section 4.1.1.3: <Postmaster> without a domain must be accepted
			String domain = s.getDeliveryConfig().getLocalDomains().isEmpty() ? s.getHostname()
					: s.getDeliveryConfig().getLocalDomains().iterator().next();
			rest = "<postmaster@" + domain + ">" + rest.substring(12);
		}
		try {
			path = MailPath.parse(rest, false, t.smtpUtf8, true);
		} catch (IllegalArgumentException e) {
			if (!t.smtpUtf8 && !Mail.isAscii(rest)) {
				p.error(MAILBOX_NAME_NOT_ALLOWED, "5.6.7", "Non-ASCII address requires SMTPUTF8");
			} else {
				p.error(PARAMETER_ERROR, "5.1.3", "Bad recipient address syntax: " + e.getMessage());
			}
			return;
		}
		String orcpt = null;
		Set<QueuedRecipient.Notify> notify = null;
		for (Map.Entry<String, String> e : path.getParameters().entrySet()) {
			if (!p.isEsmtp()) {
				p.error(PARAMETERS_NOT_RECOGNIZED, "5.5.4", "Parameters need EHLO");
				return;
			}
			switch (e.getKey()) {
			case "NOTIFY":
				try {
					notify = QueuedRecipient.parseNotify(e.getValue());
				} catch (IllegalArgumentException ex) {
					p.error(PARAMETER_ERROR, "5.5.4", "Invalid NOTIFY");
					return;
				}
				break;
			case "ORCPT": {
				String v = e.getValue();
				int semi = v.indexOf(';');
				if (semi <= 0) {
					p.error(PARAMETER_ERROR, "5.5.4", "Invalid ORCPT");
					return;
				}
				orcpt = v.substring(0, semi) + ";" + MailPath.decodeXtext(v.substring(semi + 1));
				break;
			}
			default:
				p.error(PARAMETERS_NOT_RECOGNIZED, "5.5.4", "Unsupported parameter " + e.getKey());
				return;
			}
		}
		MailAddress a = path.getAddress();
		if (s.isLocalDomain(a.getAsciiDomain())) {
			LocalDelivery.Target target = p.getQueue().getLocalDelivery().find(a.getLocalPart());
			if (target == null) {
				p.error(MAILBOX_UNAVAILABLE, "5.1.1", "<" + a + ">: Recipient address rejected: User unknown");
				return;
			}
		} else if (!p.mayRelay()) {
			p.error(MAILBOX_UNAVAILABLE, "5.7.1", "<" + a + ">: Relay access denied");
			return;
		}
		t.recipients.add(new QueuedRecipient(a, orcpt, notify));
		p.reply(OK, "2.1.5", "Ok");
	}
}
