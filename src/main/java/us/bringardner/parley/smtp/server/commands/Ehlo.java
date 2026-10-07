package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;
import us.bringardner.parley.smtp.server.SmtpServer;

/** EHLO domain (RFC 5321 section 4.1.1.1): start an ESMTP session and list the extensions. */
public class Ehlo extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Ehlo() {
		super("EHLO");
	}

	protected Ehlo(String name) {
		super(name);
	}

	/** True for a domain or address literal (lenient: any non-empty name without spaces is accepted). */
	static boolean validName(String name) {
		return !name.isEmpty() && name.indexOf(' ') < 0
				&& (MailAddress.isDomain(name) || MailAddress.isAddressLiteral(name) || name.matches("[\\x21-\\x7e]+"));
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		String name = args.trim();
		if (!validName(name)) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: " + getName() + " hostname");
			return;
		}
		p.hello(name, true);
		SmtpServer s = p.getSmtpServer();
		List<String> lines = new ArrayList<>();
		lines.add(s.getHostname() + " Hello " + name + " [" + p.getClientAddress().getHostAddress() + "]");
		lines.add(EXT_PIPELINING);
		lines.add(EXT_SIZE + " " + s.getMaxMessageSize());
		lines.add(EXT_8BITMIME);
		lines.add(EXT_SMTPUTF8);
		lines.add(EXT_ENHANCEDSTATUSCODES);
		lines.add(EXT_CHUNKING);
		lines.add(EXT_BINARYMIME);
		lines.add(EXT_DSN);
		if (!p.isTls() && s.isTlsAvailable()) {
			lines.add(EXT_STARTTLS);
		}
		if (!p.isAuthenticated() && (p.isTls() || !s.isRequireTls())) {
			lines.add(EXT_AUTH + " PLAIN LOGIN");
		}
		lines.add("HELP");
		p.reply(OK, lines);
	}
}
