package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** HELO domain (RFC 5321 section 4.1.1.1): a session without extensions. */
public class Helo extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Helo() {
		super("HELO");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		String name = args.trim();
		if (!Ehlo.validName(name)) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: HELO hostname");
			return;
		}
		p.hello(name, false);
		p.reply(OK, null, p.getSmtpServer().getHostname());
	}
}
