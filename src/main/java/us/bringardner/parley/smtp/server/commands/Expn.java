package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** EXPN (RFC 5321 section 3.5.2): mailing lists aren't disclosed. */
public class Expn extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Expn() {
		super("EXPN");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		p.reply(NOT_IMPLEMENTED, "5.5.1", "EXPN is not available");
	}
}
