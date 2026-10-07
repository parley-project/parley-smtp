package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/**
 * VRFY (RFC 5321 section 3.5.1). Users aren't disclosed (section 7.3); the 252
 * reply says the server will try to deliver anyway.
 */
public class Vrfy extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Vrfy() {
		super("VRFY");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (args.trim().isEmpty()) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: VRFY address");
			return;
		}
		p.reply(CANNOT_VRFY, "2.5.0", "Cannot VRFY user, but will accept message and attempt delivery");
	}
}
