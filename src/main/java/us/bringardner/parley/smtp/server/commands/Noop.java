package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** NOOP (RFC 5321 section 4.1.1.9); an argument is allowed and ignored. */
public class Noop extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Noop() {
		super("NOOP");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		p.reply(OK, "2.0.0", "Ok");
	}
}
