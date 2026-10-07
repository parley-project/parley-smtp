package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** HELP (RFC 5321 section 4.1.1.8). */
public class Help extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Help() {
		super("HELP");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		p.reply(HELP_MESSAGE, java.util.List.of("2.0.0 Commands: EHLO HELO MAIL RCPT DATA BDAT RSET NOOP QUIT VRFY STARTTLS AUTH HELP",
				"2.0.0 See RFC 5321"));
	}
}
