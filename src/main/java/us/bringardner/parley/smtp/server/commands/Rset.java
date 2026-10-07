package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** RSET (RFC 5321 section 4.1.1.5): abort the mail transaction. */
public class Rset extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Rset() {
		super("RSET");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!noArgs(p, args)) {
			return;
		}
		p.abortTransaction();
		p.reply(OK, "2.0.0", "Ok");
	}
}
