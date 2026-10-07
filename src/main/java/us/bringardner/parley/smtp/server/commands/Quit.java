package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** QUIT (RFC 5321 section 4.1.1.10). */
public class Quit extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Quit() {
		super("QUIT");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		p.abortTransaction();
		p.reply(SERVICE_CLOSING, "2.0.0", "Bye");
		p.close();
	}
}
