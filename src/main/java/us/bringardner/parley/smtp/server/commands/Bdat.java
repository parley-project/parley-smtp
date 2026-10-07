package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/**
 * BDAT size [LAST] (CHUNKING, RFC 3030): a chunk of exactly {@code size} bytes
 * follows the command. A refused chunk is still read, so the session stays in step.
 */
public class Bdat extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Bdat() {
		super("BDAT");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		String[] a = args.trim().split(" +");
		long size;
		boolean last = false;
		try {
			size = Long.parseLong(a[0]);
			if (size < 0) {
				throw new NumberFormatException();
			}
			if (a.length == 2 && a[1].equalsIgnoreCase("LAST")) {
				last = true;
			} else if (a.length != 1) {
				throw new NumberFormatException();
			}
		} catch (NumberFormatException e) {
			// can't know how much to skip: close the connection
			p.reply(SYNTAX_ERROR, "5.5.4", "Syntax: BDAT size [LAST]; closing the connection");
			p.close();
			return;
		}
		SmtpRequestProcessor.Transaction t = p.getTransaction();
		if (t == null || t.recipients.isEmpty()) {
			p.getInput().readFully(size, null);
			p.error(BAD_SEQUENCE, "5.5.1", t == null ? "Need MAIL command" : "No valid recipients");
			return;
		}
		p.receiveChunk(t, size, last);
	}
}
