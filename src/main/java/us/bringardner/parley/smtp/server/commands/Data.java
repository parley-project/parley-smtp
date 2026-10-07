package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.queue.QueueEntry;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/**
 * DATA (RFC 5321 section 4.1.1.4): the content follows, dot-stuffed, up to
 * CRLF "." CRLF. The message is in the queue before the 250 reply.
 */
public class Data extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Data() {
		super("DATA");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!noArgs(p, args)) {
			return;
		}
		SmtpRequestProcessor.Transaction t = p.getTransaction();
		if (t == null) {
			p.error(BAD_SEQUENCE, "5.5.1", "Need MAIL command");
			return;
		}
		if (t.recipients.isEmpty()) {
			p.error(TRANSACTION_FAILED, "5.5.1", "No valid recipients");
			return;
		}
		if (t.bdatUsed) {
			p.error(BAD_SEQUENCE, "5.5.1", "DATA after BDAT");
			return;
		}
		if (t.body == QueueEntry.Body.BINARY) {
			// RFC 3030 section 3: BINARYMIME content must be sent with BDAT
			p.error(BAD_SEQUENCE, "5.5.1", "BODY=BINARYMIME requires BDAT");
			return;
		}
		p.reply(START_MAIL_INPUT, null, "End data with <CR><LF>.<CR><LF>");
		p.flush();
		p.receiveData(t);
	}
}
