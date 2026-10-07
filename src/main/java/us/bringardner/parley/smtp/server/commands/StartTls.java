package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** STARTTLS (RFC 3207). */
public class StartTls extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public StartTls() {
		super("STARTTLS");
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!noArgs(p, args)) {
			return;
		}
		if (p.isTls()) {
			p.error(BAD_SEQUENCE, "5.5.1", "TLS already active");
			return;
		}
		if (!p.getSmtpServer().isTlsAvailable()) {
			p.reply(TEMP_AUTH_FAILURE, "4.7.0", "TLS not available");
			return;
		}
		p.reply(SERVICE_READY, "2.0.0", "Ready to start TLS");
		p.startTls();
	}
}
