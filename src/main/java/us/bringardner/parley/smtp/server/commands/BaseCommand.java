package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;

import us.bringardner.parley.net.server.AbstractCommand;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.smtp.SMTP;
import us.bringardner.parley.smtp.server.SmtpCommand;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** Base for SMTP commands. */
public abstract class BaseCommand extends AbstractCommand implements SmtpCommand, SMTP {

	private static final long serialVersionUID = 1L;


	protected BaseCommand(String command) {
		super(command);
	}

	@Override
	public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
		String line = context.getCommandLine();
		int sp = line == null ? -1 : line.indexOf(' ');
		execute((SmtpRequestProcessor) processor, sp < 0 ? "" : line.substring(sp + 1));
	}

	@Override
	public IPermission getPermission() {
		return SEND_PERMISSION;
	}

	@Override
	public boolean requiresAuthorization() {
		return false;
	}

	/** Replies 503 and returns false before EHLO/HELO. */
	protected static boolean checkHello(SmtpRequestProcessor p) throws IOException {
		if (p.getHelo() == null) {
			p.error(BAD_SEQUENCE, "5.5.1", "Send HELO or EHLO first");
			return false;
		}
		return true;
	}

	/** Replies 501 and returns false if the command has arguments. */
	protected static boolean noArgs(SmtpRequestProcessor p, String args) throws IOException {
		if (!args.trim().isEmpty()) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax error: no parameters allowed");
			return false;
		}
		return true;
	}
}
