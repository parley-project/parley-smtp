package us.bringardner.parley.smtp.server;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.smtp.server.commands.Auth;
import us.bringardner.parley.smtp.server.commands.Bdat;
import us.bringardner.parley.smtp.server.commands.Data;
import us.bringardner.parley.smtp.server.commands.Ehlo;
import us.bringardner.parley.smtp.server.commands.Expn;
import us.bringardner.parley.smtp.server.commands.Helo;
import us.bringardner.parley.smtp.server.commands.Help;
import us.bringardner.parley.smtp.server.commands.Mail;
import us.bringardner.parley.smtp.server.commands.Noop;
import us.bringardner.parley.smtp.server.commands.Quit;
import us.bringardner.parley.smtp.server.commands.Rcpt;
import us.bringardner.parley.smtp.server.commands.Rset;
import us.bringardner.parley.smtp.server.commands.StartTls;
import us.bringardner.parley.smtp.server.commands.Vrfy;

/**
 * Maps SMTP verbs to their command classes (as FtpCommandFactory does for FTP).
 * Commands can be replaced or added with {@link #addCommand(ICommand)}.
 */
public class SmtpCommandFactory implements ICommandFactory {

	private static final long serialVersionUID = 1L;

	private static final Map<String, ICommand> commands = Collections.synchronizedMap(new HashMap<>());

	static {
		// RFC 5321 section 4.1.1
		addCommand(new Ehlo());
		addCommand(new Helo());
		addCommand(new Mail());
		addCommand(new Rcpt());
		addCommand(new Data());
		addCommand(new Rset());
		addCommand(new Vrfy());
		addCommand(new Expn());
		addCommand(new Help());
		addCommand(new Noop());
		addCommand(new Quit());
		// extensions
		addCommand(new StartTls()); // RFC 3207
		addCommand(new Auth()); // RFC 4954
		addCommand(new Bdat()); // RFC 3030
	}

	public static void addCommand(ICommand cmd) {
		commands.put(cmd.getName().toUpperCase(Locale.ROOT), cmd);
	}

	@Override
	public ICommand getCommand(IRequestContext context) {
		String name = context.getFirstToken();
		return name == null ? null : getCommand(name);
	}

	public ICommand getCommand(String name) {
		return commands.get(name.toUpperCase(Locale.ROOT));
	}
}
