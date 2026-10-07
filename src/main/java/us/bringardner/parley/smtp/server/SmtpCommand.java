package us.bringardner.parley.smtp.server;

import java.io.IOException;

import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.Permission;

/**
 * An SMTP command. As for FtpCommand, Pop3Command and ImapCommand, permissions
 * come from the access control list: a user needs WRITE to send mail after AUTH.
 */
public interface SmtpCommand extends ICommand {

	IPermission SEND_PERMISSION = new Permission("WRITE");

	/**
	 * Run the command.
	 *
	 * @param args the rest of the command line after the verb and one space ("" if none)
	 */
	void execute(SmtpRequestProcessor processor, String args) throws IOException;
}
