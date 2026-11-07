package us.bringardner.parley.smtp.server;

import java.io.IOException;

import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.iam.permission.StandardPermissions;
import us.bringardner.parley.net.server.ICommand;

/**
 * An SMTP command. As for FtpCommand, Pop3Command and ImapCommand, the server's user
 * registry decides permissions: a user needs {@code write} to send mail after AUTH.
 */
public interface SmtpCommand extends ICommand {

	/** write on the server as a whole: what an authenticated user needs to send mail */
	ParleyPermission SEND_PERMISSION = new BasicParleyPermission(StandardPermissions.WRITE, null);

	/**
	 * Run the command.
	 *
	 * @param args the rest of the command line after the verb and one space ("" if none)
	 */
	void execute(SmtpRequestProcessor processor, String args) throws IOException;
}
