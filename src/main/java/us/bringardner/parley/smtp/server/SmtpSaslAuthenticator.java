package us.bringardner.parley.smtp.server;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.mail.server.MailSaslAuthenticator;

/**
 * Checks SASL logins for AUTH the way the session does everywhere else: parley-mail's
 * {@link MailSaslAuthenticator} prepares the user name and password with SASLprep and logs the
 * session in through the server's user registry; this class adds SMTP's rule that a user needs
 * the {@link SmtpCommand#SEND_PERMISSION send permission} to log in at all.
 * <p>
 * PLAIN and LOGIN are offered when the registry checks passwords, and SCRAM-SHA-1 and
 * SCRAM-SHA-256 when it keeps SCRAM credentials. SCRAM checks no password here: after it
 * succeeds, the AUTH command logs the user in with {@link #verified(String)}. CRAM-MD5 needs the
 * clear password, which a hash can't give, so it isn't offered.
 * <p>
 * Every login ends with an {@link AuthenticationResult} ({@link #getResult()}): a user without
 * the send permission is REFUSED (counted like a wrong password), and a registry that can't
 * answer the permission check is UNAVAILABLE, never refused.
 */
public class SmtpSaslAuthenticator extends MailSaslAuthenticator {

	private final SmtpRequestProcessor processor;
	/** The result after the send permission was checked, until the next login is checked */
	private volatile AuthenticationResult checked;

	public SmtpSaslAuthenticator(SmtpRequestProcessor processor) {
		super(processor);
		this.processor = processor;
	}

	/** PLAIN, LOGIN: log in with the password, then require the send permission. */
	@Override
	public boolean checkPassword(String user, String password) {
		checked = null;
		if (!super.checkPassword(user, password)) {
			return false;
		}
		AuthenticationResult r = processor.checkSendPermission(super.getResult());
		checked = r;
		return r.getStatus() == AuthenticationResult.Status.AUTHENTICATED;
	}

	/** After SCRAM succeeded: log the user in, then require the send permission. */
	@Override
	public AuthenticationResult verified(String user) {
		checked = null;
		AuthenticationResult r = processor.checkSendPermission(super.verified(user));
		checked = r;
		return r;
	}

	@Override
	public AuthenticationResult getResult() {
		AuthenticationResult r = checked;
		return r != null ? r : super.getResult();
	}

	/**
	 * @return true if the user registry couldn't answer during this authentication (a login or
	 * the permission check); the login then failed for that reason, not because of the credentials
	 */
	@Override
	public boolean isUnavailable() {
		AuthenticationResult r = checked;
		return super.isUnavailable() || (r != null && r.getStatus() == AuthenticationResult.Status.UNAVAILABLE);
	}
}
