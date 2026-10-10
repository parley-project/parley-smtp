package us.bringardner.parley.smtp.server;

import us.bringardner.parley.net.sasl.ISaslAuthenticator;

/**
 * Checks SASL passwords the way the session does everywhere else: through
 * {@link SmtpRequestProcessor#login}, which prepares the user name and password with SASLprep,
 * requires the WRITE permission and, on success, makes the user the session's principal.
 * <p>
 * PLAIN and LOGIN are served. The access control list holds password hashes, which can't answer
 * CRAM-MD5 or SCRAM; a store that has the clear password or SCRAM credentials can offer them by
 * overriding {@link #supports(String)} and the matching lookup.
 */
public class SmtpSaslAuthenticator implements ISaslAuthenticator {

	private final SmtpRequestProcessor processor;

	public SmtpSaslAuthenticator(SmtpRequestProcessor processor) {
		this.processor = processor;
	}

	@Override
	public boolean checkPassword(String user, String password) {
		return processor.login(user, password);
	}

	@Override
	public boolean supports(String mechanism) {
		return "PLAIN".equals(mechanism) || "LOGIN".equals(mechanism);
	}
}
