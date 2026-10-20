package us.bringardner.parley.smtp.server;

import us.bringardner.parley.net.sasl.ISaslAuthenticator;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.sasl.ScramMechanism;

/**
 * Checks SASL passwords the way the session does everywhere else: through
 * {@link SmtpRequestProcessor#login}, which prepares the user name and password with SASLprep,
 * requires the WRITE permission and, on success, makes the user the session's principal.
 * <p>
 * PLAIN and LOGIN are served, and SCRAM-SHA-1 and SCRAM-SHA-256 when the server's access control
 * list keeps SCRAM credentials. SCRAM checks no password here: after it succeeds, the AUTH
 * command logs the user in with {@link SmtpRequestProcessor#loginVerified(String)}. CRAM-MD5
 * needs the clear password, which a hash can't give, so it isn't served.
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
		if ("PLAIN".equals(mechanism) || "LOGIN".equals(mechanism)) {
			return true;
		}
		String hash = ScramMechanism.hashOf(mechanism);
		return hash != null && processor.supportsScram(hash);
	}

	/** SCRAM credentials from the server's access control list (the name prepared with SASLprep). */
	@Override
	public ScramCredentials getScramCredentials(String user, String hash) {
		return processor.getScramCredentials(user, hash);
	}
}
