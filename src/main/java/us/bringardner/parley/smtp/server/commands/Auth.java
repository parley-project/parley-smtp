package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.net.sasl.ISaslChannel;
import us.bringardner.parley.net.sasl.ISaslMechanism;
import us.bringardner.parley.net.sasl.SaslMechanisms;
import us.bringardner.parley.net.sasl.SaslOutcome;
import us.bringardner.parley.net.sasl.SaslServerDriver;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;
import us.bringardner.parley.smtp.server.SmtpSaslAuthenticator;

/**
 * AUTH mechanism [initial-response] (RFC 4954). The exchange itself is run by
 * {@link SaslServerDriver}; this class supplies the SMTP parts: the "334" continuations, "*" to
 * cancel, "=" for an empty response, and the replies. Which mechanisms are offered is decided by
 * {@link SmtpSaslAuthenticator} (PLAIN, RFC 4616, and LOGIN).
 */
public class Auth extends BaseCommand {

	private static final long serialVersionUID = 1L;

	/** Every mechanism known; the authenticator limits what is offered. */
	private static final SaslMechanisms MECHANISMS = SaslMechanisms.standard("smtp");

	public Auth() {
		super("AUTH");
	}

	/**
	 * @return the mechanism names to advertise to this session. Whether a plaintext mechanism may
	 *         be used before TLS is a policy of the server (require TLS), checked by the caller.
	 */
	public static List<String> mechanisms(SmtpRequestProcessor p) {
		return MECHANISMS.offered(new SmtpSaslAuthenticator(p), true);
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		if (!p.isEsmtp()) {
			p.error(BAD_SEQUENCE, "5.5.1", "Send EHLO first");
			return;
		}
		if (p.isAuthenticated()) {
			p.error(BAD_SEQUENCE, "5.5.1", "Already authenticated");
			return;
		}
		if (p.getTransaction() != null) {
			p.error(BAD_SEQUENCE, "5.5.1", "AUTH not allowed during a mail transaction");
			return;
		}
		if (p.getSmtpServer().isRequireTls() && !p.isTls()) {
			p.error(ENCRYPTION_REQUIRED, "5.7.11", "Encryption required for requested authentication mechanism");
			return;
		}
		String[] a = args.trim().split(" +");
		String name = a[0].toUpperCase(Locale.ROOT);
		String initial = a.length > 1 ? a[1] : null;
		SmtpSaslAuthenticator authenticator = new SmtpSaslAuthenticator(p);
		ISaslMechanism mechanism = MECHANISMS.find(name);
		if (mechanism == null || !MECHANISMS.offered(authenticator, true).contains(mechanism.getName())) {
			p.error(PARAMETER_NOT_IMPLEMENTED, "5.5.4", "Unrecognized authentication type");
			return;
		}
		SaslOutcome outcome = SaslServerDriver.authenticate(mechanism, authenticator, initial, new ISaslChannel() {
			@Override
			public void sendChallenge(String base64) throws IOException {
				p.reply(AUTH_CONTINUE + " " + base64);
			}

			@Override
			public String readResponse() throws IOException {
				return p.readLine();
			}
		});
		switch (outcome.getStatus()) {
		case SUCCESS:
			p.reply(AUTH_SUCCEEDED, "2.7.0", "Authentication successful");
			break;
		case FAILED:
			p.authFailed();
			break;
		case CANCELLED:
			p.error(PARAMETER_ERROR, "5.0.0", "Authentication cancelled");
			break;
		case MALFORMED:
			p.error(PARAMETER_ERROR, "5.5.2", "Invalid base64 data");
			break;
		default:
			// CLOSED: the client went away
			p.close();
			break;
		}
	}
}
