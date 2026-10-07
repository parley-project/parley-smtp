package us.bringardner.parley.smtp.queue;

import java.io.IOException;

/**
 * A delivery that didn't succeed: temporary (try again later) or permanent
 * (return the message), with an enhanced status code (RFC 3463) and, for a
 * remote server's refusal, its reply.
 */
public class DeliveryException extends IOException {

	private static final long serialVersionUID = 1L;

	private final boolean permanent;
	private final String status;
	private final String diagnostic;
	private final String remoteMta;

	/**
	 * @param status     enhanced status code, e.g. "5.1.1"
	 * @param diagnostic "smtp; 550 5.1.1 ..." for a remote reply, or null
	 */
	public DeliveryException(boolean permanent, String status, String message, String diagnostic, String remoteMta) {
		super(message);
		this.permanent = permanent;
		this.status = status;
		this.diagnostic = diagnostic;
		this.remoteMta = remoteMta;
	}

	public DeliveryException(boolean permanent, String status, String message) {
		this(permanent, status, message, null, null);
	}

	public static DeliveryException temporary(String status, String message) {
		return new DeliveryException(false, status, message);
	}

	public static DeliveryException permanent(String status, String message) {
		return new DeliveryException(true, status, message);
	}

	public boolean isPermanent() {
		return permanent;
	}

	public String getStatus() {
		return status;
	}

	public String getDiagnostic() {
		return diagnostic;
	}

	public String getRemoteMta() {
		return remoteMta;
	}
}
