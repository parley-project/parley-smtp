package us.bringardner.parley.smtp.queue;

import javax.management.ConstructorParameters;

/**
 * A recipient of a queued message, as {@link MailQueueMXBean} shows it.
 *
 * @since 2.0.0
 */
public final class QueuedRecipientInfo {

	private final String address;
	private final String status;
	private final int attempts;
	private final long nextAttempt;
	private final String lastStatus;
	private final String lastResult;
	private final String remoteMta;

	@ConstructorParameters({ "address", "status", "attempts", "nextAttempt", "lastStatus", "lastResult", "remoteMta" })
	public QueuedRecipientInfo(String address, String status, int attempts, long nextAttempt, String lastStatus, String lastResult,
			String remoteMta) {
		this.address = address;
		this.status = status;
		this.attempts = attempts;
		this.nextAttempt = nextAttempt;
		this.lastStatus = lastStatus;
		this.lastResult = lastResult;
		this.remoteMta = remoteMta;
	}

	static QueuedRecipientInfo of(QueuedRecipient r) {
		return new QueuedRecipientInfo(String.valueOf(r.getAddress()), r.getStatus().name(), r.getAttempts(), r.getNextAttempt(),
				r.getLastStatus(), r.getLastResult(), r.getRemoteMta());
	}

	public String getAddress() {
		return address;
	}

	/** PENDING, DELIVERED, FAILED or EXPANDED */
	public String getStatus() {
		return status;
	}

	public int getAttempts() {
		return attempts;
	}

	public long getNextAttempt() {
		return nextAttempt;
	}

	/** The enhanced status code of the last attempt (e.g. 4.4.1), or null */
	public String getLastStatus() {
		return lastStatus;
	}

	public String getLastResult() {
		return lastResult;
	}

	public String getRemoteMta() {
		return remoteMta;
	}
}
