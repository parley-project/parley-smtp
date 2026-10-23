package us.bringardner.parley.smtp.queue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Something that happened to a message in the {@link MailQueue}, reported to its
 * {@link QueueListener}s: a message was queued, a delivery attempt for a recipient ended, the
 * message left the queue. The values are a snapshot taken when the event happened.
 * <p>
 * The queue keeps no history of its own (a message is removed when every recipient is done), so
 * a listener is how an application records one.
 */
public final class QueueEvent {

	public enum Type {
		/** A message was put in the queue ({@link #getRecipients()} lists its recipients). */
		QUEUED,
		/** A recipient was delivered locally or accepted by the next server. */
		DELIVERED,
		/** A delivery attempt for a recipient failed temporarily; it is tried again later. */
		DEFERRED,
		/** A recipient failed permanently (or the queue gave up on it); it is returned to the sender. */
		FAILED,
		/** A recipient was an alias, replaced by its members (which get events of their own). */
		EXPANDED,
		/** Every recipient is done: the message left the queue. */
		COMPLETED,
		/** The message was removed from the queue by {@link MailQueue#delete(String)}. */
		DELETED
	}

	private final Type type;
	private final long time;
	private final String id;
	private final String from;
	private final long size;
	private final String submitter;
	private final boolean inbound;
	private final List<String> recipients;
	private final String recipient;
	private final String status;
	private final String result;
	private final String remoteMta;
	private final int attempts;
	private final long nextAttempt;

	private QueueEvent(Type type, QueueEntry e, QueuedRecipient r) {
		this.type = type;
		this.time = System.currentTimeMillis();
		this.id = e.id;
		this.from = e.from == null ? "" : e.from.toString();
		this.size = e.size;
		this.submitter = e.submitter;
		this.inbound = e.inbound;
		List<String> list = new ArrayList<>();
		for (QueuedRecipient q : e.recipients) {
			if (q.status != QueuedRecipient.Status.EXPANDED) {
				list.add(q.address.toString());
			}
		}
		this.recipients = Collections.unmodifiableList(list);
		this.recipient = r == null ? null : r.address.toString();
		this.status = r == null ? null : r.lastStatus;
		this.result = r == null ? null : r.lastResult;
		this.remoteMta = r == null ? null : r.remoteMta;
		this.attempts = r == null ? 0 : r.attempts;
		this.nextAttempt = r == null || r.status != QueuedRecipient.Status.PENDING ? 0 : r.nextAttempt;
	}

	static QueueEvent of(Type type, QueueEntry e) {
		return new QueueEvent(type, e, null);
	}

	/** The event for a recipient after an attempt, by its status. */
	static QueueEvent attempt(QueueEntry e, QueuedRecipient r) {
		Type t;
		switch (r.status) {
		case DELIVERED:
			t = Type.DELIVERED;
			break;
		case FAILED:
			t = Type.FAILED;
			break;
		case EXPANDED:
			t = Type.EXPANDED;
			break;
		default:
			t = Type.DEFERRED;
		}
		return new QueueEvent(t, e, r);
	}

	public Type getType() {
		return type;
	}

	/** When it happened (milliseconds since the epoch). */
	public long getTime() {
		return time;
	}

	/** The queue id of the message. */
	public String getId() {
		return id;
	}

	/** The reverse-path, or "" for {@code <>} (a bounce). */
	public String getFrom() {
		return from;
	}

	public long getSize() {
		return size;
	}

	/** The authenticated user who submitted the message, or null. */
	public String getSubmitter() {
		return submitter;
	}

	/** True for mail received from another server. */
	public boolean isInbound() {
		return inbound;
	}

	/** The message's recipients (aliases already expanded are left out). */
	public List<String> getRecipients() {
		return recipients;
	}

	/** The recipient of a DELIVERED, DEFERRED, FAILED or EXPANDED event, else null. */
	public String getRecipient() {
		return recipient;
	}

	/** The enhanced status code of the attempt (e.g. 2.0.0, 4.4.1, 5.1.1), or null. */
	public String getStatus() {
		return status;
	}

	/** What happened, e.g. "delivered to tony" or the remote server's reply, or null. */
	public String getResult() {
		return result;
	}

	/** The server that accepted or refused the message, or null. */
	public String getRemoteMta() {
		return remoteMta;
	}

	/** The recipient's attempts so far. */
	public int getAttempts() {
		return attempts;
	}

	/** For DEFERRED: when the recipient is tried next, else 0. */
	public long getNextAttempt() {
		return nextAttempt;
	}

	@Override
	public String toString() {
		return type + " " + id + (recipient != null ? " " + recipient + " " + status + " " + result : "");
	}
}
