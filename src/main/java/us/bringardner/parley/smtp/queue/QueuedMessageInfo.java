package us.bringardner.parley.smtp.queue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.management.ConstructorParameters;

/**
 * A message in the queue, as {@link MailQueueMXBean} shows it (a snapshot).
 *
 * @since 2.0.0
 */
public final class QueuedMessageInfo {

	private final String id;
	private final long created;
	private final String from;
	private final long size;
	private final String submitter;
	private final boolean inbound;
	private final boolean quarantine;
	private final long nextAttempt;
	private final List<QueuedRecipientInfo> recipients;

	@ConstructorParameters({ "id", "created", "from", "size", "submitter", "inbound", "quarantine", "nextAttempt", "recipients" })
	public QueuedMessageInfo(String id, long created, String from, long size, String submitter, boolean inbound, boolean quarantine,
			long nextAttempt, List<QueuedRecipientInfo> recipients) {
		this.id = id;
		this.created = created;
		this.from = from;
		this.size = size;
		this.submitter = submitter;
		this.inbound = inbound;
		this.quarantine = quarantine;
		this.nextAttempt = nextAttempt;
		this.recipients = recipients == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(recipients));
	}

	/** A snapshot of an entry */
	public static QueuedMessageInfo of(QueueEntry e) {
		synchronized (e) {
			List<QueuedRecipientInfo> list = new ArrayList<>();
			for (QueuedRecipient r : e.getRecipients()) {
				list.add(QueuedRecipientInfo.of(r));
			}
			long next = e.nextAttempt();
			return new QueuedMessageInfo(e.getId(), e.getCreated(), e.getFrom() == null ? "" : e.getFrom().toString(), e.getSize(),
					e.getSubmitter(), e.isInbound(), e.isQuarantine(), next == Long.MAX_VALUE ? 0 : next, list);
		}
	}

	public String getId() {
		return id;
	}

	public long getCreated() {
		return created;
	}

	/** The reverse-path; empty for {@code <>} */
	public String getFrom() {
		return from;
	}

	public long getSize() {
		return size;
	}

	/** Who sent it (the logged in user), or null */
	public String getSubmitter() {
		return submitter;
	}

	public boolean isInbound() {
		return inbound;
	}

	public boolean isQuarantine() {
		return quarantine;
	}

	/** When a pending recipient is next tried (ms), or 0 */
	public long getNextAttempt() {
		return nextAttempt;
	}

	public List<QueuedRecipientInfo> getRecipients() {
		return recipients;
	}
}
