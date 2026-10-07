package us.bringardner.parley.smtp.queue;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

import us.bringardner.parley.smtp.MailAddress;

/** One recipient of a queued message and how its delivery is going. */
public final class QueuedRecipient {

	public enum Status {
		/** Not delivered yet. */
		PENDING,
		/** Delivered locally or accepted by the next server. */
		DELIVERED,
		/** Given up: returned to the sender. */
		FAILED,
		/** An alias, replaced by its members. */
		EXPANDED
	}

	/** RFC 3461 NOTIFY values. */
	public enum Notify {
		NEVER, SUCCESS, FAILURE, DELAY
	}

	MailAddress address;
	/** ORCPT as given ("rfc822;user@example.com", xtext decoded), or null. */
	String orcpt;
	/** NOTIFY, or null if not given (then failures and delays are reported). */
	Set<Notify> notify;
	Status status = Status.PENDING;
	int attempts;
	long nextAttempt;
	boolean delayNotified;
	/** The last result, e.g. "4.4.1 Connection refused" or the remote reply. */
	String lastResult = "";
	String lastStatus = "";
	String remoteMta;
	/** How many alias expansions led here (to stop loops). */
	int depth;

	public QueuedRecipient(MailAddress address, String orcpt, Set<Notify> notify) {
		this.address = address;
		this.orcpt = orcpt;
		this.notify = notify;
	}

	public MailAddress getAddress() {
		return address;
	}

	public String getOrcpt() {
		return orcpt;
	}

	public Set<Notify> getNotify() {
		return notify;
	}

	public Status getStatus() {
		return status;
	}

	public int getAttempts() {
		return attempts;
	}

	public String getLastResult() {
		return lastResult;
	}

	public String getLastStatus() {
		return lastStatus;
	}

	public String getRemoteMta() {
		return remoteMta;
	}

	/** True if the sender wants to hear about this kind of event. */
	public boolean wants(Notify n) {
		if (notify == null) {
			return n == Notify.FAILURE || n == Notify.DELAY;
		}
		return notify.contains(n);
	}

	/** Parse a NOTIFY parameter ("NEVER" or a list of SUCCESS, FAILURE, DELAY). */
	public static Set<Notify> parseNotify(String value) {
		Set<Notify> ret = EnumSet.noneOf(Notify.class);
		for (String s : value.split(",")) {
			ret.add(Notify.valueOf(s.trim().toUpperCase(Locale.ROOT)));
		}
		if (ret.contains(Notify.NEVER) && ret.size() > 1) {
			throw new IllegalArgumentException("NEVER can't be combined");
		}
		return ret;
	}

	static String formatNotify(Set<Notify> n) {
		if (n == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (Notify x : n) {
			if (sb.length() > 0) {
				sb.append(',');
			}
			sb.append(x.name());
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return address + " " + status;
	}
}
