package us.bringardner.parley.smtp.queue;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.mail.store.MailboxConstants;
import us.bringardner.parley.mail.store.MailStore;
import us.bringardner.parley.mail.store.Mailbox;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.smtp.MailAddress;

/**
 * Delivery to local users: the message goes into the user's INBOX, which is the
 * same directory the POP3 and IMAP servers use (the principal's
 * {@code maildrop} parameter, or the user name, under the maildrop root).
 * IMAP sessions with INBOX selected see it at once.
 */
public final class LocalDelivery {

	/** Principal parameter naming the user's maildrop, as for POP3 and IMAP. */
	public static final String PARAMETER_MAILDROP = "maildrop";

	/** What a local part means here. */
	public static final class Target {
		/** The user (principal) name, or null for an alias. */
		public final String user;
		/** The user's INBOX directory. */
		public final FileSource inbox;
		/** For an alias: its members (user names or addresses). */
		public final List<String> members;

		Target(String user, FileSource inbox, List<String> members) {
			this.user = user;
			this.inbox = inbox;
			this.members = members;
		}
	}

	private final DeliveryConfig config;

	public LocalDelivery(DeliveryConfig config) {
		this.config = config;
	}

	/**
	 * Find a local part: an alias, a user, or "postmaster" (always accepted, RFC
	 * 5321 section 4.5.1). A "+detail" suffix is ignored if the full local part
	 * isn't known. Returns null for an unknown local part.
	 */
	public Target find(String localPart) throws IOException {
		Target t = findExact(localPart);
		if (t == null) {
			int plus = localPart.indexOf('+');
			if (plus > 0) {
				t = findExact(localPart.substring(0, plus));
			}
		}
		if (t == null && localPart.equalsIgnoreCase("postmaster")) {
			Target pm = config.getPostmaster().equalsIgnoreCase("postmaster") ? null : findExact(config.getPostmaster());
			t = pm != null ? pm : new Target("postmaster", inbox("postmaster"), null);
		}
		return t;
	}

	private Target findExact(String localPart) throws IOException {
		String lower = localPart.toLowerCase(Locale.ROOT);
		List<String> alias = config.getAliases().get(lower);
		if (alias != null) {
			return new Target(null, null, alias);
		}
		IAccessControlList acl = config.getAccessControl();
		if (acl == null) {
			return null;
		}
		IPrincipal p = acl.getPrincipal(localPart);
		if (p == null && !lower.equals(localPart)) {
			p = acl.getPrincipal(lower);
		}
		if (p == null) {
			return null;
		}
		Object param = p.getParameter(PARAMETER_MAILDROP);
		return new Target(p.getName(), inbox(param != null ? param.toString() : p.getName()), null);
	}

	/** A maildrop directory for a path relative to the root (".." can't leave it). */
	FileSource inbox(String path) throws IOException {
		ArrayDeque<String> segments = new ArrayDeque<>();
		for (String s : path.replace('\\', '/').split("/")) {
			if (s.isEmpty() || s.equals(".")) {
				continue;
			}
			if (s.equals("..")) {
				segments.pollLast();
			} else {
				segments.add(s);
			}
		}
		if (segments.isEmpty()) {
			throw new IOException("Invalid maildrop path '" + path + "'");
		}
		FileSource dir = config.getMaildropRoot();
		for (String s : segments) {
			dir = dir.getChild(s);
		}
		return dir;
	}

	/**
	 * The user's Junk mailbox: the one marked \\Junk (RFC 6154), else "Junk",
	 * created (and marked) if missing.
	 */
	static String junkMailbox(MailStore store) throws IOException {
		for (MailStore.Entry e : store.listAll()) {
			if (MailboxConstants.JUNK.equalsIgnoreCase(e.specialUse) && !e.noselect) {
				return e.name;
			}
		}
		if (!store.exists("Junk")) {
			store.create("Junk", MailboxConstants.JUNK);
		}
		return "Junk";
	}

	/**
	 * Deliver a queued message to a user's INBOX, adding Return-Path (RFC 5321
	 * section 4.4) and Delivered-To.
	 *
	 * @return the new message's UID
	 */
	public long deliver(QueueEntry entry, FileSource content, MailAddress recipient, Target target) throws IOException {
		String header = "Return-Path: <" + (entry.from == null ? "" : entry.from.toString()) + ">\r\n"
				+ "Delivered-To: " + recipient + "\r\n";
		MailStore store = new MailStore(target.inbox, MailboxRegistry.get());
		store.init(config.isCreateDefaultMailboxes());
		Mailbox mb = store.open(entry.quarantine ? junkMailbox(store) : "INBOX");
		try (InputStream in = new SequenceInputStream(new ByteArrayInputStream(header.getBytes(StandardCharsets.UTF_8)),
				new BufferedInputStream(content.getInputStream(), 64 * 1024))) {
			return mb.append(in, java.util.Set.of(), System.currentTimeMillis()).getUid();
		} finally {
			MailboxRegistry.get().release(mb);
		}
	}
}
