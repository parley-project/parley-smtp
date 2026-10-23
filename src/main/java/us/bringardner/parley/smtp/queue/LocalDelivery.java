package us.bringardner.parley.smtp.queue;

import us.bringardner.parley.io.IoUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.mail.store.MailStore;
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
	 * What an address of a local domain means here. With several local domains (virtual domains)
	 * an address can be an alias or a user of its own domain ({@code sales@example.com},
	 * {@code tony@example.com}) or, as with one domain, of every local domain ({@code sales},
	 * {@code tony}). Aliases are looked up first, the full address before the local part, then
	 * users the same way; each with a {@code +detail} suffix, then without it. "postmaster" is
	 * always accepted (RFC 5321 section 4.5.1).
	 *
	 * @return the target, or null if the address doesn't exist here
	 * @throws IOException if the user list can't answer now (the recipient is tried again later)
	 */
	public Target find(MailAddress address) throws IOException {
		String local = address.getLocalPart();
		String domain = address.getAsciiDomain();
		List<String> keys = new ArrayList<>(4);
		if (domain != null && !domain.isEmpty()) {
			addKeys(keys, local, "@" + domain.toLowerCase(Locale.ROOT));
		}
		addKeys(keys, local, "");
		return find(keys, local);
	}

	/**
	 * Find a local part: an alias, a user, or "postmaster" (always accepted, RFC
	 * 5321 section 4.5.1). A "+detail" suffix is ignored if the full local part
	 * isn't known. Returns null for an unknown local part.
	 */
	public Target find(String localPart) throws IOException {
		List<String> keys = new ArrayList<>(2);
		addKeys(keys, localPart, "");
		return find(keys, localPart);
	}

	private static void addKeys(List<String> keys, String local, String suffix) {
		keys.add(local + suffix);
		int plus = local.indexOf('+');
		if (plus > 0) {
			keys.add(local.substring(0, plus) + suffix);
		}
	}

	private Target find(List<String> keys, String localPart) throws IOException {
		// aliases first: they need no lookup in the user list (which may be unable to answer)
		for (String k : keys) {
			Target t = findAlias(k);
			if (t != null) {
				return t;
			}
		}
		for (String k : keys) {
			Target t = findUser(k);
			if (t != null) {
				return t;
			}
		}
		if (localPart.equalsIgnoreCase("postmaster")) {
			Target pm = config.getPostmaster().equalsIgnoreCase("postmaster") ? null : findExact(config.getPostmaster());
			return pm != null ? pm : new Target("postmaster", inbox("postmaster"), null);
		}
		return null;
	}

	private Target findExact(String name) throws IOException {
		Target t = findAlias(name);
		return t != null ? t : findUser(name);
	}

	private Target findAlias(String name) {
		List<String> alias = config.getAliases().get(name.toLowerCase(Locale.ROOT));
		return alias == null ? null : new Target(null, null, alias);
	}

	private Target findUser(String name) throws IOException {
		IAccessControlList acl = config.getAccessControl();
		if (acl == null) {
			return null;
		}
		String lower = name.toLowerCase(Locale.ROOT);
		// a list that can't answer throws (an IOException): the recipient is tried again later, not refused
		IPrincipal p = acl.findPrincipal(name);
		if (p == null && !lower.equals(name)) {
			p = acl.findPrincipal(lower);
		}
		if (p == null) {
			return null;
		}
		Object param = p.getParameter(PARAMETER_MAILDROP);
		return new Target(p.getName(), inbox(param != null ? param.toString() : p.getName()), null);
	}

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
		try (InputStream in = new SequenceInputStream(new ByteArrayInputStream(header.getBytes(StandardCharsets.UTF_8)),
				IoUtils.buffered(content.getInputStream()))) {
			return store.deliver(in, entry.quarantine).getUid();
		}
	}
}
