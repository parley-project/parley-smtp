package us.bringardner.parley.smtp.abuse;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.AAAA;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Ptr;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.ReverseName;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.spf.SpfDns;

/**
 * The checks an SMTP server makes of a client before it reads a message: block lists, reverse DNS,
 * the HELO name, a pregreet wait and rate limits per client address. Every check is off until it is
 * set, and the server skips them for clients that may relay (a trusted network or a login).
 * <p>
 * With {@link #setLogOnly} a failed check is only reported, so a new rule can be watched on live
 * mail before it refuses any.
 */
public final class ConnectionChecks {

	/** The refusal for a client: an SMTP reply code, its enhanced status and the text. */
	public static final class Refusal {
		public final int code;
		public final String enhanced;
		public final String text;
		/** The check that refused, for the log. */
		public final String check;

		Refusal(int code, String enhanced, String text, String check) {
			this.code = code;
			this.enhanced = enhanced;
			this.text = text;
			this.check = check;
		}

		@Override
		public String toString() {
			return check + ": " + code + " " + enhanced + " " + text;
		}
	}

	private final Dnsbl dnsbl = new Dnsbl();
	private final RateLimiter connections = new RateLimiter(60_000);
	private final RateLimiter messages = new RateLimiter(60_000);
	private final RateLimiter recipients = new RateLimiter(60_000);
	private final Map<String, AtomicInteger> open = new ConcurrentHashMap<>();

	private volatile boolean logOnly;
	private volatile boolean requireReverseDns;
	private volatile boolean checkHelo;
	private volatile long pregreetMillis;
	private volatile int maxConnectionsPerMinute;
	private volatile int maxConcurrentPerAddress;
	private volatile int maxMessagesPerMinute;
	private volatile int maxRecipientsPerMinute;

	/** The block lists (checked when a client connects). */
	public Dnsbl getDnsbl() {
		return dnsbl;
	}

	/** Report failed checks without refusing anything (default false). */
	public void setLogOnly(boolean logOnly) {
		this.logOnly = logOnly;
	}

	public boolean isLogOnly() {
		return logOnly;
	}

	/**
	 * Refuse MAIL (450 4.7.25) from a client address that has no reverse name that resolves back to
	 * the address (forward-confirmed reverse DNS). Default false.
	 */
	public void setRequireReverseDns(boolean require) {
		this.requireReverseDns = require;
	}

	public boolean isRequireReverseDns() {
		return requireReverseDns;
	}

	/**
	 * Refuse a HELO/EHLO name that isn't a host name or address literal, or that claims to be this
	 * server or one of its domains (550 5.7.1). Default false.
	 */
	public void setCheckHelo(boolean checkHelo) {
		this.checkHelo = checkHelo;
	}

	public boolean isCheckHelo() {
		return checkHelo;
	}

	/**
	 * Wait this long before the greeting, and refuse a client that sends anything meanwhile (real
	 * servers wait for the greeting; many spam tools don't). 0 (default) turns the check off.
	 */
	public void setPregreetMillis(long millis) {
		this.pregreetMillis = millis;
	}

	public long getPregreetMillis() {
		return pregreetMillis;
	}

	/** The most connections one address may open in a minute (421 4.7.0 above that); 0: no limit. */
	public void setMaxConnectionsPerMinute(int max) {
		this.maxConnectionsPerMinute = max;
	}

	public int getMaxConnectionsPerMinute() {
		return maxConnectionsPerMinute;
	}

	/** The most connections one address may have open at once (421 4.7.0 above that); 0: no limit. */
	public void setMaxConcurrentPerAddress(int max) {
		this.maxConcurrentPerAddress = max;
	}

	public int getMaxConcurrentPerAddress() {
		return maxConcurrentPerAddress;
	}

	/** The most MAIL commands one address may send in a minute (450 4.7.1 above that); 0: no limit. */
	public void setMaxMessagesPerMinute(int max) {
		this.maxMessagesPerMinute = max;
	}

	public int getMaxMessagesPerMinute() {
		return maxMessagesPerMinute;
	}

	/** The most RCPT commands one address may send in a minute (450 4.7.1 above that); 0: no limit. */
	public void setMaxRecipientsPerMinute(int max) {
		this.maxRecipientsPerMinute = max;
	}

	public int getMaxRecipientsPerMinute() {
		return maxRecipientsPerMinute;
	}

	/** Forget the counts of the rate limits (the limits stay). */
	public void resetCounters() {
		connections.clear();
		messages.clear();
		recipients.clear();
	}

	// ------------------------------------------------------------------ the checks

	/**
	 * A new connection from the address: the concurrent and per-minute limits. A connection that is
	 * counted (the result is null) must be ended with {@link #leave}.
	 *
	 * @return why the client is refused, or null
	 */
	public Refusal enter(InetAddress ip) {
		String key = key(ip);
		int now = open.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
		int maxOpen = maxConcurrentPerAddress;
		if (maxOpen > 0 && now > maxOpen) {
			return new Refusal(SERVICE_BUSY, "4.7.0", "Too many connections from your address", "concurrent");
		}
		if (!connections.tryAcquire(key, maxConnectionsPerMinute)) {
			return new Refusal(SERVICE_BUSY, "4.7.0", "Too many connections from your address, try later", "connection-rate");
		}
		return null;
	}

	/** The connection counted by {@link #enter} has ended. */
	public void leave(InetAddress ip) {
		String key = key(ip);
		AtomicInteger n = open.get(key);
		if (n != null && n.decrementAndGet() <= 0) {
			open.remove(key, n);
		}
	}

	/** The block lists: the refusal if one lists the address, else null. */
	public Refusal checkBlockList(InetAddress ip, SpfDns dns) {
		String zone = dnsbl.listedIn(ip, dns);
		if (zone == null) {
			return null;
		}
		return new Refusal(TRANSACTION_FAILED, "5.7.1",
				"Service unavailable; client [" + ip.getHostAddress() + "] blocked using " + zone, "dnsbl " + zone);
	}

	/** A client that sent data before the greeting: the refusal. */
	public Refusal pregreet() {
		return new Refusal(TRANSACTION_FAILED, "5.5.0", "Protocol error: you spoke before the greeting", "pregreet");
	}

	/**
	 * Forward-confirmed reverse DNS: a PTR name of the address whose A/AAAA records include the
	 * address. A DNS error is not a failure (the client tries again later, or isn't asked).
	 *
	 * @return the refusal, or null if the name is confirmed, DNS can't say, or the check is off
	 */
	public Refusal checkReverseDns(InetAddress ip, SpfDns dns) {
		if (!requireReverseDns || Dnsbl.isLocal(ip)) {
			return null;
		}
		LookupResult<RR> ptr = dns.lookup(ReverseName.of(ip), DNS.PTR);
		if (ptr.isTempFail()) {
			return null;
		}
		boolean v6 = ip instanceof Inet6Address;
		if (ptr.isOk()) {
			int n = 0;
			for (RR rr : ptr.getValues()) {
				if (rr.getType() != DNS.PTR || ++n > 10) {
					continue;
				}
				String name = (rr instanceof Ptr ? (Ptr) rr : new Ptr(rr)).getPtr();
				LookupResult<RR> fwd = dns.lookup(name, v6 ? DNS.AAAA : DNS.A);
				if (fwd.isTempFail()) {
					return null;
				}
				if (fwd.isOk() && contains(fwd.getValues(), ip, v6)) {
					return null;
				}
			}
		}
		return new Refusal(MAILBOX_BUSY, "4.7.25",
				"Client host rejected: cannot find your reverse hostname [" + ip.getHostAddress() + "]", "reverse-dns");
	}

	private static boolean contains(List<RR> records, InetAddress ip, boolean v6) {
		for (RR rr : records) {
			try {
				byte[] b = null;
				if (!v6 && rr.getType() == DNS.A) {
					b = (rr instanceof A ? (A) rr : new A(rr)).getAddress();
				} else if (v6 && rr.getType() == DNS.AAAA) {
					b = (rr instanceof AAAA ? (AAAA) rr : new AAAA(rr)).getAddress();
				}
				if (b != null && java.util.Arrays.equals(b, ip.getAddress())) {
					return true;
				}
			} catch (RuntimeException e) {
				// a malformed record
			}
		}
		return false;
	}

	/**
	 * The HELO/EHLO name: it must be a host name with a dot or an address literal, and must not be
	 * this server's name or one of its domains (a client of another network never is).
	 *
	 * @param own this server's host name and its local domains
	 */
	public Refusal checkHelo(String helo, Collection<String> own) {
		if (!checkHelo) {
			return null;
		}
		String h = helo.trim().toLowerCase(Locale.ROOT);
		boolean literal = h.startsWith("[") && h.endsWith("]");
		if (!literal && (!MailAddress.isDomain(h) || h.indexOf('.') < 0 || h.endsWith(".invalid") || h.endsWith(".local")
				|| h.endsWith(".localdomain"))) {
			return new Refusal(MAILBOX_UNAVAILABLE, "5.7.1", "Helo command rejected: need fully-qualified hostname", "helo-syntax");
		}
		for (String o : own) {
			if (o != null && o.equalsIgnoreCase(h)) {
				return new Refusal(MAILBOX_UNAVAILABLE, "5.7.1", "Helo command rejected: you are not " + o, "helo-impersonation");
			}
		}
		return null;
	}

	/** One more MAIL from the address: the refusal if it is over the limit. */
	public Refusal checkMessageRate(InetAddress ip) {
		if (messages.tryAcquire(key(ip), maxMessagesPerMinute)) {
			return null;
		}
		return new Refusal(MAILBOX_BUSY, "4.7.1", "Too many messages from your address, try later", "message-rate");
	}

	/** One more RCPT from the address: the refusal if it is over the limit. */
	public Refusal checkRecipientRate(InetAddress ip) {
		if (recipients.tryAcquire(key(ip), maxRecipientsPerMinute)) {
			return null;
		}
		return new Refusal(MAILBOX_BUSY, "4.7.1", "Too many recipients from your address, try later", "recipient-rate");
	}

	private static String key(InetAddress ip) {
		return ip.getHostAddress();
	}

	private static final int SERVICE_BUSY = 421;
	private static final int MAILBOX_BUSY = 450;
	private static final int MAILBOX_UNAVAILABLE = 550;
	private static final int TRANSACTION_FAILED = 554;

}
