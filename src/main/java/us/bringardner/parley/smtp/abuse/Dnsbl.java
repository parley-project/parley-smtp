package us.bringardner.parley.smtp.abuse;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.ReverseName;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.spf.SpfDns;

/**
 * DNS block lists (RFC 5782): a client address is listed if {@code d.c.b.a.zone} has an A record
 * (an IPv6 address is looked up by its nibbles). Answers are kept for a few minutes, so a busy
 * client costs one lookup per zone, not one per connection.
 * <p>
 * An answer of 127.255.255.x is the list refusing the query (a public resolver, over quota), not a
 * listing, and is ignored. A lookup that fails counts as not listed: a broken list never blocks mail.
 */
public final class Dnsbl {

	private static final long CACHE_MILLIS = 10 * 60_000;
	private static final int MAX_CACHED = 10_000;

	private static final class Entry {
		final String zone;
		final long expires;

		Entry(String zone, long expires) {
			this.zone = zone;
			this.expires = expires;
		}
	}

	private volatile List<String> zones = new ArrayList<>();
	private final Map<String, Entry> cache = new ConcurrentHashMap<>();

	/** The zones to ask (spam.example.org...), in order; the first that lists the address wins. */
	public void setZones(List<String> zones) {
		List<String> z = new ArrayList<>();
		for (String s : zones) {
			String t = s.trim();
			while (t.endsWith(".")) {
				t = t.substring(0, t.length() - 1);
			}
			if (!t.isEmpty()) {
				z.add(t);
			}
		}
		this.zones = z;
		cache.clear();
	}

	public List<String> getZones() {
		return new ArrayList<>(zones);
	}

	public boolean isEnabled() {
		return !zones.isEmpty();
	}

	/**
	 * The first zone that lists the address, or null if none does (or none is set, or the address is
	 * private and so can't be listed).
	 */
	public String listedIn(InetAddress ip, SpfDns dns) {
		List<String> z = zones;
		if (z.isEmpty() || ip == null || isLocal(ip)) {
			return null;
		}
		String key = ip.getHostAddress();
		long now = System.currentTimeMillis();
		Entry e = cache.get(key);
		if (e != null && e.expires > now) {
			return e.zone.isEmpty() ? null : e.zone;
		}
		String reversed = ReverseName.of(ip);
		reversed = reversed.substring(0, reversed.indexOf(ip instanceof Inet6Address ? ".ip6.arpa" : ".in-addr.arpa"));
		String found = "";
		boolean complete = true;
		for (String zone : z) {
			LookupResult<RR> r;
			try {
				r = dns.lookup(reversed + "." + zone, DNS.A);
			} catch (RuntimeException ex) {
				complete = false;
				continue;
			}
			if (r.isTempFail()) {
				complete = false;
			} else if (r.isOk() && listing(r)) {
				found = zone;
				complete = true;
				break;
			}
		}
		if (complete) {
			if (cache.size() >= MAX_CACHED) {
				cache.clear();
			}
			cache.put(key, new Entry(found, now + CACHE_MILLIS));
		}
		return found.isEmpty() ? null : found;
	}

	/** True if an answer is a listing: an A record 127.x.x.x other than the 127.255.255.x refusals. */
	private static boolean listing(LookupResult<RR> r) {
		for (RR rr : r.getValues()) {
			if (rr.getType() != DNS.A) {
				continue;
			}
			try {
				byte[] b = (rr instanceof us.bringardner.parley.dns.A ? (us.bringardner.parley.dns.A) rr
						: new us.bringardner.parley.dns.A(rr)).getAddress();
				if (b.length == 4 && b[0] == 127 && !((b[1] & 0xff) == 255 && (b[2] & 0xff) == 255)) {
					return true;
				}
			} catch (RuntimeException ex) {
				// a malformed record
			}
		}
		return false;
	}

	/** Loopback, private and link-local addresses are never listed, so they are not asked. */
	public static boolean isLocal(InetAddress ip) {
		return ip.isAnyLocalAddress() || ip.isLoopbackAddress() || ip.isSiteLocalAddress() || ip.isLinkLocalAddress();
	}
}
