package us.bringardner.parley.smtp.spf;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.AAAA;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Mx;
import us.bringardner.parley.dns.Ptr;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.ReverseName;
import us.bringardner.parley.dns.Txt;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.spf.SpfResult.Identity;
import us.bringardner.parley.smtp.spf.SpfResult.Result;

/**
 * Sender Policy Framework (RFC 7208): is a client address allowed to send
 * mail for a domain? Implements check_host() with all mechanisms (all,
 * include, a, mx, ptr, ip4, ip6, exists), the redirect and exp modifiers,
 * macros, and the processing limits (10 DNS-querying terms, 2 void lookups,
 * 10 addresses per MX or PTR name).
 *
 * <pre>
 * SpfChecker spf = new SpfChecker(resolver::records, "mx.example.com");
 * SpfResult r = spf.checkMailFrom(clientIp, "user@example.org", heloName);
 * </pre>
 */
public final class SpfChecker {

	/** DNS-querying terms per check (section 4.6.4). */
	public static final int MAX_DNS_TERMS = 10;
	/** Lookups returning NXDOMAIN or no records per check (section 4.6.4). */
	public static final int MAX_VOID_LOOKUPS = 2;
	/** MX records per mx mechanism, and names per ptr (section 4.6.4). */
	public static final int MAX_NAMES = 10;

	/** The explanation for a fail when the domain gives none. */
	public static final String DEFAULT_EXPLANATION = "See https://www.rfc-editor.org/rfc/rfc7208 (the sender's domain does not permit this host)";

	private final SpfDns dns;
	private final String receiver;
	private int maxDnsTerms = MAX_DNS_TERMS;
	private int maxVoidLookups = MAX_VOID_LOOKUPS;

	/**
	 * @param dns      how DNS queries are made
	 * @param receiver this server's host name (the %{r} macro and Received-SPF)
	 */
	public SpfChecker(SpfDns dns, String receiver) {
		this.dns = dns;
		this.receiver = receiver == null || receiver.isEmpty() ? "unknown" : receiver;
	}

	public void setMaxVoidLookups(int max) {
		this.maxVoidLookups = Math.max(0, max);
	}

	// ------------------------------------------------------------------ entry points

	/**
	 * Check the MAIL FROM identity (section 2.4). For a null reverse-path
	 * (empty or null {@code mailFrom}) the HELO identity is checked instead,
	 * as "postmaster@" + helo.
	 */
	public SpfResult checkMailFrom(InetAddress ip, String mailFrom, String helo) {
		if (mailFrom == null || mailFrom.isEmpty() || mailFrom.equals("<>")) {
			return checkHelo(ip, helo);
		}
		int at = mailFrom.lastIndexOf('@');
		String local = at < 0 ? "postmaster" : mailFrom.substring(0, at);
		String domain = at < 0 ? mailFrom : mailFrom.substring(at + 1);
		if (local.isEmpty()) {
			local = "postmaster";
		}
		return check(ip, domain, local, domain, helo, Identity.MAILFROM);
	}

	/** Check the HELO identity (section 2.3). */
	public SpfResult checkHelo(InetAddress ip, String helo) {
		String h = helo == null ? "" : helo;
		return check(ip, h, "postmaster", h, h, Identity.HELO);
	}

	private SpfResult check(InetAddress ip, String domain, String local, String senderDomain, String helo, Identity id) {
		InetAddress addr = unmap(ip);
		Eval e = new Eval(addr, local, senderDomain, helo);
		String sender = local + "@" + senderDomain;
		String d = trimDot(domain);
		Outcome o;
		try {
			o = checkHost(e, d, true);
		} catch (SpfException ex) {
			o = new Outcome(ex.result, null, null, ex.getMessage());
		}
		return new SpfResult(o.result, id, d, sender, addr, helo, o.mechanism, o.result == Result.FAIL ? o.explanation : null,
				o.problem);
	}

	// ------------------------------------------------------------------ check_host()

	/** State shared by one check and the includes and redirects it follows. */
	private static final class Eval {
		final InetAddress ip;
		final String local;
		final String senderDomain;
		final String helo;
		int dnsTerms;
		int voids;
		String validated; // %{p}, computed once

		Eval(InetAddress ip, String local, String senderDomain, String helo) {
			this.ip = ip;
			this.local = local;
			this.senderDomain = senderDomain;
			this.helo = helo == null ? "" : helo;
		}
	}

	private static final class Outcome {
		final Result result;
		final String mechanism;
		final String explanation;
		final String problem;

		Outcome(Result result, String mechanism, String explanation, String problem) {
			this.result = result;
			this.mechanism = mechanism;
			this.explanation = explanation;
			this.problem = problem;
		}
	}

	/** check_host(ip, domain, sender) (section 4). */
	private Outcome checkHost(Eval e, String domain, boolean top) throws SpfException {
		if (!validDomain(domain)) {
			return new Outcome(Result.NONE, null, null, null); // section 4.3
		}
		LookupResult<RR> txt = dns.lookup(domain, DNS.TXT);
		switch (txt.getStatus()) {
		case TEMPFAIL:
			throw new SpfException(Result.TEMPERROR, "DNS lookup of " + domain + " failed");
		case NXDOMAIN:
		case NODATA:
			if (!top) {
				countVoid(e);
			}
			return new Outcome(Result.NONE, null, null, null);
		default:
			break;
		}
		String record = null;
		for (RR rr : txt.getValues()) {
			if (rr.getType() != DNS.TXT) {
				continue;
			}
			String t = (rr instanceof Txt ? (Txt) rr : new Txt(rr)).getText();
			if (t.regionMatches(true, 0, "v=spf1", 0, 6) && (t.length() == 6 || t.charAt(6) == ' ')) {
				if (record != null) {
					throw new SpfException(Result.PERMERROR, "more than one SPF record for " + domain);
				}
				record = t;
			}
		}
		if (record == null) {
			return new Outcome(Result.NONE, null, null, null);
		}
		SpfRecord r = SpfRecord.parse(record);
		return evaluate(e, domain, r);
	}

	private Outcome evaluate(Eval e, String domain, SpfRecord r) throws SpfException {
		for (SpfRecord.Mechanism m : r.mechanisms) {
			if (matches(e, domain, m)) {
				Result res = m.result();
				String explanation = res == Result.FAIL ? explain(e, domain, r) : null;
				return new Outcome(res, m.text, explanation, null);
			}
		}
		if (r.redirect != null && !r.hasAll) {
			countDnsTerm(e);
			String target = expandDomain(e, r.redirect, domain);
			Outcome o = checkHost(e, target, false);
			if (o.result == Result.NONE) {
				throw new SpfException(Result.PERMERROR, "redirect to " + target + ", which has no SPF record");
			}
			return o;
		}
		return new Outcome(Result.NEUTRAL, "default", null, null);
	}

	private boolean matches(Eval e, String domain, SpfRecord.Mechanism m) throws SpfException {
		switch (m.name) {
		case "all":
			return true;
		case "ip4":
		case "ip6":
			return inNetwork(e.ip, m.network, m.ip4Cidr >= 0 && m.network instanceof Inet4Address ? m.ip4Cidr : m.ip6Cidr);
		case "a": {
			countDnsTerm(e);
			String target = m.domainSpec == null ? domain : expandDomain(e, m.domainSpec, domain);
			List<InetAddress> addrs = addresses(e, target, true);
			return anyInNetwork(e.ip, addrs, m);
		}
		case "mx": {
			countDnsTerm(e);
			String target = m.domainSpec == null ? domain : expandDomain(e, m.domainSpec, domain);
			LookupResult<RR> mx = lookup(target, DNS.MX);
			if (mx.getStatus() == LookupResult.Status.TEMPFAIL) {
				throw new SpfException(Result.TEMPERROR, "DNS lookup of " + target + " MX failed");
			}
			if (mx.isNotFound()) {
				countVoid(e);
				return false;
			}
			List<String> hosts = new ArrayList<>();
			for (RR rr : mx.getValues()) {
				if (rr.getType() == DNS.MX) {
					hosts.add(trimDot((rr instanceof Mx ? (Mx) rr : new Mx(rr)).getExchange()));
				}
			}
			if (hosts.size() > MAX_NAMES) {
				throw new SpfException(Result.PERMERROR, target + " has more than " + MAX_NAMES + " MX records");
			}
			for (String host : hosts) {
				if (host.isEmpty()) {
					continue; // null MX
				}
				if (anyInNetwork(e.ip, addresses(e, host, false), m)) {
					return true;
				}
			}
			return false;
		}
		case "ptr": {
			countDnsTerm(e);
			String target = m.domainSpec == null ? domain : expandDomain(e, m.domainSpec, domain);
			for (String name : validatedNames(e)) {
				if (isSubdomain(name, target)) {
					return true;
				}
			}
			return false;
		}
		case "exists": {
			countDnsTerm(e);
			String target = expandDomain(e, m.domainSpec, domain);
			LookupResult<RR> a = lookup(target, DNS.A); // always A (section 5.7)
			if (a.getStatus() == LookupResult.Status.TEMPFAIL) {
				throw new SpfException(Result.TEMPERROR, "DNS lookup of " + target + " failed");
			}
			for (RR rr : a.getValues()) {
				if (rr.getType() == DNS.A) {
					return true;
				}
			}
			countVoid(e);
			return false;
		}
		case "include": {
			countDnsTerm(e);
			String target = expandDomain(e, m.domainSpec, domain);
			Outcome o = checkHost(e, target, false);
			switch (o.result) {
			case PASS:
				return true;
			case FAIL:
			case SOFTFAIL:
			case NEUTRAL:
				return false;
			case TEMPERROR:
				throw new SpfException(Result.TEMPERROR, o.problem);
			default:
				throw new SpfException(Result.PERMERROR,
						o.problem != null ? o.problem : "include:" + target + " has no SPF record");
			}
		}
		default:
			throw new SpfException(Result.PERMERROR, "unknown mechanism " + m.name);
		}
	}

	/** The fail explanation (section 6.2): the exp= target's TXT record, macro-expanded. */
	private String explain(Eval e, String domain, SpfRecord r) {
		if (r.exp == null) {
			return DEFAULT_EXPLANATION;
		}
		try {
			String target = expandDomain(e, r.exp, domain);
			if (!validDomain(target)) {
				return DEFAULT_EXPLANATION;
			}
			LookupResult<RR> txt = dns.lookup(target, DNS.TXT);
			if (!txt.isOk()) {
				return DEFAULT_EXPLANATION;
			}
			List<String> texts = new ArrayList<>();
			for (RR rr : txt.getValues()) {
				if (rr.getType() == DNS.TXT) {
					texts.add((rr instanceof Txt ? (Txt) rr : new Txt(rr)).getText());
				}
			}
			if (texts.size() != 1 || !ascii(texts.get(0))) {
				return DEFAULT_EXPLANATION;
			}
			return expand(e, texts.get(0), domain, true);
		} catch (SpfException | RuntimeException ex) {
			return DEFAULT_EXPLANATION;
		}
	}

	// ------------------------------------------------------------------ DNS helpers

	private LookupResult<RR> lookup(String name, int type) throws SpfException {
		if (!validName(name)) {
			// a name no DNS query can be made for: no records
			throw new SpfException(Result.PERMERROR, "invalid domain name " + abbreviate(name));
		}
		return dns.lookup(name, type);
	}

	/** A or AAAA records (the client's address family) of a name. */
	private List<InetAddress> addresses(Eval e, String name, boolean primary) throws SpfException {
		boolean v6 = e.ip instanceof Inet6Address;
		LookupResult<RR> r = lookup(name, v6 ? DNS.AAAA : DNS.A);
		if (r.getStatus() == LookupResult.Status.TEMPFAIL) {
			throw new SpfException(Result.TEMPERROR, "DNS lookup of " + name + " failed");
		}
		List<InetAddress> ret = new ArrayList<>();
		for (RR rr : r.getValues()) {
			InetAddress a = toAddress(rr, v6);
			if (a != null) {
				ret.add(a);
			}
		}
		if (ret.isEmpty() && primary) {
			countVoid(e);
		}
		return ret;
	}

	private static InetAddress toAddress(RR rr, boolean v6) {
		try {
			if (!v6 && rr.getType() == DNS.A) {
				return InetAddress.getByAddress((rr instanceof A ? (A) rr : new A(rr)).getAddress());
			}
			if (v6 && rr.getType() == DNS.AAAA) {
				byte[] b = (rr instanceof AAAA ? (AAAA) rr : new AAAA(rr)).getAddress();
				return Inet6Address.getByAddress(null, b, (java.net.NetworkInterface) null);
			}
		} catch (UnknownHostException | RuntimeException ex) {
			// a malformed record
		}
		return null;
	}

	/**
	 * The client's validated host names (section 5.5): PTR names (the first
	 * 10) whose addresses include the client address. DNS errors skip a name.
	 */
	private List<String> validatedNames(Eval e) {
		List<String> ret = new ArrayList<>();
		LookupResult<RR> ptr = dns.lookup(ReverseName.of(e.ip), DNS.PTR);
		if (!ptr.isOk()) {
			return ret;
		}
		int n = 0;
		for (RR rr : ptr.getValues()) {
			if (rr.getType() != DNS.PTR) {
				continue;
			}
			if (++n > MAX_NAMES) {
				break; // section 4.6.4: the others are ignored
			}
			String name = trimDot((rr instanceof Ptr ? (Ptr) rr : new Ptr(rr)).getPtr());
			if (!validName(name)) {
				continue;
			}
			LookupResult<RR> a = dns.lookup(name, e.ip instanceof Inet6Address ? DNS.AAAA : DNS.A);
			if (!a.isOk()) {
				continue;
			}
			for (RR arr : a.getValues()) {
				InetAddress addr = toAddress(arr, e.ip instanceof Inet6Address);
				if (addr != null && addr.equals(e.ip)) {
					ret.add(name);
					break;
				}
			}
		}
		return ret;
	}

	private void countDnsTerm(Eval e) throws SpfException {
		if (++e.dnsTerms > maxDnsTerms) {
			throw new SpfException(Result.PERMERROR, "more than " + maxDnsTerms + " DNS lookups");
		}
	}

	private void countVoid(Eval e) throws SpfException {
		if (++e.voids > maxVoidLookups) {
			throw new SpfException(Result.PERMERROR, "more than " + maxVoidLookups + " void DNS lookups");
		}
	}

	// ------------------------------------------------------------------ addresses

	private static boolean anyInNetwork(InetAddress ip, List<InetAddress> addrs, SpfRecord.Mechanism m) {
		int bits = ip instanceof Inet4Address ? m.ip4Cidr : m.ip6Cidr;
		for (InetAddress a : addrs) {
			if (inNetwork(ip, a, bits)) {
				return true;
			}
		}
		return false;
	}

	/** True if ip is in the network/bits (both of one family; -1 bits: the whole address). */
	static boolean inNetwork(InetAddress ip, InetAddress network, int bits) {
		byte[] a = ip.getAddress();
		byte[] n = network.getAddress();
		if (a.length != n.length) {
			return false;
		}
		int len = bits < 0 ? a.length * 8 : bits;
		for (int i = 0; i < len; i++) {
			int mask = 0x80 >> (i % 8);
			if ((a[i / 8] & mask) != (n[i / 8] & mask)) {
				return false;
			}
		}
		return true;
	}

	/** An IPv4-mapped IPv6 address is checked as IPv4 (section 5). */
	static InetAddress unmap(InetAddress ip) {
		byte[] b = ip.getAddress();
		if (b.length == 16) {
			boolean mapped = b[10] == (byte) 0xff && b[11] == (byte) 0xff;
			for (int i = 0; i < 10 && mapped; i++) {
				mapped = b[i] == 0;
			}
			if (mapped) {
				try {
					return InetAddress.getByAddress(new byte[] {b[12], b[13], b[14], b[15]});
				} catch (UnknownHostException e) {
					// not possible with 4 bytes
				}
			}
		}
		return ip;
	}

	/** The address as text: dotted IPv4, or compressed IPv6 (RFC 5952). */
	static String readableIp(InetAddress ip) {
		if (ip instanceof Inet4Address) {
			return ip.getHostAddress();
		}
		byte[] b = ip.getAddress();
		int[] g = new int[8];
		for (int i = 0; i < 8; i++) {
			g[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
		}
		int bestStart = -1;
		int bestLen = 0;
		for (int i = 0; i < 8;) {
			if (g[i] == 0) {
				int j = i;
				while (j < 8 && g[j] == 0) {
					j++;
				}
				if (j - i > bestLen && j - i > 1) {
					bestStart = i;
					bestLen = j - i;
				}
				i = j;
			} else {
				i++;
			}
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			if (i == bestStart) {
				sb.append("::");
				i += bestLen - 1;
				continue;
			}
			if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
				sb.append(':');
			}
			sb.append(Integer.toHexString(g[i]));
		}
		return sb.toString();
	}

	// ------------------------------------------------------------------ macros (section 7)

	/** Expand a domain-spec and make it a query name (truncated on the left to 253 characters). */
	private String expandDomain(Eval e, String spec, String domain) throws SpfException {
		String d = trimDot(expand(e, spec, domain, false));
		while (d.length() > 253) {
			int dot = d.indexOf('.');
			if (dot < 0) {
				break;
			}
			d = d.substring(dot + 1);
		}
		return d;
	}

	private static final Pattern MACRO = Pattern.compile("([a-zA-Z])([0-9]*)(r?)([.\\-+,/_=]*)", Pattern.CASE_INSENSITIVE);

	/**
	 * Expand macros in a macro-string.
	 *
	 * @param exp true for an explanation string (c, r and t are allowed)
	 */
	String expand(Eval e, String s, String domain, boolean exp) throws SpfException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c != '%') {
				sb.append(c);
				continue;
			}
			if (i + 1 >= s.length()) {
				throw new SpfException(Result.PERMERROR, "'%' at the end of " + abbreviate(s));
			}
			char n = s.charAt(++i);
			if (n == '%') {
				sb.append('%');
			} else if (n == '_') {
				sb.append(' ');
			} else if (n == '-') {
				sb.append("%20");
			} else if (n == '{') {
				int close = s.indexOf('}', i);
				if (close < 0) {
					throw new SpfException(Result.PERMERROR, "unterminated macro in " + abbreviate(s));
				}
				String body = s.substring(i + 1, close);
				i = close;
				Matcher m = MACRO.matcher(body);
				if (!m.matches()) {
					throw new SpfException(Result.PERMERROR, "invalid macro %{" + abbreviate(body) + "}");
				}
				sb.append(macro(e, m.group(1).charAt(0), m.group(2), !m.group(3).isEmpty(), m.group(4), domain, exp));
			} else {
				throw new SpfException(Result.PERMERROR, "invalid macro %" + n);
			}
		}
		return sb.toString();
	}

	private String macro(Eval e, char letter, String digits, boolean reverse, String delims, String domain, boolean exp)
			throws SpfException {
		String v;
		switch (Character.toLowerCase(letter)) {
		case 's':
			v = e.local + "@" + e.senderDomain;
			break;
		case 'l':
			v = e.local;
			break;
		case 'o':
			v = e.senderDomain;
			break;
		case 'd':
			v = domain;
			break;
		case 'i':
			v = dottedIp(e.ip);
			break;
		case 'p':
			v = validatedName(e, domain);
			break;
		case 'v':
			v = e.ip instanceof Inet4Address ? "in-addr" : "ip6";
			break;
		case 'h':
			v = e.helo;
			break;
		case 'c':
			if (!exp) {
				throw new SpfException(Result.PERMERROR, "%{c} is only allowed in explanations");
			}
			v = readableIp(e.ip);
			break;
		case 'r':
			if (!exp) {
				throw new SpfException(Result.PERMERROR, "%{r} is only allowed in explanations");
			}
			v = receiver;
			break;
		case 't':
			if (!exp) {
				throw new SpfException(Result.PERMERROR, "%{t} is only allowed in explanations");
			}
			v = Long.toString(System.currentTimeMillis() / 1000);
			break;
		default:
			throw new SpfException(Result.PERMERROR, "unknown macro letter " + letter);
		}
		if (!digits.isEmpty() || reverse || !delims.isEmpty()) {
			String d = delims.isEmpty() ? "." : delims;
			List<String> parts = new ArrayList<>();
			int start = 0;
			for (int i = 0; i < v.length(); i++) {
				if (d.indexOf(v.charAt(i)) >= 0) {
					parts.add(v.substring(start, i));
					start = i + 1;
				}
			}
			parts.add(v.substring(start));
			if (reverse) {
				java.util.Collections.reverse(parts);
			}
			if (!digits.isEmpty()) {
				int keep;
				try {
					keep = Integer.parseInt(digits);
				} catch (NumberFormatException ex) {
					keep = Integer.MAX_VALUE;
				}
				if (keep == 0) {
					throw new SpfException(Result.PERMERROR, "macro transformer 0");
				}
				if (keep < parts.size()) {
					parts = parts.subList(parts.size() - keep, parts.size());
				}
			}
			v = String.join(".", parts);
		}
		if (Character.isUpperCase(letter)) {
			v = urlEncode(v);
		}
		return v;
	}

	/** %{p}: a validated host name, preferably in the current domain, else "unknown". */
	private String validatedName(Eval e, String domain) throws SpfException {
		if (e.validated == null) {
			List<String> names = validatedNames(e);
			String best = null;
			for (String n : names) {
				if (n.equalsIgnoreCase(domain)) {
					best = n;
					break;
				}
			}
			for (String n : names) {
				if (best == null && isSubdomain(n, domain)) {
					best = n;
				}
			}
			if (best == null && !names.isEmpty()) {
				best = names.get(0);
			}
			e.validated = best == null ? "unknown" : best;
		}
		return e.validated;
	}

	/** %{i}: dotted IPv4, or the IPv6 nibbles separated by dots. */
	static String dottedIp(InetAddress ip) {
		if (ip instanceof Inet4Address) {
			return ip.getHostAddress();
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : ip.getAddress()) {
			if (sb.length() > 0) {
				sb.append('.');
			}
			sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append('.').append(Character.forDigit(b & 0xf, 16));
		}
		return sb.toString();
	}

	private static String urlEncode(String v) {
		StringBuilder sb = new StringBuilder();
		for (byte b : v.getBytes(StandardCharsets.UTF_8)) {
			int c = b & 0xff;
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
					|| c == '~') {
				sb.append((char) c);
			} else {
				sb.append('%').append(String.format("%02X", c));
			}
		}
		return sb.toString();
	}

	// ------------------------------------------------------------------ names

	/**
	 * A domain check_host() can start with (section 4.3): labels of 1 to 63
	 * characters, at least two of them.
	 */
	static boolean validDomain(String d) {
		if (d == null) {
			return false;
		}
		String n = trimDot(d);
		if (n.isEmpty() || n.length() > 253 || n.startsWith("[")) {
			return false;
		}
		String[] labels = n.split("\\.", -1);
		if (labels.length < 2) {
			return false;
		}
		for (String l : labels) {
			if (l.isEmpty() || l.length() > 63) {
				return false;
			}
		}
		return true;
	}

	/** A name a query can be made for: labels of 1 to 63 characters. */
	private static boolean validName(String d) {
		if (d == null) {
			return false;
		}
		String n = trimDot(d);
		if (n.isEmpty() || n.length() > 253) {
			return false;
		}
		for (String l : n.split("\\.", -1)) {
			if (l.isEmpty() || l.length() > 63) {
				return false;
			}
		}
		return true;
	}

	private static boolean isSubdomain(String name, String domain) {
		String n = trimDot(name).toLowerCase(Locale.ROOT);
		String d = trimDot(domain).toLowerCase(Locale.ROOT);
		return n.equals(d) || n.endsWith("." + d);
	}

	static String trimDot(String s) {
		return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
	}

	static boolean ascii(String s) {
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c > 126) {
				return false;
			}
		}
		return true;
	}

	static String abbreviate(String s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length() && sb.length() < 40; i++) {
			char c = s.charAt(i);
			sb.append(c < 32 || c > 126 ? '?' : c);
		}
		return sb.toString();
	}
}
