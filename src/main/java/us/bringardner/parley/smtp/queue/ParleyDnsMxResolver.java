package us.bringardner.parley.smtp.queue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.AAAA;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Mx;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.dns.resolve.Resolver;

/**
 * MX lookup with parley-dns (RFC 5321 section 5.1), as an alternative to the JDK's
 * DNS provider used by {@link DnsMxResolver}. Every DNS request goes through
 * parley-dns: the MX query and the A/AAAA queries for the mail hosts, so the routes
 * carry addresses and the SMTP client doesn't look anything up itself.
 * <p>
 * Two modes:
 * <ul>
 * <li><b>stub</b> (default): ask recursive DNS servers ({@code /etc/resolv.conf}
 * or a list you give), trying each in turn;</li>
 * <li><b>iterative</b>: parley-dns's own {@link Resolver}, which starts at the root
 * servers in its {@code sbelt.prop} and caches answers.</li>
 * </ul>
 * Rules: MX records by preference (random among equals); the domain's own
 * address when there is no MX ("implicit MX"); RFC 7505 null MX ("0 .") and
 * NXDOMAIN are permanent failures; timeouts and server failures are temporary.
 */
public class ParleyDnsMxResolver implements MxResolver {

	public enum Mode {
		STUB, ITERATIVE
	}

	private static boolean resolverStarted;

	private final Mode mode;
	private final List<InetAddress> servers;
	private int dnsPort = 53;
	private int timeout = 3000;
	private int retries = 2;
	private int maxAddressesPerHost = 2;
	private boolean preferIpv6;
	private final Random random = new Random();

	/** Stub mode with the system's DNS servers (the nameserver lines of /etc/resolv.conf). */
	public ParleyDnsMxResolver() throws IOException {
		this(systemServers());
	}

	/** Stub mode with the given recursive DNS servers, tried in order. */
	public ParleyDnsMxResolver(List<InetAddress> servers) {
		if (servers.isEmpty()) {
			throw new IllegalArgumentException("No DNS servers");
		}
		this.mode = Mode.STUB;
		this.servers = new ArrayList<>(servers);
	}

	private ParleyDnsMxResolver(Mode mode) {
		this.mode = mode;
		this.servers = List.of();
	}

	/**
	 * Iterative mode: parley-dns's own resolver (started once per process with
	 * {@link Resolver#initResolver()}, which reads its root servers from
	 * {@code sbelt.prop} in the parley-dns directory).
	 */
	public static synchronized ParleyDnsMxResolver iterative() throws IOException {
		if (!resolverStarted) {
			Resolver.initResolver();
			resolverStarted = true;
		}
		return new ParleyDnsMxResolver(Mode.ITERATIVE);
	}

	/** Servers from a comma-separated list such as "192.168.1.1,1.1.1.1". */
	public static List<InetAddress> parseServers(String list) throws UnknownHostException {
		List<InetAddress> ret = new ArrayList<>();
		for (String s : list.split(",")) {
			if (!s.trim().isEmpty()) {
				ret.add(InetAddress.getByName(s.trim()));
			}
		}
		return ret;
	}

	/** The nameserver lines of /etc/resolv.conf (macOS and Linux). */
	public static List<InetAddress> systemServers() throws IOException {
		List<InetAddress> ret = new ArrayList<>();
		File f = new File("/etc/resolv.conf");
		if (f.isFile()) {
			try (BufferedReader r = new BufferedReader(new FileReader(f))) {
				String line;
				while ((line = r.readLine()) != null) {
					String[] p = line.trim().split("\\s+");
					if (p.length >= 2 && p[0].equals("nameserver")) {
						String addr = p[1];
						int pct = addr.indexOf('%'); // IPv6 zone
						ret.add(InetAddress.getByName(pct > 0 ? addr.substring(0, pct) : addr));
					}
				}
			}
		}
		if (ret.isEmpty()) {
			throw new IOException("No DNS servers in /etc/resolv.conf; give them to ParleyDnsMxResolver (JSmtp.dnsServers)");
		}
		return ret;
	}

	public Mode getMode() {
		return mode;
	}

	public List<InetAddress> getServers() {
		return Collections.unmodifiableList(servers);
	}

	/** The port of the DNS servers (53; another one for tests). */
	public void setDnsPort(int dnsPort) {
		this.dnsPort = dnsPort;
	}

	/** Milliseconds to wait for each answer (stub mode). */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/** Tries per server (stub mode). */
	public void setRetries(int retries) {
		this.retries = Math.max(1, retries);
	}

	/**
	 * Try a host's IPv6 addresses before its IPv4 ones. Off by default: many
	 * receivers check reverse DNS and reputation more strictly over IPv6, so
	 * IPv4 first is the safer default for SMTP.
	 */
	public void setPreferIpv6(boolean preferIpv6) {
		this.preferIpv6 = preferIpv6;
	}

	public boolean isPreferIpv6() {
		return preferIpv6;
	}

	/** How many addresses of each family to try for each mail host. */
	public void setMaxAddressesPerHost(int max) {
		this.maxAddressesPerHost = Math.max(1, max);
	}

	// ------------------------------------------------------------------ MxResolver

	@Override
	public List<Route> resolve(String domain, int port) throws DeliveryException {
		if (domain.startsWith("[") && domain.endsWith("]")) {
			String literal = domain.substring(1, domain.length() - 1);
			if (literal.regionMatches(true, 0, "IPv6:", 0, 5)) {
				literal = literal.substring(5);
			}
			try {
				return List.of(new Route(literal, InetAddress.getByName(literal), port));
			} catch (UnknownHostException e) {
				throw DeliveryException.permanent("5.1.2", "Invalid address literal " + domain);
			}
		}
		Message answer = query(domain, DNS.MX);
		if (answer.getResponseCode() == DNS.NAME_ERROR) {
			throw DeliveryException.permanent("5.1.2", "The domain " + domain + " doesn't exist");
		}
		List<Mx> mx = new ArrayList<>();
		for (RR rr : answer.getAnswer()) {
			if (rr instanceof Mx) {
				mx.add((Mx) rr);
			}
		}
		if (mx.isEmpty()) {
			// implicit MX: the domain's own address (RFC 5321 section 5.1)
			List<InetAddress> addrs = addresses(domain, null);
			if (addrs.isEmpty()) {
				throw DeliveryException.permanent("5.1.2", "The domain " + domain + " has no MX or address record");
			}
			List<Route> ret = new ArrayList<>();
			for (InetAddress a : addrs) {
				ret.add(new Route(domain, a, port));
			}
			return ret;
		}
		if (mx.size() == 1 && host(mx.get(0)).isEmpty()) {
			throw DeliveryException.permanent("5.1.10", "The domain " + domain + " accepts no mail (null MX)");
		}
		Collections.shuffle(mx, random);
		mx.sort((x, y) -> Integer.compare(x.getPref(), y.getPref()));
		List<Route> ret = new ArrayList<>();
		DeliveryException lookupFailure = null;
		for (Mx m : mx) {
			String host = host(m);
			if (host.isEmpty()) {
				continue;
			}
			try {
				for (InetAddress a : addresses(host, answer)) {
					ret.add(new Route(host, a, port));
				}
			} catch (DeliveryException e) {
				lookupFailure = e;
			}
		}
		if (ret.isEmpty()) {
			// the MX hosts don't resolve (yet): try again later
			throw lookupFailure != null ? lookupFailure
					: DeliveryException.temporary("4.4.3", "No address for the mail servers of " + domain);
		}
		return ret;
	}

	private static String host(Mx m) {
		String h = m.getExchange();
		if (h == null) {
			return "";
		}
		h = h.trim();
		while (h.endsWith(".")) {
			h = h.substring(0, h.length() - 1);
		}
		return h.toLowerCase(Locale.ROOT);
	}

	/**
	 * The addresses of a host. Addresses in the additional section of
	 * {@code answer} are used, and an A or AAAA query is made for each family the
	 * section didn't cover, so a host with both IPv4 and IPv6 addresses gets both.
	 * IPv4 first unless {@link #setPreferIpv6(boolean)}; at most
	 * {@link #setMaxAddressesPerHost(int)} of each family.
	 *
	 * @throws DeliveryException if the lookups failed and no address was found
	 */
	List<InetAddress> addresses(String host, Message answer) throws DeliveryException {
		List<InetAddress> v4 = new ArrayList<>();
		List<InetAddress> v6 = new ArrayList<>();
		if (answer != null) {
			for (RR rr : answer.getAdditional()) {
				if (rr.getName() != null && trim(rr.getName()).equalsIgnoreCase(host)) {
					add(rr, v4, v6);
				}
			}
		}
		DeliveryException failure = null;
		boolean noSuchHost = false;
		if (v4.isEmpty()) {
			try {
				Message a = query(host, DNS.A);
				noSuchHost = a.getResponseCode() == DNS.NAME_ERROR;
				for (RR rr : a.getAnswer()) {
					add(rr, v4, v6);
				}
			} catch (DeliveryException e) {
				failure = e;
			}
		}
		if (v6.isEmpty() && !noSuchHost) {
			try {
				for (RR rr : query(host, DNS.AAAA).getAnswer()) {
					add(rr, v4, v6);
				}
			} catch (DeliveryException e) {
				failure = e;
			}
		}
		if (v4.isEmpty() && v6.isEmpty() && failure != null) {
			throw failure;
		}
		List<InetAddress> first = preferIpv6 ? v6 : v4;
		List<InetAddress> second = preferIpv6 ? v4 : v6;
		List<InetAddress> ret = new ArrayList<>();
		for (int i = 0; i < first.size() && i < maxAddressesPerHost; i++) {
			ret.add(first.get(i));
		}
		for (int i = 0; i < second.size() && i < maxAddressesPerHost; i++) {
			ret.add(second.get(i));
		}
		return ret;
	}

	private static String trim(String name) {
		return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
	}

	private static void add(RR rr, List<InetAddress> v4, List<InetAddress> v6) {
		try {
			if (rr instanceof A) {
				v4.add(InetAddress.getByAddress(((A) rr).getAddress()));
			} else if (rr instanceof AAAA) {
				v6.add(InetAddress.getByAddress(((AAAA) rr).getAddress()));
			}
		} catch (UnknownHostException e) {
			// a malformed address: skip it
		}
	}

	/**
	 * The records of one type for a name (for SPF and the like). A timeout or
	 * server failure is {@link LookupResult.Status#TEMPFAIL}.
	 */
	public LookupResult<RR> records(String name, int type) {
		if (mode == Mode.ITERATIVE) {
			return Lookup.records(name, type);
		}
		Message m;
		try {
			m = query(name, type);
		} catch (DeliveryException e) {
			m = null;
		}
		return Lookup.fromResponse(name, type, m, rr -> rr);
	}

	/**
	 * The TXT records of a name (for DKIM keys and the like), each record's
	 * strings joined. A timeout or server failure is
	 * {@link LookupResult.Status#TEMPFAIL}.
	 */
	public LookupResult<String> txt(String name) {
		if (mode == Mode.ITERATIVE) {
			return Lookup.txt(name);
		}
		Message m;
		try {
			m = query(name, DNS.TXT);
		} catch (DeliveryException e) {
			m = null;
		}
		return Lookup.txt(name, m);
	}

	/**
	 * One question. Returns a NOERROR or NXDOMAIN answer; a timeout, SERVFAIL or
	 * REFUSED from every server is a temporary failure.
	 */
	Message query(String name, int type) throws DeliveryException {
		if (mode == Mode.ITERATIVE) {
			Message m = Resolver.resolve(name, type, DNS.IN);
			if (m == null) {
				throw DeliveryException.temporary("4.4.3", "DNS lookup of " + name + " failed");
			}
			return m;
		}
		String last = "no answer";
		for (InetAddress server : servers) {
			try {
				Message q = new Message();
				q.setServer(server);
				q.setPort(dnsPort);
				q.setQuestion(name, type, DNS.IN);
				q.recursiveDesiredOn();
				q.setTimeOut(timeout);
				q.setRetry(retries);
				q.setTcpFallback(true);
				Message r = q.query();
				if (r == null) {
					continue;
				}
				int rcode = r.getResponseCode();
				if (rcode == 0 || rcode == DNS.NAME_ERROR) {
					return r;
				}
				last = server.getHostAddress() + " returned rcode " + rcode;
			} catch (IOException | RuntimeException e) {
				last = server.getHostAddress() + ": " + e.getMessage();
			}
		}
		throw DeliveryException.temporary("4.4.3", "DNS lookup of " + name + " failed (" + last + ")");
	}
}
