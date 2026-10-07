package us.bringardner.parley.smtp.queue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import us.bringardner.parley.io.IoUtils;

/**
 * MX lookup with the JDK's DNS provider (RFC 5321 section 5.1): MX records by
 * preference (random among equals), the domain itself when there is no MX
 * ("implicit MX"), and RFC 7505 null MX ("0 .") as a permanent failure.
 */
public class DnsMxResolver implements MxResolver {

	private final Random random = new Random();

	@Override
	public List<Route> resolve(String domain, int port) throws DeliveryException {
		if (domain.startsWith("[") && domain.endsWith("]")) {
			String literal = domain.substring(1, domain.length() - 1);
			if (literal.regionMatches(true, 0, "IPv6:", 0, 5)) {
				literal = literal.substring(5);
			}
			return List.of(new Route(literal, port));
		}
		List<String[]> mx = new ArrayList<>();
		Hashtable<String, String> env = new Hashtable<>();
		env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		env.put("java.naming.provider.url", "dns:");
		env.put("com.sun.jndi.dns.timeout.initial", "3000");
		env.put("com.sun.jndi.dns.timeout.retries", "3");
		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
			Attributes attrs = ctx.getAttributes(domain + ".", new String[] {"MX"});
			Attribute a = attrs.get("MX");
			if (a != null) {
				NamingEnumeration<?> e = a.getAll();
				while (e.hasMore()) {
					String[] p = e.next().toString().trim().split("\\s+");
					if (p.length == 2) {
						mx.add(p);
					}
				}
			}
		} catch (NameNotFoundException e) {
			throw DeliveryException.permanent("5.1.2", "The domain " + domain + " doesn't exist");
		} catch (NamingException e) {
			throw DeliveryException.temporary("4.4.3", "DNS lookup of " + domain + " failed: " + e.getMessage());
		} finally {
			if (ctx != null) {
				//  DirContext isn't AutoCloseable (it's older); the method reference adapts it
				IoUtils.closeQuietly(ctx::close);
			}
		}
		if (mx.isEmpty()) {
			// implicit MX: the domain's own address (RFC 5321 section 5.1)
			try {
				InetAddress.getAllByName(domain);
			} catch (UnknownHostException e) {
				throw DeliveryException.permanent("5.1.2", "The domain " + domain + " has no MX or address record");
			}
			return List.of(new Route(domain, port));
		}
		if (mx.size() == 1 && (mx.get(0)[1].equals(".") || mx.get(0)[1].isEmpty())) {
			throw DeliveryException.permanent("5.1.10", "The domain " + domain + " accepts no mail (null MX)");
		}
		Collections.shuffle(mx, random);
		mx.sort((x, y) -> Integer.compare(Integer.parseInt(x[0]), Integer.parseInt(y[0])));
		List<Route> ret = new ArrayList<>();
		for (String[] m : mx) {
			String host = m[1].endsWith(".") ? m[1].substring(0, m[1].length() - 1) : m[1];
			if (!host.isEmpty()) {
				ret.add(new Route(host, port));
			}
		}
		return ret;
	}
}
