package us.bringardner.parley.smtp.spf;

import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.resolve.LookupResult;

/**
 * The DNS queries an SPF check makes (TXT, A, AAAA, MX, PTR). The SMTP
 * server uses parley-dns ({@code ParleyDnsMxResolver::records}); tests use a map.
 */
@FunctionalInterface
public interface SpfDns {

	/** The records of one type (DNS.TXT, DNS.A...) for a name, class IN. */
	LookupResult<RR> lookup(String name, int type);
}
