package us.bringardner.parley.smtp.dkim;

import us.bringardner.parley.dns.resolve.LookupResult;

/**
 * Finds the TXT records of a DKIM key name (selector._domainkey.domain).
 * <p>
 * The SMTP server uses parley-dns ({@code ParleyDnsMxResolver::txt}, or
 * {@code us.bringardner.parley.dns.resolve.Lookup::txt}); tests use a map.
 */
@FunctionalInterface
public interface DkimKeyLookup {

	/** The TXT records of a name, each one's strings joined. */
	LookupResult<String> txt(String name);
}
