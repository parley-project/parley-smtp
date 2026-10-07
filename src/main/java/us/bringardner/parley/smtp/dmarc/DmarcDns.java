package us.bringardner.parley.smtp.dmarc;

import us.bringardner.parley.dns.resolve.LookupResult;

/** Finds the TXT records of a name (DMARC policy records at _dmarc.domain); parley-dns in the server. */
@FunctionalInterface
public interface DmarcDns {

	LookupResult<String> txt(String name);
}
