package us.bringardner.parley.smtp.dmarc;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.smtp.dmarc.DmarcRecord.Policy;
import us.bringardner.parley.smtp.spf.SpfResult;

/**
 * DMARC (RFC 7489): does the message's From domain pass SPF or DKIM in a way
 * aligned with it, and what does the domain ask for when it doesn't?
 * <ol>
 * <li>The RFC5322.From domain: exactly one From field, with addresses in one
 * domain (otherwise permerror).</li>
 * <li>The policy: the DMARC record at _dmarc.&lt;From domain&gt;, else at
 * _dmarc.&lt;organizational domain&gt; (section 6.6.3). No record: none.</li>
 * <li>Alignment (section 3.1): a passing DKIM signature whose d= is, or an SPF
 * pass whose domain is, the From domain (strict) or in the same organizational
 * domain (relaxed, the default).</li>
 * <li>The disposition for a fail: p= (sp= for a subdomain), applied to pct=
 * percent of mail and one step milder for the rest (section 6.6.4).</li>
 * </ol>
 */
public final class DmarcChecker {

	private final DmarcDns dns;
	private final PublicSuffixList psl;
	private Random random = new Random();

	public DmarcChecker(DmarcDns dns, PublicSuffixList psl) {
		this.dns = dns;
		this.psl = psl == null ? PublicSuffixList.getDefault() : psl;
	}

	/** The source of the pct= sampling; for tests. */
	public void setRandom(Random random) {
		this.random = random;
	}

	/** Check a message, given its header and the SPF and DKIM results. */
	public DmarcResult check(HeaderFields headers, SpfResult spf, List<DkimResult> dkim) {
		List<String> from = new ArrayList<>();
		for (HeaderFields.Field f : headers.getAll("From")) {
			from.add(f.getValue());
		}
		return check(from, spf, dkim);
	}

	/**
	 * @param fromValues the values of the message's From fields
	 * @param spf        the SPF result (null if not checked)
	 * @param dkim       the DKIM results (may be empty)
	 */
	public DmarcResult check(List<String> fromValues, SpfResult spf, List<DkimResult> dkim) {
		if (fromValues.isEmpty()) {
			return error("no From field");
		}
		if (fromValues.size() > 1) {
			return error("more than one From field");
		}
		Set<String> domains = new LinkedHashSet<>();
		for (String addr : addresses(fromValues.get(0))) {
			String d = HeaderFields.addressDomain(addr);
			if (d != null) {
				domains.add(d);
			}
		}
		if (domains.isEmpty()) {
			return error("no domain in From");
		}
		if (domains.size() > 1) {
			return error("From has addresses in more than one domain");
		}
		String from = domains.iterator().next();
		if (!from.contains(".") || from.startsWith("[")) {
			return error("From domain " + from + " is not a domain name");
		}

		// policy discovery (section 6.6.3)
		String policyDomain = from;
		boolean orgLookup = false;
		DmarcRecord record;
		try {
			record = findRecord(from);
			if (record == null) {
				String org = psl.organizationalDomain(from);
				if (org != null && !org.equals(from)) {
					record = findRecord(org);
					policyDomain = org;
					orgLookup = true;
				}
			}
		} catch (TempFail e) {
			return new DmarcResult(DmarcResult.Result.TEMPERROR, from, null, null, null, null, false, null,
					"DNS lookup of _dmarc." + e.domain + " failed");
		}

		// alignment (section 3.1)
		String orgFrom = psl.organizationalDomain(from);
		boolean strictSpf = record != null && record.isStrictSpf();
		boolean strictDkim = record != null && record.isStrictDkim();
		boolean spfAligned = spf != null && spf.getResult() == SpfResult.Result.PASS
				&& aligned(spf.getDomain(), from, orgFrom, strictSpf);
		String dkimDomain = null;
		for (DkimResult r : dkim) {
			if (r.isPass() && r.getDomain() != null && aligned(r.getDomain(), from, orgFrom, strictDkim)) {
				dkimDomain = r.getDomain();
				break;
			}
		}
		if (record == null) {
			return new DmarcResult(DmarcResult.Result.NONE, from, null, null, null, null, spfAligned, dkimDomain, null);
		}
		Policy policy = orgLookup && record.getSubdomainPolicy() != null ? record.getSubdomainPolicy() : record.getPolicy();
		if (spfAligned || dkimDomain != null) {
			return new DmarcResult(DmarcResult.Result.PASS, from, policyDomain, record, policy, Policy.NONE, spfAligned, dkimDomain,
					null);
		}
		Policy disposition = policy;
		if (record.getPercent() < 100 && random.nextInt(100) >= record.getPercent()) {
			// outside the sample: one step milder (section 6.6.4)
			disposition = policy == Policy.REJECT ? Policy.QUARANTINE : Policy.NONE;
		}
		return new DmarcResult(DmarcResult.Result.FAIL, from, policyDomain, record, policy, disposition, false, null,
				"no aligned SPF or DKIM pass");
	}

	private boolean aligned(String domain, String from, String orgFrom, boolean strict) {
		String d = PublicSuffixList.normalize(domain);
		if (d == null) {
			return false;
		}
		if (strict) {
			return d.equals(from);
		}
		String org = psl.organizationalDomain(d);
		return org != null && org.equals(orgFrom);
	}

	private static final class TempFail extends Exception {
		private static final long serialVersionUID = 1L;
		final String domain;

		TempFail(String domain) {
			super(domain, null, false, false);
			this.domain = domain;
		}
	}

	/** The usable DMARC record at _dmarc.domain, or null (none, several, or unusable). */
	private DmarcRecord findRecord(String domain) throws TempFail {
		LookupResult<String> txt;
		try {
			txt = dns.txt("_dmarc." + domain);
		} catch (RuntimeException e) {
			throw new TempFail(domain);
		}
		if (txt.isTempFail()) {
			throw new TempFail(domain);
		}
		List<String> found = new ArrayList<>();
		for (String t : txt.getValues()) {
			if (DmarcRecord.isDmarc(t)) {
				found.add(t);
			}
		}
		return found.size() == 1 ? DmarcRecord.parse(found.get(0)) : null;
	}

	private static DmarcResult error(String reason) {
		return new DmarcResult(DmarcResult.Result.PERMERROR, null, null, null, null, null, false, null, reason);
	}

	/** The addresses of an address-list (commas outside quotes, comments and angle brackets; groups opened). */
	static List<String> addresses(String value) {
		List<String> ret = new ArrayList<>();
		String v = HeaderFields.stripComments(value);
		StringBuilder cur = new StringBuilder();
		boolean quoted = false;
		boolean angle = false;
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			if (quoted) {
				cur.append(c);
				if (c == '\\' && i + 1 < v.length()) {
					cur.append(v.charAt(++i));
				} else if (c == '"') {
					quoted = false;
				}
				continue;
			}
			if (c == '"') {
				quoted = true;
			} else if (c == '<') {
				angle = true;
			} else if (c == '>') {
				angle = false;
			} else if (!angle && (c == ',' || c == ';')) {
				add(ret, cur);
				continue;
			} else if (!angle && c == ':') {
				cur.setLength(0); // a group name
				continue;
			}
			cur.append(c);
		}
		add(ret, cur);
		return ret;
	}

	private static void add(List<String> list, StringBuilder sb) {
		String s = sb.toString().trim();
		if (!s.isEmpty()) {
			list.add(s);
		}
		sb.setLength(0);
	}
}
