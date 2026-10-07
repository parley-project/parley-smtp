package us.bringardner.parley.smtp.dmarc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** A DMARC policy record (RFC 7489 section 6.3), published at _dmarc.domain. */
public final class DmarcRecord {

	/** What the domain asks receivers to do with mail that fails DMARC. */
	public enum Policy {
		NONE, QUARANTINE, REJECT;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}

		static Policy parse(String s) {
			switch (s.trim().toLowerCase(Locale.ROOT)) {
			case "none":
				return NONE;
			case "quarantine":
				return QUARANTINE;
			case "reject":
				return REJECT;
			default:
				return null;
			}
		}
	}

	private final Map<String, String> tags;
	private final Policy policy;
	private final Policy subdomainPolicy;
	private final boolean strictDkim;
	private final boolean strictSpf;
	private final int percent;
	private final List<String> aggregateReports;
	private final List<String> failureReports;

	private DmarcRecord(Map<String, String> tags, Policy policy, Policy subdomainPolicy, boolean strictDkim, boolean strictSpf,
			int percent, List<String> rua, List<String> ruf) {
		this.tags = Collections.unmodifiableMap(tags);
		this.policy = policy;
		this.subdomainPolicy = subdomainPolicy;
		this.strictDkim = strictDkim;
		this.strictSpf = strictSpf;
		this.percent = percent;
		this.aggregateReports = Collections.unmodifiableList(rua);
		this.failureReports = Collections.unmodifiableList(ruf);
	}

	/** True if a TXT record is meant as a DMARC record (it starts with v=DMARC1). */
	static boolean isDmarc(String txt) {
		String t = txt.trim();
		if (!t.startsWith("v")) {
			return false;
		}
		int semi = t.indexOf(';');
		String first = semi < 0 ? t : t.substring(0, semi);
		int eq = first.indexOf('=');
		return eq > 0 && first.substring(0, eq).trim().equals("v") && first.substring(eq + 1).trim().equals("DMARC1");
	}

	/**
	 * Parse a record. Following section 6.6.3, a missing or invalid p= makes
	 * it p=none if the record has a valid rua= (so reports still flow);
	 * otherwise the record is unusable (null). Other invalid values get their
	 * defaults; unknown tags are ignored.
	 *
	 * @return the record, or null if it can't be used
	 */
	public static DmarcRecord parse(String txt) {
		if (!isDmarc(txt)) {
			return null;
		}
		Map<String, String> tags = new LinkedHashMap<>();
		for (String part : txt.split(";")) {
			int eq = part.indexOf('=');
			if (eq <= 0) {
				continue;
			}
			String name = part.substring(0, eq).trim().toLowerCase(Locale.ROOT);
			if (!tags.containsKey(name)) {
				tags.put(name, part.substring(eq + 1).trim());
			}
		}
		List<String> rua = uris(tags.get("rua"));
		List<String> ruf = uris(tags.get("ruf"));
		Policy p = tags.get("p") == null ? null : Policy.parse(tags.get("p"));
		if (p == null) {
			if (rua.isEmpty()) {
				return null;
			}
			p = Policy.NONE;
		}
		Policy sp = tags.get("sp") == null ? null : Policy.parse(tags.get("sp"));
		boolean adkim = "s".equalsIgnoreCase(tags.getOrDefault("adkim", "r").trim());
		boolean aspf = "s".equalsIgnoreCase(tags.getOrDefault("aspf", "r").trim());
		int pct = 100;
		String pctText = tags.get("pct");
		if (pctText != null && pctText.trim().matches("[0-9]{1,3}")) {
			pct = Math.min(100, Integer.parseInt(pctText.trim()));
		}
		return new DmarcRecord(tags, p, sp, adkim, aspf, pct, rua, ruf);
	}

	private static List<String> uris(String value) {
		List<String> ret = new ArrayList<>();
		if (value != null) {
			for (String u : value.split(",")) {
				String t = u.trim();
				if (t.regionMatches(true, 0, "mailto:", 0, 7) || t.regionMatches(true, 0, "https:", 0, 6)
						|| t.regionMatches(true, 0, "http:", 0, 5)) {
					ret.add(t);
				}
			}
		}
		return ret;
	}

	/** p= */
	public Policy getPolicy() {
		return policy;
	}

	/** sp= (null if absent: p= applies to subdomains too). */
	public Policy getSubdomainPolicy() {
		return subdomainPolicy;
	}

	/** adkim=s */
	public boolean isStrictDkim() {
		return strictDkim;
	}

	/** aspf=s */
	public boolean isStrictSpf() {
		return strictSpf;
	}

	/** pct= (0-100, default 100). */
	public int getPercent() {
		return percent;
	}

	/** rua= URIs (aggregate reports; not sent by this server). */
	public List<String> getAggregateReports() {
		return aggregateReports;
	}

	/** ruf= URIs (failure reports; not sent by this server). */
	public List<String> getFailureReports() {
		return failureReports;
	}

	/** All tags as written (names lower case). */
	public Map<String, String> getTags() {
		return tags;
	}
}
