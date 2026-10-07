package us.bringardner.parley.smtp.dmarc;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the XML of a DMARC aggregate report (RFC 7489 section 7.2 and the
 * schema in appendix C) for one policy domain: identical evaluations are
 * counted in one row.
 */
public final class AggregateReport {

	private AggregateReport() {
	}

	/**
	 * @param orgName  the reporting organization (report_metadata/org_name)
	 * @param email    its contact address
	 * @param reportId unique for this report
	 * @param begin    start of the reporting period (seconds since 1970)
	 * @param end      end of the period
	 * @param domain   the policy domain
	 * @param records  the evaluations (all for this domain); the policy of the last one is reported
	 */
	public static String xml(String orgName, String email, String reportId, long begin, long end, String domain,
			List<ReportRecord> records) {
		StringBuilder x = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<feedback>\n");
		el(x, 2, "version", "1.0");
		x.append("  <report_metadata>\n");
		el(x, 4, "org_name", orgName);
		el(x, 4, "email", email);
		el(x, 4, "report_id", reportId);
		x.append("    <date_range>\n");
		el(x, 6, "begin", Long.toString(begin));
		el(x, 6, "end", Long.toString(end));
		x.append("    </date_range>\n  </report_metadata>\n");

		DmarcRecord policy = null;
		for (ReportRecord r : records) {
			DmarcRecord p = DmarcRecord.parse(r.policyRecord);
			if (p != null) {
				policy = p;
			}
		}
		x.append("  <policy_published>\n");
		el(x, 4, "domain", domain);
		if (policy != null) {
			el(x, 4, "adkim", policy.isStrictDkim() ? "s" : "r");
			el(x, 4, "aspf", policy.isStrictSpf() ? "s" : "r");
			el(x, 4, "p", policy.getPolicy().keyword());
			el(x, 4, "sp", (policy.getSubdomainPolicy() != null ? policy.getSubdomainPolicy() : policy.getPolicy()).keyword());
			el(x, 4, "pct", Integer.toString(policy.getPercent()));
			el(x, 4, "fo", policy.getTags().getOrDefault("fo", "0"));
		} else {
			el(x, 4, "p", "none");
			el(x, 4, "sp", "none");
			el(x, 4, "pct", "100");
			el(x, 4, "fo", "0");
		}
		x.append("  </policy_published>\n");

		Map<String, ReportRecord> rows = new LinkedHashMap<>();
		Map<String, Integer> counts = new LinkedHashMap<>();
		for (ReportRecord r : records) {
			String k = r.key();
			rows.putIfAbsent(k, r);
			counts.merge(k, 1, Integer::sum);
		}
		for (Map.Entry<String, ReportRecord> e : rows.entrySet()) {
			ReportRecord r = e.getValue();
			x.append("  <record>\n    <row>\n");
			el(x, 6, "source_ip", r.sourceIp);
			el(x, 6, "count", Integer.toString(counts.get(e.getKey())));
			x.append("      <policy_evaluated>\n");
			el(x, 8, "disposition", r.disposition);
			el(x, 8, "dkim", r.dkimAligned);
			el(x, 8, "spf", r.spfAligned);
			if (!r.reason.isEmpty()) {
				x.append("        <reason>\n");
				el(x, 10, "type", r.reason);
				if (!r.reasonComment.isEmpty()) {
					el(x, 10, "comment", r.reasonComment);
				}
				x.append("        </reason>\n");
			}
			x.append("      </policy_evaluated>\n    </row>\n    <identifiers>\n");
			el(x, 6, "envelope_from", r.envelopeFrom.substring(r.envelopeFrom.lastIndexOf('@') + 1));
			el(x, 6, "header_from", r.headerFrom);
			x.append("    </identifiers>\n    <auth_results>\n");
			for (ReportRecord.Dkim d : r.dkim) {
				x.append("      <dkim>\n");
				el(x, 8, "domain", d.domain);
				if (!d.selector.isEmpty()) {
					el(x, 8, "selector", d.selector);
				}
				el(x, 8, "result", d.result);
				x.append("      </dkim>\n");
			}
			x.append("      <spf>\n");
			el(x, 8, "domain", r.spfDomain);
			el(x, 8, "scope", r.spfScope);
			el(x, 8, "result", r.spfResult);
			x.append("      </spf>\n    </auth_results>\n  </record>\n");
		}
		return x.append("</feedback>\n").toString();
	}

	private static void el(StringBuilder x, int indent, String name, String value) {
		for (int i = 0; i < indent; i++) {
			x.append(' ');
		}
		x.append('<').append(name).append('>').append(escape(value)).append("</").append(name).append(">\n");
	}

	static String escape(String s) {
		StringBuilder sb = new StringBuilder();
		String v = s == null ? "" : s;
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			switch (c) {
			case '<':
				sb.append("&lt;");
				break;
			case '>':
				sb.append("&gt;");
				break;
			case '&':
				sb.append("&amp;");
				break;
			case '"':
				sb.append("&quot;");
				break;
			default:
				if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
					sb.append('?'); // not allowed in XML 1.0
				} else {
					sb.append(c);
				}
			}
		}
		return sb.toString();
	}
}
