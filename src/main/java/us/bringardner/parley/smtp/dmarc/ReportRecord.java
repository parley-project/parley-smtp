package us.bringardner.parley.smtp.dmarc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * What a DMARC aggregate report says about one message (RFC 7489 appendix C):
 * where it came from, the identifiers, the policy evaluated and the raw
 * SPF and DKIM results. Stored one per line until the report is sent.
 */
public final class ReportRecord {

	/** One DKIM result in auth_results. */
	public static final class Dkim {
		public final String domain;
		public final String selector;
		public final String result;

		public Dkim(String domain, String selector, String result) {
			this.domain = domain;
			this.selector = selector;
			this.result = result;
		}
	}

	final long time;
	final String sourceIp;
	final String headerFrom;
	final String envelopeFrom;
	final String policyDomain;
	/** The published record, as written (for policy_published). */
	final String policyRecord;
	/** none, quarantine or reject: what was actually done. */
	final String disposition;
	/** pass or fail: the aligned DKIM and SPF results. */
	final String dkimAligned;
	final String spfAligned;
	/** A PolicyOverrideType (local_policy, sampled_out...) or empty. */
	final String reason;
	final String reasonComment;
	final List<Dkim> dkim;
	final String spfDomain;
	/** mfrom or helo */
	final String spfScope;
	final String spfResult;

	public ReportRecord(long time, String sourceIp, String headerFrom, String envelopeFrom, String policyDomain,
			String policyRecord, String disposition, String dkimAligned, String spfAligned, String reason, String reasonComment,
			List<Dkim> dkim, String spfDomain, String spfScope, String spfResult) {
		this.time = time;
		this.sourceIp = sourceIp;
		this.headerFrom = lower(headerFrom);
		this.envelopeFrom = lower(envelopeFrom);
		this.policyDomain = lower(policyDomain);
		this.policyRecord = policyRecord == null ? "" : policyRecord;
		this.disposition = disposition;
		this.dkimAligned = dkimAligned;
		this.spfAligned = spfAligned;
		this.reason = reason == null ? "" : reason;
		this.reasonComment = reasonComment == null ? "" : reasonComment;
		this.dkim = Collections.unmodifiableList(new ArrayList<>(dkim));
		this.spfDomain = lower(spfDomain);
		this.spfScope = spfScope == null ? "mfrom" : spfScope;
		this.spfResult = spfResult == null ? "none" : spfResult;
	}

	public String getPolicyDomain() {
		return policyDomain;
	}

	public long getTime() {
		return time;
	}

	private static String lower(String s) {
		return s == null ? "" : s.toLowerCase(Locale.ROOT);
	}

	/** Everything a report row groups by (all but the time). */
	String key() {
		StringBuilder sb = new StringBuilder();
		sb.append(sourceIp).append('\0').append(headerFrom).append('\0').append(disposition).append('\0').append(dkimAligned)
				.append('\0').append(spfAligned).append('\0').append(reason).append('\0').append(reasonComment).append('\0')
				.append(spfDomain).append('\0').append(spfScope).append('\0').append(spfResult);
		for (Dkim d : dkim) {
			sb.append('\0').append(d.domain).append('|').append(d.selector).append('|').append(d.result);
		}
		return sb.toString();
	}

	// ------------------------------------------------------------------ storage

	/** One line, tab separated (tabs, line ends and backslashes escaped). */
	String toLine() {
		StringBuilder dk = new StringBuilder();
		for (Dkim d : dkim) {
			if (dk.length() > 0) {
				dk.append(' ');
			}
			dk.append(esc2(d.domain)).append('|').append(esc2(d.selector)).append('|').append(esc2(d.result));
		}
		String[] f = {"1", Long.toString(time), sourceIp, headerFrom, envelopeFrom, policyDomain, policyRecord, disposition,
				dkimAligned, spfAligned, reason, reasonComment, dk.toString(), spfDomain, spfScope, spfResult};
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < f.length; i++) {
			if (i > 0) {
				sb.append('\t');
			}
			sb.append(esc(f[i]));
		}
		return sb.append('\n').toString();
	}

	/** Parse a stored line; null if it is damaged or from another version. */
	static ReportRecord fromLine(String line) {
		String[] f = line.split("\t", -1);
		if (f.length != 16 || !f[0].equals("1")) {
			return null;
		}
		for (int i = 0; i < f.length; i++) {
			f[i] = unesc(f[i]);
		}
		try {
			List<Dkim> dk = new ArrayList<>();
			if (!f[12].isEmpty()) {
				for (String d : f[12].split(" ")) {
					String[] p = d.split("\\|", -1);
					if (p.length == 3) {
						dk.add(new Dkim(unesc2(p[0]), unesc2(p[1]), unesc2(p[2])));
					}
				}
			}
			return new ReportRecord(Long.parseLong(f[1]), f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], dk, f[13],
					f[14], f[15]);
		} catch (RuntimeException e) {
			return null;
		}
	}

	private static String esc(String s) {
		return s == null ? "" : s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
	}

	private static String unesc(String s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '\\' && i + 1 < s.length()) {
				char n = s.charAt(++i);
				sb.append(n == 't' ? '\t' : n == 'n' ? '\n' : n == 'r' ? '\r' : n);
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/** Inside the DKIM list: also ' ' and '|'. */
	private static String esc2(String s) {
		return s == null ? "" : s.replace("%", "%25").replace(" ", "%20").replace("|", "%7C");
	}

	private static String unesc2(String s) {
		return s.replace("%7C", "|").replace("%20", " ").replace("%25", "%");
	}
}
