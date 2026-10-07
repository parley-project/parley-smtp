package us.bringardner.parley.smtp.dmarc;

import java.util.Locale;

import us.bringardner.parley.smtp.dmarc.DmarcRecord.Policy;

/** The outcome of a DMARC check (RFC 7489 sections 4 and 6.6; RFC 8601 section 2.7.1). */
public final class DmarcResult {

	public enum Result {
		/** An aligned SPF or DKIM pass. */
		PASS,
		/** The domain has a policy and neither SPF nor DKIM passed aligned. */
		FAIL,
		/** The From domain has no DMARC record. */
		NONE,
		/** The policy record could not be looked up (DNS). */
		TEMPERROR,
		/** The message has no usable From address (none, several, or not a domain). */
		PERMERROR;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}
	}

	private final Result result;
	private final String fromDomain;
	private final String policyDomain;
	private final DmarcRecord record;
	private final Policy policy;
	private final Policy disposition;
	private final boolean spfAligned;
	private final String dkimDomain;
	private final String reason;

	DmarcResult(Result result, String fromDomain, String policyDomain, DmarcRecord record, Policy policy, Policy disposition,
			boolean spfAligned, String dkimDomain, String reason) {
		this.result = result;
		this.fromDomain = fromDomain;
		this.policyDomain = policyDomain;
		this.record = record;
		this.policy = policy;
		this.disposition = disposition;
		this.spfAligned = spfAligned;
		this.dkimDomain = dkimDomain;
		this.reason = reason;
	}

	public Result getResult() {
		return result;
	}

	public boolean isPass() {
		return result == Result.PASS;
	}

	/** The RFC5322.From domain (null if there wasn't a usable one). */
	public String getFromDomain() {
		return fromDomain;
	}

	/** Where the record was found: the From domain or its organizational domain. */
	public String getPolicyDomain() {
		return policyDomain;
	}

	public DmarcRecord getRecord() {
		return record;
	}

	/** The policy that applies (p= or sp=), or null without a record. */
	public Policy getPolicy() {
		return policy;
	}

	/**
	 * What to do with the message: NONE for a pass or no policy; for a fail
	 * the policy, made milder for mail outside pct= (section 6.6.4).
	 */
	public Policy getDisposition() {
		return disposition;
	}

	public boolean isSpfAligned() {
		return spfAligned;
	}

	/** The d= of an aligned passing DKIM signature, or null. */
	public String getDkimDomain() {
		return dkimDomain;
	}

	/** Why the result is not pass (or null). */
	public String getReason() {
		return reason;
	}

	/** e.g. {@code dmarc=fail (p=reject dis=quarantine) header.from=example.org} */
	public String toAuthResults() {
		StringBuilder sb = new StringBuilder("dmarc=").append(result.keyword());
		if (policy != null) {
			sb.append(" (p=").append(policy.keyword()).append(" dis=").append(disposition.keyword()).append(')');
		}
		if (reason != null && result != Result.FAIL) {
			sb.append(" reason=").append(quote(reason));
		}
		if (fromDomain != null) {
			sb.append(" header.from=").append(fromDomain.matches("[A-Za-z0-9.-]+") ? fromDomain : quote(fromDomain));
		}
		return sb.toString();
	}

	static String quote(String v) {
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < v.length(); i++) {
			char c = v.charAt(i);
			if (c == '"' || c == '\\') {
				sb.append('\\');
			}
			sb.append(c < 32 || c > 126 ? '?' : c);
		}
		return sb.append('"').toString();
	}

	@Override
	public String toString() {
		return toAuthResults();
	}
}
