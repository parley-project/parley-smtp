package us.bringardner.parley.smtp.dkim;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** The Chain Validation Status of a message's ARC chain (RFC 8617 section 4.4). */
public final class ArcResult {

	public enum Result {
		/** No ARC sets. */
		NONE,
		/** The chain validated. */
		PASS,
		/** The chain is broken (structure, signature or DNS: all failures are permanent). */
		FAIL;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}
	}

	/** What one ARC set's seal says. */
	public static final class Seal {
		public final int instance;
		public final String domain;
		public final String selector;
		/** smtp.remote-ip from the set's ARC-Authentication-Results, or null. */
		public final String remoteIp;

		Seal(int instance, String domain, String selector, String remoteIp) {
			this.instance = instance;
			this.domain = domain;
			this.selector = selector;
			this.remoteIp = remoteIp;
		}
	}

	private final Result result;
	private final String reason;
	private final List<Seal> seals;

	ArcResult(Result result, String reason, List<Seal> seals) {
		this.result = result;
		this.reason = reason;
		this.seals = seals == null ? Collections.emptyList() : Collections.unmodifiableList(seals);
	}

	public Result getResult() {
		return result;
	}

	public boolean isPass() {
		return result == Result.PASS;
	}

	/** Why the chain failed (null otherwise). */
	public String getReason() {
		return reason;
	}

	/** The seals of a passing chain, newest first (empty otherwise). */
	public List<Seal> getSeals() {
		return seals;
	}

	/** The d= of the newest seal of a passing chain, or null. */
	public String getLatestSealDomain() {
		return seals.isEmpty() ? null : seals.get(0).domain;
	}

	/** e.g. {@code arc=pass (as[2].d=lists.example.org as[1].d=example.com)} */
	public String toAuthResults() {
		return toAuthResults(null);
	}

	/**
	 * The result with the client's address as the smtp.remote-ip property (RFC
	 * 8617 section 10.1), which a later ARC set records for DMARC reports.
	 */
	public String toAuthResults(String remoteIp) {
		String s = toAuthResultsNoIp();
		return remoteIp == null ? s : s + " smtp.remote-ip=" + remoteIp;
	}

	private String toAuthResultsNoIp() {
		StringBuilder sb = new StringBuilder("arc=").append(result.keyword());
		if (!seals.isEmpty()) {
			sb.append(" (");
			for (int i = 0; i < seals.size(); i++) {
				Seal s = seals.get(i);
				sb.append(i > 0 ? " " : "").append("as[").append(s.instance).append("].d=").append(s.domain);
			}
			sb.append(')');
		}
		if (reason != null) {
			sb.append(" reason=").append(DkimResult.quote(reason));
		}
		return sb.toString();
	}

	/**
	 * The DMARC report comment for a local policy override based on ARC
	 * (RFC 8617 section 7.2.2), e.g.
	 * {@code arc=pass as[2].d=d2.example as[2].s=s2 as[1].d=d1.example as[1].s=s3 remote-ip[1]=192.0.2.1}.
	 */
	public String toReportComment() {
		StringBuilder sb = new StringBuilder("arc=").append(result.keyword());
		String firstIp = null;
		for (Seal s : seals) {
			sb.append(" as[").append(s.instance).append("].d=").append(s.domain).append(" as[").append(s.instance).append("].s=")
					.append(s.selector);
			if (s.instance == 1) {
				firstIp = s.remoteIp;
			}
		}
		if (firstIp != null) {
			sb.append(" remote-ip[1]=").append(firstIp);
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return toAuthResults();
	}
}
