package us.bringardner.parley.smtp.dkim;

import java.util.Locale;

/** The outcome of verifying one DKIM signature (RFC 6376 section 6, RFC 8601 section 2.7.1). */
public final class DkimResult {

	/** Result values, as written in Authentication-Results. */
	public enum Result {
		/** The signature verified. */
		PASS,
		/** The signature or body hash did not verify. */
		FAIL,
		/** The signature could not be checked (e.g. an unsupported algorithm in the key). */
		NEUTRAL,
		/** The signature verified but is not acceptable by local policy. */
		POLICY,
		/** A temporary problem, usually DNS; trying again later may give another result. */
		TEMPERROR,
		/** A permanent problem with the signature or key (syntax, no key, revoked key...). */
		PERMERROR,
		/** The message has no signature. */
		NONE;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}
	}

	private final Result result;
	private final String reason;
	private final String domain;
	private final String identity;
	private final String selector;
	private final String algorithm;
	private final String signature;
	private final boolean testing;

	DkimResult(Result result, String reason, String domain, String identity, String selector, String algorithm,
			String signature, boolean testing) {
		this.result = result;
		this.reason = reason;
		this.domain = domain;
		this.identity = identity;
		this.selector = selector;
		this.algorithm = algorithm;
		this.signature = signature;
		this.testing = testing;
	}

	static DkimResult none() {
		return new DkimResult(Result.NONE, null, null, null, null, null, null, false);
	}

	public Result getResult() {
		return result;
	}

	public boolean isPass() {
		return result == Result.PASS;
	}

	/** Why the result is not pass (null for pass and none). */
	public String getReason() {
		return reason;
	}

	/** The signing domain (d=), or null if the signature couldn't be parsed that far. */
	public String getDomain() {
		return domain;
	}

	/** The agent or user identifier (i=, or "@" + d=). */
	public String getIdentity() {
		return identity;
	}

	public String getSelector() {
		return selector;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	/** The b= value (for header.b, RFC 6008). */
	public String getSignature() {
		return signature;
	}

	/** The key is in testing mode (t=y): the result shouldn't change how the message is treated. */
	public boolean isTesting() {
		return testing;
	}

	/**
	 * This result as a method in an Authentication-Results field, e.g.
	 * {@code dkim=pass header.d=example.com header.s=sel header.b=AbCd1234}.
	 */
	public String toAuthResults() {
		StringBuilder sb = new StringBuilder("dkim=").append(result.keyword());
		if (reason != null) {
			sb.append(" reason=").append(quote(reason + (testing ? " (key in testing mode)" : "")));
		} else if (testing) {
			sb.append(" reason=\"key in testing mode\"");
		}
		if (domain != null) {
			sb.append(" header.d=").append(pvalue(domain));
		}
		if (identity != null) {
			sb.append(" header.i=").append(pvalue(identity));
		}
		if (selector != null) {
			sb.append(" header.s=").append(pvalue(selector));
		}
		if (algorithm != null) {
			sb.append(" header.a=").append(pvalue(algorithm));
		}
		if (signature != null && !signature.isEmpty()) {
			sb.append(" header.b=").append(pvalue(signature.substring(0, Math.min(8, signature.length()))));
		}
		return sb.toString();
	}

	/** A value as a token (RFC 2045, '@' allowed as in RFC 8601 pvalue) or a quoted string. */
	static String pvalue(String v) {
		return v.matches("[A-Za-z0-9!#$%&'*+.^_`{|}~@-]+") ? v : quote(v);
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
