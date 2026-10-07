package us.bringardner.parley.smtp.spf;

import java.net.InetAddress;
import java.util.Locale;

/** The outcome of an SPF check (RFC 7208 sections 2.6 and 9). */
public final class SpfResult {

	/** SPF results, as written in Received-SPF and Authentication-Results. */
	public enum Result {
		/** The domain has no SPF record (or the identity is not a domain). */
		NONE,
		/** The domain makes no statement about this address ("?"). */
		NEUTRAL,
		/** The address is authorized. */
		PASS,
		/** The address is not authorized ("-"). */
		FAIL,
		/** The address is probably not authorized ("~"). */
		SOFTFAIL,
		/** A temporary (DNS) error; trying later may give a result. */
		TEMPERROR,
		/** The record can't be interpreted (syntax, too many lookups...). */
		PERMERROR;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}
	}

	/** Which identity was checked (RFC 7208 section 2.3 and 2.4). */
	public enum Identity {
		MAILFROM, HELO;

		public String keyword() {
			return name().toLowerCase(Locale.ROOT);
		}
	}

	private final Result result;
	private final Identity identity;
	private final String domain;
	private final String sender;
	private final InetAddress ip;
	private final String helo;
	private final String mechanism;
	private final String explanation;
	private final String problem;

	SpfResult(Result result, Identity identity, String domain, String sender, InetAddress ip, String helo, String mechanism,
			String explanation, String problem) {
		this.result = result;
		this.identity = identity;
		this.domain = domain;
		this.sender = sender;
		this.ip = ip;
		this.helo = helo;
		this.mechanism = mechanism;
		this.explanation = explanation;
		this.problem = problem;
	}

	public Result getResult() {
		return result;
	}

	public Identity getIdentity() {
		return identity;
	}

	/** The domain checked: the MAIL FROM domain, or the HELO name. */
	public String getDomain() {
		return domain;
	}

	/** The sender as checked ("postmaster@helo" for a null reverse-path). */
	public String getSender() {
		return sender;
	}

	public InetAddress getIp() {
		return ip;
	}

	public String getHelo() {
		return helo;
	}

	/** The mechanism that matched ("default" if none did), or null. */
	public String getMechanism() {
		return mechanism;
	}

	/** For FAIL: the domain's explanation (the exp= modifier), or a default text. */
	public String getExplanation() {
		return explanation;
	}

	/** For PERMERROR and TEMPERROR: what went wrong. */
	public String getProblem() {
		return problem;
	}

	/**
	 * The value of a Received-SPF field (RFC 7208 section 9.1), e.g.
	 * {@code pass (mx.example.com: domain of a@example.org designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; ...}
	 *
	 * @param receiver this server's host name
	 */
	public String toReceivedSpf(String receiver) {
		java.util.List<String> parts = new java.util.ArrayList<>();
		parts.add("receiver=" + receiver + ";");
		if (ip != null) {
			parts.add("client-ip=" + SpfChecker.readableIp(ip) + ";");
		}
		if (sender != null) {
			parts.add("envelope-from=" + quote(sender) + ";");
		}
		if (helo != null && !helo.isEmpty()) {
			parts.add("helo=" + (token(helo) ? helo : quote(helo)) + ";");
		}
		if (problem != null) {
			parts.add("problem=" + quote(problem) + ";");
		}
		if (mechanism != null) {
			parts.add("mechanism=" + (token(mechanism) ? mechanism : quote(mechanism)) + ";");
		}
		parts.add("identity=" + identity.keyword() + ";");
		StringBuilder sb = new StringBuilder(result.keyword()).append(" (").append(comment(receiver)).append(")");
		int col = 78; // start the pairs on a new line
		for (String p : parts) {
			if (col + 1 + p.length() > 78) {
				sb.append("\r\n\t");
				col = 1;
			} else {
				sb.append(' ');
				col++;
			}
			sb.append(p);
			col += p.length();
		}
		return sb.toString();
	}

	private String comment(String receiver) {
		String who = identity == Identity.HELO ? "domain of " + domain : "domain of " + sender;
		String addr = ip == null ? "the client" : SpfChecker.readableIp(ip);
		String text;
		switch (result) {
		case PASS:
			text = who + " designates " + addr + " as permitted sender";
			break;
		case FAIL:
			text = who + " does not designate " + addr + " as permitted sender";
			break;
		case SOFTFAIL:
			text = "transitioning " + who + " does not designate " + addr + " as permitted sender";
			break;
		case NEUTRAL:
			text = addr + " is neither permitted nor denied by " + who;
			break;
		case NONE:
			text = who + " does not designate permitted sender hosts";
			break;
		case TEMPERROR:
			text = "error in processing during lookup of " + domain;
			break;
		default:
			text = "error in the SPF record of " + domain;
		}
		return receiver + ": " + text.replace('(', '[').replace(')', ']');
	}

	/**
	 * This result as a method in an Authentication-Results field (RFC 8601),
	 * e.g. {@code spf=pass smtp.mailfrom=example.org}.
	 */
	public String toAuthResults() {
		StringBuilder sb = new StringBuilder("spf=").append(result.keyword());
		if (problem != null) {
			sb.append(" reason=").append(quote(problem));
		}
		if (identity == Identity.HELO) {
			sb.append(" smtp.helo=").append(token(domain) ? domain : quote(domain));
		} else {
			sb.append(" smtp.mailfrom=").append(token(domain) ? domain : quote(domain));
		}
		return sb.toString();
	}

	private static boolean token(String v) {
		return v != null && v.matches("[A-Za-z0-9!#$%&'*+.^_`{|}~@-]+");
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
		return result.keyword() + (problem != null ? " (" + problem + ")" : "") + " " + identity.keyword() + "=" + domain;
	}
}
