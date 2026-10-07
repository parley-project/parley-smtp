package us.bringardner.parley.smtp.spf;

import java.io.IOException;

import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.smtp.queue.ParleyDnsMxResolver;

/**
 * The SPF settings of an SMTP server (RFC 7208): whether the MAIL FROM
 * identity of mail from other servers is checked, and whether a "fail" is
 * rejected.
 */
public final class Spf {

	private volatile boolean check = true;
	private volatile boolean rejectFail;
	private volatile SpfDns dns;

	/** Check SPF for clients that are not authenticated or trusted (default true). */
	public boolean isCheck() {
		return check;
	}

	public void setCheck(boolean check) {
		this.check = check;
	}

	/**
	 * Reject MAIL FROM with 550 5.7.23 when the result is "fail" (default
	 * false: the result is only recorded, for DMARC or filters to act on).
	 */
	public boolean isRejectFail() {
		return rejectFail;
	}

	public void setRejectFail(boolean rejectFail) {
		this.rejectFail = rejectFail;
	}

	/**
	 * How DNS queries are made. If none is set, parley-dns is used: a stub
	 * resolver asking the servers in /etc/resolv.conf, else parley-dns's own
	 * iterative resolver.
	 */
	public void setDns(SpfDns dns) {
		this.dns = dns;
	}

	public SpfDns getDns() {
		SpfDns ret = dns;
		if (ret == null) {
			synchronized (this) {
				if (dns == null) {
					dns = defaultDns();
				}
				ret = dns;
			}
		}
		return ret;
	}

	private static SpfDns defaultDns() {
		try {
			return new ParleyDnsMxResolver()::records;
		} catch (IOException e) {
			return Lookup::records;
		}
	}

	/** A checker using these settings. */
	public SpfChecker checker(String receiver) {
		return new SpfChecker(getDns(), receiver);
	}
}
