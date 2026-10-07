package us.bringardner.parley.smtp.dmarc;

import java.io.IOException;

import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.smtp.queue.ParleyDnsMxResolver;

/**
 * The DMARC settings of an SMTP server: whether mail from other servers is
 * checked, and whether the domain's policy is enforced (reject at the end of
 * DATA, quarantine to the recipient's Junk mailbox).
 */
public final class Dmarc {

	private volatile boolean check = true;
	private volatile boolean enforce;
	private volatile DmarcDns dns;
	private volatile PublicSuffixList publicSuffixList;
	private final DmarcReporter reporter = new DmarcReporter();

	/** Check DMARC for clients that are not authenticated or trusted (default true). */
	public boolean isCheck() {
		return check;
	}

	public void setCheck(boolean check) {
		this.check = check;
	}

	/**
	 * Act on the policy of a domain whose mail fails DMARC (default false: the
	 * result is only recorded): p=reject is refused with 550 5.7.1, and
	 * p=quarantine is delivered to the Junk mailbox.
	 */
	public boolean isEnforce() {
		return enforce;
	}

	public void setEnforce(boolean enforce) {
		this.enforce = enforce;
	}

	/** How policy records are found. If none is set, parley-dns (as for DKIM keys). */
	public void setDns(DmarcDns dns) {
		this.dns = dns;
	}

	public DmarcDns getDns() {
		DmarcDns ret = dns;
		if (ret == null) {
			synchronized (this) {
				if (dns == null) {
					try {
						dns = new ParleyDnsMxResolver()::txt;
					} catch (IOException e) {
						dns = Lookup::txt;
					}
				}
				ret = dns;
			}
		}
		return ret;
	}

	/** The public suffix list for organizational domains (default: the included copy). */
	public void setPublicSuffixList(PublicSuffixList list) {
		this.publicSuffixList = list;
	}

	public PublicSuffixList getPublicSuffixList() {
		PublicSuffixList l = publicSuffixList;
		return l != null ? l : PublicSuffixList.getDefault();
	}

	/** Aggregate and failure reports (off unless enabled). */
	public DmarcReporter getReporter() {
		return reporter;
	}

	public DmarcChecker checker() {
		return new DmarcChecker(getDns(), getPublicSuffixList());
	}
}
