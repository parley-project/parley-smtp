package us.bringardner.parley.smtp.dkim;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.smtp.queue.ParleyDnsMxResolver;

/**
 * The DKIM settings of an SMTP server: the keys it signs with, one per
 * domain, and whether it verifies the signatures of incoming mail.
 * <p>
 * A message is signed with the key of its From domain, or of the closest
 * parent domain that has one (a key for example.com signs mail from
 * news.example.com, which DMARC's relaxed alignment accepts).
 */
public final class Dkim {

	private final Map<String, DkimSigner> signers = new ConcurrentHashMap<>();
	private volatile boolean verify = true;
	private volatile int maxSignatures = DkimVerifier.DEFAULT_MAX_SIGNATURES;
	private volatile DkimKeyLookup lookup;

	/** Sign mail from this signer's domain (and its subdomains) with it; replaces another key for the domain. */
	public void addSigner(DkimSigner signer) {
		signers.put(signer.getDomain(), signer);
	}

	public void removeSigner(String domain) {
		signers.remove(domain.toLowerCase(Locale.ROOT));
	}

	public List<DkimSigner> getSigners() {
		return Collections.unmodifiableList(new ArrayList<>(signers.values()));
	}

	/** True if any key is configured. */
	public boolean isSigning() {
		return !signers.isEmpty();
	}

	/**
	 * The signer for mail from a domain: the domain's own key, else the
	 * closest parent domain's, else null.
	 */
	public DkimSigner signerFor(String fromDomain) {
		if (fromDomain == null) {
			return null;
		}
		String d = fromDomain.toLowerCase(Locale.ROOT);
		while (true) {
			DkimSigner s = signers.get(d);
			if (s != null) {
				return s;
			}
			int dot = d.indexOf('.');
			if (dot < 0) {
				return null;
			}
			d = d.substring(dot + 1);
		}
	}

	/** Verify the signatures of mail from clients that are not authenticated or trusted (default true). */
	public boolean isVerify() {
		return verify;
	}

	public void setVerify(boolean verify) {
		this.verify = verify;
	}

	public void setMaxSignatures(int maxSignatures) {
		this.maxSignatures = Math.max(1, maxSignatures);
	}

	/**
	 * How public keys are found. If none is set, parley-dns is used: a stub
	 * resolver asking the servers in /etc/resolv.conf, else parley-dns's own
	 * iterative resolver.
	 */
	public void setLookup(DkimKeyLookup lookup) {
		this.lookup = lookup;
	}

	public DkimKeyLookup getLookup() {
		DkimKeyLookup ret = lookup;
		if (ret == null) {
			synchronized (this) {
				if (lookup == null) {
					lookup = defaultLookup();
				}
				ret = lookup;
			}
		}
		return ret;
	}

	private static DkimKeyLookup defaultLookup() {
		try {
			return new ParleyDnsMxResolver()::txt;
		} catch (IOException e) {
			return Lookup::txt;
		}
	}

	/** A verifier with these settings. */
	public DkimVerifier verifier() {
		DkimVerifier v = new DkimVerifier(getLookup());
		v.setMaxSignatures(maxSignatures);
		return v;
	}

	/** Verify a message's signatures. */
	public List<DkimResult> verify(InputStream message) throws IOException {
		return verifier().verify(message);
	}

	/**
	 * Add signers from a list such as
	 * {@code example.com:mail2026:/etc/dkim/example.com.pem,example.org:s1:/etc/dkim/org.pem}
	 * (domain:selector:private key file).
	 *
	 * @param headers fields to sign (comma or colon separated), or null for the defaults
	 */
	public void addSigners(String list, String headers) throws IOException, GeneralSecurityException {
		for (String entry : list.split(",")) {
			String e = entry.trim();
			if (e.isEmpty()) {
				continue;
			}
			String[] p = e.split(":", 3);
			if (p.length != 3) {
				throw new IllegalArgumentException("DKIM key '" + e + "' is not domain:selector:keyfile");
			}
			DkimSigner s = new DkimSigner(p[0].trim(), p[1].trim(), DkimKeys.privateKey(new File(p[2].trim())));
			if (headers != null && !headers.trim().isEmpty()) {
				s.setHeaders(Arrays.asList(headers.trim().split("\\s*[,:]\\s*")));
			}
			addSigner(s);
		}
	}
}
