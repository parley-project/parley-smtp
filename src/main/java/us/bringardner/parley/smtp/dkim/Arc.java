package us.bringardner.parley.smtp.dkim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The ARC settings of an SMTP server (RFC 8617): whether the chains of
 * incoming mail are validated, whether mail forwarded to other servers is
 * sealed, and which sealers are trusted to vouch for mail that fails DMARC.
 * <p>
 * Keys are the DKIM keys ({@link Dkim}): a set is sealed with the key of the
 * seal domain (default the server's host name) or of its closest parent
 * domain. ARC defines only rsa-sha256, so an Ed25519 key doesn't seal.
 */
public final class Arc {

	private volatile boolean verify = true;
	private volatile boolean seal = true;
	private volatile String domain;
	private final List<String> trustedSealers = new CopyOnWriteArrayList<>();

	/** Validate the ARC chains of mail from clients that are not authenticated or trusted (default true). */
	public boolean isVerify() {
		return verify;
	}

	public void setVerify(boolean verify) {
		this.verify = verify;
	}

	/** Add an ARC set to received mail that is forwarded to another server (default true, if a key fits). */
	public boolean isSeal() {
		return seal;
	}

	public void setSeal(boolean seal) {
		this.seal = seal;
	}

	/** The d= of our seals; null (the default) for the server's host name. */
	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain == null || domain.trim().isEmpty() ? null : domain.trim().toLowerCase(Locale.ROOT);
	}

	/**
	 * Domains whose seals are trusted (RFC 8617 section 7.2): mail that fails
	 * DMARC is delivered normally when its chain passes and the newest seal is
	 * from one of these organizational domains.
	 */
	public List<String> getTrustedSealers() {
		return Collections.unmodifiableList(new ArrayList<>(trustedSealers));
	}

	public void addTrustedSealer(String domain) {
		String d = domain.trim().toLowerCase(Locale.ROOT);
		if (!d.isEmpty() && !trustedSealers.contains(d)) {
			trustedSealers.add(d);
		}
	}

	/** Add trusted sealers from a comma or space separated list. */
	public void addTrustedSealers(String list) {
		for (String d : list.split("[,\\s]+")) {
			if (!d.isEmpty()) {
				addTrustedSealer(d);
			}
		}
	}

	public void removeTrustedSealer(String domain) {
		trustedSealers.remove(domain.trim().toLowerCase(Locale.ROOT));
	}

	/**
	 * The sealer for this server, or null if sealing is off or no RSA key fits
	 * the seal domain.
	 */
	public ArcSealer sealer(Dkim dkim, String hostname) {
		if (!seal) {
			return null;
		}
		DkimSigner signer = dkim.signerFor(domain != null ? domain : hostname);
		if (signer == null || !DkimSigner.RSA_SHA256.equals(signer.getAlgorithm())) {
			return null;
		}
		return new ArcSealer(signer);
	}

	/** A verifier that finds keys like DKIM does. */
	public ArcVerifier verifier(Dkim dkim) {
		return new ArcVerifier(dkim.getLookup());
	}
}
