package us.bringardner.parley.smtp.dkim;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.dns.resolve.LookupResult;

/**
 * Verifies the DKIM signatures of a message (RFC 6376 section 6, RFC 8463).
 * <p>
 * The body is read once, in a stream, and hashed for every signature, so a
 * message of any size can be checked. Public keys are found with a
 * {@link DkimKeyLookup} (parley-dns in the SMTP server).
 */
public final class DkimVerifier {

	/** Signatures beyond this many are ignored (RFC 6376 section 6.1 allows a limit). */
	public static final int DEFAULT_MAX_SIGNATURES = 5;

	private final DkimKeyLookup lookup;
	private int maxSignatures = DEFAULT_MAX_SIGNATURES;
	private java.util.function.LongSupplier clock = () -> System.currentTimeMillis() / 1000;

	public DkimVerifier(DkimKeyLookup lookup) {
		this.lookup = lookup;
	}

	public void setMaxSignatures(int max) {
		this.maxSignatures = Math.max(1, max);
	}

	/** The time (seconds since 1970) to check x= against; for tests. */
	public void setClock(java.util.function.LongSupplier clock) {
		this.clock = clock;
	}

	/** One signature being checked. */
	private static final class Check {
		final String raw;
		DkimSignature sig;
		Canonicalization.BodyHasher body;
		DkimResult result;

		Check(String raw) {
			this.raw = raw;
		}
	}

	/**
	 * Verify every signature (up to the limit), top to bottom.
	 *
	 * @return one result per signature, or a single {@link DkimResult.Result#NONE}
	 */
	public List<DkimResult> verify(InputStream message) throws IOException {
		InputStream in = message instanceof BufferedInputStream ? message : new BufferedInputStream(message, 64 * 1024);
		HeaderFields fields = HeaderFields.read(in);
		long now = clock.getAsLong();
		List<Check> checks = new ArrayList<>();
		for (HeaderFields.Field f : fields.getAll(DkimSignature.HEADER)) {
			if (checks.size() >= maxSignatures) {
				break;
			}
			Check c = new Check(f.getRaw());
			try {
				c.sig = DkimSignature.parse(f.getRaw(), now);
				c.body = c.sig.bodyCanon.bodyHasher(MessageDigest.getInstance("SHA-256"), c.sig.length);
			} catch (DkimException e) {
				c.result = error(c, e);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
			checks.add(c);
		}
		List<DkimResult> ret = new ArrayList<>();
		if (checks.isEmpty()) {
			ret.add(DkimResult.none());
			return ret;
		}

		// one pass over the body for all the signatures
		byte[] buf = new byte[64 * 1024];
		int n;
		boolean any = false;
		for (Check c : checks) {
			any |= c.body != null;
		}
		while (any && (n = in.read(buf)) > 0) {
			for (Check c : checks) {
				if (c.body != null) {
					c.body.write(buf, 0, n);
				}
			}
		}

		for (Check c : checks) {
			if (c.result == null) {
				try {
					c.result = check(c, fields);
				} catch (DkimException e) {
					c.result = error(c, e);
				}
			}
			ret.add(c.result);
		}
		return ret;
	}

	private DkimResult check(Check c, HeaderFields fields) throws DkimException {
		DkimSignature s = c.sig;
		byte[] bh = c.body.finish();
		if (s.length >= 0 && c.body.getCanonicalLength() < s.length) {
			throw DkimException.perm("l= is longer than the body");
		}
		if (!MessageDigest.isEqual(bh, s.bodyHash)) {
			throw DkimException.fail("body hash did not verify");
		}
		Key key = findKey(s);
		byte[] data = DkimSigner.headerHashInput(fields.getFields(), s.signedHeaders, s.headerCanon, s.raw);
		boolean ok;
		try {
			Signature v;
			if (s.algorithm.equals(DkimSigner.RSA_SHA256)) {
				v = Signature.getInstance("SHA256withRSA");
				v.initVerify(key.publicKey);
				v.update(data);
			} else {
				v = Signature.getInstance("Ed25519");
				v.initVerify(key.publicKey);
				v.update(MessageDigest.getInstance("SHA-256").digest(data));
			}
			ok = v.verify(s.signature);
		} catch (NoSuchAlgorithmException e) {
			throw DkimException.perm(s.algorithm + " is not supported by this Java (Ed25519 needs Java 15)");
		} catch (GeneralSecurityException e) {
			ok = false; // e.g. a signature of the wrong length
		}
		if (!ok) {
			throw new DkimException(DkimResult.Result.FAIL, "signature did not verify");
		}
		return new DkimResult(DkimResult.Result.PASS, null, s.domain, s.identity, s.selector, s.algorithm, s.signatureText,
				key.testing);
	}

	/** A usable public key. */
	private static final class Key {
		PublicKey publicKey;
		boolean testing;
	}

	/** Find and check the key for a signature (section 6.1.2). */
	private Key findKey(DkimSignature s) throws DkimException {
		LookupResult<String> r;
		try {
			r = lookup.txt(s.keyName());
		} catch (RuntimeException e) {
			throw DkimException.temp("key lookup failed");
		}
		switch (r.getStatus()) {
		case TEMPFAIL:
			throw DkimException.temp("key lookup failed");
		case NXDOMAIN:
		case NODATA:
			throw DkimException.perm("no key for signature");
		default:
			break;
		}
		DkimException last = null;
		for (String record : r.getValues()) {
			try {
				return parseKey(record, s);
			} catch (DkimException e) {
				last = e;
			}
		}
		throw last != null ? last : DkimException.perm("no key for signature");
	}

	/** Parse a key record and check it fits the signature. */
	static Key parseKey(String record, DkimSignature s) throws DkimException {
		Map<String, String> t = TagList.parse(record);
		String v = t.get("v");
		if (v != null && !v.equals("DKIM1")) {
			throw DkimException.perm("key record version is not DKIM1");
		}
		String k = t.getOrDefault("k", "rsa").toLowerCase(Locale.ROOT);
		String expected = s.algorithm.equals(DkimSigner.RSA_SHA256) ? "rsa" : "ed25519";
		if (!k.equals("rsa") && !k.equals("ed25519")) {
			throw DkimException.perm("unsupported key type k=" + TagList.abbreviate(k));
		}
		if (!k.equals(expected)) {
			throw DkimException.perm("key type k=" + k + " does not match a=" + s.algorithm);
		}
		String h = t.get("h");
		if (h != null) {
			boolean sha256 = false;
			for (String alg : h.split(":")) {
				sha256 |= alg.trim().equalsIgnoreCase("sha256");
			}
			if (!sha256) {
				throw DkimException.perm("key does not allow sha256");
			}
		}
		String svc = t.get("s");
		if (svc != null) {
			boolean email = false;
			for (String st : svc.split(":")) {
				email |= st.trim().equals("*") || st.trim().equalsIgnoreCase("email");
			}
			if (!email) {
				throw DkimException.perm("key is not for email");
			}
		}
		boolean testing = false;
		String flags = t.get("t");
		if (flags != null) {
			for (String f : flags.split(":")) {
				String flag = f.trim().toLowerCase(Locale.ROOT);
				if (flag.equals("y")) {
					testing = true;
				} else if (flag.equals("s")) {
					String id = s.identity.substring(s.identity.lastIndexOf('@') + 1).toLowerCase(Locale.ROOT);
					if (!id.equals(s.domain)) {
						throw DkimException.perm("key requires i= to be in d= exactly (t=s)");
					}
				}
			}
		}
		String p = t.get("p");
		if (p == null) {
			throw DkimException.perm("key record has no p=");
		}
		byte[] keyBytes = TagList.base64(p, "p");
		if (keyBytes.length == 0) {
			throw DkimException.perm("key revoked");
		}
		Key key = new Key();
		key.publicKey = DkimKeys.publicKey(k, keyBytes);
		key.testing = testing;
		return key;
	}

	private static DkimResult error(Check c, DkimException e) {
		DkimSignature s = c.sig;
		if (s != null) {
			return new DkimResult(e.result, e.getMessage(), s.domain, s.identity, s.selector, s.algorithm, s.signatureText,
					false);
		}
		// not parsed: report what can be read from the field
		String d = null;
		String sel = null;
		String b = null;
		try {
			Map<String, String> t = TagList.parse(c.raw.substring(c.raw.indexOf(':') + 1));
			d = t.get("d") == null ? null : t.get("d").trim().toLowerCase(Locale.ROOT);
			sel = t.get("s") == null ? null : t.get("s").trim();
			b = t.get("b") == null ? null : t.get("b").replaceAll("[ \\t\\r\\n]", "");
		} catch (DkimException ignore) {
			// nothing readable
		}
		return new DkimResult(e.result, e.getMessage(), d, null, sel, null, b, false);
	}
}
