package us.bringardner.parley.smtp.dkim;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.bringardner.parley.dns.resolve.LookupResult;

/**
 * Validates a message's Authenticated Received Chain (ARC, RFC 8617 section
 * 5.2): the structure of the ARC sets, the newest ARC-Message-Signature, and
 * every ARC-Seal. Keys are found with a {@link DkimKeyLookup} (parley-dns in the
 * server), as for DKIM.
 */
public final class ArcVerifier {

	/** The most ARC sets a message may have (section 4.2.1). */
	public static final int MAX_INSTANCES = 50;

	static final String SEAL = "ARC-Seal";
	static final String SIGNATURE = "ARC-Message-Signature";
	static final String RESULTS = "ARC-Authentication-Results";

	private static final Pattern AAR_INSTANCE = Pattern.compile("\\s*i\\s*=\\s*([0-9]+)\\s*;.*", Pattern.DOTALL);
	private static final Pattern REMOTE_IP = Pattern.compile("smtp\\.remote-ip\\s*=\\s*([0-9A-Fa-f:.]+)");

	private final DkimKeyLookup lookup;

	public ArcVerifier(DkimKeyLookup lookup) {
		this.lookup = lookup;
	}

	/** The fields of one ARC set. */
	static final class Set {
		final List<HeaderFields.Field> seal = new ArrayList<>();
		final List<HeaderFields.Field> signature = new ArrayList<>();
		final List<HeaderFields.Field> results = new ArrayList<>();
		Map<String, String> sealTags;
	}

	/** The ARC sets of a message by instance (an invalid instance is -1). */
	static TreeMap<Integer, Set> sets(HeaderFields headers) {
		TreeMap<Integer, Set> sets = new TreeMap<>();
		for (HeaderFields.Field f : headers.getFields()) {
			boolean seal = f.is(SEAL);
			boolean sig = f.is(SIGNATURE);
			boolean aar = f.is(RESULTS);
			if (!seal && !sig && !aar) {
				continue;
			}
			int i = instance(f);
			Set s = sets.computeIfAbsent(i, k -> new Set());
			(seal ? s.seal : sig ? s.signature : s.results).add(f);
		}
		return sets;
	}

	/** The instance tag of an ARC field, or -1 if it has none or a bad one. */
	static int instance(HeaderFields.Field f) {
		String v = f.getRaw().substring(f.getRaw().indexOf(':') + 1);
		String digits;
		if (f.is(RESULTS)) {
			Matcher m = AAR_INSTANCE.matcher(v);
			if (!m.matches()) {
				return -1;
			}
			digits = m.group(1);
		} else {
			try {
				digits = TagList.parse(v).get("i");
			} catch (DkimException e) {
				return -1;
			}
			if (digits == null) {
				return -1;
			}
			digits = digits.trim();
		}
		if (!digits.matches("[1-9][0-9]{0,2}")) {
			return -1;
		}
		return Integer.parseInt(digits);
	}

	/** Validate the chain of a message read from a stream. */
	public ArcResult verify(InputStream message) throws IOException {
		InputStream in = message instanceof BufferedInputStream ? message : new BufferedInputStream(message, 64 * 1024);
		HeaderFields headers = HeaderFields.read(in);
		TreeMap<Integer, Set> sets = sets(headers);
		if (sets.isEmpty()) {
			return new ArcResult(ArcResult.Result.NONE, null, null);
		}
		try {
			checkStructure(sets);
			int n = sets.lastKey();
			// the newest AMS, like a DKIM signature (step 4)
			HeaderFields.Field ams = sets.get(n).signature.get(0);
			Map<String, String> t = tags(ams);
			for (String required : new String[] {"a", "b", "bh", "d", "h", "s"}) {
				if (t.get(required) == null) {
					throw fail("AMS i=" + n + " has no " + required + "=");
				}
			}
			String alg = alg(t, "AMS");
			Canonicalization hc = Canonicalization.SIMPLE;
			Canonicalization bc = Canonicalization.SIMPLE;
			String c = t.get("c");
			if (c != null) {
				int slash = c.indexOf('/');
				hc = Canonicalization.parse(slash < 0 ? c : c.substring(0, slash));
				if (slash >= 0) {
					bc = Canonicalization.parse(c.substring(slash + 1));
				}
			}
			List<String> h = new ArrayList<>();
			// h= is followed as written: the rule that ARC fields are not signed
			// binds sealers (section 4.1.2), and early sealers signed AARs. An
			// AMS can't cover a seal, which is added after it.
			for (String name : t.get("h").split(":")) {
				String nm = name.trim().toLowerCase(Locale.ROOT);
				if (nm.equals("arc-seal")) {
					throw fail("AMS i=" + n + " signs an ARC-Seal");
				}
				if (!nm.isEmpty()) {
					h.add(nm);
				}
			}
			long l = -1;
			if (t.get("l") != null) {
				if (!t.get("l").matches("[0-9]{1,18}")) {
					throw fail("invalid AMS l=");
				}
				l = Long.parseLong(t.get("l"));
			}
			Canonicalization.BodyHasher body;
			try {
				body = bc.bodyHasher(MessageDigest.getInstance("SHA-256"), l);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
			byte[] buf = new byte[64 * 1024];
			int r;
			while ((r = in.read(buf)) > 0) {
				body.write(buf, 0, r);
			}
			if (!MessageDigest.isEqual(body.finish(), TagList.base64(t.get("bh"), "bh"))) {
				throw fail("AMS i=" + n + " body hash did not verify");
			}
			byte[] data = DkimSigner.headerHashInput(headers.getFields(), h, hc, ams.getRaw());
			if (!verifySignature(alg, key(t, alg), data, TagList.base64(t.get("b"), "b"))) {
				throw fail("AMS i=" + n + " did not verify");
			}

			// every seal, newest first (step 6)
			List<ArcResult.Seal> seals = new ArrayList<>();
			for (int k = n; k >= 1; k--) {
				Set s = sets.get(k);
				Map<String, String> st = s.sealTags;
				String salg = alg(st, "AS");
				StringBuilder sb = new StringBuilder();
				for (int j = 1; j <= k; j++) {
					Set sj = sets.get(j);
					sb.append(Canonicalization.RELAXED.header(sj.results.get(0).getRaw()));
					sb.append(Canonicalization.RELAXED.header(sj.signature.get(0).getRaw()));
					String seal = Canonicalization.RELAXED.header(
							j < k ? sj.seal.get(0).getRaw() : DkimSignature.withoutSignatureValue(ensureCrlf(sj.seal.get(0).getRaw())));
					sb.append(j < k ? seal : seal.substring(0, seal.length() - 2));
				}
				byte[] sealData = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
				if (!verifySignature(salg, key(st, salg), sealData, TagList.base64(st.get("b"), "b"))) {
					throw fail("AS i=" + k + " did not verify");
				}
				Matcher ip = REMOTE_IP.matcher(s.results.get(0).getValue());
				seals.add(new ArcResult.Seal(k, st.get("d").trim().toLowerCase(Locale.ROOT), st.get("s").trim(),
						ip.find() ? ip.group(1) : null));
			}
			return new ArcResult(ArcResult.Result.PASS, null, seals);
		} catch (DkimException e) {
			return new ArcResult(ArcResult.Result.FAIL, e.getMessage(), null);
		}
	}

	/** Steps 1 to 3: at most 50 sets, numbered 1..N, one of each field, cv none then pass. */
	static void checkStructure(TreeMap<Integer, Set> sets) throws DkimException {
		if (sets.containsKey(-1)) {
			throw fail("an ARC field has no valid instance");
		}
		int n = sets.lastKey();
		if (n > MAX_INSTANCES) {
			throw fail("more than " + MAX_INSTANCES + " ARC sets");
		}
		Set newest = sets.get(n);
		if (newest.seal.size() == 1) {
			String cv = tags(newest.seal.get(0)).get("cv");
			if (cv != null && cv.trim().equalsIgnoreCase("fail")) {
				throw fail("the newest seal says cv=fail");
			}
		}
		for (int i = 1; i <= n; i++) {
			Set s = sets.get(i);
			if (s == null) {
				throw fail("no ARC set i=" + i);
			}
			if (s.seal.size() != 1 || s.signature.size() != 1 || s.results.size() != 1) {
				throw fail("ARC set i=" + i + " does not have exactly one of each field");
			}
			Map<String, String> st = tags(s.seal.get(0));
			if (st.containsKey("h")) {
				throw fail("AS i=" + i + " has an h= tag");
			}
			for (String required : new String[] {"a", "b", "cv", "d", "s"}) {
				if (st.get(required) == null) {
					throw fail("AS i=" + i + " has no " + required + "=");
				}
			}
			String cv = st.get("cv").trim().toLowerCase(Locale.ROOT);
			if (!cv.equals(i == 1 ? "none" : "pass")) {
				throw fail("AS i=" + i + " has cv=" + TagList.abbreviate(cv));
			}
			s.sealTags = st;
		}
	}

	static Map<String, String> tags(HeaderFields.Field f) throws DkimException {
		return TagList.parse(f.getRaw().substring(f.getRaw().indexOf(':') + 1));
	}

	private static String alg(Map<String, String> t, String what) throws DkimException {
		String a = t.get("a").trim().toLowerCase(Locale.ROOT);
		if (!a.equals(DkimSigner.RSA_SHA256) && !a.equals(DkimSigner.ED25519_SHA256)) {
			throw fail(what + " has unsupported a=" + TagList.abbreviate(a));
		}
		return a;
	}

	/** The public key for d= and s= (any problem fails the chain: section 5.2.1). */
	private PublicKey key(Map<String, String> t, String alg) throws DkimException {
		String d = DkimSignature.domainName(t.get("d"), "d");
		String s = t.get("s").trim();
		if (!s.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*")) {
			throw fail("invalid s=");
		}
		LookupResult<String> r;
		try {
			r = lookup.txt(s + "._domainkey." + d);
		} catch (RuntimeException e) {
			throw fail("key lookup failed");
		}
		if (!r.isOk()) {
			throw fail("no key for " + s + "._domainkey." + d);
		}
		DkimException last = null;
		for (String record : r.getValues()) {
			try {
				Map<String, String> k = TagList.parse(record);
				String v = k.get("v");
				if (v != null && !v.equals("DKIM1")) {
					throw fail("key record version is not DKIM1");
				}
				String type = k.getOrDefault("k", "rsa").toLowerCase(Locale.ROOT);
				if (!type.equals(alg.equals(DkimSigner.RSA_SHA256) ? "rsa" : "ed25519")) {
					throw fail("key type does not match a=");
				}
				String p = k.get("p");
				if (p == null) {
					throw fail("key record has no p=");
				}
				byte[] bytes = TagList.base64(p, "p");
				if (bytes.length == 0) {
					throw fail("key revoked");
				}
				return DkimKeys.publicKey(type, bytes);
			} catch (DkimException e) {
				last = e;
			}
		}
		throw last != null ? new DkimException(DkimResult.Result.FAIL, last.getMessage()) : fail("no key");
	}

	static boolean verifySignature(String alg, PublicKey key, byte[] data, byte[] sig) throws DkimException {
		try {
			Signature v;
			if (alg.equals(DkimSigner.RSA_SHA256)) {
				v = Signature.getInstance("SHA256withRSA");
				v.initVerify(key);
				v.update(data);
			} else {
				v = Signature.getInstance("Ed25519");
				v.initVerify(key);
				v.update(MessageDigest.getInstance("SHA-256").digest(data));
			}
			return v.verify(sig);
		} catch (NoSuchAlgorithmException e) {
			throw fail(alg + " is not supported by this Java");
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	static String ensureCrlf(String s) {
		return s.endsWith("\r\n") ? s : s + "\r\n";
	}

	static DkimException fail(String message) {
		return new DkimException(DkimResult.Result.FAIL, message);
	}

	static List<String> arcNames() {
		return Arrays.asList(SEAL.toLowerCase(Locale.ROOT), SIGNATURE.toLowerCase(Locale.ROOT), RESULTS.toLowerCase(Locale.ROOT));
	}
}
