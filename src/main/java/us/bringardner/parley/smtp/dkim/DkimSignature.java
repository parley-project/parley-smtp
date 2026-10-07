package us.bringardner.parley.smtp.dkim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** A parsed DKIM-Signature header field (RFC 6376 section 3.5). */
public final class DkimSignature {

	public static final String HEADER = "DKIM-Signature";

	final String raw;
	final Map<String, String> tags;
	final String algorithm;
	final byte[] signature;
	final String signatureText;
	final byte[] bodyHash;
	final Canonicalization headerCanon;
	final Canonicalization bodyCanon;
	final String domain;
	final String identity;
	final String selector;
	final List<String> signedHeaders;
	final long timestamp;
	final long expiration;
	final long length;

	private DkimSignature(String raw, Map<String, String> tags, String algorithm, byte[] signature, String signatureText,
			byte[] bodyHash, Canonicalization headerCanon, Canonicalization bodyCanon, String domain, String identity,
			String selector, List<String> signedHeaders, long timestamp, long expiration, long length) {
		this.raw = raw;
		this.tags = tags;
		this.algorithm = algorithm;
		this.signature = signature;
		this.signatureText = signatureText;
		this.bodyHash = bodyHash;
		this.headerCanon = headerCanon;
		this.bodyCanon = bodyCanon;
		this.domain = domain;
		this.identity = identity;
		this.selector = selector;
		this.signedHeaders = signedHeaders;
		this.timestamp = timestamp;
		this.expiration = expiration;
		this.length = length;
	}

	/** The a= tag, e.g. "rsa-sha256". */
	public String getAlgorithm() {
		return algorithm;
	}

	/** The d= tag (lower case). */
	public String getDomain() {
		return domain;
	}

	/** The i= tag, or "@" + d= when it is absent. */
	public String getIdentity() {
		return identity;
	}

	/** The s= tag. */
	public String getSelector() {
		return selector;
	}

	/** The h= tag: the names of the signed fields, lower case, in order. */
	public List<String> getSignedHeaders() {
		return signedHeaders;
	}

	/** The b= tag as written (white space removed). */
	public String getSignatureText() {
		return signatureText;
	}

	/** The t= tag, or -1. */
	public long getTimestamp() {
		return timestamp;
	}

	/** The x= tag, or -1. */
	public long getExpiration() {
		return expiration;
	}

	/** The name the public key is published under: s._domainkey.d */
	public String keyName() {
		return selector + "._domainkey." + domain;
	}

	/**
	 * Parse and check a DKIM-Signature field (section 6.1.1).
	 *
	 * @param raw the whole field, as {@link HeaderFields} reads it
	 * @param now the time (seconds since 1970) to check x= against
	 */
	static DkimSignature parse(String raw, long now) throws DkimException {
		Map<String, String> t = TagList.parse(raw.substring(raw.indexOf(':') + 1));
		String v = t.get("v");
		if (v == null) {
			throw DkimException.perm("no v= tag");
		}
		if (!v.equals("1")) {
			throw DkimException.perm("unsupported version v=" + TagList.abbreviate(v));
		}
		for (String required : new String[] {"a", "b", "bh", "d", "h", "s"}) {
			if (t.get(required) == null) {
				throw DkimException.perm("no " + required + "= tag");
			}
		}
		String a = t.get("a").toLowerCase(Locale.ROOT);
		switch (a) {
		case DkimSigner.RSA_SHA256:
		case DkimSigner.ED25519_SHA256:
			break;
		case "rsa-sha1":
			throw DkimException.perm("rsa-sha1 signatures are not accepted (RFC 8301)");
		default:
			throw DkimException.perm("unsupported algorithm a=" + TagList.abbreviate(a));
		}
		String b = t.get("b").replaceAll("[ \\t\\r\\n]", "");
		byte[] sig = TagList.base64(b, "b");
		byte[] bh = TagList.base64(t.get("bh"), "bh");
		if (sig.length == 0 || bh.length == 0) {
			throw DkimException.perm("empty b= or bh=");
		}

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

		String d = domainName(t.get("d"), "d");
		String s = t.get("s").trim();
		if (s.isEmpty() || !s.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*")) {
			throw DkimException.perm("invalid selector s=" + TagList.abbreviate(s));
		}

		String i = t.get("i");
		if (i == null) {
			i = "@" + d;
		} else {
			int at = i.lastIndexOf('@');
			if (at < 0) {
				throw DkimException.perm("invalid i=" + TagList.abbreviate(i));
			}
			String id = i.substring(at + 1).toLowerCase(Locale.ROOT);
			if (!id.equals(d) && !id.endsWith("." + d)) {
				throw DkimException.perm("i= domain is not d= or a subdomain of it");
			}
		}

		List<String> h = new ArrayList<>();
		for (String name : t.get("h").split(":")) {
			String n = name.trim().toLowerCase(Locale.ROOT);
			if (n.isEmpty()) {
				throw DkimException.perm("empty name in h=");
			}
			h.add(n);
		}
		if (!h.contains("from")) {
			throw DkimException.perm("From is not signed");
		}

		String q = t.get("q");
		if (q != null) {
			boolean dns = false;
			for (String m : q.split(":")) {
				dns |= m.trim().equalsIgnoreCase("dns/txt");
			}
			if (!dns) {
				throw DkimException.perm("unsupported query method q=" + TagList.abbreviate(q));
			}
		}

		long ts = number(t.get("t"), "t");
		long x = number(t.get("x"), "x");
		long l = number(t.get("l"), "l");
		if (x >= 0 && ts >= 0 && x < ts) {
			throw DkimException.perm("x= is before t=");
		}
		if (x >= 0 && x < now) {
			throw DkimException.perm("signature expired");
		}
		return new DkimSignature(raw, t, a, sig, b, bh, hc, bc, d, i, s, Collections.unmodifiableList(h), ts, x, l);
	}

	static String domainName(String value, String tag) throws DkimException {
		String d = value.trim().toLowerCase(Locale.ROOT);
		while (d.endsWith(".")) {
			d = d.substring(0, d.length() - 1);
		}
		if (d.isEmpty() || !d.matches("[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*")) {
			throw DkimException.perm("invalid " + tag + "=" + TagList.abbreviate(value));
		}
		return d;
	}

	private static long number(String value, String tag) throws DkimException {
		if (value == null) {
			return -1;
		}
		if (!value.matches("[0-9]{1,18}")) {
			throw DkimException.perm("invalid " + tag + "=" + TagList.abbreviate(value));
		}
		return Long.parseLong(value);
	}

	/**
	 * The field with the value of b= removed (section 3.7): what the header
	 * hash covers for the signature field itself.
	 */
	static String withoutSignatureValue(String raw) {
		int colon = raw.indexOf(':');
		int end = raw.length();
		while (end > colon && (raw.charAt(end - 1) == '\n' || raw.charAt(end - 1) == '\r')) {
			end--; // the field's own line end is not part of the b= value
		}
		int pos = colon + 1;
		while (pos <= end) {
			int semi = raw.indexOf(';', pos);
			int tagEnd = semi < 0 || semi > end ? end : semi;
			int eq = raw.indexOf('=', pos);
			if (eq >= 0 && eq < tagEnd && raw.substring(pos, eq).trim().equals("b")) {
				return raw.substring(0, eq + 1) + raw.substring(tagEnd);
			}
			if (tagEnd >= end) {
				break;
			}
			pos = tagEnd + 1;
		}
		return raw;
	}
}
