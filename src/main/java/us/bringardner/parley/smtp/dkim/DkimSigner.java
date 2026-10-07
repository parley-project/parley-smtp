package us.bringardner.parley.smtp.dkim;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Signs messages for one domain with one key (RFC 6376 section 5): RSA keys
 * sign with rsa-sha256, Ed25519 keys with ed25519-sha256 (RFC 8463).
 * <p>
 * The signature uses relaxed/relaxed canonicalization by default, signs the
 * fields of {@link #DEFAULT_HEADERS} that the message has, and "over-signs"
 * the fields of {@link #DEFAULT_OVERSIGN} (one more name in h= than the
 * message has), so they can't be added after signing.
 *
 * <pre>
 * DkimSigner s = new DkimSigner("example.com", "mail2026", DkimKeys.privateKey(new File("example.com.pem")));
 * String field = s.sign(messageStream);   // "DKIM-Signature: ...\r\n", to put at the top of the message
 * </pre>
 */
public final class DkimSigner {

	public static final String RSA_SHA256 = "rsa-sha256";
	public static final String ED25519_SHA256 = "ed25519-sha256";

	/** Fields signed when present (RFC 6376 section 5.4.1, RFC 8058 for List-Unsubscribe-Post). */
	public static final List<String> DEFAULT_HEADERS = Collections.unmodifiableList(Arrays.asList("from", "sender", "reply-to",
			"subject", "date", "message-id", "to", "cc", "mime-version", "content-type", "content-transfer-encoding",
			"content-id", "content-description", "resent-date", "resent-from", "resent-sender", "resent-to", "resent-cc",
			"resent-message-id", "in-reply-to", "references", "list-id", "list-help", "list-unsubscribe",
			"list-unsubscribe-post", "list-subscribe", "list-post", "list-owner", "list-archive"));

	/** Fields signed one extra time, so another instance can't be added. */
	public static final List<String> DEFAULT_OVERSIGN = Collections.unmodifiableList(Arrays.asList("from", "sender",
			"reply-to", "subject", "date", "message-id", "to", "cc", "mime-version", "content-type",
			"content-transfer-encoding"));

	private static final int LINE = 76;

	private final String domain;
	private final String selector;
	private final PrivateKey key;
	private final String algorithm;
	private List<String> headers = DEFAULT_HEADERS;
	private List<String> oversign = DEFAULT_OVERSIGN;
	private Canonicalization headerCanon = Canonicalization.RELAXED;
	private Canonicalization bodyCanon = Canonicalization.RELAXED;
	private String identity;
	private long expireSeconds = -1;

	/**
	 * @param domain   the signing domain (d=)
	 * @param selector the selector (s=); the public key is published at selector._domainkey.domain
	 * @param key      an RSA (at least 1024 bits, 2048 recommended) or Ed25519 private key
	 */
	public DkimSigner(String domain, String selector, PrivateKey key) {
		try {
			this.domain = DkimSignature.domainName(domain, "d");
		} catch (DkimException e) {
			throw new IllegalArgumentException("Invalid signing domain " + domain);
		}
		if (selector == null || !selector.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*")) {
			throw new IllegalArgumentException("Invalid selector " + selector);
		}
		this.selector = selector;
		this.key = key;
		String alg = key.getAlgorithm();
		if (alg.equals("RSA")) {
			algorithm = RSA_SHA256;
		} else if (alg.equals("EdDSA") || alg.equals("Ed25519")) {
			algorithm = ED25519_SHA256;
		} else {
			throw new IllegalArgumentException("DKIM keys are RSA or Ed25519, not " + alg);
		}
	}

	public String getDomain() {
		return domain;
	}

	public String getSelector() {
		return selector;
	}

	/** "rsa-sha256" or "ed25519-sha256". */
	public String getAlgorithm() {
		return algorithm;
	}

	PrivateKey getKey() {
		return key;
	}

	/** Sign data with this signer's key and algorithm (for ARC). */
	byte[] signBytes(byte[] data) throws GeneralSecurityException {
		return signData(data);
	}

	/** The fields to sign when present (names, any case). */
	public void setHeaders(List<String> headers) {
		this.headers = lower(headers);
		if (!this.headers.contains("from")) {
			throw new IllegalArgumentException("From must be signed");
		}
	}

	/** The fields to sign one extra time (empty for none). */
	public void setOversign(List<String> oversign) {
		this.oversign = lower(oversign);
	}

	public void setCanonicalization(Canonicalization header, Canonicalization body) {
		this.headerCanon = header;
		this.bodyCanon = body;
	}

	/** The i= tag (e.g. "@mail.example.com" or "user@example.com"); null to leave it out. */
	public void setIdentity(String identity) {
		this.identity = identity;
	}

	/** Add x= this many seconds after t= (-1, the default, for no expiration). */
	public void setExpireSeconds(long expireSeconds) {
		this.expireSeconds = expireSeconds;
	}

	/** Sign a message read from a stream, timestamped now. */
	public String sign(InputStream message) throws IOException, GeneralSecurityException {
		return sign(message, System.currentTimeMillis() / 1000);
	}

	/**
	 * Sign a message (header and body, CRLF line ends).
	 *
	 * @param now the t= tag (seconds since 1970)
	 * @return the DKIM-Signature field, folded and ending with CRLF
	 */
	public String sign(InputStream message, long now) throws IOException, GeneralSecurityException {
		InputStream in = message instanceof BufferedInputStream ? message : new BufferedInputStream(message, 64 * 1024);
		HeaderFields fields = HeaderFields.read(in);
		if (fields.get("from") == null) {
			throw new GeneralSecurityException("The message has no From field");
		}
		Canonicalization.BodyHasher body = bodyCanon.bodyHasher(MessageDigest.getInstance("SHA-256"), -1);
		byte[] buf = new byte[64 * 1024];
		int n;
		while ((n = in.read(buf)) > 0) {
			body.write(buf, 0, n);
		}
		byte[] bh = body.finish();

		// h=: every instance of each field present, then the over-signed names
		Map<String, Integer> count = new HashMap<>();
		for (HeaderFields.Field f : fields.getFields()) {
			count.merge(f.getName().toLowerCase(Locale.ROOT), 1, Integer::sum);
		}
		List<String> h = new ArrayList<>();
		Set<String> order = new LinkedHashSet<>(headers);
		for (String name : order) {
			for (int i = count.getOrDefault(name, 0); i > 0; i--) {
				h.add(name);
			}
		}
		for (String name : oversign) {
			if (order.contains(name) || name.equals("from")) {
				h.add(name);
			}
		}

		List<String> tags = new ArrayList<>();
		tags.add("v=1");
		tags.add("a=" + algorithm);
		tags.add("c=" + headerCanon.keyword() + "/" + bodyCanon.keyword());
		tags.add("d=" + domain);
		if (identity != null) {
			tags.add("i=" + identity);
		}
		tags.add("s=" + selector);
		tags.add("t=" + now);
		if (expireSeconds >= 0) {
			tags.add("x=" + (now + expireSeconds));
		}
		tags.add("h=" + String.join(":", h));
		tags.add("bh=" + Base64.getEncoder().encodeToString(bh));
		tags.add("b=");
		String unsigned = fold(tags);

		byte[] data = headerHashInput(fields.getFields(), h, headerCanon, unsigned);
		byte[] sig = signData(data);
		return unsigned + foldBase64(Base64.getEncoder().encodeToString(sig), lastLineLength(unsigned)) + "\r\n";
	}

	private byte[] signData(byte[] data) throws GeneralSecurityException {
		Signature s;
		if (algorithm.equals(RSA_SHA256)) {
			s = Signature.getInstance("SHA256withRSA");
			s.initSign(key);
			s.update(data);
		} else {
			// RFC 8463 section 3: PureEdDSA over the SHA-256 hash
			try {
				s = Signature.getInstance("Ed25519");
			} catch (NoSuchAlgorithmException e) {
				throw new GeneralSecurityException("Ed25519 needs Java 15 or later", e);
			}
			s.initSign(key);
			s.update(MessageDigest.getInstance("SHA-256").digest(data));
		}
		return s.sign();
	}

	/**
	 * The data the header signature covers (RFC 6376 section 3.7): the signed
	 * fields in h= order, each taken from the bottom up, then the signature
	 * field without its b= value and without its final CRLF.
	 */
	static byte[] headerHashInput(List<HeaderFields.Field> fields, List<String> h, Canonicalization c, String signatureField) {
		StringBuilder sb = new StringBuilder();
		Map<String, Integer> used = new HashMap<>();
		for (String name : h) {
			int skip = used.merge(name, 1, Integer::sum) - 1;
			for (int i = fields.size() - 1; i >= 0; i--) {
				HeaderFields.Field f = fields.get(i);
				if (f.is(name) && skip-- == 0) {
					sb.append(c.header(f.getRaw()));
					break;
				}
			}
			// a name with no instance left adds nothing (over-signing)
		}
		String self = c.header(DkimSignature.withoutSignatureValue(ensureCrlf(signatureField)));
		sb.append(self, 0, self.length() - 2);
		return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
	}

	private static String ensureCrlf(String s) {
		return s.endsWith("\r\n") ? s : s + "\r\n";
	}

	/** "DKIM-Signature: " and the tags, folded between tags (and inside h=) to about 76 columns. */
	private static String fold(List<String> tags) {
		StringBuilder sb = new StringBuilder(DkimSignature.HEADER).append(": ");
		int col = sb.length();
		for (int i = 0; i < tags.size(); i++) {
			String tag = tags.get(i) + (i + 1 < tags.size() ? ";" : "");
			String sep = i == 0 ? "" : " ";
			if (col + sep.length() + tag.length() > LINE && col > 1) {
				sb.append("\r\n\t");
				col = 1;
				sep = "";
			}
			if (tag.startsWith("h=") && col + sep.length() + tag.length() > LINE) {
				// fold h= after colons (FWS is allowed around them)
				sb.append(sep);
				col += sep.length();
				String[] names = tag.split(":");
				for (int j = 0; j < names.length; j++) {
					String part = names[j] + (j + 1 < names.length ? ":" : "");
					if (col + part.length() > LINE && col > 1) {
						sb.append("\r\n\t");
						col = 1;
					}
					sb.append(part);
					col += part.length();
				}
				continue;
			}
			sb.append(sep).append(tag);
			col += sep.length() + tag.length();
		}
		return sb.toString();
	}

	private static int lastLineLength(String s) {
		int nl = s.lastIndexOf('\n');
		return nl < 0 ? s.length() : s.length() - nl;
	}

	private static String foldBase64(String b64, int col) {
		StringBuilder sb = new StringBuilder();
		int pos = 0;
		while (pos < b64.length()) {
			int room = LINE - col;
			if (room < 8) {
				sb.append("\r\n\t");
				col = 1;
				room = LINE - 1;
			}
			int end = Math.min(b64.length(), pos + room);
			sb.append(b64, pos, end);
			col += end - pos;
			pos = end;
		}
		return sb.toString();
	}

	private static List<String> lower(List<String> names) {
		List<String> ret = new ArrayList<>();
		for (String n : names) {
			String t = n.trim().toLowerCase(Locale.ROOT);
			if (!t.isEmpty()) {
				ret.add(t);
			}
		}
		return Collections.unmodifiableList(ret);
	}

	@Override
	public String toString() {
		return "DkimSigner[d=" + domain + ", s=" + selector + ", a=" + algorithm + "]";
	}
}
