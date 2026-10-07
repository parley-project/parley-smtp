package us.bringardner.parley.smtp.dkim;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Adds an ARC set to a message (RFC 8617 section 5.1): an
 * ARC-Authentication-Results field with this server's authentication results,
 * an ARC-Message-Signature over the message, and an ARC-Seal over the chain.
 * <p>
 * The Chain Validation Status (cv=) is the arc= result in this server's
 * Authentication-Results field. A chain whose newest seal says cv=fail is not
 * sealed again, and a message with 50 sets is not sealed.
 * <p>
 * Tags are written in alphabetical order, separated by "; ", as other
 * implementations (and the ARC test suite) do.
 */
public final class ArcSealer {

	private static final Pattern ARC_RESULT = Pattern.compile("(?i)(?:^|;)\\s*arc\\s*=\\s*(pass|fail|none)\\b");
	private static final int LINE = 76;
	private static final int B_LINE = 72;

	private final DkimSigner signer;
	private List<String> headers;

	/** Seal with a signer's domain, selector and key. */
	public ArcSealer(DkimSigner signer) {
		this.signer = signer;
	}

	public DkimSigner getSigner() {
		return signer;
	}

	/**
	 * Sign exactly these fields in the ARC-Message-Signature (names, any case);
	 * null (the default) for the DKIM signer's choice: the usual fields present,
	 * DKIM-Signature fields, and the over-signed names.
	 */
	public void setHeaders(List<String> headers) {
		this.headers = headers == null ? null : new ArrayList<>(headers);
	}

	/** Seal a message read from a stream, timestamped now. */
	public String seal(InputStream message, String authServId) throws IOException, GeneralSecurityException {
		return seal(message, authServId, System.currentTimeMillis() / 1000);
	}

	/**
	 * Make the ARC set for a message (header and body, CRLF line ends).
	 *
	 * @param authServId this server's authserv-id: its Authentication-Results
	 *                   fields become the ARC-Authentication-Results
	 * @param now        the t= tags (seconds since 1970)
	 * @return the three fields (ARC-Seal, ARC-Message-Signature,
	 *         ARC-Authentication-Results), each ending with CRLF, to put at the
	 *         top of the message; or null if the message must not be sealed
	 */
	public String seal(InputStream message, String authServId, long now) throws IOException, GeneralSecurityException {
		InputStream in = message instanceof BufferedInputStream ? message : new BufferedInputStream(message, 64 * 1024);
		HeaderFields fields = HeaderFields.read(in);
		TreeMap<Integer, ArcVerifier.Set> sets = ArcVerifier.sets(fields);

		// this server's results, and the chain status it found
		List<String> results = new ArrayList<>();
		String cv = null;
		for (HeaderFields.Field f : fields.getAll("Authentication-Results")) {
			String v = unfold(f.getRaw().substring(f.getRaw().indexOf(':') + 1));
			int semi = v.indexOf(';');
			String id = (semi < 0 ? v : v.substring(0, semi)).trim();
			int sp = id.indexOf(' ');
			if (sp >= 0) {
				id = id.substring(0, sp);
			}
			if (!id.equalsIgnoreCase(authServId) || semi < 0) {
				continue;
			}
			String payload = v.substring(semi + 1).trim();
			if (payload.endsWith(";")) {
				payload = payload.substring(0, payload.length() - 1).trim();
			}
			if (!payload.isEmpty() && !payload.equalsIgnoreCase("none")) {
				results.add(payload);
			}
			Matcher m = ARC_RESULT.matcher(payload);
			if (cv == null && m.find()) {
				cv = m.group(1).toLowerCase(Locale.ROOT);
			}
		}

		int n = 0;
		if (!sets.isEmpty()) {
			if (sets.containsKey(-1)) {
				cv = "fail";
				n = sets.size() > 1 ? sets.lastKey() : 0;
			} else {
				n = sets.lastKey();
				ArcVerifier.Set newest = sets.get(n);
				if (newest.seal.size() == 1) {
					try {
						String last = ArcVerifier.tags(newest.seal.get(0)).get("cv");
						if (last != null && last.trim().equalsIgnoreCase("fail")) {
							return null; // section 5.1 step 2
						}
					} catch (DkimException e) {
						cv = "fail";
					}
				}
			}
			if (cv == null || cv.equals("none")) {
				cv = "fail"; // a chain this server did not find valid
			}
		} else {
			cv = "none";
		}
		int i = n + 1;
		if (i > ArcVerifier.MAX_INSTANCES) {
			return null;
		}

		// ARC-Authentication-Results
		String aar = fold("ARC-Authentication-Results: i=" + i + "; " + authServId + "; "
				+ (results.isEmpty() ? "none" : String.join("; ", results)));

		// ARC-Message-Signature
		Canonicalization.BodyHasher body = Canonicalization.RELAXED.bodyHasher(MessageDigest.getInstance("SHA-256"), -1);
		byte[] buf = new byte[64 * 1024];
		int r;
		while ((r = in.read(buf)) > 0) {
			body.write(buf, 0, r);
		}
		List<String> h = signedHeaders(fields);
		Map<String, String> ams = new TreeMap<>();
		ams.put("a", signer.getAlgorithm());
		ams.put("b", "");
		ams.put("bh", Base64.getEncoder().encodeToString(body.finish()));
		ams.put("c", "relaxed/relaxed");
		ams.put("d", signer.getDomain());
		ams.put("h", String.join(":", h));
		ams.put("i", Integer.toString(i));
		ams.put("s", signer.getSelector());
		ams.put("t", Long.toString(now));
		String amsUnsigned = field(ArcVerifier.SIGNATURE, ams);
		byte[] amsSig = signer.signBytes(DkimSigner.headerHashInput(fields.getFields(), h, Canonicalization.RELAXED, amsUnsigned));
		ams.put("b", Base64.getEncoder().encodeToString(amsSig));
		String amsField = fold(field(ArcVerifier.SIGNATURE, ams));

		// ARC-Seal
		Map<String, String> as = new TreeMap<>();
		as.put("a", signer.getAlgorithm());
		as.put("b", "");
		as.put("cv", cv);
		as.put("d", signer.getDomain());
		as.put("i", Integer.toString(i));
		as.put("s", signer.getSelector());
		as.put("t", Long.toString(now));
		String asUnsigned = field(ArcVerifier.SEAL, as);
		StringBuilder data = new StringBuilder();
		if (!cv.equals("fail")) {
			for (int j = 1; j < i; j++) {
				ArcVerifier.Set s = sets.get(j);
				data.append(Canonicalization.RELAXED.header(s.results.get(0).getRaw()));
				data.append(Canonicalization.RELAXED.header(s.signature.get(0).getRaw()));
				data.append(Canonicalization.RELAXED.header(s.seal.get(0).getRaw()));
			}
		}
		// a failed chain: the seal covers only the new set (section 5.1.2)
		data.append(Canonicalization.RELAXED.header(aar));
		data.append(Canonicalization.RELAXED.header(amsField));
		String self = Canonicalization.RELAXED.header(DkimSignature.withoutSignatureValue(asUnsigned + "\r\n"));
		data.append(self, 0, self.length() - 2);
		byte[] asSig = signer.signBytes(data.toString().getBytes(StandardCharsets.ISO_8859_1));
		as.put("b", Base64.getEncoder().encodeToString(asSig));
		String asField = fold(field(ArcVerifier.SEAL, as));
		return asField + amsField + aar;
	}

	/** The AMS h= list: the configured names, or the DKIM signer's choice without ARC and Authentication-Results fields. */
	private List<String> signedHeaders(HeaderFields fields) {
		List<String> excluded = new ArrayList<>(ArcVerifier.arcNames());
		excluded.add("authentication-results");
		List<String> h = new ArrayList<>();
		if (headers != null) {
			for (String name : headers) {
				String n = name.trim().toLowerCase(Locale.ROOT);
				if (!n.isEmpty() && !excluded.contains(n)) {
					h.add(n);
				}
			}
			return h;
		}
		Map<String, Integer> count = new HashMap<>();
		for (HeaderFields.Field f : fields.getFields()) {
			count.merge(f.getName().toLowerCase(Locale.ROOT), 1, Integer::sum);
		}
		LinkedHashSet<String> order = new LinkedHashSet<>(DkimSigner.DEFAULT_HEADERS);
		order.add("dkim-signature"); // section 4.1.2: SHOULD sign existing DKIM signatures
		for (String name : order) {
			for (int k = count.getOrDefault(name, 0); k > 0; k--) {
				h.add(name);
			}
		}
		h.addAll(DkimSigner.DEFAULT_OVERSIGN);
		return Collections.unmodifiableList(h);
	}

	/** "Name: a=...; b=...; ..." on one line (no CRLF). */
	private static String field(String name, Map<String, String> tags) {
		StringBuilder sb = new StringBuilder(name).append(": ");
		boolean first = true;
		for (Map.Entry<String, String> e : tags.entrySet()) {
			if (!first) {
				sb.append("; ");
			}
			sb.append(e.getKey()).append('=').append(e.getValue());
			first = false;
		}
		return sb.toString();
	}

	/**
	 * Fold a field at "; " boundaries (and long b= values) to about 76 columns,
	 * ending with CRLF. Relaxed canonicalization reads the folded field exactly
	 * as the unfolded one, so the signatures are not affected.
	 */
	static String fold(String field) {
		StringBuilder sb = new StringBuilder();
		String[] parts = field.split("; ", -1);
		int col = 0;
		for (int p = 0; p < parts.length; p++) {
			String part = parts[p] + (p + 1 < parts.length ? ";" : "");
			if (p > 0) {
				if (col + 1 + part.length() > LINE) {
					sb.append("\r\n\t");
					col = 1;
				} else {
					sb.append(' ');
					col++;
				}
			}
			if (part.startsWith("b=") && part.length() > B_LINE) {
				// A long signature value is split into lines of 72 characters
				// ("b=" included), as dkimpy and OpenARC do. Relaxed canonicalization
				// keeps a space where a value is folded, so later seals (which cover
				// this field) depend on where the breaks are.
				if (col > 1) {
					sb.setLength(sb.length() - 1); // the ' ' just added
					sb.append("\r\n\t");
				}
				for (int pos = 0; pos < part.length(); pos += B_LINE) {
					if (pos > 0) {
						sb.append("\r\n\t");
					}
					sb.append(part, pos, Math.min(part.length(), pos + B_LINE));
				}
				col = 1 + (part.length() - 1) % B_LINE + 1;
				continue;
			}
			sb.append(part);
			col += part.length();
		}
		return sb.append("\r\n").toString();
	}

	private static String unfold(String s) {
		return s.replace("\r\n", "").replace("\r", "").replace("\n", "").replaceAll("[ \\t]+", " ").trim();
	}
}
