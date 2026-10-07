package us.bringardner.parley.smtp.dmarc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * The Public Suffix List (https://publicsuffix.org): which names are public
 * suffixes ("com", "co.uk", "github.io"...), so the organizational domain of
 * a name can be found (RFC 7489 section 3.2): the public suffix plus one label.
 * <p>
 * A copy of the list is included ({@link #getDefault()}); a newer one can be
 * loaded from a file.
 */
public final class PublicSuffixList {

	private static final String RESOURCE = "public_suffix_list.dat";
	private static volatile PublicSuffixList defaultList;

	private final Set<String> rules = new HashSet<>();
	private final Set<String> wildcards = new HashSet<>();
	private final Set<String> exceptions = new HashSet<>();

	/** Read the list's format: one rule per line, "//" comments, "*." wildcards, "!" exceptions. */
	public PublicSuffixList(InputStream in) throws IOException {
		try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				int sp = line.indexOf(' ');
				if (sp >= 0) {
					line = line.substring(0, sp);
				}
				if (line.isEmpty() || line.startsWith("//")) {
					continue;
				}
				if (line.startsWith("!")) {
					exceptions.add(ascii(line.substring(1)));
				} else if (line.startsWith("*.")) {
					wildcards.add(ascii(line.substring(2)));
				} else {
					rules.add(ascii(line));
				}
			}
		}
	}

	/** Load a list from a file. */
	public static PublicSuffixList load(File file) throws IOException {
		try (InputStream in = new FileInputStream(file)) {
			return new PublicSuffixList(in);
		}
	}

	/** The included copy of the list. */
	public static PublicSuffixList getDefault() {
		PublicSuffixList ret = defaultList;
		if (ret == null) {
			synchronized (PublicSuffixList.class) {
				if (defaultList == null) {
					try (InputStream in = PublicSuffixList.class.getResourceAsStream(RESOURCE)) {
						if (in == null) {
							throw new IllegalStateException("The public suffix list resource is missing");
						}
						defaultList = new PublicSuffixList(in);
					} catch (IOException e) {
						throw new IllegalStateException("Can't read the public suffix list", e);
					}
				}
				ret = defaultList;
			}
		}
		return ret;
	}

	/**
	 * The public suffix of a domain (lower case A-labels), using the rule that
	 * matches the most labels, an exception rule first, and "*" when none does.
	 * Null for an empty or malformed name.
	 */
	public String publicSuffix(String domain) {
		String d = normalize(domain);
		if (d == null) {
			return null;
		}
		String[] labels = d.split("\\.");
		// exception rules win: the suffix is the rule without its first label
		for (int i = 0; i < labels.length; i++) {
			String candidate = join(labels, i);
			if (exceptions.contains(candidate)) {
				return i + 1 < labels.length ? join(labels, i + 1) : candidate;
			}
		}
		for (int i = 0; i < labels.length; i++) {
			String candidate = join(labels, i);
			if (rules.contains(candidate)) {
				return candidate;
			}
			if (i + 1 < labels.length && wildcards.contains(join(labels, i + 1))) {
				return candidate;
			}
		}
		return labels[labels.length - 1]; // the default rule "*"
	}

	/**
	 * The registrable domain: the public suffix plus one more label, or null
	 * if the domain is itself a public suffix (or malformed).
	 */
	public String registrableDomain(String domain) {
		String d = normalize(domain);
		if (d == null) {
			return null;
		}
		String suffix = publicSuffix(d);
		if (suffix == null || d.equals(suffix)) {
			return null;
		}
		String rest = d.substring(0, d.length() - suffix.length() - 1);
		int dot = rest.lastIndexOf('.');
		return (dot < 0 ? rest : rest.substring(dot + 1)) + "." + suffix;
	}

	/**
	 * The organizational domain (RFC 7489 section 3.2): the registrable
	 * domain, or the domain itself when it is a public suffix.
	 */
	public String organizationalDomain(String domain) {
		String r = registrableDomain(domain);
		return r != null ? r : normalize(domain);
	}

	private static String join(String[] labels, int from) {
		StringBuilder sb = new StringBuilder();
		for (int i = from; i < labels.length; i++) {
			if (sb.length() > 0) {
				sb.append('.');
			}
			sb.append(labels[i]);
		}
		return sb.toString();
	}

	/** Lower case A-labels without a trailing dot; null if empty or with an empty label. */
	static String normalize(String domain) {
		if (domain == null) {
			return null;
		}
		String d = domain.trim();
		if (d.endsWith(".")) {
			d = d.substring(0, d.length() - 1);
		}
		if (d.isEmpty() || d.startsWith(".") || d.contains("..")) {
			return null;
		}
		return ascii(d);
	}

	private static String ascii(String s) {
		try {
			return IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
		} catch (IllegalArgumentException e) {
			return s.toLowerCase(Locale.ROOT);
		}
	}
}
