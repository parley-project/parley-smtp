package us.bringardner.parley.smtp.spf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.bringardner.parley.smtp.spf.SpfResult.Result;

/**
 * A parsed SPF record (RFC 7208 section 4.6 and 12). Any syntax error
 * anywhere in the record makes the whole record a permerror.
 */
final class SpfRecord {

	/** One directive: qualifier and mechanism. */
	static final class Mechanism {
		char qualifier = '+';
		String name;
		String domainSpec;
		InetAddress network;
		int ip4Cidr = -1;
		int ip6Cidr = -1;
		String text;

		Result result() {
			switch (qualifier) {
			case '-':
				return Result.FAIL;
			case '~':
				return Result.SOFTFAIL;
			case '?':
				return Result.NEUTRAL;
			default:
				return Result.PASS;
			}
		}
	}

	final List<Mechanism> mechanisms = new ArrayList<>();
	String redirect;
	String exp;
	boolean hasAll;

	private static final Pattern MODIFIER = Pattern.compile("([A-Za-z][A-Za-z0-9._-]*)=(.*)", Pattern.DOTALL);
	private static final Pattern MECHANISM = Pattern.compile("([+\\-~?]?)([A-Za-z][A-Za-z0-9._-]*)(.*)", Pattern.DOTALL);
	private static final Pattern QNUM = Pattern.compile("(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])");
	private static final Pattern IP4 = Pattern.compile(QNUM + "\\." + QNUM + "\\." + QNUM + "\\." + QNUM);
	private static final Pattern IP4_CIDR = Pattern.compile("/(0|[1-9][0-9]?)");
	private static final Pattern IP6_CIDR = Pattern.compile("/(0|[1-9][0-9]{0,2})");
	private static final Pattern DUAL_CIDR = Pattern.compile("(?:/(0|[1-9][0-9]?))?(?://(0|[1-9][0-9]{0,2}))?");
	private static final Pattern DOMAIN_AND_CIDR = Pattern.compile(":(.*?)((?:/(?:0|[1-9][0-9]?))?(?://(?:0|[1-9][0-9]{0,2}))?)", Pattern.DOTALL);
	private static final Pattern TOPLABEL = Pattern.compile("[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9]");

	private SpfRecord() {
	}

	static SpfRecord parse(String record) throws SpfException {
		for (int i = 0; i < record.length(); i++) {
			char c = record.charAt(i);
			if (c > 126 || (c < 32)) {
				throw perm("the record has a character that is not printable ASCII");
			}
		}
		SpfRecord r = new SpfRecord();
		String[] terms = record.substring(6).split(" ");
		for (String term : terms) {
			if (term.isEmpty()) {
				continue;
			}
			Matcher mod = MODIFIER.matcher(term);
			if (mod.matches()) {
				String name = mod.group(1).toLowerCase(Locale.ROOT);
				String value = mod.group(2);
				switch (name) {
				case "redirect":
					if (r.redirect != null) {
						throw perm("more than one redirect=");
					}
					domainSpec(value);
					r.redirect = value;
					break;
				case "exp":
					if (r.exp != null) {
						throw perm("more than one exp=");
					}
					domainSpec(value);
					r.exp = value;
					break;
				default:
					macroString(value); // unknown modifiers are ignored (section 6)
				}
				continue;
			}
			r.mechanisms.add(mechanism(term));
		}
		for (Mechanism m : r.mechanisms) {
			r.hasAll |= m.name.equals("all");
		}
		return r;
	}

	private static Mechanism mechanism(String term) throws SpfException {
		Matcher mm = MECHANISM.matcher(term);
		if (!mm.matches()) {
			throw perm("invalid term " + SpfChecker.abbreviate(term));
		}
		Mechanism m = new Mechanism();
		m.text = term;
		if (!mm.group(1).isEmpty()) {
			m.qualifier = mm.group(1).charAt(0);
		}
		m.name = mm.group(2).toLowerCase(Locale.ROOT);
		String rest = mm.group(3);
		switch (m.name) {
		case "all":
			if (!rest.isEmpty()) {
				throw perm("invalid term " + SpfChecker.abbreviate(term));
			}
			break;
		case "include":
		case "exists":
			if (!rest.startsWith(":") || rest.length() == 1) {
				throw perm(m.name + " needs a domain");
			}
			m.domainSpec = rest.substring(1);
			domainSpec(m.domainSpec);
			break;
		case "ptr":
			if (!rest.isEmpty()) {
				if (!rest.startsWith(":") || rest.length() == 1) {
					throw perm("invalid term " + SpfChecker.abbreviate(term));
				}
				m.domainSpec = rest.substring(1);
				domainSpec(m.domainSpec);
			}
			break;
		case "a":
		case "mx": {
			String cidr = rest;
			if (rest.startsWith(":")) {
				// a '/' starts the CIDR length only if digits follow: a domain-spec
				// may contain '/' (e.g. a:foo:bar/baz.example.com)
				Matcher dm = DOMAIN_AND_CIDR.matcher(rest);
				if (!dm.matches()) {
					throw perm("invalid term " + SpfChecker.abbreviate(term));
				}
				m.domainSpec = dm.group(1);
				cidr = dm.group(2);
				if (m.domainSpec.isEmpty()) {
					throw perm("invalid term " + SpfChecker.abbreviate(term));
				}
				domainSpec(m.domainSpec);
			}
			if (!cidr.isEmpty()) {
				Matcher dc = DUAL_CIDR.matcher(cidr);
				if (!dc.matches()) {
					throw perm("invalid CIDR length in " + SpfChecker.abbreviate(term));
				}
				if (dc.group(1) != null) {
					m.ip4Cidr = Integer.parseInt(dc.group(1));
				}
				if (dc.group(2) != null) {
					m.ip6Cidr = Integer.parseInt(dc.group(2));
				}
				if (m.ip4Cidr > 32 || m.ip6Cidr > 128) {
					throw perm("invalid CIDR length in " + SpfChecker.abbreviate(term));
				}
			}
			break;
		}
		case "ip4": {
			if (!rest.startsWith(":")) {
				throw perm("ip4 needs an address");
			}
			String v = rest.substring(1);
			int slash = v.indexOf('/');
			String addr = slash < 0 ? v : v.substring(0, slash);
			if (!IP4.matcher(addr).matches()) {
				throw perm("invalid ip4 address in " + SpfChecker.abbreviate(term));
			}
			if (slash >= 0) {
				Matcher c = IP4_CIDR.matcher(v.substring(slash));
				if (!c.matches() || Integer.parseInt(c.group(1)) > 32) {
					throw perm("invalid CIDR length in " + SpfChecker.abbreviate(term));
				}
				m.ip4Cidr = Integer.parseInt(c.group(1));
			}
			m.network = address(addr);
			break;
		}
		case "ip6": {
			if (!rest.startsWith(":")) {
				throw perm("ip6 needs an address");
			}
			String v = rest.substring(1);
			int slash = v.indexOf('/');
			String addr = slash < 0 ? v : v.substring(0, slash);
			if (!addr.matches("[0-9A-Fa-f:.]+") || addr.indexOf(':') < 0) {
				throw perm("invalid ip6 address in " + SpfChecker.abbreviate(term));
			}
			if (slash >= 0) {
				Matcher c = IP6_CIDR.matcher(v.substring(slash));
				if (!c.matches() || Integer.parseInt(c.group(1)) > 128) {
					throw perm("invalid CIDR length in " + SpfChecker.abbreviate(term));
				}
				m.ip6Cidr = Integer.parseInt(c.group(1));
			}
			InetAddress a = address(addr);
			if (a.getAddress().length != 16) {
				// ::ffff:a.b.c.d (Java gives the IPv4 address): keep it as IPv6
				byte[] b = new byte[16];
				b[10] = (byte) 0xff;
				b[11] = (byte) 0xff;
				System.arraycopy(a.getAddress(), 0, b, 12, 4);
				try {
					a = InetAddress.getByAddress(null, b);
				} catch (UnknownHostException e) {
					throw perm("invalid ip6 address in " + SpfChecker.abbreviate(term));
				}
			}
			m.network = a;
			break;
		}
		default:
			throw perm("unknown mechanism " + SpfChecker.abbreviate(m.name));
		}
		return m;
	}

	private static InetAddress address(String literal) throws SpfException {
		try {
			// only digits, hex, '.' and ':' get here: parsed, never looked up
			return InetAddress.getByName(literal);
		} catch (UnknownHostException e) {
			throw perm("invalid address " + SpfChecker.abbreviate(literal));
		}
	}

	/**
	 * Check a macro-string's syntax (section 7.1).
	 *
	 * @return true if it ends with a macro-expand
	 */
	static boolean macroString(String s) throws SpfException {
		return macroString(s, false);
	}

	/**
	 * @param exp true for explanation text, where c, r and t are allowed
	 */
	static boolean macroString(String s, boolean exp) throws SpfException {
		boolean endsWithMacro = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			endsWithMacro = false;
			if (c != '%') {
				if (c < 0x21 || c > 0x7e) {
					throw perm("invalid character in " + SpfChecker.abbreviate(s));
				}
				continue;
			}
			if (i + 1 >= s.length()) {
				throw perm("'%' at the end of " + SpfChecker.abbreviate(s));
			}
			char n = s.charAt(++i);
			if (n == '%' || n == '_' || n == '-') {
				endsWithMacro = true;
				continue;
			}
			if (n != '{') {
				throw perm("invalid macro %" + n + " in " + SpfChecker.abbreviate(s));
			}
			int close = s.indexOf('}', i);
			if (close < 0 || !s.substring(i + 1, close).matches(exp ? "(?i)[slodiphcrtv][0-9]*r?[.\\-+,/_=]*" : "(?i)[slodiphv][0-9]*r?[.\\-+,/_=]*")) {
				throw perm("invalid macro in " + SpfChecker.abbreviate(s));
			}
			i = close;
			endsWithMacro = true;
		}
		return endsWithMacro;
	}

	/** Check a domain-spec: a macro-string ending in a macro or "." toplabel ["."] (section 7.1). */
	static void domainSpec(String s) throws SpfException {
		if (s.isEmpty()) {
			throw perm("empty domain");
		}
		if (macroString(s)) {
			return;
		}
		String t = s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
		int dot = t.lastIndexOf('.');
		if (dot < 0 || !TOPLABEL.matcher(t.substring(dot + 1)).matches()) {
			throw perm("invalid domain " + SpfChecker.abbreviate(s));
		}
	}

	private static SpfException perm(String message) {
		return new SpfException(Result.PERMERROR, message);
	}
}
