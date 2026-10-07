package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.AAAA;
import us.bringardner.parley.dns.Cname;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Mx;
import us.bringardner.parley.dns.Ptr;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Txt;
import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.spf.SpfChecker;
import us.bringardner.parley.smtp.spf.SpfDns;
import us.bringardner.parley.smtp.spf.SpfResult;

/**
 * Runs the openspf.org RFC 7208 test suite (src/test/resources/spf/rfc7208-tests.yml,
 * from pyspf) against SpfChecker. The DNS data of each scenario is served the
 * way pyspf's test driver serves it: SPF-type records double as TXT records
 * unless the name has its own TXT records, "TIMEOUT" makes a query fail, and
 * a CNAME is followed one level.
 */
public class TestSpfSuite {

	/** Zone data of one scenario: name (lower case) to its entries in order. */
	static final class Zone implements SpfDns {
		final Map<String, List<Object>> data = new LinkedHashMap<>();

		@SuppressWarnings("unchecked")
		Zone(Map<String, Object> zonedata) {
			for (Map.Entry<String, Object> e : zonedata.entrySet()) {
				List<Object> entries = new ArrayList<>();
				boolean explicitTxt = false;
				List<Object> generated = new ArrayList<>();
				for (Object o : (List<Object>) e.getValue()) {
					if (o instanceof Map) {
						for (Map.Entry<String, Object> rec : ((Map<String, Object>) o).entrySet()) {
							String type = rec.getKey();
							Object v = rec.getValue();
							if (type.equals("TXT")) {
								explicitTxt = true;
							}
							if (type.equals("SPF")) {
								generated.add(new Object[] {"TXT", v});
								continue; // type SPF is never queried (RFC 7208)
							}
							if ("NONE".equals(v)) {
								continue;
							}
							entries.add(new Object[] {type, v});
						}
					} else {
						entries.add(o); // "TIMEOUT"
					}
				}
				if (!explicitTxt) {
					entries.addAll(generated);
				}
				data.put(norm(e.getKey()), entries);
			}
		}

		static String norm(String name) {
			String n = name.toLowerCase(Locale.ROOT);
			return n.endsWith(".") ? n.substring(0, n.length() - 1) : n;
		}

		@Override
		public LookupResult<RR> lookup(String name, int type) {
			return Lookup.fromResponse(name, type, query(name, type, 0), rr -> rr);
		}

		@SuppressWarnings("unchecked")
		private Message query(String name, int type, int level) {
			String n = norm(name);
			List<Object> entries = data.get(n);
			Message m = new Message();
			m.setQuestion(name, type, DNS.IN);
			m.setMessageTypeResponse();
			if (entries == null) {
				if (n.startsWith("error.")) {
					return null;
				}
				m.setResponseCode(DNS.NAME_ERROR);
				return m;
			}
			boolean seen = false;
			for (Object o : entries) {
				if ("TIMEOUT".equals(o)) {
					if (!seen) {
						return null;
					}
					break;
				}
				Object[] rec = (Object[]) o;
				String t = (String) rec[0];
				Object v = rec[1];
				int rtype = typeOf(t);
				if (rtype == type) {
					seen = true;
				}
				if ("TIMEOUT".equals(v)) {
					if (rtype == type) {
						return null;
					}
					continue;
				}
				if (rtype == DNS.CNAME && type != DNS.CNAME && level == 0) {
					Cname c = new Cname(name);
					c.setCname((String) v);
					c.setTTL(300);
					m.addAnswer(c);
					Message target = query((String) v, type, 1);
					if (target == null) {
						return null;
					}
					for (RR rr : target.getAnswer()) {
						m.addAnswer(rr);
					}
					continue;
				}
				if (rtype != type) {
					continue;
				}
				RR rr;
				switch (t) {
				case "TXT": {
					Txt x = new Txt(name);
					List<String> strings = new ArrayList<>();
					if (v instanceof List) {
						for (Object s : (List<Object>) v) {
							strings.add(String.valueOf(s));
						}
					} else {
						strings.add(String.valueOf(v));
					}
					x.setStrings(strings);
					rr = x;
					break;
				}
				case "A": {
					A a = new A(name);
					a.setAddress(String.valueOf(v));
					rr = a;
					break;
				}
				case "AAAA": {
					AAAA a = new AAAA(name);
					a.setAddress(String.valueOf(v));
					rr = a;
					break;
				}
				case "MX": {
					List<Object> p = (List<Object>) v;
					Mx x = new Mx(name);
					x.setPref((short) ((Number) p.get(0)).intValue());
					x.setExchange(String.valueOf(p.get(1)));
					rr = x;
					break;
				}
				case "PTR": {
					Ptr x = new Ptr(name);
					x.setPtr(String.valueOf(v));
					rr = x;
					break;
				}
				default:
					continue;
				}
				rr.setTTL(300);
				m.addAnswer(rr);
			}
			return m;
		}

		private static int typeOf(String t) {
			switch (t) {
			case "TXT":
				return DNS.TXT;
			case "A":
				return DNS.A;
			case "AAAA":
				return DNS.AAAA;
			case "MX":
				return DNS.MX;
			case "PTR":
				return DNS.PTR;
			case "CNAME":
				return DNS.CNAME;
			default:
				return -1;
			}
		}
	}

	@Test
	@SuppressWarnings("unchecked")
	public void rfc7208Suite() throws Exception {
		List<String> failures = new ArrayList<>();
		int count = 0;
		LoaderOptions opts = new LoaderOptions();
		try (InputStream in = getClass().getResourceAsStream("/spf/rfc7208-tests.yml")) {
			for (Object doc : new Yaml(opts).loadAll(in)) {
				Map<String, Object> scenario = (Map<String, Object>) doc;
				Zone zone = new Zone((Map<String, Object>) scenario.get("zonedata"));
				SpfChecker spf = new SpfChecker(zone, null);
				Map<String, Object> tests = (Map<String, Object>) scenario.get("tests");
				for (Map.Entry<String, Object> te : tests.entrySet()) {
					Map<String, Object> t = (Map<String, Object>) te.getValue();
					count++;
					List<String> expected = new ArrayList<>();
					Object res = t.get("result");
					if (res instanceof List) {
						for (Object o : (List<Object>) res) {
							expected.add(String.valueOf(o));
						}
					} else {
						expected.add(String.valueOf(res));
					}
					String host = String.valueOf(t.get("host"));
					String mailfrom = t.get("mailfrom") == null ? "" : String.valueOf(t.get("mailfrom"));
					String helo = t.get("helo") == null ? "" : String.valueOf(t.get("helo"));
					SpfResult r;
					try {
						r = spf.checkMailFrom(InetAddress.getByName(host), mailfrom, helo);
					} catch (RuntimeException e) {
						failures.add(te.getKey() + ": threw " + e);
						continue;
					}
					String got = r.getResult().keyword();
					if (!expected.contains(got)) {
						failures.add(te.getKey() + " (" + t.get("spec") + "): expected " + expected + " got " + r);
						continue;
					}
					Object exp = t.get("explanation");
					// v-macro-ip6: pyspf keeps the case of the input address in %{i};
					// RFC 7208 section 7.4 shows lower case nibbles (DNS ignores case)
					boolean ignoreCase = te.getKey().equals("v-macro-ip6");
					if (exp != null && !"DEFAULT".equals(exp) && !(ignoreCase ? String.valueOf(exp).equalsIgnoreCase(r.getExplanation())
							: String.valueOf(exp).equals(r.getExplanation()))) {
						failures.add(te.getKey() + ": explanation expected '" + exp + "' got '" + r.getExplanation() + "'");
					}
				}
			}
		}
		Collections.sort(failures);
		assertTrue(failures.isEmpty(), failures.size() + " of " + count + " failed:\n" + String.join("\n", failures));
		assertTrue(count > 200, "ran " + count);
	}
}
