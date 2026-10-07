package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import us.bringardner.parley.smtp.dkim.ArcResult;
import us.bringardner.parley.smtp.dkim.ArcSealer;
import us.bringardner.parley.smtp.dkim.ArcVerifier;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimSigner;

/**
 * Runs the ValiMail ARC test suite (src/test/resources/arc, MIT license, from
 * github.com/ValiMail/arc_test_suite) against ArcVerifier and ArcSealer.
 * Messages in the suite have LF line ends; they are given CRLF, as on the wire.
 */
public class TestArcSuite {

	static String crlf(String s) {
		return s.replace("\r\n", "\n").replace("\n", "\r\n");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void validation() throws Exception {
		List<String> failures = new ArrayList<>();
		int count = 0;
		try (InputStream in = getClass().getResourceAsStream("/arc/arc-draft-validation-tests.yml")) {
			for (Object doc : new Yaml().loadAll(in)) {
				Map<String, Object> scenario = (Map<String, Object>) doc;
				Map<String, String> txt = new HashMap<>();
				for (Map.Entry<String, Object> e : ((Map<String, Object>) scenario.get("txt-records")).entrySet()) {
					txt.put(e.getKey().toLowerCase(), String.valueOf(e.getValue()));
				}
				ArcVerifier v = new ArcVerifier(TestDkim.keys(txt));
				for (Map.Entry<String, Object> te : ((Map<String, Object>) scenario.get("tests")).entrySet()) {
					Map<String, Object> t = (Map<String, Object>) te.getValue();
					count++;
					String expected = String.valueOf(t.get("cv")).trim().toLowerCase();
					if (expected.isEmpty()) {
						// three cases whose expectation is blank (dkimpy returned nothing); by their names and
						// RFC 8617 section 5.2 they are failing chains
						expected = "fail";
					}
					if (te.getKey().equals("ams_fields_c_na")) {
						// the suite expects an AMS without c= to be read as relaxed/relaxed; RFC 8617 section 4.1.2
						// gives the AMS DKIM's semantics, where the default is simple/simple (RFC 6376 section 3.5)
						expected = "fail";
					}
					String message = t.get("message") == null ? "" : crlf(String.valueOf(t.get("message")));
					ArcResult r = v.verify(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
					if (!r.getResult().keyword().equals(expected)) {
						failures.add(te.getKey() + ": expected " + expected + " got " + r + " (" + t.get("description") + ")");
					}
				}
			}
		}
		Collections.sort(failures);
		assertTrue(failures.isEmpty(), failures.size() + " of " + count + " failed:\n" + String.join("\n", failures));
		assertTrue(count > 150, "ran " + count);
	}

	/** The tag=value items of a field value, white space removed (as the suite's runner compares them). */
	static Set<String> items(String value) {
		Set<String> ret = new HashSet<>();
		for (String i : value.replaceAll("\\s", "").split(";")) {
			if (!i.isEmpty()) {
				ret.add(i);
			}
		}
		return ret;
	}

	@SuppressWarnings("unchecked")
	@Test
	public void signing() throws Exception {
		List<String> failures = new ArrayList<>();
		int count = 0;
		int fixtureSeals = 0;
		// Every b= value in the suite's messages (white space removed). The suite's expected ARC-Seal
		// b= values are stale: the chains in its own later messages carry different seals for the
		// same input (i1_base holds the i=1 seal for i0_base, i2_base the i=2 seal for i1_base...).
		Set<String> fixtures = new HashSet<>();
		try (InputStream in = getClass().getResourceAsStream("/arc/arc-draft-sign-tests.yml")) {
			for (Object doc : new Yaml().loadAll(in)) {
				for (Object test : ((Map<String, Object>) ((Map<String, Object>) doc).get("tests")).values()) {
					String m = String.valueOf(((Map<String, Object>) test).get("message"));
					for (String field : m.split("\n(?![ \t])")) {
						if (field.startsWith("ARC-Seal:")) {
							for (String item : items(field.substring(9))) {
								if (item.startsWith("b=")) {
									fixtures.add(item);
								}
							}
						}
					}
				}
			}
		}
		try (InputStream in = getClass().getResourceAsStream("/arc/arc-draft-sign-tests.yml")) {
			for (Object doc : new Yaml().loadAll(in)) {
				Map<String, Object> scenario = (Map<String, Object>) doc;
				Map<String, String> txt = new HashMap<>();
				for (Map.Entry<String, Object> e : ((Map<String, Object>) scenario.get("txt-records")).entrySet()) {
					txt.put(e.getKey().toLowerCase(), String.valueOf(e.getValue()));
				}
				DkimSigner signer = new DkimSigner(String.valueOf(scenario.get("domain")), String.valueOf(scenario.get("sel")),
						DkimKeys.privateKey(String.valueOf(scenario.get("privatekey"))));
				for (Map.Entry<String, Object> te : ((Map<String, Object>) scenario.get("tests")).entrySet()) {
					Map<String, Object> t = (Map<String, Object>) te.getValue();
					count++;
					ArcSealer sealer = new ArcSealer(signer);
					sealer.setHeaders(Arrays.asList(String.valueOf(t.get("sig-headers")).split(":")));
					String message = crlf(String.valueOf(t.get("message")));
					String out = sealer.seal(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), String.valueOf(t.get("srv-id")),
							Long.parseLong(String.valueOf(t.get("t"))));
					Map<String, String> expected = new HashMap<>();
					expected.put("arc-seal", String.valueOf(t.get("AS")).trim());
					expected.put("arc-message-signature", String.valueOf(t.get("AMS")).trim());
					expected.put("arc-authentication-results", String.valueOf(t.get("AAR")).trim());
					if (out == null) {
						if (!expected.get("arc-seal").isEmpty()) {
							failures.add(te.getKey() + ": not sealed");
						}
						continue;
					}
					if (expected.get("arc-seal").isEmpty()) {
						failures.add(te.getKey() + ": sealed, but the suite expects no new set");
						continue;
					}
					for (String field : out.split("\r\n(?![ \t])")) {
						if (field.isEmpty()) {
							continue;
						}
						String name = field.substring(0, field.indexOf(':')).toLowerCase();
						Set<String> got = items(field.substring(field.indexOf(':') + 1));
						Set<String> want = items(expected.get(name));
						if (name.equals("arc-seal") && !got.equals(want)) {
							String ourB = null;
							for (String item : got) {
								if (item.startsWith("b=")) {
									ourB = item;
								}
							}
							Set<String> gotTags = new HashSet<>(got);
							Set<String> wantTags = new HashSet<>(want);
							gotTags.removeIf(x -> x.startsWith("b="));
							wantTags.removeIf(x -> x.startsWith("b="));
							if (gotTags.equals(wantTags)) {
								if (fixtures.contains(ourB)) {
									fixtureSeals++; // the seal the suite's own chain fixtures carry
								}
								// The newest seal of a chain has no later fixture to compare with; the
								// self-validation below still proves it verifies.
								continue;
							}
						}
						if (!got.equals(want)) {
							Set<String> missing = new HashSet<>(want);
							missing.removeAll(got);
							Set<String> extra = new HashSet<>(got);
							extra.removeAll(want);
							failures.add(te.getKey() + " " + name + ": missing " + missing + " extra " + extra);
						}
					}
					// what we seal also validates
					ArcResult v = new ArcVerifier(TestDkim.keys(txt)).verify(new ByteArrayInputStream((out + message).getBytes(StandardCharsets.UTF_8)));
					String cv = items(expected.get("arc-seal")).contains("cv=fail") ? "fail" : "pass";
					if (!v.getResult().keyword().equals(cv)) {
						failures.add(te.getKey() + ": our sealed message validates as " + v);
					}
				}
			}
		}
		Collections.sort(failures);
		assertTrue(failures.isEmpty(), failures.size() + " failures in " + count + " tests:\n" + String.join("\n", failures));
		assertTrue(count > 10, "ran " + count);
		assertTrue(fixtureSeals >= 10, "seals matched the suite's fixtures: " + fixtureSeals);
	}
}
