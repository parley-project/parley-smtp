package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.DkimVerifier;
import us.bringardner.parley.smtp.dmarc.DmarcChecker;
import us.bringardner.parley.smtp.dmarc.DmarcRecord;
import us.bringardner.parley.smtp.dmarc.DmarcRecord.Policy;
import us.bringardner.parley.smtp.dmarc.DmarcResult;
import us.bringardner.parley.smtp.dmarc.DmarcResult.Result;
import us.bringardner.parley.smtp.dmarc.PublicSuffixList;
import us.bringardner.parley.smtp.spf.SpfChecker;
import us.bringardner.parley.smtp.spf.SpfResult;

/** DMARC: the public suffix list, policy records, alignment and dispositions. */
public class TestDmarc {

	// ------------------------------------------------------------------ public suffix list

	/** The publicsuffix.org test file (tests/tests.txt): checkPublicSuffix(domain, registrable). */
	@Test
	public void publicSuffixListOfficialTests() throws Exception {
		PublicSuffixList psl = PublicSuffixList.getDefault();
		List<String> failures = new ArrayList<>();
		int count = 0;
		try (InputStream in = getClass().getResourceAsStream("/dmarc/psl-tests.txt");
				BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("//")) {
					continue;
				}
				String[] p = line.split("\\s+");
				String domain = p[0].equals("null") ? null : p[0];
				String expected = p[1].equals("null") ? null : java.net.IDN.toASCII(p[1]).toLowerCase();
				String got = psl.registrableDomain(domain);
				count++;
				if (expected == null ? got != null : !expected.equals(got)) {
					failures.add(line + " -> " + got);
				}
			}
		}
		assertTrue(failures.isEmpty(), failures.size() + " of " + count + " failed:\n" + String.join("\n", failures));
		assertTrue(count > 50, "ran " + count);
	}

	@Test
	public void organizationalDomains() {
		PublicSuffixList psl = PublicSuffixList.getDefault();
		assertEquals("example.com", psl.organizationalDomain("mail.news.Example.COM."));
		assertEquals("example.co.uk", psl.organizationalDomain("a.example.co.uk"));
		assertEquals("com", psl.organizationalDomain("com"), "a public suffix is its own organizational domain");
		assertEquals("example.test", psl.organizationalDomain("a.b.example.test"), "unlisted TLD: the default * rule");
	}

	// ------------------------------------------------------------------ records

	@Test
	public void recordParsing() {
		DmarcRecord r = DmarcRecord.parse("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; rua=mailto:d@example.com, junk");
		assertEquals(Policy.REJECT, r.getPolicy());
		assertEquals(Policy.QUARANTINE, r.getSubdomainPolicy());
		assertTrue(r.isStrictDkim());
		assertFalse(r.isStrictSpf());
		assertEquals(50, r.getPercent());
		assertEquals(Arrays.asList("mailto:d@example.com"), r.getAggregateReports());

		DmarcRecord d = DmarcRecord.parse("v=DMARC1;p=none");
		assertEquals(Policy.NONE, d.getPolicy());
		assertNull(d.getSubdomainPolicy());
		assertEquals(100, d.getPercent());
		assertFalse(d.isStrictDkim());

		assertNull(DmarcRecord.parse("v=spf1 -all"));
		assertNull(DmarcRecord.parse("v=DMARC2; p=reject"));
		assertNull(DmarcRecord.parse("p=reject; v=DMARC1"), "v= must be first");
		assertNull(DmarcRecord.parse("v=DMARC1; p=bogus"), "invalid p without rua: unusable");
		assertEquals(Policy.NONE, DmarcRecord.parse("v=DMARC1; p=bogus; rua=mailto:x@example.com").getPolicy(),
				"invalid p with rua: p=none (RFC 7489 6.6.3)");
		assertEquals(100, DmarcRecord.parse("v=DMARC1; p=none; pct=abc").getPercent());
	}

	// ------------------------------------------------------------------ checks

	static final String MESSAGE = "From: Joe <joe@news.example.com>\r\nTo: ann@b.test\r\nSubject: hi\r\n\r\nHello\r\n";

	private final Map<String, String> dns = new HashMap<>();

	private DmarcChecker checker() {
		return new DmarcChecker(TestDkim.keys(dns)::txt, null);
	}

	private static List<String> from(String... values) {
		return Arrays.asList(values);
	}

	/** SPF results come from a real SpfChecker over a tiny fake zone. */
	private static SpfResult spf(String mailFrom, boolean pass) throws Exception {
		Map<String, Object> zone = new HashMap<>();
		Map<String, Object> rec = new HashMap<>();
		rec.put("SPF", pass ? "v=spf1 +all" : "v=spf1 -all");
		String domain = mailFrom.substring(mailFrom.indexOf('@') + 1);
		zone.put(domain, Collections.singletonList(rec));
		return new SpfChecker(new TestSpfSuite.Zone(zone), "mx.test").checkMailFrom(InetAddress.getByName("192.0.2.1"), mailFrom,
				"client.test");
	}

	/** DKIM results from really signing and verifying MESSAGE with d=domain. */
	private List<DkimResult> dkim(String domain, String message) throws Exception {
		java.security.KeyPair k = DkimKeys.generate("rsa");
		dns.put("s1._domainkey." + domain, DkimKeys.dnsRecord(k.getPublic()));
		String sig = new DkimSigner(domain, "s1", k.getPrivate()).sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
		return new DkimVerifier(TestDkim.keys(dns)).verify(new ByteArrayInputStream((sig + message).getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void noRecordIsNone() throws Exception {
		DmarcResult r = checker().check(from("joe@example.com"), spf("x@example.com", true), Collections.emptyList());
		assertEquals(Result.NONE, r.getResult());
		assertEquals("dmarc=none header.from=example.com", r.toAuthResults());
		assertTrue(r.isSpfAligned(), "alignment is still worked out");
	}

	@Test
	public void dkimRelaxedAndStrictAlignment() throws Exception {
		dns.put("_dmarc.example.com", "v=DMARC1; p=reject");
		List<DkimResult> parent = dkim("example.com", MESSAGE);
		// From news.example.com, policy found at the organizational domain, d=example.com: relaxed alignment
		DmarcResult r = checker().check(from("Joe <joe@news.example.com>"), null, parent);
		assertEquals(Result.PASS, r.getResult(), r.toString());
		assertEquals("example.com", r.getDkimDomain());
		assertEquals("example.com", r.getPolicyDomain());
		assertEquals("dmarc=pass (p=reject dis=none) header.from=news.example.com", r.toAuthResults());

		dns.put("_dmarc.example.com", "v=DMARC1; p=reject; adkim=s");
		r = checker().check(from("Joe <joe@news.example.com>"), null, parent);
		assertEquals(Result.FAIL, r.getResult(), "strict: d= must be the From domain");
		assertEquals(Policy.REJECT, r.getDisposition());
		assertEquals("dmarc=fail (p=reject dis=reject) header.from=news.example.com", r.toAuthResults());

		// another organization's signature never aligns
		r = checker().check(from("joe@news.example.com"), null, dkim("example.net", MESSAGE));
		assertEquals(Result.FAIL, r.getResult());
	}

	@Test
	public void spfAlignment() throws Exception {
		dns.put("_dmarc.example.com", "v=DMARC1; p=quarantine");
		assertEquals(Result.PASS, checker().check(from("joe@example.com"), spf("bounce@mail.example.com", true), Collections.emptyList())
				.getResult(), "relaxed: same organizational domain");
		assertEquals(Result.FAIL, checker().check(from("joe@example.com"), spf("bounce@mail.example.com", false), Collections.emptyList())
				.getResult(), "SPF fail never aligns");
		assertEquals(Result.FAIL, checker().check(from("joe@example.com"), spf("bounce@example.net", true), Collections.emptyList())
				.getResult(), "another domain's SPF pass");
		dns.put("_dmarc.example.com", "v=DMARC1; p=quarantine; aspf=s");
		DmarcResult r = checker().check(from("joe@example.com"), spf("bounce@mail.example.com", true), Collections.emptyList());
		assertEquals(Result.FAIL, r.getResult(), "strict SPF alignment");
		assertEquals(Policy.QUARANTINE, r.getDisposition());
	}

	@Test
	public void subdomainPolicy() throws Exception {
		dns.put("_dmarc.example.com", "v=DMARC1; p=reject; sp=none");
		DmarcResult r = checker().check(from("joe@news.example.com"), null, Collections.emptyList());
		assertEquals(Result.FAIL, r.getResult());
		assertEquals(Policy.NONE, r.getPolicy(), "sp= for a subdomain");
		r = checker().check(from("joe@example.com"), null, Collections.emptyList());
		assertEquals(Policy.REJECT, r.getPolicy(), "p= for the organizational domain itself");
		// a record at the subdomain itself wins, with its p=
		dns.put("_dmarc.news.example.com", "v=DMARC1; p=quarantine");
		r = checker().check(from("joe@news.example.com"), null, Collections.emptyList());
		assertEquals(Policy.QUARANTINE, r.getPolicy());
		assertEquals("news.example.com", r.getPolicyDomain());
	}

	@Test
	public void percentSampling() throws Exception {
		dns.put("_dmarc.example.com", "v=DMARC1; p=reject; pct=10");
		DmarcChecker c = checker();
		int rejected = 0;
		int quarantined = 0;
		c.setRandom(new Random(42));
		for (int i = 0; i < 1000; i++) {
			Policy d = c.check(from("joe@example.com"), null, Collections.emptyList()).getDisposition();
			if (d == Policy.REJECT) {
				rejected++;
			} else if (d == Policy.QUARANTINE) {
				quarantined++;
			}
		}
		assertEquals(1000, rejected + quarantined, "outside pct= reject becomes quarantine");
		assertTrue(rejected > 50 && rejected < 150, "about 10% rejected: " + rejected);

		dns.put("_dmarc.example.com", "v=DMARC1; p=quarantine; pct=0");
		assertEquals(Policy.NONE, checker().check(from("joe@example.com"), null, Collections.emptyList()).getDisposition());
	}

	@Test
	public void recordProblems() throws Exception {
		dns.put("_dmarc.example.com", "TEMPFAIL");
		DmarcResult r = checker().check(from("joe@example.com"), null, Collections.emptyList());
		assertEquals(Result.TEMPERROR, r.getResult());
		assertEquals("dmarc=temperror reason=\"DNS lookup of _dmarc.example.com failed\" header.from=example.com", r.toAuthResults());

		dns.put("_dmarc.example.com", "v=DMARC1; p=bogus");
		assertEquals(Result.NONE, checker().check(from("joe@example.com"), null, Collections.emptyList()).getResult(),
				"an unusable record is no record");
	}

	@Test
	public void fromProblems() throws Exception {
		DmarcChecker c = checker();
		assertEquals("no From field", c.check(from(), null, Collections.emptyList()).getReason());
		assertEquals("more than one From field", c.check(from("a@x.example", "b@x.example"), null, Collections.emptyList()).getReason());
		assertEquals("From has addresses in more than one domain",
				c.check(from("a@x.example, \"B, the other\" <b@y.example>"), null, Collections.emptyList()).getReason());
		assertEquals(Result.PERMERROR, c.check(from("undisclosed-recipients:;"), null, Collections.emptyList()).getResult());
		assertEquals("dmarc=permerror reason=\"no From field\"", c.check(from(), null, Collections.emptyList()).toAuthResults());
		// several authors in one domain are fine
		assertEquals(Result.NONE, c.check(from("a@x.example, B <b@x.example>"), null, Collections.emptyList()).getResult());
	}
}
