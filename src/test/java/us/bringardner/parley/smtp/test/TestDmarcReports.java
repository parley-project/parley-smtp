package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.DkimVerifier;
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.smtp.dmarc.DmarcChecker;
import us.bringardner.parley.smtp.dmarc.DmarcRecord.Policy;
import us.bringardner.parley.smtp.dmarc.DmarcReporter;
import us.bringardner.parley.smtp.dmarc.DmarcResult;
import us.bringardner.parley.smtp.spf.SpfChecker;
import us.bringardner.parley.smtp.spf.SpfResult;

/** DMARC aggregate and failure reports. */
public class TestDmarcReports {

	/** A queued report message. */
	static final class Sent {
		final String from;
		final List<String> to;
		final String message;

		Sent(String from, List<String> to, byte[] message) {
			this.from = from;
			this.to = to;
			this.message = new String(message, StandardCharsets.ISO_8859_1);
		}
	}

	private final Map<String, String> txt = new HashMap<>();
	private final List<Sent> sent = new ArrayList<>();
	private final AtomicLong now = new AtomicLong(1_790_000_000_000L);
	private DmarcReporter reporter;
	private FileSource dir;

	@BeforeEach
	public void setUp() throws Exception {
		dir = FileSourceFactory.getDefaultFactory().createTempDirectory("dmarcReports");
		reporter = new DmarcReporter();
		reporter.setAggregate(true);
		reporter.setFailure(true);
		reporter.setOrgName("mx.b.test");
		reporter.setEmail("postmaster@b.test");
		reporter.setHostname("mx.b.test");
		reporter.setClock(now::get);
		reporter.start(dir, (from, to, message) -> sent.add(new Sent(from, to, message)), TestDkim.keys(txt)::txt, null);
	}

	@AfterEach
	public void tearDown() throws Exception {
		reporter.stop();
		for (FileSource f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static final String MESSAGE = "From: Joe <joe@example.com>\r\nTo: ann@b.test\r\nSubject: hello <&>\r\n\r\nHi\r\n";

	private DmarcResult dmarc(String fromHeader, SpfResult spf, List<DkimResult> dkim) {
		return new DmarcChecker(TestDkim.keys(txt)::txt, null).check(Collections.singletonList(fromHeader), spf, dkim);
	}

	private static SpfResult spf(String mailFrom, boolean pass) throws Exception {
		Map<String, Object> zone = new HashMap<>();
		Map<String, Object> rec = new HashMap<>();
		rec.put("SPF", pass ? "v=spf1 +all" : "v=spf1 -all");
		zone.put(mailFrom.substring(mailFrom.indexOf('@') + 1), Collections.singletonList(rec));
		return new SpfChecker(new TestSpfSuite.Zone(zone), "mx.b.test").checkMailFrom(InetAddress.getByName("192.0.2.7"), mailFrom,
				"client.test");
	}

	private List<DkimResult> dkim(String domain, boolean tamper) throws Exception {
		KeyPair k = DkimKeys.generate("rsa");
		txt.put("s1._domainkey." + domain, DkimKeys.dnsRecord(k.getPublic()));
		String sig = new DkimSigner(domain, "s1", k.getPrivate()).sign(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)));
		String m = sig + (tamper ? MESSAGE.replace("Hi", "Bye") : MESSAGE);
		return new DkimVerifier(TestDkim.keys(txt)).verify(new ByteArrayInputStream(m.getBytes(StandardCharsets.UTF_8)));
	}

	private static HeaderFields headers() throws Exception {
		return HeaderFields.read(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)));
	}

	private void evaluate(DmarcResult d, String ip, SpfResult spf, List<DkimResult> dkim, Policy applied) throws Exception {
		reporter.evaluated(d, InetAddress.getByName(ip), "bounce@example.com", spf, dkim, applied, headers(), "mx.b.test; spf=x");
	}

	/** The gunzipped XML of an aggregate report message. */
	static String xml(String message) throws Exception {
		int start = message.indexOf("Content-Transfer-Encoding: base64\r\n\r\n");
		assertTrue(start > 0, message);
		start += "Content-Transfer-Encoding: base64\r\n\r\n".length();
		int end = message.indexOf("\r\n--", start);
		byte[] gz = Base64.getMimeDecoder().decode(message.substring(start, end));
		try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	static void validate(String xml) throws Exception {
		SchemaFactory f = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		f.newSchema(new StreamSource(TestDmarcReports.class.getResourceAsStream("/dmarc/rfc7489.xsd"))).newValidator()
				.validate(new StreamSource(new StringReader(xml)));
	}

	static Document dom(String xml) throws Exception {
		return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
	}

	// ------------------------------------------------------------------ aggregate

	@Test
	public void aggregateReportIsValidAndCounts() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine; adkim=s; pct=100; fo=1; rua=mailto:dmarc@example.com");
		List<DkimResult> good = dkim("example.com", false);
		DmarcResult pass = dmarc("joe@example.com", spf("bounce@example.com", true), good);
		evaluate(pass, "192.0.2.7", spf("bounce@example.com", true), good, Policy.NONE);
		evaluate(pass, "192.0.2.7", spf("bounce@example.com", true), good, Policy.NONE);
		List<DkimResult> bad = dkim("example.com", true);
		DmarcResult fail = dmarc("joe@example.com", spf("bounce@example.com", false), bad);
		evaluate(fail, "2001:db8::7", spf("bounce@example.com", false), bad, Policy.NONE);
		sent.clear(); // the failure report

		now.addAndGet(3_600_000);
		assertEquals(1, reporter.flush());
		assertEquals(1, sent.size());
		Sent s = sent.get(0);
		assertEquals("postmaster@b.test", s.from);
		assertEquals(Collections.singletonList("dmarc@example.com"), s.to);
		assertTrue(s.message.contains("\r\nSubject: Report Domain: example.com Submitter: mx.b.test Report-ID: <mx.b.test.example.com."),
				s.message);
		assertTrue(s.message.contains("Content-Type: application/gzip; name=\"mx.b.test!example.com!1790000000!1790003600.xml.gz\""),
				s.message);

		String xml = xml(s.message);
		validate(xml);
		Document d = dom(xml);
		assertEquals("example.com", d.getElementsByTagName("domain").item(0).getTextContent());
		assertEquals("s", d.getElementsByTagName("adkim").item(0).getTextContent());
		assertEquals("quarantine", d.getElementsByTagName("sp").item(0).getTextContent());
		assertEquals("1", d.getElementsByTagName("fo").item(0).getTextContent());
		assertEquals(2, d.getElementsByTagName("record").getLength(), "identical evaluations share a row");
		assertEquals("2", d.getElementsByTagName("count").item(0).getTextContent());
		assertEquals("1", d.getElementsByTagName("count").item(1).getTextContent());
		assertEquals("2001:db8:0:0:0:0:0:7", d.getElementsByTagName("source_ip").item(1).getTextContent(), "IPv6 as the schema's pattern wants it");
		assertTrue(xml.contains("<disposition>none</disposition>"));
		assertTrue(xml.contains("<type>local_policy</type>"), "a fail that was not enforced: " + xml);
		assertTrue(xml.contains("<selector>s1</selector>"), xml);

		// all sent: the next flush has nothing
		assertEquals(0, reporter.flush());
		assertEquals(0, dir.listFiles().length);
	}

	@Test
	public void onlyDomainsThatAskGetReports() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=none");
		DmarcResult d = dmarc("joe@example.com", spf("bounce@example.com", true), Collections.emptyList());
		evaluate(d, "192.0.2.7", spf("bounce@example.com", true), Collections.emptyList(), Policy.NONE);
		DmarcResult none = dmarc("joe@nopolicy.example", null, Collections.emptyList());
		evaluate(none, "192.0.2.7", null, Collections.emptyList(), Policy.NONE);
		assertEquals(0, reporter.flush());
		assertTrue(sent.isEmpty());
	}

	@Test
	public void storedEvaluationsSurviveARestart() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc@example.com");
		DmarcResult d = dmarc("joe@example.com", spf("bounce@example.com", true), Collections.emptyList());
		evaluate(d, "192.0.2.7", spf("bounce@example.com", true), Collections.emptyList(), Policy.NONE);
		reporter.stop();
		reporter = new DmarcReporter();
		reporter.setAggregate(true);
		reporter.setClock(now::get);
		reporter.start(dir, (from, to, message) -> sent.add(new Sent(from, to, message)), TestDkim.keys(txt)::txt, null);
		assertEquals(1, reporter.flush());
		validate(xml(sent.get(0).message));
	}

	@Test
	public void externalReportAddressesNeedPermission() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:reports@reporting.example.net,mailto:dmarc@mail.example.com");
		DmarcResult d = dmarc("joe@example.com", spf("bounce@example.com", true), Collections.emptyList());
		evaluate(d, "192.0.2.7", spf("bounce@example.com", true), Collections.emptyList(), Policy.NONE);
		reporter.flush();
		assertEquals(Collections.singletonList("dmarc@mail.example.com"), sent.get(0).to,
				"same organization: allowed; another one: only with its _report record");

		sent.clear();
		txt.put("example.com._report._dmarc.reporting.example.net", "v=DMARC1");
		evaluate(d, "192.0.2.7", spf("bounce@example.com", true), Collections.emptyList(), Policy.NONE);
		reporter.flush();
		assertEquals(List.of("reports@reporting.example.net", "dmarc@mail.example.com"), sent.get(0).to);
	}

	@Test
	public void sizeLimitAndUriForms() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:small@example.com!100, mailto:big@example.com!10k,"
				+ " https://example.com/dmarc, mailto:d%6Darc@example.com");
		DmarcResult d = dmarc("joe@example.com", spf("bounce@example.com", true), Collections.emptyList());
		evaluate(d, "192.0.2.7", spf("bounce@example.com", true), Collections.emptyList(), Policy.NONE);
		reporter.flush();
		assertEquals(List.of("big@example.com", "dmarc@example.com"), sent.get(0).to,
				"over the !100 byte limit: skipped; https: not supported; %-encoding decoded");
	}

	// ------------------------------------------------------------------ failure

	@Test
	public void failureReportIsArf() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=reject; ruf=mailto:forensic@example.com");
		List<DkimResult> bad = dkim("example.com", true);
		DmarcResult fail = dmarc("joe@example.com", spf("bounce@example.com", false), bad);
		evaluate(fail, "192.0.2.7", spf("bounce@example.com", false), bad, Policy.REJECT);
		assertEquals(1, sent.size(), "sent at once");
		String m = sent.get(0).message;
		assertEquals(Collections.singletonList("forensic@example.com"), sent.get(0).to);
		assertTrue(m.contains("\r\nSubject: DMARC failure report for example.com\r\n"), m);
		assertTrue(m.contains("Content-Type: multipart/report; report-type=feedback-report;"), m);
		assertTrue(m.contains("\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: auth-failure\r\n"), m);
		for (String field : new String[] {"Version: 1", "Original-Mail-From: <bounce@example.com>", "Source-IP: 192.0.2.7",
				"Reported-Domain: example.com", "Authentication-Results: mx.b.test; spf=x", "Identity-Alignment: none",
				"Auth-Failure: dmarc", "Delivery-Result: reject", "DKIM-Domain: example.com", "DKIM-Selector: s1",
				"Reporting-MTA: dns; mx.b.test"}) {
			assertTrue(m.contains("\r\n" + field + "\r\n"), field + " in " + m);
		}
		assertTrue(m.contains("Content-Type: text/rfc822-headers\r\n\r\nFrom: Joe <joe@example.com>\r\n"), "the header: " + m);
		assertFalse(m.contains("\r\nHi\r\n"), "never the body");
	}

	@Test
	public void failureOptions() throws Exception {
		List<DkimResult> good = dkim("example.com", false);
		// fo=0 (default): only when nothing aligned passed
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; ruf=mailto:f@example.com");
		evaluate(dmarc("joe@example.com", spf("b@example.com", false), good), "192.0.2.7", spf("b@example.com", false), good, Policy.NONE);
		assertEquals(0, sent.size(), "DKIM passed aligned");
		// fo=1: when either mechanism failed to pass aligned
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; fo=1; ruf=mailto:f@example.com");
		evaluate(dmarc("joe@example.com", spf("b@example.com", false), good), "192.0.2.7", spf("b@example.com", false), good, Policy.NONE);
		assertEquals(1, sent.size(), "SPF did not pass aligned");
		// fo=s: SPF failed, whatever the alignment
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; fo=s; ruf=mailto:f@example.com");
		evaluate(dmarc("joe@example.com", spf("b@other.example", false), good), "192.0.2.7", spf("b@other.example", false), good,
				Policy.NONE);
		assertEquals(2, sent.size());
		// fo=d: a DKIM signature failed
		List<DkimResult> bad = dkim("other.example", true);
		List<DkimResult> both = new ArrayList<>(good);
		both.addAll(bad);
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; fo=d; ruf=mailto:f@example.com");
		evaluate(dmarc("joe@example.com", null, both), "192.0.2.7", null, both, Policy.NONE);
		assertEquals(3, sent.size());
		// rf= without afrf: no reports
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; rf=iodef; ruf=mailto:f@example.com");
		evaluate(dmarc("joe@example.com", null, Collections.emptyList()), "192.0.2.7", null, Collections.emptyList(), Policy.NONE);
		assertEquals(3, sent.size());
	}

	@Test
	public void failureReportsAreLimited() throws Exception {
		reporter.setMaxFailurePerHour(3);
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; ruf=mailto:f@example.com");
		DmarcResult fail = dmarc("joe@example.com", null, Collections.emptyList());
		for (int i = 0; i < 10; i++) {
			evaluate(fail, "192.0.2.7", null, Collections.emptyList(), Policy.NONE);
		}
		assertEquals(3, sent.size(), "per domain per hour");
		now.addAndGet(3_600_001);
		evaluate(fail, "192.0.2.7", null, Collections.emptyList(), Policy.NONE);
		assertEquals(4, sent.size(), "an hour later");
	}

	@Test
	public void noReportAboutAReport() throws Exception {
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; ruf=mailto:f@example.com");
		DmarcResult fail = dmarc("joe@example.com", null, Collections.emptyList());
		HeaderFields h = HeaderFields.read(new ByteArrayInputStream(("From: joe@example.com\r\n"
				+ "Content-Type: multipart/report; report-type=feedback-report; boundary=x\r\n\r\n").getBytes(StandardCharsets.UTF_8)));
		reporter.evaluated(fail, InetAddress.getByName("192.0.2.7"), null, null, Collections.emptyList(), Policy.NONE, h, null);
		assertTrue(sent.isEmpty());
		assertNotNull(fail);
	}
}
