package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.ILogger.Level;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.mail.store.MailStore;
import us.bringardner.parley.mail.store.Mailbox;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.queue.DeliveryException;
import us.bringardner.parley.smtp.queue.MxResolver;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * DMARC in the SMTP server: server A signs for a.test and relays to server B,
 * which checks SPF, DKIM and DMARC; mail sent straight to B with a forged
 * a.test From fails DMARC.
 */
public class TestDmarcSmtp {

	private static SmtpServer a;
	private static SmtpServer b;
	private static FileSource rootA;
	private static FileSource rootB;
	private static final Map<String, String> txt = new HashMap<>();

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("SmtpServer." + FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		FileSourceFactory f = FileSourceFactory.getDefaultFactory();
		rootA = f.createTempDirectory("dmarcA");
		rootB = f.createTempDirectory("dmarcB");
		KeyPair key = DkimKeys.generate("rsa");
		txt.put("k1._domainkey.a.test", DkimKeys.dnsRecord(key.getPublic()));
		// reports go to tony@b.test, which agrees to take them for a.test
		txt.put("_dmarc.a.test", "v=DMARC1; p=reject; rua=mailto:tony@b.test; ruf=mailto:tony@b.test");
		txt.put("a.test._report._dmarc.b.test", "v=DMARC1");
		txt.put("_dmarc.q.test", "v=DMARC1; p=quarantine");
		txt.put("_dmarc.spf.test", "v=DMARC1; p=reject");

		Map<String, Object> zone = new HashMap<>();
		Map<String, Object> spf = new HashMap<>();
		spf.put("SPF", "v=spf1 ip4:127.0.0.0/8 ip6:::1 -all");
		zone.put("bounces.spf.test", Collections.singletonList(spf));

		b = server(rootB, "mx.b.test", "b.test");
		b.getDkim().setLookup(TestDkim.keys(txt));
		b.getDmarc().setDns(TestDkim.keys(txt)::txt);
		b.getSpf().setDns(new TestSpfSuite.Zone(zone));
		b.getDmarc().getReporter().setAggregate(true);
		b.getDmarc().getReporter().setFailure(true);
		b.getDmarc().getReporter().setOrgName("mx.b.test");
		b.getDmarc().getReporter().setEmail("postmaster@b.test");
		b.startAndWait(10000);

		a = server(rootA, "mx.a.test", "a.test");
		a.addRelayNetwork("127.0.0.0/8");
		a.getDkim().addSigner(new DkimSigner("a.test", "k1", key.getPrivate()));
		a.getDeliveryConfig().setResolver((domain, port) -> {
			if (domain.equals("b.test")) {
				return List.of(new MxResolver.Route("127.0.0.1", b.getLocalPort()));
			}
			throw DeliveryException.permanent("5.1.2", "The domain " + domain + " doesn't exist");
		});
		a.startAndWait(10000);
	}

	private static SmtpServer server(FileSource root, String host, String domain) throws IOException {
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		s.setMaildropRoot(root);
		s.setHostname(host);
		s.getDeliveryConfig().getLocalDomains().clear();
		s.addLocalDomain(domain);
		s.getLogger().setLevel(Level.ERROR);
		s.getSpf().setDns(new TestSpfSuite.Zone(new HashMap<>()));
		s.getDmarc().setDns(TestDkim.keys(new HashMap<>())::txt);
		return s;
	}

	@AfterAll
	public static void stop() throws Exception {
		for (SmtpServer s : new SmtpServer[] {a, b}) {
			if (s != null) {
				s.stop();
			}
		}
		deleteAll(rootA);
		deleteAll(rootB);
	}

	private static void deleteAll(FileSource f) throws IOException {
		if (f == null) {
			return;
		}
		if (f.isDirectory()) {
			for (FileSource kid : f.listFiles()) {
				deleteAll(kid);
			}
		}
		f.delete();
	}

	private static String send(SmtpServer via, String from, String data) throws IOException {
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(via.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			return c.sendMail(from, "team1@b.test", data);
		}
	}

	private static String find(String subject) {
		try {
			for (String m : TestSmtpServer.inbox(rootB, "team")) {
				if (m.contains("Subject: " + subject + "\r\n")) {
					return m;
				}
			}
		} catch (IOException e) {
			// not yet
		}
		return null;
	}

	private static String waitFor(String subject) throws InterruptedException {
		TestSmtpServer.waitFor(() -> find(subject) != null, 30000, subject);
		return find(subject);
	}

	@Test
	public void signedRelayPasses() throws Exception {
		String r = send(a, "tony@a.test", "From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: dmarc pass\r\n\r\nhi\r\n");
		assertTrue(r.startsWith("250"), r);
		String m = waitFor("dmarc pass");
		assertTrue(m.contains("\tdkim=pass header.d=a.test"), m);
		assertTrue(m.contains(";\r\n\tdmarc=pass (p=reject dis=none) header.from=a.test;\r\n\tarc=none smtp.remote-ip="), m);
	}

	@Test
	public void forgedFromRecordedWhenNotEnforcing() throws Exception {
		String r = send(b, "tony@a.test", "From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: dmarc recorded\r\n\r\nhi\r\n");
		assertTrue(r.startsWith("250"), r);
		String m = waitFor("dmarc recorded");
		assertTrue(m.contains("\r\n\tdmarc=fail (p=reject dis=reject) header.from=a.test;\r\n\tarc=none"), m);
	}

	@Test
	public void enforcedRejectAndQuarantine() throws Exception {
		b.getDmarc().setEnforce(true);
		try {
			String r = send(b, "tony@a.test", "From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: dmarc reject\r\n\r\nhi\r\n");
			assertTrue(r.startsWith("550 5.7.1 Rejected by the DMARC policy of a.test"), r);

			int before = junkCount();
			r = send(b, "x@q.test", "From: x@q.test\r\nTo: team1@b.test\r\nSubject: dmarc quarantine\r\n\r\nhi\r\n");
			assertTrue(r.startsWith("250"), r);
			TestSmtpServer.waitFor(() -> junkCount() == before + 1, 30000, "delivery to Junk");
			assertTrue(find("dmarc quarantine") == null, "not in the INBOX");

			// an aligned SPF pass (MAIL FROM bounces.spf.test, From spf.test) passes
			r = send(b, "x@bounces.spf.test", "From: news@spf.test\r\nTo: team1@b.test\r\nSubject: dmarc spf\r\n\r\nhi\r\n");
			assertTrue(r.startsWith("250"), r);
			String m = waitFor("dmarc spf");
			assertTrue(m.contains("spf=pass smtp.mailfrom=bounces.spf.test"), m);
			assertTrue(m.contains("dmarc=pass (p=reject dis=none) header.from=spf.test"), m);
		} finally {
			b.getDmarc().setEnforce(false);
		}
	}

	@Test
	public void noPolicyAndBadFrom() throws Exception {
		String r = send(b, "x@nopolicy.test", "From: x@nopolicy.test\r\nTo: team1@b.test\r\nSubject: dmarc none\r\n\r\nhi\r\n");
		assertTrue(r.startsWith("250"), r);
		assertTrue(waitFor("dmarc none").contains("\tdmarc=none header.from=nopolicy.test;\r\n\tarc=none"));
		r = send(b, "x@nopolicy.test", "From: a@x.test\r\nFrom: b@y.test\r\nTo: team1@b.test\r\nSubject: dmarc two\r\n\r\nhi\r\n");
		assertTrue(r.startsWith("250"), r);
		assertTrue(waitFor("dmarc two").contains("\tdmarc=permerror reason=\"more than one From field\";\r\n\tarc=none"));
	}

	private static String report(String subjectStart) {
		try {
			for (String m : TestSmtpServer.inbox(rootB, "tony")) {
				if (m.contains("\r\nSubject: " + subjectStart)) {
					return m;
				}
			}
		} catch (IOException e) {
			// not yet
		}
		return null;
	}

	@Test
	public void reportsReachTheirAddress() throws Exception {
		String r = send(b, "tony@a.test", "From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: dmarc report me\r\n\r\nhi\r\n");
		assertTrue(r.startsWith("250"), r);
		waitFor("dmarc report me");
		// the failure report, at once, through the queue
		TestSmtpServer.waitFor(() -> report("DMARC failure report for a.test") != null, 30000, "failure report");
		String f = report("DMARC failure report for a.test");
		assertTrue(f.contains("Feedback-Type: auth-failure\r\n"), f);
		assertTrue(f.contains("Delivery-Result: delivered\r\n"), f);
		// the aggregate report, when the interval ends (here: flushed now)
		assertTrue(b.getDmarc().getReporter().flush() >= 1);
		TestSmtpServer.waitFor(() -> report("Report Domain: a.test Submitter: mx.b.test") != null, 30000, "aggregate report");
		String xml = TestDmarcReports.xml(report("Report Domain: a.test Submitter: mx.b.test"));
		TestDmarcReports.validate(xml);
		assertTrue(xml.contains("<header_from>a.test</header_from>"), xml);
		assertTrue(xml.contains("<source_ip>127.0.0.1</source_ip>") || xml.contains("<source_ip>0:0:0:0:0:0:0:1</source_ip>"), xml);
	}

	static int junkCount() {
		try {
			MailStore store = new MailStore(rootB.getChild("team"), MailboxRegistry.get());
			if (!store.exists("Junk")) {
				return 0;
			}
			Mailbox mb = store.open("Junk");
			try {
				mb.refresh(true);
				return mb.count();
			} finally {
				MailboxRegistry.get().release(mb);
			}
		} catch (IOException e) {
			return -1;
		}
	}
}
