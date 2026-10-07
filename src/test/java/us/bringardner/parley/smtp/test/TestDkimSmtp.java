package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
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
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.DkimResult.Result;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.DkimVerifier;
import us.bringardner.parley.smtp.queue.DeliveryException;
import us.bringardner.parley.smtp.queue.MxResolver;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * DKIM in the SMTP server: server A (a.test) signs the mail of its trusted
 * network with a key for a.test and relays it to server B (b.test), which
 * verifies it and adds Authentication-Results.
 */
public class TestDkimSmtp {

	private static SmtpServer a;
	private static SmtpServer b;
	private static FileSource rootA;
	private static FileSource rootB;
	private static KeyPair key;
	private static final Map<String, String> dns = new HashMap<>();

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("SmtpServer." + FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		FileSourceFactory f = FileSourceFactory.getDefaultFactory();
		rootA = f.createTempDirectory("dkimA");
		rootB = f.createTempDirectory("dkimB");
		key = DkimKeys.generate("rsa");
		dns.put("k1._domainkey.a.test", DkimKeys.dnsRecord(key.getPublic()));

		b = server(rootB, "mx.b.test", "b.test");
		b.getDkim().setLookup(TestDkim.keys(dns));
		b.startAndWait(10000);

		a = server(rootA, "mx.a.test", "a.test");
		a.addRelayNetwork("127.0.0.0/8");
		a.getDkim().addSigner(new DkimSigner("a.test", "k1", key.getPrivate()));
		a.getDkim().setLookup(TestDkim.keys(dns));
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
		s.setLoginFailureDelay(0);
		s.getLogger().setLevel(Level.ERROR);
		s.getSpf().setDns(new TestSpfSuite.Zone(new java.util.HashMap<>())); // SPF without real DNS: every domain has none
		s.getDmarc().setDns(TestDkim.keys(new java.util.HashMap<>())::txt); // nor DMARC: no policy records
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

	/** Send through a server and wait for the message with {@code subject} to reach a maildrop. */
	private static String deliver(SmtpServer via, String from, String rcpt, String data, FileSource root, String maildrop,
			String subject) throws Exception {
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(via.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.sendMail(from, rcpt, data);
			assertTrue(r.startsWith("250"), r);
		}
		TestSmtpServer.waitFor(() -> find(root, maildrop, subject) != null, 30000, subject);
		return find(root, maildrop, subject);
	}

	private static String find(FileSource root, String maildrop, String subject) {
		try {
			for (String m : TestSmtpServer.inbox(root, maildrop)) {
				if (m.contains("Subject: " + subject + "\r\n")) {
					return m;
				}
			}
		} catch (IOException e) {
			// not yet
		}
		return null;
	}

	/** The message as delivered, without the fields local delivery adds (Return-Path, Delivered-To). */
	private static List<DkimResult> verify(String delivered) throws IOException {
		return new DkimVerifier(TestDkim.keys(dns)).verify(new ByteArrayInputStream(delivered.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void signedAndVerified() throws Exception {
		String m = deliver(a, "tony@a.test", "team1@b.test",
				"From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: signed\r\n\r\nHello Team\r\n", rootB, "team", "signed");
		assertTrue(m.contains("\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"), m);
		assertTrue(m.contains("d=a.test; s=k1;"), m);
		int received = m.indexOf("\r\nReceived: from ");
		int ar = m.indexOf("\r\nAuthentication-Results: mx.b.test;\r\n\tspf=none smtp.mailfrom=a.test;\r\n\tdkim=pass header.d=a.test header.i=@a.test header.s=k1"
				+ " header.a=rsa-sha256 header.b=");
		assertTrue(ar > received && received > 0, "A-R after B's Received: " + m);
		assertTrue(m.indexOf("\r\nDKIM-Signature:") > ar, m);
		// still verifies after delivery
		assertEquals(Result.PASS, verify(m).get(0).getResult());
	}

	@Test
	public void subdomainSignedWithParentKey() throws Exception {
		String m = deliver(a, "news@lists.a.test", "team1@b.test",
				"From: news@lists.a.test\r\nTo: team1@b.test\r\nSubject: subdomain\r\n\r\nNews\r\n", rootB, "team", "subdomain");
		assertTrue(m.contains("d=a.test; s=k1;"), m);
		assertTrue(m.contains("dkim=pass header.d=a.test"), m);
	}

	@Test
	public void otherDomainsNotSigned() throws Exception {
		String m = deliver(a, "app@c.test", "team1@b.test",
				"From: app@c.test\r\nTo: team1@b.test\r\nSubject: unsigned\r\n\r\nHi\r\n", rootB, "team", "unsigned");
		assertFalse(m.contains("DKIM-Signature"), m);
		assertTrue(m.contains("\r\nAuthentication-Results: mx.b.test;\r\n\tspf=none smtp.mailfrom=c.test;\r\n\tdkim=none;\r\n\tdmarc=none header.from=c.test;\r\n\tarc=none"), m);
	}

	@Test
	public void tamperedAndForgedResults() throws Exception {
		String body = "From: Tony <tony@a.test>\r\nTo: team1@b.test\r\nSubject: tampered\r\n\r\nPay 10 dollars\r\n";
		String sig = new DkimSigner("a.test", "k1", key.getPrivate()).sign(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
		String data = "Authentication-Results: mx.b.test; dkim=pass header.d=a.test\r\n"
				+ "Authentication-Results: MX.B.TEST (forged) 1; spf=pass\r\n"
				+ "Authentication-Results: other.example; dkim=pass\r\n"
				+ sig + body.replace("10", "10000");
		// straight to B, as from the internet
		String m = deliver(b, "tony@a.test", "team1@b.test", data, rootB, "team", "tampered");
		assertTrue(m.contains("\r\nAuthentication-Results: mx.b.test;\r\n\tspf=none smtp.mailfrom=a.test;\r\n\tdkim=fail reason=\"body hash did not verify\" header.d=a.test"), m);
		assertEquals(1, count(m, "Authentication-Results: mx.b.test"), "the forged ones are removed: " + m);
		assertFalse(m.contains("MX.B.TEST"), m);
		assertTrue(m.contains("\r\nAuthentication-Results: other.example; dkim=pass\r\n"), "others' results are kept: " + m);
	}

	@Test
	public void bouncesAndCodeSentMailSigned() throws Exception {
		// a bounce from MAILER-DAEMON@mx.a.test is signed with the a.test key
		deliver(a, "tony@a.test", "nobody@nowhere.test",
				"From: tony@a.test\r\nTo: nobody@nowhere.test\r\nSubject: will bounce\r\n\r\nHi\r\n", rootA, "tony",
				"Undelivered Mail Returned to Sender");
		String dsn = find(rootA, "tony", "Undelivered Mail Returned to Sender");
		assertNotNull(dsn);
		assertTrue(dsn.contains("DKIM-Signature: v=1;"), dsn);
		assertEquals(Result.PASS, verify(dsn).get(0).getResult(), dsn);

		// mail queued from code
		a.getQueue().enqueue(MailAddress.parse("app@a.test", false), List.of(MailAddress.parse("team1@b.test", false)),
				new ByteArrayInputStream("From: app@a.test\nTo: team1@b.test\nSubject: from code\n\nqueued\n".getBytes(StandardCharsets.UTF_8)),
				false);
		TestSmtpServer.waitFor(() -> find(rootB, "team", "from code") != null, 30000, "mail from code");
		String m = find(rootB, "team", "from code");
		assertTrue(m.contains("dkim=pass header.d=a.test"), m);
	}

	private static int count(String s, String what) {
		int n = 0;
		for (int i = s.indexOf(what); i >= 0; i = s.indexOf(what, i + 1)) {
			n++;
		}
		return n;
	}
}
