package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import us.bringardner.parley.smtp.dkim.ArcResult;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.queue.DeliveryException;
import us.bringardner.parley.smtp.queue.MxResolver;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * ARC in the SMTP server (RFC 8617): server F receives mail for an alias whose
 * member is at r.test, seals it and forwards it to server R. Forwarding breaks
 * the original authentication, so R's DMARC check of o.test (p=reject) fails;
 * R delivers it anyway when F is a trusted sealer, and rejects it otherwise.
 */
public class TestArcSmtp {

	private static SmtpServer f;
	private static SmtpServer r;
	private static FileSource rootF;
	private static FileSource rootR;
	private static final Map<String, String> txt = new HashMap<>();

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("SmtpServer." + FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		FileSourceFactory fs = FileSourceFactory.getDefaultFactory();
		rootF = fs.createTempDirectory("arcF");
		rootR = fs.createTempDirectory("arcR");
		KeyPair key = DkimKeys.generate("rsa");
		txt.put("k1._domainkey.f.test", DkimKeys.dnsRecord(key.getPublic()));
		txt.put("_dmarc.o.test", "v=DMARC1; p=reject; rua=mailto:tony@r.test");
		txt.put("o.test._report._dmarc.r.test", "v=DMARC1");

		r = server(rootR, "mx.r.test", "r.test");
		r.getDmarc().setEnforce(true);
		r.getDmarc().getReporter().setAggregate(true);
		r.getDmarc().getReporter().setOrgName("mx.r.test");
		r.getDmarc().getReporter().setEmail("postmaster@r.test");
		r.startAndWait(10000);

		f = server(rootF, "mx.f.test", "f.test");
		// seals with the f.test key (the closest parent of the host name mx.f.test)
		f.getDkim().addSigner(new DkimSigner("f.test", "k1", key.getPrivate()));
		f.getDeliveryConfig().addAlias("list", "team1@r.test");
		f.getDeliveryConfig().setResolver((domain, port) -> {
			if (domain.equals("r.test")) {
				return List.of(new MxResolver.Route("127.0.0.1", r.getLocalPort()));
			}
			throw DeliveryException.permanent("5.1.2", "The domain " + domain + " doesn't exist");
		});
		f.startAndWait(10000);
	}

	private static SmtpServer server(FileSource root, String host, String domain) throws IOException {
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		s.setMaildropRoot(root);
		s.setHostname(host);
		s.getDeliveryConfig().getLocalDomains().clear();
		s.addLocalDomain(domain);
		s.getLogger().setLevel(Level.ERROR);
		s.getSpf().setDns(new TestSpfSuite.Zone(new HashMap<>()));
		s.getDkim().setLookup(TestDkim.keys(txt));
		s.getDmarc().setDns(TestDkim.keys(txt)::txt);
		return s;
	}

	@AfterAll
	public static void stop() throws Exception {
		for (SmtpServer s : new SmtpServer[] {f, r}) {
			if (s != null) {
				s.stop();
			}
		}
		deleteAll(rootF);
		deleteAll(rootR);
	}

	private static void deleteAll(FileSource file) throws IOException {
		if (file == null) {
			return;
		}
		if (file.isDirectory()) {
			for (FileSource kid : file.listFiles()) {
				deleteAll(kid);
			}
		}
		file.delete();
	}

	/** Send to list@f.test from another server (not a relay client), envelope sender tony@f.test. */
	private static String send(String subject) throws IOException {
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(f.getLocalPort())) {
			c.ok("EHLO mail.o.test", "250");
			return c.sendMail("tony@f.test", "list@f.test",
					"From: Tony <tony@o.test>\r\nTo: list@f.test\r\nSubject: " + subject + "\r\n\r\nhello list\r\n");
		}
	}

	private static String find(FileSource root, String maildrop, String text) {
		try {
			for (String m : TestSmtpServer.inbox(root, maildrop)) {
				if (m.contains(text)) {
					return m;
				}
			}
		} catch (IOException e) {
			// not yet
		}
		return null;
	}

	@Test
	public void trustedSealerOverridesDmarc() throws Exception {
		r.getArc().addTrustedSealer("f.test");
		try {
			String reply = send("arc trusted");
			assertTrue(reply.startsWith("250"), reply);
			TestSmtpServer.waitFor(() -> find(rootR, "team", "Subject: arc trusted\r\n") != null, 30000, "forwarded copy");
			String m = find(rootR, "team", "Subject: arc trusted\r\n");

			String u = m.replaceAll("\r\n[ \t]+", " "); // unfolded
			// F's set: the first in the chain, with F's results
			assertTrue(u.contains("\r\nARC-Seal: a=rsa-sha256; b="), u);
			assertTrue(u.contains("; cv=none; d=f.test; i=1; s=k1; t="), u);
			assertTrue(u.contains("\r\nARC-Message-Signature: a=rsa-sha256; b="), u);
			assertTrue(u.contains("\r\nARC-Authentication-Results: i=1; mx.f.test; "), u);
			assertTrue(u.contains("; arc=none smtp.remote-ip="), u);
			// R: the chain validates; DMARC fails but the trusted seal wins
			assertTrue(u.contains("dmarc=fail (p=reject dis=reject) header.from=o.test"), u);
			assertTrue(u.contains("; arc=pass (as[1].d=f.test) smtp.remote-ip="), u);

			ArcResult arc = r.getArc().verifier(r.getDkim()).verify(new ByteArrayInputStream(m.getBytes(StandardCharsets.UTF_8)));
			assertEquals(ArcResult.Result.PASS, arc.getResult(), String.valueOf(arc));

			// the aggregate report says why the policy wasn't applied (RFC 8617 section 7.2.2)
			assertTrue(r.getDmarc().getReporter().flush() >= 1);
			TestSmtpServer.waitFor(() -> find(rootR, "tony", "Report Domain: o.test") != null, 30000, "aggregate report");
			String xml = TestDmarcReports.xml(find(rootR, "tony", "Report Domain: o.test"));
			TestDmarcReports.validate(xml);
			assertTrue(xml.contains("<type>local_policy</type>"), xml);
			assertTrue(xml.contains("<comment>arc=pass as[1].d=f.test as[1].s=k1 remote-ip[1]="), xml);
		} finally {
			r.getArc().removeTrustedSealer("f.test");
		}
	}

	@Test
	public void untrustedSealerIsRejected() throws Exception {
		String reply = send("arc untrusted");
		assertTrue(reply.startsWith("250"), reply);
		// R refuses the forwarded copy; F returns it to tony@f.test
		TestSmtpServer.waitFor(() -> find(rootF, "tony", "Rejected by the DMARC policy of o.test") != null, 30000, "bounce");
		assertTrue(find(rootR, "team", "Subject: arc untrusted\r\n") == null);
	}
}
