package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
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
import us.bringardner.parley.smtp.server.SmtpServer;

/** SPF in the SMTP server: results recorded in Received-SPF and Authentication-Results, and optional rejection. */
public class TestSpfSmtp {

	private static SmtpServer b;
	private static FileSource rootB;

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("SmtpServer." + FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		rootB = FileSourceFactory.getDefaultFactory().createTempDirectory("spfB");
		b = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		b.setMaildropRoot(rootB);
		b.setHostname("mx.b.test");
		b.getDeliveryConfig().getLocalDomains().clear();
		b.addLocalDomain("b.test");
		b.getLogger().setLevel(Level.ERROR);

		Map<String, Object> zone = new HashMap<>();
		zone.put("pass.test", records("SPF", "v=spf1 ip4:127.0.0.0/8 ip6:::1 -all"));
		zone.put("fail.test", records("SPF", "v=spf1 -all exp=why.fail.test"));
		zone.put("why.fail.test", records("TXT", "%{i} may not send for %{d}"));
		zone.put("soft.test", records("SPF", "v=spf1 ~all"));
		zone.put("helo.test", records("SPF", "v=spf1 a -all", "A", "127.0.0.1", "AAAA", "::1"));
		zone.put("slow.test", Arrays.asList("TIMEOUT"));
		b.getSpf().setDns(new TestSpfSuite.Zone(zone));
		b.getDmarc().setDns(TestDkim.keys(new HashMap<>())::txt);
		b.startAndWait(10000);
	}

	private static List<Object> records(String... typeValue) {
		List<Object> ret = new java.util.ArrayList<>();
		for (int i = 0; i < typeValue.length; i += 2) {
			Map<String, Object> m = new HashMap<>();
			m.put(typeValue[i], typeValue[i + 1]);
			ret.add(m);
		}
		return ret;
	}

	@AfterAll
	public static void stop() throws Exception {
		if (b != null) {
			b.stop();
		}
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

	private static String deliver(String helo, String from, String data, String subject) throws Exception {
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO " + helo, "250");
			String r = c.sendMail(from, "team1@b.test", data);
			assertTrue(r.startsWith("250"), r);
		}
		TestSmtpServer.waitFor(() -> find(subject) != null, 30000, subject);
		return find(subject);
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

	@Test
	public void passRecorded() throws Exception {
		String m = deliver("client.pass.test", "a@pass.test", "From: a@pass.test\r\nSubject: spf pass\r\n\r\nhi\r\n", "spf pass");
		assertTrue(m.contains("\r\nReceived-SPF: pass (mx.b.test: domain of a@pass.test designates "), m);
		assertTrue(m.contains("receiver=mx.b.test;"), m);
		assertTrue(m.contains("envelope-from=\"a@pass.test\";"), m);
		assertTrue(m.contains("helo=client.pass.test;"), m);
		assertTrue(m.contains("identity=mailfrom;"), m);
		assertTrue(m.contains("\r\nAuthentication-Results: mx.b.test;\r\n\tspf=pass smtp.mailfrom=pass.test;\r\n\tdkim=none;\r\n\tdmarc=none header.from=pass.test;\r\n\tarc=none"), m);
		assertTrue(m.indexOf("\r\nReceived: from client.pass.test") < m.indexOf("\r\nReceived-SPF:"), "after our Received: " + m);
	}

	@Test
	public void failAndSoftfailRecorded() throws Exception {
		String m = deliver("client.example", "a@fail.test", "From: a@fail.test\r\nSubject: spf fail\r\n\r\nhi\r\n", "spf fail");
		assertTrue(m.contains("\r\nReceived-SPF: fail (mx.b.test: domain of a@fail.test does not designate "), m);
		assertTrue(m.contains("spf=fail smtp.mailfrom=fail.test"), m);
		m = deliver("client.example", "a@soft.test", "From: a@soft.test\r\nSubject: spf soft\r\n\r\nhi\r\n", "spf soft");
		assertTrue(m.contains("\r\nReceived-SPF: softfail ("), m);
		m = deliver("client.example", "a@slow.test", "From: a@slow.test\r\nSubject: spf temp\r\n\r\nhi\r\n", "spf temp");
		assertTrue(m.contains("\r\nReceived-SPF: temperror ("), m);
		assertTrue(m.contains("spf=temperror reason=\"DNS lookup of slow.test failed\" smtp.mailfrom=slow.test"), m);
		m = deliver("client.example", "a@nospf.test", "From: a@nospf.test\r\nSubject: spf none\r\n\r\nhi\r\n", "spf none");
		assertTrue(m.contains("spf=none smtp.mailfrom=nospf.test"), m);
	}

	@Test
	public void rejectFail() throws Exception {
		b.getSpf().setRejectFail(true);
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.cmd("MAIL FROM:<a@fail.test>");
			assertTrue(r.startsWith("550 5.7.23 SPF validation failed: "), r);
			assertTrue(r.contains("may not send for fail.test"), "the domain's explanation: " + r);
			// softfail is not rejected
			c.ok("MAIL FROM:<a@soft.test>", "250");
			c.ok("RSET", "250");
			c.ok("MAIL FROM:<a@pass.test>", "250");
		} finally {
			b.getSpf().setRejectFail(false);
		}
	}

	@Test
	public void nullSenderChecksHelo() throws Exception {
		String m = deliver("helo.test", "", "From: mailer-daemon@helo.test\r\nSubject: spf helo\r\n\r\nbounce\r\n", "spf helo");
		assertTrue(m.contains("\r\nReceived-SPF: pass (mx.b.test: domain of helo.test designates "), m);
		assertTrue(m.contains("identity=helo;"), m);
		assertTrue(m.contains("spf=pass smtp.helo=helo.test"), m);
	}

	@Test
	public void forgedResultsRemoved() throws Exception {
		String data = "Received-SPF: pass (mx.b.test: forged) receiver=mx.b.test;\r\n"
				+ "Received-SPF: pass (upstream.example: domain of a@x designates 1.2.3.4) receiver=upstream.example;\r\n"
				+ "Authentication-Results: mx.b.test; spf=pass smtp.mailfrom=fail.test\r\n"
				+ "From: a@fail.test\r\nSubject: spf forged\r\n\r\nhi\r\n";
		String m = deliver("client.example", "a@fail.test", data, "spf forged");
		assertFalse(m.contains("(mx.b.test: forged)"), m);
		assertTrue(m.contains("Received-SPF: pass (upstream.example:"), "another receiver's result is kept: " + m);
		assertTrue(m.contains("spf=fail smtp.mailfrom=fail.test"), m);
		assertFalse(m.contains("spf=pass smtp.mailfrom=fail.test"), m);
	}

	@Test
	public void trustedClientsNotChecked() throws Exception {
		b.getSpf().setCheck(false);
		try {
			String m = deliver("client.example", "a@fail.test", "From: a@fail.test\r\nSubject: spf off\r\n\r\nhi\r\n", "spf off");
			assertFalse(m.contains("Received-SPF"), m);
			assertTrue(m.contains("\r\nAuthentication-Results: mx.b.test;\r\n\tdkim=none;\r\n\tdmarc=none header.from=fail.test;\r\n\tarc=none"), m);
		} finally {
			b.getSpf().setCheck(true);
		}
	}
}
