package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.server.DnsServer;
import us.bringardner.parley.smtp.queue.ParleyDnsMxResolver;
import us.bringardner.parley.smtp.queue.DeliveryException;
import us.bringardner.parley.smtp.queue.DnsMxResolver;
import us.bringardner.parley.smtp.queue.MxResolver;

/**
 * ParleyDnsMxResolver against a real parley-dns {@link DnsServer}, configured with zone
 * files in a temp directory and running on a free port on 127.0.0.1:
 * <pre>
 * mx.test        MX 10 mail1.mx.test (A), MX 20 mail2.mx.test (A and AAAA)
 * implicit.test  A 127.0.0.3 (no MX)
 * nullmx.test    MX 0 . (RFC 7505)
 * v6only.test    MX 10 mail6.v6only.test, which has only AAAA ::1
 * </pre>
 * The server is authoritative for these zones only and doesn't recurse, so a
 * question about any other domain gets SERVFAIL.
 */
public class TestParleyDnsMxResolver {

	private static DnsServer dns;
	private static int dnsPort;
	private static File dnsDir;

	static final String MX_ZONE = String.join("\n",
			"$ORIGIN mx.test.",
			"$TTL 300",
			"@       IN SOA ns.mx.test. admin.mx.test. ( 1 3600 600 86400 300 )",
			"@       IN NS  ns.mx.test.",
			"ns      IN A   127.0.0.1",
			"@       IN MX  20 mail2.mx.test.",
			"@       IN MX  10 mail1.mx.test.",
			"mail1   IN A   127.0.0.1",
			"mail2   IN A   127.0.0.2",
			"mail2   IN AAAA ::1",
			"txtonly IN TXT \"no mail here\"",
			"@       IN TXT \"v=spf1 mx -all\"",
			// a DKIM key longer than one 255-byte string (the RFC 8463 example RSA key)
			"test._domainkey IN TXT \"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/b\" \"yYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB\"",
			"");

	static final String IMPLICIT_ZONE = String.join("\n",
			"$ORIGIN implicit.test.",
			"$TTL 300",
			"@       IN SOA ns.mx.test. admin.mx.test. ( 1 3600 600 86400 300 )",
			"@       IN NS  ns.mx.test.",
			"@       IN A   127.0.0.3",
			"");

	/** A domain whose only mail host has only an IPv6 address. */
	static final String V6_ONLY_ZONE = String.join("\n",
			"$ORIGIN v6only.test.",
			"$TTL 300",
			"@       IN SOA ns.mx.test. admin.mx.test. ( 1 3600 600 86400 300 )",
			"@       IN NS  ns.mx.test.",
			"@       IN MX  10 mail6.v6only.test.",
			"mail6   IN AAAA ::1",
			"");

	static final String NULL_MX_ZONE = String.join("\n",
			"$ORIGIN nullmx.test.",
			"$TTL 300",
			"@       IN SOA ns.mx.test. admin.mx.test. ( 1 3600 600 86400 300 )",
			"@       IN NS  ns.mx.test.",
			"@       IN MX  0 .",
			"");

	@BeforeAll
	public static void startDns() throws Exception {
		dnsDir = Files.createTempDirectory("parleydns").toFile();
		File zones = new File(dnsDir, "zones");
		zones.mkdirs();
		Files.writeString(new File(zones, "mx.test.txt").toPath(), MX_ZONE);
		Files.writeString(new File(zones, "implicit.test.txt").toPath(), IMPLICIT_ZONE);
		Files.writeString(new File(zones, "nullmx.test.txt").toPath(), NULL_MX_ZONE);
		Files.writeString(new File(zones, "v6only.test.txt").toPath(), V6_ONLY_ZONE);
		dnsPort = freePort();
		System.setProperty(DnsServer.PROP_DNS_DIR, dnsDir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_ZONE_DIR, zones.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "mx.test");
		System.setProperty(DnsServer.PROP_PORT, String.valueOf(dnsPort));
		System.setProperty(DnsServer.PROP_UDP_PORT, String.valueOf(dnsPort));
		System.setProperty(DnsServer.PROP_TCP_PORT, String.valueOf(dnsPort));
		System.setProperty(DnsServer.PROP_ADMIN_PORT, String.valueOf(freePort()));
		System.setProperty(DnsServer.PROP_BIND_ADDRESS, "127.0.0.1");
		System.setProperty(DnsServer.PROP_USE_DATABASE, "false");
		dns = new DnsServer();
		dns.start();
		dns.awaitStarted(10000);
		assertTrue(dns.isRunning(), "the DNS server started");
	}

	/** A port free for both UDP and TCP. */
	private static int freePort() throws Exception {
		for (int i = 0; i < 20; i++) {
			try (ServerSocket tcp = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
					DatagramSocket udp = new DatagramSocket(tcp.getLocalPort(), InetAddress.getByName("127.0.0.1"))) {
				return tcp.getLocalPort();
			} catch (java.net.BindException e) {
				// try another
			}
		}
		throw new IllegalStateException("No free port");
	}

	@AfterAll
	public static void stopDns() throws Exception {
		if (dns != null) {
			dns.stopAndWait(10000);
		}
		if (dnsDir != null) {
			try (var walk = Files.walk(dnsDir.toPath())) {
				walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
			}
		}
	}

	private static ParleyDnsMxResolver resolver() throws Exception {
		ParleyDnsMxResolver r = new ParleyDnsMxResolver(List.of(InetAddress.getLoopbackAddress()));
		r.setDnsPort(dnsPort);
		r.setTimeout(1000);
		r.setRetries(1);
		return r;
	}

	@Test
	public void testMxByPreference() throws Exception {
		List<MxResolver.Route> routes = resolver().resolve("mx.test", 2525);
		assertEquals(3, routes.size(), routes.toString());
		assertEquals("mail1.mx.test", routes.get(0).host, "lowest preference first");
		assertEquals("127.0.0.1", routes.get(0).address.getHostAddress());
		assertEquals("mail2.mx.test", routes.get(1).host);
		assertEquals("127.0.0.2", routes.get(1).address.getHostAddress(), "IPv4 first");
		assertEquals("mail2.mx.test", routes.get(2).host);
		assertTrue(routes.get(2).address instanceof Inet6Address, "and its IPv6 address: " + routes);
		assertTrue(routes.get(2).address.isLoopbackAddress());
		assertEquals(2525, routes.get(0).port);
	}

	/** Both families are found even when the MX answer carries only the A record (glue). */
	@Test
	public void testBothAddressFamilies() throws Exception {
		ParleyDnsMxResolver r = resolver();
		r.setPreferIpv6(true);
		List<MxResolver.Route> routes = r.resolve("mx.test", 25);
		assertEquals("mail2.mx.test", routes.get(1).host);
		assertTrue(routes.get(1).address instanceof Inet6Address, "IPv6 first when preferred: " + routes);
		assertEquals("127.0.0.2", routes.get(2).address.getHostAddress());

		routes = resolver().resolve("v6only.test", 25);
		assertEquals(1, routes.size(), routes.toString());
		assertEquals("mail6.v6only.test", routes.get(0).host);
		assertTrue(routes.get(0).address instanceof Inet6Address, "an IPv6-only host still gets a route");
	}

	@Test
	public void testIpv6Literals() throws Exception {
		List<MxResolver.Route> routes = resolver().resolve("[IPv6:2001:db8::25]", 25);
		assertEquals(InetAddress.getByName("2001:db8::25"), routes.get(0).address);
		routes = new DnsMxResolver().resolve("[IPv6:2001:db8::25]", 25);
		assertEquals("2001:db8::25", routes.get(0).host);
	}

	@Test
	public void testImplicitMx() throws Exception {
		List<MxResolver.Route> routes = resolver().resolve("implicit.test", 25);
		assertEquals(1, routes.size());
		assertEquals("implicit.test", routes.get(0).host);
		assertEquals("127.0.0.3", routes.get(0).address.getHostAddress());
	}

	@Test
	public void testFailures() throws Exception {
		ParleyDnsMxResolver r = resolver();
		DeliveryException e = assertThrows(DeliveryException.class, () -> r.resolve("nullmx.test", 25));
		assertTrue(e.isPermanent());
		assertEquals("5.1.10", e.getStatus());
		e = assertThrows(DeliveryException.class, () -> r.resolve("nosuchname.mx.test", 25));
		assertTrue(e.isPermanent(), "NXDOMAIN");
		assertEquals("5.1.2", e.getStatus());
		e = assertThrows(DeliveryException.class, () -> r.resolve("txtonly.mx.test", 25));
		assertTrue(e.isPermanent(), "no MX and no address");
		e = assertThrows(DeliveryException.class, () -> r.resolve("elsewhere.test", 25));
		assertFalse(e.isPermanent(), "SERVFAIL (not our zone, no recursion) is temporary");
		assertEquals("4.4.3", e.getStatus());
	}

	/** SPF checks make their queries (TXT, MX, A) with parley-dns too. */
	@Test
	public void testSpfThroughParleyDns() throws Exception {
		us.bringardner.parley.smtp.spf.SpfChecker spf = new us.bringardner.parley.smtp.spf.SpfChecker(resolver()::records, "mx.test");
		us.bringardner.parley.smtp.spf.SpfResult r = spf.checkMailFrom(InetAddress.getByName("127.0.0.2"), "joe@mx.test", "mail2.mx.test");
		assertEquals(us.bringardner.parley.smtp.spf.SpfResult.Result.PASS, r.getResult(), r.toString());
		r = spf.checkMailFrom(InetAddress.getByName("::1"), "joe@mx.test", "mail2.mx.test");
		assertEquals(us.bringardner.parley.smtp.spf.SpfResult.Result.PASS, r.getResult(), "mail2's AAAA: " + r);
		r = spf.checkMailFrom(InetAddress.getByName("127.0.0.9"), "joe@mx.test", "x.example");
		assertEquals(us.bringardner.parley.smtp.spf.SpfResult.Result.FAIL, r.getResult(), r.toString());
		r = spf.checkMailFrom(InetAddress.getByName("127.0.0.9"), "joe@implicit.test", "x.example");
		assertEquals(us.bringardner.parley.smtp.spf.SpfResult.Result.NONE, r.getResult(), r.toString());
		r = spf.checkMailFrom(InetAddress.getByName("127.0.0.9"), "joe@elsewhere.test", "x.example");
		assertEquals(us.bringardner.parley.smtp.spf.SpfResult.Result.TEMPERROR, r.getResult(), "SERVFAIL: " + r);
	}

	/** DKIM keys come from parley-dns too: TXT lookups through the same servers. */
	@Test
	public void testDkimKeyLookup() throws Exception {
		ParleyDnsMxResolver r = resolver();
		us.bringardner.parley.dns.resolve.LookupResult<String> key = r.txt("test._domainkey.mx.test");
		assertTrue(key.isOk(), key.toString());
		assertTrue(key.getFirst().startsWith("v=DKIM1; k=rsa; p=MIGf") && key.getFirst().endsWith("QIDAQAB"), key.getFirst());
		assertEquals(us.bringardner.parley.dns.resolve.LookupResult.Status.NXDOMAIN, r.txt("none._domainkey.mx.test").getStatus());
		assertTrue(r.txt("elsewhere.test").isTempFail(), "SERVFAIL");

		String msg = "From: joe@mx.test\r\nTo: ann@example.net\r\nSubject: hi\r\n\r\nHello\r\n";
		us.bringardner.parley.smtp.dkim.DkimSigner signer = new us.bringardner.parley.smtp.dkim.DkimSigner("mx.test", "test",
				us.bringardner.parley.smtp.dkim.DkimKeys.privateKey(TestDkim.RSA_SECRET));
		String field = signer.sign(new java.io.ByteArrayInputStream(msg.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		List<us.bringardner.parley.smtp.dkim.DkimResult> results = new us.bringardner.parley.smtp.dkim.DkimVerifier(r::txt)
				.verify(new java.io.ByteArrayInputStream((field + msg).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		assertTrue(results.get(0).isPass(), results.toString());
	}

	@Test
	public void testNextServerAndLiterals() throws Exception {
		// the first server doesn't answer (nothing listens there); the second does
		ParleyDnsMxResolver r = new ParleyDnsMxResolver(List.of(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("127.0.0.1")));
		r.setDnsPort(dnsPort);
		r.setTimeout(300);
		r.setRetries(1);
		assertEquals(3, r.resolve("mx.test", 25).size());

		// no server answers: temporary
		ParleyDnsMxResolver none = new ParleyDnsMxResolver(List.of(InetAddress.getByName("127.0.0.2")));
		none.setDnsPort(dnsPort);
		none.setTimeout(300);
		none.setRetries(1);
		DeliveryException e = assertThrows(DeliveryException.class, () -> none.resolve("mx.test", 25));
		assertFalse(e.isPermanent(), "a timeout is temporary");

		List<MxResolver.Route> lit = resolver().resolve("[127.0.0.9]", 25);
		assertEquals("127.0.0.9", lit.get(0).address.getHostAddress());
	}

	/** True if this machine has an IPv6 loopback (CI containers sometimes don't). */
	static boolean ipv6Available() {
		try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("::1"))) {
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Start a receiving server B for {@code domain} and a relaying server A that
	 * finds B with {@code resolver}; send one message from A to tony@domain and
	 * return it as B stored it.
	 */
	private static String relay(String domain, MxResolver resolver) throws Exception {
		us.bringardner.parley.files.FileSourceFactory f = us.bringardner.parley.files.FileSourceFactory.getDefaultFactory();
		us.bringardner.parley.files.FileSource rootA = f.createTempDirectory("dnsA");
		us.bringardner.parley.files.FileSource rootB = f.createTempDirectory("dnsB");
		System.setProperty("SmtpServer." + us.bringardner.parley.net.server.FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + us.bringardner.parley.net.server.IServer.AUTHENTICATION_PROVIDER_PROPERTY,
				us.bringardner.parley.net.server.FileBasedAcl.class.getName());
		us.bringardner.parley.smtp.server.SmtpServer b = new us.bringardner.parley.smtp.server.SmtpServer(0, "JSmtp", false);
		us.bringardner.parley.smtp.server.SmtpServer a = new us.bringardner.parley.smtp.server.SmtpServer(0, "JSmtp", false);
		try {
			b.setMaildropRoot(rootB);
			b.setHostname("mx." + domain);
			b.getDeliveryConfig().getLocalDomains().clear();
			b.addLocalDomain(domain);
			b.getLogger().setLevel(us.bringardner.parley.core.ILogger.Level.ERROR);
			b.getSpf().setDns(resolver()::records); // SPF from the test DNS server, not the real one
			b.getDmarc().setDns(resolver()::txt);
			b.startAndWait(10000);

			a.setMaildropRoot(rootA);
			a.setHostname("mx.a.test");
			a.getDeliveryConfig().getLocalDomains().clear();
			a.addLocalDomain("a.test");
			a.addRelayNetwork("127.0.0.1/32");
			a.addRelayNetwork("::1/128");
			a.getDeliveryConfig().setResolver(resolver);
			a.getDeliveryConfig().setRemotePort(b.getLocalPort());
			a.getDeliveryConfig().setConnectTimeout(1000);
			a.getLogger().setLevel(us.bringardner.parley.core.ILogger.Level.ERROR);
			a.startAndWait(10000);

			try (TestSmtpServer.Client c = new TestSmtpServer.Client(a.getLocalPort())) {
				c.ok("EHLO client.example", "250");
				String r = c.sendMail("app@a.test", "tony@" + domain, "Subject: relayed\r\n\r\nhi\r\n");
				assertTrue(r.startsWith("250"), r);
			}
			TestSmtpServer.waitFor(() -> TestSmtpServer.count(rootB, "tony") == 1, 30000, "relay to " + domain);
			return TestSmtpServer.inbox(rootB, "tony").get(0);
		} finally {
			a.stop();
			b.stop();
			deleteAll(rootA);
			deleteAll(rootB);
		}
	}

	/** The queue relays through routes found with parley-dns (the SMTP client connects to their addresses). */
	@Test
	public void testRelayWithParleyDns() throws Exception {
		String m = relay("mx.test", resolver());
		assertTrue(m.contains("by mx.mx.test (Parley)"), m);
		assertTrue(m.contains("from mx.a.test ([127.0.0.1])"), "A connected to mail1's IPv4 address: " + m);
	}

	/** Delivery to a mail host that has only an IPv6 address, over ::1. Skipped without IPv6. */
	@Test
	public void testRelayOverIpv6() throws Exception {
		assumeTrue(ipv6Available(), "no IPv6 loopback on this machine");
		String m = relay("v6only.test", resolver());
		assertTrue(m.contains("from mx.a.test ([IPv6:"), "B saw an IPv6 client: " + m);
	}

	/** An unreachable IPv6 address is skipped for the host's next (IPv4) address. Runs with or without IPv6. */
	@Test
	public void testFallbackBetweenFamilies() throws Exception {
		InetAddress unreachable = InetAddress.getByName("2001:db8::25"); // documentation prefix
		InetAddress v4 = InetAddress.getByName("127.0.0.1");
		MxResolver r = (domain, port) -> List.of(new MxResolver.Route("mail1." + domain, unreachable, port),
				new MxResolver.Route("mail1." + domain, v4, port));
		String m = relay("fallback.test", r);
		assertTrue(m.contains("from mx.a.test ([127.0.0.1])"), m);
	}

	private static void deleteAll(us.bringardner.parley.files.FileSource f) throws java.io.IOException {
		if (f.isDirectory()) {
			for (us.bringardner.parley.files.FileSource k : f.listFiles()) {
				deleteAll(k);
			}
		}
		f.delete();
	}
}
