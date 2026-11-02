package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.smtp.queue.DeliveryConfig;
import us.bringardner.parley.smtp.test.MailStoreSetup;

/**
 * 2.0.0's settings with a unit in the value, not the name (To-Do 2.19): the queue's maxAge,
 * delayWarning, retry and dmarc.reportInterval, the server's timeout and pregreet.delay; and the
 * queue's smart host as smartHost.* (was relayHost...).
 */
public class TestDurationSettings {

	private static final String[] CLEARED = { "parley.mail.root", "parley.mail.smtp.hostname", "parley.mail.smtp.timeout",
			"parley.mail.smtp.pregreet.delay", "parley.mail.smtp.spam.timeout" };

	@TempDir
	File dir;

	private final Map<String, String> saved = new HashMap<>();

	@BeforeEach
	public void setUp() {
		for (String n : CLEARED) {
			saved.put(n, System.getProperty(n));
			System.clearProperty(n);
		}
		System.setProperty("parley.mail.root", new File(dir, "mail").getPath());
		System.setProperty("parley.mail.smtp.hostname", "mx.localhost");
	}

	@AfterEach
	public void restore() {
		for (String n : CLEARED) {
			System.clearProperty(n);
			if (saved.get(n) != null) {
				System.setProperty(n, saved.get(n));
			}
		}
	}

	private FileSource mail() throws IOException {
		return FileSourceFactory.getDefaultFactory().createFileSource(new File(dir, "mail").getPath());
	}

	@Test
	public void theQueuesTimesAreDurations() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "maxAge", "5d", "delayWarning", "90m", "retry", "30s, 5m,1h",
				"dmarc.reportInterval", "12h");
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		DeliveryConfig c = s.getQueue().getConfig();
		assertEquals(5L * 24 * 3_600_000, c.getMaxAge());
		assertEquals(90L * 60_000, c.getDelayWarning());
		assertArrayEquals(new long[] { 30_000, 300_000, 3_600_000 }, c.getRetrySchedule());
		assertEquals(12L * 3_600_000, c.getDmarc().getReporter().getIntervalMillis());
	}

	@Test
	public void theOldHourAndMinuteSettingsAreNotRead() throws Exception {
		DeliveryConfig defaults = new DeliveryConfig();
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "maxAgeHours", "1", "delayWarningHours", "1",
				"dmarc.reportIntervalHours", "1");
		DeliveryConfig c = new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue().getConfig();
		assertEquals(defaults.getMaxAge(), c.getMaxAge());
		assertEquals(defaults.getDelayWarning(), c.getDelayWarning());
	}

	@Test
	public void aWrongDurationRefusesTheQueue() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "maxAge", "five days");
		UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue());
		assertTrue(e.getMessage().contains("maxAge"), e.getMessage());
	}

	@Test
	public void theSmartHostIsSmartHostStar() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "smartHost", "smtp.provider.example", "smartHost.port", "2525",
				"smartHost.user", "me", "smartHost.auth", "SCRAM-SHA-256, PLAIN", "smartHost.tls", "opportunistic");
		DeliveryConfig c = new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue().getConfig();
		assertEquals("smtp.provider.example", c.getRelayHost());
		assertEquals(2525, c.getRelayPort());
		assertEquals("me", c.getRelayUser());
		assertEquals(java.util.Arrays.asList("SCRAM-SHA-256", "PLAIN"), c.getRelayAuthMechanisms());
		assertEquals(DeliveryConfig.TlsMode.OPPORTUNISTIC, c.getRelayTlsMode());
	}

	@Test
	public void theSmartHostsPortDefaultsToSubmission() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "smartHost", "smtp.provider.example");
		assertEquals(587, new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue().getConfig().getRelayPort());
	}

	@Test
	public void aPortInSmartHostIsRefused() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "smartHost", "smtp.provider.example:2525");
		UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue());
		assertTrue(e.getMessage().contains("smartHost.port"), e.getMessage());
	}

	@Test
	public void theOldRelaySettingsAreNotRead() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "relayHost", "smtp.provider.example:2525", "relayUser", "me");
		DeliveryConfig c = new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue().getConfig();
		assertNull(c.getRelayHost());
		assertNull(c.getRelayUser());
	}

	@Test
	public void aSmartHostPasswordMustBeAReference() throws Exception {
		MailStoreSetup.setUp(mail(), "mx.localhost", "localhost", "smartHost", "smtp.provider.example", "smartHost.password", "hunter2");
		UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> new SmtpServer(0, SmtpServer.SMTP_NAME, false).getQueue());
		assertTrue(e.getMessage().contains("smartHost.password"), e.getMessage());
	}

	@Test
	public void theServersTimesAreDurations() throws Exception {
		System.setProperty("parley.mail.smtp.timeout", "2m");
		System.setProperty("parley.mail.smtp.pregreet.delay", "3s");
		System.setProperty("parley.mail.smtp.spam.timeout", "750ms");
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		assertEquals(120_000, s.getTimeout());
		assertEquals(3_000, s.getConnectionChecks().getPregreetMillis());
		assertEquals(750, s.getSpam().getTimeoutMillis());
	}
}
