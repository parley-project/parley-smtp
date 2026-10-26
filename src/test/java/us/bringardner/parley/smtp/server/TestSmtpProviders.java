package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.server.LaunchSettings;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerLauncher;
import us.bringardner.parley.smtp.queue.MailQueueMXBean;
import us.bringardner.parley.smtp.queue.QueueHistory;

/**
 * The SMTP providers: the relay and submission servers, each from its own configuration, using the
 * queue their settings name, each queue's JMX bean, its history, and what a server needs to start.
 */
public class TestSmtpProviders {

	private static final String[] CLEARED = { "parley.mail.smtp.port", "parley.mail.submission.port", "parley.mail.submissions.port",
			"parley.mail.smtp.secure", "parley.mail.users", "parley.mail.root", "parley.mail.smtp.domains", "parley.mail.smtp.hostname",
			"parley.mail.smtp.authenticationProvider", "parley.mail.smtp.userFile", "parley.mail.submission.authenticationProvider",
			"parley.mail.submission.userFile", QueueHistory.HISTORY_PROP, QueueHistory.DIRECTORY_PROP };

	@TempDir
	File dir;

	private final Map<String, String> saved = new HashMap<>();
	private ServerLauncher launcher;

	@BeforeEach
	public void clear() {
		for (String n : CLEARED) {
			saved.put(n, System.getProperty(n));
			System.clearProperty(n);
		}
	}

	@AfterEach
	public void restore() {
		if (launcher != null) {
			launcher.close();
		}
		for (String n : CLEARED) {
			System.clearProperty(n);
			if (saved.get(n) != null) {
				System.setProperty(n, saved.get(n));
			}
		}
	}

	private static int freePort() throws Exception {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}

	private void write(String name, String... lines) throws Exception {
		// (a .properties file reads \ as an escape: the paths in it have / on Windows)
		Files.write(new File(dir, name).toPath(), (String.join("\n", lines).replace('\\', '/') + "\n").getBytes(StandardCharsets.UTF_8));
	}

	private static String reply(BufferedReader in) throws IOException {
		String line;
		do {
			line = in.readLine();
		} while (line != null && line.length() > 3 && line.charAt(3) == '-');
		return line;
	}

	private static void send(int port) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			String[][] dialog = { { "EHLO client.example", "250" }, { "MAIL FROM:<someone@example.com>", "250" },
					{ "RCPT TO:<tony@localhost>", "250" }, { "DATA", "354" },
					{ "Subject: hi\r\nFrom: someone@example.com\r\nTo: tony@localhost\r\n\r\nHello\r\n.", "250" }, { "QUIT", "221" } };
			for (String[] step : dialog) {
				out.write((step[0] + "\r\n").getBytes(StandardCharsets.US_ASCII));
				String r = reply(in);
				assertTrue(r != null && r.startsWith(step[1]), step[0] + ": " + r);
			}
		}
	}

	@Test
	public void providersFound() {
		assertTrue(ServerLauncher.providers().keySet().containsAll(Arrays.asList("smtp", "submission", "submissions")));
	}

	private static us.bringardner.parley.files.FileSource fs(File f) throws java.io.IOException {
		return us.bringardner.parley.files.FileSourceFactory.getDefaultFactory().createFileSource(f.getPath());
	}

	/**
	 * The relay and submission servers, each from its own configuration, given the same queue: each
	 * opens it (as servers in two processes would) and its queue is a JMX bean named after it.
	 */
	@Test
	public void relayAndSubmissionUseTheQueueTheirSettingsName() throws Exception {
		int smtp = freePort();
		int submission = freePort();
		File mail = new File(dir, "mail");
		us.bringardner.parley.smtp.test.MailStoreSetup.setUp(fs(mail), "localhost", "localhost"); // the administrator
		write("users.txt", "tony , secret , READ|WRITE");
		write("parley-mail.properties", "parley.mail.root=" + mail.getPath(), "parley.mail.users=" + new File(dir, "users.txt").getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + smtp, "parley.mail.submission.port=" + submission,
				"parley.mail.smtp.hostname=mx.localhost", "parley.mail.submission.hostname=submit.localhost");
		ServerContext context = new ServerContext();
		launcher = new ServerLauncher("SmtpTest", new LaunchSettings(new Properties()), Arrays.asList("smtp", "submission", "submissions"), dir,
				context);
		launcher.init();
		assertEquals(ServerLauncher.State.OFF, launcher.getState("submissions"));
		launcher.startAll();
		assertEquals(ServerLauncher.State.RUNNING, launcher.getState("smtp"));
		assertEquals(ServerLauncher.State.RUNNING, launcher.getState("submission"));

		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		ObjectName name = new ObjectName("us.bringardner.parley:type=MailQueue,name=smtp");
		ObjectName subName = new ObjectName("us.bringardner.parley:type=MailQueue,name=submission");
		assertTrue(mbs.isRegistered(name));
		assertTrue(mbs.isRegistered(subName));
		MailQueueMXBean q = JMX.newMXBeanProxy(mbs, name, MailQueueMXBean.class);
		assertTrue(q.isRunning());
		assertEquals(new File(mail, QueueHistory.DEFAULT_DIRECTORY).getAbsolutePath(), q.getHistoryDirectory());

		// each server's own hostname
		try (Socket s = new Socket("127.0.0.1", smtp)) {
			assertTrue(new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine().contains("mx.localhost"));
		}
		try (Socket s = new Socket("127.0.0.1", submission)) {
			assertTrue(new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine().contains("submit.localhost"));
		}

		send(smtp);
		File history = new File(q.getHistoryDirectory(), QueueHistory.PREFIX + LocalDate.now() + QueueHistory.SUFFIX);
		String text = "";
		for (int i = 0; i < 100 && !text.contains("\"DELIVERED\""); i++) {
			Thread.sleep(100);
			text = history.isFile() ? new String(Files.readAllBytes(history.toPath()), StandardCharsets.UTF_8) : "";
		}
		assertTrue(text.contains("\"type\":\"QUEUED\"") && text.contains("\"recipient\":\"tony@localhost\""), text);
		assertTrue(text.contains("\"type\":\"DELIVERED\""), text);

		// the open connections
		try (Socket open = new Socket("127.0.0.1", submission)) {
			new BufferedReader(new InputStreamReader(open.getInputStream(), StandardCharsets.US_ASCII)).readLine(); // the greeting
			us.bringardner.parley.net.server.ParleyConnection[] list = launcher.getServer("submission").getConnectionList();
			assertEquals(1, list.length);
			assertTrue(list[0].getRemote().startsWith("127.0.0.1:"), list[0].getRemote());
			assertEquals(null, list[0].getUser(), "not logged in");
			assertFalse(list[0].isSecure());
		}

		// each server's queue goes with it
		launcher.restart("submission");
		assertTrue(mbs.isRegistered(name));
		assertTrue(mbs.isRegistered(subName));
		launcher.stop("submission");
		assertFalse(mbs.isRegistered(subName));
		assertTrue(mbs.isRegistered(name), "the relay still runs");
		launcher.stop("smtp");
		assertFalse(mbs.isRegistered(name));
	}

	/** A queue without settings isn't used: the server doesn't start. */
	@Test
	public void aQueueWithoutSettingsIsRefused() throws Exception {
		File mail = new File(dir, "mail");
		us.bringardner.parley.mail.store.MailLocks.writeStoreSettings(fs(mail), us.bringardner.parley.net.lock.Sharing.HOST);
		write("parley-mail.properties", "parley.mail.root=" + mail.getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + freePort(), "parley.mail.smtp.hostname=mx.localhost");
		launcher = new ServerLauncher("SmtpNoQueue", new LaunchSettings(new Properties()), Arrays.asList("smtp"), dir,
				new ServerContext(javax.management.MBeanServerFactory.newMBeanServer()));
		launcher.init();
		java.io.IOException e = org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class, () -> launcher.startAll());
		assertTrue(e.getMessage().contains(us.bringardner.parley.smtp.queue.MailQueue.SETTINGS_FILE), e.getMessage());
	}

	/** No hostname: no default from the machine's name, the server doesn't start. */
	@Test
	public void aServerWithoutAHostnameIsRefused() throws Exception {
		File mail = new File(dir, "mail");
		us.bringardner.parley.smtp.test.MailStoreSetup.setUp(fs(mail), "localhost", "localhost");
		write("parley-mail.properties", "parley.mail.root=" + mail.getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + freePort());
		launcher = new ServerLauncher("SmtpNoHost", new LaunchSettings(new Properties()), Arrays.asList("smtp"), dir,
				new ServerContext(javax.management.MBeanServerFactory.newMBeanServer()));
		launcher.init();
		Exception e = org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> launcher.startAll());
		assertTrue(e.getMessage().contains("parley.mail.smtp.hostname"), e.getMessage());
	}

	/** AUTH PLAIN on a server; the reply's code */
	private static String auth(int port, String user, String password) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			s.setSoTimeout(20000);
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			out.write("EHLO client.example\r\n".getBytes(StandardCharsets.US_ASCII));
			assertTrue(reply(in).startsWith("250"));
			String token = java.util.Base64.getEncoder().encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
			out.write(("AUTH PLAIN " + token + "\r\n").getBytes(StandardCharsets.US_ASCII));
			String r = reply(in);
			return r.substring(0, 3);
		}
	}

	@Test
	public void aSubmissionServerWithItsOwnUsersKeepsThem() throws Exception {
		int smtp = freePort();
		int submission = freePort();
		write("users.txt", "tony , secret , READ|WRITE");
		write("own.txt", "jose , other , READ|WRITE");
		us.bringardner.parley.smtp.test.MailStoreSetup.setUp(fs(new File(dir, "mail")), "localhost", "localhost");
		write("parley-mail.properties", "parley.mail.root=" + new File(dir, "mail").getPath(), "parley.mail.users=" + new File(dir, "users.txt").getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + smtp, "parley.mail.submission.port=" + submission,
				"parley.mail.smtp.hostname=localhost", "parley.mail.submission.hostname=localhost",
				"parley.mail.submission.authenticationProvider=us.bringardner.parley.net.server.FileBasedAcl",
				"parley.mail.submission.userFile=" + new File(dir, "own.txt").getPath());
		ServerContext context = new ServerContext(javax.management.MBeanServerFactory.newMBeanServer());
		launcher = new ServerLauncher("SmtpUsersTest", new LaunchSettings(new Properties()), Arrays.asList("smtp", "submission"), dir, context);
		launcher.init();
		launcher.startAll();
		assertEquals("235", auth(submission, "jose", "other"), "its own users");
		assertEquals("535", auth(submission, "tony", "secret"), "not the shared users");
		assertEquals("235", auth(smtp, "tony", "secret"), "the relay has the shared users");
		assertNotNull(us.bringardner.parley.mail.server.AbstractMailServer.sharedUsers(context, new File(dir, "users.txt")));
	}

	@Test
	public void legacySecureRelay() {
		Properties c = new Properties();
		c.setProperty("parley.mail.smtp.secure", "true");
		c.setProperty("parley.mail.smtps.port", "0");
		assertFalse(ServerLauncher.providers().get("smtp").enabled(c), "the relay's port is parley.mail.smtps.port then");
		assertTrue(ServerLauncher.providers().get("smtp").enabled(new Properties()));
	}
}
