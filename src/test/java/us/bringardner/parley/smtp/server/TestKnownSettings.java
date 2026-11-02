package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.mail.server.MailServerProvider;
import us.bringardner.parley.net.server.KnownSettings;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerLauncher;
import us.bringardner.parley.net.server.ServerMain;

/**
 * To-Do 2.16: parley-smtp's list of settings (META-INF/parley/settings.list) has every name its code
 * spells out, and every name its servers read while they start and take a message, so a server's
 * start-up check never warns about a real setting. (The queue's own settings, in its
 * queue.properties, aren't server settings.)
 */
public class TestKnownSettings {

	@TempDir
	File dir;

	@Test
	public void everyConstantIsListed() throws Exception {
		assertEquals(List.of(), KnownSettings.load().undeclared(KnownSettings.settingConstants(SmtpServer.class)));
	}

	@Test
	public void everyNameTheServersReadIsListed() throws Exception {
		KnownSettings k = KnownSettings.load();
		assertTrue(k.prefixes().containsAll(List.of(SmtpServer.SMTP_PREFIX, SmtpServer.SUBMISSION_PREFIX, SmtpServer.SUBMISSIONS_PREFIX)),
				k.prefixes().toString());
		File mail = new File(dir, "mail");
		us.bringardner.parley.smtp.test.MailStoreSetup.setUp(FileSourceFactory.getDefaultFactory().createFileSource(mail.getPath()),
				"localhost", "localhost");
		File users = new File(dir, "users.txt");
		Files.write(users.toPath(), "tony , secret , READ|WRITE\n".getBytes(StandardCharsets.UTF_8));

		for (String id : List.of("smtp", "submission", "submissions")) {
			KnownSettings.RecordingProperties c = new KnownSettings.RecordingProperties();
			c.setProperty("parley.mail.root", mail.getPath());
			c.setProperty("parley.mail.users", users.getPath());
			MailServerProvider p = (MailServerProvider) ServerLauncher.providers().get(id);
			int port = freePort();
			c.setProperty(p.prefix() + ".port", "" + port);
			c.setProperty(p.prefix() + ".hostname", "localhost");
			p.enabled(c);
			p.unavailable(c);
			p.warnings(c);
			p.port(c);
			if (!p.implicitTls()) {
				ServerMain.Service s = p.create(new ServerContext(), c);
				s.startAndWait(5000);
				try {
					session(port, id.equals("smtp"));
				} finally {
					s.stop(5000);
				}
			}
			assertEquals(List.of(), k.undeclared(c.asked()), id + " read these");
		}
	}

	private static void session(int port, boolean send) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			String[][] dialog = send
					? new String[][] { { "EHLO client.example", "250" }, { "MAIL FROM:<someone@example.com>", "250" },
							{ "RCPT TO:<tony@localhost>", "250" }, { "DATA", "354" },
							{ "Subject: hi\r\nFrom: someone@example.com\r\nTo: tony@localhost\r\n\r\nHello\r\n.", "250" }, { "QUIT", "221" } }
					: new String[][] { { "EHLO client.example", "250" }, { "MAIL FROM:<tony@localhost>", "5" }, { "QUIT", "221" } };
			for (String[] step : dialog) {
				out.write((step[0] + "\r\n").getBytes(StandardCharsets.US_ASCII));
				String r = reply(in);
				assertTrue(r != null && r.startsWith(step[1]), step[0] + ": " + r);
			}
		}
	}

	/** The last line of a reply */
	private static String reply(BufferedReader in) throws Exception {
		String line;
		do {
			line = in.readLine();
		} while (line != null && line.length() > 3 && line.charAt(3) == '-');
		return line;
	}

	private static int freePort() throws Exception {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}
}
