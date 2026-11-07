package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static us.bringardner.parley.mail.test.MailTestSupport.ACL_FILE;
import static us.bringardner.parley.mail.test.MailTestSupport.deleteAll;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.ILogger.Level;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.smtp.server.SmtpServer;

/** The 421 a session gets when the server closes it on its own (parley-net's replyClosing). */
public class TestCloseReplies {

	@Test
	public void stoppingTheServerIs421ShuttingDown() throws Exception {
		System.setProperty("parley.mail.smtp." + FileUserRegistry.PROP_FILE_NAME, ACL_FILE);
		System.setProperty("parley.mail.smtp." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileUserRegistry.class.getName());
		FileSource root = FileSourceFactory.getDefaultFactory().createTempDirectory("ccClose");
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		try {
			s.setMaildropRoot(root);
			MailStoreSetup.setUp(root, "mx.c.test", "c.test");
			s.setHostname("mx.c.test");
			s.getLogger().setLevel(Level.ERROR);
			s.startAndWait(10000);
			try (TestSmtpServer.Client c = new TestSmtpServer.Client(s.getLocalPort())) {
				assertTrue(c.greeting.startsWith("220 "), c.greeting);
				s.stop();
				assertEquals("421 4.3.2 mx.c.test Service shutting down", c.line());
			}
		} finally {
			s.stop();
			deleteAll(root);
		}
	}
}
