package us.bringardner.parley.smtp.test;

import java.io.IOException;
import java.util.Properties;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.mail.store.MailLocks;
import us.bringardner.parley.net.lock.Sharing;
import us.bringardner.parley.smtp.queue.MailQueue;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * What an administrator does once for a new mail store, for the tests: the store's settings
 * (servers in one JVM share it, as two processes on a host would: sharing=host) and the default
 * queue's settings (hostname, domains).
 */
public final class MailStoreSetup {

	private MailStoreSetup() {
	}

	/** The store's settings and the default queue's, with this hostname and these domains (comma separated) */
	public static void setUp(FileSource root, String hostname, String domains, String... queueSettings) throws IOException {
		MailLocks.writeStoreSettings(root, Sharing.HOST);
		Properties q = new Properties();
		q.setProperty("hostname", hostname);
		q.setProperty("domains", domains);
		for (int i = 0; i + 1 < queueSettings.length; i += 2) {
			q.setProperty(queueSettings[i], queueSettings[i + 1]);
		}
		MailQueue.writeSettings(root.getChild(SmtpServer.QUEUE_DIRECTORY), q);
	}
}
