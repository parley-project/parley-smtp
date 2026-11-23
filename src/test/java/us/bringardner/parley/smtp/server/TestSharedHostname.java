/**
 * <PRE>
 *
 * Copyright Tony Bringarder 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 */
package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.smtp.test.MailStoreSetup;

/**
 * The relay and the submission servers share the {@code hostname}: a submission server's own value
 * wins, otherwise it takes the relay's.
 */
public class TestSharedHostname {

	private static final String[] CLEARED = { "parley.mail.root", "parley.mail.smtp.hostname",
			"parley.mail.submission.hostname", "parley.mail.submissions.hostname" };

	@TempDir
	File dir;

	private final Map<String, String> saved = new HashMap<>();

	@BeforeEach
	public void setUp() throws IOException {
		for (String n : CLEARED) {
			saved.put(n, System.getProperty(n));
			System.clearProperty(n);
		}
		System.setProperty("parley.mail.root", new File(dir, "mail").getPath());
		FileSource mail = FileSourceFactory.getDefaultFactory().createFileSource(new File(dir, "mail").getPath());
		MailStoreSetup.setUp(mail, "mx.localhost", "localhost");
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

	@Test
	public void submissionServersTakeTheRelaysHostname() {
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		assertEquals("mx2.example.test", new SmtpServer(0, "t", false, false).getHostname());
		assertEquals("mx2.example.test", new SmtpServer(0, "t", false, true).getHostname());
		assertEquals("mx2.example.test", new SmtpServer(0, "t", true, true).getHostname());
	}

	@Test
	public void aSubmissionServersOwnHostnameWins() {
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		System.setProperty("parley.mail.submissions.hostname", "sub.example.test");
		assertEquals("mx2.example.test", new SmtpServer(0, "t", false, false).getHostname());
		assertEquals("mx2.example.test", new SmtpServer(0, "t", false, true).getHostname());
		assertEquals("sub.example.test", new SmtpServer(0, "t", true, true).getHostname());
	}

	@Test
	public void theRelayNeverTakesASubmissionHostname() {
		System.setProperty("parley.mail.submission.hostname", "sub.example.test");
		assertNull(new SmtpServer(0, "t", false, false).getHostname());
	}

	@Test
	public void switchingARelayToSubmissionKeepsTheSharedHostname() {
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		SmtpServer s = new SmtpServer(0, "t", false, false);
		s.setSubmission(true);
		assertEquals("mx2.example.test", s.getHostname());
		System.setProperty("parley.mail.submission.hostname", "sub.example.test");
		s.setSubmission(false);
		s.setSubmission(true);
		assertEquals("sub.example.test", s.getHostname());
	}

	@Test
	public void theQueuesHostnameIsNotRead() throws Exception {
		// MailStoreSetup gave the queue "mx.localhost"
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		SmtpServer s = new SmtpServer(0, "t", false, false);
		assertEquals("mx2.example.test", s.getQueue().getConfig().getHostname());
	}

	@Test
	public void aQueueWithoutAHostnameIsFine() throws Exception {
		FileSource mail = FileSourceFactory.getDefaultFactory().createFileSource(new File(dir, "mail").getPath());
		java.util.Properties q = new java.util.Properties();
		q.setProperty("domains", "localhost");
		us.bringardner.parley.smtp.queue.MailQueue.writeSettings(mail.getChild(SmtpServer.QUEUE_DIRECTORY), q);
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		SmtpServer s = new SmtpServer(0, "t", false, false);
		assertEquals("mx2.example.test", s.getQueue().getConfig().getHostname());
	}

	@Test
	public void setHostnameChangesWhatTheQueueSays() {
		System.setProperty("parley.mail.smtp.hostname", "mx2.example.test");
		SmtpServer s = new SmtpServer(0, "t", false, false);
		s.setHostname("other.example.test");
		assertEquals("other.example.test", s.getQueue().getConfig().getHostname());
	}
}
