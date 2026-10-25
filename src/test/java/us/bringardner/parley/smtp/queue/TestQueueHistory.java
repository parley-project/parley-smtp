package us.bringardner.parley.smtp.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.smtp.MailAddress;

/** QueueHistory: JSON lines, one file per day written a line at a time, old files deleted, the settings. */
public class TestQueueHistory {

	@TempDir
	File dir;

	@AfterEach
	public void clear() {
		System.clearProperty(QueueHistory.HISTORY_PROP);
		System.clearProperty(QueueHistory.DIRECTORY_PROP);
		System.clearProperty(QueueHistory.DAYS_PROP);
	}

	private FileSource fs(File f) throws Exception {
		return FileSourceFactory.getDefaultFactory().createFileSource(f.getPath());
	}

	private static QueueEntry entry(String id) throws Exception {
		QueueEntry e = new QueueEntry(id);
		e.setFrom(MailAddress.parse("josé@example.org", true));
		e.setSize(1234);
		e.addRecipient(new QueuedRecipient(MailAddress.parse("a@example.com", true), null, null));
		return e;
	}

	@Test
	public void escapes() throws Exception {
		QueueEntry e = entry("q1");
		QueuedRecipient r = e.getRecipients().get(0);
		r.status = QueuedRecipient.Status.FAILED;
		r.lastStatus = "5.1.1";
		r.lastResult = "550 \"no\" such\\user\r\n\ttab";
		String json = QueueHistory.toJson(QueueEvent.attempt(e, r));
		assertTrue(json.contains("\"from\":\"josé@example.org\""), json);
		assertTrue(json.contains("\"result\":\"550 \\\"no\\\" such\\\\user\\r\\n\\ttab\""), json);
	}

	@Test
	public void oneFilePerDayWrittenALineAtATimeAndOldOnesGo() throws Exception {
		File h = new File(dir, "history");
		LocalDate today = LocalDate.now(ZoneOffset.UTC);
		h.mkdirs();
		File old = new File(h, QueueHistory.PREFIX + today.minusDays(31) + QueueHistory.SUFFIX);
		File kept = new File(h, QueueHistory.PREFIX + today.minusDays(30) + QueueHistory.SUFFIX);
		File other = new File(h, "notes.txt");
		for (File f : Arrays.asList(old, kept, other)) {
			Files.write(f.toPath(), "x\n".getBytes(StandardCharsets.UTF_8));
		}
		QueueHistory history = new QueueHistory(fs(h), 30, ZoneOffset.UTC);
		QueueEntry e = entry("q2");
		history.queueEvent(QueueEvent.of(QueueEvent.Type.QUEUED, e));
		File day = new File(h, QueueHistory.PREFIX + today + QueueHistory.SUFFIX);
		assertTrue(day.delete(), "closed after each line: it can go at any time");
		history.queueEvent(QueueEvent.of(QueueEvent.Type.COMPLETED, e));
		List<String> lines = Files.readAllLines(day.toPath(), StandardCharsets.UTF_8);
		assertEquals(1, lines.size());
		assertTrue(lines.get(0).contains("\"COMPLETED\""));
		assertFalse(old.exists(), "older than 30 days");
		assertTrue(kept.exists());
		assertTrue(other.exists(), "not a history file");

		// another writer (another process) appends to the same file
		QueueHistory second = new QueueHistory(fs(h), 30, ZoneOffset.UTC);
		second.queueEvent(QueueEvent.of(QueueEvent.Type.DELETED, e));
		assertEquals(2, Files.readAllLines(day.toPath(), StandardCharsets.UTF_8).size());
	}

	@Test
	public void theSettings() throws Exception {
		File root = new File(dir, "mail");
		root.mkdirs();
		assertEquals(new File(root, QueueHistory.DEFAULT_DIRECTORY).getAbsolutePath(),
				QueueHistory.fromSettings(fs(root)).getDirectory().getAbsolutePath());
		System.setProperty(QueueHistory.DIRECTORY_PROP, new File(dir, "elsewhere").getPath());
		assertEquals(new File(dir, "elsewhere").getAbsolutePath(), QueueHistory.fromSettings(fs(root)).getDirectory().getAbsolutePath());
		System.setProperty(QueueHistory.HISTORY_PROP, "false");
		assertNull(QueueHistory.fromSettings(fs(root)));
	}
}
