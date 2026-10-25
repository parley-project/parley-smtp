package us.bringardner.parley.smtp.queue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import us.bringardner.parley.files.FileSource;

/**
 * {@link MailQueueMXBean} for a queue.
 *
 * @since 2.0.0
 */
public final class MailQueueBean implements MailQueueMXBean {

	/** Most of a message {@link #readContent} returns */
	public static final int MAX_CONTENT = 1024 * 1024;

	private final MailQueue queue;
	private final QueueHistory history;

	/** @param history the queue's history, or null */
	public MailQueueBean(MailQueue queue, QueueHistory history) {
		this.queue = queue;
		this.history = history;
	}

	@Override
	public boolean isRunning() {
		return queue.isRunning();
	}

	@Override
	public int getMessageCount() {
		return queue.getEntries().size();
	}

	@Override
	public List<QueuedMessageInfo> getMessages() {
		List<QueuedMessageInfo> list = new ArrayList<>();
		for (QueueEntry e : queue.getEntries()) {
			list.add(QueuedMessageInfo.of(e));
		}
		list.sort(Comparator.comparingLong(QueuedMessageInfo::getCreated));
		return list;
	}

	@Override
	public QueuedMessageInfo getMessage(String id) {
		QueueEntry e = queue.getEntry(id);
		return e == null ? null : QueuedMessageInfo.of(e);
	}

	@Override
	public String readContent(String id, int maxBytes) throws IOException {
		FileSource f = queue.getContent(id);
		if (f == null) {
			return null;
		}
		int max = Math.max(0, Math.min(maxBytes, MAX_CONTENT));
		try (InputStream in = f.getInputStream()) {
			byte[] b = in.readNBytes(max);
			return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPLACE)
					.onUnmappableCharacter(CodingErrorAction.REPLACE).decode(ByteBuffer.wrap(b)).toString();
		}
	}

	@Override
	public void flush() {
		queue.flush();
	}

	@Override
	public boolean retry(String id) {
		return queue.retry(id);
	}

	@Override
	public boolean delete(String id) throws IOException {
		return queue.delete(id);
	}

	@Override
	public String getHistoryDirectory() {
		return history == null ? null : history.getDirectory().getAbsolutePath();
	}
}
