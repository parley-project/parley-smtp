package us.bringardner.parley.smtp.queue;

import java.io.IOException;
import java.util.List;

/**
 * A mail queue over JMX ({@code us.bringardner.parley:type=MailQueue,name=smtp}): the messages
 * waiting, and an administrator's actions on them. An application can use
 * {@code JMX.newMXBeanProxy(connection, name, MailQueueMXBean.class)}.
 *
 * @since 2.0.0
 */
public interface MailQueueMXBean {

	/** True while it delivers */
	boolean isRunning();

	/** How many messages it holds */
	int getMessageCount();

	/** The messages it holds, oldest first */
	List<QueuedMessageInfo> getMessages();

	/** One message, or null if it isn't in the queue */
	QueuedMessageInfo getMessage(String id);

	/**
	 * The start of a message's content (RFC 5322, read as UTF-8), at most maxBytes, or null if it
	 * isn't in the queue
	 */
	String readContent(String id, int maxBytes) throws IOException;

	/** Try every pending message now */
	void flush();

	/** Try one message's pending recipients now; false if it isn't in the queue */
	boolean retry(String id);

	/** Remove a message without delivering it or telling the sender; false if it isn't there or is being delivered */
	boolean delete(String id) throws IOException;

	/**
	 * Read the queue's domains, aliases file and DKIM keys again and use them from now on (no restart);
	 * nothing changes if any of them can't be read. Call it after changing them.
	 *
	 * @return what is used now, in a line
	 * @since 2.0.0
	 */
	String reload() throws IOException;

	/** The folder of the queue's history ({@link QueueHistory}), or null if it keeps none */
	String getHistoryDirectory();
}
