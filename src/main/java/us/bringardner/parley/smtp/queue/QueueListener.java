package us.bringardner.parley.smtp.queue;

/**
 * Told about what happens to the messages in a {@link MailQueue} (see
 * {@link MailQueue#addQueueListener}). Called on the queue's own threads, sometimes while the
 * message's lock is held, so a listener must return quickly and never call back into the queue
 * for the same message. An exception thrown by a listener is logged and otherwise ignored.
 */
@FunctionalInterface
public interface QueueListener {

	void queueEvent(QueueEvent event);
}
