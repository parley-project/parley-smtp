package us.bringardner.parley.smtp.abuse;

import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts events per key (a client address) in a sliding window and says when a key is over a limit.
 * A key is forgotten once its window is empty, so an idle address costs nothing.
 */
public final class RateLimiter {

	private final long windowMillis;
	private final Map<String, ArrayDeque<Long>> events = new ConcurrentHashMap<>();
	private long lastSweep = System.currentTimeMillis();

	public RateLimiter(long windowMillis) {
		this.windowMillis = windowMillis;
	}

	/**
	 * Record one event for the key.
	 *
	 * @param limit the most events allowed in the window (0 or less: no limit)
	 * @return false if the event is over the limit (it is not counted then)
	 */
	public boolean tryAcquire(String key, int limit) {
		return tryAcquire(key, limit, System.currentTimeMillis());
	}

	/** As {@link #tryAcquire(String, int)} at a given time (milliseconds), for tests. */
	public boolean tryAcquire(String key, int limit, long now) {
		if (limit <= 0) {
			return true;
		}
		sweep(now);
		ArrayDeque<Long> q = events.computeIfAbsent(key, k -> new ArrayDeque<>());
		synchronized (q) {
			while (!q.isEmpty() && q.peekFirst() <= now - windowMillis) {
				q.removeFirst();
			}
			if (q.size() >= limit) {
				return false;
			}
			q.addLast(now);
			return true;
		}
	}

	/** Forget every count. */
	public void clear() {
		events.clear();
	}

	private synchronized void sweep(long now) {
		if (now - lastSweep < windowMillis) {
			return;
		}
		lastSweep = now;
		events.entrySet().removeIf(e -> {
			ArrayDeque<Long> q = e.getValue();
			synchronized (q) {
				return q.isEmpty() || q.peekLast() <= now - windowMillis;
			}
		});
	}
}
