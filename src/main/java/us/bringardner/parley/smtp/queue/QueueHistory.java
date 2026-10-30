package us.bringardner.parley.smtp.queue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/**
 * The history of a mail queue: every {@link QueueEvent} as a JSON line, one file per day
 * ({@code smtp-YYYY-MM-DD.jsonl}), files older than the days kept deleted. The queue forgets a
 * message once it's done; this is where a person (or an admin tool) looks afterwards.
 * <p>
 * A line has {@code time} (ms), {@code type}, {@code id}, {@code from}, then either
 * {@code recipients} (QUEUED, COMPLETED, DELETED) or {@code recipient}, {@code status},
 * {@code result}, {@code remoteMta} and {@code attempts} (and {@code nextAttempt} when deferred), then
 * {@code size}, {@code submitter} and {@code inbound}.
 * <p>
 * The folder is a FileSource, like the mail root it defaults to, so the history works on any
 * store. Each line is appended and the file closed again: servers in several processes sharing a
 * queue append to the same files, and a file can be read, moved or deleted at any time.
 *
 * @since 2.0.0
 */
public final class QueueHistory implements QueueListener {

	/** Queue setting ({@link MailQueue#SETTINGS_FILE}): writes the history (default true) */
	public static final String HISTORY_PROP = "history";
	/** Queue setting: the history's folder (default: .smtp-history in the mail root), on the mail root's file system */
	public static final String DIRECTORY_PROP = "historyDirectory";
	/** Queue setting: days of history kept (default 30; 0 keeps every day) */
	public static final String DAYS_PROP = "historyDays";
	/**
	 * Queue setting: the file system the history's folder is on (a FileSource type id, such as
	 * {@code FileProxy} for local disk). Default: the mail root's, so the history is wherever the mail
	 * is. A file system other than the mail root's needs {@link #DIRECTORY_PROP} too.
	 */
	public static final String FILE_SOURCE_PROP = "historyFileSource";
	/** The folder's name in the mail root */
	public static final String DEFAULT_DIRECTORY = ".smtp-history";
	public static final String PREFIX = "smtp-";
	public static final String SUFFIX = ".jsonl";

	private static final System.Logger LOG = System.getLogger(QueueHistory.class.getName());

	private final FileSource dir;
	private final int keepDays;
	private final ZoneId zone;
	private LocalDate prunedFor;

	public QueueHistory(FileSource dir, int keepDays) {
		this(dir, keepDays, ZoneId.systemDefault());
	}

	QueueHistory(FileSource dir, int keepDays, ZoneId zone) {
		this.dir = dir;
		this.keepDays = keepDays;
		this.zone = zone;
	}

	/**
	 * The history the queue's settings ask for, or null when it's turned off.
	 *
	 * @param mailRoot the mail root: the default folder is in it, and a folder the settings name is
	 *                 on its file system, unless they name another ({@link #FILE_SOURCE_PROP})
	 * @param queueSettings the queue's settings ({@link MailQueue#readSettings})
	 */
	public static QueueHistory fromSettings(FileSource mailRoot, java.util.Properties queueSettings) throws IOException {
		if (!Boolean.parseBoolean(queueSettings.getProperty(HISTORY_PROP, "true").trim())) {
			return null;
		}
		FileSource folder = folder(mailRoot, queueSettings.getProperty(FILE_SOURCE_PROP), queueSettings.getProperty(DIRECTORY_PROP));
		int days = 30;
		String n = queueSettings.getProperty(DAYS_PROP);
		if (n != null && !n.trim().isEmpty()) {
			try {
				days = Integer.parseInt(n.trim());
			} catch (NumberFormatException e) {
				throw new IOException("The mail queue's " + DAYS_PROP + "=" + n.trim() + " isn't a number of days", e);
			}
		}
		return new QueueHistory(folder, days);
	}

	/**
	 * The history's folder: {@code directory} on the file system {@code fileSource} names, else on the
	 * mail root's, else (no directory) {@link #DEFAULT_DIRECTORY} in the mail root. Used by the queue
	 * and by an application that reads the history, so both look in the same place.
	 *
	 * @param mailRoot the mail root
	 * @param fileSource a FileSource type id ({@link #FILE_SOURCE_PROP}), or null/blank for the mail root's
	 * @param directory the folder ({@link #DIRECTORY_PROP}), or null/blank for the default
	 * @throws IOException if the file system doesn't exist or can't be connected, or it isn't the mail
	 *                     root's and there's no directory (the default is in the mail root)
	 */
	public static FileSource folder(FileSource mailRoot, String fileSource, String directory) throws IOException {
		String type = fileSource == null ? "" : fileSource.trim();
		String d = directory == null ? "" : directory.trim();
		FileSourceFactory factory = mailRoot.getFileSourceFactory();
		if (!type.isEmpty() && !type.equalsIgnoreCase(factory.getTypeId())) {
			if (d.isEmpty()) {
				throw new IOException("The mail queue's " + FILE_SOURCE_PROP + "=" + type + " needs " + DIRECTORY_PROP
						+ ": the default folder is in the mail root, which is on " + factory.getTypeId());
			}
			factory = FileSourceFactory.getFileSourceFactory(type);
			if (factory == null) {
				throw new IOException("There is no file system " + type + " (the mail queue's " + FILE_SOURCE_PROP + ")");
			}
			if (!factory.isConnected() && !factory.connect()) {
				throw new IOException("Can't connect the file system " + type + " of the mail queue's history");
			}
		}
		return d.isEmpty() ? mailRoot.getChild(DEFAULT_DIRECTORY) : factory.createFileSource(d);
	}

	public FileSource getDirectory() {
		return dir;
	}

	/** The file of one day */
	public FileSource file(LocalDate day) throws IOException {
		return dir.getChild(PREFIX + day + SUFFIX);
	}

	@Override
	public void queueEvent(QueueEvent event) {
		try {
			append(event.getTime(), toJson(event));
		} catch (IOException | RuntimeException e) {
			LOG.log(System.Logger.Level.WARNING, "Can't record " + event + " in the queue history " + dir.getAbsolutePath(), e);
		}
	}

	private synchronized void append(long time, String json) throws IOException {
		LocalDate day = Instant.ofEpochMilli(time).atZone(zone).toLocalDate();
		if (!dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
			throw new IOException("Can't create " + dir.getAbsolutePath());
		}
		try (OutputStream out = file(day).getOutputStream(true)) {
			out.write((json + "\n").getBytes(StandardCharsets.UTF_8));
		}
		if (!day.equals(prunedFor)) {
			prunedFor = day;
			prune(day);
		}
	}

	/** Delete the files of days before those kept */
	int prune(LocalDate today) {
		if (keepDays <= 0) {
			return 0;
		}
		String oldest = PREFIX + today.minusDays(keepDays) + SUFFIX;
		int n = 0;
		try {
			FileSource[] files = dir.listFiles();
			for (FileSource f : files == null ? new FileSource[0] : files) {
				String name = f.getName();
				if (name.startsWith(PREFIX) && name.endsWith(SUFFIX) && name.length() == oldest.length() && name.compareTo(oldest) < 0) {
					if (f.delete()) {
						n++;
					} else {
						LOG.log(System.Logger.Level.WARNING, "Can't delete the old queue history " + f.getAbsolutePath());
					}
				}
			}
		} catch (IOException e) {
			LOG.log(System.Logger.Level.WARNING, "Can't list the queue history " + dir.getAbsolutePath(), e);
		}
		return n;
	}

	/** Nothing to close (each line is written and its file closed); kept for callers */
	public void close() {
	}

	/** An event as the JSON line written */
	public static String toJson(QueueEvent e) {
		StringBuilder b = new StringBuilder(256).append('{');
		field(b, "time", e.getTime());
		field(b, "type", e.getType().name());
		field(b, "id", e.getId());
		field(b, "from", e.getFrom());
		if (e.getRecipient() != null) {
			field(b, "recipient", e.getRecipient());
			field(b, "status", e.getStatus());
			field(b, "result", e.getResult());
			if (e.getRemoteMta() != null) {
				field(b, "remoteMta", e.getRemoteMta());
			}
			field(b, "attempts", e.getAttempts());
			if (e.getNextAttempt() > 0) {
				field(b, "nextAttempt", e.getNextAttempt());
			}
		} else {
			field(b, "recipients", e.getRecipients());
		}
		field(b, "size", e.getSize());
		if (e.getSubmitter() != null) {
			field(b, "submitter", e.getSubmitter());
		}
		field(b, "inbound", e.isInbound());
		return b.append('}').toString();
	}

	private static void field(StringBuilder b, String name, Object value) {
		if (b.length() > 1) {
			b.append(',');
		}
		string(b, name);
		b.append(':');
		if (value == null) {
			b.append("null");
		} else if (value instanceof Number || value instanceof Boolean) {
			b.append(value);
		} else if (value instanceof List) {
			b.append('[');
			boolean first = true;
			for (Object o : (List<?>) value) {
				if (!first) {
					b.append(',');
				}
				first = false;
				string(b, String.valueOf(o));
			}
			b.append(']');
		} else {
			string(b, value.toString());
		}
	}

	private static void string(StringBuilder b, String s) {
		b.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
			case '"':
				b.append("\\\"");
				break;
			case '\\':
				b.append("\\\\");
				break;
			case '\n':
				b.append("\\n");
				break;
			case '\r':
				b.append("\\r");
				break;
			case '\t':
				b.append("\\t");
				break;
			default:
				if (c < 0x20 || c == 0x2028 || c == 0x2029) {
					b.append(String.format("\\u%04x", (int) c));
				} else {
					b.append(c);
				}
			}
		}
		b.append('"');
	}
}
