package us.bringardner.parley.smtp.spam;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** What a provider says about its scanner when asked ({@link SpamFilter#status}): reachable or not, and its details. */
public final class SpamStatus {

	private final boolean available;
	private final String version;
	private final String message;
	private final Map<String, String> details;

	public SpamStatus(boolean available, String version, String message, Map<String, String> details) {
		this.available = available;
		this.version = version == null ? "" : version;
		this.message = message == null ? "" : message;
		this.details = details == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(details));
	}

	public static SpamStatus up(String version, String message) {
		return new SpamStatus(true, version, message, null);
	}

	public static SpamStatus down(String message) {
		return new SpamStatus(false, null, message, null);
	}

	/** True if the scanner answered. */
	public boolean isAvailable() {
		return available;
	}

	/** The scanner's version, or "". */
	public String getVersion() {
		return version;
	}

	/** A sentence for people: what was found, or why the scanner can't be used. */
	public String getMessage() {
		return message;
	}

	/** Anything else the scanner reported (name to value). */
	public Map<String, String> getDetails() {
		return details;
	}

	@Override
	public String toString() {
		return (available ? "up" : "down") + (version.isEmpty() ? "" : " " + version) + (message.isEmpty() ? "" : ": " + message);
	}
}
