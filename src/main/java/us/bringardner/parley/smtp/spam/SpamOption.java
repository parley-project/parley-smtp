package us.bringardner.parley.smtp.spam;

/** A setting of a spam filter, described so the web administration can offer it. */
public final class SpamOption {

	/** How the value is edited. */
	public enum Type {
		TEXT, NUMBER, BOOLEAN, SECRET
	}

	private final String key;
	private final String label;
	private final Type type;
	private final String defaultValue;
	private final String description;

	public SpamOption(String key, String label, Type type, String defaultValue, String description) {
		this.key = key;
		this.label = label;
		this.type = type;
		this.defaultValue = defaultValue;
		this.description = description;
	}

	/** The setting's name after {@code spam.<id>.}. */
	public String getKey() {
		return key;
	}

	public String getLabel() {
		return label;
	}

	public Type getType() {
		return type;
	}

	/** The value used when it isn't set (as text), or null. */
	public String getDefaultValue() {
		return defaultValue;
	}

	public String getDescription() {
		return description;
	}
}
