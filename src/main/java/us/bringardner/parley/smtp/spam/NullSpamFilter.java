package us.bringardner.parley.smtp.spam;

import java.util.Map;

/** The filter that checks nothing: every message is clean with score 0. */
public final class NullSpamFilter implements SpamFilter {

	/** The id of this filter. */
	public static final String ID = "none";

	public static final class Factory implements SpamFilterFactory {
		@Override
		public String id() {
			return ID;
		}

		@Override
		public String label() {
			return "None (no checking)";
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			return new NullSpamFilter();
		}
	}

	@Override
	public String id() {
		return ID;
	}

	@Override
	public SpamVerdict check(SpamRequest request) {
		return SpamVerdict.clean();
	}
}
