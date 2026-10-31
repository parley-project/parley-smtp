package us.bringardner.parley.smtp.spam;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** The filter that checks nothing: every message is clean with score 0. */
public final class NullSpamFilter implements SpamFilter {

	/** The id of this filter. */
	public static final String ID = "none";

	/** The provider of this filter, listed in META-INF/services. */
	public static final class Provider implements SpamProvider {
		@Override
		public String getId() {
			return ID;
		}

		@Override
		public String getTitle() {
			return "None (no checking)";
		}

		@Override
		public String getDescription() {
			return "Checks nothing: every message is clean. Choose it to turn spam checking off for a domain or for all.";
		}

		@Override
		public Set<Feature> getFeatures() {
			return EnumSet.of(Feature.CHECK, Feature.STATUS);
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

	@Override
	public SpamStatus status() {
		return SpamStatus.up(null, "Nothing to check: always available");
	}
}
