package us.bringardner.parley.smtp.spf;

/** Ends a check with PERMERROR or TEMPERROR. */
final class SpfException extends Exception {

	private static final long serialVersionUID = 1L;

	final SpfResult.Result result;

	SpfException(SpfResult.Result result, String message) {
		super(message);
		this.result = result;
	}
}
