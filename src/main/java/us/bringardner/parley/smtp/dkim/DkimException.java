package us.bringardner.parley.smtp.dkim;

/** A signature that can't be verified, with the result it gets (RFC 6376 section 6.1). */
final class DkimException extends Exception {

	private static final long serialVersionUID = 1L;

	final DkimResult.Result result;

	DkimException(DkimResult.Result result, String message) {
		super(message);
		this.result = result;
	}

	static DkimException perm(String message) {
		return new DkimException(DkimResult.Result.PERMERROR, message);
	}

	static DkimException temp(String message) {
		return new DkimException(DkimResult.Result.TEMPERROR, message);
	}

	static DkimException fail(String message) {
		return new DkimException(DkimResult.Result.FAIL, message);
	}
}
