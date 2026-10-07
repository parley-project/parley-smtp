package us.bringardner.parley.smtp;

/**
 * SMTP protocol constants: RFC 5321 (and its revision, draft-ietf-emailcore-rfc5321bis),
 * with the service extensions this server implements.
 */
public interface SMTP {

	/** Relay between servers (RFC 5321). */
	int SMTP_PORT = 25;
	/** Message submission (RFC 6409). */
	int SUBMISSION_PORT = 587;
	/** Message submission over implicit TLS (RFC 8314). */
	int SUBMISSIONS_PORT = 465;

	// reply codes (RFC 5321 section 4.2.3)
	int SYSTEM_STATUS = 211;
	int HELP_MESSAGE = 214;
	int SERVICE_READY = 220;
	int SERVICE_CLOSING = 221;
	int AUTH_SUCCEEDED = 235;
	int OK = 250;
	int CANNOT_VRFY = 252;
	int AUTH_CONTINUE = 334;
	int START_MAIL_INPUT = 354;
	int SERVICE_NOT_AVAILABLE = 421;
	int MAILBOX_BUSY = 450;
	int LOCAL_ERROR = 451;
	int INSUFFICIENT_STORAGE = 452;
	int TEMP_AUTH_FAILURE = 454;
	int SYNTAX_ERROR = 500;
	int PARAMETER_ERROR = 501;
	int NOT_IMPLEMENTED = 502;
	int BAD_SEQUENCE = 503;
	int PARAMETER_NOT_IMPLEMENTED = 504;
	int AUTH_REQUIRED = 530;
	int AUTH_FAILED = 535;
	int ENCRYPTION_REQUIRED = 538;
	int MAILBOX_UNAVAILABLE = 550;
	int USER_NOT_LOCAL = 551;
	int EXCEEDED_STORAGE = 552;
	int MAILBOX_NAME_NOT_ALLOWED = 553;
	int TRANSACTION_FAILED = 554;
	int PARAMETERS_NOT_RECOGNIZED = 555;

	// service extensions
	String EXT_8BITMIME = "8BITMIME";
	String EXT_SMTPUTF8 = "SMTPUTF8";
	String EXT_SIZE = "SIZE";
	String EXT_PIPELINING = "PIPELINING";
	String EXT_ENHANCEDSTATUSCODES = "ENHANCEDSTATUSCODES";
	String EXT_CHUNKING = "CHUNKING";
	String EXT_BINARYMIME = "BINARYMIME";
	String EXT_DSN = "DSN";
	String EXT_STARTTLS = "STARTTLS";
	String EXT_AUTH = "AUTH";
}
