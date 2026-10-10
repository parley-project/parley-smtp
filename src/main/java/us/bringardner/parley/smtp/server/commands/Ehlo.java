package us.bringardner.parley.smtp.server.commands;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import us.bringardner.parley.net.capability.CapabilityRegistry;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.server.SmtpRequestProcessor;

/** EHLO domain (RFC 5321 section 4.1.1.1): start an ESMTP session and list the extensions. */
public class Ehlo extends BaseCommand {

	private static final long serialVersionUID = 1L;

	public Ehlo() {
		super("EHLO");
	}

	protected Ehlo(String name) {
		super(name);
	}

	/**
	 * The extensions this server offers and when (RFC 1869): STARTTLS only before TLS, AUTH only
	 * until the user has authenticated and not while TLS must come first.
	 */
	private static final CapabilityRegistry EXTENSIONS = new CapabilityRegistry()
			.add(EXT_PIPELINING)
			.addDynamic(EXT_SIZE, p -> Collections.singletonList(
					String.valueOf(((SmtpRequestProcessor) p).getSmtpServer().getMaxMessageSize())))
			.add(EXT_8BITMIME)
			.add(EXT_SMTPUTF8)
			.add(EXT_ENHANCEDSTATUSCODES)
			.add(EXT_CHUNKING)
			.add(EXT_BINARYMIME)
			.add(EXT_DSN)
			.addWhen(p -> {
				SmtpRequestProcessor sp = (SmtpRequestProcessor) p;
				return !sp.isTls() && sp.getSmtpServer().isTlsAvailable();
			}, EXT_STARTTLS)
			.addDynamicRequireParams(EXT_AUTH, p -> {
				SmtpRequestProcessor sp = (SmtpRequestProcessor) p;
				boolean open = !sp.isAuthenticated() && (sp.isTls() || !sp.getSmtpServer().isRequireTls());
				return open ? Auth.mechanisms(sp) : null;
			})
			.add("HELP");

	/** True for a domain or address literal (lenient: any non-empty name without spaces is accepted). */
	static boolean validName(String name) {
		return !name.isEmpty() && name.indexOf(' ') < 0
				&& (MailAddress.isDomain(name) || MailAddress.isAddressLiteral(name) || name.matches("[\\x21-\\x7e]+"));
	}

	@Override
	public void execute(SmtpRequestProcessor p, String args) throws IOException {
		String name = args.trim();
		if (!validName(name)) {
			p.error(PARAMETER_ERROR, "5.5.4", "Syntax: " + getName() + " hostname");
			return;
		}
		p.hello(name, true);
		List<String> lines = new ArrayList<>();
		lines.add(p.getSmtpServer().getHostname() + " Hello " + name + " [" + p.getClientAddress().getHostAddress() + "]");
		lines.addAll(EXTENSIONS.resolve(p).toLines());
		p.reply(OK, lines);
	}
}
