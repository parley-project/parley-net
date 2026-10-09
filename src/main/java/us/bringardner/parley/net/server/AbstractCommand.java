package us.bringardner.parley.net.server;

import java.util.Locale;

/**
 * Base for the command classes of the line protocols (FTP, POP3, SMTP, IMAP): holds the
 * upper-cased command name and its help text.
 */
public abstract class AbstractCommand implements ICommand {

	private static final long serialVersionUID = 1L;

	private String name;
	private String help;

	protected AbstractCommand(String command) {
		this.name = command.toUpperCase(Locale.ROOT);
		this.help = "No help available for " + name;
	}

	@Override
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String getHelp() {
		return help;
	}

	public void setHelp(String help) {
		this.help = help;
	}
}
