package us.bringardner.parley.net.server;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Maps command names (case-insensitive) to command objects. A subclass keeps its own static
 * registry, built with {@link #newRegistry()} and {@link #register(Map, ICommand)}, and passes it
 * to the constructor, so every instance of that subclass shares one set of commands.
 */
public abstract class AbstractCommandFactory implements ICommandFactory {

	private static final long serialVersionUID = 1L;

	private final Map<String, ICommand> commands;

	protected AbstractCommandFactory(Map<String, ICommand> commands) {
		this.commands = commands;
	}

	/** A registry for a subclass to hold in a static field. */
	protected static Map<String, ICommand> newRegistry() {
		return Collections.synchronizedMap(new HashMap<>());
	}

	/** Add (or replace) a command in a registry. */
	protected static void register(Map<String, ICommand> registry, ICommand cmd) {
		registry.put(cmd.getName().toUpperCase(Locale.ROOT), cmd);
	}

	/** The command for the line's first token, or {@link #unknownCommand()} if there is none. */
	@Override
	public ICommand getCommand(IRequestContext context) {
		String name = context.getFirstToken();
		ICommand ret = name == null ? null : getCommand(name);
		return ret != null ? ret : unknownCommand();
	}

	public ICommand getCommand(String name) {
		return commands.get(name.toUpperCase(Locale.ROOT));
	}

	/** What to run for a name that isn't a command; null (the default) means none. */
	protected ICommand unknownCommand() {
		return null;
	}
}
