package us.bringardner.parley.net.server;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Maps command names (case-insensitive) to command objects. A subclass keeps its own static
 * registry, built with {@link #newRegistry()} and {@link #register(Map, ICommand)}, and passes it
 * to the constructor, so every instance of that subclass shares one set of commands.
 *
 * <PRE>
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
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
