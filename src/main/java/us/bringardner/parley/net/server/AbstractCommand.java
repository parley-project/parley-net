package us.bringardner.parley.net.server;

import java.util.Locale;

/**
 * Base for the command classes of the line protocols (FTP, POP3, SMTP, IMAP): holds the
 * upper-cased command name and its help text.
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
