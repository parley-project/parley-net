package us.bringardner.parley.net.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Start-up helpers for the {@code main} methods of the servers. */
/**
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
public final class ServerMain {

	private ServerMain() {
	}

	/**
	 * Apply command line settings as system properties ({@code -Dname=value} or {@code name value}),
	 * then load the properties file named by the {@code configProperty} system property, if any.
	 */
	public static void configure(String serverName, String[] args, String configProperty) throws IOException {
		System.out.println("\nStarting " + serverName + " with " + args.length + " args");
		for (int idx = 0; idx < args.length; idx++) {
			if (args[idx].startsWith("-D")) {
				String[] tmp = args[idx].substring(2).split("=", 2);
				if (tmp.length == 2) {
					System.out.println("\t" + tmp[0] + "=" + tmp[1]);
					System.setProperty(tmp[0], tmp[1]);
				} else {
					System.out.println("Invalid arg = " + args[idx]);
				}
			} else if (idx + 1 < args.length) {
				System.out.println("\t" + args[idx] + "=" + args[idx + 1]);
				System.setProperty(args[idx++], args[idx]);
			}
		}
		String tmp = System.getProperty(configProperty);
		if (tmp != null) {
			System.out.println("Looking for " + tmp);
			Properties prop = System.getProperties();
			try (InputStream in = new FileInputStream(new File(tmp))) {
				prop.load(in);
			}
			System.out.println("Loaded properties from " + tmp);
		}
	}
}
