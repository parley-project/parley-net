package us.bringardner.parley.net.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Start-up helpers for the {@code main} methods of the servers. */
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
