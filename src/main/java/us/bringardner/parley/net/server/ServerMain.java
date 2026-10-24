package us.bringardner.parley.net.server;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import us.bringardner.parley.plugin.PluginFolders;

/**
 * The {@code main} methods of the servers: run one or more servers as a service (systemd, launchd,
 * a Windows service) until the process is stopped.
 *
 * <pre>
 * public static void main(String[] args) throws Exception {
 *     ServerMain.run("Pop3Server", args, CONFIG_PROP, "parley-pop3.properties", () -&gt; {
 *         Pop3Server s = new Pop3Server(port(), POP3_NAME, secure());
 *         return List.of(ServerMain.service(s, "Pop3Server"));
 *     });
 * }
 * </pre>
 *
 * {@link #run} does what every server needs ({@link #service} adapts any {@link IBaseServer}):
 * <ol>
 * <li>Settings: the command line ({@code -Dname=value} or {@code name value}), and the settings
 * file named by the server's configFile property, else {@code CONF/parley-NAME.properties} when it
 * is there. CONF is the folder of Parley's administrator file: /etc/parley (Windows
 * %ProgramData%\Parley), or the folder of the file the PARLEY_CONF environment variable names. The
 * command line wins over the file.</li>
 * <li>The servers start, each waiting until it listens; if one can't start, those started are
 * stopped and the process exits with 1, so a service manager sees the failure.</li>
 * <li>Stopping the process (SIGTERM, a service stop) stops the servers; the process lives as long
 * as one of them runs.</li>
 * </ol>
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
public final class ServerMain {

	/** How long a server has to start listening */
	public static final long START_TIMEOUT = 60000;
	/** How long the servers have to stop when the process is stopped */
	public static final long STOP_TIMEOUT = 10000;

	/** A server {@link #run} starts and stops */
	public interface Service {
		/** for the messages, e.g. "Submission server" */
		String name();

		/** start, and return once it listens */
		void startAndWait(long timeoutMillis) throws IOException;

		/** the port it listens on, or 0 if it doesn't say */
		int port();

		/** stop, waiting up to timeoutMillis */
		void stop(long timeoutMillis) throws InterruptedException;

		/** wait until it has stopped */
		void awaitStop() throws InterruptedException;
	}

	/** Makes the servers, set up from the system properties {@link #run} has set */
	@FunctionalInterface
	public interface ServiceFactory {
		List<Service> create() throws Exception;
	}

	private ServerMain() {
	}

	/** Any Parley server: thread-per-connection (POP3, IMAP, SMTP, FTP ...) or non-blocking (SSH ...) */
	public static Service service(IBaseServer server, String name) {
		return new Service() {
			@Override
			public String name() {
				return name;
			}

			@Override
			public void startAndWait(long timeoutMillis) throws IOException {
				server.startAndWait(timeoutMillis);
			}

			@Override
			public int port() {
				return server.getLocalPort();
			}

			@Override
			public void stop(long timeoutMillis) throws InterruptedException {
				server.stop(timeoutMillis, false);
			}

			@Override
			public void awaitStop() throws InterruptedException {
				server.join(0);
			}
		};
	}

	/**
	 * Run the servers until the process is stopped (see the class description); exits the process
	 * with 1 when the settings can't be read or a server can't be made or started.
	 *
	 * @param serverName for the messages, e.g. Pop3Server
	 * @param configProperty the property that names the settings file, e.g. parley.mail.pop3.configFile
	 * @param defaultFileName the settings file's name in CONF, e.g. parley-pop3.properties (null: none)
	 */
	public static void run(String serverName, String[] args, String configProperty, String defaultFileName,
			ServiceFactory factory) throws InterruptedException {
		List<Service> services;
		try {
			configure(serverName, args, configProperty, defaultFileName);
			services = factory.create();
		} catch (Exception e) {
			failed(serverName, e);
			return;
		}
		List<Service> started = new ArrayList<Service>();
		for (Service s : services) {
			try {
				s.startAndWait(START_TIMEOUT);
				started.add(s);
				System.out.println(s.name()+" started on port "+s.port());
			} catch (IOException | RuntimeException e) {
				stopAll(started);
				failed(s.name(), e);
				return;
			}
		}
		Runtime.getRuntime().addShutdownHook(new Thread(() -> stopAll(started), serverName+"-shutdown"));
		// (the servers' threads may be daemons: the process lives as long as this waits)
		for (Service s : started) {
			s.awaitStop();
		}
	}

	private static void failed(String name, Exception e) {
		System.err.println(name+" not started: "+(e.getMessage() != null ? e.getMessage() : e.toString()));
		System.exit(1);
	}

	/** stop them, the last started first */
	private static void stopAll(List<Service> services) {
		List<Service> tmp = new ArrayList<Service>(services);
		Collections.reverse(tmp);
		for (Service s : tmp) {
			try {
				s.stop(STOP_TIMEOUT);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return;
			} catch (RuntimeException e) {
				System.err.println("Can't stop "+s.name()+": "+e);
			}
		}
	}

	/**
	 * The folder of Parley's administrator file: /etc/parley (Windows %ProgramData%\Parley), or
	 * the folder of the file the PARLEY_CONF environment variable names
	 */
	public static File confDir() {
		return confDir(System.getenv(), System.getProperty("os.name", "").toLowerCase().startsWith("windows"));
	}

	static File confDir(Map<String, String> env, boolean windows) {
		return PluginFolders.adminFile(env, windows).getAbsoluteFile().getParentFile();
	}

	/**
	 * Apply command line settings ({@code -Dname=value} or {@code name value}) as system properties,
	 * with no default settings file; see {@link #configure(String, String[], String, String)}.
	 */
	public static void configure(String serverName, String[] args, String configProperty) throws IOException {
		configure(serverName, args, configProperty, null, null);
	}

	/**
	 * Set the system properties: the settings file's, then the command line's ({@code -Dname=value}
	 * or {@code name value}), which win. The file is the one configProperty names (on the command
	 * line or as a system property), else CONF/defaultFileName when it is there ({@link #confDir()};
	 * configProperty is then set to it).
	 *
	 * @throws IOException if the file named can't be read
	 */
	public static void configure(String serverName, String[] args, String configProperty, String defaultFileName) throws IOException {
		configure(serverName, args, configProperty, defaultFileName, confDir());
	}

	static void configure(String serverName, String[] args, String configProperty, String defaultFileName, File confDir) throws IOException {
		System.out.println("\nStarting " + serverName + " with " + args.length + " args");
		Properties commandLine = new Properties();
		for (int idx = 0; idx < args.length; idx++) {
			if (args[idx].startsWith("-D")) {
				String[] tmp = args[idx].substring(2).split("=", 2);
				if (tmp.length == 2) {
					commandLine.setProperty(tmp[0], tmp[1]);
				} else {
					System.out.println("Invalid arg = " + args[idx]);
				}
			} else if (idx + 1 < args.length) {
				commandLine.setProperty(args[idx++], args[idx]);
			} else {
				System.out.println("Invalid arg = " + args[idx]);
			}
		}
		for (String name : commandLine.stringPropertyNames()) {
			System.out.println("\t" + name + "=" + commandLine.getProperty(name));
		}
		String file = commandLine.getProperty(configProperty, System.getProperty(configProperty));
		if (file == null && defaultFileName != null && confDir != null) {
			File f = new File(confDir, defaultFileName);
			if (f.isFile()) {
				file = f.getPath();
				System.setProperty(configProperty, file);
			}
		}
		if (file != null) {
			Properties fromFile = new Properties();
			try (InputStream in = Files.newInputStream(new File(file).toPath())) {
				fromFile.load(in);
			}
			System.getProperties().putAll(fromFile);
			System.out.println("Loaded properties from " + file);
		}
		// (the command line wins over the file)
		System.getProperties().putAll(commandLine);
	}
}
