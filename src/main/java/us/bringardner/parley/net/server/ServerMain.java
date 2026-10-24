package us.bringardner.parley.net.server;

import java.io.File;
import java.io.IOException;
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
 * command line wins over the JVM's own {@code -D} options (java -Dname=value ...), which win over
 * the file. The file is UTF-8 (a file that isn't valid UTF-8 is read as ISO-8859-1, as
 * Properties.load reads it). Values whose names say password or secret are never printed.</li>
 * <li>The servers start, each waiting until it listens; if one can't start, those started are
 * stopped and the process exits with 1, so a service manager sees the failure.</li>
 * <li>Stopping the process (SIGTERM, a service stop) stops the servers; the process lives as long
 * as one of them runs. When the last one stops by itself (not because the process was stopped), the
 * process exits with 1, so a service manager can restart it.</li>
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

		/** the connections open now (0 if it doesn't say) */
		default int connections() {
			return 0;
		}

		/** the connections open now: who and from where (empty if it doesn't say) */
		default List<ParleyConnection> connectionList() {
			return Collections.emptyList();
		}
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

			@Override
			public int connections() {
				if (server instanceof IServer) {
					java.util.Map<?, ?> m = ((IServer) server).getActiveClients();
					return m == null ? 0 : m.size();
				}
				if (server instanceof us.bringardner.parley.net.nio.NioServer) {
					return ((us.bringardner.parley.net.nio.NioServer) server).getConnectionCount();
				}
				return 0;
			}

			@Override
			public List<ParleyConnection> connectionList() {
				List<ParleyConnection> ret = new ArrayList<ParleyConnection>();
				if (server instanceof IServer) {
					java.util.Map<java.net.Socket, us.bringardner.parley.net.IProcessor> m = ((IServer) server).getActiveClients();
					if (m != null) {
						for (java.util.Map.Entry<java.net.Socket, us.bringardner.parley.net.IProcessor> e : new java.util.LinkedHashMap<>(m).entrySet()) {
							java.net.Socket s = e.getKey();
							IPrincipal p = null;
							try {
								p = e.getValue() == null ? null : e.getValue().getPrincipal();
							} catch (RuntimeException ex) {
								// not known
							}
							ret.add(new ParleyConnection(address(s.getRemoteSocketAddress()), p == null ? null : p.getName(),
									s instanceof javax.net.ssl.SSLSocket));
						}
					}
				} else if (server instanceof us.bringardner.parley.net.nio.NioServer) {
					for (us.bringardner.parley.net.nio.INioConnection c : ((us.bringardner.parley.net.nio.NioServer) server).getConnections()) {
						IPrincipal p = c.getPrincipal();
						ret.add(new ParleyConnection(address(c.getRemoteAddress()), p == null ? null : p.getName(), c.isSecure()));
					}
				}
				return ret;
			}
		};
	}

	/** host:port of an address, without the leading / of an InetSocketAddress with no host name */
	static String address(java.net.SocketAddress a) {
		return a == null ? "" : a.toString().replaceFirst("^/", "");
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
		java.util.concurrent.atomic.AtomicBoolean stopping = new java.util.concurrent.atomic.AtomicBoolean();
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			stopping.set(true);
			stopAll(started);
		}, serverName+"-shutdown"));
		// (the servers' threads may be daemons: the process lives as long as this waits)
		for (Service s : started) {
			s.awaitStop();
		}
		if (!stopping.get()) {
			// every server stopped by itself: a failure the service manager should see (and may restart)
			System.err.println(serverName+" stopped: no server is running");
			System.exit(1);
		}
	}

	/** The launcher's own settings file in CONF: parley.servers and any other settings */
	public static final String LAUNCHER_FILE = "parley-servers.properties";
	/** names the launcher's settings file instead of CONF/parley-servers.properties */
	public static final String LAUNCHER_CONFIG_PROPERTY = "parley.servers.configFile";

	/**
	 * The generic launcher: runs the servers {@code parley.servers} lists (comma separated ids, e.g.
	 * {@code smtp,submission,imap,pop3}), set on the command line, with java -D, or in
	 * CONF/parley-servers.properties. See {@link #launch(String, String[], String...)}.
	 */
	public static void main(String[] args) throws InterruptedException {
		launch("Parley", args);
	}

	/**
	 * Run servers in this process until it is stopped, as a service or from a shell.
	 * <ol>
	 * <li>The servers are the {@link ServerProvider}s with these ids (none: those
	 * {@code parley.servers} lists); an unknown id is an error that lists the ids there are.</li>
	 * <li>Settings, a later one winning: the launcher's file when ids aren't given
	 * (CONF/parley-servers.properties, or the file {@code parley.servers.configFile} names), each
	 * server's shared files and its own file in CONF (or the file its configFile property names),
	 * the JVM's {@code -D} options, and the command line ({@code -Dname=value} or
	 * {@code name value}).</li>
	 * <li>Each server and the launcher can be managed with JMX ({@link ServerLauncher}). A server
	 * stopped with JMX doesn't end the process; the launcher's shutdown does (exit 0), as does
	 * stopping the process (SIGTERM, a service stop). When the last running server stops by itself
	 * the process exits with 1, so a service manager can restart it.</li>
	 * <li>The process exits with 1 if the settings can't be read or a server can't start.</li>
	 * </ol>
	 *
	 * @param processName for the messages and the launcher's JMX name, e.g. Pop3Server
	 */
	public static void launch(String processName, String[] args, String... ids) throws InterruptedException {
		ServerLauncher launcher;
		try {
			launcher = launcher(processName, args, confDir(), ids);
			launcher.getSettings().print(processName);
			launcher.init();
		} catch (Exception e) {
			failed(processName, e);
			return;
		}
		java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
		launcher.setOnFailure(id -> {
			if (!launcher.isAnyRunning()) {
				System.err.println(processName + " stopped: no server is running");
				exitLater(1);
			}
		});
		launcher.setOnShutdown(() -> exitLater(0));
		try {
			launcher.startAll();
		} catch (Exception e) {
			failed(processName, e);
			return;
		}
		boolean any = false;
		for (String id : launcher.getServers()) {
			ParleyServerMBean s = launcher.getServer(id);
			if (launcher.getState(id) == ServerLauncher.State.RUNNING) {
				any = true;
				System.out.println(s.getDescription() + " (" + id + ") started on port " + s.getPort());
			} else {
				System.out.println(s.getDescription() + " (" + id + ") is turned off by its settings");
			}
		}
		if (!any) {
			launcher.close();
			failed(processName, new IOException("Every server is turned off by its settings: nothing to run"));
			return;
		}
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			launcher.close();
			done.countDown();
		}, processName + "-shutdown"));
		// (the servers' threads may be daemons: the process lives as long as this waits)
		done.await();
	}

	/**
	 * A launcher for these servers, or (no ids) those parley.servers lists, with its settings
	 * files; not started.
	 */
	static ServerLauncher launcher(String processName, String[] args, File confDir, String... ids) throws IOException {
		LaunchSettings settings = new LaunchSettings(LaunchSettings.parse(args));
		List<String> list = new ArrayList<String>();
		for (String id : ids) {
			list.add(id);
		}
		if (list.isEmpty()) {
			String named = settings.early(LAUNCHER_CONFIG_PROPERTY);
			File file = named != null ? new File(named) : confDir == null ? null : new File(confDir, LAUNCHER_FILE);
			String servers = settings.early(ServerLauncher.SERVERS_PROPERTY);
			if (file != null) {
				settings.addFile(file, named != null);
				if (servers == null && file.isFile()) {
					servers = load(file).getProperty(ServerLauncher.SERVERS_PROPERTY);
				} else if (named != null && !file.isFile()) {
					throw new IOException("Can't read the settings file " + file);
				}
			}
			if (servers != null) {
				for (String id : servers.split("[,\\s]+")) {
					if (!id.isEmpty()) {
						list.add(id);
					}
				}
			}
			if (list.isEmpty()) {
				throw new IOException("No servers to run: set " + ServerLauncher.SERVERS_PROPERTY + " (one or more of "
						+ ServerLauncher.providers().keySet() + ")");
			}
		}
		return new ServerLauncher(processName, settings, list, confDir, new ServerContext());
	}

	/** exit from another thread, so a JMX call or a server's thread isn't held by the shutdown hook */
	private static void exitLater(int status) {
		Thread t = new Thread(() -> System.exit(status), "parley-exit");
		t.start();
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
	 * Set the system properties: the settings file's (except those already set, with java -D), then
	 * the command line's ({@code -Dname=value} or {@code name value}), which win. The file is the one configProperty names (on the command
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
			System.out.println("\t" + name + "=" + printable(name, commandLine.getProperty(name)));
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
			Properties fromFile = load(new File(file));
			for (String name : fromFile.stringPropertyNames()) {
				String jvm = System.getProperty(name);
				if (jvm == null) {
					System.setProperty(name, fromFile.getProperty(name));
				} else if (!jvm.equals(fromFile.getProperty(name))) {
					// set with java -Dname=value: that wins over the file
					System.out.println("\t" + name + "=" + printable(name, jvm) + " (the JVM's -D, not the file's)");
				}
			}
			System.out.println("Loaded properties from " + file);
		}
		// (the command line wins over the file and the JVM's -D)
		System.getProperties().putAll(commandLine);
	}

	/** A settings file: UTF-8, or ISO-8859-1 (what Properties.load reads) when it isn't valid UTF-8. */
	static Properties load(File f) throws IOException {
		byte[] bytes = Files.readAllBytes(f.toPath());
		String text;
		try {
			text = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
					.onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
					.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
		} catch (java.nio.charset.CharacterCodingException e) {
			text = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
		}
		if (text.startsWith("\uFEFF")) {
			text = text.substring(1);
		}
		Properties ret = new Properties();
		ret.load(new java.io.StringReader(text));
		return ret;
	}

	/** A value for the console: hidden when the name says it's a password or secret. */
	static String printable(String name, String value) {
		String n = name.toLowerCase(java.util.Locale.ROOT);
		boolean secret = n.contains("password") || n.contains("secret") || n.contains("passphrase") || n.endsWith("token");
		return secret ? "********" : value;
	}
}
