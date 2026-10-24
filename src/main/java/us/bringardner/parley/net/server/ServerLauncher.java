package us.bringardner.parley.net.server;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

import javax.management.ObjectName;

import us.bringardner.parley.plugin.Plugins;

/**
 * Runs a set of servers in this JVM, any set: one server alone, or several (the mail suite, say)
 * together. The servers are {@link ServerProvider}s found at run time, chosen by id; their settings
 * are read from the settings folder ({@link ServerMain#confDir()}) by {@link LaunchSettings}: each
 * provider's shared files ({@code parley-mail.properties}), then its own
 * ({@code parley-pop3.properties}).
 * <p>
 * Each server can be started, stopped and restarted on its own, from code or with JMX (a
 * {@link ParleyServerMBean} for each server and a {@link ParleyLauncherMBean} for the launcher, on
 * the platform MBean server; remote access is the JVM's usual
 * {@code -Dcom.sun.management.jmxremote.*} settings). A restart reads the settings files again and
 * makes a new server from them.
 * <p>
 * {@link ServerMain#launch} runs a launcher as a process; an application (an admin tool) can run
 * one in its own JVM.
 *
 * @since 2.0.0
 */
public final class ServerLauncher implements ParleyLauncherMBean, AutoCloseable {

	/** The ids of the servers to run, comma separated: {@code parley.servers=smtp,submission,imap,pop3} */
	public static final String SERVERS_PROPERTY = "parley.servers";

	public enum State {
		STOPPED, RUNNING, FAILED,
		/** turned off by its settings ({@link ServerProvider#enabled()}) */
		OFF
	}

	/** One server: its provider and, while it runs, the server */
	private final class Entry implements ParleyServerMBean {
		final ServerProvider provider;
		volatile ServerMain.Service service;
		volatile State state = State.STOPPED;
		volatile long started;
		volatile String error;
		/** stopped on request: not a failure */
		volatile boolean stopRequested;
		ObjectName name;

		Entry(ServerProvider provider) {
			this.provider = provider;
		}

		@Override
		public String getId() {
			return provider.id();
		}

		@Override
		public String getDescription() {
			return provider.description();
		}

		@Override
		public String getState() {
			return state.name();
		}

		@Override
		public int getPort() {
			ServerMain.Service s = service;
			return s == null ? 0 : s.port();
		}

		@Override
		public long getStarted() {
			return state == State.RUNNING ? started : 0;
		}

		@Override
		public String getError() {
			return error;
		}

		@Override
		public int getConnections() {
			ServerMain.Service s = service;
			return s == null || state != State.RUNNING ? 0 : s.connections();
		}

		@Override
		public ParleyConnection[] getConnectionList() {
			ServerMain.Service s = service;
			if (s == null || state != State.RUNNING) {
				return new ParleyConnection[0];
			}
			List<ParleyConnection> list = s.connectionList();
			return list == null ? new ParleyConnection[0] : list.toArray(new ParleyConnection[0]);
		}

		@Override
		public void start() throws Exception {
			ServerLauncher.this.start(provider.id());
		}

		@Override
		public void stop() throws Exception {
			ServerLauncher.this.stop(provider.id());
		}

		@Override
		public void restart() throws Exception {
			ServerLauncher.this.restart(provider.id());
		}
	}

	private final String name;
	private final LaunchSettings settings;
	private final ServerContext context;
	private final Map<String, Entry> entries = new LinkedHashMap<>();
	private final long createdAt = System.currentTimeMillis();
	private volatile Consumer<String> onFailure = id -> {
	};
	private volatile Runnable onShutdown = () -> {
	};
	private ObjectName launcherName;

	/**
	 * A launcher for these servers.
	 *
	 * @param name     for the messages and the JMX name, e.g. "Pop3Server" or "ParleyMail"
	 * @param settings the command line and the files to read (the providers' files are added)
	 * @param ids      the servers' ids, in the order they start
	 * @param confDir  the settings folder (null: no default files)
	 * @throws IllegalArgumentException if a server isn't known (no provider has that id)
	 */
	public ServerLauncher(String name, LaunchSettings settings, List<String> ids, File confDir, ServerContext context) {
		this.name = name;
		this.settings = settings;
		this.context = context;
		Map<String, ServerProvider> known = providers();
		List<String> unknown = new ArrayList<>();
		for (String id : ids) {
			ServerProvider p = known.get(id.trim().toLowerCase(Locale.ROOT));
			if (p == null) {
				unknown.add(id);
			} else if (!entries.containsKey(p.id())) {
				entries.put(p.id(), new Entry(p));
			}
		}
		if (!unknown.isEmpty()) {
			throw new IllegalArgumentException("Unknown server" + (unknown.size() > 1 ? "s " : " ") + unknown + "; known: " + known.keySet());
		}
		for (Entry e : entries.values()) {
			if (confDir != null) {
				for (String f : e.provider.sharedSettingsFiles()) {
					settings.addFile(new File(confDir, f), false);
				}
			}
			String named = e.provider.configProperty() == null ? null : settings.early(e.provider.configProperty());
			if (named != null) {
				settings.addFile(new File(named), true);
			} else if (confDir != null && e.provider.settingsFile() != null) {
				settings.addFile(new File(confDir, e.provider.settingsFile()), false);
			}
		}
	}

	/** Every provider found (the class path and the plugins), by id */
	public static Map<String, ServerProvider> providers() {
		Map<String, ServerProvider> ret = new LinkedHashMap<>();
		for (ServerProvider p : Plugins.providers(ServerProvider.class, e -> System.err.println("A server provider can't be loaded: " + e))) {
			ret.putIfAbsent(p.id().toLowerCase(Locale.ROOT), p);
		}
		return ret;
	}

	/** Called with a server's id when it stops by itself (not on request) */
	public void setOnFailure(Consumer<String> onFailure) {
		this.onFailure = onFailure;
	}

	/** Called by {@link #shutdown()} after the servers stopped */
	public void setOnShutdown(Runnable onShutdown) {
		this.onShutdown = onShutdown;
	}

	public ServerContext getContext() {
		return context;
	}

	public LaunchSettings getSettings() {
		return settings;
	}

	/** Read the settings and register the management beans (once, before the first start). */
	public synchronized void init() throws Exception {
		if (launcherName != null) {
			return;
		}
		settings.apply();
		for (Entry e : entries.values()) {
			if (!e.provider.enabled()) {
				e.state = State.OFF;
			}
		}
		launcherName = context.register("Launcher", name, this);
		for (Entry e : entries.values()) {
			e.name = context.register("Server", e.provider.id(), e);
		}
	}

	// ------------------------------------------------------------------ life cycle

	private Entry entry(String id) {
		Entry e = entries.get(id == null ? "" : id.trim().toLowerCase(Locale.ROOT));
		if (e == null) {
			throw new IllegalArgumentException("No server " + id + " here; there are " + entries.keySet());
		}
		return e;
	}

	/** Start one server, made from the settings as they are now; nothing happens if it runs. */
	public void start(String id) throws Exception {
		Entry e = entry(id);
		synchronized (e) {
			if (e.state == State.RUNNING) {
				return;
			}
			if (!e.provider.enabled()) {
				e.state = State.OFF;
				e.error = null;
				throw new IOException(e.provider.description() + " is turned off by its settings");
			}
			ServerMain.Service s;
			try {
				s = e.provider.create(context);
				s.startAndWait(ServerMain.START_TIMEOUT);
			} catch (Exception ex) {
				e.state = State.FAILED;
				e.error = ex.getMessage() != null ? ex.getMessage() : ex.toString();
				e.service = null;
				throw ex;
			}
			e.service = s;
			e.stopRequested = false;
			e.error = null;
			e.started = System.currentTimeMillis();
			e.state = State.RUNNING;
			watch(e, s);
		}
	}

	/** Notice when a server stops by itself */
	private void watch(Entry e, ServerMain.Service s) {
		Thread t = new Thread(() -> {
			try {
				s.awaitStop();
			} catch (InterruptedException ex) {
				return;
			}
			boolean failed;
			synchronized (e) {
				if (e.service != s) {
					return; // replaced (restarted)
				}
				failed = !e.stopRequested;
				e.state = failed ? State.FAILED : State.STOPPED;
				if (failed) {
					e.error = "Stopped by itself";
				}
			}
			if (failed) {
				System.err.println(s.name() + " stopped by itself");
				onFailure.accept(e.provider.id());
			}
		}, name + "-" + e.provider.id() + "-watch");
		t.setDaemon(true);
		t.start();
	}

	/** Stop one server (on request: not a failure). */
	public void stop(String id) throws InterruptedException {
		Entry e = entry(id);
		synchronized (e) {
			ServerMain.Service s = e.service;
			e.stopRequested = true;
			if (s != null && e.state == State.RUNNING) {
				s.stop(ServerMain.STOP_TIMEOUT);
			}
			e.state = e.provider.enabled() ? State.STOPPED : State.OFF;
		}
	}

	/** Read the settings files again, then stop the server and start a new one. */
	public void restart(String id) throws Exception {
		Entry e = entry(id);
		synchronized (e) {
			settings.apply();
			stop(id);
			start(id);
		}
	}

	/**
	 * Start the servers in order, except those turned off by their settings; if one can't start,
	 * those started are stopped and the error thrown.
	 */
	public void startAll() throws Exception {
		List<String> started = new ArrayList<>();
		for (Entry e : entries.values()) {
			if (!e.provider.enabled()) {
				synchronized (e) {
					if (e.state != State.RUNNING) {
						e.state = State.OFF;
						e.error = null;
					}
				}
				continue;
			}
			try {
				start(e.provider.id());
				started.add(e.provider.id());
			} catch (Exception ex) {
				Collections.reverse(started);
				for (String id : started) {
					stop(id);
				}
				throw new IOException(e.provider.id() + ": " + (ex.getMessage() != null ? ex.getMessage() : ex), ex);
			}
		}
	}

	/** Stop the servers, the last started first. */
	@Override
	public void stopAll() throws InterruptedException {
		List<Entry> list = new ArrayList<>(entries.values());
		Collections.reverse(list);
		for (Entry e : list) {
			try {
				stop(e.provider.id());
			} catch (RuntimeException ex) {
				System.err.println("Can't stop " + e.provider.id() + ": " + ex);
			}
		}
	}

	@Override
	public void reloadSettings() throws IOException {
		settings.apply();
	}

	@Override
	public void shutdown() {
		try {
			stopAll();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		onShutdown.run();
	}

	/** True while one of the servers runs */
	public boolean isAnyRunning() {
		for (Entry e : entries.values()) {
			if (e.state == State.RUNNING) {
				return true;
			}
		}
		return false;
	}

	public State getState(String id) {
		return entry(id).state;
	}

	/** The server's bean (its status), for an application in this JVM */
	public ParleyServerMBean getServer(String id) {
		return entry(id);
	}

	/** Stop the servers and let go of the beans and shared objects. */
	@Override
	public void close() {
		try {
			stopAll();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		context.close();
		launcherName = null;
	}

	// ------------------------------------------------------------------ the launcher's bean

	@Override
	public String[] getServers() {
		return entries.keySet().toArray(new String[0]);
	}

	@Override
	public String[] getSettingsFiles() {
		List<String> ret = new ArrayList<>();
		for (File f : settings.getFiles()) {
			ret.add(f.getPath());
		}
		return ret.toArray(new String[0]);
	}

	@Override
	public long getStarted() {
		return createdAt;
	}
}
