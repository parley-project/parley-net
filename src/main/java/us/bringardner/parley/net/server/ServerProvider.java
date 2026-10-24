package us.bringardner.parley.net.server;

import java.util.Collections;
import java.util.List;

/**
 * A server {@link ServerLauncher} can run: found at run time (Java's ServiceLoader, through
 * parley-core's plugins: {@code META-INF/services/us.bringardner.parley.net.server.ServerProvider}),
 * so a launcher runs any set of servers, alone or several in one JVM, without depending on their
 * modules. Each listener is one provider: SMTP's MX and submission servers are two, POP3 and POP3
 * with implicit TLS are two.
 * <p>
 * A provider makes its server from the system properties (the settings files and the command line,
 * see {@link ServerLauncher}); what the servers of one JVM share (a user list, a queue) comes from
 * the {@link ServerContext}.
 *
 * @since 2.0.0
 */
public interface ServerProvider {

	/** The id that names the server in {@code parley.servers}, in lower case, e.g. {@code pop3} */
	String id();

	/** For people, e.g. "POP3 (port 110)" */
	String description();

	/**
	 * Settings files (in the settings folder, {@link ServerMain#confDir()}) read before the server's
	 * own, for the settings a family of servers shares, e.g. {@code parley-mail.properties}.
	 */
	default List<String> sharedSettingsFiles() {
		return Collections.emptyList();
	}

	/** The server's own settings file in the settings folder (null: none); it wins over the shared ones */
	default String settingsFile() {
		return "parley-" + id() + ".properties";
	}

	/**
	 * The property naming a file to read instead of {@link #settingsFile()} (e.g.
	 * parley.mail.pop3.configFile), or null
	 */
	default String configProperty() {
		return null;
	}

	/**
	 * Whether its settings (as the system properties are now) turn it on; a server that is off (its
	 * port is 0, say) isn't started with the others, and can't be started until its settings change.
	 */
	default boolean enabled() {
		return true;
	}

	/** Make the server, from the system properties; it is started by the launcher. */
	ServerMain.Service create(ServerContext context) throws Exception;
}
