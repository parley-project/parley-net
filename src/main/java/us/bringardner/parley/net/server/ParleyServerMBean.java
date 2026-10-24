package us.bringardner.parley.net.server;

/**
 * A server run by a {@link ServerLauncher}, as JMX sees it ({@code us.bringardner.parley:type=Server,name=ID}).
 *
 * @since 2.0.0
 */
public interface ParleyServerMBean {

	String getId();

	String getDescription();

	/** STOPPED, RUNNING, FAILED or OFF (turned off by its settings) */
	String getState();

	/** The port it listens on, or the port it will listen on */
	int getPort();

	/** When it started (ms since the epoch), or 0 */
	long getStarted();

	/** Why it failed, or null */
	String getError();

	/** Open connections, or -1 if the server doesn't say */
	int getConnections();

	/** Start it (made from the settings as they are now) */
	void start() throws Exception;

	/** Stop it; the process stays up (it can be started again) */
	void stop() throws Exception;

	/** Read the settings files again, then stop it and start it */
	void restart() throws Exception;
}
