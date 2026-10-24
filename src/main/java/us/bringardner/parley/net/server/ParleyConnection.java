package us.bringardner.parley.net.server;

import java.io.Serializable;

/**
 * An open connection of a server, as {@link ParleyServerMBean#getConnectionList()} shows it (a
 * snapshot): the client's address, the user once logged in, and whether it's encrypted.
 *
 * @since 2.0.0
 */
public final class ParleyConnection implements Serializable {

	private static final long serialVersionUID = 1L;

	private final String remote;
	private final String user;
	private final boolean secure;

	/**
	 * @param remote the client's address and port (host:port), or empty if it isn't known
	 * @param user   the user it logged in as, or null
	 * @param secure true when the connection is TLS (implicit or after STARTTLS)
	 */
	public ParleyConnection(String remote, String user, boolean secure) {
		this.remote = remote == null ? "" : remote;
		this.user = user;
		this.secure = secure;
	}

	public String getRemote() {
		return remote;
	}

	/** The user it logged in as, or null */
	public String getUser() {
		return user;
	}

	/** TLS (implicit, or after STARTTLS) */
	public boolean isSecure() {
		return secure;
	}

	@Override
	public String toString() {
		return remote + (user != null ? " " + user : "") + (secure ? " (TLS)" : "");
	}
}
