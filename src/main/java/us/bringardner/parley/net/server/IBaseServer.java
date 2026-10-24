/**
 * <PRE>
 *
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
 *
 *
 *	@author Tony Bringardner
 *
 *
 */
package us.bringardner.parley.net.server;

import java.io.IOException;

import us.bringardner.parley.net.IManagedThread;

/**
 * What every Parley server is, whatever way it serves its connections: the thread-per-connection
 * {@link Server} ({@link IServer}) and the non-blocking
 * {@link us.bringardner.parley.net.nio.NioServer}.
 * <p>
 * It has a property prefix, a port, a life cycle that can be started and waited for, stopped and
 * joined (what {@link ServerMain} needs to run any server as a service), and an access control
 * list that logs users in and authorizes what they do.
 *
 * @since 2.0.0
 * @author Tony Bringardner
 */
public interface IBaseServer extends IManagedThread {

	/** Property (prefix.authenticationProvider) naming the {@link IAccessControlList} class */
	public static final String AUTHENTICATION_PROVIDER_PROPERTY = "authenticationProvider";

	/**
	 * The prefix of this server's properties (for example parley.mail.pop3): its own settings, such as
	 * port, and those of its access control list, such as userFile, are read as prefix.name.
	 */
	public String getPropertyPrefix();

	/** @return the port the server listens on (0 means any free port) */
	public int getPort();

	public void setPort(int port);

	/** @return true if the server speaks TLS from the first byte */
	public boolean isSecure();

	public void setSecure(boolean secure);

	// ------------------------------------------------------------------ life cycle

	/**
	 * Start the server and wait until it is accepting connections. Unlike {@link #start()}, a
	 * server that can't start (port in use ...) is reported to the caller instead of only being
	 * logged.
	 *
	 * @throws IOException with the reason if the server did not start within the timeout
	 */
	public void startAndWait(long timeoutMillis) throws IOException;

	/**
	 * @return why the last start() failed, or null if it started (or is still starting)
	 */
	public Throwable getStartupError();

	/**
	 * @return the port the server is listening on (the one chosen when the port is 0), or -1 if
	 * it isn't listening
	 */
	public int getLocalPort();

	/**
	 * Stop the server and wait (up to timeoutMillis) for it to end.
	 *
	 * @param timeoutMillis maximum time to wait; zero means don't wait
	 * @param interrupt if true, the server's thread is also interrupted
	 * @return true if the server has ended
	 * @throws InterruptedException if the calling thread is interrupted while waiting
	 */
	public boolean stop(long timeoutMillis, boolean interrupt) throws InterruptedException;

	/**
	 * Wait for the server to end.
	 *
	 * @param timeoutMillis maximum time to wait (0 means wait forever)
	 * @throws InterruptedException if the calling thread is interrupted while waiting
	 */
	public void join(long timeoutMillis) throws InterruptedException;

	// ------------------------------------------------------------------ access control

	/**
	 * Authenticate a user with the given credentials (probably a password).
	 *
	 * @param user
	 * @param credentials (password)
	 * @return a read only authenticated principal, or null if the user can't be authenticated,
	 * the access control list can't answer now (see {@link #checkLogin(String, byte[])}), or
	 * there is no access control
	 */
	public IPrincipal authenticate(String user, byte[] credentials);

	/**
	 * Check a login like {@link #authenticate(String, byte[])}, but tell a failed login (null)
	 * from an access control list that can't answer now (the exception), so the server can answer
	 * "try again later" instead of "wrong password".
	 * <p>
	 * The default looks the user up in {@link #getAccessControl()} with
	 * {@link IAccessControlList#findPrincipal(String)}.
	 *
	 * @return a read only authenticated principal, or null if the login failed or there is no
	 * access control
	 * @throws AccessControlUnavailableException if the access control list can't answer now
	 * @since 1.1.0
	 */
	default IPrincipal checkLogin(String user, byte[] credentials) throws AccessControlUnavailableException {
		IAccessControlList acl = getAccessControl();
		if( acl == null || user == null ) {
			return null;
		}
		IPrincipal tmp = acl.findPrincipal(user);
		if( tmp == null ) {
			// same work as a real check so timing doesn't reveal valid user names
			acl.authenticateUnknownUser(credentials);
			return null;
		}
		if( !tmp.authenticate(credentials) ) {
			return null;
		}
		IPrincipal ret = new ImmutablePrincipal(tmp);
		ret.setState(IPrincipal.State.Authenticated);
		return ret;
	}

	/**
	 * The principal of a user whose identity a SASL mechanism has already proven without
	 * {@link #authenticate(String, byte[])} (SCRAM checks a proof against the credentials
	 * from {@link IAccessControlList#getScramCredentials(String, String)}). Call it only
	 * after such a mechanism succeeded for this user.
	 * <p>
	 * The default looks the user up in {@link #getAccessControl()}.
	 *
	 * @param user the user the mechanism proved
	 * @return a read only authenticated principal, or null if there is no access control or
	 * no such user
	 * @throws AccessControlUnavailableException if the access control list can't answer now
	 * @since 1.1.0
	 */
	default IPrincipal getVerifiedPrincipal(String user) throws AccessControlUnavailableException {
		IAccessControlList acl = getAccessControl();
		if( acl == null || user == null ) {
			return null;
		}
		IPrincipal p = acl.findPrincipal(user);
		if( p == null ) {
			return null;
		}
		IPrincipal ret = new ImmutablePrincipal(p);
		ret.setState(IPrincipal.State.Authenticated);
		return ret;
	}

	/**
	 * @return true if the user is logged in and the access control allows the action
	 */
	default boolean isAuthorized(IPrincipal user, IPermission action) {
		if( user == null ) {
			// Not logged in
			return false;
		}
		IAccessControlList acl = getAccessControl();
		return acl != null && acl.checkPermission(user, action);
	}

	/**
	 * @return the access control set with {@link #setAccessControl(IAccessControlList)}, else
	 * one made from the {@value #AUTHENTICATION_PROVIDER_PROPERTY} property, else null
	 */
	IAccessControlList getAccessControl();

	/**
	 * @param acl the access control, already initialized; null to look at the property again on the next use
	 */
	void setAccessControl(IAccessControlList acl);
}
