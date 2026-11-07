/**
 * <PRE>
 * 
 * Copyright 2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
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

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;

/**
 * A server's session with one client, as far as logging in goes: who is asking, and the one
 * way to log in. Both kinds of server session are one ({@link us.bringardner.parley.net.IProcessor}
 * and {@link us.bringardner.parley.net.nio.INioConnection}).
 * <p>
 * {@link #authenticate(Credential)} is the only way a session becomes logged in. Code that
 * checks a login in steps (a SASL exchange) is given the session and calls it at the end.
 *
 * @since 2.0.0
 */
public interface LoginSession {

	/**
	 * @return the server this session belongs to; {@link us.bringardner.parley.net.IProcessor}
	 * narrows it to {@link IServer} and {@link us.bringardner.parley.net.nio.INioConnection} to
	 * {@link us.bringardner.parley.net.nio.NioServer}
	 * @since 2.0.0
	 */
	IBaseServer getServer();

	/**
	 * Who is asking: the logged-in principal, or nobody, and the facts about the connection
	 * (the client's address, the local port, TLS, the server's name). It is current: after
	 * STARTTLS it says the connection is secure.
	 *
	 * @return the requester; never null
	 */
	Requester getRequester();

	/** @return the logged-in principal, or null when nobody is logged in */
	default ParleyPrincipal getPrincipal() {
		return getRequester().getPrincipal();
	}

	/**
	 * Check a credential with the server and, when it is good, log the session in as its
	 * principal. Any other result leaves the session as it was.
	 *
	 * @param credential what the client offered, made with {@link #getRequester()}
	 * @return the server's answer
	 */
	AuthenticationResult authenticate(Credential credential);

	/**
	 * Refuse a login that never reached the user registry, or that the registry was never asked to
	 * prove right: text SASLprep can't prepare, an APOP that wasn't offered, a wrong SCRAM proof
	 * (found by the mechanism itself). It is counted and answered late like a wrong password
	 * ({@link LoginFailures}): a thread-per-connection session waits before returning, and a
	 * non-blocking one holds the reply the protocol writes next. The session is left as it was.
	 * <p>
	 * A missing permission is not a refused login: the password was right, the session stays
	 * logged in, and the protocol refuses the commands that need the permission.
	 *
	 * @param reason why, for the log
	 * @return a REFUSED result, for the protocol's reply
	 * @since 2.0.0
	 */
	AuthenticationResult refuseLogin(String reason);

	/**
	 * @return true once this session has had as many refused logins as the server allows
	 * ({@code maxLoginAttempts}); the session is ended after the reply to the last one
	 * @since 2.0.0
	 */
	boolean isTooManyLoginFailures();

	/** Log the session out; nobody is logged in afterwards. */
	void logout();

	/**
	 * May this session do something?
	 *
	 * @param needed the permission needed
	 * @param resource what it is about, or null for the server as a whole
	 * @return ALLOWED, DENIED or UNAVAILABLE
	 */
	AuthorizationResult checkPermission(ParleyPermission needed, ProtectedResource resource);
}
