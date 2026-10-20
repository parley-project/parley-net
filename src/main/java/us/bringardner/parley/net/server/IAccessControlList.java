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

import us.bringardner.parley.net.sasl.ScramCredentials;

/**
 * Access Control list maintains or produces a list of principles (a.k..a. users) at runtime 
 * and is responsible for authentication and authorization.
 * 
 * initialize 
 * 
 */
public interface IAccessControlList {

	/**
	 * Do any work that needs to be done to initialize this controller
	 * (i.e. load principles from someplace)
	 * 
	 * @param server the sever that will used this controller
	 * @throws IOException
	 */
	void initialize (IServer server) throws IOException;

	/**
	 * Initialize for a server known only by name, for servers that are not an IServer 
	 * (e.g. a non-blocking server). The name is the prefix of the controller's properties, 
	 * as {@link #initialize(IServer)} uses the server's name.
	 * <p>
	 * The default throws UnsupportedOperationException; FileBasedAcl and PropertyAuthenticator 
	 * implement it, and their initialize(IServer) calls it.
	 * 
	 * @param serverName the server's name
	 * @throws IOException
	 */
	default void initialize(String serverName) throws IOException {
		throw new UnsupportedOperationException(getClass().getName()+" needs an IServer to initialize");
	}
	
	/**
	 * 
	 * @param user
	 * @param action
	 * @return true if the principal is authorized to execute or access the action.
	 */
	boolean checkPermission(IPrincipal user, IPermission action);
	
	/**
	 * 
	 * @param user
	 * @return an principle or null if the user/principal does not exist.
	 */
	IPrincipal getPrincipal(String user);

	/**
	 * Look a user up like {@link #getPrincipal(String)}, but tell "no such user" (null) from "I
	 * can't answer now" (the exception). Servers use this one, so a list whose store can fail
	 * (a database) should implement it; getPrincipal can then return null for both.
	 * <p>
	 * The default calls {@link #getPrincipal(String)}, so it never throws.
	 *
	 * @return the principal, or null if the user doesn't exist or can't log in
	 * @throws AccessControlUnavailableException if the list can't answer right now
	 * @since 1.1.0
	 */
	default IPrincipal findPrincipal(String user) throws AccessControlUnavailableException {
		return getPrincipal(user);
	}

	/**
	 * Called when a login names a user that doesn't exist. Implementations that 
	 * hash passwords should do equivalent work here so the response time doesn't
	 * reveal which user names are valid. 
	 */
	default void authenticateUnknownUser(byte[] credentials) {
	}

	/**
	 * True if this list can serve SCRAM logins with that hash (RFC 5802, RFC 7677), so a 
	 * server may offer SCRAM-SHA-1 or SCRAM-SHA-256. A list should say so only when every 
	 * user who can log in has SCRAM credentials: a client that picks SCRAM because it was 
	 * offered can't fall back to a password mechanism for a user who has none.
	 * <p>
	 * The default says no.
	 * 
	 * @param hash "SHA-1" or "SHA-256", as {@link us.bringardner.parley.net.sasl.ScramMechanism#getHash()}
	 * @return true if SCRAM with this hash can be offered
	 * @since 1.1.0
	 */
	default boolean supportsScram(String hash) {
		return false;
	}

	/**
	 * The SCRAM credentials kept for the user, so a server can check a SCRAM login 
	 * without the password. Return null for a user that doesn't exist, can't log in or 
	 * has no credentials for that hash; the SCRAM mechanism then fails the login the 
	 * same way it fails a wrong password.
	 * <p>
	 * The default returns null.
	 * 
	 * @param user the user name, as the client gave it (after SASLprep)
	 * @param hash "SHA-1" or "SHA-256"
	 * @return the user's credentials for that hash, or null
	 * @throws AccessControlUnavailableException if the list can't answer right now
	 * @since 1.1.0
	 */
	default ScramCredentials getScramCredentials(String user, String hash) throws AccessControlUnavailableException {
		return null;
	}

}
