package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

import us.bringardner.parley.net.server.AccessControlUnavailableException;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.IServer;

/**
 * Checks SASL logins with the server's own access control list, so SASL logins and the
 * protocol's USER / PASS use the same users. It serves PLAIN and LOGIN, and SCRAM-SHA-1 and
 * SCRAM-SHA-256 when the list keeps SCRAM credentials
 * ({@link us.bringardner.parley.net.server.IAccessControlList#supportsScram(String)}). Hashed
 * passwords can't answer CRAM-MD5, so it isn't served.
 * <p>
 * Create one per authentication. After a successful {@link #checkPassword} it holds the
 * authenticated principal, for the protocol to attach to the session. SCRAM doesn't check a
 * password here: when {@link SaslServerDriver} reports success for it, call
 * {@link #verified(String)} with the outcome's user to get the principal.
 * <p>
 * When the access control list can't answer (its database is down, say), the login fails and
 * {@link #isUnavailable()} is true: answer with a temporary failure, not "wrong password".
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
public class ServerSaslAuthenticator implements ISaslAuthenticator {

	private final IServer server;
	private IPrincipal principal;
	private volatile boolean unavailable;

	public ServerSaslAuthenticator(IServer server) {
		this.server = server;
	}

	@Override
	public boolean checkPassword(String user, String password) {
		try {
			principal = server.checkLogin(user, password.getBytes(StandardCharsets.UTF_8));
		} catch (AccessControlUnavailableException e) {
			unavailable = true;
			principal = null;
		}
		return principal != null;
	}

	/** @return the principal of the last successful check or {@link #verified(String)}, or null */
	public IPrincipal getPrincipal() {
		return principal;
	}

	/**
	 * After a mechanism that proves the user without a password (SCRAM) succeeded: look the
	 * user up and keep the principal.
	 *
	 * @param user the user from the successful outcome
	 * @return the authenticated principal, or null if the user isn't there any more
	 * @throws AccessControlUnavailableException if the access control list can't answer now
	 * @since 1.1.0
	 */
	public IPrincipal verified(String user) throws AccessControlUnavailableException {
		try {
			principal = server.getVerifiedPrincipal(user);
		} catch (AccessControlUnavailableException e) {
			unavailable = true;
			principal = null;
			throw e;
		}
		return principal;
	}

	/**
	 * @return true if the access control list couldn't answer during this authentication; the
	 * login then failed for that reason, not because of the credentials
	 * @since 1.1.0
	 */
	public boolean isUnavailable() {
		return unavailable;
	}

	/** The SCRAM credentials from the access control list; null (and {@link #isUnavailable()}) if it can't answer. */
	@Override
	public ScramCredentials getScramCredentials(String user, String hash) {
		IAccessControlList acl = server.getAccessControl();
		if( acl == null || user == null ) {
			return null;
		}
		try {
			return acl.getScramCredentials(user, hash);
		} catch (AccessControlUnavailableException e) {
			unavailable = true;
			return null;
		}
	}

	@Override
	public boolean supports(String mechanism) {
		if( PlainMechanism.NAME.equals(mechanism) || LoginMechanism.NAME.equals(mechanism) ) {
			return true;
		}
		String hash = ScramMechanism.hashOf(mechanism);
		IAccessControlList acl = hash == null ? null : server.getAccessControl();
		return acl != null && acl.supportsScram(hash);
	}
}
