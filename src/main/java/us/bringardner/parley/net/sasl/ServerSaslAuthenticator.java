package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.IServer;

/**
 * Checks SASL passwords with the server's own access control list, so SASL logins and the
 * protocol's USER / PASS use the same users. It serves PLAIN and LOGIN only: the
 * {@link us.bringardner.parley.net.server.FileBasedAcl} keeps password hashes, which can't
 * answer CRAM-MD5 or SCRAM. Extend it (or write another {@link ISaslAuthenticator}) for a
 * store that has the clear password or SCRAM credentials.
 * <p>
 * Create one per authentication: after a successful {@link #checkPassword} it holds the
 * authenticated principal, for the protocol to attach to the session.
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

	public ServerSaslAuthenticator(IServer server) {
		this.server = server;
	}

	@Override
	public boolean checkPassword(String user, String password) {
		principal = server.authenticate(user, password.getBytes(StandardCharsets.UTF_8));
		return principal != null;
	}

	/** @return the principal of the last successful check, or null */
	public IPrincipal getPrincipal() {
		return principal;
	}

	@Override
	public boolean supports(String mechanism) {
		return PlainMechanism.NAME.equals(mechanism) || LoginMechanism.NAME.equals(mechanism);
	}
}
