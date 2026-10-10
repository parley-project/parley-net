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
