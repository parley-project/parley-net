package us.bringardner.parley.net.sasl;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ProofVerifier;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.net.server.IBaseServer;
import us.bringardner.parley.net.server.ILoginSession;

/**
 * Checks SASL logins with the server's own user registry, so SASL logins and the protocol's
 * USER / PASS use the same users. It serves PLAIN and LOGIN, and SCRAM-SHA-1 and SCRAM-SHA-256
 * when the registry keeps SCRAM credentials for every user
 * ({@link UserRegistry#supports(Class, StoredCredentialType)}). Hashed passwords can't answer
 * CRAM-MD5, so it isn't served.
 * <p>
 * Create one per authentication. Made with the session, it logs the session in: every check
 * goes through {@link ILoginSession#authenticate}, the session's one way to log in. Made with
 * a requester only, it checks and reports, and logs nobody in.
 * <p>
 * SCRAM doesn't check a password here: when {@link SaslServerDriver} reports success for it,
 * call {@link #verified(String)} with the outcome's user. That goes through the server's
 * {@link IBaseServer#authenticate} too, so the registry is told the outcome and the principal
 * is looked up in one place.
 * <p>
 * When the registry can't answer (its database is down, say), the login fails and
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

	private final IBaseServer server;
	private final ILoginSession session;
	private final Requester requester;
	private volatile AuthenticationResult result;
	private volatile boolean unavailable;
	/** The user and SCRAM credentials of the last exchange, for {@link #verified(String)} */
	private String scramUser;
	private StoredCredentialType scramType;
	private ScramCredentials scramCredentials;

	/**
	 * Checks logins and logs the session in when one succeeds.
	 *
	 * @param server the server whose registry checks the logins
	 * @param session the session to log in
	 * @since 2.0.0
	 */
	public ServerSaslAuthenticator(IBaseServer server, ILoginSession session) {
		this.server = server;
		this.session = session;
		this.requester = null;
	}

	/**
	 * Checks logins and only reports them ({@link #getResult()}); nobody is logged in.
	 *
	 * @param server the server whose registry checks the logins
	 * @param requester who is asking
	 * @since 2.0.0
	 */
	public ServerSaslAuthenticator(IBaseServer server, Requester requester) {
		this.server = server;
		this.session = null;
		this.requester = requester;
	}

	private Requester requester() {
		return session != null ? session.getRequester() : requester;
	}

	/** Through the session when there is one, so a good result logs it in. */
	private AuthenticationResult check(Credential credential) {
		AuthenticationResult ret = session != null ? session.authenticate(credential) : server.authenticate(credential);
		if( ret.getStatus() == AuthenticationResult.Status.UNAVAILABLE ) {
			unavailable = true;
		}
		result = ret;
		return ret;
	}

	@Override
	public boolean checkPassword(String user, String password) {
		PasswordCredential credential = new PasswordCredential(user, password.toCharArray(), requester());
		try {
			return check(credential).getStatus() == AuthenticationResult.Status.AUTHENTICATED;
		} finally {
			credential.clear();
		}
	}

	/**
	 * @return how the last check or {@link #verified(String)} ended, or null before the first
	 * @since 2.0.0
	 */
	public AuthenticationResult getResult() {
		return result;
	}

	/**
	 * After SCRAM succeeded: log the user in through the server, with the credentials the
	 * exchange used. The registry is asked for them again; if they changed meanwhile (a new
	 * password), the login is refused.
	 *
	 * @param user the user from the successful outcome
	 * @return the result; AUTHENTICATED when the user is still there with the same credentials
	 * @since 1.1.0
	 */
	public AuthenticationResult verified(String user) {
		final ScramCredentials used;
		StoredCredentialType type;
		synchronized (this) {
			boolean same = user != null && user.equals(scramUser);
			used = same ? scramCredentials : null;
			type = same ? scramType : StoredCredentialType.SCRAM_SHA_256;
		}
		ProofVerifier exchangeDone = new ProofVerifier() {
			@Override
			public boolean verify(StoredCredential stored) {
				Object value = stored.getValue();
				return used != null && value instanceof ScramCredentials
						&& ((ScramCredentials) value).format().equals(used.format());
			}
		};
		return check(new ProofCredential(user, type, exchangeDone, requester()));
	}

	/**
	 * @return true if the user registry couldn't answer during this authentication; the
	 * login then failed for that reason, not because of the credentials
	 * @since 1.1.0
	 */
	public boolean isUnavailable() {
		return unavailable;
	}

	/** The SCRAM credentials from the user registry; null (and {@link #isUnavailable()}) if it can't answer. */
	@Override
	public ScramCredentials getScramCredentials(String user, String hash) {
		UserRegistry registry = server.getUserRegistry();
		StoredCredentialType type = storedType(hash);
		if( registry == null || user == null || type == null ) {
			return null;
		}
		StoredCredential stored;
		try {
			stored = registry.findStoredCredential(user, type);
		} catch (UserRegistryUnavailableException e) {
			unavailable = true;
			return null;
		}
		ScramCredentials ret = null;
		if( stored != null && stored.getValue() instanceof ScramCredentials ) {
			ret = (ScramCredentials) stored.getValue();
		}
		synchronized (this) {
			scramUser = user;
			scramType = type;
			scramCredentials = ret;
		}
		return ret;
	}

	@Override
	public boolean supports(String mechanism) {
		UserRegistry registry = server.getUserRegistry();
		if( registry == null ) {
			return false;
		}
		if( PlainMechanism.NAME.equals(mechanism) || LoginMechanism.NAME.equals(mechanism) ) {
			return registry.supports(PasswordCredential.class, null);
		}
		StoredCredentialType type = storedType(ScramMechanism.hashOf(mechanism));
		return type != null && registry.supports(ProofCredential.class, type);
	}

	/** @return the stored kind for "SHA-1" or "SHA-256" (any case), or null */
	private static StoredCredentialType storedType(String hash) {
		if( ScramMechanism.SHA_256.getHash().equalsIgnoreCase(hash) ) {
			return ScramMechanism.SHA_256.getStoredType();
		}
		if( ScramMechanism.SHA_1.getHash().equalsIgnoreCase(hash) ) {
			return ScramMechanism.SHA_1.getStoredType();
		}
		return null;
	}
}
