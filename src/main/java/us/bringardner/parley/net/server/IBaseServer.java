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
import java.util.UUID;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.iam.credential.ProofCredential;
import us.bringardner.parley.net.IManagedThread;
import us.bringardner.parley.net.sasl.ScramMechanism;

/**
 * What every Parley server is, whatever way it serves its connections: the thread-per-connection
 * {@link Server} ({@link IServer}) and the non-blocking
 * {@link us.bringardner.parley.net.nio.NioServer}.
 * <p>
 * It has a property prefix, a port, a life cycle that can be started and waited for, stopped and
 * joined (what {@link ServerMain} needs to run any server as a service), and a
 * {@link UserRegistry} that logs users in and decides what they may do.
 *
 * @since 2.0.0
 * @author Tony Bringardner
 */
public interface IBaseServer extends IManagedThread {

	/**
	 * The JMX domain of Parley's management beans ({@code us.bringardner.parley:type=...,name=...})
	 * @since 2.0.0
	 */
	String JMX_DOMAIN = "us.bringardner.parley";

	/**
	 * The server's own settings, given when it was made (see parley-core's
	 * {@code BaseObject.setConfiguration}), or null when it reads the system properties; the
	 * objects it makes (processors, its user registry) read the same settings.
	 *
	 * @since 2.0.0
	 */
	default java.util.Properties getConfiguration() {
		return null;
	}

	/** Property (prefix.authenticationProvider) naming the {@link UserRegistry} class */
	public static final String AUTHENTICATION_PROVIDER_PROPERTY = "authenticationProvider";

	/**
	 * The prefix of this server's properties (for example parley.mail.pop3): its own settings, such as
	 * port, and those of its user registry, such as userFile, are read as prefix.name.
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

	// ------------------------------------------------------------------ users

	/**
	 * Check a credential. A proof (a {@link ProofCredential}) is run here, so every protocol
	 * does it the same way:
	 * <ol>
	 * <li>the registry gives the user's stored secret (quick; no waiting on the client). For a
	 * user without one, {@link #makeUpStoredCredential} gives a made-up one so the exchange fails
	 * the same way; when it can't, the proof is refused without running;</li>
	 * <li>the proof's verifier runs, holding no lock of the registry;</li>
	 * <li>on success the registry gives the principal;</li>
	 * <li>the registry is told the outcome ({@link UserRegistry#recordOutcome}).</li>
	 * </ol>
	 * Every other credential goes to {@link UserRegistry#authenticate(Credential)}.
	 *
	 * @param credential what the client offered
	 * @return AUTHENTICATED (for a proof, the method is the stored secret's kind), REFUSED,
	 * UNSUPPORTED or UNAVAILABLE (the registry can't answer now)
	 * @throws IllegalStateException when there is no user registry ({@link #requireUserRegistry()})
	 * @since 2.0.0
	 */
	default AuthenticationResult authenticate(Credential credential) {
		UserRegistry registry = requireUserRegistry();
		try {
			if( credential instanceof ProofCredential ) {
				return checkProof(registry, (ProofCredential) credential, true);
			}
			return registry.authenticate(credential);
		} catch (UserRegistryUnavailableException e) {
			return AuthenticationResult.unavailable(e.getMessage());
		}
	}

	/**
	 * Would this credential be accepted? Like {@link #authenticate(Credential)}, but the
	 * registry isn't told the outcome of a proof. For a client that asks before it proves
	 * (SSH asks whether a public key would do).
	 *
	 * @param credential what the client offered
	 * @return what {@link #authenticate(Credential)} would answer
	 * @since 2.0.0
	 */
	default AuthenticationResult probe(Credential credential) {
		UserRegistry registry = requireUserRegistry();
		try {
			if( credential instanceof ProofCredential ) {
				return checkProof(registry, (ProofCredential) credential, false);
			}
			return registry.authenticate(credential);
		} catch (UserRegistryUnavailableException e) {
			return AuthenticationResult.unavailable(e.getMessage());
		}
	}

	/** The steps of a proof, see {@link #authenticate(Credential)}. */
	private AuthenticationResult checkProof(UserRegistry registry, ProofCredential proof, boolean record)
			throws UserRegistryUnavailableException {
		String user = proof.getUser();
		StoredCredentialType type = proof.getStoredType();
		StoredCredential stored = user == null ? null : registry.findStoredCredential(user, type);
		boolean known = stored != null;
		if( !known ) {
			stored = makeUpStoredCredential(user, type);
		}
		AuthenticationResult result;
		if( stored == null ) {
			result = AuthenticationResult.refused("no " + type + " secret for " + user);
		} else {
			boolean proven;
			try {
				proven = proof.getVerifier().verify(stored);
			} catch (IOException e) {
				proven = false;
			}
			if( !proven || !known ) {
				result = AuthenticationResult.refused(type + " proof failed for " + user);
			} else {
				// a group doesn't log in, even one a registry keeps a secret for
				ParleyPrincipal principal = registry.findUser(user);
				if( principal == null ) {
					result = AuthenticationResult.refused("no user " + user);
				} else {
					result = AuthenticationResult.authenticated(principal, type.getName());
				}
			}
		}
		if( record ) {
			registry.recordOutcome(user, result);
		}
		return result;
	}

	/**
	 * A stored secret for a user the registry has none for (an unknown user), so a proof
	 * fails the same way as for a known user with a wrong answer. It never proves anything.
	 * <p>
	 * The default makes one for SCRAM (salt the same each time for a user) and for
	 * {@link StoredCredentialType#PLAIN_TEXT}, and null for every other kind; a server that
	 * serves other proofs overrides it.
	 *
	 * @param user the user name the client gave, or null
	 * @param type the kind of secret the proof needs
	 * @return the made-up secret, or null when none can be made for this kind
	 * @since 2.0.0
	 */
	default StoredCredential makeUpStoredCredential(String user, StoredCredentialType type) {
		ScramMechanism scram = ScramMechanism.forStoredType(type);
		if( scram != null ) {
			return new StoredCredential(type, scram.madeUpCredentials(user));
		}
		if( StoredCredentialType.PLAIN_TEXT.equals(type) ) {
			return new StoredCredential(type, UUID.randomUUID().toString());
		}
		return null;
	}

	/**
	 * May the requester do something? The registry answers (rule 5); the server never compares
	 * permissions itself. A null permission (a command that names none) is DENIED. With no user registry this throws
	 * ({@link #requireUserRegistry()}).
	 *
	 * @param requester who is asking
	 * @param needed the permission needed, or null
	 * @param resource what it is about, or null for the server as a whole
	 * @return ALLOWED, DENIED or UNAVAILABLE
	 * @since 2.0.0
	 */
	default AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
		if( needed == null ) {
			return AuthorizationResult.denied("no permission named");
		}
		AuthorizationResult result = requireUserRegistry().checkPermission(requester, needed, resource);
		if( result == null ) {
			return AuthorizationResult.unavailable("the user registry gave no answer");
		}
		return result;
	}

	/**
	 * The user registry, for a part of the server that needs one (logging in, checking a
	 * permission). Using such a part with no registry configured is a mistake in the
	 * configuration, not a refused login or a denied permission (rule 9).
	 *
	 * @return the registry; never null
	 * @throws IllegalStateException when no registry is set or configured, naming the setting
	 * @since 2.0.0
	 */
	default UserRegistry requireUserRegistry() {
		UserRegistry registry = getUserRegistry();
		if( registry == null ) {
			String prefix = getPropertyPrefix();
			String setting = prefix == null || prefix.isEmpty() ? AUTHENTICATION_PROVIDER_PROPERTY
					: prefix+"."+AUTHENTICATION_PROVIDER_PROPERTY;
			throw new IllegalStateException("No user registry: set "+setting
					+" (or call setUserRegistry) to log in or check permissions");
		}
		return registry;
	}

	/**
	 * The registry set with {@link #setUserRegistry(UserRegistry)}, else one made from the
	 * {@value #AUTHENTICATION_PROVIDER_PROPERTY} setting, else null. To make one from the setting
	 * the server uses the class's public constructor that takes an {@link IBaseServer} when it
	 * has one (so the registry can read the server's settings), otherwise its no-argument one.
	 * A registry made from the setting is the server's: it is closed when the server stops, and
	 * a restart makes a new one.
	 *
	 * @return the registry, or null
	 * @throws IllegalStateException if the setting names a class that can't be made
	 * @since 2.0.0
	 */
	UserRegistry getUserRegistry();

	/**
	 * @param registry the registry to use, ready to use; it is the caller's to close. Null
	 * looks at the setting again on the next use. A registry the server made itself is closed
	 * when it is replaced.
	 * @since 2.0.0
	 */
	void setUserRegistry(UserRegistry registry);
}
