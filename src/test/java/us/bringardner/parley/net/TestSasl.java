package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.BasicParleyPermission;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.net.sasl.CramMd5Mechanism;
import us.bringardner.parley.net.sasl.ISaslAuthenticator;
import us.bringardner.parley.net.sasl.ISaslChannel;
import us.bringardner.parley.net.sasl.ISaslClient;
import us.bringardner.parley.net.sasl.ISaslMechanism;
import us.bringardner.parley.net.sasl.ISaslServer;
import us.bringardner.parley.net.sasl.LoginMechanism;
import us.bringardner.parley.net.sasl.PlainMechanism;
import us.bringardner.parley.net.sasl.SaslEncoding;
import us.bringardner.parley.net.sasl.SaslException;
import us.bringardner.parley.net.sasl.SaslMechanisms;
import us.bringardner.parley.net.sasl.SaslOutcome;
import us.bringardner.parley.net.sasl.SaslOutcome.Status;
import us.bringardner.parley.net.sasl.SaslServerDriver;
import us.bringardner.parley.net.sasl.SaslStep;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.sasl.ScramMechanism;
import us.bringardner.parley.net.sasl.ServerSaslAuthenticator;
import us.bringardner.parley.net.sasl.XOAuth2Mechanism;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.ILoginSession;
import us.bringardner.parley.net.server.Server;

/**
 * SASL mechanisms against the published test vectors, then end to end through the driver.
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
public class TestSasl {

	private static byte[] utf8(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	private static String str(byte[] b) {
		return new String(b, StandardCharsets.UTF_8);
	}

	/** One user, with every kind of secret the mechanisms ask for. */
	static class Users implements ISaslAuthenticator {
		final String user;
		final String password;
		final ScramCredentials sha1;
		final ScramCredentials sha256;
		final String token = "ya29.token";

		Users(String user, String password) {
			this.user = user;
			this.password = password;
			byte[] salt = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
			sha1 = ScramMechanism.SHA_1.deriveCredentials(password, salt, 4096);
			sha256 = ScramMechanism.SHA_256.deriveCredentials(password, salt, 4096);
		}

		@Override
		public boolean checkPassword(String u, String p) {
			return user.equals(u) && password.equals(p);
		}

		@Override
		public String getPassword(String u) {
			return user.equals(u) ? password : null;
		}

		@Override
		public ScramCredentials getScramCredentials(String u, String hash) {
			if (!user.equals(u)) {
				return null;
			}
			return hash.equals("SHA-1") ? sha1 : sha256;
		}

		@Override
		public boolean checkBearerToken(String u, String t) {
			return user.equals(u) && token.equals(t);
		}
	}

	// ------------------------------------------------------------------ vectors

	@Test
	public void cramMd5MatchesRfc2195() throws Exception {
		String challenge = "<1896.697170952@postoffice.reston.mci.net>";
		CramMd5Mechanism mech = new CramMd5Mechanism(() -> challenge);
		ISaslAuthenticator auth = new ISaslAuthenticator() {
			@Override
			public boolean checkPassword(String user, String password) {
				return false;
			}

			@Override
			public String getPassword(String user) {
				return "tim".equals(user) ? "tanstaaftanstaaf" : null;
			}
		};
		ISaslServer server = mech.newServer(auth);
		SaslStep first = server.start(null);
		assertEquals(SaslStep.Kind.CHALLENGE, first.getKind());
		assertEquals(challenge, str(first.getData()));

		SaslStep done = server.respond(utf8("tim b913a602c7eda7a495b4e6e7334d3890"));
		assertEquals(SaslStep.Kind.SUCCESS, done.getKind());
		assertEquals("tim", done.getUser());

		ISaslServer again = mech.newServer(auth);
		again.start(null);
		assertEquals(SaslStep.Kind.FAILURE, again.respond(utf8("tim b913a602c7eda7a495b4e6e7334d3891")).getKind());

		// and the client side makes the same answer
		ISaslClient client = CramMd5Mechanism.client("tim", "tanstaaftanstaaf");
		assertEquals("tim b913a602c7eda7a495b4e6e7334d3890", str(client.evaluateChallenge(utf8(challenge))));
		assertTrue(client.isComplete());
	}

	@Test
	public void scramSha1MatchesRfc5802() throws Exception {
		// RFC 5802 section 5
		String serverNonce = "3rfcNHYJY1ZVvWVs7j";
		ScramMechanism mech = new ScramMechanism("SHA-1", () -> serverNonce);
		byte[] salt = Base64.getDecoder().decode("QSXCR+Q6sek8bf92");
		ScramCredentials stored = mech.deriveCredentials("pencil", salt, 4096);
		ISaslAuthenticator auth = new Users("user", "pencil") {
			@Override
			public ScramCredentials getScramCredentials(String u, String hash) {
				return "user".equals(u) ? stored : null;
			}
		};

		ISaslServer server = mech.newServer(auth);
		SaslStep sf = server.start(utf8("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"));
		assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", str(sf.getData()));

		SaslStep fin = server.respond(utf8("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,"
				+ "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="));
		assertEquals(SaslStep.Kind.CHALLENGE, fin.getKind());
		assertEquals("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", str(fin.getData()));
		SaslStep ok = server.respond(new byte[0]);
		assertEquals(SaslStep.Kind.SUCCESS, ok.getKind());
		assertEquals("user", ok.getUser());
	}

	@Test
	public void scramSha256MatchesRfc7677() throws Exception {
		// RFC 7677 section 3
		String clientNonce = "rOprNGfwEbeRWgbNEkqO";
		String serverNonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
		ScramMechanism mech = new ScramMechanism("SHA-256", () -> serverNonce);
		byte[] salt = Base64.getDecoder().decode("W22ZaJ0SNY7soEsUEjb6gQ==");
		ScramCredentials stored = mech.deriveCredentials("pencil", salt, 4096);
		ISaslAuthenticator auth = new Users("user", "pencil") {
			@Override
			public ScramCredentials getScramCredentials(String u, String hash) {
				return "user".equals(u) ? stored : null;
			}
		};

		// client side
		ISaslClient client = mech.client("user", "pencil", () -> clientNonce);
		assertEquals("n,,n=user,r=" + clientNonce, str(client.initialResponse()));
		String serverFirst = "r=" + clientNonce + serverNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
		assertEquals("c=biws,r=" + clientNonce + serverNonce + ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
				str(client.evaluateChallenge(utf8(serverFirst))));
		assertFalse(client.isComplete());
		assertArrayEquals(new byte[0], client.evaluateChallenge(utf8("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")));
		assertTrue(client.isComplete());

		// server side
		ISaslServer server = mech.newServer(auth);
		SaslStep first = server.start(utf8("n,,n=user,r=" + clientNonce));
		assertEquals(serverFirst, str(first.getData()));
		SaslStep fin = server.respond(utf8("c=biws,r=" + clientNonce + serverNonce
				+ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="));
		assertEquals("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", str(fin.getData()));
		assertEquals(SaslStep.Kind.SUCCESS, server.respond(new byte[0]).getKind());
	}

	@Test
	public void scramClientRejectsAServerThatDoesNotKnowThePassword() throws Exception {
		ScramMechanism mech = ScramMechanism.SHA_256;
		ISaslClient client = mech.client("user", "pencil", () -> "cnonce");
		client.initialResponse();
		client.evaluateChallenge(utf8("r=cnonceSNONCE,s=" + SaslEncoding.encode(utf8("saltsaltsaltsalt")) + ",i=4096"));
		SaslException e = assertThrows(SaslException.class, 
				() -> client.evaluateChallenge(utf8("v=" + SaslEncoding.encode(new byte[32]))));
		assertNotNull(e.getMessage());
		assertFalse(client.isComplete());
	}

	@Test
	public void scramClientRejectsAForeignNonce() throws Exception {
		ISaslClient client = ScramMechanism.SHA_256.client("user", "pencil", () -> "cnonce");
		client.initialResponse();
		assertThrows(SaslException.class, () -> client.evaluateChallenge(
				utf8("r=someoneelse,s=" + SaslEncoding.encode(utf8("saltsaltsaltsalt")) + ",i=4096")));
	}

	@Test
	public void scramUnknownUserAndBadProofFail() {
		Users users = new Users("alice", "secret");
		ISaslServer server = ScramMechanism.SHA_256.newServer(users);
		// an unknown user still gets a challenge, so the answer doesn't give the user away
		SaslStep first = server.start(utf8("n,,n=mallory,r=abc"));
		assertEquals(SaslStep.Kind.CHALLENGE, first.getKind());
		String nonce = str(first.getData()).split(",")[0].substring(2);
		SaslStep fin = server.respond(utf8("c=biws,r=" + nonce + ",p=" + SaslEncoding.encode(new byte[32])));
		assertEquals(SaslStep.Kind.FAILURE, fin.getKind());
	}

	@Test
	public void scramRefusesChannelBindingAndAuthzid() {
		Users users = new Users("alice", "secret");
		assertEquals(SaslStep.Kind.FAILURE, 
				ScramMechanism.SHA_256.newServer(users).start(utf8("p=tls-unique,,n=alice,r=abc")).getKind());
		assertEquals(SaslStep.Kind.FAILURE, 
				ScramMechanism.SHA_256.newServer(users).start(utf8("n,a=bob,n=alice,r=abc")).getKind());
		assertEquals(SaslStep.Kind.FAILURE, 
				ScramMechanism.SHA_256.newServer(users).start(utf8("garbage")).getKind());
	}

	// ------------------------------------------------------------------ simple mechanisms

	@Test
	public void plainChecksPasswordAndRefusesAuthzid() {
		Users users = new Users("alice", "secret");
		PlainMechanism plain = new PlainMechanism();
		assertEquals("alice", plain.newServer(users).start(utf8("\0alice\0secret")).getUser());
		assertEquals("alice", plain.newServer(users).start(utf8("alice\0alice\0secret")).getUser());
		assertEquals(SaslStep.Kind.FAILURE, plain.newServer(users).start(utf8("\0alice\0wrong")).getKind());
		assertEquals(SaslStep.Kind.FAILURE, plain.newServer(users).start(utf8("bob\0alice\0secret")).getKind());
		assertEquals(SaslStep.Kind.FAILURE, plain.newServer(users).start(utf8("alice\0secret")).getKind());
		assertEquals(SaslStep.Kind.CHALLENGE, plain.newServer(users).start(null).getKind(), "asks for the response");
	}

	@Test
	public void loginAsksForUserThenPassword() {
		Users users = new Users("alice", "secret");
		ISaslServer s = new LoginMechanism().newServer(users);
		assertEquals("Username:", str(s.start(null).getData()));
		assertEquals("Password:", str(s.respond(utf8("alice")).getData()));
		assertEquals("alice", s.respond(utf8("secret")).getUser());

		ISaslServer withUser = new LoginMechanism().newServer(users);
		assertEquals("Password:", str(withUser.start(utf8("alice")).getData()), "user sent with the command");
		assertEquals(SaslStep.Kind.FAILURE, withUser.respond(utf8("nope")).getKind());
	}

	@Test
	public void xoauth2ChecksTokenAndAcknowledgesFailure() throws Exception {
		Users users = new Users("alice", "secret");
		XOAuth2Mechanism mech = new XOAuth2Mechanism();
		byte[] good = XOAuth2Mechanism.client("alice", users.token).initialResponse();
		assertEquals("alice", mech.newServer(users).start(good).getUser());

		ISaslServer bad = mech.newServer(users);
		SaslStep err = bad.start(XOAuth2Mechanism.client("alice", "wrong").initialResponse());
		assertEquals(SaslStep.Kind.CHALLENGE, err.getKind(), "the error is sent as JSON first");
		assertTrue(str(err.getData()).contains("invalid_token"));
		assertEquals(SaslStep.Kind.FAILURE, bad.respond(new byte[0]).getKind());
	}

	@Test
	public void loginClientAnswersInOrder() throws Exception {
		ISaslClient c = LoginMechanism.client("alice", "secret");
		assertNull(c.initialResponse());
		assertEquals("alice", str(c.evaluateChallenge(utf8("Username:"))));
		assertFalse(c.isComplete());
		assertEquals("secret", str(c.evaluateChallenge(utf8("Password:"))));
		assertTrue(c.isComplete());
		assertThrows(SaslException.class, () -> c.evaluateChallenge(utf8("again")));
	}

	// ------------------------------------------------------------------ driver

	/** The protocol side: challenges are recorded, responses come from a script. */
	static class ScriptedChannel implements ISaslChannel {
		final List<String> challenges = new ArrayList<>();
		final Deque<String> responses;

		ScriptedChannel(String... responses) {
			this.responses = new ArrayDeque<>(Arrays.asList(responses));
		}

		@Override
		public void sendChallenge(String base64) {
			challenges.add(base64);
		}

		@Override
		public String readResponse() {
			return responses.poll();
		}
	}

	@Test
	public void driverRunsPlainWithAnInitialResponse() throws IOException {
		Users users = new Users("alice", "secret");
		ScriptedChannel ch = new ScriptedChannel();
		SaslOutcome out = SaslServerDriver.authenticate(new PlainMechanism(), users,
				SaslEncoding.encode(utf8("\0alice\0secret")), ch);
		assertTrue(out.isSuccess());
		assertEquals("alice", out.getUser());
		assertTrue(ch.challenges.isEmpty());
	}

	@Test
	public void driverAsksWhenThereIsNoInitialResponse() throws IOException {
		Users users = new Users("alice", "secret");
		ScriptedChannel ch = new ScriptedChannel(SaslEncoding.encode(utf8("\0alice\0secret")));
		SaslOutcome out = SaslServerDriver.authenticate(new PlainMechanism(), users, null, ch);
		assertTrue(out.isSuccess());
		assertEquals(Arrays.asList(""), ch.challenges, "an empty challenge");
	}

	@Test
	public void driverHandlesCancelEmptyAndBadBase64() throws IOException {
		Users users = new Users("alice", "secret");
		assertEquals(Status.CANCELLED, SaslServerDriver.authenticate(new LoginMechanism(), users, null,
				new ScriptedChannel("*")).getStatus());
		assertEquals(Status.MALFORMED, SaslServerDriver.authenticate(new LoginMechanism(), users, null,
				new ScriptedChannel("***not base64***")).getStatus());
		assertEquals(Status.MALFORMED, SaslServerDriver.authenticate(new PlainMechanism(), users,
				"%%%", new ScriptedChannel()).getStatus());
		assertEquals(Status.CLOSED, SaslServerDriver.authenticate(new LoginMechanism(), users, null,
				new ScriptedChannel()).getStatus());
		// "=" is an empty response, which PLAIN then finds malformed rather than a base64 error
		assertEquals(Status.FAILED, SaslServerDriver.authenticate(new PlainMechanism(), users, "=",
				new ScriptedChannel()).getStatus());
	}

	/** Connect an in-process client mechanism to the driver; returns the outcome. */
	private static SaslOutcome run(ISaslMechanism server, ISaslClient client, ISaslAuthenticator auth, 
			boolean useInitialResponse) throws IOException {
		Deque<String> toClient = new ArrayDeque<>();
		ISaslChannel channel = new ISaslChannel() {
			@Override
			public void sendChallenge(String base64) {
				toClient.add(base64);
			}

			@Override
			public String readResponse() throws IOException {
				String challenge = toClient.poll();
				return SaslEncoding.encode(client.evaluateChallenge(SaslEncoding.decode(challenge)));
			}
		};
		String ir = null;
		if (useInitialResponse && client.hasInitialResponse()) {
			ir = SaslEncoding.encode(client.initialResponse());
		}
		return SaslServerDriver.authenticate(server, auth, ir, channel);
	}

	@Test
	public void everyMechanismWorksEndToEnd() throws Exception {
		Users users = new Users("al,ice=x", "s3cret pass");
		String u = users.user;
		for (boolean ir : new boolean[] {true, false}) {
			assertTrue(run(new PlainMechanism(), PlainMechanism.client(u, users.password), users, ir).isSuccess(), "PLAIN");
			assertTrue(run(new LoginMechanism(), LoginMechanism.client(u, users.password), users, ir).isSuccess(), "LOGIN");
			assertTrue(run(new CramMd5Mechanism("example.com"), CramMd5Mechanism.client(u, users.password), users, ir)
					.isSuccess(), "CRAM-MD5");
			assertTrue(run(new XOAuth2Mechanism(), XOAuth2Mechanism.client(u, users.token), users, ir).isSuccess(),
					"XOAUTH2");
			for (ScramMechanism m : new ScramMechanism[] {ScramMechanism.SHA_1, ScramMechanism.SHA_256}) {
				SaslOutcome out = run(m, m.client(u, users.password), users, ir);
				assertTrue(out.isSuccess(), m.getName() + " " + out);
				assertEquals(u, out.getUser(), "the escaped user name comes back whole");
			}
		}
	}

	@Test
	public void wrongPasswordFailsEverywhere() throws Exception {
		Users users = new Users("alice", "secret");
		assertEquals(Status.FAILED, run(new PlainMechanism(), PlainMechanism.client("alice", "x"), users, true).getStatus());
		assertEquals(Status.FAILED, run(new LoginMechanism(), LoginMechanism.client("alice", "x"), users, false).getStatus());
		assertEquals(Status.FAILED, run(new CramMd5Mechanism("h"), CramMd5Mechanism.client("alice", "x"), users, false)
				.getStatus());
		assertEquals(Status.FAILED, run(ScramMechanism.SHA_256, ScramMechanism.SHA_256.client("alice", "x"), users, true)
				.getStatus());
	}

	// ------------------------------------------------------------------ registry and server

	@Test
	public void registryOffersByStrengthAndSecurity() {
		SaslMechanisms all = SaslMechanisms.standard("example.com");
		ISaslAuthenticator everything = new Users("a", "b");
		assertEquals(Arrays.asList("SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5"), all.offered(everything, false));
		assertEquals(Arrays.asList("SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5", "PLAIN", "LOGIN", "XOAUTH2"),
				all.offered(everything, true));
		assertNotNull(all.find("scram-sha-256"));
		assertNull(all.find("GSSAPI"));
		assertNull(all.find(null));
	}

	@Test
	public void authenticatorLimitsWhatIsOffered() {
		ISaslAuthenticator passwordsOnly = new ISaslAuthenticator() {
			@Override
			public boolean checkPassword(String user, String password) {
				return false;
			}

			@Override
			public boolean supports(String mechanism) {
				return mechanism.equals("PLAIN");
			}
		};
		assertEquals(Arrays.asList("PLAIN"), SaslMechanisms.standard("h").offered(passwordsOnly, true));
		assertTrue(SaslMechanisms.standard("h").offered(passwordsOnly, false).isEmpty());
	}

	/** A session for these tests: logs in only through its server, as a real one does. */
	private static final class Session implements ILoginSession {
		private final Server server;
		private Requester requester = ServerTestSupport.requester();
		int logins;

		Session(Server server) {
			this.server = server;
		}

		@Override
		public Requester getRequester() {
			return requester;
		}

		@Override
		public AuthenticationResult authenticate(Credential credential) {
			AuthenticationResult result = server.authenticate(credential);
			if( result.getStatus() == AuthenticationResult.Status.AUTHENTICATED ) {
				requester = requester.loggedIn(result);
				logins++;
			}
			return result;
		}

		@Override
		public void logout() {
			requester = requester.loggedOut();
		}

		@Override
		public AuthorizationResult checkPermission(ParleyPermission needed, ProtectedResource resource) {
			return server.checkPermission(requester, needed, resource);
		}
	}

	@Test
	public void serverAuthenticatorUsesTheServersUsers() throws Exception {
		Server svr = ServerTestSupport.create("SaslServer", ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(ServerTestSupport.registry("bob, bobpw, Secret"));
		Session session = new Session(svr);
		ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr, session);
		// a plain text password can serve SCRAM too
		assertEquals(Arrays.asList("SCRAM-SHA-256", "SCRAM-SHA-1", "PLAIN", "LOGIN"), SaslMechanisms.standard("h").offered(auth, true));

		SaslOutcome out = run(new PlainMechanism(), PlainMechanism.client("bob", "bobpw"), auth, true);
		assertTrue(out.isSuccess());
		assertEquals("bob", auth.getResult().getPrincipal().getName());
		assertEquals("bob", session.getPrincipal().getName(), "the session is logged in");
		assertTrue(session.checkPermission(new BasicParleyPermission("Secret", null), null).isAllowed());

		Session other = new Session(svr);
		ServerSaslAuthenticator wrong = new ServerSaslAuthenticator(svr, other);
		assertEquals(Status.FAILED, run(new PlainMechanism(), PlainMechanism.client("bob", "wrong"), wrong, true).getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, wrong.getResult().getStatus());
		assertNull(other.getPrincipal());

		// made with a requester only: it reports and logs nobody in
		ServerSaslAuthenticator report = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertTrue(run(new PlainMechanism(), PlainMechanism.client("bob", "bobpw"), report, true).isSuccess());
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, report.getResult().getStatus());
	}

	@Test
	public void nothingIsServedWithoutARegistry() {
		Server svr = new Server(0, "SaslNoRegistry-" + System.nanoTime());
		ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertFalse(auth.supports("PLAIN"));
		assertFalse(auth.supports("SCRAM-SHA-256"));
		// rule 9: logging in with no registry is an error, not a refusal
		assertThrows(IllegalStateException.class, () -> auth.getScramCredentials("bob", "SHA-256"));
		assertThrows(IllegalStateException.class, () -> auth.checkPassword("bob", "pw"));
		assertNull(new ServerSaslAuthenticator(svr, ServerTestSupport.requester()).getResult());
	}

	// ------------------------------------------------------------------ SCRAM from the user registry

	@Test
	public void scramCredentialsAsTextRoundTrip() {
		ScramCredentials c = ScramMechanism.SHA_256.newCredentials("pencil");
		ScramCredentials back = ScramCredentials.parse(c.format());
		assertNotNull(back);
		assertEquals(c.getIterations(), back.getIterations());
		assertArrayEquals(c.getSalt(), back.getSalt());
		assertArrayEquals(c.getStoredKey(), back.getStoredKey());
		assertArrayEquals(c.getServerKey(), back.getServerKey());
		assertEquals(ScramMechanism.DEFAULT_ITERATIONS, c.getIterations());
		assertEquals(16, c.getSalt().length);
		assertFalse(Arrays.equals(c.getSalt(), ScramMechanism.SHA_256.newCredentials("pencil").getSalt()), "a new salt each time");
		for (String bad : new String[] {null, "", "4096", "x:AAAA:AAAA:AAAA", "0:AAAA:AAAA:AAAA", "4096:AAAA:AAAA", 
				"4096:AAAA:AAAA:AA", "4096:!!:AAAA:AAAA", "4096:AAAA:AAAA:AAAA:AAAA"}) {
			assertNull(ScramCredentials.parse(bad), String.valueOf(bad));
		}
		assertEquals("SHA-256", ScramMechanism.hashOf("scram-sha-256"));
		assertEquals("SHA-1", ScramMechanism.hashOf("SCRAM-SHA-1"));
		assertNull(ScramMechanism.hashOf("PLAIN"));
		assertNull(ScramMechanism.hashOf(null));
		assertEquals(StoredCredentialType.SCRAM_SHA_256, ScramMechanism.SHA_256.getStoredType());
		assertEquals(StoredCredentialType.SCRAM_SHA_1, ScramMechanism.SHA_1.getStoredType());
		assertEquals(ScramMechanism.SHA_1, ScramMechanism.forStoredType(StoredCredentialType.SCRAM_SHA_1));
		assertNull(ScramMechanism.forStoredType(StoredCredentialType.PLAIN_TEXT));
		assertArrayEquals(ScramMechanism.SHA_256.madeUpCredentials("x").getSalt(), ScramMechanism.SHA_256.madeUpCredentials("x").getSalt(),
				"a made up salt is the same each time");
	}

	@Test
	public void fileUserRegistryServesScramFromTheUserFile() throws Exception {
		String field = FileUserRegistry.hashPasswordWithScram("s3cret".toCharArray());
		assertTrue(field.startsWith(FileUserRegistry.HASH_PREFIX));
		FileUserRegistry registry = ServerTestSupport.registry("carol, " + field + ", READ, maildrop=c");
		assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256));
		assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_1));
		assertFalse(registry.supports(ProofCredential.class, StoredCredentialType.TSIG_SECRET));
		assertFalse(registry.supports(ProofCredential.class, null));
		assertNull(registry.findStoredCredential("nobody", StoredCredentialType.SCRAM_SHA_256));

		// the password still works on its own: the SCRAM part isn't part of it
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(registry, "carol", "s3cret").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(registry, "carol", "wrong").getStatus());
		assertFalse(registry.supports(ProofCredential.class, StoredCredentialType.PLAIN_TEXT), "a hashed password can't serve APOP");

		Server svr = ServerTestSupport.create("SaslScram", ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(registry);
		for (ScramMechanism m : new ScramMechanism[] {ScramMechanism.SHA_256, ScramMechanism.SHA_1}) {
			Session session = new Session(svr);
			ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr, session);
			assertTrue(auth.supports(m.getName()));
			SaslOutcome out = run(m, m.client("carol", "s3cret"), auth, true);
			assertTrue(out.isSuccess(), m.getName() + " " + out);
			assertNull(auth.getResult(), "SCRAM checks no password here");
			assertNull(session.getPrincipal(), "and logs nobody in by itself");
			AuthenticationResult v = auth.verified(out.getUser());
			assertEquals(AuthenticationResult.Status.AUTHENTICATED, v.getStatus());
			assertEquals(m.getStoredType().getName(), v.getMethod());
			ParleyPrincipal carol = session.getPrincipal();
			assertEquals("carol", carol.getName());
			assertEquals("c", carol.getAttribute("maildrop"));
			assertEquals(Arrays.asList(m.getStoredType().getName()), session.getRequester().getMethods());
			assertTrue(session.checkPermission(new BasicParleyPermission("READ", null), null).isAllowed());

			assertEquals(Status.FAILED, run(m, m.client("carol", "wrong"), new ServerSaslAuthenticator(svr, session), true).getStatus());
			assertEquals(Status.FAILED, run(m, m.client("nobody", "s3cret"), new ServerSaslAuthenticator(svr, session), true).getStatus());
		}
		// verified() with no exchange for that user proves nothing
		Session session = new Session(svr);
		assertEquals(AuthenticationResult.Status.REFUSED, new ServerSaslAuthenticator(svr, session).verified("carol").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, new ServerSaslAuthenticator(svr, session).verified("nobody").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, new ServerSaslAuthenticator(svr, session).verified(null).getStatus());
		assertNull(session.getPrincipal());
		registry.close(); // the test made it: the server leaves a registry it was given alone
	}

	/** Credentials that change between the exchange and verified() (a new password) don't log in. */
	@Test
	public void changedCredentialsAreNotVerified() throws Exception {
		Server svr = ServerTestSupport.create("SaslChanged", ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(ServerTestSupport.registry("carol, " + FileUserRegistry.hashPasswordWithScram("one".toCharArray()) + ", READ"));
		Session session = new Session(svr);
		ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr, session);
		SaslOutcome out = run(ScramMechanism.SHA_256, ScramMechanism.SHA_256.client("carol", "one"), auth, true);
		assertTrue(out.isSuccess());
		svr.setUserRegistry(ServerTestSupport.registry("carol, " + FileUserRegistry.hashPasswordWithScram("two".toCharArray()) + ", READ"));
		assertEquals(AuthenticationResult.Status.REFUSED, auth.verified("carol").getStatus());
		assertNull(session.getPrincipal());
	}

	@Test
	public void scramIsOfferedOnlyWhenEveryUserCanUseIt() throws Exception {
		String hashed = FileUserRegistry.hashPassword("pw".toCharArray());
		FileUserRegistry mixed = ServerTestSupport.registry(
				"carol, " + FileUserRegistry.hashPasswordWithScram("pw".toCharArray()) + ", READ",
				"dave, " + hashed + ", READ");
		assertFalse(mixed.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256), "dave has no SCRAM credentials");
		assertNotNull(mixed.findStoredCredential("carol", StoredCredentialType.SCRAM_SHA_256));
		assertNull(mixed.findStoredCredential("dave", StoredCredentialType.SCRAM_SHA_256));
		Server svr = ServerTestSupport.create("SaslMixed", ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(mixed);
		assertEquals(Arrays.asList("PLAIN", "LOGIN"), SaslMechanisms.standard("h").offered(new ServerSaslAuthenticator(svr, ServerTestSupport.requester()), true));

		// only SHA-256 kept: SHA-1 isn't offered
		String sha256Only = hashed + ";" + FileUserRegistry.SCRAM_SHA_256_PREFIX + ScramMechanism.SHA_256.newCredentials("pw").format();
		FileUserRegistry one = ServerTestSupport.registry("erin, " + sha256Only + ", READ");
		assertTrue(one.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256));
		assertFalse(one.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_1));

		// malformed SCRAM credentials are ignored, the password still works
		FileUserRegistry bad = ServerTestSupport.registry("fred, " + hashed + ";" + FileUserRegistry.SCRAM_SHA_256_PREFIX + "junk, READ");
		assertFalse(bad.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256));
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(bad, "fred", "pw").getStatus());

		assertFalse(ServerTestSupport.registry().supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256), "no users");
	}

	@Test
	public void plainTextPasswordsServeScramWithAStableSalt() throws Exception {
		FileUserRegistry registry = ServerTestSupport.registry("bob, pass;word, READ");
		assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256));
		ScramCredentials first = scram(registry, "bob", StoredCredentialType.SCRAM_SHA_256);
		assertNotNull(first);
		assertArrayEquals(first.getSalt(), scram(registry, "bob", StoredCredentialType.SCRAM_SHA_256).getSalt(),
				"the same salt each time, so it doesn't tell a real user from an unknown one");
		FileUserRegistry reloaded = ServerTestSupport.registry("bob, pass;word, READ");
		assertArrayEquals(first.getSalt(), scram(reloaded, "bob", StoredCredentialType.SCRAM_SHA_256).getSalt(), "and after the file is read again");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(registry, "bob", "pass;word").getStatus(),
				"a ; in a plain text password is part of it");
		Server svr = ServerTestSupport.create("SaslPlainText", ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(registry);
		ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertEquals(first.format(), auth.getScramCredentials("bob", "sha-256").format(), "the hash in any case");
		SaslOutcome out = run(ScramMechanism.SHA_1, ScramMechanism.SHA_1.client("bob", "pass;word"), new ServerSaslAuthenticator(svr, ServerTestSupport.requester()), false);
		assertTrue(out.isSuccess(), out.toString());
	}

	private static ScramCredentials scram(UserRegistry registry, String user, StoredCredentialType type) throws Exception {
		StoredCredential stored = registry.findStoredCredential(user, type);
		return stored == null ? null : (ScramCredentials) stored.getValue();
	}

	/** A registry whose store is down: every lookup throws. */
	static UserRegistry down() {
		return new UserRegistry() {
			@Override
			public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
				return true;
			}

			@Override
			public AuthenticationResult authenticate(Credential credential) {
				return AuthenticationResult.unavailable("the database is down");
			}

			@Override
			public StoredCredential findStoredCredential(String user, StoredCredentialType type) throws UserRegistryUnavailableException {
				throw new UserRegistryUnavailableException("the database is down");
			}

			@Override
			public ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException {
				throw new UserRegistryUnavailableException("the database is down");
			}

			@Override
			public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
				throw new UserRegistryUnavailableException("the database is down");
			}

			@Override
			public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
					ProtectedResource resource) {
				return AuthorizationResult.unavailable("the database is down");
			}
		};
	}

	@Test
	public void aRegistryThatCantAnswerIsNotAWrongPassword() throws Exception {
		Server svr = ServerTestSupport.create("SaslDown", ServerTestSupport.standardCommands(), null);
		svr.getLogger().setLevel(us.bringardner.parley.core.ILogger.Level.NONE);
		svr.setUserRegistry(down());
		assertEquals(AuthenticationResult.Status.UNAVAILABLE, ServerTestSupport.login(svr, "bob", "pw").getStatus());

		ServerSaslAuthenticator plain = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertEquals(Status.FAILED, run(new PlainMechanism(), PlainMechanism.client("bob", "pw"), plain, true).getStatus());
		assertTrue(plain.isUnavailable());

		ServerSaslAuthenticator scram = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertEquals(Status.FAILED, run(ScramMechanism.SHA_256, ScramMechanism.SHA_256.client("bob", "pw"), scram, true).getStatus());
		assertTrue(scram.isUnavailable());
		assertEquals(AuthenticationResult.Status.UNAVAILABLE, scram.verified("bob").getStatus());

		// a registry that can answer: a wrong password isn't "unavailable"
		svr.setUserRegistry(ServerTestSupport.registry("bob, pw, READ"));
		ServerSaslAuthenticator wrong = new ServerSaslAuthenticator(svr, ServerTestSupport.requester());
		assertEquals(Status.FAILED, run(new PlainMechanism(), PlainMechanism.client("bob", "x"), wrong, true).getStatus());
		assertFalse(wrong.isUnavailable());
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(svr, "bob", "pw").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "bob", "x").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "nobody", "pw").getStatus());
	}
}
