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
import us.bringardner.parley.net.server.Server;

/**
 * SASL mechanisms against the published test vectors, then end to end through the driver.
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

	@Test
	public void serverAuthenticatorUsesTheServersUsers() throws Exception {
		Server svr = ServerTestSupport.create("SaslServer", ServerTestSupport.standardCommands(), null);
		svr.setAccessControl(ServerTestSupport.acl("bob, bobpw, Secret"));
		ServerSaslAuthenticator auth = new ServerSaslAuthenticator(svr);
		assertEquals(Arrays.asList("PLAIN", "LOGIN"), SaslMechanisms.standard("h").offered(auth, true));

		SaslOutcome out = run(new PlainMechanism(), PlainMechanism.client("bob", "bobpw"), auth, true);
		assertTrue(out.isSuccess());
		assertEquals("bob", auth.getPrincipal().getName());

		ServerSaslAuthenticator other = new ServerSaslAuthenticator(svr);
		assertEquals(Status.FAILED, run(new PlainMechanism(), PlainMechanism.client("bob", "wrong"), other, true).getStatus());
		assertNull(other.getPrincipal());
	}
}
