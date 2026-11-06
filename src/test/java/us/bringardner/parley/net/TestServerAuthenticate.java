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
package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ProofVerifier;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.client.ICommandResponse;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.server.ApopVerifier;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.net.server.Server;

/** The server's authenticate door: proofs, made-up secrets, outcomes, and sessions that log in through it. */
public class TestServerAuthenticate {

	private static final String TS = "<1896.697170952@dbc.mtview.ca.us>";
	private static final String DIGEST = "c4c9334bac560ecc979e58001b3e22fb";

	/** A file registry that remembers the outcomes it is told */
	private static final class RecordingRegistry extends FileUserRegistry {
		final List<String> outcomes = new ArrayList<String>();

		RecordingRegistry(String... lines) {
			load(Arrays.asList(lines));
		}

		@Override
		public void recordOutcome(String user, AuthenticationResult result) {
			outcomes.add(user + " " + result.getStatus());
		}
	}

	/** A verifier that counts its runs and gives a fixed answer, or fails talking to the client */
	private static final class CountingVerifier implements ProofVerifier {
		final AtomicInteger runs = new AtomicInteger();
		final Boolean answer;

		CountingVerifier(Boolean answer) {
			this.answer = answer;
		}

		@Override
		public boolean verify(StoredCredential stored) throws IOException {
			runs.incrementAndGet();
			if( answer == null ) {
				throw new IOException("the client went away");
			}
			return answer.booleanValue();
		}
	}

	private static ProofCredential proof(String user, StoredCredentialType type, ProofVerifier verifier) {
		return new ProofCredential(user, type, verifier, ServerTestSupport.requester());
	}

	@Test
	public void aProofRunsThroughTheServer() {
		RecordingRegistry registry = new RecordingRegistry("plain, tanstaaf, READ");
		Server svr = new Server(0, "ProofServer-" + System.nanoTime());
		svr.setUserRegistry(registry);

		AuthenticationResult in = svr.authenticate(proof("plain", StoredCredentialType.PLAIN_TEXT, new ApopVerifier(TS, DIGEST)));
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus());
		assertEquals("plain", in.getPrincipal().getName());
		assertEquals(Arrays.asList("plain AUTHENTICATED"), registry.outcomes);

		assertEquals(AuthenticationResult.Status.REFUSED,
				svr.authenticate(proof("plain", StoredCredentialType.PLAIN_TEXT, new ApopVerifier(TS, "00"))).getStatus());
		assertEquals("plain REFUSED", registry.outcomes.get(1));

		// a probe answers the same and records nothing
		assertEquals(AuthenticationResult.Status.AUTHENTICATED,
				svr.probe(proof("plain", StoredCredentialType.PLAIN_TEXT, new ApopVerifier(TS, DIGEST))).getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED,
				svr.probe(proof("plain", StoredCredentialType.PLAIN_TEXT, new ApopVerifier(TS, "00"))).getStatus());
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, svr.probe(new PasswordCredential(
				"plain", "tanstaaf".toCharArray(), ServerTestSupport.requester())).getStatus(), "other credentials go to the registry");
		assertEquals(2, registry.outcomes.size());
	}

	@Test
	public void anUnknownUserFailsTheSameWay() {
		RecordingRegistry registry = new RecordingRegistry("plain, tanstaaf, READ");
		Server svr = new Server(0, "UnknownServer-" + System.nanoTime());
		svr.setUserRegistry(registry);

		// a made-up secret: the verifier runs, and even a "yes" proves nothing
		CountingVerifier yes = new CountingVerifier(Boolean.TRUE);
		assertEquals(AuthenticationResult.Status.REFUSED, svr.authenticate(proof("nobody", StoredCredentialType.PLAIN_TEXT, yes)).getStatus());
		assertEquals(1, yes.runs.get());
		CountingVerifier scram = new CountingVerifier(Boolean.TRUE);
		assertEquals(AuthenticationResult.Status.REFUSED, svr.authenticate(proof("nobody", StoredCredentialType.SCRAM_SHA_256, scram)).getStatus());
		assertEquals(1, scram.runs.get());

		// no secret can be made up for this kind: refused without running
		CountingVerifier tsig = new CountingVerifier(Boolean.TRUE);
		assertEquals(AuthenticationResult.Status.REFUSED, svr.authenticate(proof("plain", StoredCredentialType.TSIG_SECRET, tsig)).getStatus());
		assertEquals(0, tsig.runs.get());

		// talking to the client failed
		CountingVerifier broken = new CountingVerifier(null);
		assertEquals(AuthenticationResult.Status.REFUSED, svr.authenticate(proof("plain", StoredCredentialType.PLAIN_TEXT, broken)).getStatus());
		assertEquals(1, broken.runs.get());
		assertEquals(Arrays.asList("nobody REFUSED", "nobody REFUSED", "plain REFUSED", "plain REFUSED"), registry.outcomes);
	}

	@Test
	public void madeUpSecrets() {
		Server svr = new Server(0, "MadeUp-" + System.nanoTime());
		StoredCredential scram = svr.makeUpStoredCredential("x", StoredCredentialType.SCRAM_SHA_1);
		assertTrue(scram.getValue() instanceof ScramCredentials);
		assertEquals(((ScramCredentials) scram.getValue()).format(),
				((ScramCredentials) svr.makeUpStoredCredential("x", StoredCredentialType.SCRAM_SHA_1).getValue()).format(), "the same each time");
		assertTrue(svr.makeUpStoredCredential(null, StoredCredentialType.PLAIN_TEXT).getValue() instanceof String);
		assertNull(svr.makeUpStoredCredential("x", StoredCredentialType.SSH_PUBLIC_KEYS));
	}

	@Test
	public void outagesAndMissingRegistries() {
		Server svr = new Server(0, "Outage-" + System.nanoTime());
		assertEquals(AuthenticationResult.Status.UNSUPPORTED, svr.authenticate(proof("x", StoredCredentialType.PLAIN_TEXT, new CountingVerifier(Boolean.TRUE))).getStatus());
		assertEquals(AuthenticationResult.Status.UNSUPPORTED, svr.probe(proof("x", StoredCredentialType.PLAIN_TEXT, new CountingVerifier(Boolean.TRUE))).getStatus());
		svr.setUserRegistry(TestSasl.down());
		CountingVerifier verifier = new CountingVerifier(Boolean.TRUE);
		assertEquals(AuthenticationResult.Status.UNAVAILABLE, svr.authenticate(proof("x", StoredCredentialType.PLAIN_TEXT, verifier)).getStatus());
		assertEquals(AuthenticationResult.Status.UNAVAILABLE, svr.probe(proof("x", StoredCredentialType.PLAIN_TEXT, verifier)).getStatus());
		assertEquals(0, verifier.runs.get());
	}

	// ------------------------------------------------------------------ a session logs in through the server

	private static ICommand command(String name, boolean requiresAuthorization, ServerTestSupport.CommandBody body) {
		return ServerTestSupport.command(name, requiresAuthorization, body);
	}

	@Test
	public void aSessionLogsInThroughTheServer() throws Exception {
		ServerTestSupport.useTestHome();
		Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		commands.put("Whoami", command("Whoami", false, new ServerTestSupport.CommandBody() {
			@Override
			public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
				Requester requester = processor.getRequester();
				ParleyPrincipal principal = processor.getPrincipal();
				processor.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, (principal == null ? "nobody" : principal.getName())
						+ " " + requester.isSecure() + " " + requester.getServerName() + " " + requester.getMethods());
			}
		}));
		commands.put("Logout", command("Logout", false, new ServerTestSupport.CommandBody() {
			@Override
			public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
				processor.logout();
				processor.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, "bye");
			}
		}));
		TestServer svr = ServerTestSupport.create("DoorServer", commands, ServerTestSupport.serverContext());
		svr.setUserRegistry(ServerTestSupport.registry("bob, bobpw, Secret", "eve, evepw, Echo"));
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEquals("nobody false DoorServer []", whoami(client));
			assertEquals(500, client.executeCommand(ServerTestSupport.SECRET).getResponseCode(), "not logged in");

			assertEquals(200, client.executeCommand(ServerTestSupport.LOGIN, "bob", "bobpw").getResponseCode());
			assertEquals("bob false DoorServer [password]", whoami(client));
			assertEquals(200, client.executeCommand(ServerTestSupport.SECRET).getResponseCode());

			// a failed login leaves the session as it was
			assertEquals(400, client.executeCommand(ServerTestSupport.LOGIN, "eve", "wrong").getResponseCode());
			assertEquals("bob false DoorServer [password]", whoami(client));

			// STARTTLS: the requester says so, and the login stays
			client.setTrustAllCertificates(true);
			assertEquals(220, client.executeCommand(ServerTestSupport.START_TLS).getResponseCode());
			client.negotiateSecureSocket("TLS");
			assertEquals("bob true DoorServer [password]", whoami(client));

			assertEquals(200, client.executeCommand("Logout").getResponseCode());
			assertEquals("nobody true DoorServer []", whoami(client));
			assertEquals(500, client.executeCommand(ServerTestSupport.SECRET).getResponseCode(), "logged out");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	private static String whoami(CommandClient client) throws IOException {
		ICommandResponse resp = client.executeCommand("Whoami");
		assertNotNull(resp);
		assertEquals(200, resp.getResponseCode(), resp.toString());
		return resp.getResponseText();
	}
}
