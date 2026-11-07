package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.client.ICommandResponse;
import us.bringardner.parley.net.server.ICommand;

/**
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
public class TestLoginLimits {

	private static final int DELAY = 300;
	/** A login refused by the protocol itself (refuseLogin), as for text SASLprep can't prepare */
	private static final String REFUSE = "Refuse";

	/** @return the next line, or null if the connection was closed or reset */
	private static String readOrNull(CommandClient client) {
		try {
			return client.readLine();
		} catch (IOException e) {
			return null;
		}
	}

	private static TestServer server(String name) {
		Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		commands.put(REFUSE, ServerTestSupport.command(REFUSE, false, new ServerTestSupport.CommandBody() {
			@Override
			public void execute(us.bringardner.parley.net.server.ICommandProcessor p, us.bringardner.parley.net.server.IRequestContext c) throws IOException {
				p.refuseLogin("refused before the registry");
				p.reply(400, "User not identified");
			}
		}));
		TestServer svr = ServerTestSupport.create(name+"-"+System.nanoTime(), commands, null);
		svr.setUserRegistry(ServerTestSupport.registry("alice, secret, Secret"));
		svr.setMaxLoginAttempts(3);
		svr.setLoginFailureDelay(DELAY);
		return ServerTestSupport.start(svr);
	}

	/** @return how long the command took, in milliseconds */
	private static long timed(CommandClient client, String... words) throws IOException {
		long start = System.currentTimeMillis();
		ICommandResponse resp = client.executeCommand(words);
		long took = System.currentTimeMillis()-start;
		if( words[0].equals(ServerTestSupport.LOGIN) && words[2].equals("secret") ) {
			assertTrue(resp.isPositive(), resp.toString());
		}
		return took;
	}

	/** Rule 8: a refused login is answered late; a good one is not, and starts the count again. */
	@Test
	public void theFrameworkWaitsAndCounts() throws Exception {
		TestServer svr = server("Limits");
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertTrue(timed(client, ServerTestSupport.LOGIN, "alice", "wrong") >= DELAY, "a refusal waits");
			assertTrue(timed(client, ServerTestSupport.LOGIN, "alice", "wrong") >= DELAY);
			assertTrue(timed(client, ServerTestSupport.LOGIN, "alice", "secret") < DELAY, "a good login doesn't wait");
			// the count started again: two more refusals keep the connection open
			timed(client, ServerTestSupport.LOGIN, "alice", "wrong");
			timed(client, ServerTestSupport.LOGIN, "alice", "wrong");
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, "still here").isPositive());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** Rule 8: the third refusal is answered, then the connection is closed. */
	@Test
	public void tooManyClosesAfterTheReply() throws Exception {
		TestServer svr = server("TooMany");
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			timed(client, ServerTestSupport.LOGIN, "alice", "wrong");
			timed(client, ServerTestSupport.LOGIN, "alice", "wrong");
			ICommandResponse last = client.executeCommand(ServerTestSupport.LOGIN, "alice", "wrong");
			assertEquals("User not identified", last.getResponseText().trim(), "the protocol's own reply comes first");
			assertNull(readOrNull(client), "then the connection is closed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** Rules 6 and 8: an outage is not counted, not delayed, and not reported as "not authorized". */
	@Test
	public void anOutageIsNotAFailure() throws Exception {
		TestServer svr = server("Outage");
		svr.setUserRegistry(TestSasl.down());
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			for (int i = 0; i < 5; i++) {
				assertTrue(timed(client, ServerTestSupport.LOGIN, "alice", "wrong") < DELAY, "not delayed");
			}
			ICommandResponse secret = client.executeCommand(ServerTestSupport.SECRET);
			assertEquals(400, secret.getResponseCode(), secret.toString());
			assertTrue(!secret.getResponseText().contains(" refused: "), secret.toString());
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, "still here").isPositive(), "not closed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** Rule 6: a real denial is still "not authorized". */
	@Test
	public void aDenialIsNotAuthorized() throws Exception {
		TestServer svr = server("Denied");
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			ICommandResponse secret = client.executeCommand(ServerTestSupport.SECRET);
			assertEquals(500, secret.getResponseCode(), secret.toString());
			assertTrue(secret.getResponseText().contains(" refused: "), secret.toString());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** A login the protocol refuses itself (refuseLogin) waits and counts like a wrong password. */
	@Test
	public void aRefusalByTheProtocolCounts() throws Exception {
		TestServer svr = server("Refuse");
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			long start = System.currentTimeMillis();
			assertEquals(400, client.executeCommand(REFUSE).getResponseCode());
			assertTrue(System.currentTimeMillis()-start >= DELAY, "a refusal waits");
			timed(client, ServerTestSupport.LOGIN, "alice", "wrong");
			ICommandResponse last = client.executeCommand(REFUSE);
			assertEquals("User not identified", last.getResponseText().trim(), "the protocol's own reply comes first");
			assertNull(readOrNull(client), "the third refusal closes the connection");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}
}
