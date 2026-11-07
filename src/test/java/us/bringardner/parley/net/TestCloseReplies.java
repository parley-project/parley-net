package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.CloseReason;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.IRequestContext;

/**
 * The protocol's replies when a command fails unexpectedly (replyCommandFailed) and when the
 * server closes a session on its own (replyClosing), and the defaults that keep the old behaviour.
 */
public class TestCloseReplies {

	/** A server whose sessions answer a failed command with 451 and say goodbye with 421 */
	private static TestServer server(String name, boolean replies) {
		final Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		TestServer svr = ServerTestSupport.create(name, commands, null);
		if( replies ) {
			svr.setProcessorFactory(() -> new AbstractCommandProcessor() {
				private static final long serialVersionUID = 1L;

				@Override
				public String translateResponseCode(int code) {
					return "" + code;
				}

				@Override
				public ICommandFactory getCommandFactory() {
					return new ICommandFactory() {
						@Override
						public ICommand getCommand(IRequestContext context) {
							String command = context.getNextToken();
							return command == null ? null : commands.get(command);
						}
					};
				}

				@Override
				protected void replyCommandFailed(IRequestContext request) throws IOException {
					reply(451, request.getFirstToken() + " failed: local error");
				}

				@Override
				public void replyClosing(CloseReason reason) throws IOException {
					reply(421, "closing: " + reason);
				}
			});
		}
		return svr;
	}

	private static TestServer started(String name, boolean replies) {
		return ServerTestSupport.start(server(name, replies));
	}

	private static String readOrNull(CommandClient client) {
		try {
			return client.readLine();
		} catch (IOException e) {
			return null;
		}
	}

	@Test
	public void aFailedCommandGetsTheProtocolsReply() throws Exception {
		TestServer svr = started("FailedServer", true);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			us.bringardner.parley.net.client.ICommandResponse failed = client.executeCommand(ServerTestSupport.FAIL);
			assertEquals(451, failed.getResponseCode());
			assertEquals("Fail failed: local error", failed.getResponseText().trim());
			// the session goes on
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void theDefaultsAreUnchanged() throws Exception {
		TestServer svr = started("DefaultServer", false);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			us.bringardner.parley.net.client.ICommandResponse failed = client.executeCommand(ServerTestSupport.FAIL);
			assertEquals(500, failed.getResponseCode());
			assertFalse(failed.getResponseText().contains(ServerTestSupport.FAIL_DETAIL), failed.getResponseText());
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
			svr.setMaxIdleConnection(50);
			Thread.sleep(200);
			svr.runAdmin();
			// no goodbye: just closed
			assertNull(readOrNull(client), "closed without a reply");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void anIdleSessionIsToldWhy() throws Exception {
		TestServer svr = started("IdleGoodbyeServer", true);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
			svr.setMaxIdleConnection(50);
			Thread.sleep(200);
			svr.runAdmin();
			assertEquals("421 closing: IDLE", readOrNull(client));
			assertNull(readOrNull(client), "then closed");
			ServerTestSupport.waitFor(() -> svr.getActiveClients().isEmpty(), 5000, "idle client not removed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void noLoginInTimeIsToldWhy() throws Exception {
		TestServer svr = server("LoginGoodbyeServer", true);
		svr.setUserRegistry(ServerTestSupport.registry("bob, bobpw, Secret"));
		svr.setLoginTimeLimit(300);
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEquals("421 closing: LOGIN_TIME_LIMIT", readOrNull(client));
			assertNull(readOrNull(client), "then closed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void stoppingTheServerSaysGoodbyeToEverySession() throws Exception {
		TestServer svr = started("StopGoodbyeServer", true);
		try (CommandClient a = ServerTestSupport.connect(svr); CommandClient b = ServerTestSupport.connect(svr)) {
			assertTrue(a.executeCommand(ServerTestSupport.ECHO, new String[] { "a" }).isPositive());
			assertTrue(b.executeCommand(ServerTestSupport.ECHO, new String[] { "b" }).isPositive());
			ServerTestSupport.stop(svr);
			assertEquals("421 closing: SERVER_STOPPING", readOrNull(a));
			assertEquals("421 closing: SERVER_STOPPING", readOrNull(b));
			assertNull(readOrNull(a));
		}
	}
}
