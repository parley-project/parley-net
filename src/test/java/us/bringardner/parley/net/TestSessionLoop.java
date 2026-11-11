package us.bringardner.parley.net;

import us.bringardner.parley.core.LogLevel;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.IRequestContext;

/**
 * The session loop's hooks (AbstractCommandProcessor.run): a protocol's greeting, its own reading
 * of requests, afterRequest after each one, isSessionEnding to end a session without stop(), and
 * sessionEnded once however the session ends. Debug logging is on, as it once moved the request's
 * token position so the wrong command ran.
 */
public class TestSessionLoop {

	/** Released at the end of a test, so a "Stuck" command returns. */
	private static volatile java.util.concurrent.CountDownLatch stuck = new java.util.concurrent.CountDownLatch(1);

	/** What the processors of one test server did, counted across their sessions. */
	static class Counts {
		final AtomicInteger requestsRead = new AtomicInteger();
		final AtomicInteger afterRequest = new AtomicInteger();
		final AtomicInteger sessionEnded = new AtomicInteger();
	}

	/**
	 * A server whose sessions greet with "220 hello", read requests through the default reader
	 * (counting them), and end after "Bye" (answered "221 bye") through isSessionEnding.
	 */
	private static TestServer started(String name, Counts counts) {
		Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		// a command that doesn't return until the test lets it (a session stuck in a command)
		commands.put("Stuck", ServerTestSupport.command("Stuck", false, new ServerTestSupport.CommandBody() {
			@Override
			public void execute(us.bringardner.parley.net.server.ICommandProcessor processor, IRequestContext context) {
				try {
					stuck.await(10, java.util.concurrent.TimeUnit.SECONDS);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		}));
		TestServer svr = ServerTestSupport.create(name, commands, null);
		svr.setProcessorFactory(() -> new AbstractCommandProcessor() {
			private static final long serialVersionUID = 1L;
			private boolean ending;

			{
				// debug logging on: the loop's debug lines must not change which command runs
				setLogLevel(us.bringardner.parley.core.LogLevel.DEBUG);
			}

			@Override
			public String translateResponseCode(int code) {
				return "" + code;
			}

			@Override
			public ICommandFactory getCommandFactory() {
				return new ICommandFactory() {
					private static final long serialVersionUID = 1L;

					@Override
					public ICommand getCommand(IRequestContext context) {
						String command = context.getNextToken();
						return command == null ? null : commands.get(command);
					}
				};
			}

			@Override
			protected void sendGreeting() throws IOException {
				reply("220 hello");
			}

			@Override
			protected IRequestContext readRequest() throws IOException {
				IRequestContext request = super.readRequest();
				if( request != null ) {
					counts.requestsRead.incrementAndGet();
				}
				return request;
			}

			@Override
			protected void runRequest(IRequestContext request) throws IOException {
				// the line, not getFirstToken(): that would move the token position the command factory reads from
				if( "Bye".equals(request.getCommandLine().trim()) ) {
					reply("221 bye");
					ending = true;
				} else {
					super.runRequest(request);
				}
			}

			@Override
			protected void afterRequest() {
				counts.afterRequest.incrementAndGet();
			}

			@Override
			protected boolean isSessionEnding() {
				return ending;
			}

			@Override
			protected void sessionEnded() {
				counts.sessionEnded.incrementAndGet();
			}
		});
		return ServerTestSupport.start(svr);
	}

	/** Connect, and read the protocol's greeting (the test client doesn't expect one). */
	private static CommandClient greeted(TestServer svr) throws IOException {
		CommandClient client = ServerTestSupport.connect(svr);
		assertEquals("220 hello", client.readLine());
		return client;
	}

	private static String readOrNull(CommandClient client) {
		try {
			return client.readLine();
		} catch (IOException e) {
			return null;
		}
	}

	@Test
	public void theProtocolsHooksRunInOrder() throws Exception {
		Counts counts = new Counts();
		TestServer svr = started("LoopHooksServer", counts);
		try (CommandClient client = greeted(svr)) {
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "one" }).isPositive());
			// a failed command is answered and the session goes on
			assertEquals(500, client.executeCommand(ServerTestSupport.FAIL).getResponseCode());
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "two" }).isPositive());
			assertEquals(221, client.executeCommand("Bye").getResponseCode());
			// isSessionEnding: no more requests are read, and the connection is closed
			assertNull(readOrNull(client), "closed after Bye");
			ServerTestSupport.waitFor(() -> counts.sessionEnded.get() == 1, 5000, "sessionEnded not called");
			assertEquals(4, counts.requestsRead.get());
			assertEquals(4, counts.afterRequest.get());
			ServerTestSupport.waitFor(() -> svr.getActiveClients().isEmpty(), 5000, "session not removed");
		} finally {
			ServerTestSupport.stop(svr);
		}
		assertEquals(1, counts.sessionEnded.get(), "sessionEnded runs once");
	}

	@Test
	public void sessionEndedRunsWhenTheClientLeaves() throws Exception {
		Counts counts = new Counts();
		TestServer svr = started("LoopClientLeavesServer", counts);
		try {
			try (CommandClient client = greeted(svr)) {
				assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
			}
			// the client closed the connection without a goodbye
			ServerTestSupport.waitFor(() -> counts.sessionEnded.get() == 1, 5000, "sessionEnded not called");
			ServerTestSupport.waitFor(() -> svr.getActiveClients().isEmpty(), 5000, "session not removed");
		} finally {
			ServerTestSupport.stop(svr);
		}
		assertEquals(1, counts.sessionEnded.get(), "sessionEnded runs once");
	}

	@Test
	public void sessionEndedRunsWhenTheServerStops() throws Exception {
		Counts counts = new Counts();
		TestServer svr = started("LoopServerStopsServer", counts);
		try (CommandClient client = greeted(svr)) {
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
			ServerTestSupport.stop(svr);
			ServerTestSupport.waitFor(() -> counts.sessionEnded.get() == 1, 5000, "sessionEnded not called");
		}
		assertEquals(1, counts.sessionEnded.get(), "sessionEnded runs once");
	}

	@Test
	public void anIdleSessionEndsItselfWithoutTheAdminCheck() throws Exception {
		Counts counts = new Counts();
		TestServer svr = started("LoopIdleServer", counts);
		try (CommandClient client = greeted(svr)) {
			assertTrue(client.executeCommand(ServerTestSupport.ECHO, new String[] { "hi" }).isPositive());
			// the admin check runs every 5 minutes; the session checks itself every second
			svr.setMaxIdleConnection(200);
			long start = System.currentTimeMillis();
			assertNull(readOrNull(client), "the idle session was closed");
			ServerTestSupport.waitFor(() -> counts.sessionEnded.get() == 1, 5000, "sessionEnded not called");
			long took = System.currentTimeMillis() - start;
			assertTrue(took < 3000, "closed after " + took + " ms");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void aSessionStuckInACommandIsClosedByTheAdminCheck() throws Exception {
		stuck = new java.util.concurrent.CountDownLatch(1);
		Counts counts = new Counts();
		TestServer svr = started("LoopStuckServer", counts);
		try (CommandClient client = greeted(svr)) {
			client.writeLine("Stuck");
			client.flush();
			svr.setMaxIdleConnection(100);
			Thread.sleep(1500);
			// the session isn't waiting for a request, so it can't check itself: the server closes it
			assertEquals(1, svr.getActiveClients().size(), "still open before the admin check");
			svr.runAdmin();
			assertNull(readOrNull(client), "the stuck session was closed");
		} finally {
			stuck.countDown();
			ServerTestSupport.stop(svr);
		}
	}
}
