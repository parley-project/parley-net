package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.core.BaseThread;
import us.bringardner.parley.core.LogContext;
import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.server.ICommand;

/**
 * To-Do 19.7: every session of a Server has an ID that is in front of everything logged for it,
 * whichever object logs it, and the server logs when it connects, logs in and disconnects.
 */
public class TestSessionLog {

	private static final String WORK = "Work";
	private static final String TASK = "Task";
	private static final String WHO = "Who";

	/** Something else that logs while it works for a session, as a mail store does. */
	static class Helper extends BaseObject {
	}

	/** A thread a session starts through its server. */
	static class Task extends BaseThread {
		final CountDownLatch done = new CountDownLatch(1);

		@Override
		public void run() {
			new Helper().logInfo("task working");
			done.countDown();
		}
	}

	private static volatile Task lastTask;

	private static TestServer server(String name) {
		Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		commands.put(WORK, ServerTestSupport.command(WORK, false, (p, c) -> {
			new Helper().logInfo("helper working");
			p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, "done");
		}));
		commands.put(WHO, ServerTestSupport.command(WHO, false, (p, c) ->
			p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, String.valueOf(LogContext.get()))));
		commands.put(TASK, ServerTestSupport.command(TASK, false, (p, c) -> {
			Task t = new Task();
			lastTask = t;
			p.getServer().startTask((IProcessor) p, t);
			p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, "started");
		}));
		TestServer svr = ServerTestSupport.create(name, commands, null);
		svr.setUserRegistry(ServerTestSupport.registry("alice, secret, Secret"));
		svr.setLoginFailureDelay(0);
		return ServerTestSupport.start(svr);
	}

	private static List<String> waitForLine(LogCapture log, String text) {
		ServerTestSupport.waitFor(() -> log.first(text) != null, 5000, "not logged: "+text);
		return log.containing(text);
	}

	@Test
	public void everyLineOfASessionStartsWithItsId() throws Exception {
		String name = "SessionLog"+System.nanoTime();
		TestServer svr = server(name);
		try (LogCapture log = new LogCapture()) {
			String id;
			try (CommandClient client = ServerTestSupport.connect(svr)) {
				//  the session's thread works with the ID
				id = client.executeCommand(WHO).getResponseText().trim();
				assertTrue(id.startsWith(name+"-"), id);
				client.executeCommand(ServerTestSupport.LOGIN, "alice", "wrong");
				assertTrue(client.executeCommand(ServerTestSupport.LOGIN, "alice", "secret").isPositive());
				assertTrue(client.executeCommand(WORK).isPositive());
				assertTrue(client.executeCommand(TASK).isPositive());
				assertTrue(lastTask.done.await(5, TimeUnit.SECONDS), "the task ran");
			}
			String prefix = "["+id+"] ";
			waitForLine(log, prefix+"Disconnected");
			List<String> lines = log.containing(prefix);
			//  the task's line may come before or after the lines around it: look at it by itself
			assertEquals(1, log.containing("INFO "+prefix+"task working").size(), lines.toString());
			lines.removeIf(l -> l.contains("task working"));

			assertEquals(5, lines.size(), lines.toString());
			assertTrue(lines.get(0).startsWith("INFO "+prefix+"Connected from 127.0.0.1:"), lines.get(0));
			assertTrue(lines.get(1).startsWith("INFO "+prefix+"Login failed for alice"), lines.get(1));
			assertTrue(lines.get(2).startsWith("INFO "+prefix+"Login alice"), lines.get(2));
			assertEquals("INFO "+prefix+"helper working", lines.get(3));
			assertTrue(lines.get(4).startsWith("INFO "+prefix+"Disconnected (client closed the connection) after "), lines.get(4));
			//  the session is over: the server has forgotten it
			assertEquals(1, log.containing(prefix+"Disconnected").size());
		} finally {
			ServerTestSupport.stop(svr);
		}
		//  nothing is left on the test's own thread
		assertNull(LogContext.get());
	}

	@Test
	public void twoSessionsHaveTwoIds() throws Exception {
		String name = "TwoSessions"+System.nanoTime();
		TestServer svr = server(name);
		try (LogCapture log = new LogCapture();
				CommandClient one = ServerTestSupport.connect(svr);
				CommandClient two = ServerTestSupport.connect(svr)) {
			String first = one.executeCommand(WHO).getResponseText().trim();
			String second = two.executeCommand(WHO).getResponseText().trim();
			assertNotEquals(first, second);
			//  and each keeps its own
			assertEquals(first, one.executeCommand(WHO).getResponseText().trim());
			assertEquals(second, two.executeCommand(WHO).getResponseText().trim());
			assertNotNull(log.first("["+first+"] Connected from"));
			assertNotNull(log.first("["+second+"] Connected from"));
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void aStoppingServerSaysSo() throws Exception {
		String name = "Stopping"+System.nanoTime();
		TestServer svr = server(name);
		try (LogCapture log = new LogCapture(); CommandClient client = ServerTestSupport.connect(svr)) {
			String id = client.executeCommand(WHO).getResponseText().trim();
			ServerTestSupport.stop(svr);
			List<String> lines = waitForLine(log, "["+id+"] Disconnected");
			assertTrue(lines.get(0).contains("Disconnected (server stopping) after "), lines.toString());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}
}
