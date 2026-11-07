package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.CloseReason;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IRequestContext;

/** A server that stops while a session is in the middle of a reply says goodbye after the reply, not inside it. */
public class GoodbyeAfterReplyTest {

	@Test
	public void theGoodbyeComesAfterTheReplyBeingWritten() throws Exception {
		final CountDownLatch halfWay = new CountDownLatch(1);
		final Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		commands.put("Slow", ServerTestSupport.command("Slow", false, new ServerTestSupport.CommandBody() {
			@Override
			public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
				// a reply of two lines, held together, with a pause in the middle
				ReentrantLock lock = processor.getOutputLock();
				lock.lock();
				try {
					processor.reply("250-first");
					halfWay.countDown();
					pause(500);
					processor.reply("250 last");
				} finally {
					lock.unlock();
				}
			}
		}));
		TestServer svr = new TestServer("GoodbyeServer");
		svr.setAcceptTimeout(200);
		svr.setConnectionFactory(socket -> new Connection(socket, true) {
			@Override
			public javax.net.ssl.SSLContext getSSLContext(String sslOrTsl) throws IOException {
				throw new IOException("no TLS in this test");
			}
		});
		svr.setProcessorFactory(() -> new AbstractCommandProcessor() {
			private static final long serialVersionUID = 1L;

			@Override
			public String translateResponseCode(int code) {
				return "" + code;
			}

			@Override
			public ICommandFactory getCommandFactory() {
				return context -> {
					String name = context.getNextToken();
					return name == null ? null : commands.get(name);
				};
			}

			@Override
			public void replyClosing(CloseReason reason) throws IOException {
				reply("421 bye");
			}
		});
		ServerTestSupport.start(svr);
		try (Socket s = new Socket("localhost", svr.getLocalPort())) {
			s.setSoTimeout(10000);
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
			OutputStream out = s.getOutputStream();
			out.write("Slow\r\n".getBytes(StandardCharsets.UTF_8));
			out.flush();
			assertTrue(halfWay.await(10, TimeUnit.SECONDS), "the reply started");
			Thread stopper = new Thread(new Runnable() {
				@Override
				public void run() {
					svr.stop();
				}
			});
			stopper.start();

			List<String> after = new ArrayList<String>();
			String line;
			boolean started = false;
			while( (line = in.readLine()) != null ) {
				if( line.equals("250-first") ) {
					started = true; // anything before it is the greeting
				}
				if( started ) {
					after.add(line);
				}
			}
			stopper.join(10000);
			assertEquals(List.of("250-first", "250 last", "421 bye"), after);
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** Wait, even if the thread is interrupted (as a stopping server may do). */
	private static void pause(long millis) {
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
		long left;
		while( (left = end - System.nanoTime()) > 0 ) {
			LockSupport.parkNanos(left);
		}
	}
}
