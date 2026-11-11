package us.bringardner.parley.net.nio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.core.LogContext;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.net.LogCapture;
import us.bringardner.parley.net.ServerTestSupport;

/**
 * To-Do 19.7 for the NIO server: one thread serves many connections, so the session's ID is set
 * for each call into a connection's handler and cleared after it.
 */
public class NioSessionLogTest {

	private NioServer server;
	private ExecutorService executor;

	@AfterEach
	public void tearDown() throws InterruptedException {
		if( server != null ) {
			server.stop(5000, false);
		}
		if( executor != null ) {
			executor.shutdownNow();
			executor.awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	/** Something else that logs while it works for a connection. */
	static class Helper extends BaseObject {
	}

	private static class Handler implements INioHandler {
		@Override
		public void onConnect(INioConnection connection) throws Exception {
			connection.writeLine("220 ready");
		}

		@Override
		public void onMessage(INioConnection connection, ByteBuffer frame) throws Exception {
			String[] words = LineFrameDecoder.toString(frame).split(" ");
			if( words[0].equals("LOGIN") && words.length == 3 ) {
				AuthenticationResult result = connection.authenticate(
						new PasswordCredential(words[1], words[2].toCharArray(), connection.getRequester()));
				connection.writeLine(result.getStatus() == AuthenticationResult.Status.AUTHENTICATED ? "200 ok" : "500 failed");
			} else if( words[0].equals("WORK") ) {
				new Helper().logInfo("helper working");
				connection.writeLine("200 done");
			} else {
				//  WHO: the ID this thread works with during the call
				connection.writeLine("200 "+LogContext.get());
			}
		}
	}

	private void start(String name, boolean withExecutor) throws IOException {
		server = new NioServer(0, name);
		server.setHandlerFactory(Handler::new);
		server.setDecoderFactory(LineFrameDecoder::new);
		server.setUserRegistry(ServerTestSupport.registry("alice, secret, echo"));
		server.setLoginFailureDelay(0);
		//  one reactor thread, so both test connections are served by the same thread
		server.setReactorCount(1);
		if( withExecutor ) {
			executor = Executors.newFixedThreadPool(2);
			server.setHandlerExecutor(executor);
		}
		server.startAndWait(5000);
	}

	private Socket connect() throws IOException {
		Socket socket = new Socket("localhost", server.getLocalPort());
		socket.setSoTimeout(5000);
		return socket;
	}

	private static BufferedReader reader(Socket socket) throws IOException {
		return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
	}

	private static String send(Socket socket, BufferedReader in, String line) throws IOException {
		OutputStream out = socket.getOutputStream();
		out.write((line+"\r\n").getBytes(StandardCharsets.UTF_8));
		out.flush();
		return in.readLine();
	}

	private void sessionLines(boolean withExecutor) throws Exception {
		String name = "NioLog"+System.nanoTime();
		start(name, withExecutor);
		try (LogCapture log = new LogCapture()) {
			String id;
			String other;
			try (Socket a = connect(); Socket b = connect()) {
				BufferedReader inA = reader(a);
				BufferedReader inB = reader(b);
				assertEquals("220 ready", inA.readLine());
				assertEquals("220 ready", inB.readLine());
				//  the same thread(s) serve both connections; each call has its own connection's ID
				id = send(a, inA, "WHO").substring(4);
				other = send(b, inB, "WHO").substring(4);
				assertTrue(id.startsWith(name+"-"), id);
				assertTrue(other.startsWith(name+"-"), other);
				assertNotEquals(id, other);
				assertEquals(id, send(a, inA, "WHO").substring(4));
				assertEquals(other, send(b, inB, "WHO").substring(4));

				assertEquals("500 failed", send(a, inA, "LOGIN alice wrong"));
				assertEquals("200 ok", send(a, inA, "LOGIN alice secret"));
				assertEquals("200 done", send(a, inA, "WORK"));
				assertEquals("200 done", send(b, inB, "WORK"));
			}
			String prefix = "["+id+"] ";
			ServerTestSupport.waitFor(() -> log.first(prefix+"Disconnected") != null, 5000, "no disconnect line for "+id);
			ServerTestSupport.waitFor(() -> log.first("["+other+"] Disconnected") != null, 5000, "no disconnect line for "+other);
			List<String> lines = log.containing(prefix);
			assertEquals(5, lines.size(), lines.toString());
			assertTrue(lines.get(0).startsWith("INFO "+prefix+"Connected from 127.0.0.1:"), lines.get(0));
			assertTrue(lines.get(1).startsWith("INFO "+prefix+"Login failed for alice"), lines.get(1));
			assertTrue(lines.get(2).startsWith("INFO "+prefix+"Login alice"), lines.get(2));
			assertEquals("INFO "+prefix+"helper working", lines.get(3));
			assertTrue(lines.get(4).startsWith("INFO "+prefix+"Disconnected (client closed the connection) after "), lines.get(4));

			//  the other connection's lines are its own
			List<String> others = log.containing("["+other+"] ");
			assertEquals(3, others.size(), others.toString());
			assertEquals("INFO ["+other+"] helper working", others.get(1));
		}
	}

	@Test
	public void everyLineOfAConnectionStartsWithItsIdOnTheReactorThread() throws Exception {
		sessionLines(false);
	}

	@Test
	public void everyLineOfAConnectionStartsWithItsIdOnAHandlerExecutor() throws Exception {
		sessionLines(true);
	}

	@Test
	public void theReactorThreadKeepsNoIdBetweenCalls() throws Exception {
		String name = "NioClear"+System.nanoTime();
		start(name, false);
		try (Socket a = connect()) {
			BufferedReader in = reader(a);
			assertEquals("220 ready", in.readLine());
			assertTrue(send(a, in, "WHO").startsWith("200 "+name+"-"));
			//  work the reactor thread does for nobody has no ID: the handler call's was cleared
			java.util.concurrent.CompletableFuture<String> seen = new java.util.concurrent.CompletableFuture<>();
			//  (the server keeps its reactors to itself, so the test reaches for the field)
			java.lang.reflect.Field field = NioServer.class.getDeclaredField("reactors");
			field.setAccessible(true);
			NioReactor reactor = ((NioReactor[]) field.get(server))[0];
			reactor.execute(() -> seen.complete(String.valueOf(LogContext.get())));
			assertEquals("null", seen.get(5, TimeUnit.SECONDS));
		}
	}
}
