package us.bringardner.parley.net.nio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.net.ServerTestSupport;

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
public class NioLoginLimitsTest {

	private static final int DELAY = 300;

	private NioServer server;

	@AfterEach
	public void tearDown() throws InterruptedException {
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	/** LOGIN user password, ECHO text; a goodbye line when there were too many failed logins. */
	private static class LoginHandler implements INioHandler {
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
			} else if( words[0].equals("REFUSE") ) {
				// refused by the protocol itself, before the registry
				connection.refuseLogin("refused before the registry");
				connection.writeLine("500 refused");
			} else {
				connection.writeLine("200 "+String.join(" ", words));
			}
		}

		@Override
		public void onTooManyLoginFailures(INioConnection connection) throws Exception {
			connection.writeLine("421 goodbye");
		}
	}

	private Socket start(int loginTimeLimit) throws IOException {
		server = new NioServer(0, "nio-login-"+System.nanoTime());
		server.setHandlerFactory(LoginHandler::new);
		server.setDecoderFactory(LineFrameDecoder::new);
		server.setUserRegistry(ServerTestSupport.registry("alice, secret, echo"));
		server.setMaxLoginAttempts(3);
		server.setLoginFailureDelay(DELAY);
		server.setLoginTimeLimit(loginTimeLimit);
		server.startAndWait(5000);
		Socket socket = new Socket("localhost", server.getLocalPort());
		socket.setSoTimeout(5000);
		return socket;
	}

	private static String send(Socket socket, BufferedReader in, String line) throws IOException {
		OutputStream out = socket.getOutputStream();
		out.write((line+"\r\n").getBytes(StandardCharsets.UTF_8));
		out.flush();
		return in.readLine();
	}

	private static long timedLogin(Socket socket, BufferedReader in, String password, String expected) throws IOException {
		long start = System.currentTimeMillis();
		assertEquals(expected, send(socket, in, "LOGIN alice "+password));
		return System.currentTimeMillis()-start;
	}

	/** The reply to a refused login is held for the delay; a good login isn't, and starts the count again. */
	@Test
	public void refusalsAreHeldAndCounted() throws Exception {
		try (Socket socket = start(0)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			assertTrue(timedLogin(socket, in, "wrong", "500 failed") >= DELAY-20, "held");
			assertTrue(timedLogin(socket, in, "wrong", "500 failed") >= DELAY-20);
			assertTrue(timedLogin(socket, in, "secret", "200 ok") < DELAY, "not held");
			timedLogin(socket, in, "wrong", "500 failed");
			timedLogin(socket, in, "wrong", "500 failed");
			assertEquals("200 ECHO still here", send(socket, in, "ECHO still here"));
		}
	}

	/** Guesses sent together are still answered one delay apart. */
	@Test
	public void pipelinedGuessesWaitEachTime() throws Exception {
		try (Socket socket = start(0)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			long start = System.currentTimeMillis();
			OutputStream out = socket.getOutputStream();
			out.write("LOGIN alice a\r\nLOGIN alice b\r\n".getBytes(StandardCharsets.UTF_8));
			out.flush();
			assertEquals("500 failed", in.readLine());
			assertEquals("500 failed", in.readLine());
			assertTrue(System.currentTimeMillis()-start >= 2*DELAY-40, "each guess waited");
		}
	}

	/** After the third refusal: its reply, the protocol's goodbye, then the connection is closed. */
	@Test
	public void tooManyClosesAfterTheReply() throws Exception {
		try (Socket socket = start(0)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			timedLogin(socket, in, "wrong", "500 failed");
			timedLogin(socket, in, "wrong", "500 failed");
			timedLogin(socket, in, "wrong", "500 failed");
			assertEquals("421 goodbye", in.readLine());
			assertNull(in.readLine(), "closed");
		}
	}

	/** A connection nobody logs in to within the time limit is closed. */
	@Test
	public void loginTimeLimit() throws Exception {
		try (Socket socket = start(300)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			long start = System.currentTimeMillis();
			assertNull(in.readLine(), "closed");
			assertTrue(System.currentTimeMillis()-start < 3000);
		}
		try (Socket socket = start(300)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			timedLogin(socket, in, "secret", "200 ok");
			Thread.sleep(600);
			assertEquals("200 ECHO logged in", send(socket, in, "ECHO logged in"), "stays open");
		}
	}

	/** A login the protocol refuses itself (refuseLogin) is held and counted like a wrong password. */
	@Test
	public void aRefusalByTheProtocolIsHeldAndCounted() throws Exception {
		try (Socket socket = start(0)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("220 ready", in.readLine());
			long start = System.currentTimeMillis();
			assertEquals("500 refused", send(socket, in, "REFUSE"));
			assertTrue(System.currentTimeMillis()-start >= DELAY-20, "held");
			timedLogin(socket, in, "wrong", "500 failed");
			assertEquals("500 refused", send(socket, in, "REFUSE"));
			assertEquals("421 goodbye", in.readLine());
			assertNull(in.readLine(), "closed after the third refusal");
		}
	}
}
