package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.client.ICommandResponse;

/**
 * Connection management: max clients, idle connection cleanup, start / stop, client connect failures.
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
public class TestServerLimits {

	private static void assertEcho(CommandClient client) throws IOException {
		ICommandResponse resp = client.executeCommand(ServerTestSupport.ECHO, "hi");
		assertTrue(resp.isPositive(), resp.toString());
	}

	/** @return the next line, or null if the connection was closed or reset */
	private static String readOrNull(CommandClient client) {
		try {
			return client.readLine();
		} catch (IOException e) {
			return null;
		}
	}

	@Test
	public void testMaxClientsRejectsWithBusyMessage() throws Exception {
		TestServer svr = ServerTestSupport.create("LimitServer", ServerTestSupport.standardCommands(), null);
		svr.setMaxClients(1);
		svr.setServerBusyMessage("421 too many connections");
		ServerTestSupport.start(svr);
		try {
			CommandClient first = ServerTestSupport.connect(svr);
			assertEcho(first);

			try (CommandClient second = ServerTestSupport.connect(svr)) {
				assertEquals("421 too many connections", second.readLine());
				assertNull(readOrNull(second), "rejected connection should be closed");
			}

			// Once the first client leaves there is room again
			first.close();
			ServerTestSupport.waitFor(() -> svr.getActiveClients().isEmpty(), 5000, "first client not removed");
			try (CommandClient third = ServerTestSupport.connect(svr)) {
				assertEcho(third);
			}
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testOneAddressCantTakeEveryPlace() throws Exception {
		TestServer svr = ServerTestSupport.create("PerClientServer", ServerTestSupport.standardCommands(), null);
		svr.setMaxClients(10);
		svr.setMaxConnectionsPerClient(2);
		svr.setServerBusyMessage("421 too many connections");
		ServerTestSupport.start(svr);
		try {
			CommandClient first = ServerTestSupport.connect(svr);
			assertEcho(first);
			try (CommandClient second = ServerTestSupport.connect(svr)) {
				assertEcho(second);
				try (CommandClient third = ServerTestSupport.connect(svr)) {
					assertEquals("421 too many connections", third.readLine(), "a third from the same address");
					assertNull(readOrNull(third));
				}
			}
			//  a session that ends gives its place back
			ServerTestSupport.waitFor(() -> svr.getClientConnections(java.net.InetAddress.getLoopbackAddress()) == 1, 5000, "place not given back");
			try (CommandClient again = ServerTestSupport.connect(svr)) {
				assertEcho(again);
			}
			first.close();
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testAddressesNotOnTheAllowListAreRefused() throws Exception {
		TestServer svr = ServerTestSupport.create("AllowListServer", ServerTestSupport.standardCommands(), null);
		svr.setAllowedClients("192.0.2.0/24");
		ServerTestSupport.start(svr);
		try {
			try (CommandClient refused = ServerTestSupport.connect(svr)) {
				assertNull(readOrNull(refused), "closed without a greeting");
			}
			assertEquals(0, svr.getClientConnections(java.net.InetAddress.getLoopbackAddress()));
			svr.setAllowedClients("127.0.0.0/8 ::1");
			try (CommandClient ok = ServerTestSupport.connect(svr)) {
				assertEcho(ok);
			}
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** A non-loopback IPv4 address of this machine, or null */
	private static java.net.InetAddress otherLocalAddress() throws Exception {
		for(java.net.NetworkInterface ni : java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())) {
			if( !ni.isUp() || ni.isLoopback() ) {
				continue;
			}
			for(java.net.InetAddress a : java.util.Collections.list(ni.getInetAddresses())) {
				if( a instanceof java.net.Inet4Address && !a.isLoopbackAddress() ) {
					return a;
				}
			}
		}
		return null;
	}

	@Test
	public void testBindAddressIsUsed() throws Exception {
		java.net.InetAddress other = otherLocalAddress();
		org.junit.jupiter.api.Assumptions.assumeTrue(other != null, "no non-loopback address to test with");
		TestServer svr = ServerTestSupport.create("BindServer", ServerTestSupport.standardCommands(), null);
		svr.setBindAddr(java.net.InetAddress.getLoopbackAddress());
		ServerTestSupport.start(svr);
		try {
			try (CommandClient ok = ServerTestSupport.connect(svr)) {
				assertEcho(ok);
			}
			//  the bind address used to be ignored: the server listened on every interface
			try (java.net.Socket s = new java.net.Socket()) {
				s.connect(new java.net.InetSocketAddress(other, svr.getLocalPort()), 2000);
				org.junit.jupiter.api.Assertions.fail("connected on "+other+" to a server bound to loopback");
			} catch (IOException expected) {
				// refused
			}
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testIdleConnectionsClosed() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("IdleServer", ServerTestSupport.standardCommands(), null));
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			svr.setMaxIdleConnection(50);
			Thread.sleep(200);
			svr.runAdmin();
			assertNull(readOrNull(client), "idle connection should have been closed");
			ServerTestSupport.waitFor(() -> svr.getActiveClients().isEmpty(), 5000, "idle client not removed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testActiveConnectionsSurviveAdmin() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("ActiveServer", ServerTestSupport.standardCommands(), null));
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			svr.runAdmin();
			assertEcho(client);
			assertEquals(1, svr.getActiveClients().size());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testStartAndStop() {
		TestServer svr = ServerTestSupport.create("StartStopServer", ServerTestSupport.standardCommands(), null);
		assertEquals(-1, svr.getLocalPort());
		ServerTestSupport.start(svr);
		assertTrue(svr.getLocalPort() > 0);
		ServerTestSupport.stop(svr);
		assertFalse(svr.isRunning());
	}

	/**
	 * stop() used to only set a flag, so it waited for accept() to time out
	 * (5 s with the default accept timeout).
	 */
	@Test
	public void testStopIsImmediateWithDefaultAcceptTimeout() {
		TestServer svr = ServerTestSupport.create("QuickStopServer", ServerTestSupport.standardCommands(), null);
		svr.setAcceptTimeout(us.bringardner.parley.net.server.Server.DEFAULT_ACCEPT_TIMEOUT);
		ServerTestSupport.start(svr);
		long start = System.currentTimeMillis();
		svr.stop();
		ServerTestSupport.waitFor(() -> !svr.isRunning(), 10000, "server did not stop");
		long elapsed = System.currentTimeMillis() - start;
		assertTrue(elapsed < 1000, "stop() took " + elapsed + " ms");
	}

	/** A stopped server can be started again (it used to reuse its closed server socket). */
	@Test
	public void testRestartAfterStop() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("RestartServer", ServerTestSupport.standardCommands(), null));
		ServerTestSupport.stop(svr);
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testStopClosesClients() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("StopServer", ServerTestSupport.standardCommands(), null));
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			ServerTestSupport.stop(svr);
			assertNull(readOrNull(client), "stop() should close client connections");
		}
	}

	@Test
	public void testConnectFailureReported() throws Exception {
		int port;
		try (ServerSocket tmp = new ServerSocket(0)) {
			port = tmp.getLocalPort();
		}
		// Nothing is listening on port now
		try (CommandClient client = new CommandClient("localhost", port)) {
			assertFalse(client.connect());
			assertFalse(client.isConnected());
			assertNotNull(client.getLastConnectError());
		}
	}

	@Test
	public void testReconnect() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("ReconnectServer", ServerTestSupport.standardCommands(), null));
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			assertTrue(client.connect());
			assertNull(client.getLastConnectError());
			assertEcho(client);
			// The first connection was closed, not leaked
			ServerTestSupport.waitFor(() -> svr.getActiveClients().size() == 1, 5000, "old connection not closed on reconnect");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** @return the server side of the only active client */
	private static java.net.Socket serverSide(TestServer svr) throws Exception {
		ServerTestSupport.waitFor(() -> svr.getActiveClients().size() == 1, 5000, "client not accepted");
		return svr.getActiveClients().keySet().iterator().next();
	}

	@Test
	public void testKeepAliveOffByDefault() throws Exception {
		TestServer svr = ServerTestSupport.create("NoKeepAliveServer", ServerTestSupport.standardCommands(), null);
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			assertFalse(serverSide(svr).getKeepAlive());
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testKeepAlive() throws Exception {
		TestServer svr = ServerTestSupport.create("KeepAliveServer", ServerTestSupport.standardCommands(), null);
		svr.setKeepAlive(true);
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			assertTrue(serverSide(svr).getKeepAlive(), "accepted sockets should have SO_KEEPALIVE");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** loginTimeLimit: a session that hasn't logged in by then is closed, one that has stays */
	@Test
	public void testLoginTimeLimit() throws Exception {
		TestServer svr = ServerTestSupport.create("LoginLimitServer", ServerTestSupport.standardCommands(), null);
		svr.setAccessControl(ServerTestSupport.acl("bob, bobpw, Secret"));
		svr.setLoginTimeLimit(500);
		ServerTestSupport.start(svr);
		try (CommandClient idle = ServerTestSupport.connect(svr); CommandClient user = ServerTestSupport.connect(svr)) {
			assertEcho(idle);
			assertTrue(user.executeCommand(ServerTestSupport.LOGIN, "bob", "bobpw").isPositive());
			Thread.sleep(1000);
			assertNull(readOrNull(idle), "not logged in after the limit: closed");
			assertEcho(user);
			ServerTestSupport.waitFor(() -> svr.getActiveClients().size() == 1, 5000, "closed session not removed");
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	@Test
	public void testNoLoginTimeLimitByDefault() throws Exception {
		TestServer svr = ServerTestSupport.start(ServerTestSupport.create("NoLoginLimitServer", ServerTestSupport.standardCommands(), null));
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEquals(0, svr.getLoginTimeLimit());
			Thread.sleep(300);
			assertEcho(client);
		} finally {
			ServerTestSupport.stop(svr);
		}
	}

	/** A protocol that can be used without logging in has no login time limit */
	@Test
	public void testLoginTimeLimitOnlyWhereLoginIsRequired() throws Exception {
		TestServer svr = new TestServer("AnonymousServer") {
			@Override
			protected boolean isLoginRequired() {
				return false;
			}
		};
		TestServer configured = ServerTestSupport.create("AnonymousServerConfig", ServerTestSupport.standardCommands(), null);
		svr.setProcessorFactory(configured.getProcessorFactory());
		svr.setConnectionFactory(configured.getConnectionFactory());
		svr.setAcceptTimeout(200);
		svr.setLoginTimeLimit(200);
		ServerTestSupport.start(svr);
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEcho(client);
			Thread.sleep(600);
			assertEcho(client);
		} finally {
			ServerTestSupport.stop(svr);
		}
	}
}
