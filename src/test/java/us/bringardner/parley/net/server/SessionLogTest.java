package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.net.ServerTestSupport;

/** The words of the standard session lines (To-Do 19.7). */
public class SessionLogTest {

	@Test
	public void ids() {
		assertEquals("Pop3Server-4127", SessionLog.id("Pop3Server", 4127));
		assertEquals("session-1", SessionLog.id(null, 1));
		assertEquals("session-1", SessionLog.id("", 1));
		String one = SessionLog.nextId("A");
		String two = SessionLog.nextId("A");
		assertNotEquals(one, two);
	}

	@Test
	public void connected() throws Exception {
		InetAddress a = InetAddress.getByAddress(new byte[] {(byte) 203, 0, 113, 9});
		assertEquals("Connected from 203.0.113.9:51234", SessionLog.connected(a, 51234));
		assertEquals("Connected from 203.0.113.9", SessionLog.connected(a, 0));
		assertEquals("Connected from unknown", SessionLog.connected(null, 0));
		assertEquals("Connected from 203.0.113.9:25", SessionLog.connected(new InetSocketAddress(a, 25)));
		assertEquals("Connected from unknown", SessionLog.connected(null));
	}

	@Test
	public void logins() {
		PasswordCredential wrong = new PasswordCredential("alice", "x".toCharArray(), ServerTestSupport.requester());
		assertEquals("Login failed for alice: wrong password", SessionLog.login(wrong, AuthenticationResult.refused("wrong password")));
		assertEquals("Login failed: no such user", SessionLog.login(null, AuthenticationResult.refused("no such user")));
		assertEquals("Login failed", SessionLog.login(null, null));
		assertEquals("Login refused: TLS is required", SessionLog.loginRefused("TLS is required"));
		assertEquals("Login refused", SessionLog.loginRefused(null));
		//  a client can't start a log line of its own with its user name
		PasswordCredential forged = new PasswordCredential("al\r\nINFO forged", "x".toCharArray(), ServerTestSupport.requester());
		assertEquals("Login failed for al??INFO forged: no", SessionLog.login(forged, AuthenticationResult.refused("no")));
	}

	@Test
	public void disconnected() {
		assertEquals("Disconnected (idle) after 264ms", SessionLog.disconnected(SessionLog.REASON_IDLE, 264));
		assertEquals("Disconnected (session ended) after 0ms", SessionLog.disconnected(null, -5));
		assertEquals("12.3s", SessionLog.duration(12_345));
		assertEquals("5m 12s", SessionLog.duration(312_000));
		assertEquals("2h 5m", SessionLog.duration(7_500_000));
		assertEquals("idle", SessionLog.reason(CloseReason.IDLE));
		assertEquals("login time limit", SessionLog.reason(CloseReason.LOGIN_TIME_LIMIT));
		assertEquals("server stopping", SessionLog.reason(CloseReason.SERVER_STOPPING));
		assertNull(SessionLog.reason(null));
	}

	@Test
	public void clean() {
		assertNull(SessionLog.clean(null));
		assertEquals("plain", SessionLog.clean("plain"));
		assertEquals("a?b?", SessionLog.clean("a\tb\u007f"));
		String longName = "x".repeat(250);
		assertEquals("x".repeat(200)+"...", SessionLog.clean(longName));
		assertEquals("?"+"x".repeat(199)+"...", SessionLog.clean("\n"+longName));
	}
}
