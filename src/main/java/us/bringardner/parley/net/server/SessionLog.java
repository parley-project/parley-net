/**
 * <PRE>
 *
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
package us.bringardner.parley.net.server;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.ParleyPrincipal;

/**
 * The words of the standard lines every server logs about a session, at INFO: that it connected,
 * each login, and that it disconnected. {@link Server} and the NIO server use the same words, so a
 * log reads the same whichever kind of server wrote it. Each line starts with the session's ID
 * ({@link us.bringardner.parley.core.LogContext}):
 *
 * <pre>
 * [Pop3Server-4127] Connected from 203.0.113.9:51234
 * [Pop3Server-4127] Login tony@bringardner.us (PLAIN)
 * [Pop3Server-4127] Login failed for tony@bringardner.us: wrong password
 * [Pop3Server-4127] Disconnected (client closed the connection) after 264ms
 * </pre>
 *
 * @since 2.0.0
 */
public final class SessionLog {

	/** Why a session ended, when nothing more exact is known: the protocol ended it (QUIT, say). */
	public static final String REASON_SESSION_ENDED = "session ended";
	/** The client ended the session with the protocol's own command (QUIT, LOGOUT). */
	public static final String REASON_CLIENT_QUIT = "client quit";
	public static final String REASON_CLIENT_CLOSED = "client closed the connection";
	public static final String REASON_CONNECTION_LOST = "connection lost";
	public static final String REASON_IDLE = "idle";
	public static final String REASON_LOGIN_TIME_LIMIT = "login time limit";
	public static final String REASON_SERVER_STOPPING = "server stopping";
	public static final String REASON_TOO_MANY_LOGIN_FAILURES = "too many failed logins";
	public static final String REASON_TLS_HANDSHAKE_FAILED = "TLS handshake failed";
	public static final String REASON_LINE_TOO_LONG = "line too long";
	public static final String REASON_TIMEOUT = "timed out";
	public static final String REASON_ERROR = "error";
	public static final String REASON_NOT_STARTED = "could not be started";

	//  One sequence for every thread-per-session server in the JVM, so two servers with the same
	//  name (a POP3 and a POP3S server, say) never give two sessions the same ID
	private static final AtomicLong NUMBERS = new AtomicLong();

	private SessionLog() {
	}

	/**
	 * @param serverName the server's name
	 * @return a new session ID, the name and the next number ({@code Pop3Server-4127})
	 */
	public static String nextId(String serverName) {
		return id(serverName, NUMBERS.incrementAndGet());
	}

	/**
	 * @param serverName the server's name
	 * @param number the session's number
	 * @return the session ID, the name and the number ({@code Pop3Server-4127})
	 */
	public static String id(String serverName, long number) {
		return (serverName == null || serverName.isEmpty() ? "session" : serverName)+"-"+number;
	}

	/**
	 * @param address the client's address, may be null
	 * @param port the client's port, 0 or less to leave it out
	 * @return "Connected from 203.0.113.9:51234"
	 */
	public static String connected(InetAddress address, int port) {
		return "Connected from "+(address == null ? "unknown" : address.getHostAddress())+(port > 0 ? ":"+port : "");
	}

	/**
	 * @param address the client's address, may be null
	 * @return "Connected from 203.0.113.9:51234"
	 */
	public static String connected(SocketAddress address) {
		if( address instanceof InetSocketAddress ) {
			InetSocketAddress a = (InetSocketAddress) address;
			return connected(a.getAddress(), a.getPort());
		}
		return "Connected from "+(address == null ? "unknown" : clean(address.toString()));
	}

	/**
	 * The line for a login the registry answered.
	 *
	 * @param credential what the client presented, may be null
	 * @param result the registry's answer
	 * @return "Login tony@bringardner.us (PLAIN)", or "Login failed for tony@bringardner.us: the reason"
	 */
	public static String login(Credential credential, AuthenticationResult result) {
		if( result != null && result.getStatus() == AuthenticationResult.Status.AUTHENTICATED ) {
			ParleyPrincipal p = result.getPrincipal();
			String name = p == null ? null : p.getName();
			if( name == null && credential != null ) {
				name = credential.getUser();
			}
			String method = result.getMethod();
			return "Login "+(name == null ? "(no name)" : clean(name))+(method == null || method.isEmpty() ? "" : " ("+clean(method)+")");
		}
		String user = credential == null ? null : credential.getUser();
		String reason = result == null ? null : result.getReason();
		return "Login failed"+(user == null || user.isEmpty() ? "" : " for "+clean(user))+(reason == null || reason.isEmpty() ? "" : ": "+clean(reason));
	}

	/**
	 * The line for a login the protocol refused before (or without) asking the registry.
	 *
	 * @param reason why, may be null
	 * @return "Login refused: the reason"
	 */
	public static String loginRefused(String reason) {
		return "Login refused"+(reason == null || reason.isEmpty() ? "" : ": "+clean(reason));
	}

	/**
	 * @param reason why the session ended, null for {@link #REASON_SESSION_ENDED}
	 * @param millis how long it lasted
	 * @return "Disconnected (idle) after 5m"
	 */
	public static String disconnected(String reason, long millis) {
		return "Disconnected ("+(reason == null || reason.isEmpty() ? REASON_SESSION_ENDED : reason)+") after "+duration(millis);
	}

	/** A duration for a person to read: 264ms, 12.3s, 5m 12s, 2h 5m. */
	static String duration(long millis) {
		if( millis < 1000 ) {
			return Math.max(0, millis)+"ms";
		}
		if( millis < 60_000 ) {
			return (millis/1000)+"."+((millis%1000)/100)+"s";
		}
		long seconds = millis/1000;
		if( seconds < 3600 ) {
			return (seconds/60)+"m "+(seconds%60)+"s";
		}
		return (seconds/3600)+"h "+((seconds%3600)/60)+"m";
	}

	/**
	 * @param reason why the server closes a session
	 * @return the words for it in the disconnect line
	 */
	public static String reason(CloseReason reason) {
		if( reason == null ) {
			return null;
		}
		switch (reason) {
		case IDLE: return REASON_IDLE;
		case LOGIN_TIME_LIMIT: return REASON_LOGIN_TIME_LIMIT;
		case SERVER_STOPPING: return REASON_SERVER_STOPPING;
		default: return reason.name();
		}
	}

	/**
	 * Text a client sent (a user name) is logged without control characters, so a client can't
	 * start a line of its own in the log, and no longer than 200 characters.
	 *
	 * @param text the text, may be null
	 * @return the text with each control character replaced by '?'
	 */
	public static String clean(String text) {
		if( text == null ) {
			return null;
		}
		StringBuilder ret = null;
		int length = Math.min(text.length(), 200);
		for(int i = 0; i < length; i++) {
			char c = text.charAt(i);
			if( c < 0x20 || c == 0x7f ) {
				if( ret == null ) {
					ret = new StringBuilder(text.substring(0, length));
				}
				ret.setCharAt(i, '?');
			}
		}
		if( ret != null ) {
			return text.length() > length ? ret.append("...").toString() : ret.toString();
		}
		return text.length() > length ? text.substring(0, length)+"..." : text;
	}
}
