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
 *
 *
 *	@author Tony Bringardner
 *
 *
 */
package us.bringardner.parley.net.server;

/**
 * Why the server is closing a session on its own (not because the client asked or went away).
 * The server calls {@link us.bringardner.parley.net.IProcessor#replyClosing(CloseReason)} with it
 * just before it closes the connection, so the protocol can say goodbye in its own way (FTP and
 * SMTP send 421; POP3 sends nothing, as RFC 1939 says).
 *
 * @since 2.0.0
 */
public enum CloseReason {

	/** No traffic for longer than the server's idle time (maxIdleConnection) */
	IDLE,

	/** Nobody logged in within the server's loginTimeLimit */
	LOGIN_TIME_LIMIT,

	/** The server is stopping */
	SERVER_STOPPING
}
