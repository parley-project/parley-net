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

import java.io.IOException;

/**
 * An access control list can't answer right now (its database is unreachable, say), so it
 * can't tell whether a user exists or a login is good. A server should answer with a temporary
 * failure (try again later), not "wrong password" or "no such user", and not count it as a
 * failed login.
 *
 * @since 1.1.0
 */
public class AccessControlUnavailableException extends IOException {

	private static final long serialVersionUID = 1L;

	public AccessControlUnavailableException(String message) {
		super(message);
	}

	public AccessControlUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}
}
