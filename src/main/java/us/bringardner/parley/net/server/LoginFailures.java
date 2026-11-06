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

import us.bringardner.parley.core.util.AbstractCoreServer;
import us.bringardner.parley.iam.AuthenticationResult;

/**
 * Counts one session's failed logins and says when the application's limit is reached.
 * <p>
 * The values are the application's, read from the server: {@code maxLoginAttempts} (failed
 * logins before the connection is closed) and {@code loginFailureDelay} (how long to wait before
 * answering a failed login). This class only counts; the session does the waiting, because a
 * thread-per-connection session can sleep and a non-blocking one can't.
 * <ul>
 * <li>AUTHENTICATED starts the count again.</li>
 * <li>REFUSED adds one.</li>
 * <li>UNSUPPORTED and UNAVAILABLE change nothing: they say nothing about the password.</li>
 * </ul>
 * One instance per connection; a new connection starts at zero.
 * @since 2.0.0
 */
public final class LoginFailures {

	private final AbstractCoreServer server;
	private int failed;
	private boolean tooMany;

	/** @param server where the application's values come from */
	public LoginFailures(AbstractCoreServer server) {
		this.server = server;
	}

	/**
	 * Called with every login result the session gets.
	 * @param result the answer to one login
	 * @return true when this result was a refusal (the session then waits {@link #getDelayMillis()})
	 */
	public synchronized boolean record(AuthenticationResult result) {
		AuthenticationResult.Status status = result.getStatus();
		if (status == AuthenticationResult.Status.AUTHENTICATED) {
			failed = 0;
			tooMany = false;
			return false;
		}
		if (status != AuthenticationResult.Status.REFUSED) {
			return false;
		}
		failed = failed + 1;
		if (server.isTooManyLoginFailures(failed)) {
			tooMany = true;
		}
		return true;
	}

	/** @return milliseconds to wait before answering a refused login (0 = don't wait) */
	public int getDelayMillis() {
		return server.getLoginFailureDelay();
	}

	/** @return true once the limit is reached: the connection is closed after the current reply */
	public synchronized boolean isTooMany() {
		return tooMany;
	}

	/** @return failed logins so far on this connection */
	public synchronized int getFailed() {
		return failed;
	}
}
