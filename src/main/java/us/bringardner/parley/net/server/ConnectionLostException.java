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
 * The client's connection is gone (as opposed to a failure in what a command was doing, such as
 * the mail store). A protocol that reads and writes the socket through its own streams wraps
 * their I/O errors in this, so a command's own error handling doesn't take a dropped connection
 * for a failed operation; the session loop ({@link AbstractCommandProcessor#run()}) ends the
 * session and logs it as a debug line.
 *
 * @since 2.0.0
 */
public class ConnectionLostException extends IOException {

	private static final long serialVersionUID = 1L;

	/** @param cause the I/O error from the connection */
	public ConnectionLostException(IOException cause) {
		super(cause.getMessage(), cause);
	}
}
