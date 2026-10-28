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
 * A domain list can't be read right now (its file is missing or unreadable, its database is
 * unreachable). The caller keeps using the list it had, and tries again later.
 *
 * @since 2.0.0
 */
public class DomainListUnavailableException extends IOException {

	private static final long serialVersionUID = 1L;

	public DomainListUnavailableException(String message) {
		super(message);
	}

	public DomainListUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}
}
