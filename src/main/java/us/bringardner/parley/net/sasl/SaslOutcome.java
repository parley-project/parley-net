package us.bringardner.parley.net.sasl;

/** How an authentication exchange ended, from {@link SaslServerDriver}. */
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
public final class SaslOutcome {

	public enum Status {
		/** The client proved its identity; {@link #getUser()} says who. */
		SUCCESS,
		/** The credentials were wrong, or the mechanism gave up. */
		FAILED,
		/** The client cancelled with "*". */
		CANCELLED,
		/** A response was not valid Base64. */
		MALFORMED,
		/** The connection closed in the middle of the exchange. */
		CLOSED
	}

	private final Status status;
	private final String user;
	private final String reason;

	SaslOutcome(Status status, String user, String reason) {
		this.status = status;
		this.user = user;
		this.reason = reason;
	}

	public Status getStatus() {
		return status;
	}

	public boolean isSuccess() {
		return status == Status.SUCCESS;
	}

	/** @return the authenticated user, for SUCCESS */
	public String getUser() {
		return user;
	}

	/** @return why it ended, for logs; null for SUCCESS */
	public String getReason() {
		return reason;
	}

	@Override
	public String toString() {
		return status + (user != null ? " " + user : "") + (reason != null ? " (" + reason + ")" : "");
	}
}
