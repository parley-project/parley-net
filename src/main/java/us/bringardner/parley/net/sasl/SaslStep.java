package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * What the server side of a SASL exchange does next: send a challenge, finish with success
 * (the user is known), or finish with failure.
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
public final class SaslStep {

	public enum Kind {
		CHALLENGE, SUCCESS, FAILURE
	}

	private static final byte[] EMPTY = new byte[0];

	private final Kind kind;
	private final byte[] data;
	private final String text;

	private SaslStep(Kind kind, byte[] data, String text) {
		this.kind = kind;
		this.data = data;
		this.text = text;
	}

	/** Send this data to the client and wait for its response. */
	public static SaslStep challenge(byte[] data) {
		return new SaslStep(Kind.CHALLENGE, data.clone(), null);
	}

	public static SaslStep challenge(String data) {
		return new SaslStep(Kind.CHALLENGE, data.getBytes(StandardCharsets.UTF_8), null);
	}

	/** An empty challenge, asking the client for its first message. */
	public static SaslStep emptyChallenge() {
		return new SaslStep(Kind.CHALLENGE, EMPTY, null);
	}

	/** The client proved who it is. */
	public static SaslStep success(String user) {
		return new SaslStep(Kind.SUCCESS, EMPTY, user);
	}

	/** The exchange failed; the reason is for logs, not for the client. */
	public static SaslStep failure(String reason) {
		return new SaslStep(Kind.FAILURE, EMPTY, reason);
	}

	public Kind getKind() {
		return kind;
	}

	/** @return the challenge data (empty unless this is a CHALLENGE) */
	public byte[] getData() {
		return data.clone();
	}

	/** @return the authenticated user name, for SUCCESS */
	public String getUser() {
		return kind == Kind.SUCCESS ? text : null;
	}

	/** @return why the exchange failed, for FAILURE */
	public String getReason() {
		return kind == Kind.FAILURE ? text : null;
	}
}
