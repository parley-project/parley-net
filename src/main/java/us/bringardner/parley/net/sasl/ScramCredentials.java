package us.bringardner.parley.net.sasl;

import java.util.Base64;

/**
 * What a server keeps to verify a SCRAM login without keeping the password (RFC 5802): the
 * salt, the iteration count, and the StoredKey and ServerKey derived from the password. Make
 * them with {@link ScramMechanism#deriveCredentials(String, byte[], int)}.
 * <p>
 * {@link #format()} and {@link #parse(String)} turn them into text and back, for a user file
 * or a database column: {@code iterations:salt:storedKey:serverKey}, the last three in Base64.
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
public final class ScramCredentials {

	private final byte[] salt;
	private final int iterations;
	private final byte[] storedKey;
	private final byte[] serverKey;

	public ScramCredentials(byte[] salt, int iterations, byte[] storedKey, byte[] serverKey) {
		this.salt = salt.clone();
		this.iterations = iterations;
		this.storedKey = storedKey.clone();
		this.serverKey = serverKey.clone();
	}

	public byte[] getSalt() {
		return salt.clone();
	}

	public int getIterations() {
		return iterations;
	}

	public byte[] getStoredKey() {
		return storedKey.clone();
	}

	public byte[] getServerKey() {
		return serverKey.clone();
	}

	/**
	 * @return {@code iterations:salt:storedKey:serverKey} (Base64), which {@link #parse(String)} reads back
	 * @since 1.1.0
	 */
	public String format() {
		Base64.Encoder enc = Base64.getEncoder();
		return iterations+":"+enc.encodeToString(salt)+":"+enc.encodeToString(storedKey)+":"+enc.encodeToString(serverKey);
	}

	/**
	 * @param text a value made by {@link #format()}
	 * @return the credentials, or null if text is null, empty or not in that form
	 * @since 1.1.0
	 */
	public static ScramCredentials parse(String text) {
		if( text == null ) {
			return null;
		}
		String parts[] = text.trim().split(":");
		if( parts.length != 4 ) {
			return null;
		}
		try {
			int iterations = Integer.parseInt(parts[0]);
			Base64.Decoder dec = Base64.getDecoder();
			byte[] salt = dec.decode(parts[1]);
			byte[] storedKey = dec.decode(parts[2]);
			byte[] serverKey = dec.decode(parts[3]);
			if( iterations < 1 || salt.length == 0 || storedKey.length == 0 || storedKey.length != serverKey.length ) {
				return null;
			}
			return new ScramCredentials(salt, iterations, storedKey, serverKey);
		} catch (IllegalArgumentException e) {
			return null;
		}
	}
}
