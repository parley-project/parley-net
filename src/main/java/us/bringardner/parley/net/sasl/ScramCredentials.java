package us.bringardner.parley.net.sasl;

/**
 * What a server keeps to verify a SCRAM login without keeping the password (RFC 5802): the
 * salt, the iteration count, and the StoredKey and ServerKey derived from the password. Make
 * them with {@link ScramMechanism#deriveCredentials(String, byte[], int)}.
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
}
