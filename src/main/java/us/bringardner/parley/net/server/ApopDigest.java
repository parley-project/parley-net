package us.bringardner.parley.net.server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import us.bringardner.parley.core.util.Hex;
import us.bringardner.parley.net.sasl.SaslPrep;

/**
 * The APOP check (RFC 1939 section 7) for user registries that keep plain text
 * passwords: MD5(timestamp + secret), with the secret prepared by SASLprep (RFC 6856
 * section 2.2), compared in constant time.
 *
 * <PRE>
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
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
 * @since 2.0.0
 */
public final class ApopDigest {

	private ApopDigest() {
	}

	/**
	 * @param timestamp the greeting's timestamp, with its angle brackets
	 * @param secret the user's stored plain text secret (not a hash)
	 * @param digest what the client sent (hex, any case)
	 * @return true if the digest is MD5(timestamp + secret)
	 */
	public static boolean matches(String timestamp, String secret, String digest) {
		if( timestamp == null || secret == null || digest == null ) {
			return false;
		}
		String prepared = SaslPrep.prepare(secret, true);
		if( prepared == null ) {
			return false;
		}
		String expected = digest(timestamp, prepared);
		return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
				digest.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
	}

	/** @return the lower case hex MD5 of the timestamp followed by the (already prepared) secret */
	public static String digest(String timestamp, String secret) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(timestamp.getBytes(StandardCharsets.US_ASCII));
			md.update(secret.getBytes(StandardCharsets.UTF_8));
			return Hex.encode(md.digest()).toLowerCase(Locale.ROOT);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
