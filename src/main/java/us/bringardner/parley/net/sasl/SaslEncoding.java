package us.bringardner.parley.net.sasl;

import java.util.Base64;

/**
 * The Base64 form SASL data takes in SMTP, IMAP, POP3 and the like: "=" stands for an empty
 * response where an empty line would be taken as no response (RFC 4954, RFC 4422).
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
public final class SaslEncoding {

	private SaslEncoding() {
	}

	/** @return the Base64 text of the data; empty data gives "" */
	public static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	/**
	 * @param text a response line, "=" for empty
	 * @throws IllegalArgumentException if it isn't valid Base64
	 */
	public static byte[] decode(String text) {
		String t = text.trim();
		if (t.equals("=")) {
			return new byte[0];
		}
		return Base64.getDecoder().decode(t);
	}
}
