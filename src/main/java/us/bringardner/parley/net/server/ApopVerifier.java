/**
 * <PRE>
 * 
 * Copyright 2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
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

import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ProofVerifier;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;

/**
 * The APOP check (RFC 1939 section 7) as a {@link ProofVerifier}, for a POP3 server's
 * APOP command. It needs the user's plain text secret
 * ({@link StoredCredentialType#PLAIN_TEXT}, a String) and compares it with
 * {@link ApopDigest#matches(String, String, String)}.
 * <p>
 * Give it to the server in a {@link ProofCredential}:
 * <pre>
 * new ProofCredential(user, StoredCredentialType.PLAIN_TEXT, new ApopVerifier(timestamp, digest), requester)
 * </pre>
 *
 * @since 2.0.0
 */
public final class ApopVerifier implements ProofVerifier {

	private final String timestamp;
	private final String digest;

	/**
	 * @param timestamp the timestamp the server sent in its greeting, with its angle brackets
	 * @param digest what the client sent
	 */
	public ApopVerifier(String timestamp, String digest) {
		this.timestamp = timestamp;
		this.digest = digest;
	}

	/** @return true when the stored secret is plain text and the digest matches it */
	@Override
	public boolean verify(StoredCredential stored) {
		if( stored == null || !StoredCredentialType.PLAIN_TEXT.equals(stored.getType()) ) {
			return false;
		}
		Object secret = stored.getValue();
		return secret instanceof String && ApopDigest.matches(timestamp, (String) secret, digest);
	}
}
