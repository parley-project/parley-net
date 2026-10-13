package us.bringardner.parley.net.sasl;

/**
 * Where a server's SASL mechanisms check credentials. A mechanism calls only the method it
 * needs, and {@link #supports(String)} says which mechanisms this store can serve: a store of
 * salted password hashes can check a PLAIN password but can't answer CRAM-MD5, which needs
 * the password itself.
 * <p>
 * Instances are used by one session at a time.
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
public interface ISaslAuthenticator {

	/** @return true if the user's password is correct (PLAIN, LOGIN) */
	boolean checkPassword(String user, String password);

	/** @return the user's clear text password, or null if unknown or not available (CRAM-MD5) */
	default String getPassword(String user) {
		return null;
	}

	/**
	 * @param hash "SHA-1" or "SHA-256"
	 * @return the user's stored SCRAM credentials for that hash, or null if there are none
	 */
	default ScramCredentials getScramCredentials(String user, String hash) {
		return null;
	}

	/** @return true if the bearer token is valid for the user (XOAUTH2) */
	default boolean checkBearerToken(String user, String token) {
		return false;
	}

	/** @return true if this store can serve the mechanism; the default says it can serve all */
	default boolean supports(String mechanism) {
		return true;
	}
}
