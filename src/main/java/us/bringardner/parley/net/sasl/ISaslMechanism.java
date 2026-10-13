package us.bringardner.parley.net.sasl;

/**
 * A SASL mechanism (RFC 4422): PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-256, XOAUTH2 ...
 * Implementations are stateless and shared; each exchange gets its own {@link ISaslServer}.
 * Client sides are created by factory methods on the mechanism classes, since each needs
 * different credentials.
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
public interface ISaslMechanism {

	/** @return the registered mechanism name, upper case */
	String getName();

	/**
	 * @return true if a passive eavesdropper can read the secret from the exchange. Such a
	 *         mechanism should be offered only over TLS.
	 */
	boolean isPlaintext();

	/**
	 * @param authenticator checks the credentials
	 * @return a new server side of the exchange
	 */
	ISaslServer newServer(ISaslAuthenticator authenticator);
}
