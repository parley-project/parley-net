package us.bringardner.parley.net.sasl;

/**
 * The server side of one authentication exchange. It knows nothing about the protocol that
 * carries it (AUTH in SMTP, AUTHENTICATE in IMAP, ...): bytes in, a {@link SaslStep} out.
 * Use {@link SaslServerDriver} to run it over a connection. One instance per exchange.
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
public interface ISaslServer {

	/**
	 * Begin the exchange.
	 *
	 * @param initialResponse what the client sent with the command, or null if it sent
	 *                        nothing. An empty array is an empty initial response.
	 */
	SaslStep start(byte[] initialResponse);

	/** The client answered a challenge. */
	SaslStep respond(byte[] response);
}
