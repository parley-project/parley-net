package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * XOAUTH2, the bearer token login used by Gmail and Microsoft 365, the client side only: one
 * message, "user=" user 0x01 "auth=Bearer " token 0x01 0x01. The token is a secret, so send it
 * only over TLS. A server that rejects the token answers with a JSON error challenge, and the
 * client ends the exchange with an empty response.
 * <p>
 * Parley's servers don't offer XOAUTH2 (removed in 2.0.0): a server needs something to issue
 * and check tokens. It can come back built on parley-iam's TokenCredential, checked by a user
 * registry, when Parley is connected to an identity provider.
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
public final class XOAuth2Mechanism {

	public static final String NAME = "XOAUTH2";

	private static final char SOH = '\u0001';
	private static final String BEARER = "auth=Bearer ";

	private XOAuth2Mechanism() {
	}

	/** @return the client side, which sends the user and token as the initial response */
	public static ISaslClient client(final String user, final String token) {
		return new ISaslClient() {
			private boolean sent;

			@Override
			public String getName() {
				return NAME;
			}

			@Override
			public boolean hasInitialResponse() {
				return true;
			}

			@Override
			public byte[] initialResponse() {
				sent = true;
				return ("user=" + user + SOH + BEARER + token + SOH + SOH).getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) {
				// the server sent an error as JSON; an empty response ends the exchange
				if (sent && challenge.length > 0) {
					return new byte[0];
				}
				return initialResponse();
			}

			@Override
			public boolean isComplete() {
				return sent;
			}
		};
	}
}
