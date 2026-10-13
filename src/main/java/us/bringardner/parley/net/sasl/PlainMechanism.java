package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * PLAIN (RFC 4616): one message, "authzid NUL authcid NUL password". Sends the password in the
 * clear, so offer it only over TLS. An authorization identity that differs from the
 * authentication identity (acting as another user) is refused.
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
public final class PlainMechanism implements ISaslMechanism {

	public static final String NAME = "PLAIN";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean isPlaintext() {
		return true;
	}

	@Override
	public ISaslServer newServer(ISaslAuthenticator authenticator) {
		return new ISaslServer() {
			@Override
			public SaslStep start(byte[] initialResponse) {
				return initialResponse == null ? SaslStep.emptyChallenge() : respond(initialResponse);
			}

			@Override
			public SaslStep respond(byte[] response) {
				String[] parts = new String(response, StandardCharsets.UTF_8).split("\u0000", -1);
				if (parts.length != 3 || parts[1].isEmpty()) {
					return SaslStep.failure("Malformed PLAIN response");
				}
				if (!parts[0].isEmpty() && !parts[0].equals(parts[1])) {
					return SaslStep.failure("Authorization identity differs from the user");
				}
				if (authenticator.checkPassword(parts[1], parts[2])) {
					return SaslStep.success(parts[1]);
				}
				return SaslStep.failure("Bad credentials");
			}
		};
	}

	/** @return the client side, which sends the credentials as the initial response */
	public static ISaslClient client(final String user, final String password) {
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
				return ("\u0000" + user + "\u0000" + password).getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) {
				return initialResponse();
			}

			@Override
			public boolean isComplete() {
				return sent;
			}
		};
	}
}
