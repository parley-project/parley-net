package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Supplier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * CRAM-MD5 (RFC 2195): the server sends a one-time challenge and the client answers with
 * "user HMAC-MD5(password, challenge)", so the password isn't sent. The server needs the
 * clear text password ({@link ISaslAuthenticator#getPassword}), which a store of password
 * hashes doesn't have. MD5 is weak: prefer SCRAM.
 */
public final class CramMd5Mechanism implements ISaslMechanism {

	public static final String NAME = "CRAM-MD5";

	private static final SecureRandom RANDOM = new SecureRandom();

	private final Supplier<String> challenges;

	/** @param host the host name placed in each challenge ("&lt;nonce.time@host&gt;") */
	public CramMd5Mechanism(final String host) {
		this(() -> "<" + Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE) + "." 
				+ (System.currentTimeMillis() / 1000) + "@" + host + ">");
	}

	/**
	 * @param challenges supplies the challenge of each exchange, like "&lt;1896.697170952@host&gt;".
	 *                   It must not repeat: a repeated challenge lets a recorded answer be replayed.
	 */
	public CramMd5Mechanism(Supplier<String> challenges) {
		this.challenges = challenges;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean isPlaintext() {
		return false;
	}

	@Override
	public ISaslServer newServer(final ISaslAuthenticator authenticator) {
		return new ISaslServer() {
			private String challenge;

			@Override
			public SaslStep start(byte[] initialResponse) {
				if (initialResponse != null) {
					return SaslStep.failure("CRAM-MD5 takes no initial response");
				}
				challenge = challenges.get();
				return SaslStep.challenge(challenge);
			}

			@Override
			public SaslStep respond(byte[] response) {
				String text = new String(response, StandardCharsets.UTF_8);
				int sp = text.lastIndexOf(' ');
				if (challenge == null || sp <= 0) {
					return SaslStep.failure("Malformed CRAM-MD5 response");
				}
				String user = text.substring(0, sp);
				String digest = text.substring(sp + 1);
				String password = authenticator.getPassword(user);
				if (password == null) {
					return SaslStep.failure("Unknown user");
				}
				byte[] expected = hex(hmacMd5(password, challenge)).getBytes(StandardCharsets.US_ASCII);
				byte[] given = digest.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.US_ASCII);
				if (MessageDigest.isEqual(expected, given)) {
					return SaslStep.success(user);
				}
				return SaslStep.failure("Bad credentials");
			}
		};
	}

	/** @return the client side, which answers the server's challenge */
	public static ISaslClient client(final String user, final String password) {
		return new ISaslClient() {
			private boolean done;

			@Override
			public String getName() {
				return NAME;
			}

			@Override
			public boolean hasInitialResponse() {
				return false;
			}

			@Override
			public byte[] initialResponse() {
				return null;
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
				if (done || challenge.length == 0) {
					throw new SaslException("CRAM-MD5: expected a challenge");
				}
				done = true;
				String digest = hex(hmacMd5(password, new String(challenge, StandardCharsets.UTF_8)));
				return (user + " " + digest).getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public boolean isComplete() {
				return done;
			}
		};
	}

	static byte[] hmacMd5(String password, String challenge) {
		try {
			Mac mac = Mac.getInstance("HmacMD5");
			// an empty key is not allowed by SecretKeySpec; HMAC pads a short key with zeros anyway
			byte[] key = password.getBytes(StandardCharsets.UTF_8);
			mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacMD5"));
			return mac.doFinal(challenge.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException(e);
		}
	}

	static String hex(byte[] data) {
		StringBuilder buf = new StringBuilder(data.length * 2);
		for (byte b : data) {
			buf.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
		}
		return buf.toString();
	}
}
