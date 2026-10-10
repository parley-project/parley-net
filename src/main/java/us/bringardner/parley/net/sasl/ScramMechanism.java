package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SCRAM (RFC 5802, RFC 7677): the client proves it knows the password without sending it, and
 * the server proves it knows the stored verifier, so both ends are authenticated. The server
 * keeps {@link ScramCredentials}, not the password.
 * <p>
 * {@link #SHA_256} is the one to use; {@link #SHA_1} is for older clients. This implements the
 * mechanisms without channel binding (SCRAM-SHA-256, not SCRAM-SHA-256-PLUS). User names and
 * passwords are used as given: SASLprep (RFC 4013) is not applied.
 */
public final class ScramMechanism implements ISaslMechanism {

	public static final ScramMechanism SHA_256 = new ScramMechanism("SHA-256");
	public static final ScramMechanism SHA_1 = new ScramMechanism("SHA-1");

	/** Iteration count used when a server makes credentials without being told one. */
	public static final int DEFAULT_ITERATIONS = 4096;

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final byte[] FAKE_SECRET = new byte[32];
	static {
		RANDOM.nextBytes(FAKE_SECRET);
	}

	private final String name;
	private final String digest;
	private final String hmac;
	private final String pbkdf2;
	private final int hashLength;
	private final Supplier<String> nonces;

	private ScramMechanism(String hash) {
		this(hash, ScramMechanism::randomNonce);
	}

	/**
	 * @param hash   "SHA-1" or "SHA-256"
	 * @param nonces supplies the nonce of each exchange; for tests, a real one must be random
	 */
	public ScramMechanism(String hash, Supplier<String> nonces) {
		if (hash.equals("SHA-256")) {
			digest = "SHA-256";
			hmac = "HmacSHA256";
			pbkdf2 = "PBKDF2WithHmacSHA256";
			hashLength = 32;
		} else if (hash.equals("SHA-1")) {
			digest = "SHA-1";
			hmac = "HmacSHA1";
			pbkdf2 = "PBKDF2WithHmacSHA1";
			hashLength = 20;
		} else {
			throw new IllegalArgumentException("Unsupported SCRAM hash " + hash);
		}
		this.name = "SCRAM-" + hash;
		this.nonces = nonces;
	}

	private static String randomNonce() {
		byte[] raw = new byte[24];
		RANDOM.nextBytes(raw);
		// Base64 has no ',' which the message format reserves
		return Base64.getEncoder().withoutPadding().encodeToString(raw);
	}

	@Override
	public String getName() {
		return name;
	}

	/** @return "SHA-1" or "SHA-256", the hash name {@link ISaslAuthenticator#getScramCredentials} is asked for */
	public String getHash() {
		return digest;
	}

	@Override
	public boolean isPlaintext() {
		return false;
	}

	/**
	 * Make what a server stores for a password. Store the result, not the password.
	 *
	 * @param salt       random, at least 16 bytes; kept with the credentials
	 * @param iterations how hard to make guessing; 4096 or more
	 */
	public ScramCredentials deriveCredentials(String password, byte[] salt, int iterations) {
		byte[] salted = salted(password, salt, iterations);
		return new ScramCredentials(salt, iterations, hash(hmac(salted, "Client Key")), hmac(salted, "Server Key"));
	}

	// ------------------------------------------------------------------ crypto

	private byte[] salted(String password, byte[] salt, int iterations) {
		try {
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, hashLength * 8);
			return SecretKeyFactory.getInstance(pbkdf2).generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private byte[] hmac(byte[] key, String data) {
		return hmac(key, data.getBytes(StandardCharsets.UTF_8));
	}

	private byte[] hmac(byte[] key, byte[] data) {
		try {
			Mac mac = Mac.getInstance(hmac);
			mac.init(new SecretKeySpec(key, hmac));
			return mac.doFinal(data);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private byte[] hash(byte[] data) {
		try {
			return MessageDigest.getInstance(digest).digest(data);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] xor(byte[] a, byte[] b) {
		byte[] ret = new byte[a.length];
		for (int idx = 0; idx < a.length; idx++) {
			ret[idx] = (byte) (a[idx] ^ b[idx]);
		}
		return ret;
	}

	private static String b64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	// ------------------------------------------------------------------ message helpers

	/** @return the value of the attribute ("r=...") or null; attributes are comma separated */
	private static String attribute(String[] parts, char key) {
		for (String p : parts) {
			if (p.length() >= 2 && p.charAt(0) == key && p.charAt(1) == '=') {
				return p.substring(2);
			}
		}
		return null;
	}

	private static String escapeName(String user) {
		return user.replace("=", "=3D").replace(",", "=2C");
	}

	private static String unescapeName(String name) {
		return name.replace("=2C", ",").replace("=3D", "=");
	}

	// ------------------------------------------------------------------ server

	@Override
	public ISaslServer newServer(final ISaslAuthenticator authenticator) {
		return new ISaslServer() {
			private int stage;          // 0 expect client-first, 1 expect client-final, 2 expect the ack
			private String user;
			private String gs2Header;
			private String clientFirstBare;
			private String serverFirst;
			private String nonce;
			private ScramCredentials credentials;
			private boolean unknownUser;

			@Override
			public SaslStep start(byte[] initialResponse) {
				return initialResponse == null ? SaslStep.emptyChallenge() : respond(initialResponse);
			}

			@Override
			public SaslStep respond(byte[] response) {
				String message = new String(response, StandardCharsets.UTF_8);
				switch (stage) {
				case 0:
					return clientFirst(message);
				case 1:
					return clientFinal(message);
				case 2:
					stage = 3;
					return SaslStep.success(user);
				default:
					return SaslStep.failure("Unexpected SCRAM message");
				}
			}

			private SaslStep clientFirst(String message) {
				// gs2-header = cbind-flag "," [authzid] "," ; we don't offer channel binding
				int first = message.indexOf(',');
				int second = first < 0 ? -1 : message.indexOf(',', first + 1);
				if (second < 0) {
					return SaslStep.failure("Malformed client-first-message");
				}
				String flag = message.substring(0, first);
				if (!flag.equals("n") && !flag.equals("y")) {
					return SaslStep.failure("Channel binding is not supported");
				}
				if (second != first + 1) {
					return SaslStep.failure("An authorization identity is not supported");
				}
				gs2Header = message.substring(0, second + 1);
				clientFirstBare = message.substring(second + 1);
				String[] parts = clientFirstBare.split(",");
				String n = attribute(parts, 'n');
				String r = attribute(parts, 'r');
				if (n == null || n.isEmpty() || r == null || r.isEmpty() || attribute(parts, 'm') != null) {
					return SaslStep.failure("Malformed client-first-message");
				}
				user = unescapeName(n);
				credentials = authenticator.getScramCredentials(user, digest);
				if (credentials == null) {
					// carry on with made up values, so an unknown user looks like a bad password
					unknownUser = true;
					credentials = fake(user);
				}
				nonce = r + nonces.get();
				serverFirst = "r=" + nonce + ",s=" + b64(credentials.getSalt()) + ",i=" + credentials.getIterations();
				stage = 1;
				return SaslStep.challenge(serverFirst);
			}

			private SaslStep clientFinal(String message) {
				int proofAt = message.lastIndexOf(",p=");
				if (proofAt < 0) {
					return SaslStep.failure("Malformed client-final-message");
				}
				String withoutProof = message.substring(0, proofAt);
				String[] parts = withoutProof.split(",");
				String c = attribute(parts, 'c');
				String r = attribute(parts, 'r');
				if (c == null || r == null || !r.equals(nonce)
						|| !c.equals(b64(gs2Header.getBytes(StandardCharsets.UTF_8)))) {
					return SaslStep.failure("Bad client-final-message");
				}
				byte[] proof;
				try {
					proof = Base64.getDecoder().decode(message.substring(proofAt + 3));
				} catch (IllegalArgumentException e) {
					return SaslStep.failure("Bad proof encoding");
				}
				byte[] stored = credentials.getStoredKey();
				if (unknownUser || proof.length != stored.length) {
					return SaslStep.failure("Bad credentials");
				}
				String authMessage = clientFirstBare + "," + serverFirst + "," + withoutProof;
				byte[] clientKey = xor(proof, hmac(stored, authMessage));
				if (!MessageDigest.isEqual(hash(clientKey), stored)) {
					return SaslStep.failure("Bad credentials");
				}
				byte[] serverSignature = hmac(credentials.getServerKey(), authMessage);
				stage = 2;
				// the server's proof goes as one more challenge, which the client acknowledges
				return SaslStep.challenge("v=" + b64(serverSignature));
			}
		};
	}

	private ScramCredentials fake(String user) {
		byte[] salt = java.util.Arrays.copyOf(hmac(FAKE_SECRET, user), 16);
		byte[] key = new byte[hashLength];
		return new ScramCredentials(salt, DEFAULT_ITERATIONS, key, key);
	}

	// ------------------------------------------------------------------ client

	/** @return the client side, using a random nonce */
	public ISaslClient client(String user, String password) {
		return client(user, password, nonces);
	}

	/** @return the client side with the nonce supplied (for tests) */
	public ISaslClient client(final String user, final String password, final Supplier<String> clientNonce) {
		return new ISaslClient() {
			private int stage;          // 0 nothing sent, 1 sent client-first, 2 sent client-final, 3 done
			private String clientNonceValue;
			private String clientFirstBare;
			private byte[] expectedServerSignature;

			@Override
			public String getName() {
				return name;
			}

			@Override
			public boolean hasInitialResponse() {
				return true;
			}

			@Override
			public byte[] initialResponse() {
				if (stage == 0) {
					clientNonceValue = clientNonce.get();
					clientFirstBare = "n=" + escapeName(user) + ",r=" + clientNonceValue;
					stage = 1;
				}
				return ("n,," + clientFirstBare).getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
				String message = new String(challenge, StandardCharsets.UTF_8);
				switch (stage) {
				case 0:
					return initialResponse();
				case 1:
					return clientFinal(message);
				case 2:
					return serverFinal(message);
				default:
					throw new SaslException(name + ": unexpected challenge");
				}
			}

			private byte[] clientFinal(String serverFirst) throws SaslException {
				if (challengeIsEmpty(serverFirst)) {
					// the server wants the first message again (no initial response was sent)
					return initialResponse();
				}
				String[] parts = serverFirst.split(",");
				String r = attribute(parts, 'r');
				String s = attribute(parts, 's');
				String i = attribute(parts, 'i');
				if (r == null || s == null || i == null || !r.startsWith(clientNonceValue)) {
					throw new SaslException(name + ": invalid server-first-message");
				}
				byte[] salt;
				int iterations;
				try {
					salt = Base64.getDecoder().decode(s);
					iterations = Integer.parseInt(i);
				} catch (IllegalArgumentException e) {
					throw new SaslException(name + ": invalid server-first-message");
				}
				if (iterations < 1) {
					throw new SaslException(name + ": invalid iteration count");
				}
				byte[] salted = salted(password, salt, iterations);
				byte[] clientKey = hmac(salted, "Client Key");
				String withoutProof = "c=" + b64("n,,".getBytes(StandardCharsets.UTF_8)) + ",r=" + r;
				String authMessage = clientFirstBare + "," + serverFirst + "," + withoutProof;
				byte[] proof = xor(clientKey, hmac(hash(clientKey), authMessage));
				expectedServerSignature = hmac(hmac(salted, "Server Key"), authMessage);
				stage = 2;
				return (withoutProof + ",p=" + b64(proof)).getBytes(StandardCharsets.UTF_8);
			}

			private byte[] serverFinal(String message) throws SaslException {
				String[] parts = message.split(",");
				if (attribute(parts, 'e') != null) {
					throw new SaslException(name + ": the server refused: " + attribute(parts, 'e'));
				}
				String v = attribute(parts, 'v');
				byte[] given;
				try {
					given = v == null ? null : Base64.getDecoder().decode(v);
				} catch (IllegalArgumentException e) {
					given = null;
				}
				if (given == null || !MessageDigest.isEqual(given, expectedServerSignature)) {
					throw new SaslException(name + ": the server did not prove it knows the password");
				}
				stage = 3;
				return new byte[0];
			}

			@Override
			public boolean isComplete() {
				return stage == 3;
			}
		};
	}

	private static boolean challengeIsEmpty(String s) {
		return s.isEmpty();
	}
}
