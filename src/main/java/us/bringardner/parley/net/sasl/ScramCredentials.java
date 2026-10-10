package us.bringardner.parley.net.sasl;

/**
 * What a server keeps to verify a SCRAM login without keeping the password (RFC 5802): the
 * salt, the iteration count, and the StoredKey and ServerKey derived from the password. Make
 * them with {@link ScramMechanism#deriveCredentials(String, byte[], int)}.
 */
public final class ScramCredentials {

	private final byte[] salt;
	private final int iterations;
	private final byte[] storedKey;
	private final byte[] serverKey;

	public ScramCredentials(byte[] salt, int iterations, byte[] storedKey, byte[] serverKey) {
		this.salt = salt.clone();
		this.iterations = iterations;
		this.storedKey = storedKey.clone();
		this.serverKey = serverKey.clone();
	}

	public byte[] getSalt() {
		return salt.clone();
	}

	public int getIterations() {
		return iterations;
	}

	public byte[] getStoredKey() {
		return storedKey.clone();
	}

	public byte[] getServerKey() {
		return serverKey.clone();
	}
}
