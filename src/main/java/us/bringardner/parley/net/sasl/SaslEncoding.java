package us.bringardner.parley.net.sasl;

import java.util.Base64;

/**
 * The Base64 form SASL data takes in SMTP, IMAP, POP3 and the like: "=" stands for an empty
 * response where an empty line would be taken as no response (RFC 4954, RFC 4422).
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
