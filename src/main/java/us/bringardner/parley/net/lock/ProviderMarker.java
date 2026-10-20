package us.bringardner.parley.net.lock;

import java.io.IOException;

import us.bringardner.parley.files.FileSource;

/**
 * Every server must keep a store's locks the same way, or they don't see each other's. The first
 * records its provider as a directory, {@code provider-<id>} (or {@code provider@<domain>@<id>} in
 * a coordination store), made with an atomic mkdir; a server that finds another is refused. Two
 * servers starting at once with different providers can both see the other's marker: both remove
 * their own and are refused, and the next start succeeds.
 * <p>
 * The id (compared without case, as providers are found) and the domain are written so that
 * different ones never make the same name, on any store: lower-case letters, digits, {@code .}
 * and {@code -} as they are, every other byte of their UTF-8 as {@code _} and two hex digits
 * ({@code vendor_locks} is {@code vendor_5flocks}, {@code vendor/locks} {@code vendor_2flocks}).
 * So the {@code @} between them is never part of either.
 */
final class ProviderMarker {

	private static final String PREFIX = "provider-";

	private ProviderMarker() {
	}

	static void check(FileSource lockDir, String domain, String providerId) throws IOException {
		String prefix = domain == null ? PREFIX : "provider@" + encode(domain) + "@";
		String mine = prefix + encode(providerId.toLowerCase(java.util.Locale.ROOT));
		String other = otherThan(lockDir, prefix, mine);
		if( other != null ) {
			throw refusal(lockDir, providerId, other, prefix);
		}
		FileSource marker = lockDir.getChild(mine);
		boolean made = marker.mkdir();
		other = otherThan(lockDir, prefix, mine);
		if( other != null ) {
			if( made ) {
				marker.delete();
			}
			throw refusal(lockDir, providerId, other, prefix);
		}
		if( !made && !marker.isDirectory() ) {
			throw new IOException("Can't record the lock provider in " + lockDir.getAbsolutePath());
		}
	}

	/** One name for one string: see the class comment. */
	static String encode(String s) {
		StringBuilder b = new StringBuilder();
		for (byte x : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
			int c = x & 0xff;
			if( (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' ) {
				b.append((char) c);
			} else {
				b.append('_').append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 0xf, 16));
			}
		}
		return b.toString();
	}

	private static String otherThan(FileSource lockDir, String prefix, String mine) throws IOException {
		FileSource[] kids = lockDir.listFiles();
		if( kids != null ) {
			for (FileSource k : kids) {
				String n = k.getName();
				if( n.startsWith(prefix) && !n.equals(mine) && k.isDirectory() ) {
					return n;
				}
			}
		}
		return null;
	}

	/** The string {@link #encode} wrote (for messages). */
	static String decode(String s) {
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if( c == '_' && i + 2 < s.length() && Character.digit(s.charAt(i + 1), 16) >= 0 && Character.digit(s.charAt(i + 2), 16) >= 0 ) {
				out.write(Character.digit(s.charAt(i + 1), 16) * 16 + Character.digit(s.charAt(i + 2), 16));
				i += 2;
			} else {
				out.write(c);
			}
		}
		return new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
	}

	private static LockSetupException refusal(FileSource lockDir, String providerId, String other, String prefix) {
		String theirs = decode(other.substring(prefix.length()));
		return new LockSetupException("The store's locks in " + lockDir.getAbsolutePath() + " are kept by "
				+ theirs + ", and this server would use " + providerId
				+ ": servers keeping one store's locks differently don't see each other's. Use "
				+ theirs + ", or stop every server, delete " + lockDir.getAbsolutePath() + "/" + other
				+ " and start them all with " + providerId + ".");
	}
}
