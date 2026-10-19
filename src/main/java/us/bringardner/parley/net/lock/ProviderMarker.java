package us.bringardner.parley.net.lock;

import java.io.IOException;

import us.bringardner.parley.files.FileSource;

/**
 * Every server must keep a store's locks the same way, or they don't see each other's. The first
 * records its provider as a directory, {@code provider-<id>} (or {@code provider@<domain>@<id>} in
 * a coordination store), made with an atomic mkdir; a server that finds another is refused. Two
 * servers starting at once with different providers can both see the other's marker: both remove
 * their own and are refused, and the next start succeeds.
 */
final class ProviderMarker {

	private static final String PREFIX = "provider-";

	private ProviderMarker() {
	}

	static void check(FileSource lockDir, String domain, String providerId) throws IOException {
		String prefix = domain == null ? PREFIX : "provider@" + domain + "@";
		String mine = prefix + providerId.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9._-]", "_");
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

	private static LockSetupException refusal(FileSource lockDir, String providerId, String other, String prefix) {
		return new LockSetupException("The store's locks in " + lockDir.getAbsolutePath() + " are kept by "
				+ other.substring(prefix.length()) + ", and this server would use " + providerId
				+ ": servers keeping one store's locks differently don't see each other's. Use "
				+ other.substring(prefix.length()) + ", or stop every server, delete " + lockDir.getAbsolutePath() + "/" + other
				+ " and start them all with " + providerId + ".");
	}
}
