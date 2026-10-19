package us.bringardner.parley.net.lock;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/**
 * Another server, for the cross-process tests: opens Locks with a local directory as domain "test" and answers
 * commands on stdin, one per line, with a line starting {@value #PREFIX} on stdout.
 * <ul>
 * <li>{@code lock <name> X|S} → GOT or BUSY (no waiting)</li>
 * <li>{@code release <name>} → OK</li>
 * <li>{@code claim <id>} → CLAIMED or REFUSED</li>
 * </ul>
 * Arguments: the root's path, the sharing, the provider, the lease and renew times in ms.
 */
public final class LocksWorker {

	static final String PREFIX = "WORKER: ";

	private LocksWorker() {
	}

	public static void main(String[] args) throws Exception {
		FileSource root = FileSourceFactory.getDefaultFactory().createFileSource(args[0]);
		LockOptions o = LockOptions.sharing(Sharing.valueOf(args[1])).withProvider(args[2])
				.withLease(Duration.ofMillis(Long.parseLong(args[3])), Duration.ofMillis(Long.parseLong(args[4])))
				.withOwnerId("worker");
		Map<String, NamedLock> held = new HashMap<>();
		try (Locks locks = Locks.open(o)) {
			LockDomain space = locks.domain("test", root);
			System.out.println(PREFIX + "READY");
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
			String line;
			while ((line = in.readLine()) != null) {
				String[] p = line.trim().split(" ");
				String reply;
				try {
					switch (p[0]) {
					case "lock": {
						NamedLock l = space.tryLock(p[1], "S".equals(p[2]) ? Mode.SHARED : Mode.EXCLUSIVE);
						if( l != null ) {
							held.put(p[1], l);
						}
						reply = l == null ? "BUSY" : "GOT";
						break;
					}
					case "release":
						held.remove(p[1]).close();
						reply = "OK";
						break;
					case "claim":
						try {
							space.claimStore(p[1]);
							reply = "CLAIMED";
						} catch (StoreClaimException e) {
							reply = "REFUSED";
						}
						break;
					default:
						reply = "?" + line;
					}
				} catch (Exception e) {
					reply = "ERROR " + e;
				}
				System.out.println(PREFIX + reply);
			}
		}
	}
}
