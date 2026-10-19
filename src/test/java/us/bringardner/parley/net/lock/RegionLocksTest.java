package us.bringardner.parley.net.lock;

import us.bringardner.parley.files.FileSource;

/** Region locks, forced on a memory store (unsafe between servers, so allowed explicitly). */
public class RegionLocksTest extends AbstractLocksTests {
	@Override
	protected FileSource newRoot() throws Exception {
		return MemoryRoots.newRoot();
	}

	@Override
	protected LockOptions options() {
		return LockOptions.sharing(Sharing.CLUSTER).withProvider(RegionLockProvider.ID).withAllowUnsafe(true);
	}
}
