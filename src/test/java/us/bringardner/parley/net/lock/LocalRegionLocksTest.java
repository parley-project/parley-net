package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** A local directory shared within the machine: region locks (the OS's, through parley-files). */
public class LocalRegionLocksTest extends AbstractLocalLocksTests {
	@Override
	protected LockOptions options() {
		return LockOptions.sharing(Sharing.HOST);
	}

	@Override
	protected long deadHolderFreedWithinMs() {
		return 0;
	}

	@Test
	public void regionLocksAreChosen() {
		assertTrue(space.provider().id().equals(RegionLockProvider.ID), space.describe());
	}
}
