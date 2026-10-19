package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/** A local directory shared between machines (as over NFS): local locks don't reach, so leases. */
public class LocalLeaseLocksTest extends AbstractLocalLocksTests {
	@Override
	protected LockOptions options() {
		return LockOptions.sharing(Sharing.CLUSTER).withLease(Duration.ofSeconds(1), Duration.ofMillis(200));
	}

	@Override
	protected long deadHolderFreedWithinMs() {
		return 1000;
	}

	@Test
	public void leasesAreChosen() {
		assertTrue(space.provider().id().equals(LeaseLockProvider.ID), space.describe());
	}
}
