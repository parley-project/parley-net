package us.bringardner.parley.net.lock;

import java.time.Duration;

import us.bringardner.parley.files.FileSource;

/** Sharing OFF: names within the JVM, the store claim by lease (memory locks reach only the process). */
public class InJvmLocksTest extends AbstractLocksTests {
	@Override
	protected FileSource newRoot() throws Exception {
		return MemoryRoots.newRoot();
	}

	@Override
	protected LockOptions options() {
		return LockOptions.sharing(Sharing.OFF).withLease(Duration.ofSeconds(1), Duration.ofMillis(200));
	}
}
