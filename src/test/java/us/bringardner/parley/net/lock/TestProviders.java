package us.bringardner.parley.net.lock;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.spi.LockContext;
import us.bringardner.parley.net.lock.spi.LockHandle;
import us.bringardner.parley.net.lock.spi.LockProvider;
import us.bringardner.parley.net.lock.spi.LockService;

/** Providers for the tests. */
public final class TestProviders {

	private TestProviders() {
	}

	/** One that never works. */
	public static final class Unsupported implements LockProvider {
		@Override
		public String id() {
			return "unsupported-test";
		}

		@Override
		public Fit fit(FileSourceCapabilities capabilities, Sharing sharing) {
			return Fit.UNSUPPORTED;
		}

		@Override
		public LockService open(LockContext context) {
			throw new AssertionError("never opened");
		}
	}

	/**
	 * Locks in a static set (one JVM): registered with ServiceLoader under the id
	 * {@code in-memory-test}, with priority 0 unless {@link #PRIORITY_PROPERTY} is true.
	 */
	public static final class InMemory implements LockProvider {
		static final String PRIORITY_PROPERTY = "parley.test.inMemoryProviderPriority";
		private static final Set<String> HELD = ConcurrentHashMap.newKeySet();

		static boolean held(String name) {
			return HELD.contains(name);
		}

		@Override
		public String id() {
			return "in-memory-test";
		}

		@Override
		public int priority() {
			return Boolean.getBoolean(PRIORITY_PROPERTY) ? 10 : 0;
		}

		@Override
		public Fit fit(FileSourceCapabilities capabilities, Sharing sharing) {
			return Fit.SAFE;
		}

		@Override
		public LockService open(LockContext context) {
			return new LockService() {
				@Override
				public LockHandle tryAcquire(String name, Mode mode) {
					return HELD.add(name) ? () -> HELD.contains(name) : null;
				}

				@Override
				public void release(LockHandle h) {
					HELD.clear();
				}

				@Override
				public void close() {
				}
			};
		}
	}

	/** Locks in a static set, but the store "fails" when a server id is asked for. */
	public static final class FailsOnServerId implements LockProvider {
		static final Set<String> HELD = ConcurrentHashMap.newKeySet();

		@Override
		public String id() {
			return "fails-on-server-id-test";
		}

		@Override
		public Fit fit(FileSourceCapabilities capabilities, Sharing sharing) {
			return Fit.SAFE;
		}

		@Override
		public LockService open(LockContext context) {
			return new LockService() {
				@Override
				public LockHandle tryAcquire(String name, Mode mode) throws java.io.IOException {
					if( name.contains(Locks.SERVER) ) {
						throw new java.io.IOException("the store failed");
					}
					if( !HELD.add(name) ) {
						return null;
					}
					return new LockHandle() {
						@Override
						public boolean isValid() {
							return HELD.contains(name);
						}

						@Override
						public String toString() {
							return name;
						}
					};
				}

				@Override
				public void release(LockHandle h) {
					HELD.remove(h.toString());
				}

				@Override
				public void close() {
				}
			};
		}
	}
}
