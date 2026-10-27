package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;

/**
 * The rules of Locks among the threads of one JVM, the store claim and AtomicWrite, for one
 * way of keeping the locks. Subclasses give the store and the options.
 */
public abstract class AbstractLocksTests {

	protected static final Duration SHORT = Duration.ofMillis(300);
	protected static final Duration LONG = Duration.ofSeconds(10);

	/** A new, empty store root. */
	protected abstract FileSource newRoot() throws Exception;

	/** The options the tests run with (a short lease where there are leases). */
	protected abstract LockOptions options();

	protected FileSource root;
	protected LockDomain space;
	protected final List<Locks> spaces = new ArrayList<>();
	protected final ExecutorService pool = Executors.newCachedThreadPool();

	@BeforeEach
	public void openSpace() throws Exception {
		root = newRoot();
		space = open(options());
	}

	/** Another server on the same store: a Locks of its own, with the store as domain "test". */
	protected LockDomain open(LockOptions o) throws Exception {
		Locks s = Locks.open(o);
		spaces.add(s);
		return s.domain("test", root);
	}

	@AfterEach
	public void closeSpaces() {
		pool.shutdownNow();
		for (Locks s : spaces) {
			s.close();
		}
	}

	/** Run on a new thread of its own and wait for the answer. */
	protected <T> T elsewhere(java.util.concurrent.Callable<T> c) throws Exception {
		ExecutorService one = Executors.newSingleThreadExecutor();
		try {
			return one.submit(c).get(30, TimeUnit.SECONDS);
		} finally {
			one.shutdown();
		}
	}

	/** A thread that keeps what it takes until told to let go. */
	protected static final class Holder implements AutoCloseable {
		private final ExecutorService thread = Executors.newSingleThreadExecutor();

		<T> T run(java.util.concurrent.Callable<T> c) throws Exception {
			return thread.submit(c).get(30, TimeUnit.SECONDS);
		}

		@Override
		public void close() {
			thread.shutdownNow();
		}
	}

	// ------------------------------------------------------------------ closing a domain

	@Test
	public void closingADomainLetsGoOfWhatItHolds() throws Exception {
		Locks mine = spaces.get(0);
		LockDomain other = open(options().withOwnerId("other"));
		try (Holder h = new Holder()) {
			NamedLock held = h.run(() -> space.lock("box", Mode.EXCLUSIVE, LONG));
			java.util.concurrent.Future<NamedLock> waiter = pool.submit(() -> space.lock("box", Mode.EXCLUSIVE, LONG));
			Thread.sleep(200);
			space.close();
			java.util.concurrent.ExecutionException x = assertThrows(java.util.concurrent.ExecutionException.class,
					() -> waiter.get(5, TimeUnit.SECONDS));
			assertTrue(x.getCause() instanceof IOException && x.getCause().getMessage().contains("closed"), "the waiter: " + x.getCause());
			assertFalse(held.isValid(), "the holding still open finds it lost");
			assertThrows(LockLostException.class, held::checkValid);
			assertTrue(elsewhere(() -> {
				try (NamedLock y = other.tryLock("box", Mode.EXCLUSIVE)) {
					return y != null;
				}
			}), "another server can take it");
			LockDomain again = mine.domain("test", root);
			assertTrue(elsewhere(() -> {
				try (NamedLock y = again.tryLock("box", Mode.EXCLUSIVE)) {
					return y != null;
				}
			}), "and so can the domain registered again");
			h.run(() -> {
				held.close(); // later: harmless
				return null;
			});
			assertTrue(elsewhere(() -> {
				try (NamedLock y = again.tryLock("box", Mode.EXCLUSIVE)) {
					return y != null;
				}
			}), "still free");
			assertThrows(IOException.class, () -> space.tryLock("box", Mode.EXCLUSIVE), "the closed domain takes nothing");
		}
	}

	// ------------------------------------------------------------------ among threads

	@Test
	public void exclusiveKeepsOtherThreadsOut() throws Exception {
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertTrue(l.isValid());
			assertNull(elsewhere(() -> space.tryLock("box", Mode.EXCLUSIVE)), "exclusive");
			assertNull(elsewhere(() -> space.tryLock("box", Mode.SHARED)), "shared");
			NamedLock other = elsewhere(() -> {
				NamedLock x = space.tryLock("other", Mode.EXCLUSIVE);
				if( x != null ) {
					x.close();
				}
				return x;
			});
			assertNotNull(other, "another name is free");
		}
		NamedLock after = elsewhere(() -> {
			NamedLock x = space.tryLock("box", Mode.EXCLUSIVE);
			x.close();
			return x;
		});
		assertNotNull(after, "free once closed");
	}

	@Test
	public void reentrantLikeSynchronized() throws Exception {
		try (NamedLock outer = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			try (NamedLock inner = space.lock("box", Mode.EXCLUSIVE, LONG)) {
				assertTrue(inner.isValid());
				assertNull(elsewhere(() -> space.tryLock("box", Mode.EXCLUSIVE)));
			}
			assertTrue(outer.isValid(), "still held after the inner holding closes");
			assertNull(elsewhere(() -> space.tryLock("box", Mode.EXCLUSIVE)), "and still keeps others out");
		}
		assertNotNull(elsewhere(() -> {
			NamedLock x = space.tryLock("box", Mode.EXCLUSIVE);
			x.close();
			return x;
		}), "free when the outermost closes");
	}

	@Test
	public void notReentrantWhenAsked() throws Exception {
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertThrows(IllegalStateException.class, () -> space.request("box").reentrant(false).acquire());
			assertTrue(l.isValid(), "the first holding is untouched");
		}
		LockDomain strict = open(options().withReentrant(false));
		try (NamedLock l = strict.lock("strict", Mode.EXCLUSIVE, LONG)) {
			assertThrows(IllegalStateException.class, () -> strict.lock("strict", Mode.EXCLUSIVE, LONG), "the space's default");
			try (NamedLock again = strict.request("strict").reentrant(true).acquire()) {
				assertTrue(again.isValid(), "a request can still ask for reentrancy");
			}
		}
	}

	@Test
	public void sharedCantBeUpgradedButExclusiveCanBeAskedShared() throws Exception {
		try (NamedLock r = space.lock("box", Mode.SHARED, LONG)) {
			assertThrows(IllegalStateException.class, () -> space.lock("box", Mode.EXCLUSIVE, LONG));
			try (NamedLock r2 = space.lock("box", Mode.SHARED, LONG)) {
				assertEquals(Mode.SHARED, r2.mode());
			}
		}
		try (NamedLock w = space.lock("box", Mode.EXCLUSIVE, LONG); NamedLock r = space.lock("box", Mode.SHARED, LONG)) {
			assertEquals(Mode.EXCLUSIVE, r.mode(), "still held exclusive");
			assertNull(elsewhere(() -> space.tryLock("box", Mode.SHARED)), "others are still kept out");
		}
	}

	@Test
	public void onlyTheHolderLetsGo() throws Exception {
		NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG);
		Exception e = assertThrows(java.util.concurrent.ExecutionException.class, () -> elsewhere(() -> {
			l.close();
			return null;
		}));
		assertTrue(e.getCause() instanceof IllegalMonitorStateException, String.valueOf(e.getCause()));
		assertTrue(l.isValid());
		l.close();
		l.close(); // twice does nothing more
		assertFalse(l.isValid());
		assertThrows(LockLostException.class, l::checkValid);
	}

	@Test
	public void waitsThenTimesOut() throws Exception {
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			long start = System.nanoTime();
			Exception e = assertThrows(java.util.concurrent.ExecutionException.class,
					() -> elsewhere(() -> space.lock("box", Mode.EXCLUSIVE, SHORT)));
			long ms = (System.nanoTime() - start) / 1_000_000;
			assertTrue(e.getCause() instanceof LockTimeoutException, String.valueOf(e.getCause()));
			assertTrue(ms >= SHORT.toMillis() - 20 && ms < 5000, "waited about the timeout: " + ms + " ms");
		}
	}

	@Test
	public void aWaiterGetsItWhenTheHolderLetsGo() throws Exception {
		NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG);
		CountDownLatch asking = new CountDownLatch(1);
		Future<Boolean> waiter = pool.submit(() -> {
			asking.countDown();
			try (NamedLock x = space.lock("box", Mode.EXCLUSIVE, LONG)) {
				return x.isValid();
			}
		});
		asking.await();
		Thread.sleep(100);
		l.close();
		assertTrue(waiter.get(10, TimeUnit.SECONDS));
	}

	@Test
	public void readersShareAndAWriterWaitsForThem() throws Exception {
		try (Holder other = new Holder()) {
			NamedLock r1 = space.lock("box", Mode.SHARED, LONG);
			NamedLock r2 = other.run(() -> space.tryLock("box", Mode.SHARED));
			assertNotNull(r2, "a second reader");
			assertNull(elsewhere(() -> space.tryLock("box", Mode.EXCLUSIVE)), "no writer while there are readers");
			r1.close();
			assertNull(elsewhere(() -> space.tryLock("box", Mode.EXCLUSIVE)), "nor while one is left");
			other.run(() -> {
				r2.close();
				return null;
			});
			assertNotNull(elsewhere(() -> {
				NamedLock x = space.tryLock("box", Mode.EXCLUSIVE);
				x.close();
				return x;
			}), "a writer once they're gone");
		}
	}

	/** A reader that comes while a writer waits queues behind the writer, so writers aren't starved. */
	@Test
	public void aWaitingWriterGoesBeforeLaterReaders() throws Exception {
		NamedLock r = space.lock("box", Mode.SHARED, LONG);
		List<String> order = Collections.synchronizedList(new ArrayList<>());
		Future<?> writer = pool.submit(() -> {
			try (NamedLock w = space.lock("box", Mode.EXCLUSIVE, LONG)) {
				order.add("writer");
				Thread.sleep(50);
			}
			return null;
		});
		Thread.sleep(150);
		Future<?> reader = pool.submit(() -> {
			try (NamedLock x = space.lock("box", Mode.SHARED, LONG)) {
				order.add("reader");
			}
			return null;
		});
		Thread.sleep(150);
		assertTrue(order.isEmpty(), "the later reader waits behind the writer: " + order);
		r.close();
		writer.get(10, TimeUnit.SECONDS);
		reader.get(10, TimeUnit.SECONDS);
		assertEquals(Arrays.asList("writer", "reader"), order);
	}

	@Test
	public void waitersAreServedInTheOrderTheyCame() throws Exception {
		NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG);
		List<Integer> order = Collections.synchronizedList(new ArrayList<>());
		List<Future<?>> all = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			int n = i;
			all.add(pool.submit(() -> {
				try (NamedLock x = space.lock("box", Mode.EXCLUSIVE, LONG)) {
					order.add(n);
				}
				return null;
			}));
			Thread.sleep(80); // so they arrive in order
		}
		l.close();
		for (Future<?> f : all) {
			f.get(20, TimeUnit.SECONDS);
		}
		assertEquals(Arrays.asList(0, 1, 2, 3, 4), order);
	}

	@Test
	public void lockAllTakesAllOrNone() throws Exception {
		try (Holder other = new Holder()) {
			NamedLock b = other.run(() -> space.lock("b", Mode.EXCLUSIVE, LONG));
			assertThrows(LockTimeoutException.class, () -> space.lockAll(Arrays.asList("c", "b", "a"), Mode.EXCLUSIVE, SHORT));
			assertNotNull(elsewhere(() -> {
				NamedLock x = space.tryLock("a", Mode.EXCLUSIVE);
				x.close();
				return x;
			}), "a was let go again");
			other.run(() -> {
				b.close();
				return null;
			});
		}
		try (LockGroup g = space.lockAll(Arrays.asList("c", "b", "a"), Mode.EXCLUSIVE, LONG)) {
			assertEquals(Arrays.asList("a", "b", "c"), Arrays.asList(g.locks().get(0).name(), g.locks().get(1).name(),
					g.locks().get(2).name()), "taken in one order");
		}
		assertNotNull(elsewhere(() -> {
			NamedLock x = space.tryLock("b", Mode.EXCLUSIVE);
			x.close();
			return x;
		}));
	}

	@Test
	public void anInterruptedWaiterHoldsNothing() throws Exception {
		NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG);
		Future<Boolean> waiter = pool.submit(() -> {
			try {
				space.lock("box", Mode.EXCLUSIVE, LONG).close();
				return false;
			} catch (InterruptedIOException e) {
				return Thread.currentThread().isInterrupted();
			}
		});
		Thread.sleep(150);
		waiter.cancel(true);
		Thread.sleep(150);
		l.close();
		assertNotNull(elsewhere(() -> {
			NamedLock x = space.tryLock("box", Mode.EXCLUSIVE);
			x.close();
			return x;
		}), "the interrupted request left nothing behind");
	}

	@Test
	public void namesForTheFrameworkAreRefused() {
		assertThrows(IllegalArgumentException.class, () -> space.tryLock(".parley/store", Mode.EXCLUSIVE));
		assertThrows(IllegalArgumentException.class, () -> space.tryLock("", Mode.EXCLUSIVE));
	}

	@Test
	public void aManyThreadedCounterLosesNothing() throws Exception {
		AtomicInteger inside = new AtomicInteger();
		int[] counter = {0};
		List<Future<?>> all = new ArrayList<>();
		for (int t = 0; t < 8; t++) {
			all.add(pool.submit(() -> {
				for (int i = 0; i < 25; i++) {
					try (NamedLock l = space.lock("counter", Mode.EXCLUSIVE, LONG)) {
						assertEquals(1, inside.incrementAndGet(), "one holder at a time");
						counter[0]++;
						inside.decrementAndGet();
					}
				}
				return null;
			}));
		}
		for (Future<?> f : all) {
			f.get(60, TimeUnit.SECONDS);
		}
		assertEquals(200, counter[0]);
	}

	// ------------------------------------------------------------------ the store claim

	@Test
	public void aStoreClaimedAloneRefusesASecondServer() throws Exception {
		LockDomain a = open(withSharing(Sharing.OFF).withOwnerId("a"));
		LockDomain b = open(withSharing(Sharing.OFF).withOwnerId("b"));
		StoreClaim ca = a.claimStore("a");
		assertTrue(ca.isValid());
		assertThrows(StoreClaimException.class, () -> b.claimStore("b"));
		ca.close();
		try (StoreClaim cb = b.claimStore("b")) {
			assertTrue(cb.isValid(), "free once the first lets go");
		}
	}

	/**
	 * A server of this JVM gets the answer a server in another process would: with sharing off, a
	 * second server of the same JVM is refused too.
	 */
	@Test
	public void aSecondServerInTheSameJvmIsRefusedWhenSharingIsOff() throws Exception {
		LockDomain a = open(withSharing(Sharing.OFF).withOwnerId("a"));
		LockDomain b = open(withSharing(Sharing.OFF).withOwnerId("b"));
		StoreClaim imap = a.claimStore("imap");
		assertTrue(imap.isValid());
		assertThrows(StoreClaimException.class, () -> a.claimStore("pop3"), "same JVM, as another process would be");
		assertThrows(StoreClaimException.class, () -> b.claimStore("b"));
		imap.close();
		assertFalse(imap.isValid());
		try (StoreClaim pop3 = a.claimStore("pop3")) {
			assertTrue(pop3.isValid(), "free once the first lets go");
		}
	}

	/** Sharing servers of one JVM claim the store together, each with its own id. */
	@Test
	public void sharingServersInOneJvmNeedTheirOwnIds() throws Exception {
		LockDomain a = open(withSharing(Sharing.CLUSTER).withOwnerId("a"));
		LockDomain alone = open(withSharing(Sharing.OFF).withOwnerId("alone"));
		StoreClaim imap = a.claimStore("imap");
		StoreClaim pop3 = a.claimStore("pop3");
		assertTrue(imap.isValid() && pop3.isValid());
		assertThrows(StoreClaimException.class, () -> a.claimStore("imap"), "two running servers with one id");
		imap.close();
		assertFalse(imap.isValid());
		assertTrue(pop3.isValid(), "still claimed while one server runs");
		assertThrows(StoreClaimException.class, () -> alone.claimStore("alone"), "and still keeps a lone server out");
		try (StoreClaim again = a.claimStore("imap")) {
			assertTrue(again.isValid(), "its id is free again");
		}
		pop3.close();
		try (StoreClaim c = alone.claimStore("alone")) {
			assertTrue(c.isValid(), "free once the last closes");
		}
	}

	/** A server that shares the store and one that wants it alone exclude each other, both ways. */
	@Test
	public void aSharingServerAndALoneOneExcludeEachOther() throws Exception {
		LockDomain sharer = open(withSharing(Sharing.CLUSTER).withOwnerId("sharer"));
		LockDomain alone = open(withSharing(Sharing.OFF).withOwnerId("alone"));
		try (StoreClaim c = sharer.claimStore("sharer")) {
			assertThrows(StoreClaimException.class, () -> alone.claimStore("alone"));
		}
		try (StoreClaim c = alone.claimStore("alone")) {
			assertThrows(StoreClaimException.class, () -> sharer.claimStore("sharer"));
		}
	}

	/**
	 * The options with another sharing, keeping the provider this suite's domain uses (every server
	 * on a store must use the same one), allowed even where it would be unsafe for that sharing.
	 */
	protected LockOptions withSharing(Sharing s) {
		LockOptions o = options();
		return LockOptions.sharing(s).withLease(o.lease(), o.renew()).withTimeout(o.timeout()).withProvider(space.provider().id())
				.withAllowUnsafe(true);
	}

	// ------------------------------------------------------------------ AtomicWrite

	@Test
	public void atomicWriteReplacesTheFile() throws Exception {
		FileSource f = root.getChild("index");
		try (NamedLock l = space.lock("index", Mode.EXCLUSIVE, LONG)) {
			AtomicWrite.replace(f, l, out -> out.write("one".getBytes(StandardCharsets.UTF_8)));
			AtomicWrite.replace(f, l, out -> out.write("two".getBytes(StandardCharsets.UTF_8)));
		}
		assertEquals("two", read(f));
		assertEquals(0, tempFiles(), "no temporary files left");
	}

	@Test
	public void atomicWriteUnderALostLockWritesNothing() throws Exception {
		FileSource f = root.getChild("index");
		NamedLock l = space.lock("index", Mode.EXCLUSIVE, LONG);
		AtomicWrite.replace(f, l, out -> out.write("kept".getBytes(StandardCharsets.UTF_8)));
		l.close();
		assertThrows(LockLostException.class,
				() -> AtomicWrite.replace(f, l, out -> out.write("lost".getBytes(StandardCharsets.UTF_8))));
		assertEquals("kept", read(f));
		assertEquals(0, tempFiles());
	}

	protected static String read(FileSource f) throws Exception {
		try (InputStream in = f.getInputStream()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	private int tempFiles() throws Exception {
		int n = 0;
		for (FileSource k : root.listFiles()) {
			if( k.getName().endsWith(".tmp") ) {
				n++;
			}
		}
		return n;
	}

}
