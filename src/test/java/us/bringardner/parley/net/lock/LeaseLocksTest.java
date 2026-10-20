package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;

/** Leases (chosen on their own: memory locks don't reach a cluster), with a 1 s lease. */
public class LeaseLocksTest extends AbstractLocksTests {
	@Override
	protected FileSource newRoot() throws Exception {
		return MemoryRoots.newRoot();
	}

	@Override
	protected LockOptions options() {
		return LockOptions.sharing(Sharing.CLUSTER).withLease(Duration.ofSeconds(1), Duration.ofMillis(200));
	}

	private FileSource leases() throws Exception {
		return root.getChild(Locks.DIRECTORY).getChild(LeaseLockService.DIR);
	}

	/** The writer's marker for a name. */
	private FileSource leaseDir(String name) throws Exception {
		return leases().getChild(LeaseLockService.dirName(name) + LeaseLockService.WRITER);
	}

	private void fakeEntry(FileSource d, String owner) throws Exception {
		assertTrue(d.mkdirs());
		try (OutputStream out = d.getChild(LeaseLockService.OWNER).getOutputStream()) {
			out.write(("name=box\nowner=" + owner + "\ntoken=t\nbeat=0\n").getBytes(StandardCharsets.UTF_8));
		}
	}

	private FileSource readerEntry(String name) throws Exception {
		for (FileSource k : leases().listFiles()) {
			if( k.getName().startsWith(LeaseLockService.dirName(name) + LeaseLockService.READER) ) {
				return k;
			}
		}
		return null;
	}

	@Test
	public void readersOnSeveralServersShare() throws Exception {
		LockDomain a = open(options().withOwnerId("a"));
		LockDomain b = open(options().withOwnerId("b"));
		try (NamedLock ra = a.lock("box", Mode.SHARED, LONG); NamedLock rb = b.lock("box", Mode.SHARED, LONG)) {
			assertTrue(ra.isValid() && rb.isValid(), "both read at once");
			assertNull(space.tryLock("box", Mode.EXCLUSIVE), "and no writer gets in");
			Thread.sleep(1500); // past a lease: both renewed
			ra.checkValid();
			rb.checkValid();
		}
		try (NamedLock w = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertTrue(w.isValid(), "a writer once they're gone");
		}
	}

	@Test
	public void aWriterWaitsForReadersOnOtherServersAndKeepsNewOnesOut() throws Exception {
		LockDomain a = open(options().withOwnerId("a"));
		LockDomain b = open(options().withOwnerId("b"));
		try (Holder reader = new Holder()) {
			NamedLock ra = reader.run(() -> a.lock("box", Mode.SHARED, LONG));
			java.util.concurrent.Future<Boolean> writer = pool.submit(() -> {
				try (NamedLock w = space.lock("box", Mode.EXCLUSIVE, LONG)) {
					return w.isValid();
				}
			});
			Thread.sleep(300);
			assertFalse(writer.isDone(), "the writer waits for the reader");
			assertNull(b.tryLock("box", Mode.SHARED), "a new reader waits behind the writer");
			reader.run(() -> {
				ra.close();
				return null;
			});
			assertTrue(writer.get(10, java.util.concurrent.TimeUnit.SECONDS));
		}
		try (NamedLock rb = b.lock("box", Mode.SHARED, LONG)) {
			assertTrue(rb.isValid(), "then the new reader");
		}
	}

	@Test
	public void aWriterThatGivesUpLetsReadersIn() throws Exception {
		LockDomain a = open(options().withOwnerId("a"));
		LockDomain b = open(options().withOwnerId("b"));
		try (NamedLock ra = a.lock("box", Mode.SHARED, LONG)) {
			assertNull(space.tryLock("box", Mode.EXCLUSIVE), "tryLock: busy, and takes its marker back");
			assertThrows(LockTimeoutException.class, () -> space.lock("box", Mode.EXCLUSIVE, SHORT));
			try (NamedLock rb = b.tryLock("box", Mode.SHARED)) {
				assertNotNull(rb, "no marker was left behind");
			}
		}
	}

	@Test
	public void aDeadReadersEntryIsTakenOverByAWriter() throws Exception {
		fakeEntry(leases().getChild(LeaseLockService.dirName("box") + LeaseLockService.READER + "dead"), "dead");
		long start = System.nanoTime();
		try (NamedLock w = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			long ms = (System.nanoTime() - start) / 1_000_000;
			assertTrue(ms >= 900, "after a whole lease unchanged: " + ms + " ms");
		}
	}

	@Test
	public void aDeadWritersMarkerIsTakenOverByAReader() throws Exception {
		fakeEntry(leaseDir("box"), "dead");
		try (NamedLock r = space.lock("box", Mode.SHARED, LONG)) {
			r.checkValid();
		}
	}

	@Test
	public void aReaderTakenOverIsReportedLost() throws Exception {
		NamedLock r = space.lock("box", Mode.SHARED, LONG);
		try (OutputStream out = readerEntry("box").getChild(LeaseLockService.OWNER).getOutputStream()) {
			out.write("name=box\nowner=thief\ntoken=other\nbeat=0\n".getBytes(StandardCharsets.UTF_8));
		}
		assertThrows(LockLostException.class, r::checkValid);
		r.close();
	}

	/** Two sharing servers (here two spaces: leases don't care which JVM they're in). */
	@Test
	public void sharingServersAdmitEachOther() throws Exception {
		LockDomain a = open(options().withOwnerId("a"));
		LockDomain b = open(options().withOwnerId("b"));
		try (StoreClaim ca = a.claimStore("a"); StoreClaim cb = b.claimStore("b")) {
			assertTrue(ca.isValid() && cb.isValid());
			LockDomain c = open(options().withOwnerId("c"));
			assertThrows(StoreClaimException.class, () -> c.claimStore("a"), "but not two with one id");
		}
	}

	@Test
	public void leasesAreChosenWhereLocksDontReach() {
		assertEquals(LeaseLockProvider.ID, space.provider().id(), space.describe());
	}

	@Test
	public void anotherServersLeaseKeepsUsOut() throws Exception {
		LockDomain other = open(options().withOwnerId("other"));
		try (NamedLock l = other.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertNull(space.tryLock("box", Mode.EXCLUSIVE));
			Thread.sleep(1500); // longer than a lease: it is renewed, so it stays
			assertNull(space.tryLock("box", Mode.EXCLUSIVE), "renewed, not stale");
			assertTrue(l.isValid());
			l.checkValid();
		}
		try (NamedLock mine = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertNotNull(mine);
		}
	}

	@Test
	public void aDeadServersLeaseIsTakenOver() throws Exception {
		fakeEntry(leaseDir("box"), "dead");
		long start = System.nanoTime();
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			long ms = (System.nanoTime() - start) / 1_000_000;
			assertTrue(ms >= 900, "after a whole lease unchanged: " + ms + " ms");
			l.checkValid();
		}
	}

	@Test
	public void aServerThatDiedBeforeWritingItsOwnerIsTakenOver() throws Exception {
		assertTrue(leaseDir("box").mkdirs());
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			l.checkValid();
		}
	}

	@Test
	public void aLeaseTakenOverIsReportedLost() throws Exception {
		NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG);
		// as if another server decided it was stale and took it
		try (OutputStream out = leaseDir("box").getChild(LeaseLockService.OWNER).getOutputStream()) {
			out.write("name=box\nowner=thief\ntoken=other\nbeat=0\n".getBytes(StandardCharsets.UTF_8));
		}
		assertThrows(LockLostException.class, l::checkValid);
		Thread.sleep(500);
		assertFalse(l.isValid(), "the renewer saw it too");
		l.close();
	}

	/**
	 * A holder that was paused for most of a lease (a long garbage collection, say) wakes up to
	 * find its lease lost, and never renews it: by then another server may be taking it over.
	 */
	@Test
	public void aPausedHolderStopsTrustingItsLeaseAndDoesntRenewIt() throws Exception {
		LeaseLockService svc = new LeaseLockService(MemoryRoots.newRoot(), "a", Duration.ofSeconds(1), Duration.ofMillis(200), true);
		try {
			LeaseLockService.LeaseHandle h = (LeaseLockService.LeaseHandle) svc.tryAcquire("box", Mode.EXCLUSIVE);
			assertNotNull(h);
			assertTrue(h.isValid());
			// as if this process was paused: its last renewal is a lease minus a renew interval old
			h.lastRenew = System.nanoTime() - Duration.ofMillis(810).toNanos();
			assertFalse(h.isValid(), "no longer trusted");
			assertThrows(LockLostException.class, h::verify);
			long beat = h.beat;
			Thread.sleep(600); // a few renewer runs
			assertEquals(beat, h.beat, "and not renewed");
		} finally {
			svc.close();
		}
	}

	/** A takeover marker left by a server that died while taking over is cleared after a lease. */
	@Test
	public void aDeadTakersMarkerIsClearedAndTheLeaseTakenOver() throws Exception {
		fakeEntry(leaseDir("box"), "dead");
		fakeEntry(leases().getChild(leaseDir("box").getName() + ".stale-taking"), "dead-taker");
		long start = System.nanoTime();
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			long ms = (System.nanoTime() - start) / 1_000_000;
			assertTrue(ms >= 1800, "the marker after a lease, then the entry: " + ms + " ms");
			l.checkValid();
		}
		assertFalse(leases().getChild(leaseDir("box").getName() + ".stale-taking").exists(), "the marker is gone");
	}

	@Test
	public void theRenewIntervalIsAtMostAThirdOfTheLease() {
		assertThrows(IllegalArgumentException.class, () -> options().withLease(Duration.ofSeconds(1), Duration.ofMillis(400)));
		options().withLease(Duration.ofSeconds(3), Duration.ofSeconds(1));
	}
}
