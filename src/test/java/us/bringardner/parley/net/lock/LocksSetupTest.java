package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.files.lock.LockScope;
import us.bringardner.parley.net.lock.spi.LockProvider;

/** Choosing a provider, the safety rules, coordination stores and several domains. */
public class LocksSetupTest {

	private static final Duration LONG = Duration.ofSeconds(10);
	private final List<Locks> opened = new ArrayList<>();

	@AfterEach
	public void close() {
		for (Locks l : opened) {
			l.close();
		}
	}

	private Locks locks(LockOptions o) {
		Locks l = Locks.open(o);
		opened.add(l);
		return l;
	}

	private static FileSource localRoot() throws Exception {
		File d = Files.createTempDirectory("parley-net-setup").toFile();
		d.deleteOnExit();
		return FileSourceFactory.getDefaultFactory().createFileSource(d.getCanonicalPath());
	}

	private static LockOptions opts(Sharing s) {
		return LockOptions.sharing(s).withLease(Duration.ofSeconds(1), Duration.ofMillis(200));
	}

	// ------------------------------------------------------------------ auto

	@Test
	public void autoUsesTheStoresOwnLocksWhereTheyReach() throws Exception {
		assertEquals(RegionLockProvider.ID, locks(opts(Sharing.HOST)).domain("d", localRoot()).provider().id(), "local disk, one machine");
		assertEquals(RegionLockProvider.ID, locks(opts(Sharing.OFF)).domain("d", localRoot()).provider().id(), "local disk, one server");
	}

	@Test
	public void autoUsesLeasesWhereTheyDont() throws Exception {
		assertEquals(LeaseLockProvider.ID, locks(opts(Sharing.CLUSTER)).domain("d", localRoot()).provider().id(), "local disk, many machines");
		assertEquals(LeaseLockProvider.ID, locks(opts(Sharing.CLUSTER)).domain("d", MemoryRoots.newRoot()).provider().id(), "PROCESS-scope store");
		assertEquals(LeaseLockProvider.ID, locks(opts(Sharing.OFF)).domain("d", MemoryRoots.newRoot()).provider().id(),
				"one server on a PROCESS-scope store: the claim needs leases");
	}

	@Test
	public void theBuiltInProvidersJudgeCapabilities() {
		FileSourceCapabilities process = FileSourceCapabilities.defaults(LockScope.PROCESS);
		FileSourceCapabilities host = FileSourceCapabilities.defaults(LockScope.HOST);
		FileSourceCapabilities cluster = FileSourceCapabilities.defaults(LockScope.CLUSTER);
		RegionLockProvider region = new RegionLockProvider();
		assertEquals(LockProvider.Fit.UNSAFE, region.fit(process, Sharing.OFF));
		assertEquals(LockProvider.Fit.SAFE, region.fit(host, Sharing.HOST));
		assertEquals(LockProvider.Fit.UNSAFE, region.fit(host, Sharing.CLUSTER));
		assertEquals(LockProvider.Fit.SAFE, region.fit(cluster, Sharing.CLUSTER));
		LeaseLockProvider lease = new LeaseLockProvider();
		assertEquals(LockProvider.Fit.SAFE, lease.fit(process, Sharing.CLUSTER));
		assertEquals(LockProvider.Fit.UNSUPPORTED, lease.fit(process.withAtomicMkdir(false), Sharing.CLUSTER));
	}

	// ------------------------------------------------------------------ the safety rules

	@Test
	public void anUnsafeProviderIsRefusedUnlessAllowed() throws Exception {
		FileSource root = MemoryRoots.newRoot();
		LockSetupException e = assertThrows(LockSetupException.class,
				() -> locks(opts(Sharing.CLUSTER).withProvider("region")).domain("d", root));
		assertTrue(e.getMessage().contains(LockOptions.ALLOW_UNSAFE_PROPERTY), e.getMessage());
		LockDomain d = locks(opts(Sharing.CLUSTER).withProvider("region").withAllowUnsafe(true)).domain("d", root);
		assertEquals(RegionLockProvider.ID, d.provider().id(), "you said you know better");
	}

	@Test
	public void aProviderThatCantWorkIsRefusedEvenIfAllowed() throws Exception {
		LockSetupException e = assertThrows(LockSetupException.class,
				() -> locks(opts(Sharing.CLUSTER).withProvider(TestProviders.Unsupported.class.getName()).withAllowUnsafe(true))
						.domain("d", MemoryRoots.newRoot()));
		assertTrue(e.getMessage().contains("can't be used"), e.getMessage());
	}

	@Test
	public void serversMustKeepAStoresLocksTheSameWay() throws Exception {
		FileSource root = localRoot();
		locks(opts(Sharing.HOST).withProvider("lease")).domain("d", root);
		LockSetupException e = assertThrows(LockSetupException.class,
				() -> locks(opts(Sharing.HOST).withProvider("region")).domain("d", root));
		assertTrue(e.getMessage().contains("kept by lease") && e.getMessage().contains("provider-lease"), e.getMessage());
		assertNotNull(locks(opts(Sharing.HOST).withProvider("lease")).domain("d", root), "the same way is fine");
	}

	@Test
	public void anUnknownProviderIsRefused() {
		assertThrows(LockSetupException.class, () -> locks(opts(Sharing.HOST).withProvider("no.such.Provider")).domain("d", localRoot()));
	}

	// ------------------------------------------------------------------ other providers

	@Test
	public void aProviderByClassName() throws Exception {
		LockDomain d = locks(opts(Sharing.CLUSTER).withProvider(TestProviders.InMemory.class.getName())).domain("d", MemoryRoots.newRoot());
		assertEquals("in-memory-test", d.provider().id());
		try (NamedLock l = d.lock("x", Mode.EXCLUSIVE, LONG)) {
			assertTrue(TestProviders.InMemory.held("x"), "the provider was asked");
		}
		assertTrue(!TestProviders.InMemory.held("x"), "and told when it was let go");
	}

	@Test
	public void aProviderByIdFromServiceLoader() throws Exception {
		LockDomain d = locks(opts(Sharing.CLUSTER).withProvider("in-memory-test")).domain("d", MemoryRoots.newRoot());
		assertEquals("in-memory-test", d.provider().id());
	}

	@Test
	public void autoPrefersAFoundProviderWithAPriority() throws Exception {
		System.setProperty(TestProviders.InMemory.PRIORITY_PROPERTY, "true");
		try {
			assertEquals("in-memory-test", locks(opts(Sharing.CLUSTER)).domain("d", MemoryRoots.newRoot()).provider().id());
		} finally {
			System.clearProperty(TestProviders.InMemory.PRIORITY_PROPERTY);
		}
	}

	// ------------------------------------------------------------------ several stores

	@Test
	public void domainsAreSeparateAndRegisteredOnce() throws Exception {
		Locks l = locks(opts(Sharing.OFF));
		FileSource r1 = MemoryRoots.newRoot();
		LockDomain a = l.domain("a", r1);
		LockDomain b = l.domain("b", MemoryRoots.newRoot());
		assertSame(a, l.domain("a", r1), "registered once");
		assertThrows(IllegalArgumentException.class, () -> l.domain("a", MemoryRoots.newRoot()), "one root per name");
		try (NamedLock x = a.lock("x", Mode.EXCLUSIVE, LONG); NamedLock y = b.tryLock("x", Mode.EXCLUSIVE)) {
			assertNotNull(y, "the same name in another domain is another lock");
		}
	}

	@Test
	public void lockAllAcrossDomainsTakesThemInOneOrder() throws Exception {
		Locks l = locks(opts(Sharing.OFF));
		LockDomain archive = l.domain("archive", MemoryRoots.newRoot());
		LockDomain mail = l.domain("mail", MemoryRoots.newRoot());
		try (LockGroup g = l.lockAll(Arrays.asList(mail.name("tony/INBOX"), archive.name("tony/2025"), mail.name("ann/INBOX")),
				Mode.EXCLUSIVE, LONG)) {
			assertEquals("archive:tony/2025", g.locks().get(0).domain().name() + ":" + g.locks().get(0).name());
			assertEquals("mail:ann/INBOX", g.locks().get(1).domain().name() + ":" + g.locks().get(1).name());
			assertEquals("mail:tony/INBOX", g.locks().get(2).domain().name() + ":" + g.locks().get(2).name());
		}
	}

	@Test
	public void aCoordinationStoreKeepsEveryDomainsLocks() throws Exception {
		FileSource coordination = localRoot();
		LockOptions o = opts(Sharing.HOST).withCoordinationStore(coordination);
		FileSource mailRoot = MemoryRoots.newRoot();
		LockDomain mail = locks(o.withOwnerId("one")).domain("mail", mailRoot);
		assertEquals(RegionLockProvider.ID, mail.provider().id(), "chosen for the coordination store (local, HOST), not the memory store");
		assertTrue(coordination.getChild(Locks.DIRECTORY).isDirectory());
		assertTrue(!mailRoot.getChild(Locks.DIRECTORY).exists(), "nothing in the data store");
		Locks other = locks(o.withOwnerId("two"));
		LockDomain mail2 = other.domain("mail", MemoryRoots.newRoot()); // another server's view of the same domain
		LockDomain queue2 = other.domain("queue", MemoryRoots.newRoot());
		try (NamedLock l = mail.lock("x", Mode.EXCLUSIVE, LONG)) {
			// two Locks in one JVM on region locks: the JVM holds the region, so the other finds it busy
			assertNull(mail2.tryLock("x", Mode.EXCLUSIVE), "the same domain's name, kept in the coordination store");
			try (NamedLock q = queue2.tryLock("x", Mode.EXCLUSIVE)) {
				assertNotNull(q, "another domain's name of the same spelling is another lock");
			}
		}
	}
}
