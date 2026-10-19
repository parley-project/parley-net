package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/** On a local directory, with another server in another JVM. */
public abstract class AbstractLocalLocksTests extends AbstractLocksTests {

	private final List<Worker> workers = new ArrayList<>();

	@Override
	protected FileSource newRoot() throws Exception {
		File d = Files.createTempDirectory("parley-net-locks").toFile();
		d.deleteOnExit();
		return FileSourceFactory.getDefaultFactory().createFileSource(d.getCanonicalPath());
	}

	@AfterEach
	public void stopWorkers() {
		for (Worker w : workers) {
			w.process.destroyForcibly();
		}
	}

	/** The time a dead holder's lock takes to be free (zero for region locks). */
	protected abstract long deadHolderFreedWithinMs();

	protected Worker worker(LockOptions o) throws Exception {
		Worker w = new Worker(root, o);
		workers.add(w);
		return w;
	}

	@Test
	public void anotherServerIsKeptOutAndLetIn() throws Exception {
		Worker w = worker(options());
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertEquals("BUSY", w.ask("lock box X"));
			assertEquals("BUSY", w.ask("lock box S"));
			assertEquals("GOT", w.ask("lock other X"), "another name");
		}
		assertEquals("GOT", w.ask("lock box X"), "free once released");
		assertNull(space.tryLock("box", Mode.EXCLUSIVE), "now it keeps us out");
		assertEquals("OK", w.ask("release box"));
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertTrue(l.isValid());
		}
	}

	@Test
	public void readersInTwoJvmsShare() throws Exception {
		Worker w = worker(options());
		try (NamedLock r = space.lock("box", Mode.SHARED, LONG)) {
			assertEquals("GOT", w.ask("lock box S"), "another server reads too");
		}
		assertNull(space.tryLock("box", Mode.EXCLUSIVE), "the other server still reads");
		assertEquals("OK", w.ask("release box"));
		try (NamedLock x = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			assertTrue(x.isValid());
		}
	}

	@Test
	public void aServerThatDiesLetsGo() throws Exception {
		Worker w = worker(options());
		assertEquals("GOT", w.ask("lock box X"));
		assertNull(space.tryLock("box", Mode.EXCLUSIVE));
		w.process.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
		long start = System.nanoTime();
		try (NamedLock l = space.lock("box", Mode.EXCLUSIVE, LONG)) {
			long ms = (System.nanoTime() - start) / 1_000_000;
			assertTrue(ms <= deadHolderFreedWithinMs() + 2000, "freed in " + ms + " ms");
		}
	}

	@Test
	public void theStoreClaimReachesAnotherServer() throws Exception {
		Worker w = worker(withSharing(Sharing.OFF).withOwnerId("worker"));
		assertEquals("CLAIMED", w.ask("claim w"));
		LockDomain alone = open(withSharing(Sharing.OFF).withOwnerId("me"));
		assertThrows(StoreClaimException.class, () -> alone.claimStore("me"));
		LockDomain shared = open(withSharing(Sharing.HOST).withOwnerId("me2"));
		assertThrows(StoreClaimException.class, () -> shared.claimStore("me2"));
	}

	@Test
	public void sharingServersInTwoJvmsAdmitEachOther() throws Exception {
		Worker w = worker(withSharing(Sharing.HOST).withOwnerId("worker"));
		LockDomain shared = open(withSharing(Sharing.HOST).withOwnerId("me"));
		try (StoreClaim c = shared.claimStore("me")) {
			assertEquals("CLAIMED", w.ask("claim w"));
		}
	}

	/** Another JVM running {@link LocksWorker}. */
	protected static final class Worker {
		final Process process;
		private final PrintWriter in;
		private final BlockingQueue<String> replies = new LinkedBlockingQueue<>();

		Worker(FileSource root, LockOptions o) throws Exception {
			String java = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
			ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
					LocksWorker.class.getName(), root.getAbsolutePath(), o.sharing().name(), o.provider(),
					String.valueOf(o.lease().toMillis()), String.valueOf(o.renew().toMillis()));
			pb.redirectError(ProcessBuilder.Redirect.INHERIT);
			process = pb.start();
			in = new PrintWriter(process.getOutputStream(), true, StandardCharsets.UTF_8);
			Thread reader = new Thread(() -> {
				try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
					String line;
					while ((line = r.readLine()) != null) {
						if( line.startsWith(LocksWorker.PREFIX) ) {
							replies.add(line.substring(LocksWorker.PREFIX.length()));
						}
					}
				} catch (IOException e) {
					// gone
				}
			}, "locks-worker-reader");
			reader.setDaemon(true);
			reader.start();
			String hello = replies.poll(60, TimeUnit.SECONDS);
			if( !"READY".equals(hello) ) {
				throw new IOException("The worker didn't start: " + hello);
			}
		}

		String ask(String command) throws Exception {
			in.println(command);
			String r = replies.poll(120, TimeUnit.SECONDS);
			assertNotNull(r, "no reply to " + command);
			return r;
		}
	}
}
