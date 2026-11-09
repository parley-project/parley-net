package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.jupiter.api.Test;

/** A session's output: what it collects goes out whole, and a goodbye comes after it. */
public class SessionOutputStreamTest {

	private static byte[] bytes(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	@Test
	public void aGoodbyeWaitsForTheFlushAndComesAfterIt() throws Exception {
		final ByteArrayOutputStream wire = new ByteArrayOutputStream();
		final ReentrantLock lock = new ReentrantLock();
		try (OutputStream session = new SessionOutputStream(new BufferedOutputStream(wire), lock)) {
			// the session starts a reply of two lines and hasn't flushed yet
			session.write(bytes("250-first\r\n"));
			assertTrue(lock.isHeldByCurrentThread(), "held from the first write");

			final CountDownLatch started = new CountDownLatch(1);
			final CountDownLatch done = new CountDownLatch(1);
			Thread goodbye = new Thread(new Runnable() {
				@Override
				public void run() {
					started.countDown();
					lock.lock();
					try {
						// as Server.closeSession does: the lock first, then the protocol's goodbye
						session.write(bytes("421 bye\r\n"));
						session.flush();
					} catch (IOException e) {
						throw new RuntimeException(e);
					} finally {
						lock.unlock();
					}
					done.countDown();
				}
			});
			goodbye.start();
			assertTrue(started.await(5, TimeUnit.SECONDS));
			assertFalse(done.await(200, TimeUnit.MILLISECONDS), "the goodbye waits for the reply");

			session.write(bytes("250 last\r\n"));
			session.flush();
			assertFalse(lock.isHeldByCurrentThread(), "let go at the flush");
			assertTrue(done.await(5, TimeUnit.SECONDS));
			goodbye.join(5000);
		}

		assertEquals("250-first\r\n250 last\r\n421 bye\r\n", wire.toString(StandardCharsets.UTF_8.name()));
		assertFalse(lock.isLocked(), "the goodbye let go too");
	}

	@Test
	public void aThreadThatHoldsTheLockKeepsItAfterAFlush() throws Exception {
		ByteArrayOutputStream wire = new ByteArrayOutputStream();
		ReentrantLock lock = new ReentrantLock();
		try (OutputStream session = new SessionOutputStream(wire, lock)) {
			lock.lock();
			try {
				session.write(bytes("one\r\n"));
				session.flush();
				assertTrue(lock.isHeldByCurrentThread(), "taken by the caller, so not let go by the stream");
				assertEquals(1, lock.getHoldCount());
			} finally {
				lock.unlock();
			}
		}
		assertFalse(lock.isLocked());
	}

	@Test
	public void aFailedFlushStillLetsGo() throws Exception {
		ReentrantLock lock = new ReentrantLock();
		OutputStream broken = new OutputStream() {
			@Override
			public void write(int b) {
			}

			@Override
			public void flush() throws IOException {
				throw new IOException("the client went away");
			}
		};
		try (OutputStream session = new SessionOutputStream(broken, lock)) {
			session.write(bytes("x"));
			try {
				session.flush();
			} catch (IOException expected) {
				// as the client went away
			}
		}
		assertFalse(lock.isLocked(), "a goodbye isn't left waiting");
	}
}
