package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.FileBasedAcl.FileBasedPrincipal;

/**
 * <PRE>
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 */
public class TestPasswordHash {

	@Test
	public void testHashRoundTrip() {
		String hash = FileBasedAcl.hashPassword("s3cret".toCharArray());
		assertTrue(hash.startsWith(FileBasedAcl.HASH_PREFIX));
		assertTrue(FileBasedAcl.verifyPassword("s3cret".toCharArray(), hash));
		assertFalse(FileBasedAcl.verifyPassword("wrong".toCharArray(), hash));
		// salted, so the same password hashes differently
		assertNotEquals(hash, FileBasedAcl.hashPassword("s3cret".toCharArray()));
	}

	@Test
	public void testPrincipalHashedAndPlain() {
		FileBasedPrincipal p = new FileBasedPrincipal("user");

		p.setCredentials(FileBasedAcl.hashPassword("pw".toCharArray()).getBytes(StandardCharsets.UTF_8));
		assertTrue(p.authenticate("pw".getBytes(StandardCharsets.UTF_8)));
		assertFalse(p.authenticate("px".getBytes(StandardCharsets.UTF_8)));

		p.setCredentials("plain".getBytes(StandardCharsets.UTF_8));
		assertTrue(p.authenticate("plain".getBytes(StandardCharsets.UTF_8)));
		assertFalse(p.authenticate("plaiN".getBytes(StandardCharsets.UTF_8)));
		assertFalse(p.authenticate(null));
	}

	/** Only a limited number of password hashes run at once. */
	@Test
	public void concurrentHashesAreLimited() throws Exception {
		String hash = FileBasedAcl.hashPassword("pw".toCharArray());
		int oldMax = FileBasedAcl.getMaxConcurrentHashes();
		long oldWait = FileBasedAcl.getHashWaitMs();
		FileBasedAcl.setMaxConcurrentHashes(2);
		FileBasedAcl.setHashWaitMs(60000);
		ExecutorService pool = Executors.newFixedThreadPool(6);
		AtomicBoolean done = new AtomicBoolean();
		AtomicInteger peak = new AtomicInteger();
		Thread watcher = new Thread(() -> {
			while (!done.get()) {
				peak.accumulateAndGet(FileBasedAcl.getHashesInProgress(), Math::max);
				Thread.onSpinWait();
			}
		});
		try {
			watcher.start();
			List<Future<Boolean>> results = new ArrayList<>();
			for (int i = 0; i < 6; i++) {
				results.add(pool.submit(() -> FileBasedAcl.verifyPassword("pw".toCharArray(), hash)));
			}
			for (Future<Boolean> f : results) {
				assertTrue(f.get(60, TimeUnit.SECONDS), "every login waits its turn and succeeds");
			}
		} finally {
			done.set(true);
			watcher.join();
			pool.shutdownNow();
			FileBasedAcl.setMaxConcurrentHashes(oldMax);
			FileBasedAcl.setHashWaitMs(oldWait);
		}
		assertTrue(peak.get() >= 1 && peak.get() <= 2, "hashes running at once: " + peak.get());
	}

	/** A check that can't get its turn in time fails instead of piling up threads. */
	@Test
	public void checkThatWaitsTooLongFails() throws Exception {
		String hash = FileBasedAcl.hashPassword("pw".toCharArray());
		int oldMax = FileBasedAcl.getMaxConcurrentHashes();
		long oldWait = FileBasedAcl.getHashWaitMs();
		FileBasedAcl.setMaxConcurrentHashes(1);
		FileBasedAcl.setHashWaitMs(1);
		ExecutorService pool = Executors.newFixedThreadPool(4);
		try {
			List<Future<Boolean>> results = new ArrayList<>();
			for (int i = 0; i < 4; i++) {
				results.add(pool.submit(() -> FileBasedAcl.verifyPassword("pw".toCharArray(), hash)));
			}
			int ok = 0;
			for (Future<Boolean> f : results) {
				if (f.get(60, TimeUnit.SECONDS)) {
					ok++;
				}
			}
			assertTrue(ok >= 1 && ok < 4, "logins that got a turn: " + ok);
		} finally {
			pool.shutdownNow();
			FileBasedAcl.setMaxConcurrentHashes(oldMax);
			FileBasedAcl.setHashWaitMs(oldWait);
		}
		// with a turn free, the same check succeeds
		assertTrue(FileBasedAcl.verifyPassword("pw".toCharArray(), hash));
	}

	@Test
	public void limitsAreValidated() {
		assertTrue(FileBasedAcl.getMaxConcurrentHashes() >= 1);
		assertEquals(FileBasedAcl.DEFAULT_HASH_WAIT_MS, FileBasedAcl.getHashWaitMs());
		assertThrows(IllegalArgumentException.class, () -> FileBasedAcl.setMaxConcurrentHashes(0));
		assertThrows(IllegalArgumentException.class, () -> FileBasedAcl.setHashWaitMs(-1));
	}
}
