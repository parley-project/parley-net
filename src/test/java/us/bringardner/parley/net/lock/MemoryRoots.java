package us.bringardner.parley.net.lock;

import java.util.concurrent.atomic.AtomicInteger;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/** Store roots in memory, each in a file system of its own. */
final class MemoryRoots {
	private static final AtomicInteger N = new AtomicInteger();

	private MemoryRoots() {
	}

	static FileSource newRoot() throws Exception {
		MemoryFileSourceFactory f = new MemoryFileSourceFactory();
		f.connect();
		FileSource r = f.createFileSource("/store" + N.incrementAndGet());
		r.mkdirs();
		return r;
	}
}
