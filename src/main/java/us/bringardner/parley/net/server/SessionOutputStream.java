/**
 * <PRE>
 *
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
 *
 *
 *	@author Tony Bringardner
 *
 *
 */
package us.bringardner.parley.net.server;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The output of a session that collects its replies and sends them with one flush (SMTP's
 * pipelined replies, an IMAP response with its literals). It takes the session's output lock
 * ({@link us.bringardner.parley.net.IProcessor#getOutputLock()}) at the first write and lets it
 * go when it is flushed, so a goodbye or any other thread of the session writes before or after
 * what was collected, never inside it.
 * <p>
 * A thread that already holds the lock (the server's goodbye takes it first) writes and flushes
 * without taking it again, and keeps it after the flush. Wrap it around the protocol's buffer, so
 * the first write to the buffer is the first write here.
 *
 * @since 2.0.0
 */
public class SessionOutputStream extends FilterOutputStream {

	private final ReentrantLock lock;

	/** True while this stream holds the lock it took at a first write; only its holder reads or changes it */
	private boolean holding;

	/**
	 * @param out where the bytes go, usually the protocol's buffer
	 * @param lock the session's output lock
	 */
	public SessionOutputStream(OutputStream out, ReentrantLock lock) {
		super(Objects.requireNonNull(out, "out"));
		this.lock = Objects.requireNonNull(lock, "lock");
	}

	/** Take the lock unless this thread already holds it. */
	private void hold() {
		if( !lock.isHeldByCurrentThread() ) {
			lock.lock();
			holding = true;
		}
	}

	/** Let the lock go if this stream took it. */
	private void release() {
		if( holding && lock.isHeldByCurrentThread() ) {
			holding = false;
			lock.unlock();
		}
	}

	@Override
	public void write(int b) throws IOException {
		hold();
		out.write(b);
	}

	/** Written as one block (FilterOutputStream would write it a byte at a time). */
	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		hold();
		out.write(b, off, len);
	}

	/** Send what was collected, then let the lock go, even when the flush fails. */
	@Override
	public void flush() throws IOException {
		try {
			out.flush();
		} finally {
			release();
		}
	}

	@Override
	public void close() throws IOException {
		try {
			out.close();
		} finally {
			release();
		}
	}
}
