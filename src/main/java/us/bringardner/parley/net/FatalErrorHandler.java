/**
 * <PRE>
 *
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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
 */
package us.bringardner.parley.net;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntConsumer;

import us.bringardner.parley.core.BaseObject;

/**
 * Handles errors that escape a thread (the thread is about to die).
 * <p>
 * Every such error is logged, so a dead accept, reactor or session thread is
 * visible instead of silently reducing what the server can do. A JVM error
 * ({@link VirtualMachineError}, e.g. OutOfMemoryError) leaves the process in an
 * unknown state, so when halting is on the process is stopped at once with exit
 * code 1 and a supervisor (systemd, launchd, a container runtime...) starts a
 * clean one. Runtime.halt() is used rather than System.exit(), which runs shutdown
 * hooks and can hang when memory is exhausted.
 * <p>
 * A server's main() installs it as the default handler:
 * <pre>
 * FatalErrorHandler.install(true);
 * </pre>
 * Applications that embed a server and manage the process themselves can install it
 * with halting off (errors are still logged), or not at all. Running the JVM with
 * -XX:+ExitOnOutOfMemoryError gives the same protection for OutOfMemoryError.
 * <p>
 * From parley-dns, where it replaced catching OutOfMemoryError in request threads,
 * trimming caches, retrying and finally calling System.exit(1) from a request thread.
 */
public final class FatalErrorHandler extends BaseObject implements Thread.UncaughtExceptionHandler {

	private static final FatalErrorHandler INSTANCE = new FatalErrorHandler();
	private static volatile boolean haltOnFatal = false;
	private static volatile IntConsumer halter = code -> Runtime.getRuntime().halt(code);
	private static final AtomicLong deaths = new AtomicLong();

	private FatalErrorHandler() {
	}

	/**
	 * Make this the default handler for threads without their own.
	 * @param haltOnFatalError stop the process on a VirtualMachineError
	 */
	public static void install(boolean haltOnFatalError) {
		haltOnFatal = haltOnFatalError;
		Thread.setDefaultUncaughtExceptionHandler(INSTANCE);
	}

	/** @return the handler, to set on threads (or BaseThreads) that should use it explicitly */
	public static FatalErrorHandler getInstance() {
		return INSTANCE;
	}

	/** @return threads that died from an uncaught error since the JVM started */
	public static long getThreadDeaths() {
		return deaths.get();
	}

	/** @return true if a VirtualMachineError stops the process */
	public static boolean isHaltOnFatal() {
		return haltOnFatal;
	}

	/** @param halt stop the process on a VirtualMachineError */
	public static void setHaltOnFatal(boolean halt) {
		haltOnFatal = halt;
	}

	/**
	 * Replace what stops the process (for tests).
	 * @param h called with the exit code; null restores Runtime.halt
	 */
	public static void setHalter(IntConsumer h) {
		halter = h != null ? h : code -> Runtime.getRuntime().halt(code);
	}

	@Override
	public void uncaughtException(Thread t, Throwable e) {
		deaths.incrementAndGet();
		boolean fatal = e instanceof VirtualMachineError;
		String msg = "Thread "+t.getName()+" died: "+e
				+(fatal && haltOnFatal ? " - halting the process so it can be restarted" : "");
		//  stderr first: logging may itself fail when memory is exhausted
		System.err.println(msg);
		try {
			logError(msg, e);
		} catch(Throwable ignore) {
		}
		if( fatal && haltOnFatal ) {
			halter.accept(1);
		}
	}
}
