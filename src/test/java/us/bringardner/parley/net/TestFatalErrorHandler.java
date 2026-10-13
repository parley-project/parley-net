package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * FatalErrorHandler: every thread death is counted and logged; only a
 * VirtualMachineError stops the process, and only when halting is on.
 */
public class TestFatalErrorHandler {

	private final AtomicInteger halted = new AtomicInteger(-1);

	@AfterEach
	public void restore() {
		FatalErrorHandler.setHalter(null);
		FatalErrorHandler.setHaltOnFatal(false);
	}

	private void die(Throwable e, boolean halt) throws InterruptedException {
		FatalErrorHandler.setHalter(halted::set);
		FatalErrorHandler.setHaltOnFatal(halt);
		Thread t = new Thread(() -> {
			if( e instanceof Error ) {
				throw (Error)e;
			}
			throw (RuntimeException)e;
		}, "TestDyingThread");
		t.setUncaughtExceptionHandler(FatalErrorHandler.getInstance());
		t.start();
		t.join(5000);
	}

	@Test
	public void anOrdinaryErrorIsCountedNotFatal() throws Exception {
		long before = FatalErrorHandler.getThreadDeaths();
		die(new IllegalStateException("bug"), true);
		assertEquals(before+1, FatalErrorHandler.getThreadDeaths());
		assertEquals(-1, halted.get(), "a RuntimeException doesn't stop the process");
	}

	@Test
	public void aJvmErrorHaltsWhenAskedTo() throws Exception {
		die(new OutOfMemoryError("simulated"), true);
		assertEquals(1, halted.get());
	}

	@Test
	public void aJvmErrorIsOnlyLoggedWhenHaltingIsOff() throws Exception {
		long before = FatalErrorHandler.getThreadDeaths();
		die(new OutOfMemoryError("simulated"), false);
		assertEquals(-1, halted.get());
		assertEquals(before+1, FatalErrorHandler.getThreadDeaths());
	}

	@Test
	public void installSetsTheDefaultHandler() {
		Thread.UncaughtExceptionHandler saved = Thread.getDefaultUncaughtExceptionHandler();
		try {
			FatalErrorHandler.install(false);
			assertSame(FatalErrorHandler.getInstance(), Thread.getDefaultUncaughtExceptionHandler());
		} finally {
			Thread.setDefaultUncaughtExceptionHandler(saved);
		}
	}
}
