package us.bringardner.parley.net.lock.spi;

import java.io.IOException;

import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.Sharing;

/**
 * A way of keeping locks between servers. Parley has two: {@code region} (liberal: the store's
 * own locks, fast, but only where they reach every server) and {@code lease} (conservative: lease
 * directories, which need only an atomic {@code mkdir}). Others are found with
 * {@link java.util.ServiceLoader} ({@code META-INF/services/us.bringardner.parley.net.lock.spi.LockProvider})
 * or named by class.
 * <p>
 * A provider says whether it suits a store ({@link #fit}); the framework uses the one configured
 * for the domain, or, with {@code auto}, the best that fits.
 * @since 1.1.0
 */
public interface LockProvider {

	/** How well a provider suits a store. */
	enum Fit {
		/** Its locks reach every server the sharing asks for. */
		SAFE,
		/** It can run, but its locks wouldn't reach every server: refused unless allowed. */
		UNSAFE,
		/** It can't work on this store at all. */
		UNSUPPORTED
	}

	/** @return its id, as configured ({@code region}, {@code lease}, ...) */
	String id();

	/**
	 * @param capabilities what the store can guarantee
	 * @param sharing how many servers use it
	 * @return how well it suits
	 */
	Fit fit(FileSourceCapabilities capabilities, Sharing sharing);

	/**
	 * @param capabilities what the store can guarantee
	 * @param sharing how many servers use it
	 * @return why it doesn't fit, in words, or null if it is SAFE
	 */
	default String whyNot(FileSourceCapabilities capabilities, Sharing sharing) {
		return fit(capabilities, sharing) == Fit.SAFE ? null : id() + " doesn't suit a store with " + capabilities;
	}

	/**
	 * For {@code auto}: a provider found with ServiceLoader that is SAFE is chosen over Parley's own
	 * if its priority is above zero; the highest wins.
	 * @return its priority (Parley's own: 0)
	 */
	default int priority() {
		return 0;
	}

	/**
	 * Open the service for one domain.
	 * @param context the domain, its store and options
	 * @return the service
	 * @throws IOException if the store can't be prepared
	 */
	LockService open(LockContext context) throws IOException;
}
