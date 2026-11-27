package us.bringardner.parley.net;

import java.util.LinkedHashMap;
import java.util.Map;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.logging.LogLevel;
import us.bringardner.parley.logging.ParleyLoggerFinder;

/**
 * Changes the level of an object's logger in a test. The tests log through ParleyLogger (parley-logging),
 * whose levels come only from configuration, so this sets the system property
 * {@code parley.log.level.<name>} for the object's logger name. The logger is shared by every object of the
 * class, and {@link TestLoggingReset} (found by JUnit's extension autodetection) puts each property back
 * after the test.
 */
public final class TestLogging {

	private TestLogging() {
	}

	/** The properties a test changed, with their value before (null for not set). */
	private static final Map<String, String> changed = new LinkedHashMap<>();

	/**
	 * @param obj the object whose logger's level is changed
	 * @param level the level it lets through (NONE for nothing)
	 */
	public static synchronized void setLevel(BaseObject obj, LogLevel level) {
		String key = ParleyLoggerFinder.levelProperty(obj.getLogger().getName());
		if( !changed.containsKey(key) ) {
			changed.put(key, System.getProperty(key));
		}
		System.setProperty(key, level.name());
	}

	/** Puts every property a test changed back. */
	static synchronized void reset() {
		changed.forEach((key, value) -> {
			if( value == null ) {
				System.clearProperty(key);
			} else {
				System.setProperty(key, value);
			}
		});
		changed.clear();
	}
}
