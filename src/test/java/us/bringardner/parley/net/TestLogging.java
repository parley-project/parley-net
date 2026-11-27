package us.bringardner.parley.net;

import java.lang.System.Logger.Level;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.logging.testing.TestLogLevels;

/**
 * Changes the level of an object's logger in a test. The tests log through ParleyLogger (parley-logging),
 * whose levels come only from configuration, so this sets the level setting for the object's logger name
 * ({@link TestLogLevels}). The logger is shared by every object of the class; the setting goes back after the
 * test (TestLogLevels is registered as a JUnit extension in META-INF/services).
 */
public final class TestLogging {

	private TestLogging() {
	}

	/**
	 * @param obj the object whose logger's level is changed
	 * @param level the level it lets through (OFF for nothing)
	 */
	public static void setLevel(BaseObject obj, Level level) {
		TestLogLevels.set(obj.getLogger().getName(), level);
	}
}
