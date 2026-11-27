package us.bringardner.parley.net;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.logging.LogLevel;
import us.bringardner.parley.logging.ParleyLogger;

/**
 * Gives an object its own ParleyLogger (parley-logging) with the level a test needs. The tests log through
 * ParleyLogger; BaseObject has no level of its own, the logging framework owns it. The object's logger is
 * private to it, so nothing is left behind for the next test (the shared logger of its class keeps the level
 * the build's configuration gives it).
 */
public final class TestLogging {

	private TestLogging() {
	}

	/**
	 * @param obj the object whose log lines are changed
	 * @param level the level its logger lets through
	 */
	public static void setLevel(BaseObject obj, LogLevel level) {
		obj.setLogger(new ParleyLogger(obj.getLogger().getName(), level));
	}
}
