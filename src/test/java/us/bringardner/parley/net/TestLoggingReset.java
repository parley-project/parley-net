package us.bringardner.parley.net;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/** After every test: the log levels it changed through {@link TestLogging} go back (registered in META-INF/services). */
public class TestLoggingReset implements AfterEachCallback {

	@Override
	public void afterEach(ExtensionContext context) {
		TestLogging.reset();
	}
}
