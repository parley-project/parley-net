package us.bringardner.parley.net;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Collects what is logged while a test runs. Without a System.LoggerFinder (the tests have none)
 * Parley's messages go to java.util.logging, so this is a Handler on its root logger. Close it
 * (try-with-resources) to take the handler off again.
 */
public class LogCapture extends Handler implements AutoCloseable {

	private final Logger root = Logger.getLogger("");
	private final List<String> messages = new CopyOnWriteArrayList<>();

	public LogCapture() {
		root.addHandler(this);
	}

	@Override
	public void publish(LogRecord record) {
		if( record != null && record.getMessage() != null ) {
			messages.add(record.getLevel()+" "+record.getMessage());
		}
	}

	@Override
	public void flush() {
	}

	/** Takes the handler off the root logger. */
	@Override
	public void close() {
		root.removeHandler(this);
	}

	/** @return every message so far that contains the text, as "LEVEL message", in the order logged */
	public List<String> containing(String text) {
		List<String> ret = new ArrayList<>();
		for(String m : messages) {
			if( m.contains(text) ) {
				ret.add(m);
			}
		}
		return ret;
	}

	/** @return the first message so far that contains the text, or null */
	public String first(String text) {
		List<String> found = containing(text);
		return found.isEmpty() ? null : found.get(0);
	}

	/**
	 * @param message a recorded message that starts with a session ID, "INFO [Name-12] ..."
	 * @return the ID (Name-12), or null when there is none
	 */
	public static String sessionId(String message) {
		if( message == null ) {
			return null;
		}
		int start = message.indexOf('[');
		int end = message.indexOf(']', start+1);
		return start < 0 || end < 0 ? null : message.substring(start+1, end);
	}
}
