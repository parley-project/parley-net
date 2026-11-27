package us.bringardner.parley.net;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.bringardner.parley.logging.ParleyLoggerFinder;

/**
 * Collects what is logged while a test runs. The tests log through ParleyLogger (parley-logging), which
 * writes its lines to System.out, so this takes System.out for a while and reads the lines
 * ({@code time [thread] LEVEL name - message}) back as "LEVEL message". It also lets INFO through
 * (the surefire default is ERROR). Close it (try-with-resources) to put System.out and the level back.
 */
public class LogCapture implements AutoCloseable {

	private static final Pattern LINE = Pattern.compile("^\\S+ \\[.*?\\] (\\w+) \\S+ - (.*)$");

	private final PrintStream previousOut = System.out;
	private final String previousLevel = System.getProperty(ParleyLoggerFinder.PROPERTY_LOG_LEVEL);
	private final StringBuilder pending = new StringBuilder();
	private final List<String> messages = new ArrayList<>();
	private final PrintStream capture;

	public LogCapture() {
		capture = new PrintStream(new ByteArrayOutputStream() {
			@Override
			public synchronized void write(byte[] b, int off, int len) {
				add(new String(b, off, len, StandardCharsets.UTF_8));
			}

			@Override
			public synchronized void write(int b) {
				add(String.valueOf((char) b));
			}
		}, true, StandardCharsets.UTF_8);
		System.setProperty(ParleyLoggerFinder.PROPERTY_LOG_LEVEL, "INFO");
		System.setOut(capture);
	}

	private synchronized void add(String text) {
		pending.append(text);
		int end;
		while( (end = pending.indexOf("\n")) >= 0 ) {
			String line = pending.substring(0, end).replace("\r", "");
			pending.delete(0, end+1);
			Matcher m = LINE.matcher(line);
			if( m.matches() ) {
				messages.add(m.group(1)+" "+m.group(2));
			}
		}
	}

	/** Puts System.out and the log level back. */
	@Override
	public void close() {
		System.setOut(previousOut);
		if( previousLevel == null ) {
			System.clearProperty(ParleyLoggerFinder.PROPERTY_LOG_LEVEL);
		} else {
			System.setProperty(ParleyLoggerFinder.PROPERTY_LOG_LEVEL, previousLevel);
		}
		capture.close();
	}

	/** @return every message so far that contains the text, as "LEVEL message", in the order logged */
	public synchronized List<String> containing(String text) {
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
