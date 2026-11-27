package us.bringardner.parley.net;

/**
 * parley-logging's LogCapture, with the one thing this module adds: reading the session ID BaseObject puts in
 * front of a message.
 */
public class LogCapture extends us.bringardner.parley.logging.testing.LogCapture {

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
