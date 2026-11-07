/**
 * <PRE>
 * 
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
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
 *
 *
 */
package us.bringardner.parley.net.server;
/**
 * CommandProcessor reads commands from the input and
 * delegates the processing to a Command.
 * We assume that the input has the form of "command arg1 arg2 ... argn".
 *    
 */
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.TreeMap;

import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.net.IConnection;
import us.bringardner.parley.net.IGenericResponseCode;



public abstract  class AbstractCommandProcessor extends AbstractProcessor implements ICommandProcessor {
	
	
	private static final long serialVersionUID = 1L;
	private IRequestContextFactory requestContextFactory = new DefaultRequestContextFactory();	
	private ICommandFactory commandFactory ;
	private boolean debug;
	/** The commands this session used, kept only in debug mode */
	private final Map<String,String> cmdUsed = new TreeMap<String, String>();
	

	public IRequestContextFactory getRequestContextFactory() {
		return requestContextFactory;
	}

	public void setRequestContextFactory(IRequestContextFactory requestContextFactory) {
		this.requestContextFactory = requestContextFactory;
	}

	public AbstractCommandProcessor () {
		super();
	}

	public AbstractCommandProcessor (ICommandFactory factory) {
		this();
		setCommandFactory(factory);
	}

	public ICommandFactory getCommandFactory() {
		return commandFactory;
	}


	public void setCommandFactory(ICommandFactory commandFactory) {
		this.commandFactory = commandFactory;
	}


	/**
	 * The session: the greeting, then one request after another until the client leaves, the
	 * session ends or the server stops, then the protocol's clean-up and the connection closed.
	 * This is the only command loop; a protocol changes what differs by overriding
	 * {@link #sendGreeting()}, {@link #readRequest()}, {@link #runRequest(IRequestContext)},
	 * {@link #afterRequest()}, {@link #isSessionEnding()} and {@link #sessionEnded()}, and the
	 * replies (replyCommandFailed, replyTooManyLoginFailures, ...).
	 * <p>
	 * What every protocol gets the same way: a request that fails with a RuntimeException is logged
	 * and answered ({@link #replyCommandFailed(IRequestContext)}), and the session goes on; after
	 * too many failed logins the session ends after the protocol's goodbye; a failed TLS handshake
	 * is one INFO line, a connection the client dropped is a debug line, any other I/O error is
	 * logged as an error.
	 */
	public void run() {
		running = true;
		try {
			if( startSession() ) {
				loop();
			}
		} finally {
			if( !stopping ) {
				stop();
			}
			running = false;
			// a write that failed half way may have left the output lock held: a goodbye must not wait for it
			java.util.concurrent.locks.ReentrantLock lock = getOutputLock();
			while( lock.isHeldByCurrentThread() ) {
				lock.unlock();
			}
			closeSession();
		}
	}

	/** The greeting; false if the session can't go on. */
	private boolean startSession() {
		try {
			sendGreeting();
			return true;
		} catch(IOException e) {
			connectionFailed(e, "sending the greeting");
		} catch(RuntimeException e) {
			logError("Error starting the session", e);
		} catch(Error e) {
			logError("Fatal error starting the session", e);
		}
		return false;
	}

	private void loop() {
		while( running && !stopping && !isSessionEnding() ) {
			IRequestContext request;
			try {
				request = readRequest();
			} catch(IOException e) {
				connectionFailed(e, "reading a request");
				return;
			} catch(RuntimeException e) {
				logError("Error reading a request", e);
				return;
			}
			if( request == null ) {
				// the client closed the connection, or the protocol ended the session while reading
				return;
			}
			try {
				try {
					runRequest(request);
				} catch(RuntimeException e) {
					// a failed command should not end the session
					logError("Error processing command "+commandName(request), e);
					replyCommandFailed(request);
				}
				boolean tooMany = !isSessionEnding() && isTooManyLoginFailures();
				if( tooMany ) {
					// the protocol has answered the last failed login; say goodbye and close
					logInfo("Too many failed logins, closing the connection from "+clientAddressText());
					replyTooManyLoginFailures();
				}
				afterRequest();
				if( tooMany ) {
					return;
				}
			} catch(IOException e) {
				connectionFailed(e, "processing a request");
				return;
			} catch(RuntimeException e) {
				logError("Error after command "+commandName(request), e);
				return;
			} catch(Error e) {
				logError("Fatal error in processor", e);
				return;
			}
		}
	}

	/**
	 * The connection can't be used any more. A failed TLS handshake is the client's doing (one INFO
	 * line); so is a connection it dropped ({@link #isConnectionLost(IOException)}, a debug line);
	 * anything else is an error, unless the session was already closing.
	 */
	private void connectionFailed(IOException e, String doing) {
		if( isTlsHandshakeFailure(e) ) {
			logTlsHandshakeFailure(e);
		} else if( isConnectionLost(e) ) {
			logDebug("Connection lost "+doing+": "+e);
		} else if( !isClosed(getConnection()) && !stopping ) {
			logError("I/O error "+doing, e);
		}
	}

	/**
	 * Let the protocol release what the session holds, close the connection, and take the session
	 * off the server's list. The clean-up comes before the close, so a client that reconnects as
	 * soon as it sees the close finds what the session held (a connection count, a maildrop) free.
	 */
	private void closeSession() {
		try {
			sessionEnded();
		} catch(Throwable e) {
			logError("Error ending the session", e);
		}
		IConnection con = getConnection();
		if( con != null ) {
			try {
				con.close();
			} catch (IOException e) {
				logDebug("Error closing the connection: "+e);
			}
		}
		try {
			getServer().removeClient(this);
		} catch(RuntimeException e) {
			logError("Error removing the session from the server", e);
		}
		if( isDebug()) {
			logInfo(""+cmdUsed.size()+" Server commands used "+cmdUsed.keySet());
		}
	}

	/**
	 * Send the greeting. The default sends the greeting the server asked for
	 * ({@link #setPendingGreeting(String)}), if any; a protocol overrides it for its own, and for
	 * what it checks or sets up first (SMTP's checks of the client). To refuse the client, send the
	 * refusal and make {@link #isSessionEnding()} true.
	 *
	 * @throws IOException if the connection can't be used (the session ends)
	 * @since 2.0.0
	 */
	protected void sendGreeting() throws IOException {
		String greeting = takePendingGreeting();
		if( greeting != null ) {
			reply(greeting);
		}
	}

	/**
	 * Read the next request. The default reads one line and makes it a request with the
	 * {@link #getRequestContextFactory() request context factory}; while the client sends nothing it
	 * keeps waiting, and once the session is {@link #isIdleTooLong() idle for too long} it says
	 * goodbye ({@link #replyClosing(CloseReason) replyClosing(IDLE)}) and ends. A line longer than the
	 * connection's limit is answered with {@link #replyLineTooLong(int)} and ends the session.
	 * <p>
	 * A protocol overrides it for its own framing (SMTP's byte lines, IMAP's literals). It may answer
	 * a request it can't parse itself and read on. It checks {@link #isIdleTooLong()} while it waits,
	 * and ends an idle session with replyClosing(IDLE), as the default does.
	 *
	 * @return the request, or null to end the session (the client closed the connection)
	 * @throws IOException if the connection can't be used (the session ends)
	 * @since 2.0.0
	 */
	protected IRequestContext readRequest() throws IOException {
		IConnection con = getConnection();
		// wake every IDLE_POLL_MS to check for an idle session and a stopping server;
		// the line reader keeps a part of a line read before a time-out
		int timeout = con.getTimeout();
		con.setTimeout(IDLE_POLL_MS);
		try {
			return readLine(con);
		} finally {
			con.setTimeout(timeout);
		}
	}

	private IRequestContext readLine(IConnection con) throws IOException {
		while( running && !stopping ) {
			String line;
			try {
				line = con.readLine();
			} catch(SocketTimeoutException e) {
				if( stopping ) {
					// the server says goodbye (replyClosing) when it stops
					return null;
				}
				if( isIdleTooLong() ) {
					logDebug("Idle for too long, closing the connection from "+clientAddressText());
					replyClosing(CloseReason.IDLE);
					return null;
				}
				continue;
			} catch(us.bringardner.parley.io.LineTooLongException e) {
				// the rest of the line can't be trusted: the session ends, after telling the client
				try {
					replyLineTooLong(e.getMaxLineLength());
				} catch(IOException ignore) {
					// the client is gone
				}
				logDebug("Line longer than "+e.getMaxLineLength()+" bytes, closing");
				return null;
			}
			if( line == null ) {
				logDebug("End of input: the client closed the connection");
				return null;
			}
			return getRequestContextFactory().getRequestContext(line);
		}
		return null;
	}

	/**
	 * Run one request. The default finds the command with the {@link #getCommandFactory() command
	 * factory} and runs it if the session's state ({@link #getStateMachine()}) and permissions allow
	 * it; otherwise it gives the protocol's reply (replyInvalidState, replyNotAuthorized,
	 * replyPermissionUnavailable).
	 *
	 * @throws IOException if the connection can no longer be used; this ends the session.
	 * A RuntimeException is logged and answered with {@link #replyCommandFailed(IRequestContext)},
	 * and the session goes on.
	 * @since 2.0.0
	 */
	protected void runRequest(IRequestContext context) throws IOException {
		// Only log the command name, the rest of the line may contain credentials (e.g. PASS)
		if( isDebugEnabled()) {
			// from the line, not getFirstToken(): that moves the request's token position
			logDebug("Received command="+firstWord(context.getCommandLine()));
		}
		ICommand command = getCommandFactory().getCommand(context);
		if( command == null ) {
			reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, "Not a valid command ("+context.getCommandLine()+").");
		} else {
			recordCommandUsed(command.getName());
			StateMachine<?> states = getStateMachine();
			if( states != null 
					&& command instanceof IStatefulCommand 
					&& !states.isValid((IStatefulCommand<?>) command)) {
				replyInvalidState(command, states);
			} else if( !command.requiresAuthorization() ) {
				command.execute(this,context);
			} else {
				AuthorizationResult allowed = checkPermission(command.getPermission(), null);
				if( allowed.getStatus() == AuthorizationResult.Status.ALLOWED ) {
					command.execute(this,context);
				} else if( allowed.getStatus() == AuthorizationResult.Status.UNAVAILABLE ) {
					logError(command.getName()+" not checked: "+allowed.getReason());
					replyPermissionUnavailable(command);
				} else {
					replyNotAuthorized(command, reportMissingPermission(command.getName(), command.getPermission()));
				}
			}
		}
	}

	/**
	 * Called after each request, after the session's goodbye when it had too many failed logins.
	 * The default does nothing (every reply is sent at once); a protocol that buffers its replies
	 * sends them here (SMTP when the client has sent nothing more, for pipelining; IMAP always).
	 *
	 * @throws IOException if the connection can't be used (the session ends)
	 * @since 2.0.0
	 */
	protected void afterRequest() throws IOException {
	}

	/**
	 * @return true when the session is to end before the next request, without the server
	 * stopping: the protocol has said goodbye (SMTP's 421, IMAP's LOGOUT) or refused the client.
	 * The default is false; a protocol that ends a session with {@link #stop()} needs nothing more.
	 * @since 2.0.0
	 */
	protected boolean isSessionEnding() {
		return false;
	}

	/**
	 * Called once when the session has ended, however it ended (the client left, an error, the
	 * server stopping), before the connection is closed, so a client that reconnects at once finds
	 * what the session held free: release it here (a connection count, a mail transaction, a
	 * selected mailbox, a maildrop, a data connection). The default does nothing. An exception here
	 * is logged; the connection is still closed.
	 * @since 2.0.0
	 */
	protected void sessionEnded() {
	}

	/**
	 * @return true if the I/O error means the client dropped the connection (a reset, a broken
	 * pipe): nothing wrong on the server, so it is a debug line, not an error. The default:
	 * a {@link java.net.SocketException} or a {@link ConnectionLostException}.
	 * @since 2.0.0
	 */
	protected boolean isConnectionLost(IOException e) {
		return e instanceof java.net.SocketException || e instanceof ConnectionLostException;
	}

	/**
	 * In debug mode, note that the session used this command; the list is logged when the session
	 * ends. The default {@link #runRequest(IRequestContext)} calls it; a protocol's own calls it too.
	 * @since 2.0.0
	 */
	protected void recordCommandUsed(String name) {
		if( isDebug() && name != null ) {
			cmdUsed.put(name, name);
		}
	}

	/**
	 * How often (ms) a session waiting for a request wakes to check whether it is idle for too long
	 * and whether the server is stopping.
	 * @since 2.0.0
	 */
	public static final int IDLE_POLL_MS = 1000;

	/**
	 * @return true once the client has been quiet for longer than the server's idle limit
	 * ({@link Server#getMaxIdleConnection()}, measured from {@link #getLastActivityTime()}), unless
	 * the session has a task running (an FTP transfer): such a session isn't idle. A session checks
	 * this itself while it waits for a request; the server's admin check leaves it alone.
	 * @since 2.0.0
	 */
	public boolean isIdleTooLong() {
		IServer server = getServer();
		if( !(server instanceof Server) ) {
			return false;
		}
		Server s = (Server) server;
		long limit = s.getMaxIdleConnection();
		if( limit <= 0 || System.currentTimeMillis() - getLastActivityTime() <= limit ) {
			return false;
		}
		return !s.hasRunningTask(this);
	}

	/**
	 * @return when (ms since the epoch) the client was last heard from, for {@link #isIdleTooLong()}.
	 * The default: the connection's last read or write, whichever is later. A protocol that reads
	 * the socket through its own streams returns their time instead (SMTP, IMAP).
	 * @since 2.0.0
	 */
	protected long getLastActivityTime() {
		IConnection con = getConnection();
		return con == null ? System.currentTimeMillis() : Math.max(con.getLastReadTime(), con.getLastWriteTime());
	}

	/** The first word of a line (the command), or null. */
	private static String firstWord(String line) {
		if( line == null ) {
			return null;
		}
		String tmp = line.trim();
		int idx = tmp.indexOf(' ');
		return idx > 0 ? tmp.substring(0, idx) : tmp;
	}

	/**
	 * The request's command name, for the log after it has run; never its arguments (they may hold a
	 * password). getFirstToken() moves the request's token position, so not before it runs.
	 */
	private static String commandName(IRequestContext request) {
		try {
			return request.getFirstToken();
		} catch(RuntimeException e) {
			return null;
		}
	}

	/**
	 * A session lacks a permission a command needs. This isn't a failed login and isn't counted
	 * as one: the command is refused, and the administrators are told (a warning in the log) who,
	 * which permission, which command and from which address, so they can find the problem.
	 * <p>
	 * The dispatcher calls it for every command it refuses; a protocol that checks a permission
	 * itself (its own command loop, or at a point such as SMTP's MAIL FROM) calls it too, so every
	 * refusal reads and is logged the same way.
	 *
	 * @param command the command refused (or "login", when telling a user at login)
	 * @param permission the permission it needs
	 * @return the text for the reply, e.g. "tony doesn't have the read permission", or "nobody is
	 * logged in"
	 * @since 2.0.0
	 */
	public String reportMissingPermission(String command, ParleyPermission permission) {
		ParleyPrincipal principal = getPrincipal();
		String text;
		if( principal == null ) {
			text = "nobody is logged in";
		} else {
			text = principal.getName()+" doesn't have the "+permission.getName()+" permission";
		}
		java.net.InetAddress from = getRequester().getClientAddress();
		logWarn(command+" refused: "+text+"; client "+(from == null ? "unknown" : from.getHostAddress()));
		return text;
	}

	/**
	 * A command failed with an unexpected error (a RuntimeException, already logged); the session
	 * goes on. The default is a generic 500, as before; a protocol overrides it for its own reply
	 * (FTP 451, POP3 -ERR [SYS/TEMP], SMTP 451 4.3.0, IMAP's tagged NO [SERVERBUG]): 500 means a
	 * syntax error to most protocols.
	 *
	 * @param request the request that failed; its first token is the command's name as the client
	 * sent it (null for an empty line)
	 * @since 2.0.0
	 */
	protected void replyCommandFailed(IRequestContext request) throws IOException {
		reply(REPLY_500_GENERIC_ERROR, "An error occured processing the request.");
	}

	/**
	 * Answer a command the session isn't allowed to run. The default is a generic 500
	 * "COMMAND refused: reason"; a protocol overrides it for its own reply (code and form only).
	 *
	 * @param command the command refused
	 * @param reason what's missing, from {@link #reportMissingPermission(String, ParleyPermission)}
	 */
	protected void replyNotAuthorized(ICommand command, String reason) throws IOException {
		reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, command.getName()+" refused: "+reason);
	}

	/**
	 * Answer a command whose permission couldn't be checked because the user registry can't
	 * answer now (UNAVAILABLE). It must not say "not authorized" (rule 6): the default is a
	 * generic temporary error (400), so the client may try again later; a protocol overrides
	 * it for its own reply (SMTP 451, IMAP NO [UNAVAILABLE], POP3 -ERR [SYS/TEMP]).
	 */
	protected void replyPermissionUnavailable(ICommand command) throws IOException {
		reply(IGenericResponseCode.REPLY_400_GENERIC_TEMPORARY_ERROR,
				command.getName()+" can't be checked now, try again later");
	}

	/**
	 * A request line was longer than the connection's limit
	 * ({@link us.bringardner.parley.net.Connection#setMaxLineLength(int)}); the session ends after
	 * this. The default sends a generic 500; a protocol overrides it for its own reply (SMTP 500
	 * "Line too long", IMAP BAD...).
	 * @param maxLineLength the limit that was exceeded
	 */
	protected void replyLineTooLong(int maxLineLength) throws IOException {
		reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, "Line too long (max "+maxLineLength+" bytes)");
	}

	/**
	 * The state of this session, or null (the default) if the protocol has no states. When
	 * it isn't null, a command that is an {@link IStatefulCommand} runs only in the states
	 * it declares.
	 */
	protected StateMachine<?> getStateMachine() {
		return null;
	}

	/**
	 * Answer a command that isn't valid in the current state. The default is a generic 500;
	 * a protocol overrides it for its own code (SMTP 503, POP3 -ERR, IMAP BAD).
	 */
	protected void replyInvalidState(ICommand command, StateMachine<?> states) throws IOException {
		reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, 
				command.getName()+" is not valid in the "+states.get()+" state");
	}

	private static boolean isClosed(IConnection con) {
		java.net.Socket sock = con.getSocket();
		return sock == null || sock.isClosed();
	}

	public void reply(int responseCode, String text) throws IOException {
		reply(translateResponseCode(responseCode)+" "+text);
		
	}

	/** One reply line, flushed, under the session's output lock ({@link #getOutputLock()}). */
	public void reply(String text) throws IOException {
		IConnection con = getConnection();
		java.util.concurrent.locks.ReentrantLock lock = getOutputLock();
		lock.lock();
		try {
			con.writeLine(text);
			con.flush();
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Send several reply lines with one flush, e.g. a multi-line reply ("211-...", ...,
	 * "211 End"): they go out together instead of one TCP segment / TLS record per line
	 * The caller formats the lines.
	 * @param lines the reply lines
	 */
	public void reply(java.util.List<String> lines) throws IOException {
		java.util.concurrent.locks.ReentrantLock lock = getOutputLock();
		lock.lock();
		try {
			getConnection().writeLines(lines);
		} finally {
			lock.unlock();
		}
	}

	public void setDebug(boolean b) {
		this.debug = b;
	}
	
	public boolean isDebug() {
		return debug;
	}
	
	


	/**
	 * Called once, when the connection is about to be closed because the client has had as many
	 * failed logins as the application allows, after the protocol's answer to the last one. The
	 * default sends nothing; a protocol overrides it for a closing line of its own (SMTP 421 ...).
	 */
	protected void replyTooManyLoginFailures() throws IOException {
	}

	/** True if the connection uses TLS (implicit, or after STARTTLS). */
	public boolean isTls() {
		IConnection con = getConnection();
		return con != null && con.isSecure();
	}

	/**
	 * True if this is, or was caused by, a failed TLS handshake (implicit TLS, or after STARTTLS).
	 * That is the client's doing: it hung up (a port check, a scanner), or offered nothing this
	 * server accepts (an old protocol, no cipher in common). Servers log it as one line
	 * ({@link #logTlsHandshakeFailure}), not as an error with a stack trace.
	 *
	 * @since 2.0.0
	 */
	public static boolean isTlsHandshakeFailure(Throwable e) {
		return handshakeFailure(e) != null;
	}

	private static javax.net.ssl.SSLHandshakeException handshakeFailure(Throwable e) {
		for (int depth = 0; e != null && depth < 20; depth++, e = e.getCause()) {
			if (e instanceof javax.net.ssl.SSLHandshakeException) {
				return (javax.net.ssl.SSLHandshakeException) e;
			}
		}
		return null;
	}

	/**
	 * Logs a failed TLS handshake ({@link #isTlsHandshakeFailure}) as one INFO line: the client's
	 * address and why.
	 *
	 * @since 2.0.0
	 */
	protected void logTlsHandshakeFailure(Throwable e) {
		javax.net.ssl.SSLHandshakeException h = handshakeFailure(e);
		String why = h == null ? String.valueOf(e) : h.getMessage();
		logInfo("TLS handshake with " + clientAddressText() + " failed: " + why);
	}

	private String clientAddressText() {
		try {
			IConnection con = getConnection();
			java.net.Socket s = con == null ? null : con.getSocket();
			java.net.InetAddress a = s == null ? null : s.getInetAddress();
			return a == null ? "the client" : a.getHostAddress();
		} catch (RuntimeException e) {
			return "the client";
		}
	}
}
