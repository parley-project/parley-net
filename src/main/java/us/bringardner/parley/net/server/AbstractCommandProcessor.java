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


	public void run() {
		IConnection con = getConnection();
		running = true;
		Map<String,String> cmdUsed = new TreeMap<String, String>();

		// Greeting is sent here (not on the server accept thread) so a slow client 
		// or TLS handshake only blocks this processor.
		String greeting = takePendingGreeting();
		if( greeting != null ) {
			try {
				reply(greeting);
			} catch (IOException e) {
				logDebug("Can't send greeting, closing connection", e);
				stop();
			}
		}

		while(running &&  !stopping ) {
			String line = null;
			try {
				line = con.readLine();
			} catch(SocketTimeoutException e) {
				//  Idle, keep waiting. Server.doAdmin closes connections that are idle too long.
				continue;
			} catch(us.bringardner.parley.io.LineTooLongException e) {
				//  The rest of the line can't be trusted: the session ends, after telling the client
				try {
					replyLineTooLong(e.getMaxLineLength());
				} catch(IOException ignore) {
					// the client is gone
				}
				logDebug("Line longer than "+e.getMaxLineLength()+" bytes, closing");
				break;
			} catch(IOException e) {
				if( isTlsHandshakeFailure(e) ) {
					logTlsHandshakeFailure(e);
				} else if( e instanceof java.net.SocketException ) {
					//  the client went away (reset the connection): nothing wrong here
					logDebug("Connection lost reading a request: "+e);
				} else if( !isClosed(con) && !stopping ) {
					logError("Error reading request",e);
				}
				break;
			}

			if( line == null ) {
				logDebug("read null??? EOF reached? Connection must be closed by client or network stack error.");
				break;
			}

			try {
				processLine(line, cmdUsed);
				if( isTooManyLoginFailures() ) {
					// the protocol has answered the last failed login; say goodbye and close
					logInfo("Too many failed logins, closing "+con.getSocket());
					replyTooManyLoginFailures();
					break;
				}
			} catch(IOException e) {
				//  Can't talk to the client any more
				if( isTlsHandshakeFailure(e) ) {
					logTlsHandshakeFailure(e);
				} else if( !isClosed(con) && !stopping ) {
					logError("I/O error processing request",e);
				}
				break;
			} catch(RuntimeException e) {
				//  A failed command should not end the session
				logError("Error processing command "+firstToken(line),e);
				try {
					reply(REPLY_500_GENERIC_ERROR, "An error occured processing the request.");
				} catch(IOException ex) {
					break;
				}
			} catch(Error e) {
				logError("Fatal error in processor",e);
				break;
			}
		}

		if( !stopping ) {
			stop();
		}
		running = false;
		getServer().removeClient(this);
		try {
			con.close();
		} catch (IOException e) {
			logError("error on close", e);
		}

		if( isDebug()) {
			logInfo(""+cmdUsed.size()+" Server commands used "+cmdUsed.keySet());
		}
	}

	/**
	 * Parse and execute a single request line.
	 * 
	 * @throws IOException if the connection can no longer be used, this ends the session. 
	 * Any RuntimeException is reported to the client as a 500 and the session continues.
	 */
	protected void processLine(String line, Map<String,String> cmdUsed) throws IOException {
		// Only log the command name, the rest of the line may contain credentials (e.g. PASS)
		if( isDebugEnabled()) {
			logDebug("Received command="+firstToken(line));
		}
		IRequestContext context = getRequestContextFactory().getRequestContext(line);

		ICommand command = getCommandFactory().getCommand(context);
		if( command == null ) {
			reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, "Not a valid command ("+line+").");
		} else {
			if( isDebug()) {
				cmdUsed.put(command.getName(), command.getName());
			}
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

	private static String firstToken(String line) {
		if( line == null ) {
			return null;
		}
		String tmp = line.trim();
		int idx = tmp.indexOf(' ');
		return idx > 0 ? tmp.substring(0, idx) : tmp;
	}

	private static boolean isClosed(IConnection con) {
		java.net.Socket sock = con.getSocket();
		return sock == null || sock.isClosed();
	}

	public void reply(int responseCode, String text) throws IOException {
		reply(translateResponseCode(responseCode)+" "+text);
		
	}

	public void reply(String text) throws IOException {
		IConnection con = getConnection();
		con.writeLine(text);
		con.flush();
		
	}

	/**
	 * Send several reply lines with one flush, e.g. a multi-line reply ("211-...", ...,
	 * "211 End"): they go out together instead of one TCP segment / TLS record per line
	 * The caller formats the lines.
	 * @param lines the reply lines
	 */
	public void reply(java.util.List<String> lines) throws IOException {
		getConnection().writeLines(lines);
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
