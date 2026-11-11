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

import java.net.InetAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import us.bringardner.parley.core.BaseThread;
import us.bringardner.parley.core.util.AbstractCoreServer;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.net.IConnection;
import us.bringardner.parley.net.IProcessor;


public abstract class AbstractProcessor extends BaseThread implements IProcessor {

	private IConnection connection;
	private IServer server;
	private Map<String, Object> sessionValues = new HashMap<String, Object>();
	/** Who is asking; made on first use, guarded by requesterLock */
	private Requester requester;
	private final Object requesterLock = new Object();
	private volatile String pendingGreeting;
	/** This connection's failed logins; made on first use, guarded by requesterLock */
	private LoginFailures loginFailures;
	
	public AbstractProcessor() {
	}

	/** The session's output lock ({@link #getOutputLock()}) */
	private final java.util.concurrent.locks.ReentrantLock outputLock = new java.util.concurrent.locks.ReentrantLock();

	@Override
	public final java.util.concurrent.locks.ReentrantLock getOutputLock() {
		return outputLock;
	}

	
	public IServer getServer() {
		return server;
	}

	
	
	/** Made on first use from the connection; says the connection is secure once TLS has started. */
	@Override
	public final Requester getRequester() {
		synchronized (requesterLock) {
			IConnection con = getConnection();
			boolean secure = con != null && con.isSecure();
			if( requester == null ) {
				Socket socket = con == null ? null : con.getSocket();
				InetAddress client = socket == null ? null : socket.getInetAddress();
				int localPort = socket == null ? 0 : socket.getLocalPort();
				IServer svr = getServer();
				String serverName = svr == null || svr.getPropertyPrefix() == null ? "" : svr.getPropertyPrefix();
				requester = Requester.connected(client, localPort, secure, Requester.Transport.TCP, serverName);
			} else if( requester.isSecure() != secure ) {
				requester = requester.withSecure(secure);
			}
			return requester;
		}
	}

	/** Doesn't make a requester just to say nobody is logged in. */
	@Override
	public final ParleyPrincipal getPrincipal() {
		synchronized (requesterLock) {
			return requester == null ? null : requester.getPrincipal();
		}
	}

	@Override
	public final AuthenticationResult authenticate(Credential credential) {
		IServer svr = getServer();
		if( svr == null ) {
			throw new IllegalStateException("No server: a session logs in through its server");
		}
		AuthenticationResult result = svr.authenticate(credential);
		if( result.getStatus() == AuthenticationResult.Status.AUTHENTICATED ) {
			synchronized (requesterLock) {
				requester = getRequester().loggedIn(result);
			}
		}
		LoginFailures failures = getLoginFailures();
		if( failures != null && failures.record(result) ) {
			// a refused login: wait before the protocol answers, to slow down password guessing
			waitMillis(failures.getDelayMillis());
		}
		return result;
	}

	@Override
	public final AuthenticationResult refuseLogin(String reason) {
		AuthenticationResult result = AuthenticationResult.refused(reason);
		LoginFailures failures = getLoginFailures();
		if( failures != null && failures.record(result) ) {
			// counted like a wrong password, and answered as late
			waitMillis(failures.getDelayMillis());
		}
		return result;
	}

	/**
	 * @return this connection's failed logins, or null when the server has no login limits
	 * (it isn't an {@link AbstractCoreServer})
	 */
	protected LoginFailures getLoginFailures() {
		synchronized (requesterLock) {
			if( loginFailures == null && getServer() instanceof AbstractCoreServer ) {
				loginFailures = new LoginFailures((AbstractCoreServer) getServer());
			}
			return loginFailures;
		}
	}

	/** @return true once this connection has had as many failed logins as the application allows */
	@Override
	public boolean isTooManyLoginFailures() {
		LoginFailures failures = getLoginFailures();
		return failures != null && failures.isTooMany();
	}

	private static void waitMillis(int millis) {
		if( millis <= 0 ) {
			return;
		}
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public final void logout() {
		synchronized (requesterLock) {
			if( requester != null ) {
				requester = requester.loggedOut();
			}
		}
	}

	public void setServer(IServer server) {
		setSecure(server.isSecure());
		this.server = server;
		// a processor reads its server's settings (its configuration, when it has one)
		if (server instanceof us.bringardner.parley.core.BaseObject) {
			useConfigurationOf((us.bringardner.parley.core.BaseObject) server);
		}
	}

	/** A new connection has a new requester, with nobody logged in. */
	public void setConnection(IConnection connection) {
		this.connection = connection;
		synchronized (requesterLock) {
			requester = null;
			loginFailures = null;
		}
	}

	public IConnection getConnection() {
		return connection;
	}

	public Map<String, Object> getSessionValues() {
		return sessionValues;
	}

	public void setSessionValues(Map<String, Object> sessionValues) {
		this.sessionValues = sessionValues;
	}
	
	public void setSessionValue(String name, Object value) {
		sessionValues.put(name, value);
	}
	
	public Object getSessionValue(String name) {
		Object ret = sessionValues.get(name);
		
		return ret;
	}
	
	public Object removeSessionValue(String name) {
		return sessionValues.remove(name);
	}
	

	public void setServerRuntimeValue(String name, Object value) {
		getServer().setRuntimeValue(name, value);
	}
	
	public Object getServerRuntimeValue(String name) {
		return getServer().getRuntimeValue(name);
	}

	public Object removeServerRuntimeValue(String name) {
		return getServer().removeRuntimeValue(name);
	}
	
	public Map<String, Object> getServerRuntimeValues() {
		return getServer().getRuntimeValues();
	}
	
	/**
	 * Set by the server so the greeting is written from this processor's thread
	 * rather than the server's accept thread. 
	 */
	public void setPendingGreeting(String greeting) {
		this.pendingGreeting = greeting;
	}

	/**
	 * @return the greeting the server asked this processor to send (once), or null.
	 */
	protected String takePendingGreeting() {
		String ret = pendingGreeting;
		pendingGreeting = null;
		return ret;
	}

	public String getThreadName() {
		return getName();
	}

}
