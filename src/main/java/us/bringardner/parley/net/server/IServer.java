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

import java.io.IOException;
import java.net.Socket;
import java.util.Map;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;

import us.bringardner.parley.net.IConnectionFactory;
import us.bringardner.parley.net.IManagedThread;
import us.bringardner.parley.net.IProcessor;
import us.bringardner.parley.net.IProcessorFactory;

/**
 * 
 * @author Tony Bringardner
 *
 */


public interface IServer extends IManagedThread {
	public static final String AUTHENTICATION_PROVIDER_PROPERTY = "authenticationProvider";
	/** @deprecated misspelled, use {@link #AUTHENTICATION_PROVIDER_PROPERTY} (same value) */
	@Deprecated
	public static final String AUTHENTICATOION_PROVIDER_PROPERTY = AUTHENTICATION_PROVIDER_PROPERTY;
	
	/**
	 * The prefix of this server's properties (for example parley.mail.pop3): its own settings, such as
	 * port, and those of its access control list, such as userFile, are read as prefix.name.
	 */
	public String getPropertyPrefix();

	public int getPort();
	public void setPort(int p);

	public IProcessorFactory getProcessorFactory();
	public void setProcessorFactory(IProcessorFactory processorFactory);
	
	public void setConnectionFactory(IConnectionFactory connectionFactory) ;
	public IConnectionFactory getConnectionFactory();
	
	public IProcessor getProcessor() throws InstantiationException, IllegalAccessException;
	
	public void setServerSocketFactory(ServerSocketFactory factory);
	public ServerSocketFactory getServerSocketFactory() throws IOException;
			
	public void setAcceptTimeout(int milliSeconds);
	public int getAcceptTimeout();
		
	public Object getRuntimeValue(String name) ;
	public void setRuntimeValue(String name, Object value) ;
	public Object removeRuntimeValue(String name);
	public Map<String,Object> getRuntimeValues();
	public void removeClient(IProcessor processor);
	public Map<Socket, IProcessor> getActiveClients();
	public boolean isSecure();
	public void setSecure(boolean b);
	
	/**
	 * @param channelSecure
	 * @return
	 */
	public SocketFactory getSocketFactory(boolean channelSecure);
	/**
	 * @param channelSecure
	 * @return
	 */
	public ServerSocketFactory getServerSocketFactory(boolean channelSecure);
	/**
	 * The TLS context for upgrading a connection (STARTTLS, AUTH TLS...). The name is the
	 * mechanism the client asked for; it does not select a different context, so all
	 * connections share one TLS session cache.
	 * @param sslOrTsl the mechanism the client asked for (TLS, SSL, ...) or null
	 * @return the server's TLS context
	 * @throws IOException if the mechanism is not supported or the context can't be created
	 */
	public SSLContext getSSLContext(String sslOrTsl) throws IOException;
	
	/**
	 * @param debug
	 */
	public void setDebug(boolean debug);
	
	public boolean isDebug();
	
	
	
	/**
	 * Authenticate a user with the given credentials (probably a password).
	 * If the user can not be authenticated, null is returned.
	 * 
	 * If the ACL is undefined, all actions are allowed.
	 * 
	 * @param user
	 * @param credentials (password)
	 * @return The an authenticated AbstractPrincipal or null
	 */
	public IPrincipal authenticate(String user, byte[] credentials ) ;
		
	
	/**
	 * The principal of a user whose identity a SASL mechanism has already proven without 
	 * {@link #authenticate(String, byte[])} (SCRAM checks a proof against the credentials 
	 * from {@link IAccessControlList#getScramCredentials(String, String)}). Call it only 
	 * after such a mechanism succeeded for this user.
	 * <p>
	 * The default looks the user up in {@link #getAccessControl()}.
	 * 
	 * @param user the user the mechanism proved
	 * @return a read only authenticated principal, or null if there is no access control or 
	 * no such user
	 * @throws AccessControlUnavailableException if the access control list can't answer now
	 * @since 1.1.0
	 */
	/**
	 * Check a login like {@link #authenticate(String, byte[])}, but tell a failed login (null)
	 * from an access control list that can't answer now (the exception), so the server can answer
	 * "try again later" instead of "wrong password".
	 * <p>
	 * The default looks the user up in {@link #getAccessControl()} with
	 * {@link IAccessControlList#findPrincipal(String)}.
	 *
	 * @return a read only authenticated principal, or null if the login failed or there is no 
	 * access control
	 * @throws AccessControlUnavailableException if the access control list can't answer now
	 * @since 1.1.0
	 */
	default IPrincipal checkLogin(String user, byte[] credentials) throws AccessControlUnavailableException {
		IAccessControlList acl = getAccessControl();
		if( acl == null || user == null ) {
			return null;
		}
		IPrincipal tmp = acl.findPrincipal(user);
		if( tmp == null ) {
			// same work as a real check so timing doesn't reveal valid user names
			acl.authenticateUnknownUser(credentials);
			return null;
		}
		if( !tmp.authenticate(credentials) ) {
			return null;
		}
		IPrincipal ret = new ImmutablePrincipal(tmp);
		ret.setState(IPrincipal.State.Authenticated);
		return ret;
	}

	default IPrincipal getVerifiedPrincipal(String user) throws AccessControlUnavailableException {
		IAccessControlList acl = getAccessControl();
		if( acl == null || user == null ) {
			return null;
		}
		IPrincipal p = acl.findPrincipal(user);
		if( p == null ) {
			return null;
		}
		IPrincipal ret = new ImmutablePrincipal(p);
		ret.setState(IPrincipal.State.Authenticated);
		return ret;
	}

	/**
	 * @param user
	 * @param action
	 * @return true if the given user is authorized for the given action 
	 */
	boolean isAuthorized(IPrincipal user, IPermission action);
	
	/**
	 * 
	 * @return
	 */
	IAccessControlList getAccessControl();
	
	/**
	 * 
	 * @param acl
	 */
	void setAccessControl(IAccessControlList acl);
	

	/**
	 * Start a thread that belongs to a session so the server manages it (thread kind, name,
	 * stopped with its session and with the server). See Server.startTask.
	 * The default just starts it, for servers that don't manage tasks.
	 */
	default void startTask(IProcessor owner, us.bringardner.parley.core.BaseThread task) {
		task.start();
	}

	/**
	 * Run a task once after a delay on the server's scheduler. See Server.schedule.
	 */
	default java.util.concurrent.ScheduledFuture<?> schedule(Runnable task, long delay, java.util.concurrent.TimeUnit unit) {
		throw new UnsupportedOperationException("This server has no scheduler");
	}

	/**
	 * Run a task periodically on the server's scheduler. See Server.scheduleAtFixedRate.
	 */
	default java.util.concurrent.ScheduledFuture<?> scheduleAtFixedRate(Runnable task, long initialDelay, long period, java.util.concurrent.TimeUnit unit) {
		throw new UnsupportedOperationException("This server has no scheduler");
	}
}
