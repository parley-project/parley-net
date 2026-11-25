/**
 * <PRE>
 *
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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
package us.bringardner.parley.net.nio;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import javax.net.ssl.SSLEngine;

import us.bringardner.parley.core.LogContext;
import us.bringardner.parley.core.util.AbstractCoreServer;
import us.bringardner.parley.core.util.SocketOptions;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.io.IoUtils;
import us.bringardner.parley.net.server.IBaseServer;
import us.bringardner.parley.net.server.Server;
import us.bringardner.parley.net.server.SessionLog;

/**
 * A non-blocking server, the NIO counterpart of the framework's Server. Both are an
 * {@link IBaseServer}; the thread-per-connection parts of {@link us.bringardner.parley.net.server.IServer}
 * (processors, connection factories, accept timeout) have no meaning here.
 * <p>
 * The server thread accepts connections on a non-blocking ServerSocketChannel and hands
 * each one to one of a few {@link NioReactor}s (round robin). A reactor thread serves all
 * of its connections, so a few threads serve thousands of connections instead of one
 * thread per connection.
 * <p>
 * Each connection gets a handler from the {@link INioHandlerFactory} and a decoder from
 * the decoder factory. The handler calls run on the reactor thread, or on the
 * handler executor if one is set (use one when handlers block: authentication,
 * file I/O, starting processes...).
 * <p>
 * Like every Parley server it extends parley-core's AbstractCoreServer, so the same properties 
 * configure it (port, bindAddress, backlog, keepAlive, tcpNoDelay, maxConnections, the key 
 * store settings of SecureBaseObject...), and the server attributes are shared by all connections.
 * Its own properties are {@value #PROPERTY_FRAME_TIMEOUT}, {@value IBaseServer#PROPERTY_MAX_IDLE_TIME},
 * {@value IBaseServer#PROPERTY_REUSE_ADDRESS},
 * {@value #PROPERTY_REACTOR_COUNT}, {@value #PROPERTY_INITIAL_INPUT_BUFFER},
 * {@value #PROPERTY_MAX_INPUT_BUFFER}, {@value #PROPERTY_RECEIVE_BUFFER_SIZE} and
 * {@value #PROPERTY_SEND_BUFFER_SIZE}. For each, a value set in code wins, else the property
 * (read the first time it's needed), else the default.
 * <p>
 * TLS uses the server's SSLContext ({@code getSSLContext()}, from the key store settings): a 
 * secure server ({@code setSecure(true)} or the {@code secure} property) speaks TLS from the 
 * first byte, and any connection can switch with {@link INioConnection#startTls()}.
 *
 * <pre>
 * NioServer server = new NioServer(2222);
 * server.setHandlerFactory(() -&gt; new MyHandler());
 * server.setDecoderFactory(LineFrameDecoder::new);
 * server.startAndWait(5000);
 * </pre>
 *
 * @author Tony Bringardner
 */
public class NioServer extends AbstractCoreServer implements IBaseServer {

	/** Close connections idle for 24 hours, as the framework's Server does */
	public static final long DEFAULT_MAX_IDLE_TIME = 1000L*60*60*24;
	public static final int DEFAULT_REACTOR_COUNT = Math.max(1, Math.min(4, Runtime.getRuntime().availableProcessors()));
	/**
	 * How long (ms) the server stops accepting after accept() fails, e.g. with too many open
	 * files: the connections waiting in the backlog would fail the same way, so retrying at
	 * once only spins.
	 */
	public static final long ACCEPT_ERROR_PAUSE = 1000;

	// Settings: set on any thread, read by the server thread. null until set, or read from the property
	private volatile Boolean reuseAddress;
	// null until set or read from the tcpNoDelay property; unlike AbstractCoreServer (false) the default is true
	private volatile Boolean tcpNoDelay;
	/** Property: SO_RCVBUF (bytes) for accepted sockets, 0 = the OS default */
	public static final String PROPERTY_RECEIVE_BUFFER_SIZE = "receiveBufferSize";
	/** Property: SO_SNDBUF (bytes) for accepted sockets, 0 = the OS default */
	public static final String PROPERTY_SEND_BUFFER_SIZE = "sendBufferSize";
	/** Property: the number of reactor (selector) threads */
	public static final String PROPERTY_REACTOR_COUNT = "reactorCount";
	/** Property: the starting size (bytes) of a connection's input buffer */
	public static final String PROPERTY_INITIAL_INPUT_BUFFER = "initialInputBuffer";
	/** Property: the largest size (bytes) of a connection's input buffer; it must hold the largest frame */
	public static final String PROPERTY_MAX_INPUT_BUFFER = "maxInputBuffer";
	//  For each setting below: null until set, or until read from its property the first time it's needed
	private volatile Integer receiveBufferSize;
	private volatile Integer sendBufferSize;
	private volatile String serverBusyMessage;
	private volatile Long maxIdleTime;
	//  setServerChannel: a channel bound by the caller, for the next start
	private volatile ServerSocketChannel boundChannel;
	/** Property: the most time (ms) a frame may take to arrive once it has started, 0 = no limit */
	public static final String PROPERTY_FRAME_TIMEOUT = "frameTimeout";
	private volatile long frameTimeout = -1;
	//  The client address of each connection, to give back its per-client place
	private final Map<Long, InetAddress> clientAddresses = new ConcurrentHashMap<Long, InetAddress>();
	private volatile Integer reactorCount;
	private volatile Integer initialInputBuffer;
	private volatile Integer maxInputBuffer;
	private volatile INioHandlerFactory handlerFactory;
	private volatile Supplier<IFrameDecoder> decoderFactory = RawFrameDecoder::new;
	private volatile Executor handlerExecutor;

	private final Map<Long, NioConnection> connections = new ConcurrentHashMap<Long, NioConnection>();

	private volatile Selector acceptSelector;
	private volatile ServerSocketChannel serverChannel;
	// Accept thread only: the server channel's key, and when accepting resumes after an accept error (0 = not paused)
	private SelectionKey acceptKey;
	private volatile long acceptPausedUntil;
	private volatile NioReactor[] reactors;
	private final AtomicInteger nextReactor = new AtomicInteger();
	private volatile UserRegistry userRegistry;
	// True once the provider setting has been looked at and named no registry
	private volatile boolean noUserRegistry;
	// True when userRegistry was made here from the provider setting: it is closed when the server stops
	private volatile boolean ownsUserRegistry;
	// Why the last start() failed (null if it started or is still starting)
	private volatile Throwable startupError;

	public NioServer() {
	}

	public NioServer(int port) {
		this();
		setPort(port);
	}

	/**
	 * @param name the server's name, which is also the prefix of its properties (name.port,
	 *  name.user0 ...) unless a subclass sets another one
	 */
	public NioServer(int port, String name) {
		this(port);
		setName(name);
		if( name != null && !name.isEmpty() ) {
			setPropertyPrefix(name);
		}
	}

	public NioServer(int port, INioHandlerFactory handlerFactory) {
		this(port);
		setHandlerFactory(handlerFactory);
	}

	// ------------------------------------------------------------------ life cycle

	/**
	 * Clears any previous startup error, see {@link #startAndWait(long)}.
	 */
	@Override
	public synchronized void start() {
		startupError = null;
		super.start();
	}

	/**
	 * Start the server and wait until it is accepting connections.
	 * Unlike start(), a server that can't start (port in use, no handler factory...)
	 * is reported to the caller instead of only being logged.
	 *
	 * @throws IOException with the reason if the server did not start within the timeout
	 */
	public void startAndWait(long timeoutMillis) throws IOException {
		start();
		long end = System.currentTimeMillis() + timeoutMillis;
		while( !isRunning() ) {
			Throwable error = startupError;
			if( error != null ) {
				if( error instanceof IOException ) {
					throw (IOException) error;
				}
				throw new IOException("Server "+getName()+" failed to start: "+error.getMessage(), error);
			}
			if( System.currentTimeMillis() > end ) {
				throw new IOException("Server "+getName()+" did not start within "+timeoutMillis+" ms");
			}
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new InterruptedIOException("Interrupted waiting for server "+getName()+" to start");
			}
		}
	}

	/**
	 * @return why the last start() failed, or null if it started (or is still starting).
	 */
	public Throwable getStartupError() {
		return startupError;
	}

	/**
	 * Stop accepting, close every connection and stop the reactors.
	 * Returns at once, the server thread does the work.
	 */
	@Override
	public void stop() {
		// AbstractCoreServer's stop() also closes its (unused) blocking ServerSocket
		super.stop();
		Selector s = acceptSelector;
		if( s != null ) {
			s.wakeup();
		}
	}

	@Override
	public void run() {
		if( handlerFactory == null ) {
			logError("No handler factory defined.");
			startupError = new IllegalStateException("No handler factory defined.");
			return;
		}

		try {
			open();
		} catch (IOException | RuntimeException e) {
			// e.g. port in use
			logError("Can't open server "+getName()+" on port "+getPort(), e);
			startupError = e;
			cleanup();
			// as when it stops: a registry made from the provider setting before start() isn't left open
			closeOwnUserRegistry();
			return;
		}

		started = running = true;
		logInfo("Server "+getName()+" is running on port "+getLocalPort()+".");
		try {
			while( !stopping ) {
				if( acceptPausedUntil != 0 ) {
					long wait = acceptPausedUntil-System.currentTimeMillis();
					if( wait > 0 ) {
						// nothing is selected while paused: this waits for the pause to end or for stop()
						acceptSelector.select(wait);
						continue;
					}
					acceptPausedUntil = 0;
					acceptKey.interestOps(SelectionKey.OP_ACCEPT);
				}
				acceptSelector.select();
				Iterator<SelectionKey> it = acceptSelector.selectedKeys().iterator();
				while( it.hasNext() ) {
					SelectionKey key = it.next();
					it.remove();
					if( key.isValid() && key.isAcceptable() ) {
						acceptAll();
					}
				}
			}
		} catch (IOException | ClosedSelectorException e) {
			if( !stopping ) {
				logError("Error in server "+getName(), e);
			}
		} catch (RuntimeException | Error e) {
			logError("Error in server "+getName(), e);
		} finally {
			cleanup();
			closeOwnUserRegistry();
			running = false;
			logInfo("Server "+getName()+" has stopped.");
		}
	}

	private void open() throws IOException {
		if( isSecure() ) {
			// A missing key store or wrong password is a startup error, not a failed handshake later
			getSSLContext();
		}
		acceptSelector = Selector.open();
		ServerSocketChannel ch = boundChannel;
		boundChannel = null;
		if( ch != null ) {
			// Bound by the caller (setServerChannel): its address and options are the caller's
			serverChannel = ch;
			ch.configureBlocking(false);
		} else {
			ch = ServerSocketChannel.open();
			serverChannel = ch;
			ch.configureBlocking(false);
			// set before binding so a restart doesn't fail while the old port is in TIME_WAIT
			ch.setOption(StandardSocketOptions.SO_REUSEADDR, isReuseAddress());
			int rcvbuf = getReceiveBufferSize();
			if( rcvbuf > 0 ) {
				// set before binding so it applies to the window of accepted sockets
				ch.setOption(StandardSocketOptions.SO_RCVBUF, rcvbuf);
			}
			ch.bind(new InetSocketAddress(getBindAddr(), getPort()), getBacklog());
		}
		acceptPausedUntil = 0;
		acceptKey = ch.register(acceptSelector, SelectionKey.OP_ACCEPT);

		int count = Math.max(1, getReactorCount());
		NioReactor[] rs = new NioReactor[count];
		reactors = rs;
		String name = getName();
		for (int i = 0; i < count; i++) {
			rs[i] = new NioReactor(name+"-reactor-"+i);
			rs[i].start();
		}
	}

	private void cleanup() {
		ServerSocketChannel ch = serverChannel;
		serverChannel = null;
		IoUtils.closeQuietly(ch);
		Selector s = acceptSelector;
		acceptSelector = null;
		acceptKey = null;
		IoUtils.closeQuietly(s);
		for (NioConnection conn : new ArrayList<NioConnection>(connections.values())) {
			conn.close();
		}
		connections.clear();
		NioReactor[] rs = reactors;
		reactors = null;
		if( rs != null ) {
			for (NioReactor r : rs) {
				if( r != null ) {
					r.stop();
				}
			}
			for (NioReactor r : rs) {
				try {
					if( r != null ) {
						r.join(5000);
					}
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}
	}

	/**
	 * Accept every waiting connection. An accept that fails while the server channel is still
	 * open (too many open files...) pauses accepting for {@link #ACCEPT_ERROR_PAUSE} ms, as the
	 * framework's Server logs it and goes on; only a closed server channel ends the server.
	 *
	 * @throws IOException if the server channel is closed
	 */
	private void acceptAll() throws IOException {
		ServerSocketChannel ch = serverChannel;
		while( ch != null && !stopping ) {
			SocketChannel sc;
			try {
				sc = accept(ch);
			} catch (IOException e) {
				if( e instanceof ClosedChannelException || !ch.isOpen() ) {
					throw e;
				}
				logError("Can't accept a connection in server "+getName()+", not accepting for "+ACCEPT_ERROR_PAUSE+" ms", e);
				acceptPausedUntil = System.currentTimeMillis()+ACCEPT_ERROR_PAUSE;
				acceptKey.interestOps(0);
				return;
			}
			if( sc == null ) {
				return;
			}
			handleNewConnection(sc);
		}
	}

	/** The accept itself, separate so a test can make it fail */
	SocketChannel accept(ServerSocketChannel ch) throws IOException {
		return ch.accept();
	}

	/**
	 * Hand a newly accepted channel to a reactor. Runs on the accept thread so it must 
	 * not block and must never throw. If the hand off fails the channel is closed.
	 */
	protected void handleNewConnection(SocketChannel sc) {
		boolean acquired = false;
		InetAddress acquiredFor = null;
		NioConnection conn = null;
		try {
			sc.configureBlocking(false);
			InetAddress client = sc.getRemoteAddress() instanceof InetSocketAddress
					? ((InetSocketAddress)sc.getRemoteAddress()).getAddress() : null;
			if( !isClientAllowed(client) ) {
				logInfo("Refusing connection from "+client+": not in "+PROPERTY_ALLOWED_CLIENTS);
				IoUtils.closeQuietly(sc);
				return;
			}
			if( !tryAcquireConnection(client) ) {
				logInfo("Rejecting connection from "+sc.getRemoteAddress()+", "+getActiveConnections()+" clients active (max="+getMaxConnections()
						+"), "+getClientConnections(client)+" from this address (max="+getMaxConnectionsPerClient()+")");
				rejectBusy(sc);
				IoUtils.closeQuietly(sc);
				return;
			}
			acquired = true;
			acquiredFor = client;
			sc.setOption(StandardSocketOptions.TCP_NODELAY, isTcpNoDelay());
			sc.setOption(StandardSocketOptions.SO_KEEPALIVE, isKeepAlive());
			int sndbuf = getSendBufferSize();
			if( sndbuf > 0 ) {
				sc.setOption(StandardSocketOptions.SO_SNDBUF, sndbuf);
			}

			NioReactor reactor = nextReactor();
			INioHandler handler = handlerFactory.getHandler();
			if( handler == null ) {
				throw new IllegalStateException("The handler factory returned null");
			}
			conn = new NioConnection(sc, reactor, this, handler, decoderFactory.get(), 
					handlerExecutor, getInitialInputBuffer(), getMaxInputBuffer(), getMaxIdleTime(), this::createSSLEngine, isSecure());
			conn.setFrameTimeout(getFrameTimeout());
			if( client != null ) {
				clientAddresses.put(conn.getId(), client);
			}
			connections.put(conn.getId(), conn);
			NioConnection accepted = conn;
			logDebug(() -> "Accepted "+accepted);
			try (LogContext.Scope scope = LogContext.enter(conn.getSessionId())) {
				logInfo(SessionLog.connected(sc.getRemoteAddress()));
			}
			reactor.register(conn, true);
			startLoginTimer(conn, reactor);
		} catch (Exception e) {
			logError("Can't start connection for "+sc, e);
			if( conn != null ) {
				// releases the connection through connectionClosed()
				conn.close();
			} else {
				if( acquired ) {
					releaseConnection(acquiredFor);
				}
				IoUtils.closeQuietly(sc);
			}
		}
	}

	/**
	 * Make the SSLEngine for a connection, from the server's SSLContext. Override to change 
	 * the protocols, cipher suites or client certificate settings.
	 * 
	 * @throws IOException if the SSLContext can't be created (no key store...)
	 */
	protected SSLEngine createSSLEngine(INioConnection connection) throws IOException {
		return TlsLayer.serverEngine(getSSLContext(), isNeedClientAuth());
	}

	/**
	 * Called when max clients has been reached, the channel is closed by the caller.
	 * The busy message is sent with one non-blocking write (it fits an empty socket buffer).
	 */
	protected void rejectBusy(SocketChannel sc) {
		String msg = serverBusyMessage;
		if( msg != null && !msg.isEmpty() ) {
			try {
				sc.write(ByteBuffer.wrap((msg+"\r\n").getBytes(StandardCharsets.UTF_8)));
			} catch (IOException e) {
				// Ignore, we're closing it anyway
			}
		}
	}

	private NioReactor nextReactor() {
		NioReactor[] rs = reactors;
		if( rs == null ) {
			throw new IllegalStateException("Server "+getName()+" is not running");
		}
		return rs[Math.floorMod(nextReactor.getAndIncrement(), rs.length)];
	}

	/**
	 * Called by a connection as it closes (once per connection).
	 */
	@Override
	public void connectionClosed(Object connectionObject) {
		if( connectionObject instanceof NioConnection ) {
			NioConnection conn = (NioConnection) connectionObject;
			if( connections.remove(conn.getId(), conn) ) {
				releaseConnection(clientAddresses.remove(conn.getId()));
			}
		}
	}

	// ------------------------------------------------------------------ properties

	/**
	 * Serve connections from a channel that is already bound, instead of opening one on
	 * port / bindAddress at start: e.g. when the caller has to know the port before the
	 * server runs, or was handed the channel (an inherited channel). The server owns it
	 * from then on and closes it when it stops. Used by the next start only.
	 * @param channel a bound ServerSocketChannel
	 */
	public void setServerChannel(ServerSocketChannel channel) {
		boundChannel = channel;
	}

	/**
	 * @return the port the server is listening on (useful when the port was 0), or -1 if not bound.
	 */
	public int getLocalPort() {
		ServerSocketChannel ch = serverChannel;
		if( ch != null ) {
			try {
				SocketAddress addr = ch.getLocalAddress();
				if( addr instanceof InetSocketAddress ) {
					return ((InetSocketAddress) addr).getPort();
				}
			} catch (IOException e) {
				// closed
			}
		}
		return -1;
	}

	/**
	 * @return the open connections (a read only view)
	 */
	public Collection<INioConnection> getConnections() {
		return Collections.unmodifiableCollection(connections.values());
	}

	public int getConnectionCount() {
		return connections.size();
	}

	/**
	 * @return true to set SO_REUSEADDR on the server socket: the value set, else the
	 * {@value IBaseServer#PROPERTY_REUSE_ADDRESS} property, else true
	 */
	public boolean isReuseAddress() {
		Boolean ret = reuseAddress;
		if( ret == null ) {
			ret = getBooleanProperty(propertyName(PROPERTY_REUSE_ADDRESS), true);
			reuseAddress = ret;
		}
		return ret;
	}

	/**
	 * Set SO_REUSEADDR on the server socket (default true), in place of the property.
	 */
	public void setReuseAddress(boolean reuseAddress) {
		this.reuseAddress = reuseAddress;
	}

	/**
	 * @return true to set TCP_NODELAY on accepted sockets: the value set, else the
	 * {@value SocketOptions#PROPERTY_TCP_NO_DELAY} property, else true (AbstractCoreServer's
	 * default is false; like the framework's Server this one defaults to true)
	 */
	@Override
	public boolean isTcpNoDelay() {
		Boolean ret = tcpNoDelay;
		if( ret == null ) {
			ret = getBooleanProperty(propertyName(SocketOptions.PROPERTY_TCP_NO_DELAY), true);
			tcpNoDelay = ret;
		}
		return ret;
	}

	/**
	 * Set TCP_NODELAY on accepted sockets (default true), in place of the property.
	 */
	@Override
	public void setTcpNoDelay(boolean tcpNoDelay) {
		this.tcpNoDelay = tcpNoDelay;
	}

	/**
	 * @return SO_RCVBUF (bytes) for accepted sockets, 0 = the OS default: the value set, else the
	 * {@value #PROPERTY_RECEIVE_BUFFER_SIZE} property, else 0
	 */
	public int getReceiveBufferSize() {
		Integer ret = receiveBufferSize;
		if( ret == null ) {
			ret = Math.max(0, getIntProperty(propertyName(PROPERTY_RECEIVE_BUFFER_SIZE), 0));
			receiveBufferSize = ret;
		}
		return ret;
	}

	/**
	 * SO_RCVBUF for accepted sockets, 0 = OS default, in place of the property. Applies from the next start.
	 */
	public void setReceiveBufferSize(int receiveBufferSize) {
		this.receiveBufferSize = receiveBufferSize;
	}

	/**
	 * @return SO_SNDBUF (bytes) for accepted sockets, 0 = the OS default: the value set, else the
	 * {@value #PROPERTY_SEND_BUFFER_SIZE} property, else 0
	 */
	public int getSendBufferSize() {
		Integer ret = sendBufferSize;
		if( ret == null ) {
			ret = Math.max(0, getIntProperty(propertyName(PROPERTY_SEND_BUFFER_SIZE), 0));
			sendBufferSize = ret;
		}
		return ret;
	}

	/**
	 * SO_SNDBUF for accepted sockets, 0 = OS default, in place of the property.
	 */
	public void setSendBufferSize(int sendBufferSize) {
		this.sendBufferSize = sendBufferSize;
	}

	public String getServerBusyMessage() {
		return serverBusyMessage;
	}

	/**
	 * @param serverBusyMessage optional line sent to clients rejected because {@link #getMaxConnections()} are open
	 */
	public void setServerBusyMessage(String serverBusyMessage) {
		this.serverBusyMessage = serverBusyMessage;
	}

	/**
	 * @return the most time (ms) a frame may take to arrive once its first byte is here, 0 for
	 *  no limit: the value set, else the {@value #PROPERTY_FRAME_TIMEOUT} property (read the first
	 *  time it's needed), else 0. A peer that trickles a frame one byte at a time is never idle;
	 *  this closes it.
	 */
	public long getFrameTimeout() {
		if( frameTimeout < 0 ) {
			frameTimeout = Math.max(0, getDuration(propertyName(PROPERTY_FRAME_TIMEOUT), 0));
		}
		return frameTimeout;
	}

	/** @param milliSeconds see {@link #getFrameTimeout()}; applies to connections accepted after this */
	public void setFrameTimeout(long milliSeconds) {
		frameTimeout = Math.max(0, milliSeconds);
	}

	/**
	 * @return time (ms) without reads or writes before the handler's onIdle, 0 = never: the value
	 * set, else the {@value IBaseServer#PROPERTY_MAX_IDLE_TIME} property (a duration, {@code 30m}), else
	 * {@link #DEFAULT_MAX_IDLE_TIME} (24 hours)
	 */
	public long getMaxIdleTime() {
		Long ret = maxIdleTime;
		if( ret == null ) {
			ret = Math.max(0, getDuration(propertyName(PROPERTY_MAX_IDLE_TIME), DEFAULT_MAX_IDLE_TIME));
			maxIdleTime = ret;
		}
		return ret;
	}

	/**
	 * @param milliSeconds time without reads or writes before the handler's onIdle
	 * (which closes the connection by default), 0 = never, in place of the property.
	 * Applies to new connections.
	 */
	public void setMaxIdleTime(long milliSeconds) {
		this.maxIdleTime = milliSeconds;
	}

	/**
	 * @return the number of reactor (selector) threads: the value set, else the
	 * {@value #PROPERTY_REACTOR_COUNT} property, else {@link #DEFAULT_REACTOR_COUNT}
	 * (the processors, 1 to 4)
	 */
	public int getReactorCount() {
		Integer ret = reactorCount;
		if( ret == null ) {
			ret = getIntProperty(propertyName(PROPERTY_REACTOR_COUNT), DEFAULT_REACTOR_COUNT);
			if( ret < 1 ) {
				logError("Invalid "+propertyName(PROPERTY_REACTOR_COUNT)+" "+ret+", using "+DEFAULT_REACTOR_COUNT);
				ret = DEFAULT_REACTOR_COUNT;
			}
			reactorCount = ret;
		}
		return ret;
	}

	/**
	 * @param reactorCount number of selector threads, in place of the property; applies from the next start
	 */
	public void setReactorCount(int reactorCount) {
		this.reactorCount = reactorCount;
	}

	/**
	 * @return the starting size (bytes) of a connection's input buffer: the value set, else the
	 * {@value #PROPERTY_INITIAL_INPUT_BUFFER} property, else NioConnection's default
	 */
	public int getInitialInputBuffer() {
		Integer ret = initialInputBuffer;
		if( ret == null ) {
			ret = getIntProperty(propertyName(PROPERTY_INITIAL_INPUT_BUFFER), NioConnection.DEFAULT_INITIAL_INPUT_BUFFER);
			initialInputBuffer = ret;
		}
		return ret;
	}

	/**
	 * @param size the starting size of a connection's input buffer, in place of the property;
	 * applies to new connections
	 */
	public void setInitialInputBuffer(int size) {
		this.initialInputBuffer = size;
	}

	/**
	 * @return the largest size (bytes) of a connection's input buffer, which must hold the largest
	 * frame: the value set, else the {@value #PROPERTY_MAX_INPUT_BUFFER} property, else
	 * NioConnection's default
	 */
	public int getMaxInputBuffer() {
		Integer ret = maxInputBuffer;
		if( ret == null ) {
			ret = getIntProperty(propertyName(PROPERTY_MAX_INPUT_BUFFER), NioConnection.DEFAULT_MAX_INPUT_BUFFER);
			maxInputBuffer = ret;
		}
		return ret;
	}

	/**
	 * @param size the largest input buffer of a connection, in place of the property; it must
	 * hold the largest frame. Applies to new connections.
	 */
	public void setMaxInputBuffer(int size) {
		this.maxInputBuffer = size;
	}

	public INioHandlerFactory getHandlerFactory() {
		return handlerFactory;
	}

	public void setHandlerFactory(INioHandlerFactory handlerFactory) {
		this.handlerFactory = handlerFactory;
	}

	public Supplier<IFrameDecoder> getDecoderFactory() {
		return decoderFactory;
	}

	/**
	 * @return true if every connection must log in, so the loginTimeLimit applies to it (the
	 * default); false for a protocol that can be used without logging in
	 * @since 2.0.0
	 */
	protected boolean isLoginRequired() {
		return true;
	}

	/**
	 * With a loginTimeLimit, close the connection if nobody has logged in (it has no
	 * principal) by then. Runs on the connection's reactor, so no thread waits.
	 * The timer holds only the connection's ID: a connection that closes sooner isn't kept
	 * in memory until the limit is up.
	 */
	private void startLoginTimer(NioConnection connection, NioReactor reactor) {
		int limit = getLoginTimeLimit();
		if( limit <= 0 || !isLoginRequired() ) {
			return;
		}
		long id = connection.getId();
		reactor.schedule(() -> {
			// gone from connections once it has closed
			NioConnection conn = connections.get(id);
			if( conn != null && conn.isOpen() && conn.getPrincipal() == null ) {
				try (LogContext.Scope scope = LogContext.enter(conn.getSessionId())) {
					logInfo("Login time limit reached, closing "+conn);
				}
				conn.setCloseReason(SessionLog.REASON_LOGIN_TIME_LIMIT);
				conn.close();
			}
		}, limit);
	}

	/**
	 * @param decoderFactory makes the decoder of each new connection (default {@link RawFrameDecoder})
	 */
	public void setDecoderFactory(Supplier<IFrameDecoder> decoderFactory) {
		this.decoderFactory = decoderFactory == null ? RawFrameDecoder::new : decoderFactory;
	}

	public Executor getHandlerExecutor() {
		return handlerExecutor;
	}

	/**
	 * @param handlerExecutor runs the handler calls of new connections (each connection's
	 * calls still one at a time, in order), null to run them on the reactor threads
	 */
	public void setHandlerExecutor(Executor handlerExecutor) {
		this.handlerExecutor = handlerExecutor;
	}

	// ------------------------------------------------------------------ users

	/**
	 * @return the registry set with {@link #setUserRegistry(UserRegistry)}, else one made from the
	 * {@value #AUTHENTICATION_PROVIDER_PROPERTY} setting (e.g. FileUserRegistry or
	 * PropertiesUserRegistry), else null
	 * @throws IllegalStateException if the setting names a class that can't be made
	 */
	@Override
	public UserRegistry getUserRegistry() {
		if( userRegistry == null && !noUserRegistry ) {
			synchronized (this) {
				if( userRegistry == null && !noUserRegistry ) {
					String tmp = getProperty(propertyName(AUTHENTICATION_PROVIDER_PROPERTY));
					if( tmp != null && !tmp.trim().isEmpty() ) {
						try {
							userRegistry = newUserRegistry(tmp.trim());
							ownsUserRegistry = true;
						} catch (Exception e) {
							logError("Can't configure the user registry class='"+tmp+"'", e);
							throw new IllegalStateException("Can't configure the user registry class='"+tmp+"'", e);
						}
					} else {
						noUserRegistry = true;
						logInfo("No user registry defined in server "+getName());
					}
				}
			}
		}
		return userRegistry;
	}

	/**
	 * Make the registry the provider setting names: with its public constructor that takes an
	 * IBaseServer when it has one, otherwise with its no-argument constructor.
	 */
	private UserRegistry newUserRegistry(String className) throws ReflectiveOperationException {
		Class<?> registryClass = Class.forName(className);
		java.lang.reflect.Constructor<?> withServer = null;
		try {
			withServer = registryClass.getConstructor(IBaseServer.class);
		} catch (NoSuchMethodException e) {
			// it has none; the no-argument constructor is used
		}
		Object made;
		if( withServer != null ) {
			made = withServer.newInstance(this);
		} else {
			made = registryClass.getDeclaredConstructor().newInstance();
		}
		if( !(made instanceof UserRegistry) ) {
			throw new IllegalArgumentException(className+" is not a "+UserRegistry.class.getName());
		}
		return (UserRegistry) made;
	}

	/**
	 * The registry is the caller's: the server doesn't close it. A registry the server made itself
	 * from the provider setting is closed here when it is replaced.
	 *
	 * @param registry the registry, ready to use; null to look at the setting again on the next use
	 */
	@Override
	public void setUserRegistry(UserRegistry registry) {
		UserRegistry old;
		synchronized (this) {
			old = ownsUserRegistry && userRegistry != registry ? userRegistry : null;
			// the registry the server made, given back: still the server's
			this.ownsUserRegistry = ownsUserRegistry && userRegistry == registry && registry != null;
			this.userRegistry = registry;
			this.noUserRegistry = false;
		}
		close(old);
	}

	/**
	 * Close the registry made from the provider setting, if one was made, and forget it, so a
	 * restart makes a new one. A registry given with setUserRegistry is left alone.
	 */
	private void closeOwnUserRegistry() {
		UserRegistry registry;
		synchronized (this) {
			registry = ownsUserRegistry ? userRegistry : null;
			if (registry != null) {
				userRegistry = null;
				ownsUserRegistry = false;
			}
		}
		close(registry);
	}

	private void close(UserRegistry registry) {
		if (registry != null) {
			try {
				registry.close();
			} catch (IOException | RuntimeException e) {
				logError("Can't close the user registry of "+getName(), e);
			}
		}
	}
}
