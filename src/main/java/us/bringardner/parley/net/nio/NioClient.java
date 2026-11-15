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

import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import javax.net.ssl.SSLEngine;

import us.bringardner.parley.core.NamedThreadFactory;
import us.bringardner.parley.core.SecureBaseObject;
import us.bringardner.parley.io.IoUtils;

/**
 * Makes non-blocking connections. All the connections of a client share one
 * {@link NioReactor} thread, started with the first connect. A host name is looked up on a
 * thread of the client's own, so connect() returns at once and never holds up the reactor.
 * <p>
 * TLS uses the client's SSLContext ({@code getSSLContext()} of SecureBaseObject: its trust 
 * managers, and a key store for client certificates): a secure client ({@code setSecure(true)}) 
 * speaks TLS from the first byte, and any connection can switch with 
 * {@link INioConnection#startTls()}. The server's certificate must match the host name 
 * unless {@link #setVerifyHostname(boolean)} turns that off.
 *
 * <pre>
 * try (NioClient client = new NioClient()) {
 *     client.setDecoderFactory(LineFrameDecoder::new);
 *     INioConnection con = client.connectAndWait("localhost", 2222, new MyHandler());
 *     con.writeLine("SSH-2.0-ParleySsh_1.0");
 *     ...
 * }
 * </pre>
 *
 * @author Tony Bringardner
 */
public class NioClient extends SecureBaseObject implements Closeable {

	public static final int DEFAULT_CONNECT_TIMEOUT = 30000;
	/** How long (ms) {@link #close()} waits for the reactor to close the connections and stop */
	public static final long CLOSE_TIMEOUT = 5000;

	private final String name;
	// guarded by this: the reactor, the threads that look up host names, and a count of the
	// closes, so a connect that was looking up a name when the client closed doesn't go on
	private NioReactor reactor;
	private ExecutorService resolver;
	private int generation;
	private volatile int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
	private volatile boolean tcpNoDelay = true;
	private volatile boolean keepAlive = false;
	private volatile long maxIdleTime = 0;
	private volatile int initialInputBuffer = NioConnection.DEFAULT_INITIAL_INPUT_BUFFER;
	private volatile int maxInputBuffer = NioConnection.DEFAULT_MAX_INPUT_BUFFER;
	private volatile Supplier<IFrameDecoder> decoderFactory = RawFrameDecoder::new;
	private volatile Executor handlerExecutor;
	private volatile boolean verifyHostname = true;

	public NioClient() {
		this("NioClient");
	}

	/**
	 * @param name the reactor thread's name
	 */
	public NioClient(String name) {
		this.name = name;
	}

	/**
	 * @return the client's reactor, started if needed
	 */
	public synchronized NioReactor getReactor() throws IOException {
		// a reactor whose thread ended on an error (not stopping) can't serve anything either
		if( reactor == null || reactor.isStopping() || !reactor.isAlive() ) {
			reactor = new NioReactor(name+"-reactor");
			reactor.start();
		}
		return reactor;
	}

	/**
	 * Connect, using the decoder factory for the decoder. The host name is looked up on a
	 * thread of the client's, not the caller's.
	 */
	public CompletableFuture<INioConnection> connect(String host, int port, INioHandler handler) {
		SocketAddress address;
		IFrameDecoder decoder;
		try {
			address = InetSocketAddress.createUnresolved(host, port);
			decoder = decoderFactory.get();
		} catch (RuntimeException e) {
			// a bad port, or the decoder factory failed
			CompletableFuture<INioConnection> ret = new CompletableFuture<INioConnection>();
			ret.completeExceptionally(e);
			return ret;
		}
		return connect(address, handler, decoder);
	}

	/**
	 * Start connecting. The future completes when the connection is established (after the
	 * TLS handshake, if any), once the handler's onConnect has run (or been handed to the
	 * handler executor). It fails with the reason (UnknownHostException for a host name that
	 * can't be found), or with a TimeoutException after the connect timeout, which counts the
	 * host name lookup and the TLS handshake too.
	 *
	 * @param address where to connect; an unresolved InetSocketAddress is looked up on a
	 *  thread of the client's
	 * @param handler receives the connection's events
	 * @param decoder splits the input into frames
	 */
	public CompletableFuture<INioConnection> connect(SocketAddress address, INioHandler handler, IFrameDecoder decoder) {
		CompletableFuture<INioConnection> ret = new CompletableFuture<INioConnection>();
		int timeout = connectTimeout;
		if( timeout > 0 ) {
			ret.orTimeout(timeout, TimeUnit.MILLISECONDS);
		}
		int gen;
		synchronized (this) {
			gen = generation;
		}
		if( address instanceof InetSocketAddress && ((InetSocketAddress) address).isUnresolved() ) {
			InetSocketAddress unresolved = (InetSocketAddress) address;
			try {
				getResolver().execute(() -> {
					if( ret.isDone() ) {
						// timed out or cancelled while waiting for a thread
						return;
					}
					InetSocketAddress resolved = new InetSocketAddress(unresolved.getHostString(), unresolved.getPort());
					if( resolved.isUnresolved() ) {
						ret.completeExceptionally(new UnknownHostException(unresolved.getHostString()));
					} else {
						startConnect(resolved, handler, decoder, ret, gen);
					}
				});
			} catch (RejectedExecutionException e) {
				// closed meanwhile
				ret.completeExceptionally(new IOException("The client was closed while connecting", e));
			}
		} else {
			startConnect(address, handler, decoder, ret, gen);
		}
		return ret;
	}

	/**
	 * Open the channel and hand it to the reactor; ret completes when it is connected.
	 * @param gen the close count when connect was called: if the client has closed since, it fails
	 */
	private void startConnect(SocketAddress address, INioHandler handler, IFrameDecoder decoder,
			CompletableFuture<INioConnection> ret, int gen) {
		SocketChannel sc = null;
		NioConnection conn = null;
		try {
			sc = SocketChannel.open();
			sc.configureBlocking(false);
			sc.setOption(StandardSocketOptions.TCP_NODELAY, tcpNoDelay);
			sc.setOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive);
			NioReactor r = reactorFor(gen);
			String host = null;
			int port = -1;
			if( address instanceof InetSocketAddress ) {
				host = ((InetSocketAddress) address).getHostString();
				port = ((InetSocketAddress) address).getPort();
			}
			String peerHost = host;
			int peerPort = port;
			conn = new NioConnection(sc, r, null, handler, decoder, handlerExecutor,
					initialInputBuffer, maxInputBuffer, maxIdleTime, c -> createSSLEngine(c, peerHost, peerPort), isSecure());
			conn.setConnectFuture(ret);
			boolean connected = sc.connect(address);
			r.register(conn, connected);
			// Timed out or failed: don't leave the channel connecting
			NioConnection registered = conn;
			ret.whenComplete((c, error) -> {
				if( error != null ) {
					registered.close();
				}
			});
		} catch (IOException | RuntimeException e) {
			// e.g. an unresolved host, or the connection refused at once
			ret.completeExceptionally(e);
			if( conn != null ) {
				// closes the channel
				conn.close();
			} else {
				IoUtils.closeQuietly(sc);
			}
		}
	}

	/** The reactor, unless the client has closed since connect was called */
	private synchronized NioReactor reactorFor(int gen) throws IOException {
		if( gen != generation ) {
			throw new IOException("The client was closed while connecting");
		}
		return getReactor();
	}

	/** The threads that look up host names: made when first needed, ended by close() */
	private synchronized Executor getResolver() {
		if( resolver == null ) {
			resolver = Executors.newCachedThreadPool(new NamedThreadFactory(name+"-resolver").daemon(true));
		}
		return resolver;
	}

	/**
	 * Connect and wait for the connection to be established.
	 *
	 * @throws IOException if it can't connect (SocketTimeoutException after the connect timeout)
	 */
	public INioConnection connectAndWait(String host, int port, INioHandler handler) throws IOException {
		return await(connect(host, port, handler));
	}

	public INioConnection connectAndWait(SocketAddress address, INioHandler handler, IFrameDecoder decoder) throws IOException {
		return await(connect(address, handler, decoder));
	}

	private INioConnection await(CompletableFuture<INioConnection> future) throws IOException {
		try {
			return future.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			future.cancel(false);
			throw new InterruptedIOException("Interrupted while connecting");
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			if( cause instanceof TimeoutException ) {
				SocketTimeoutException ste = new SocketTimeoutException("Connect timed out after "+connectTimeout+" ms");
				ste.initCause(cause);
				throw ste;
			}
			if( cause instanceof IOException ) {
				throw (IOException) cause;
			}
			throw new IOException("Can't connect: "+cause, cause);
		}
	}

	/**
	 * Close every connection of this client and stop its reactor, waiting up to
	 * {@link #CLOSE_TIMEOUT} ms for that to finish: when it returns the sockets are closed,
	 * and the handlers' onClose has run unless they run on a handler executor.
	 * Called on the reactor thread (from a handler) it returns at once and the reactor
	 * finishes after the handler call returns.
	 * A later connect starts a new reactor.
	 */
	@Override
	public void close() {
		NioReactor r;
		ExecutorService lookups;
		synchronized (this) {
			generation++;
			r = reactor;
			reactor = null;
			lookups = resolver;
			resolver = null;
		}
		if( lookups != null ) {
			// a lookup under way finishes on its own and then fails (the generation has changed)
			lookups.shutdown();
		}
		if( r == null ) {
			return;
		}
		r.stop();
		if( r.inReactorThread() ) {
			// waiting here would wait for this thread itself
			return;
		}
		try {
			r.join(CLOSE_TIMEOUT);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Make the SSLEngine for a connection, from the client's SSLContext, with SNI and 
	 * (if {@link #isVerifyHostname()}) a host name check. Override to change the protocols or 
	 * cipher suites.
	 * 
	 * @throws IOException if the SSLContext can't be created
	 */
	protected SSLEngine createSSLEngine(INioConnection connection, String host, int port) throws IOException {
		return TlsLayer.clientEngine(getSSLContext(), host, port, verifyHostname);
	}

	public boolean isVerifyHostname() {
		return verifyHostname;
	}

	/**
	 * @param verifyHostname false to accept a certificate that doesn't match the host name 
	 * (default true; turning it off is only safe with trust managers that pin the certificate)
	 */
	public void setVerifyHostname(boolean verifyHostname) {
		this.verifyHostname = verifyHostname;
	}

	public int getConnectTimeout() {
		return connectTimeout;
	}

	/**
	 * @param milliSeconds how long a connect may take, 0 = no limit (the OS's)
	 */
	public void setConnectTimeout(int milliSeconds) {
		this.connectTimeout = milliSeconds;
	}

	public boolean isTcpNoDelay() {
		return tcpNoDelay;
	}

	public void setTcpNoDelay(boolean tcpNoDelay) {
		this.tcpNoDelay = tcpNoDelay;
	}

	public boolean isKeepAlive() {
		return keepAlive;
	}

	public void setKeepAlive(boolean keepAlive) {
		this.keepAlive = keepAlive;
	}

	public long getMaxIdleTime() {
		return maxIdleTime;
	}

	/**
	 * @param milliSeconds time without reads or writes before the handler's onIdle, 0 = never (default)
	 */
	public void setMaxIdleTime(long milliSeconds) {
		this.maxIdleTime = milliSeconds;
	}

	public int getInitialInputBuffer() {
		return initialInputBuffer;
	}

	public void setInitialInputBuffer(int size) {
		this.initialInputBuffer = size;
	}

	public int getMaxInputBuffer() {
		return maxInputBuffer;
	}

	/**
	 * @param size the largest input buffer of a connection; it must hold the largest frame
	 */
	public void setMaxInputBuffer(int size) {
		this.maxInputBuffer = size;
	}

	public Supplier<IFrameDecoder> getDecoderFactory() {
		return decoderFactory;
	}

	/**
	 * @param decoderFactory makes the decoder for {@link #connect(String, int, INioHandler)} (default {@link RawFrameDecoder})
	 */
	public void setDecoderFactory(Supplier<IFrameDecoder> decoderFactory) {
		this.decoderFactory = decoderFactory == null ? RawFrameDecoder::new : decoderFactory;
	}

	public Executor getHandlerExecutor() {
		return handlerExecutor;
	}

	/**
	 * @param handlerExecutor runs the handler calls of new connections, null to run them on the reactor thread
	 */
	public void setHandlerExecutor(Executor handlerExecutor) {
		this.handlerExecutor = handlerExecutor;
	}
}
