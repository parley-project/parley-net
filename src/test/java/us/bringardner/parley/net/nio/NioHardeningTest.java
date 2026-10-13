package us.bringardner.parley.net.nio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Protection against clients that hold connections without doing anything useful:
 * a time limit for each frame (a client sending one byte at a time is never idle),
 * a deadline a handler can set, a connection limit per client address and an
 * allow list of client addresses. Learned from parley-dns (round 5 #72, #78).
 */
public class NioHardeningTest {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private NioServer server;

	@AfterEach
	public void tearDown() throws InterruptedException {
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	/** Echoes each length-prefixed frame (2-byte length, as DNS over TCP) */
	private static class Echo implements INioHandler {
		@Override
		public void onMessage(INioConnection connection, ByteBuffer frame) throws Exception {
			byte [] b = new byte[frame.remaining()];
			frame.get(b);
			connection.write(LengthFieldFrameDecoder.frame(b, 2));
		}
	}

	private void start(INioHandlerFactory handlers) throws IOException {
		server = new NioServer(0, "hardening");
		server.setHandlerFactory(handlers);
		server.setDecoderFactory(() -> new LengthFieldFrameDecoder(2, 65535, true));
		server.setReactorCount(1);
	}

	private Socket connect() throws IOException {
		Socket s = new Socket(LOOPBACK, server.getLocalPort());
		s.setSoTimeout(5000);
		return s;
	}

	/** Send one frame and read the echo; IOException if the server closed the connection */
	private static byte [] roundTrip(Socket s, byte [] payload) throws IOException {
		OutputStream out = s.getOutputStream();
		out.write(new byte[] {(byte)(payload.length >> 8), (byte)payload.length});
		out.write(payload);
		out.flush();
		InputStream in = s.getInputStream();
		int hi = in.read();
		int lo = in.read();
		if( hi < 0 || lo < 0 ) {
			throw new IOException("closed by the server");
		}
		byte [] b = new byte[(hi << 8) | lo];
		int n = 0;
		while( n < b.length ) {
			int r = in.read(b, n, b.length-n);
			if( r < 0 ) {
				throw new IOException("closed by the server");
			}
			n += r;
		}
		return b;
	}

	/** true if the server closes the connection within the socket timeout */
	private static boolean closedByServer(Socket s) throws IOException {
		try {
			return s.getInputStream().read() == -1;
		} catch(SocketTimeoutException ex) {
			return false;
		} catch(IOException ex) {
			return true;
		}
	}

	@Test
	public void aFrameSentOneByteAtATimeIsCutOff() throws Exception {
		start(Echo::new);
		server.setFrameTimeout(500);
		server.setMaxIdleTime(1000);
		server.startAndWait(5000);
		try(Socket s = connect()) {
			OutputStream out = s.getOutputStream();
			out.write(new byte[] {0, 40});
			long start = System.currentTimeMillis();
			boolean closed = false;
			//  one byte every 200 ms for 3 s: never idle for 1000 ms, never a whole frame
			for(int i=0; i < 15 && !closed; i++ ) {
				Thread.sleep(200);
				try {
					out.write(0);
					out.flush();
				} catch(IOException ex) {
					closed = true;
				}
			}
			//  checked while still well inside the idle time, so only the frame limit can have closed it
			s.setSoTimeout(300);
			assertTrue(closed || closedByServer(s), "the connection was still open after "+(System.currentTimeMillis()-start)+" ms");
		}
	}

	@Test
	public void wholeFramesAreNotCutOff() throws Exception {
		start(Echo::new);
		server.setFrameTimeout(500);
		server.startAndWait(5000);
		try(Socket s = connect()) {
			for(int i=0; i < 6; i++ ) {
				//  frames 400 ms apart: the time limit is per frame, not per connection
				assertEquals(3, roundTrip(s, new byte[] {1, 2, 3}).length);
				Thread.sleep(400);
			}
		}
	}

	@Test
	public void framesAreUnlimitedByDefault() throws Exception {
		start(Echo::new);
		assertEquals(0, server.getFrameTimeout());
	}

	@Test
	public void aDeadlineClosesTheConnectionByDefault() throws Exception {
		start(() -> new Echo() {
			@Override
			public void onConnect(INioConnection connection) {
				connection.setDeadline(300);
			}
		});
		server.startAndWait(5000);
		try(Socket s = connect()) {
			//  traffic doesn't move a deadline
			assertEquals(1, roundTrip(s, new byte[] {9}).length);
			s.setSoTimeout(4000);
			assertTrue(closedByServer(s));
		}
	}

	@Test
	public void aClearedDeadlineDoesNothing() throws Exception {
		start(() -> new Echo() {
			@Override
			public void onConnect(INioConnection connection) {
				connection.setDeadline(300);
			}

			@Override
			public void onMessage(INioConnection connection, ByteBuffer frame) throws Exception {
				connection.clearDeadline();   //  e.g. logged in
				super.onMessage(connection, frame);
			}
		});
		server.startAndWait(5000);
		try(Socket s = connect()) {
			assertEquals(1, roundTrip(s, new byte[] {9}).length);
			s.setSoTimeout(2000);
			assertTrue(!closedByServer(s), "closed although the deadline was cleared");
		}
	}

	@Test
	public void aHandlerDecidesWhatADeadlineDoes() throws Exception {
		start(() -> new Echo() {
			@Override
			public void onConnect(INioConnection connection) {
				connection.setDeadline(200);
			}

			@Override
			public void onDeadline(INioConnection connection) throws Exception {
				connection.write(LengthFieldFrameDecoder.frame(new byte[] {'T', 'O'}, 2));
				connection.closeAfterFlush();
			}
		});
		server.startAndWait(5000);
		try(Socket s = connect()) {
			InputStream in = s.getInputStream();
			assertEquals(0, in.read());
			assertEquals(2, in.read());
			assertEquals('T', in.read());
			assertEquals('O', in.read());
			assertEquals(-1, in.read());
		}
	}

	@Test
	public void oneAddressCantTakeEveryPlace() throws Exception {
		start(Echo::new);
		server.setMaxConnections(10);
		server.setMaxConnectionsPerClient(2);
		server.startAndWait(5000);
		List<Socket> open = new ArrayList<Socket>();
		try {
			open.add(connect());
			open.add(connect());
			assertEquals(1, roundTrip(open.get(0), new byte[] {1}).length);
			assertEquals(1, roundTrip(open.get(1), new byte[] {1}).length);
			try(Socket third = connect()) {
				assertTrue(closedByServer(third), "a third connection from the same address");
			}
			//  one closes: there is room again
			open.remove(0).close();
			long end = System.currentTimeMillis()+3000;
			boolean ok = false;
			while( !ok && System.currentTimeMillis() < end ) {
				try(Socket again = connect()) {
					roundTrip(again, new byte[] {2});
					ok = true;
				} catch(IOException ex) {
					Thread.sleep(50);
				}
			}
			assertTrue(ok, "no room after a connection closed");
		} finally {
			for(Socket s : open) {
				s.close();
			}
		}
	}

	@Test
	public void addressesNotOnTheAllowListAreRefused() throws Exception {
		start(Echo::new);
		server.setAllowedClients("192.0.2.0/24");
		server.startAndWait(5000);
		try(Socket s = connect()) {
			assertTrue(closedByServer(s));
		}
		server.setAllowedClients("127.0.0.0/8 ::1");
		try(Socket s = connect()) {
			assertEquals(1, roundTrip(s, new byte[] {7}).length);
		}
	}

	@Test
	public void waitingOnAPausedHandlerIsntTheClientsFault() throws Exception {
		//  The handler pauses reading while it works on frame 1; the rest of frame 2 waits
		//  in the kernel for 2.5 s. The frame time limit (500 ms) must not count that.
		server = new NioServer(0, "paused");
		server.setDecoderFactory(() -> new LengthFieldFrameDecoder(2, 65535, true));
		server.setReactorCount(1);
		server.setFrameTimeout(500);
		server.setHandlerFactory(() -> new INioHandler() {
			int n;

			@Override
			public void onMessage(INioConnection c, ByteBuffer f) throws Exception {
				byte [] b = new byte[f.remaining()];
				f.get(b);
				if( n++ == 0 ) {
					c.pauseReading();
					new Thread(() -> {
						try {
							Thread.sleep(2500);
							c.write(LengthFieldFrameDecoder.frame(b, 2));
						} catch(Exception e) {
							// closed
						}
						c.resumeReading();
					}).start();
				} else {
					c.write(LengthFieldFrameDecoder.frame(b, 2));
				}
			}
		});
		server.startAndWait(5000);
		try(Socket s = new Socket(LOOPBACK, server.getLocalPort())) {
			s.setSoTimeout(8000);
			OutputStream out = s.getOutputStream();
			//  frame 1 and the start of frame 2 together, the rest of frame 2 soon after
			out.write(new byte[] {0, 1, 7, 0, 4, 1});
			out.flush();
			Thread.sleep(200);
			out.write(new byte[] {2, 3, 4});
			out.flush();
			byte [] got = readFully(s.getInputStream(), 3+6);
			assertEquals(9, got.length, "closed after "+got.length+" bytes");
		}
	}

	private static byte [] readFully(InputStream in, int len) throws IOException {
		byte [] b = new byte[len];
		int n = 0;
		while( n < len ) {
			int r = in.read(b, n, len-n);
			if( r < 0 ) {
				return java.util.Arrays.copyOf(b, n);
			}
			n += r;
		}
		return b;
	}

	@Test
	public void aTlsHandshakeTrickledInIsCutOff() throws Exception {
		//  Before TLS is up nothing reaches the frame decoder: the handshake itself must
		//  be done within the frame time limit
		start(Echo::new);
		server.setSecure(true);
		server.setKeyStoreType("PKCS12");
		server.setKeyStoreFileName("/test-keystore.p12");
		server.setKeyStorePassword("changeit");
		server.setFrameTimeout(500);
		server.setMaxIdleTime(5000);
		server.startAndWait(5000);
		try(Socket s = connect()) {
			OutputStream out = s.getOutputStream();
			//  the start of a ClientHello record, one byte every 200 ms
			byte [] hello = {0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, (byte)0xfc, 0x03, 0x03, 0, 0, 0, 0, 0};
			boolean closed = false;
			for(int i=0; i < hello.length && !closed; i++ ) {
				try {
					out.write(hello[i]);
					out.flush();
				} catch(IOException ex) {
					closed = true;
				}
				Thread.sleep(200);
			}
			s.setSoTimeout(300);
			assertTrue(closed || closedByServer(s), "the TLS connection was still open");
		}
	}

	@Test
	public void aChannelBoundBeforeStartIsServed() throws Exception {
		java.nio.channels.ServerSocketChannel ch = java.nio.channels.ServerSocketChannel.open();
		ch.bind(new java.net.InetSocketAddress(LOOPBACK, 0));
		int port = ((java.net.InetSocketAddress)ch.getLocalAddress()).getPort();
		start(Echo::new);
		server.setServerChannel(ch);
		server.startAndWait(5000);
		assertEquals(port, server.getLocalPort());
		try(Socket s = new Socket(LOOPBACK, port)) {
			s.setSoTimeout(5000);
			assertEquals(2, roundTrip(s, new byte[] {4, 2}).length);
		}
		server.stop(5000, false);
		assertTrue(!ch.isOpen(), "the server closes the channel it was given");
		server = null;
	}
}
