/**
 * A non-blocking (NIO) framework for network protocols, client and server.
 * <p>
 * A {@link us.bringardner.parley.net.nio.NioServer} accepts connections on a non-blocking
 * channel and serves them from a few {@link us.bringardner.parley.net.nio.NioReactor}
 * selector threads; a {@link us.bringardner.parley.net.nio.NioClient} connects the same way.
 * The input of each connection is split into frames by an
 * {@link us.bringardner.parley.net.nio.IFrameDecoder} and passed to its
 * {@link us.bringardner.parley.net.nio.INioHandler}; writes are queued and sent by the reactor.
 * TLS (from the first byte or with STARTTLS) uses an SSLEngine configured like the blocking
 * framework's sockets.
 * <p>
 * Use it for protocols where both ends send at any time or many channels share a connection
 * (SSH, WebSocket...). For request / response protocols the blocking
 * {@link us.bringardner.parley.net.server.Server} is simpler.
 * <p>
 * Preview: the API may still change.
 */
package us.bringardner.parley.net.nio;
