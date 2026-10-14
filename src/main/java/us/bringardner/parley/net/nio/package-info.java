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
 *
 * <PRE>
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
 */
package us.bringardner.parley.net.nio;
