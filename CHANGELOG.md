# Changelog

## parley-net 2.0.0 (unreleased)

### Removed (needs a code change)

- The misspelled names deprecated in 1.0.0: `IPrincipal.getPermisssions` (implement `getPermissions`),
  `ICommandResponse.readResonse` (implement `readResponse`), `ICommandClient` and `IRequestContext`
  `get/setSeperator` (implement `get/setSeparator`), `DefaultRequestContext.get/setDefaultSeperator`,
  `IServer.AUTHENTICATOION_PROVIDER_PROPERTY`, `IGenericResponseCode.REPLY_300_GENERIC_TEMPOARY_OK` and
  `REPLY_400_GENERIC_TEMPOARY_ERROR`, `Server.DEFAULT_MAX_IDEL_CONNECTION` and `get/setServerGreating`, and the
  class `CertificateValidotorDialog` (use `CertificateValidatorDialog`).
- `Server.getSSLContext(sslOrTls, instanceName, keyStoreType, passPhrase, keyFileName)`: set the key store on the
  server (`setKeyStoreFileName`, `setKeyStorePassword` ...) and call `getSSLContext()`.

### Changed (needs a configuration change)

- Properties are read with `propertyName(name)` (`<prefix>.authenticationProvider`, `<prefix>.userFile`,
  `<prefix>.virtualThreads` ...): the name alone (`-DauthenticationProvider=...`) no longer applies to every
  server, since parley-core's `getProperty` now looks up exactly the name it is given.
- **Property names** (Parley 2.0.0; the old names are no longer read): `AuthenticationProvider` is
  `authenticationProvider`, `FrameTimeout` `frameTimeout`, `VirtualThreads` `virtualThreads`, and parley-core's
  server settings are lowerCamel too (`port`, `maxConnections`, `keyStoreName` ...).
  `FileBasedAcl.maxConcurrentHashes` and `FileBasedAcl.hashWaitMs` are `parley.net.acl.maxConcurrentHashes`
  and `parley.net.acl.hashWaitMs`.
- **Access control lists use the server's property prefix**, not its name: `IServer.getPropertyPrefix()` is
  new, and `FileBasedAcl`, `PropertyAuthenticator` and `NioServer` read `<prefix>.userFile`, `<prefix>.user0` ...
  `new Server(port, name)` and `new NioServer(port, name)` make the name the property prefix, so a server
  made that way reads `name.port`, `name.userFile` ... as its access control list did before.

## parley-net 1.1.0 (unreleased)

### Added

- **SCRAM from the access control list.** `IAccessControlList.supportsScram(hash)` and
  `getScramCredentials(user, hash)` (defaults: no, null), so a server can offer SCRAM-SHA-1 and
  SCRAM-SHA-256 with its own users. `ServerSaslAuthenticator` serves them when the list does;
  after a SCRAM success, `verified(user)` gives the principal. `IServer.getVerifiedPrincipal(user)`
  (and `NioServer.getVerifiedPrincipal`) is the principal of a user a SASL mechanism proved.
  `ScramCredentials.format()` / `parse(text)` keep credentials as text,
  `ScramMechanism.newCredentials(password)` makes them with a new salt, `ScramMechanism.hashOf(name)`.
- A tests jar (`parley-net-<version>-tests.jar`) with `ServerTestSupport`, for the protocols' tests:
  `writeKeystore(file)` writes the test keystore (`KEYSTORE_PASSWORD`) for a server's KeyStoreName.
- **An access control list that can't answer** (its database is down) isn't a wrong password:
  `AccessControlUnavailableException`, `IAccessControlList.findPrincipal(user)` (the default calls
  `getPrincipal`, so it never throws) and `IServer.checkLogin(user, credentials)` (and `NioServer.checkLogin`)
  say "try again later" apart from "failed". `authenticate` still returns null for both, and logs the outage.
  `getScramCredentials`, `getVerifiedPrincipal` and `ServerSaslAuthenticator.verified` throw it;
  `ServerSaslAuthenticator.isUnavailable()` tells why a SASL login failed.
- `FileBasedAcl` keeps SCRAM credentials after a hashed password
  (`{PBKDF2}...;{SCRAM-SHA-256}...;{SCRAM-SHA-1}...`, made by `FileBasedAcl --scram` or
  `hashPasswordWithScram`) and makes them for plain text passwords; it offers SCRAM only when every
  user in the file can use it. Servers whose users all have plain text passwords now offer SCRAM.
- `StoreLocks`: this JVM's lock domains for file servers (FTP, SFTP), one per served root, nested roots sharing
  one, with file lock names from the domain's root and `isLockFile` to keep clients out of the lock directory.
  `NamedLock.closeFromAnyThread()` is public, for work that ends on another thread.
- **Locks for servers** (`us.bringardner.parley.net.lock`): locks on names (a mailbox, a maildrop, a queue entry)
  that reach this JVM's threads and the other servers using the same stores. Now depends on parley-files 1.1.0.
  - `Locks.open(LockOptions.sharing(Sharing.OFF | HOST | CLUSTER))`, one per JVM; `locks.domain(name, root)` for
    each store; then `lock(name, mode, timeout)`, `tryLock(name, mode)`, `request(name)...acquire()` for every
    option, and `Locks.lockAll(names, mode, timeout)` across domains in one order.
  - Threads wait first come, first served, up to a timeout (`LockTimeoutException`); readers that come while a
    writer waits queue behind it. Reentrant by default, like `synchronized`; a request or the options can ask
    for locks that aren't. A shared holding can't be upgraded to exclusive.
  - Kept between servers by a provider: `region` (the store's own locks; liberal) or `lease` (lease
    directories; conservative; readers on several servers share a name), chosen from the store's capabilities
    with `auto`, or named in the options or `parley.net.lock.provider`; others through the
    `us.bringardner.parley.net.lock.spi` interfaces. An unsafe choice is refused unless allowed, and a server that
    would keep a store's locks differently from the others is refused.
  - A coordination store keeps every domain's locks in one place (`LockOptions.withCoordinationStore`).
  - `LockDomain.claimStore(serverId)`: a server's claim on its store, alone (OFF: a second server is refused)
    or shared (HOST, CLUSTER: refuses one that wants it alone). Servers in one JVM claim once.
  - `AtomicWrite.replace(file, lock, writer)`: a shared file replaced through a uniquely named temporary file,
    renamed into place (atomically where the store can) only while the lock is still held.

## parley-net 1.0.0 (2026-10-16)

BjlNetFramework is now **parley-net**, part of the Parley library family. It continues from
BjlNetFramework 1.0.1 (see [BjlNetFramework history](#bjlnetframework-history)); the changes since
then are below, with the renames first.

### Changed (needs a code change)

- Maven coordinates: `us.bringardner:bjl_net_framework` is now `us.bringardner.parley:parley-net`.
- Packages: `us.bringardner.net.framework` (and `.client`, `.server`, `.nio`) is now
  `us.bringardner.parley.net`.
- Module name (`Automatic-Module-Name`): `us.bringardner.parley.net` (none was set before).
- Property names that start with a class name change with the package, for example
  `us.bringardner.net.framework.server.Server.<name>` is now `us.bringardner.parley.net.server.Server.<name>`.
- Dependencies: `bjl_core` and `bjl_io` are now `parley-core` and `parley-io`.
- **Sessions run on virtual threads by default on Java 24 and later.** The `VirtualThreads`
  default is now AUTO (it was OFF): virtual threads where blocking I/O no longer pins a carrier
  thread (JEP 491), platform threads on Java 11-23, so nothing changes there. A server that must
  keep a platform thread per session on Java 24+ calls `setVirtualThreads(OFF)` or sets the
  `VirtualThreads` property to `OFF`.

### Changed (may need a code change)

- `Server.getSSLContext(name)` accepts only TLS or SSL mechanism names (`TLS`, `SSL`, `TLS-C`,
  `TLS-P`, `TLSv1.3` ...); anything else throws `IOException`. The name no longer selects a TLS
  version: use the socket's enabled protocols (for example `SecureBaseObject.PROPERTY_FORCE_TLS_VERSION`).
- `doAdmin()` (the idle connection check) runs on the server's scheduler thread instead of between
  accepts. A subclass that overrides it now runs on that thread.
- Under a burst of logins, a password check can fail after waiting `hashWaitMs` for its turn (the
  client can retry), instead of every login slowing every session.
- `Connection`'s TLS upgrade and `Client.setTrustAllCertificates(true)` use `bjl_core`'s `TlsSockets`
  and `TrustAllCertificates`. Behaviour is unchanged.

### Fixed

- `Server` ignored `BindAddress` / `setBindAddr`: it always listened on every interface, so a server
  meant for this machine only (an admin port, say) could be reached from the network. `NioServer`
  already used it.

- **STARTTLS / AUTH TLS used a new TLS context for every upgrade (BJL-38).** `getSSLContext(name)`
  switched the server's protocol to the name the client sent, built a context and switched back:
  the server's main context was thrown away each time, no session could be resumed (so FTP data
  connections couldn't resume the control session), and another thread could get the wrong context
  during the switch. Every upgrade now uses the server's one context.
- **Without an access control provider, every command took the server lock** to look the provider
  property up again and logged "No access control defined" (BJL-42). It is now looked up and logged once.
- **TLS sessions ended with a `user_canceled` alert** before `close_notify` (Java's close of a TLS 1.3
  socket), which GnuTLS clients such as FileZilla and lftp report as a fatal error (BJL-2). Only
  `close_notify` is sent now.
- The connection's write lock is a lock, not `synchronized`, so a virtual thread flushing to a slow
  client doesn't hold on to its carrier thread on Java 21-23 (BJL-55).

### Added

- `client.UpstreamHealth`: what a client knows about one upstream server: smoothed response time
  and the timeout it suggests, failures in a row, an exponential hold-off with probing while every
  server is held off, and `order`/`soonest` to choose among several. From parley-dns (`ServerA`).
- `NioServer.setServerChannel(channel)`: serve a channel the caller has already bound (to know the
  port before the server starts, or an inherited channel) instead of opening one at start.

- `AbstractCommandProcessor.replyLineTooLong(max)`: a request line over the connection's limit is
  now answered (default `500 Line too long (max N bytes)`; a protocol overrides it for its own
  reply) before the session ends. It used to end without a reply.

- **Limits per client** (from parley-core): `MaxConnectionsPerClient` caps the connections one client
  address may have, so a single host can't take every place under `MaxConnections` /
  `setMaxClients`, and `AllowedClients` lists the addresses allowed to connect; others are closed as
  soon as they are accepted. `Server` and `NioServer` both apply them. Both default to no limit.
- **NIO deadlines**: `INioConnection.setDeadline(ms)` / `clearDeadline()` and
  `INioHandler.onDeadline` (default: close), for things that must happen in time however much
  traffic there is, such as logging in. Checked with the idle checks (about once a second).
- **NIO frame time limit**: `NioServer.setFrameTimeout(ms)` (property `FrameTimeout`, default 0 =
  none) closes a connection whose frame doesn't arrive in time once it has started (with TLS, also a
  record or the handshake). A client sending one byte at a time is never idle, so the idle time alone
  let it hold a connection for ever. Time spent waiting on the handler (reading paused, input
  buffer full) doesn't count.
- `LengthFieldFrameDecoder.frame(payload, lengthFieldSize)`, for 1 and 2 byte lengths (DNS over TCP
  uses 2).
- `FatalErrorHandler` (from parley-dns): logs every thread that dies from an uncaught error and, when
  installed with halting on, stops the process on a `VirtualMachineError` (OutOfMemoryError...) so a
  supervisor can start a clean one.

- **Session states**: `StateMachine` (a session's state as an enum, optionally with the legal
  moves) and `IStatefulCommand` (the states a command is valid in). `AbstractCommandProcessor`
  checks them before running a command when the processor returns a machine from
  `getStateMachine()`; `replyInvalidState` sets the reply. Nothing changes for a processor that
  doesn't override `getStateMachine()`.
- **Capabilities** (`us.bringardner.parley.net.capability`): `Capability` and `CapabilitySet`
  render and parse what EHLO, CAPA, FEAT and CAPABILITY list (one per line, or IMAP's inline
  `AUTH=PLAIN`), and `CapabilityRegistry` decides per session what to offer (STLS only before
  TLS, AUTH mechanisms only after it, ...).
- **SASL** (`us.bringardner.parley.net.sasl`): a protocol independent server and client SPI
  (`ISaslMechanism`, `ISaslServer`, `ISaslClient`, `ISaslAuthenticator`) with PLAIN, LOGIN,
  CRAM-MD5, SCRAM-SHA-1, SCRAM-SHA-256 and XOAUTH2. `SaslServerDriver` runs an exchange given
  only how the protocol sends a challenge and reads a response (`ISaslChannel`), and
  `SaslMechanisms` lists what to advertise. `ServerSaslAuthenticator` checks PLAIN and LOGIN
  against the server's access control list. SASLprep is not applied and channel binding
  (`-PLUS`) is not offered.
  `SaslClients` creates the client side of the password mechanisms by name and picks one from
  what a server offers, in the caller's order of preference.
- **A non-blocking (NIO) framework, package `nio`.** For
  protocols where both ends send at any time or many channels share one connection (SSH, WebSocket,
  MQTT...), and for many connections on Java 11-20 without a thread each. `NioServer` (an
  `AbstractCoreServer`, configured by the same properties) accepts on a non-blocking channel and
  serves its connections from a few `NioReactor` selector threads; `NioClient` connects the same way.
  Input is split into frames by an `IFrameDecoder` (`LineFrameDecoder`, `LengthFieldFrameDecoder`,
  `RawFrameDecoder`), which a handler can change between frames, and passed to an `INioHandler`
  (`onConnect`, `onMessage`, `onIdle`, `onError`, `onClose`): one call at a time per connection, on
  the reactor thread or a handler executor. Writes are queued, with `getPendingWriteBytes()` and
  `pauseReading()` / `resumeReading()` for flow control. TLS uses `SSLEngine` with the server's or
  client's `SecureBaseObject` settings: from the first byte (`setSecure(true)`) or `startTls()` for
  STARTTLS. Logins use the same `IAccessControlList` as `Server`. The blocking `Server` remains the
  simpler choice for request / response protocols, with virtual threads on Java 21+.
- **Access control without an `IServer`.** `IAccessControlList.initialize(String serverName)` sets up
  an access control list for a server known only by name (for example the non-blocking
  `nio.NioServer`). `FileBasedAcl` and `PropertyAuthenticator` implement it and their
  `initialize(IServer)` calls it; the interface's default throws `UnsupportedOperationException`, so
  existing implementations still compile. The read only principal `Server.authenticate()` returns is
  now the public class `ImmutablePrincipal`, so other servers can hand out the same kind.
- **Session tasks and a scheduler (BJL-59).** `Server.startTask(session, thread)` starts a thread that
  belongs to a session: it runs on the same kind of thread as sessions, gets a name, keeps the idle
  check from closing its session, and is stopped when the session ends or the server stops
  (`setTaskStopWait()`, default 5 seconds). `schedule()` and `scheduleAtFixedRate()` run work on the
  server's own scheduler thread. `IServer` has default versions for servers that don't manage tasks.
- **Virtual threads for sessions (BJL-51).** `Server.setVirtualThreads(OFF | ON | AUTO)` or the
  `VirtualThreads` property. OFF (the default) is unchanged; ON uses virtual threads on Java 21+;
  AUTO only on Java 24+. Safe on Java 21-23 with `bjl_io` 1.0.1 or later (its line reader uses a lock).
- **Pipelining (BJL-43).** `CommandClient.executeCommands(list)` sends several commands at once (at
  most `MAX_PIPELINED`, 64, per batch) and reads the replies in order, one round trip per batch
  instead of per command (for example SMTP PIPELINING, RFC 2920). `ICommandClient` has a default
  that runs them one at a time.
- **Multi-line replies in one write (BJL-41).** `Connection.writeLines(list)` /
  `IConnection.writeLines` and `AbstractCommandProcessor.reply(list)` send several lines with one
  flush, so a `211-` ... `211 End` reply goes out as one TCP segment or TLS record, not one per line.
- **TLS session resumption for clients (BJL-39).** Clients share one TLS context per protocol and trust
  mode, so a client that reconnects to the same server resumes its session instead of a full
  handshake. `Client.setContext()` / `getContext()` give a group of clients their own context.
- **A limit on concurrent password hashing (BJL-40).** Each PBKDF2 check takes a few hundred
  milliseconds of CPU by design, so a burst of logins could use every core. `FileBasedAcl` runs at most
  `setMaxConcurrentHashes()` at once (default half the cores) and a login waits up to `setHashWaitMs()`
  (default 30 seconds) for its turn (properties `FileBasedAcl.maxConcurrentHashes` and
  `FileBasedAcl.hashWaitMs`).
- **Keep-alive.** Accepted sockets get SO_KEEPALIVE when `bjl_core`'s `KeepAlive` setting is on
  (`setKeepAlive(true)`, default off), so clients that vanish without closing are noticed.

### Deprecated

- `Server.getSSLContext(protocol, algorithm, keyStoreType, password, keyFile)`: set the key store on the
  server (`setKeyStoreFileName`, `setKeyStorePassword` ...) and use `getSSLContext()`, or configure a
  `bjl_core` `SecureBaseObject`. It now does the latter itself instead of loading the key store with its
  own code; the result is the same.

## BjlNetFramework history

Releases made before the library became parley-net, as `us.bringardner:bjl_net_framework` (BjlNetFramework).

## 1.0.1

### Fixed

- `Server.stop()` only set `stopping`, so a server waiting in `accept()` kept running until the accept
  timeout (5 seconds by default). It now closes the listening socket, so it stops at once.
- A stopped `Server` could not be started again: it kept the closed listening socket. A new one is
  created on the next start.

## 1.0.0

First stable release. It contains breaking changes from 0.1.x; see
[Upgrading from 0.1.x](#upgrading-from-01x) below.

Requires Java 11, `bjl_core` 1.0.0 and `bjl_io` 1.0.0 (both have their own breaking changes,
see their changelogs).

### Breaking changes

- **Client TLS certificates are validated.** `Client` used to accept any server certificate.
  It now trusts the JVM trust store plus certificates the user approved through
  `DynamicTrustManager`, and checks that the certificate matches the host name.
  `setTrustAllCertificates(true)` restores the old behavior; `setVerifyHostname(false)` turns
  off only the host name check.
- **Timeouts are on by default.** Server connections time out reads after 60 seconds
  (`Server.setConnectionTimeout`), clients after 5 minutes (`setTimeout`, or the `readTimeout`
  property). Clients also have a 30 second connect timeout. Use 0 for the old wait-forever behavior.
- **Lines are limited to 64 KiB.** A longer line ends the session with a `LineTooLongException`.
  Change it with `Connection.setDefaultMaxLineLength` or `setMaxLineLength`, 0 for no limit.
- **A failing command no longer ends the session.** A `RuntimeException` from a command is
  logged and the client gets a `500` reply; only I/O errors end the session. The exception text
  is no longer sent to the client.
- **`DefaultRequestContext`**: a one character separator is literal (`|` and `.` were regex
  operators), and `getRemainingTokens()` returns the rest of the line exactly as received.
- **`Server.getServerSocketFactory(boolean)` / `getSocketFactory(boolean)`** throw
  `IllegalStateException` with the cause instead of returning `null`.
- **`DynamicTrustManager`** extends `X509ExtendedTrustManager` (it no longer extends
  `BaseObject`) and approvals are tied to the host. Approvals saved by 0.1.x still apply to any host.
- **Permissions are stored by name** in `AbstractPrincipal`, so duplicates are ignored and
  `remove()` really revokes. The package-private `permissions` field is now a `Map`.
- **Server runtime values**: setting `null` removes the value, and `setRuntimeValues` copies
  the map it is given.
- **Removed** `Server.getBufferSize()`, `setBufferSize()` and `DEFAULT_BUFFER_SIZE` (never
  used) and the unused `ISession` interface.

### Deprecated

Misspelled names have correctly spelled replacements. The old names still work in 1.x and
will be removed in 2.0.

| Deprecated | Use |
|---|---|
| `IPrincipal.getPermisssions()` | `getPermissions()` |
| `ICommandResponse.readResonse()` | `readResponse()` |
| `ICommandClient` / `IRequestContext` `getSeperator()`, `setSeperator()` | `getSeparator()`, `setSeparator()` |
| `DefaultRequestContext.getDefaultSeperator()`, `setDefaultSeperator()` | `getDefaultSeparator()`, `setDefaultSeparator()` |
| `Server.getServerGreating()`, `setServerGreating()` | `getServerGreeting()`, `setServerGreeting()` |
| `IServer.AUTHENTICATOION_PROVIDER_PROPERTY` | `AUTHENTICATION_PROVIDER_PROPERTY` |
| `REPLY_300_GENERIC_TEMPOARY_OK`, `REPLY_400_GENERIC_TEMPOARY_ERROR` | `REPLY_300_GENERIC_TEMPORARY_OK`, `REPLY_400_GENERIC_TEMPORARY_ERROR` |
| `Server.DEFAULT_MAX_IDEL_CONNECTION` | `DEFAULT_MAX_IDLE_CONNECTION` |
| `CertificateValidotorDialog` | `CertificateValidatorDialog` |

In 1.x, classes that implement `IPrincipal` or `ICommandResponse` still implement the old
method (`getPermisssions`, `readResonse`); the new one is a default method that calls it.

### Added

- `Server.startAndWait(timeout)` and `getStartupError()`: a server that can't start (port in
  use, bad key store or password, missing factories) is reported instead of only logged.
- `Server.setMaxClients()` and `setServerBusyMessage()` to limit concurrent connections.
- `Server.setConnectionTimeout()`, `setMaxIdleConnection()`, `getLocalPort()` (useful with
  port 0), `setReuseAddress()`, `setBacklog()`, `setTcpNoDelay()`.
- `MultiLineCommandResponse` for FTP / SMTP style `250-` replies.
- `Client.getLastConnectError()`, `setConnectTimeout()`, `setTrustAllCertificates()`,
  `setVerifyHostname()`, `setTcpNoDelay()`, `Client.setDefaultReadTimeout()`, and the
  `readTimeout` / `connectTimeout` properties.
- Hashed passwords for `FileBasedAcl` / `PropertyAuthenticator`: `FileBasedAcl.hashPassword()`
  (or its `main()`) creates a salted PBKDF2 value to put in the password field.
- `IAccessControlList.authenticateUnknownUser()` so logins for unknown users take as long as
  real ones.
- `DynamicTrustManager.removeTrusted(host)` and `CertificateValidator.validate(cert, host)`;
  `CertificateValidatorDialog` shows the host.
- `Connection.setMaxLineLength()` / `setDefaultMaxLineLength()`.
- A javadoc jar is published with the sources jar.

### Fixed

- Thread safety: the server's client list and runtime values, lazily created access control,
  and `DynamicTrustManager`'s approvals are safe to use from many connections at once.
- Sessions that switched to TLS were never removed from the server's client list, and one bad
  entry stopped idle connections from being closed. Idle connections are now also closed when
  the server is quiet.
- The accept thread no longer writes the greeting or runs TLS handshakes, so one slow client
  can't stop new connections; a failed hand off closes the socket; an unexpected error no
  longer stops the server.
- A user who isn't logged in gets "not authorized" instead of a dropped connection.
- `negotiateSecureSocket()` works on the client side (it was hard coded to server mode), checks
  "already secure" before touching the live TLS socket, and only switches the socket factory
  after a successful handshake. A client that reconnects after STARTTLS starts in plain text.
- Connections accepted by a TLS server socket report `isSecure()`, so STARTTLS on them is refused.
- `Server.getSSLContext(String)` ignored the requested protocol.
- `AbstractPrincipal.setParameters()` cleared the caller's map and left the principal unchanged.
- Plain text passwords are compared in constant time, and the user file is read as UTF-8.
- A malformed reply code gives a `500` response instead of `NumberFormatException`.
- The key store file is closed after loading; `DynamicTrustManager` saves its file atomically.

### Upgrading from 0.1.x

1. Change the dependency to `bjl_net_framework` 1.0.0 (it brings `bjl_core` and `bjl_io` 1.0.0).
2. Clients connecting to servers with self-signed certificates: add the certificate to the JVM
   trust store, set a `CertificateValidator` (for example `VisualCertificateValidator`) with
   `DynamicTrustManager.setDefaultValidator()`, or call `setTrustAllCertificates(true)`.
3. If commands legitimately wait longer than the new timeouts, or read lines longer than
   64 KiB, raise the limits (see Breaking changes).
4. Replace deprecated names; your IDE lists them as warnings.
5. Remove calls to `Server.getBufferSize()` / `setBufferSize()` and uses of `ISession`.
