# parley-net

A small Java framework for writing both ends of line based network protocols such as
FTP, SMTP or POP3: a client sends a command line, the server answers with a reply code
and text.

The framework handles the sockets, threads, TLS (from the first byte or with STARTTLS),
authentication, time-outs and limits. You write the commands.

For protocols that don't take turns (both ends send at any time, or many channels share one
connection, such as SSH), the `nio` package has a non-blocking server and client: see
[Non-blocking (NIO)](#non-blocking-nio).

- Java 11 or later
- Depends on [`parley-core`](https://github.com/parley-project/parley-core) and
  [`parley-io`](https://github.com/parley-project/parley-io)
- Apache License 2.0

## Installation

parley-net is part of **Parley**, a family of Java libraries for implementing internet
protocols. It is on Maven Central, so no extra repository is needed:

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-net</artifactId>
    <version>1.0.0</version>
</dependency>
```

> parley-net was previously `us.bringardner:bjl_net_framework` (BjlNetFramework), with
> packages under `us.bringardner.net.framework`. Moving over means changing the dependency and
> replacing `us.bringardner.net.framework` with `us.bringardner.parley.net` in imports and in
> property names that start with a class name.

## How it fits together

| Server side | |
|---|---|
| `Server` | Accepts connections and starts one processor thread per client. |
| `IConnectionFactory` → `Connection` | Wraps each socket; reads and writes lines (CR LF or LF). |
| `IProcessorFactory` → `AbstractCommandProcessor` | Reads a line, finds the command, checks permission, runs it. |
| `ICommandFactory` → `ICommand` | Your protocol: one `ICommand` per command. |
| parley-iam's `UserRegistry` (`FileUserRegistry`, `PropertiesUserRegistry`) | Users, passwords, groups and permissions. |

| Client side | |
|---|---|
| `CommandClient` | Connects, sends a command, reads the reply. |
| `SingleCommandResponse` / `MultiLineCommandResponse` | Parse `250 text` or `250-...` / `250 last` replies. |
| `DynamicTrustManager` | Decides which server certificates to trust. |
| `UpstreamHealth` | Tracks one upstream server (a name server, a relay, a mirror): smoothed response time, hold-off after repeated failures, probing when all are down. |

| Both | |
|---|---|
| `FatalErrorHandler` | Logs errors that kill a thread; on a JVM error (`OutOfMemoryError`) halts the process so a supervisor restarts it. |

## A minimal echo server and client

```java
ICommand echo = new ICommand() {
    public String getName()            { return "ECHO"; }
    public IPermission getPermission() { return new Permission("ECHO"); }
    public boolean requiresAuthorization() { return false; }
    public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
        processor.reply(REPLY_200_GENERIC_OK, context.getRemainingTokens());
    }
};

Server server = new Server(2525, "EchoServer");
server.setServerGreeting("220 Echo server ready");
server.setConnectionFactory(socket -> new Connection(socket, true) {   // true = CR LF lines
    @Override
    public SSLContext getSSLContext(String protocol) throws IOException {
        return null;   // no STARTTLS in this example
    }
});
server.setProcessorFactory(() -> new AbstractCommandProcessor() {
    @Override
    public String translateResponseCode(int code) {
        return String.valueOf(code);
    }

    @Override
    public ICommandFactory getCommandFactory() {
        return context -> "ECHO".equalsIgnoreCase(context.getNextToken()) ? echo : null;
    }
});
server.startAndWait(5000);   // throws if the server can't start (port in use, bad key store...)
```

```java
try (CommandClient client = new CommandClient("localhost", 2525)) {
    if (!client.connect()) {
        throw client.getLastConnectError();
    }
    System.out.println(client.readLine());               // the greeting
    ICommandResponse reply = client.executeCommand("ECHO", "hello", "world");
    if (reply.isPositive()) {
        System.out.println(reply.getResponseText());     // hello world
    }
}
```

`TestNetFramework` and `TestNetFrameworkWithPropertyAuth` in `src/test` are complete,
runnable versions of this, the second with a login command and permissions.

Unknown commands get a `500` reply, and so does a command that throws a `RuntimeException`;
the session carries on. Only an I/O error ends a session.

## TLS

**TLS from the first byte.** Give the server a key store and call `setSecure(true)`:

```java
server.setSecure(true);
server.setKeyStoreFileName("/server.p12");   // class path resource or file
server.setKeyStoreType("PKCS12");
server.setKeyStorePassword(password);
```

(or the `keyStoreName`, `keyStoreType` and `keyStorePassword` properties). The client
connects with a TLS socket factory: `client.setSocketFactory(sslContext.getSocketFactory())`.

**STARTTLS.** Return a server `SSLContext` from your `Connection.getSSLContext()`, and write
a command that replies and then calls `processor.getConnection().negotiateSecureSocket("TLS")`.
The client sends that command, then calls `client.negotiateSecureSocket("TLS")`.
A connection that is already secure refuses a second negotiation.

**Which server certificates the client trusts.** By default: the JVM trust store, and the
certificate must match the host name. For self-signed certificates either

- set a `CertificateValidator` with `DynamicTrustManager.setDefaultValidator(...)`. It is asked
  about unknown certificates and can accept once or always. `VisualCertificateValidator` asks the
  user in a dialog. Approvals are stored in `~/.parley/trusted-certificates` (or the file the system property
  `parley.net.client.trustFile` names) and apply only to that host;
- or give the client your own trust managers with `client.setContext(...)`;
- or, for testing only, `client.setTrustAllCertificates(true)`.

`client.setVerifyHostname(false)` turns off only the host name check.

## Authentication and permissions

Users, credentials and permissions are parley-iam's types (`UserRegistry`, `Credential`,
`ParleyPrincipal`, `ParleyPermission`, `Requester`). Give a server a registry with
`server.setUserRegistry(...)`, or name the class in the `authenticationProvider` property
(`IBaseServer.AUTHENTICATION_PROVIDER_PROPERTY`). The server makes it with the class's public
constructor that takes an `IBaseServer` when it has one (so it can read the server's settings),
otherwise with the no-argument one. `FileUserRegistry` reads users from the file named by the
`<property prefix>.userFile` property (for example `parley.mail.pop3.userFile`); `PropertiesUserRegistry`
reads them from `<property prefix>.user0`, `.user1`, ... properties. The prefix is the server's
`getPropertyPrefix()`: the name given to `new Server(port, name)` (or `NioServer`), or the one a Parley
server sets, such as `parley.mail.pop3`. Each user is one line:

```
# name,  password,         permissions,   parameters
alice,   {PBKDF2}210000:..., ECHO|LOGIN,  home=/home/alice
```

The permissions are held on the server as a whole; the parameters are the principal's attributes.
The file has no ids, so a user's id is `user:` and its name (a group's, `group:` and its name):
renaming someone in the file makes a new principal.

Store hashed passwords rather than plain text. Create the hash with

```
java -cp parley-net-2.0.0.jar:parley-core-2.0.0.jar:parley-iam-2.0.0.jar us.bringardner.parley.net.server.FileUserRegistry 'the password'
```

For SCRAM logins, `FileUserRegistry --scram 'the password'` prints the hash followed by SCRAM
credentials (`{PBKDF2}...;{SCRAM-SHA-256}...;{SCRAM-SHA-1}...`); paste the whole value into the
password field (and replace the whole field when the password changes: SCRAM credentials left from
the old password would still let it in). A plain text password serves SCRAM as it is. The registry offers
SCRAM (`supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256)`) only when every user in the
file can use it, because a client that picks SCRAM can't fall back to a password for a user who has no
SCRAM credentials.

`FileUserRegistry` notices when its file changes (`initialize(File)` reads a file without a property naming it)
(checked at most every 15 seconds, set by `parley.net.acl.reloadInterval`, a duration such as `15s`; 0 turns it
off) and reads it again, so users added or removed take effect without a restart. A file that can't be read keeps
the users it had.

A user's groups are a `groups=` parameter, separated by `;`
(`tony@bringardner.us, {PBKDF2}..., READ|WRITE, groups=sales@bringardner.us;support@bringardner.us`);
`registry.findGroups(principal)` returns them.

A principal holds no secrets: the registry checks passwords, and hands out a stored secret only for a
proof the server runs (SCRAM credentials, and the plain text password for POP3's APOP, which works
only for users whose password is kept in plain text).

A registry is closed by whoever made it (`UserRegistry` is `Closeable`; the default `close()` does nothing): a
server closes the registry it made from `authenticationProvider` when it stops, and makes a new one if it starts
again; a registry given with `setUserRegistry` is yours to close once the server is done with it.

A session logs in only through `processor.authenticate(credential)` (`INioConnection.authenticate` for NIO),
with a credential made with `processor.getRequester()`:

```java
AuthenticationResult result = processor.authenticate(
    new PasswordCredential(user, password.toCharArray(), processor.getRequester()));
```

The result is AUTHENTICATED (the session is now logged in), REFUSED, UNSUPPORTED, or UNAVAILABLE when the
registry can't answer now (answer "try again later", without counting a failed login). `logout()` logs the
session out. A challenge and response (APOP, SSH keys) is a `ProofCredential` with the protocol's
`ProofVerifier` (`ApopVerifier` for APOP); the server gets the stored secret, runs the verifier without
holding the registry, looks the principal up and tells the registry the outcome. Commands whose
`requiresAuthorization()` is true run only when `checkPermission(command.getPermission(), null)` allows it
(the registry's `checkPermission` answers; the server never compares permissions itself). A denial is
answered "not authorized" (`replyNotAuthorized`), and a registry that can't answer now gets a temporary error
(`replyPermissionUnavailable`). Logging in or checking a permission with no registry is an
`IllegalStateException` naming the `authenticationProvider` setting.

The server applies the login limits itself. A refused login is answered only after `loginFailureDelay`
(1 second by default), a successful one starts the count again, and an unavailable registry isn't counted.
After `maxLoginAttempts` refusals (3 by default) the connection is closed once the reply to the last one has
gone; a protocol adds a closing line of its own by overriding `replyTooManyLoginFailures()` (or
`INioHandler.onTooManyLoginFailures` on a non-blocking server, which holds the reply instead of sleeping).
A connection nobody has logged in to within `loginTimeLimit` (none by default) is closed.

## Session state, capabilities and SASL

Three things nearly every line protocol needs are shared here, so each protocol only says
what is particular to it.

**Session state.** Define the states as an enum, return a `StateMachine` from
`AbstractCommandProcessor.getStateMachine()`, and have commands implement `IStatefulCommand`
to declare where they are valid. A command used in the wrong state is answered by
`replyInvalidState` (a generic 500 unless you override it) and never runs. Commands change the
state with `moveTo`, and `allow(from, to...)` lists the legal moves if you want them enforced.

**Capabilities.** `CapabilityRegistry` holds what the server offers and the conditions for
offering it; `resolve(processor)` gives a `CapabilitySet` for the session, which renders as
lines (`toLines()`, for EHLO, CAPA and FEAT) or one line (`toInline()`, for IMAP). A client
reads the same shape with `CapabilitySet.parseReply(reply, skipFirst, skipLast)`,
`parseLines` or `parseInline`, and tests it with `has("AUTH", "PLAIN")`.

**SASL.** `SaslMechanisms.standard(host)` lists SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5, PLAIN,
LOGIN and XOAUTH2; `offered(authenticator, tls)` gives the names to advertise, leaving out the
ones that send the secret in the clear unless the connection uses TLS. An `AUTH` command
finds the mechanism and runs it:

```java
ISaslMechanism mech = mechanisms.find(mechanismName);
SaslOutcome out = SaslServerDriver.authenticate(mech, authenticator, initialResponseOrNull,
    new ISaslChannel() {
        public void sendChallenge(String base64) throws IOException { processor.reply("334 " + base64); }
        public String readResponse() throws IOException { return connection.readLine(); }
    });
if (out.isSuccess()) { /* out.getUser() is who it is */ }
```

`ServerSaslAuthenticator` checks PLAIN and LOGIN against the server's user registry, and
serves SCRAM-SHA-1 and SCRAM-SHA-256 when the registry keeps SCRAM credentials for every user. Make it
with the session (`new ServerSaslAuthenticator(server, processor)`) and it logs the session in through
the session's `authenticate`. SCRAM proves the user without a password check, so on success call
`authenticator.verified(out.getUser())`, which goes through the same door. Make SCRAM credentials once with `ScramMechanism.SHA_256.newCredentials(password)` and
keep `credentials.format()`; `ScramCredentials.parse` reads it back. CRAM-MD5 needs the clear
password, which a hash can't give: implement `ISaslAuthenticator` over your own store for it.
Clients use the mechanism's `client(...)` factory and `evaluateChallenge` for each server
challenge.

## Non-blocking (NIO)

The `us.bringardner.parley.net.nio` package serves many connections from a few selector
threads instead of a thread per connection. Nothing blocks: input arrives as frames, writes are
queued.

| | |
|---|---|
| `NioServer` | Accepts on a non-blocking channel and hands connections to its `NioReactor`s. An `AbstractCoreServer`, so the usual properties (port, maxConnections, key store...) configure it. Like `Server` it is an `IBaseServer` (property prefix, port, life cycle, access control), so code such as `ServerMain.service` takes either one. |
| `NioClient` | Non-blocking connects (`connect` returns a `CompletableFuture`, or `connectAndWait`). |
| `INioHandlerFactory` → `INioHandler` | Your protocol: `onConnect`, `onMessage`, `onIdle`, `onError`, `onClose`. One call at a time per connection. |
| `IFrameDecoder` | Splits the input: `LineFrameDecoder`, `LengthFieldFrameDecoder`, `RawFrameDecoder`, or your own. A handler can switch decoders between frames. |
| `INioConnection` | `write`, `closeAfterFlush`, `startTls`, `pauseReading` / `resumeReading`, the logged in principal, attributes. |

```java
NioServer server = new NioServer(2222, "echo");
server.setDecoderFactory(LineFrameDecoder::new);
server.setHandlerFactory(() -> (connection, frame) ->
        connection.writeLine("echo " + LineFrameDecoder.toString(frame)));
server.startAndWait(5000);
```

Handlers run on the reactor threads, so they must not block; give the server a handler executor
(`setHandlerExecutor`) when they do (file I/O, password hashing...). TLS uses the same
`SecureBaseObject` settings as `Server`: `setSecure(true)` for TLS from the first byte, or
`connection.startTls()` after a STARTTLS style command. `NioServer.authenticate()` uses the same
access control list as `Server`.

**Time limits.** The idle time (`setMaxIdleTime`) closes connections with no traffic, but any byte
resets it, so it can't stop a client that sends a frame one byte at a time. `setFrameTimeout(ms)`
does: once a frame has started it must arrive within that time (for TLS, also each record and the handshake). Time the connection spends waiting on its own handler (reading paused, input buffer full) doesn't count. For anything else that must happen
in time whatever the traffic (logging in, say), a handler sets `connection.setDeadline(ms)`;
`onDeadline` is called when it passes (the default closes the connection) and `clearDeadline()`
cancels it. Both are checked about once a second.

**A channel you bound yourself.** `setServerChannel(channel)` serves an already bound
`ServerSocketChannel` (when the caller needs the port before the server runs, or was handed the
channel) instead of opening one on port / bindAddress; the server closes it when it stops.

For request / response protocols (FTP, SMTP, POP3) the blocking `Server` is simpler, and with
virtual threads (Java 21+) it serves many idle sessions just as cheaply.

## Upstream servers and fatal errors

`client.UpstreamHealth` is for a client that picks among several servers. Call `started()` before a
request and `succeeded(start)` or `failed(start)` after it. Each server keeps a smoothed response time
(a failure counts as a slow answer) and, after more than `maxTries` failures in a row, is held off for
`minHoldOff` ms, doubling up to `maxHoldOff`; any answer ends the hold-off. `timeoutFor(remaining)`
gives a timeout of about twice the response time. `UpstreamHealth.order(servers, health, rotation)`
sorts servers fastest first (untried ones first, so they get measured), and when every server is held
off, `soonest(servers, health)` plus `tryProbe()` lets one through at most once per `probeInterval`, so
recovery follows the servers, not the hold-off timer. The limits come from a `Policy`
(`UpstreamHealth.SimplePolicy` has setters).

`FatalErrorHandler.install(true)` in a server's `main()` logs any error that kills a thread and, on a
`VirtualMachineError`, stops the process at once (`Runtime.halt(1)`) for the supervisor (systemd,
launchd, a container runtime) to restart. `install(false)` only logs, for applications that embed a
server; `getThreadDeaths()` counts them.

## Locks for servers

Servers that share stores (several IMAP servers on one database, say) need locks that reach each other, and
threads of one server need to wait their turn for a mailbox or a queue entry. `us.bringardner.parley.net.lock`
provides both, on top of parley-files.

```java
Locks locks = Locks.open(LockOptions.sharing(Sharing.CLUSTER));   // one per JVM
LockDomain mail = locks.domain("mail", mailRoot);                // each store the servers use
StoreClaim claim = mail.claimStore("imap-1");                     // held while the server runs

try (NamedLock l = mail.lock("tony/INBOX", Mode.EXCLUSIVE, Duration.ofSeconds(5))) {
    ... read and change ...
    AtomicWrite.replace(index, l, out -> write(out));             // renamed into place only if still held
}
```

- **Among threads:** first come, first served, with a timeout (`LockTimeoutException`); shared locks admit any
  number of readers, and a writer that waits isn't overtaken by later readers. Reentrant by default, like
  `synchronized` (`request(name).reentrant(false)`, or `LockOptions.withReentrant(false)`, for locks that aren't).
  `Locks.lockAll` takes names in several domains in one order (domain, then name), so callers can't deadlock.
- **Domains:** each store is registered under a name, the same on every server. Lock names are relative to it,
  so servers that mount a store at different paths still agree. A resource on another store (a mounted archive,
  say) is a name in that store's domain.
- **Among servers:** `Sharing` says how many servers use a store: `OFF` (one; its claim keeps a second out),
  `HOST` (several on one machine) or `CLUSTER` (several anywhere). A server in this JVM gets the answer a server
  in another process would: with `OFF` a second one is refused, and sharing servers each claim with an id of
  their own. A *provider* keeps the locks between them:
  - `region`, the liberal one: the store's own locks (FileSource region locks on one file, a one-byte region per
    name). Fast, and a dead server's locks go with it, but only where the store's lock scope reaches every server.
  - `lease`, the conservative one: lease directories, which need only an atomic `mkdir`. Renewed every 10 s and
    taken over when unchanged for a whole lease (30 s), by one server at a time; each reading server has its own
    entry, so readers on several servers share a name. A holder stops trusting its lease a renew interval before
    it runs out (20 s), and never renews it after that, so a server that was paused (a long garbage collection, a
    machine asleep) finds its lock lost instead of renewing it while another server takes it over. Call
    `NamedLock.checkValid()` (or use `AtomicWrite`) before committing. `LockOptions.withLease(lease, renew)`:
    the renew interval is at most a third of the lease.
  - Any other, through `us.bringardner.parley.net.lock.spi.LockProvider`: found with `ServiceLoader` (by its id)
    or named by class.

  The provider comes from `LockOptions.withProvider(...)` or the `parley.net.lock.provider` system property;
  `auto` (the default) chooses from the store's capabilities (`FileSource.getCapabilities()`): `region` where the
  store's lock scope covers the sharing, else `lease`; a provider found with ServiceLoader that has a priority
  above zero comes first.

  | Store (capabilities) | OFF | HOST | CLUSTER |
  |---|---|---|---|
  | local disk (HOST scope) | region | region | lease |
  | PostgreSQL, MySQL (CLUSTER scope) | region | region | region |
  | FTP, SFTP, HSQLDB, memory (PROCESS scope) | lease | lease | lease |

  (With `OFF`, names are locked in the JVM only; the provider keeps the store claim.)
- **Two safety rules.** A provider whose locks wouldn't reach every server (`region` on a store whose scope is
  too narrow) is refused unless `LockOptions.withAllowUnsafe(true)` or `parley.net.lock.allowUnsafe=true`; one
  that can't work there at all is always refused (`LockSetupException`). And every server must keep a store's
  locks the same way: the provider is recorded in the store's `.parley-net-locks` (`provider-<id>`), and a server
  that would use another is refused, with what to do in the message.
- **A coordination store:** `LockOptions.withCoordinationStore(store)` keeps every domain's locks in one store
  every server reaches (a database, say), wherever the data is; the provider is chosen for that store.
- **File servers** (FTP, SFTP): `StoreLocks.get()` keeps this JVM's domains, one per served root, shared by every
  server here. `acquire(root, sharing)` / `release(d)` per server or session; a root inside one already registered
  uses its domain, so nested roots (FTP on `/srv`, SFTP on `/srv/tony`) lock a file under one name,
  `fileLockName(d, file)` (`file/` and its path from the domain's root); `acquireFor(file)` keeps the domain open
  while a file's lock is held. Servers elsewhere reach the same locks when they serve the same root. The lock
  directory is in the root, so servers keep clients out of it (`isLockFile(file)`).
  `NamedLock.closeFromAnyThread()` lets go of a lock whose work ended on another thread (an FTP data transfer).

## Running servers: as a service, alone or together

A server can run in its own process, share a process with other servers, or be run by an
application; nothing assumes the user or group it runs as (the service manager, or whoever starts
it, decides that).

- **Each server is written as if it were alone.** It is made from a configuration of its own and
  reads only that (and its classes' defaults), never the system properties or another server's
  settings, so nothing changes when it shares a process with other servers: two servers can have
  different values for the same name. parley-core's `BaseObject.setConfiguration` / `makeWith` give
  an object its settings (a server's processors and access control list read the same ones); an
  object with no configuration reads the system properties, as when it is alone in its JVM.
- **One process for one protocol's servers.** `ServerMain.run(name, args, configProperty,
  defaultFile, factory)` runs the servers a `main` makes (`ServerMain.service(server, name)` adapts
  any `IBaseServer`) until the process is stopped. Settings: the command line (`-Dname=value` or
  `name value`), the JVM's `-D` options, then the server's settings file (the one its `configFile`
  property names, else `CONF/parley-NAME.properties`), read as system properties. CONF is
  `ServerMain.confDir()`: `/etc/parley` (Windows `%ProgramData%\Parley`), or the folder of the file
  `PARLEY_CONF` names. It exits with 1 when the settings can't be read or a server can't start, and
  when the last running server stops by itself, so a service manager can restart it.
Running several servers of different protocols together, choosing which run, what they share (a
user registry given to each with `setUserRegistry`) and how a failure is handled, is an application's
job, not the framework's. For an example that does (providers found at run time, `parley.servers`,
JMX management, one server never stopping another), see parley-mail-admin.

## Configuration

| Setting | Default | Where |
|---|---|---|
| Server read time-out | 60 s | `Server.setConnectionTimeout(ms)`, 0 = none |
| Idle connections closed after | 24 h | `Server.setMaxIdleConnection(ms)` |
| Maximum concurrent clients | unlimited | `Server.setMaxClients(n)`, `setServerBusyMessage("421 ...")` |
| Connections per client address | unlimited | `setMaxConnectionsPerClient(n)` or the `maxConnectionsPerClient` property (`Server` and `NioServer`) |
| Client addresses allowed | everyone | `setAllowedClients("127.0.0.1 10.0.0.0/8")` or the `allowedClients` property; others are closed at once |
| NIO frame time limit | none | `NioServer.setFrameTimeout(ms)` or the `frameTimeout` property (a duration, `30s`): a frame must arrive within this once it has started |
| Longest line | 64 KiB | `Connection.setDefaultMaxLineLength(n)` or `setMaxLineLength(n)`, 0 = none |
| Client read time-out | 5 min | `client.setTimeout(ms)`, `Client.setDefaultReadTimeout(ms)`, or the `readTimeout` property (a duration, `5m`) |
| Client connect time-out | 30 s | `client.setConnectTimeout(ms)` or the `connectTimeout` property (a duration, `30s`) |
| TCP_NODELAY | on | `setTcpNoDelay(false)` on `Server` or `Client` |
| SO_REUSEADDR | on | `Server.setReuseAddress(false)` |
| Listen address | every address | `setBindAddr(address)` or the `bindAddress` property (`Server` and `NioServer`) |
| Reply to a too-long line | `500 Line too long` | override `AbstractCommandProcessor.replyLineTooLong(max)` for the protocol's own reply; the session then ends |

Each property name in the table is read with the object's property prefix in front of it
(`propertyName(name)` in `parley-core`'s `BaseObject`): `<prefix>.<name>`, where the prefix is the name given
to `new Server(port, name)`, the one a Parley server sets (such as `parley.mail.pop3`), or else the fully
qualified class name. `getProperty` looks that full name up as a system property, then in class-named
`.properties` files on the class path.

## Building

```
mvn test      # unit and socket tests; coverage report in target/site/jacoco/index.html
mvn package   # jar, sources jar and javadoc jar
```

See [CHANGELOG.md](CHANGELOG.md) for changes, including upgrading from 0.1.x.
