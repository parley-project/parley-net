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
- Depends on [`parley-core`](https://github.com/tony-bringardner/parley-core) and
  [`parley-io`](https://github.com/tony-bringardner/parley-io)
- Apache License 2.0

## Installation

parley-net is part of **Parley**, a family of Java libraries for implementing internet
protocols. It is published to GitHub Packages (and, once released there, Maven Central):

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

GitHub Packages needs authentication even for public packages. Add the repositories
(this project and its two dependencies) to your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/tony-bringardner/parley-net</url>
    </repository>
    <repository>
        <id>github-core</id>
        <url>https://maven.pkg.github.com/tony-bringardner/parley-core</url>
    </repository>
    <repository>
        <id>github-io</id>
        <url>https://maven.pkg.github.com/tony-bringardner/parley-io</url>
    </repository>
</repositories>
```

Then add a matching `<server>` for each id to `~/.m2/settings.xml`, with your GitHub user name
and a token that has the `read:packages` scope.

## How it fits together

| Server side | |
|---|---|
| `Server` | Accepts connections and starts one processor thread per client. |
| `IConnectionFactory` → `Connection` | Wraps each socket; reads and writes lines (CR LF or LF). |
| `IProcessorFactory` → `AbstractCommandProcessor` | Reads a line, finds the command, checks permission, runs it. |
| `ICommandFactory` → `ICommand` | Your protocol: one `ICommand` per command. |
| `IAccessControlList` (`FileBasedAcl`, `PropertyAuthenticator`) | Users, passwords and permissions. |

| Client side | |
|---|---|
| `CommandClient` | Connects, sends a command, reads the reply. |
| `SingleCommandResponse` / `MultiLineCommandResponse` | Parse `250 text` or `250-...` / `250 last` replies. |
| `DynamicTrustManager` | Decides which server certificates to trust. |

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

(or the `KeyStoreName`, `KeyStoreType` and `KeyStorePassword` properties). The client
connects with a TLS socket factory: `client.setSocketFactory(sslContext.getSocketFactory())`.

**STARTTLS.** Return a server `SSLContext` from your `Connection.getSSLContext()`, and write
a command that replies and then calls `processor.getConnection().negotiateSecureSocket("TLS")`.
The client sends that command, then calls `client.negotiateSecureSocket("TLS")`.
A connection that is already secure refuses a second negotiation.

**Which server certificates the client trusts.** By default: the JVM trust store, and the
certificate must match the host name. For self-signed certificates either

- set a `CertificateValidator` with `DynamicTrustManager.setDefaultValidator(...)`. It is asked
  about unknown certificates and can accept once or always. `VisualCertificateValidator` asks the
  user in a dialog. Approvals are stored in `~/.bjlTructed` and apply only to that host;
- or give the client your own trust managers with `client.setContext(...)`;
- or, for testing only, `client.setTrustAllCertificates(true)`.

`client.setVerifyHostname(false)` turns off only the host name check.

## Authentication and permissions

Set an `IAccessControlList` with `server.setAccessControl(...)`, or name the class in the
`AuthenticationProvider` property (`IServer.AUTHENTICATION_PROVIDER_PROPERTY`).
`FileBasedAcl` reads users from the file named by the `<server name>.userFile` property;
`PropertyAuthenticator` reads them from `<server name>.user0`, `.user1`, ... properties.
Each user is one line:

```
# name,  password,         permissions,   parameters
alice,   {PBKDF2}210000:..., ECHO|LOGIN,  home=/home/alice
```

Store hashed passwords rather than plain text. Create the hash with

```
java -cp parley-net-1.0.0.jar:parley-core-1.0.0.jar us.bringardner.parley.net.server.FileBasedAcl 'the password'
```

A login command calls `processor.getServer().authenticate(user, password)` and
`processor.setPrincipal(...)`. Commands whose `requiresAuthorization()` is true then run only
if the principal has the command's permission; otherwise the client gets "not authorized".

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

`ServerSaslAuthenticator` checks PLAIN and LOGIN against the server's access control list. The
other mechanisms need what a password hash can't give: the clear password (CRAM-MD5) or
`ScramCredentials` made once with `ScramMechanism.deriveCredentials`. Implement
`ISaslAuthenticator` over your own store for those. Clients use the mechanism's `client(...)`
factory and `evaluateChallenge` for each server challenge.

## Non-blocking (NIO)

*Preview: the API may still change.*

The `us.bringardner.parley.net.nio` package serves many connections from a few selector
threads instead of a thread per connection. Nothing blocks: input arrives as frames, writes are
queued.

| | |
|---|---|
| `NioServer` | Accepts on a non-blocking channel and hands connections to its `NioReactor`s. An `AbstractCoreServer`, so the usual properties (Port, MaxConnections, key store...) configure it. |
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

For request / response protocols (FTP, SMTP, POP3) the blocking `Server` is simpler, and with
virtual threads (Java 21+) it serves many idle sessions just as cheaply.

## Configuration

| Setting | Default | Where |
|---|---|---|
| Server read time-out | 60 s | `Server.setConnectionTimeout(ms)`, 0 = none |
| Idle connections closed after | 24 h | `Server.setMaxIdleConnection(ms)` |
| Maximum concurrent clients | unlimited | `Server.setMaxClients(n)`, `setServerBusyMessage("421 ...")` |
| Longest line | 64 KiB | `Connection.setDefaultMaxLineLength(n)` or `setMaxLineLength(n)`, 0 = none |
| Client read time-out | 5 min | `client.setTimeout(ms)`, `Client.setDefaultReadTimeout(ms)`, or the `readTimeout` property |
| Client connect time-out | 30 s | `client.setConnectTimeout(ms)` or the `connectTimeout` property |
| TCP_NODELAY | on | `setTcpNoDelay(false)` on `Server` or `Client` |
| SO_REUSEADDR | on | `Server.setReuseAddress(false)` |

Properties are looked up with `BaseObject.getProperty` from `parley-core`: first
`<fully qualified class name>.<name>`, then `<name>`, as system properties or in class-named
`.properties` files on the class path.

## Building

```
mvn test      # unit and socket tests; coverage report in target/site/jacoco/index.html
mvn package   # jar, sources jar and javadoc jar
```

See [CHANGELOG.md](CHANGELOG.md) for changes, including upgrading from 0.1.x.
