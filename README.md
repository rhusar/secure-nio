# Secure NIO

[![Maven](https://github.com/rhusar/secure-nio/actions/workflows/maven.yml/badge.svg)](https://github.com/rhusar/secure-nio/actions/workflows/maven.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

> Drop-in TLS- and DTLS-secured implementations of the JDK NIO channel API – SocketChannel, ServerSocketChannel, DatagramChannel, and Selector wrappers powered by SSLEngine, with zero dependencies.

Secure NIO lets existing NIO code speak TLS with minimal changes:
channels are decorated rather than replaced, all `SSLEngine` mechanics (handshaking, encryption, decryption, delegated tasks) are handled internally,
and both blocking and non-blocking selector-driven I/O are supported.
The library has no runtime dependencies.

## Components

| Class | Description |
|---|---|
| `SecureSocketChannel` | A `SocketChannel` decorator that transparently encrypts writes and decrypts reads. Non-I/O operations are delegated to the underlying raw channel. |
| `SecureServerSocketChannel` | A `ServerSocketChannel` decorator that produces `SecureSocketChannel` instances (with server-mode `SSLEngine`s from a supplied `SSLContext`) for each accepted connection. |
| `SecureDatagramChannel` | A `DatagramChannel` decorator that transparently encrypts and decrypts datagrams with DTLS. Operates in connected mode only – one DTLS session per peer pair. |
| `DelegatingSelectorProvider` | A `SelectorProvider` that opens `Selector`s capable of registering the TLS/DTLS-wrapped channels above, transparently unwrapping them to the raw channel on registration. |

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.rhusar.securenio</groupId>
    <artifactId>secure-nio</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Usage

### Server side

```java
SSLContext sslContext = ...; // initialized with your key material
ExecutorService taskExecutor = Executors.newCachedThreadPool(); // runs SSLEngine delegated tasks

ServerSocketChannel rawServer = ServerSocketChannel.open();
SecureServerSocketChannel server = new SecureServerSocketChannel(rawServer, sslContext, taskExecutor);
server.bind(new InetSocketAddress(8443));

SocketChannel channel = server.accept(); // returns a SecureSocketChannel
```

### Client side

```java
SocketChannel rawChannel = SocketChannel.open();
SSLEngine engine = sslContext.createSSLEngine();
engine.setUseClientMode(true);

SecureSocketChannel channel = new SecureSocketChannel(rawChannel, engine, taskExecutor);
channel.connect(new InetSocketAddress("example.com", 8443));
```

Once connected, use `read(ByteBuffer)` and `write(ByteBuffer)` as with any `SocketChannel` – the TLS handshake is driven transparently as a side effect of reading and writing.

### Non-blocking I/O with a Selector

Secure channels cannot be registered directly with a system selector (because the JDK's `SelectorImpl` requires its own internal channel types).
Use `DelegatingSelectorProvider`, which unwraps the secure channel on registration:

```java
DelegatingSelectorProvider provider = new DelegatingSelectorProvider();
Selector selector = provider.openSelector();

channel.configureBlocking(false);
channel.register(selector, SelectionKey.OP_READ);
```

Alternatively, register the raw channel with a regular selector and attach the secure channel to the key:

```java
SelectionKey key = channel.delegate().register(selector, SelectionKey.OP_READ);
key.attach(channel);
```

See [`TLSLoopbackTestCase`](impl/src/test/java/io/github/rhusar/securenio/channels/TLSLoopbackTestCase.java) for a complete end-to-end example:
a non-blocking client and server exchanging data over TLS.

### DTLS over UDP

`SecureDatagramChannel` secures unicast UDP with DTLS 1.2 using the JDK's DTLS `SSLEngine`.
The channel operates in connected mode only:
the DTLS session is bound to a single peer, so the underlying channel must be connected before any secure I/O (`disconnect()` and multicast `join` are unsupported).

```java
SSLContext sslContext = SSLContext.getInstance("DTLS");
sslContext.init(keyManagers, trustManagers, null);

DatagramChannel rawChannel = DatagramChannel.open();
rawChannel.bind(new InetSocketAddress(0));
rawChannel.connect(peerAddress);

SSLEngine engine = sslContext.createSSLEngine();
engine.setUseClientMode(true); // or false on the accepting side

SecureDatagramChannel channel = new SecureDatagramChannel(rawChannel, engine, taskExecutor);
```

Datagram semantics are preserved:
* each `write(ByteBuffer)` produces one DTLS-protected datagram,
* each `read(ByteBuffer)` delivers the plaintext of at most one received datagram,
* and plaintext exceeding the caller's buffer is discarded just as with a plain `DatagramChannel`.
The handshake is driven transparently as a side effect of reading and writing;
* while it is in progress, writes consume nothing and simply advance the handshake.

Two DTLS-specific caveats:

* Retransmission – UDP loses packets and the JDK's DTLS engine has no timer,
so a lost handshake flight must be re-sent by the application:
when no progress is observed within a select timeout while `isHandshaking()` returns `true`, call `retransmit()` to re-send the last flight.
The `close_notify` alert sent on `close()` is likewise a single datagram delivered best-effort.
* Path MTU: To avoid IP fragmentation, constrain the datagram size via `SSLParameters.setMaximumPacketSize(...)` (for example `1432` for Ethernet-sized MTUs) on the engine before constructing the channel.

See [`DTLSLoopbackTestCase`](impl/src/test/java/io/github/rhusar/securenio/channels/DTLSLoopbackTestCase.java) for a complete end-to-end example, including handshake recovery from packet loss.

## Building

```sh
mvn clean verify
```

Requires Maven (or use Maven Wrapper scripting) and JDK 17 or higher.
The build generates a self-signed test keystore automatically for testing, so no manual setup is required.

Continuous integration runs on [GitHub Actions](https://github.com/rhusar/secure-nio/actions).

## Reporting Issues

Please report bugs and feature requests via [GitHub Issues](https://github.com/rhusar/secure-nio/issues).

## License

[Apache License 2.0](LICENSE)
