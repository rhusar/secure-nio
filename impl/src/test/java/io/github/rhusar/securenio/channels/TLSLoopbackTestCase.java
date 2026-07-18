/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import io.github.rhusar.securenio.channels.spi.DelegatingSelectorProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * End-to-end TLS integration test over loopback using {@link SecureSocketChannel},
 * {@link SecureServerSocketChannel}, and {@link TLSByteChannel} with non-blocking
 * selector-driven I/O.
 *
 * @author Radoslav Husar
 */
public class TLSLoopbackTestCase {

    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
    private static final int HANDSHAKE_TIMEOUT_MS = 10_000;
    private static SSLContext sslContext;
    private static ExecutorService taskExecutor;

    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = TLSLoopbackTestCase.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(is, KEYSTORE_PASSWORD);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        taskExecutor = Executors.newCachedThreadPool();
    }

    @AfterClass
    public static void tearDownClass() {
        taskExecutor.shutdownNow();
    }

    @Test
    public void bidirectionalDataExchange() throws Exception {
        // 64KB payload exercises large data + multiple TLS records
        byte[] clientPayload = new byte[64 * 1024];
        for (int i = 0; i < clientPayload.length; i++) {
            clientPayload[i] = (byte) (i % 127);
        }
        byte[] serverPayload = "Hello from server".getBytes();

        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            // Connect client
            SocketChannel rawClientChannel = SocketChannel.open();
            SSLEngine clientEngine = sslContext.createSSLEngine();
            clientEngine.setUseClientMode(true);
            SecureSocketChannel clientChannel = new SecureSocketChannel(rawClientChannel, clientEngine, taskExecutor);
            clientChannel.configureBlocking(false);
            clientChannel.connect(serverAddress);

            Selector clientSelector = selectorProvider.openSelector();
            clientChannel.register(clientSelector, SelectionKey.OP_CONNECT);

            // Finish client connect
            finishConnect(clientChannel, clientSelector);

            // Accept server side
            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            Iterator<SelectionKey> acceptKeys = acceptSelector.selectedKeys().iterator();
            assertTrue(acceptKeys.hasNext());
            acceptKeys.next();
            acceptKeys.remove();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            Selector serverSelector = selectorProvider.openSelector();
            ((SecureSocketChannel) serverChannel).delegate().register(serverSelector, SelectionKey.OP_READ);
            clientChannel.delegate().register(clientSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            // Perform TLS handshake + data exchange using non-blocking selector-driven I/O
            ByteBuffer clientWriteBuf = ByteBuffer.wrap(clientPayload);
            boolean clientWriteDone = false;
            boolean serverWriteDone = false;
            // Use a small (16-byte) read buffer on the server side to exercise the scratchpad transfer logic
            ByteBuffer smallServerReadBuf = ByteBuffer.allocate(16);
            ByteBuffer serverAccumulated = ByteBuffer.allocate(clientPayload.length);
            ByteBuffer clientReadBuf = ByteBuffer.allocate(1024);

            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;

            while ((!clientWriteDone || !serverWriteDone || clientReadBuf.position() < serverPayload.length || serverAccumulated.hasRemaining())
                    && System.currentTimeMillis() < deadline) {

                // Client I/O
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();

                if (!clientWriteDone) {
                    clientChannel.write(clientWriteBuf);
                    if (!clientWriteBuf.hasRemaining()) {
                        clientWriteDone = true;
                    }
                }

                if (clientReadBuf.position() < serverPayload.length) {
                    int read = clientChannel.read(clientReadBuf);
                    if (read < 0) break;
                }

                // Server I/O — read into small buffer, accumulate
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();

                if (serverAccumulated.hasRemaining()) {
                    smallServerReadBuf.clear();
                    int read = serverChannel.read(smallServerReadBuf);
                    if (read < 0) break;
                    if (read > 0) {
                        smallServerReadBuf.flip();
                        serverAccumulated.put(smallServerReadBuf);
                    }
                }

                if (!serverAccumulated.hasRemaining() && !serverWriteDone) {
                    ByteBuffer writeBuf = ByteBuffer.wrap(serverPayload);
                    int written = serverChannel.write(writeBuf);
                    if (written > 0 && !writeBuf.hasRemaining()) {
                        serverWriteDone = true;
                    }
                }

                Thread.yield();
            }

            serverAccumulated.flip();
            byte[] serverReceived = new byte[serverAccumulated.remaining()];
            serverAccumulated.get(serverReceived);
            assertArrayEquals(clientPayload, serverReceived);

            clientReadBuf.flip();
            byte[] clientReceived = new byte[clientReadBuf.remaining()];
            clientReadBuf.get(clientReceived);
            assertArrayEquals(serverPayload, clientReceived);

            serverChannel.close();
            clientChannel.close();
            clientSelector.close();
            serverSelector.close();
            secureServerChannel.close();
        }
    }

    /**
     * A peer that hits raw end-of-stream (TCP FIN/RST) without first sending a TLS
     * {@code close_notify} alert must be reported as an error, not a clean end-of-stream.
     * Otherwise an active attacker can silently truncate the tail of a message.
     */
    @Test
    public void truncationAttackDetectedOnEof() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            SocketChannel rawClientChannel = SocketChannel.open();
            SSLEngine clientEngine = sslContext.createSSLEngine();
            clientEngine.setUseClientMode(true);
            SecureSocketChannel clientChannel = new SecureSocketChannel(rawClientChannel, clientEngine, taskExecutor);
            clientChannel.configureBlocking(false);
            clientChannel.connect(serverAddress);

            Selector clientSelector = selectorProvider.openSelector();
            clientChannel.register(clientSelector, SelectionKey.OP_CONNECT);
            finishConnect(clientChannel, clientSelector);

            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            acceptSelector.selectedKeys().clear();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            Selector serverSelector = selectorProvider.openSelector();
            ((SecureSocketChannel) serverChannel).delegate().register(serverSelector, SelectionKey.OP_READ);
            clientChannel.delegate().register(clientSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            // Drive a small data exchange to guarantee the TLS handshake has completed.
            byte[] payload = "ping".getBytes();
            ByteBuffer writeBuf = ByteBuffer.wrap(payload);
            ByteBuffer readBuf = ByteBuffer.allocate(payload.length);
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (readBuf.hasRemaining() && System.currentTimeMillis() < deadline) {
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();
                if (writeBuf.hasRemaining()) {
                    clientChannel.write(writeBuf);
                }
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                serverChannel.read(readBuf);
                Thread.yield();
            }
            readBuf.flip();
            byte[] received = new byte[readBuf.remaining()];
            readBuf.get(received);
            assertArrayEquals(payload, received);

            // Simulate the attack: tear down the raw TCP socket beneath the client, emitting a
            // FIN with no preceding TLS close_notify. The server's next read must NOT report a
            // clean end-of-stream.
            rawClientChannel.close();

            ByteBuffer afterTruncation = ByteBuffer.allocate(16);
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            try {
                while (System.currentTimeMillis() < deadline) {
                    serverSelector.selectNow();
                    serverSelector.selectedKeys().clear();
                    int read = serverChannel.read(afterTruncation);
                    if (read < 0) {
                        fail("Server read returned a clean EOF (-1); truncation was not detected");
                    }
                    Thread.yield();
                }
                fail("Server read did not surface a truncation error within the timeout");
            } catch (SSLException expected) {
                // Truncation correctly surfaced as a TLS error.
            }

            serverChannel.close();
            clientChannel.close();
            clientSelector.close();
            serverSelector.close();
            secureServerChannel.close();
        }
    }

    /**
     * A peer that sends the first few bytes of a TLS record and then goes quiet must not pin the
     * server thread. Before the fix, {@code performDecryption} would spin forever on the resulting
     * {@code BUFFER_UNDERFLOW} — a remotely triggerable CPU denial-of-service. The read call must
     * instead return control to the caller so decryption can resume once more data arrives.
     */
    @Test
    public void partialRecordDoesNotBusyLoop() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            SocketChannel rawClientChannel = SocketChannel.open();
            SSLEngine clientEngine = sslContext.createSSLEngine();
            clientEngine.setUseClientMode(true);
            SecureSocketChannel clientChannel = new SecureSocketChannel(rawClientChannel, clientEngine, taskExecutor);
            clientChannel.configureBlocking(false);
            clientChannel.connect(serverAddress);

            Selector clientSelector = selectorProvider.openSelector();
            clientChannel.register(clientSelector, SelectionKey.OP_CONNECT);
            finishConnect(clientChannel, clientSelector);

            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            acceptSelector.selectedKeys().clear();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            Selector serverSelector = selectorProvider.openSelector();
            ((SecureSocketChannel) serverChannel).delegate().register(serverSelector, SelectionKey.OP_READ);
            clientChannel.delegate().register(clientSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            // Drive a small data exchange to guarantee the TLS handshake has completed.
            byte[] payload = "ping".getBytes();
            ByteBuffer writeBuf = ByteBuffer.wrap(payload);
            ByteBuffer readBuf = ByteBuffer.allocate(payload.length);
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (readBuf.hasRemaining() && System.currentTimeMillis() < deadline) {
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();
                if (writeBuf.hasRemaining()) {
                    clientChannel.write(writeBuf);
                }
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                serverChannel.read(readBuf);
                Thread.yield();
            }
            readBuf.flip();
            byte[] received = new byte[readBuf.remaining()];
            readBuf.get(received);
            assertArrayEquals(payload, received);

            // Inject a partial TLS record straight onto the raw socket, bypassing the SSLEngine: the
            // leading bytes of a record header (application_data, TLS 1.2) with no length or body.
            // The server engine cannot complete a record from this and reports BUFFER_UNDERFLOW.
            ByteBuffer partialRecord = ByteBuffer.wrap(new byte[]{0x17, 0x03, 0x03});
            while (partialRecord.hasRemaining()) {
                rawClientChannel.write(partialRecord);
            }

            // Wait until the partial bytes are readable at the server's raw channel, so the read
            // under test is guaranteed to exercise the underflow path rather than an empty socket.
            boolean readable = false;
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (!readable && System.currentTimeMillis() < deadline) {
                serverSelector.selectNow();
                readable = !serverSelector.selectedKeys().isEmpty();
                serverSelector.selectedKeys().clear();
                Thread.yield();
            }
            assertTrue("partial record bytes never arrived at the server", readable);

            // The read must return promptly. Run it on a probe thread so a regression (the infinite
            // busy-loop) surfaces as a timeout failure instead of hanging the whole test suite.
            ByteBuffer dst = ByteBuffer.allocate(16);
            ExecutorService probe = Executors.newSingleThreadExecutor();
            try {
                Future<Integer> future = probe.submit(() -> serverChannel.read(dst));
                int read = future.get(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                // No plaintext can be delivered from an incomplete record.
                assertEquals(0, read);
                assertEquals(0, dst.position());
            } catch (TimeoutException e) {
                fail("read() did not return on a partial TLS record — busy-loop / CPU DoS present");
            } finally {
                probe.shutdownNow();
            }

            serverChannel.close();
            clientChannel.close();
            clientSelector.close();
            serverSelector.close();
            secureServerChannel.close();
        }
    }

    /**
     * A peer that streams records decrypting to zero plaintext (TLS 1.3 {@code NewSessionTicket},
     * {@code KeyUpdate}) must not pin the reading thread. Such records never fill the caller's
     * buffer, so before the fix the decryption loop had no bound at all – it kept consuming them
     * for as long as the peer kept sending, never returning to the selector and starving every
     * other connection served by that thread. {@code MAX_ENGINE_LOOPS} must cap the loop and hand
     * control back. A stub engine that consumes ciphertext without producing plaintext stands in
     * for that record stream, driven by a raw client that keeps the socket fed.
     */
    @Test
    public void zeroPlaintextRecordStreamDoesNotPinThread() throws Exception {
        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             SocketChannel rawClientChannel = SocketChannel.open()) {

            rawServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            rawClientChannel.connect(rawServerChannel.getLocalAddress());
            SocketChannel serverRawChannel = rawServerChannel.accept();

            SSLEngine stubEngine = new ZeroPlaintextSSLEngine(sslContext.createSSLEngine().getSession());
            SecureSocketChannel serverChannel = new SecureSocketChannel(serverRawChannel, stubEngine, taskExecutor);
            serverChannel.configureBlocking(false);

            // The attacking peer: a blocking writer keeps the server's receive buffer fed with raw
            // bytes for the whole probe window, standing in for the sustained record stream.
            AtomicBoolean stopWriter = new AtomicBoolean();
            Thread writer = new Thread(() -> {
                ByteBuffer junk = ByteBuffer.allocate(8192);
                try {
                    while (!stopWriter.get()) {
                        junk.clear();
                        rawClientChannel.write(junk);
                    }
                } catch (IOException ignored) {
                    // The client channel is closed at the end of the test.
                }
            });
            writer.start();

            // The read must return even though data keeps arriving and no plaintext is ever
            // produced. Run it on a probe thread so a regression surfaces as a timeout failure
            // instead of hanging the whole test suite.
            ByteBuffer dst = ByteBuffer.allocate(1024);
            ExecutorService probe = Executors.newSingleThreadExecutor();
            try {
                Future<Integer> future = probe.submit(() -> serverChannel.read(dst));
                int read = future.get(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                assertEquals(0, read);
                assertEquals(0, dst.position());
            } catch (TimeoutException e) {
                fail("read() did not return while the peer streamed zero-plaintext records – engine loop unbounded, thread pinned");
            } finally {
                stopWriter.set(true);
                rawClientChannel.close();
                probe.shutdownNow();
                writer.join(HANDSHAKE_TIMEOUT_MS);
            }

            serverChannel.close();
        }
    }

    /**
     * The engine tolerates records up to twice the spec maximum (~33KB) for interoperability with
     * old buggy TLS stacks, expanding the session's buffer sizes when such a record's header
     * arrives. The channel's internal buffers, sized from the initial session, must be re-grown
     * accordingly. Before the fix they never were: the inbound store filled to its original
     * capacity, every unwrap reported {@code BUFFER_UNDERFLOW}, and each {@code read()} returned 0
     * with the record's tail still pending in the kernel — so a level-triggered selector fires
     * forever without progress, spinning the CPU at 100% (remotely triggerable DoS). With
     * re-growth the record is fully ingested and this garbage one is then rejected by the engine,
     * surfacing an {@link SSLException}.
     */
    @Test
    public void oversizedRecordRegrowsInboundBufferInsteadOfStalling() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector();
             SocketChannel rawClientChannel = SocketChannel.open()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            // A raw (non-TLS) client stands in for the misbehaving peer.
            rawClientChannel.connect(serverAddress);

            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            acceptSelector.selectedKeys().clear();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            // Craft a handshake record whose claimed length exceeds the packet buffer size of the
            // initial session (~16.7KB) but stays within the engine's large-record tolerance
            // (~33KB), followed by a garbage body of that length.
            int claimedLength = 20_000;
            ByteBuffer oversizedRecord = ByteBuffer.allocate(5 + claimedLength);
            oversizedRecord.put((byte) 0x16).put((byte) 0x03).put((byte) 0x01);
            oversizedRecord.putShort((short) claimedLength);
            while (oversizedRecord.hasRemaining()) {
                oversizedRecord.put((byte) 0xFF);
            }
            oversizedRecord.flip();
            while (oversizedRecord.hasRemaining()) {
                rawClientChannel.write(oversizedRecord);
            }

            // The server must ingest the whole record — growing its inbound buffer along with the
            // expanded session size — and then reject the garbage. Before the fix, read() consumed
            // the head of the record and returned 0 forever, never able to fit the rest.
            ByteBuffer dst = ByteBuffer.allocate(1024);
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            try {
                while (System.currentTimeMillis() < deadline) {
                    int read = serverChannel.read(dst);
                    assertEquals("no plaintext can be produced from a garbage record", 0, read);
                    Thread.yield();
                }
                fail("read() never ingested the oversized record — the inbound buffer was not re-grown");
            } catch (SSLException expected) {
                // The record was fully ingested and rejected — no stall.
            }

            serverChannel.close();
            secureServerChannel.close();
        }
    }

    /**
     * A graceful {@link SecureSocketChannel#close()} must transmit a TLS {@code close_notify} alert
     * before tearing down the raw socket. The peer must then observe a clean end-of-stream ({@code -1})
     * rather than a truncation {@link SSLException} — otherwise our own orderly close is indistinguishable
     * from an attack, and (once truncation detection is in place) unusable against a compliant peer.
     */
    @Test
    public void gracefulCloseSendsCloseNotify() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            SocketChannel rawClientChannel = SocketChannel.open();
            SSLEngine clientEngine = sslContext.createSSLEngine();
            clientEngine.setUseClientMode(true);
            SecureSocketChannel clientChannel = new SecureSocketChannel(rawClientChannel, clientEngine, taskExecutor);
            clientChannel.configureBlocking(false);
            clientChannel.connect(serverAddress);

            Selector clientSelector = selectorProvider.openSelector();
            clientChannel.register(clientSelector, SelectionKey.OP_CONNECT);
            finishConnect(clientChannel, clientSelector);

            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            acceptSelector.selectedKeys().clear();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            Selector serverSelector = selectorProvider.openSelector();
            ((SecureSocketChannel) serverChannel).delegate().register(serverSelector, SelectionKey.OP_READ);
            clientChannel.delegate().register(clientSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            // Drive a small data exchange to guarantee the TLS handshake has completed.
            byte[] payload = "ping".getBytes();
            ByteBuffer writeBuf = ByteBuffer.wrap(payload);
            ByteBuffer readBuf = ByteBuffer.allocate(payload.length);
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (readBuf.hasRemaining() && System.currentTimeMillis() < deadline) {
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();
                if (writeBuf.hasRemaining()) {
                    clientChannel.write(writeBuf);
                }
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                serverChannel.read(readBuf);
                Thread.yield();
            }
            readBuf.flip();
            byte[] received = new byte[readBuf.remaining()];
            readBuf.get(received);
            assertArrayEquals(payload, received);

            // Orderly shutdown: this must emit close_notify before the FIN.
            clientChannel.close();

            // The server must observe a clean end-of-stream, not a truncation error.
            ByteBuffer afterClose = ByteBuffer.allocate(16);
            boolean cleanEof = false;
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                int read = serverChannel.read(afterClose);
                if (read < 0) {
                    cleanEof = true;
                    break;
                }
                Thread.yield();
            }
            assertTrue("Server never observed a clean end-of-stream after a graceful close", cleanEof);

            serverChannel.close();
            clientSelector.close();
            serverSelector.close();
            secureServerChannel.close();
        }
    }

    /**
     * When end-of-stream is reached in the same {@code read()} that also delivers buffered plaintext,
     * the byte count must be reported first and the {@code -1} deferred to the next read. Before the fix,
     * {@code decrypt()} returned the last {@code performDecryption} result (-1 on EOF) even after copying
     * bytes into the caller's buffer, so a caller obeying the {@link java.nio.channels.ReadableByteChannel}
     * contract would discard the tail of the stream — silent data loss.
     */
    @Test
    public void noDataLossWhenEofCoincidesWithBufferedPlaintext() throws Exception {
        // Payload larger than the tiny server read buffer, so decrypted plaintext must be drained across
        // several reads and residual is guaranteed to still be pending when end-of-stream arrives.
        byte[] payload = new byte[200];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 127);
        }

        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (ServerSocketChannel rawServerChannel = ServerSocketChannel.open();
             Selector acceptSelector = selectorProvider.openSelector()) {

            SecureServerSocketChannel secureServerChannel = new SecureServerSocketChannel(rawServerChannel, sslContext, taskExecutor);
            secureServerChannel.configureBlocking(false);
            secureServerChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

            InetSocketAddress serverAddress = (InetSocketAddress) secureServerChannel.getLocalAddress();
            secureServerChannel.register(acceptSelector, SelectionKey.OP_ACCEPT);

            SocketChannel rawClientChannel = SocketChannel.open();
            SSLEngine clientEngine = sslContext.createSSLEngine();
            clientEngine.setUseClientMode(true);
            SecureSocketChannel clientChannel = new SecureSocketChannel(rawClientChannel, clientEngine, taskExecutor);
            clientChannel.configureBlocking(false);
            clientChannel.connect(serverAddress);

            Selector clientSelector = selectorProvider.openSelector();
            clientChannel.register(clientSelector, SelectionKey.OP_CONNECT);
            finishConnect(clientChannel, clientSelector);

            acceptSelector.select(HANDSHAKE_TIMEOUT_MS);
            acceptSelector.selectedKeys().clear();
            SocketChannel serverChannel = secureServerChannel.accept();
            assertTrue(serverChannel instanceof SecureSocketChannel);
            serverChannel.configureBlocking(false);

            Selector serverSelector = selectorProvider.openSelector();
            ((SecureSocketChannel) serverChannel).delegate().register(serverSelector, SelectionKey.OP_READ);
            clientChannel.delegate().register(clientSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            // Drive a small data exchange to guarantee the TLS handshake has completed.
            byte[] ping = "ping".getBytes();
            ByteBuffer pingWriteBuf = ByteBuffer.wrap(ping);
            ByteBuffer pingReadBuf = ByteBuffer.allocate(ping.length);
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (pingReadBuf.hasRemaining() && System.currentTimeMillis() < deadline) {
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();
                if (pingWriteBuf.hasRemaining()) {
                    clientChannel.write(pingWriteBuf);
                }
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                serverChannel.read(pingReadBuf);
                Thread.yield();
            }
            assertFalse("handshake did not complete", pingReadBuf.hasRemaining());

            // Write the whole payload, then gracefully close so the client emits data + close_notify + FIN.
            ByteBuffer writeBuf = ByteBuffer.wrap(payload);
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (writeBuf.hasRemaining() && System.currentTimeMillis() < deadline) {
                clientSelector.selectNow();
                clientSelector.selectedKeys().clear();
                clientChannel.write(writeBuf);
                Thread.yield();
            }
            assertFalse("client failed to write the full payload", writeBuf.hasRemaining());
            clientChannel.close();

            // Wait until the server socket is readable, then let the whole stream (data + close_notify +
            // FIN) settle into the OS buffer, so the first decrypt fills the scratchpad and the trailing
            // residual is still pending when the engine observes end-of-stream.
            boolean readable = false;
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            while (!readable && System.currentTimeMillis() < deadline) {
                serverSelector.selectNow();
                readable = !serverSelector.selectedKeys().isEmpty();
                serverSelector.selectedKeys().clear();
                Thread.yield();
            }
            assertTrue("payload never arrived at the server", readable);
            Thread.sleep(50);

            // Drain with a tiny buffer. All decrypted bytes must be delivered before the -1; none dropped.
            ByteBuffer smallReadBuf = ByteBuffer.allocate(8);
            ByteBuffer accumulated = ByteBuffer.allocate(payload.length);
            deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
            boolean sawEof = false;
            while (System.currentTimeMillis() < deadline) {
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();
                smallReadBuf.clear();
                int read = serverChannel.read(smallReadBuf);
                if (read < 0) {
                    sawEof = true;
                    break;
                }
                if (read > 0) {
                    smallReadBuf.flip();
                    accumulated.put(smallReadBuf);
                }
                Thread.yield();
            }
            assertTrue("server never observed end-of-stream", sawEof);

            accumulated.flip();
            byte[] received = new byte[accumulated.remaining()];
            accumulated.get(received);
            assertArrayEquals("plaintext was truncated when EOF coincided with buffered data", payload, received);

            serverChannel.close();
            clientSelector.close();
            serverSelector.close();
            secureServerChannel.close();
        }
    }

    private static void finishConnect(SecureSocketChannel channel, Selector selector) throws Exception {
        long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
        while (!channel.finishConnect() && System.currentTimeMillis() < deadline) {
            selector.select(100);
            selector.selectedKeys().clear();
        }
        assertTrue(channel.isConnected());
    }
}
