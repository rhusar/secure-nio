/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

import io.github.rhusar.securenio.channels.spi.DelegatingSelectorProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * End-to-end DTLS integration test over loopback using {@link SecureDatagramChannel} and
 * {@link DTLSByteChannel} with non-blocking selector-driven I/O.
 *
 * @author Radoslav Husar
 */
public class DTLSLoopbackTestCase {

    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
    private static final int TEST_TIMEOUT_MS = 10_000;
    private static final int RETRANSMIT_STALL_MS = 250;
    private static SSLContext sslContext;
    private static ExecutorService taskExecutor;

    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = DTLSLoopbackTestCase.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(is, KEYSTORE_PASSWORD);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        sslContext = SSLContext.getInstance("DTLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        taskExecutor = Executors.newCachedThreadPool();
    }

    @AfterClass
    public static void tearDownClass() {
        taskExecutor.shutdownNow();
    }

    private static SecureDatagramChannel secureChannel(DatagramChannel rawChannel, boolean clientMode) throws Exception {
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(clientMode);
        SecureDatagramChannel channel = new SecureDatagramChannel(rawChannel, engine, taskExecutor);
        channel.configureBlocking(false);
        return channel;
    }

    private static DatagramChannel boundLoopbackChannel() throws Exception {
        DatagramChannel channel = DatagramChannel.open();
        channel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        return channel;
    }

    @Test
    public void bidirectionalDataExchange() throws Exception {
        byte[][] clientMessages = {
                "First message from client".getBytes(),
                new byte[1024],
                "Third message from client".getBytes(),
        };
        for (int i = 0; i < clientMessages[1].length; i++) {
            clientMessages[1][i] = (byte) (i % 127);
        }
        byte[][] serverMessages = {
                "Hello from server".getBytes(),
                "Goodbye from server".getBytes(),
        };

        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        DatagramChannel rawClientChannel = boundLoopbackChannel();
        DatagramChannel rawServerChannel = boundLoopbackChannel();
        rawClientChannel.connect(rawServerChannel.getLocalAddress());
        rawServerChannel.connect(rawClientChannel.getLocalAddress());

        SecureDatagramChannel clientChannel = secureChannel(rawClientChannel, true);
        SecureDatagramChannel serverChannel = secureChannel(rawServerChannel, false);

        try (Selector clientSelector = selectorProvider.openSelector();
             Selector serverSelector = selectorProvider.openSelector()) {

            clientChannel.register(clientSelector, SelectionKey.OP_READ);
            serverChannel.register(serverSelector, SelectionKey.OP_READ);

            List<byte[]> serverReceived = new ArrayList<>();
            List<byte[]> clientReceived = new ArrayList<>();
            int clientSent = 0;
            int serverSent = 0;
            ByteBuffer readBuf = ByteBuffer.allocate(4 * 1024);

            long deadline = System.currentTimeMillis() + TEST_TIMEOUT_MS;
            long lastProgress = System.currentTimeMillis();

            while ((serverReceived.size() < clientMessages.length || clientReceived.size() < serverMessages.length)
                    && System.currentTimeMillis() < deadline) {

                boolean progressed = false;

                clientSelector.select(10);
                clientSelector.selectedKeys().clear();
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();

                // Datagram semantics: a write consumes the whole message or nothing.
                if (clientSent < clientMessages.length) {
                    ByteBuffer writeBuf = ByteBuffer.wrap(clientMessages[clientSent]);
                    clientChannel.write(writeBuf);
                    if (!writeBuf.hasRemaining()) {
                        clientSent++;
                        progressed = true;
                    }
                }

                // The server only sends once it has received everything, keeping ordering simple.
                if (serverReceived.size() == clientMessages.length && serverSent < serverMessages.length) {
                    ByteBuffer writeBuf = ByteBuffer.wrap(serverMessages[serverSent]);
                    serverChannel.write(writeBuf);
                    if (!writeBuf.hasRemaining()) {
                        serverSent++;
                        progressed = true;
                    }
                }

                readBuf.clear();
                if (serverChannel.read(readBuf) > 0) {
                    readBuf.flip();
                    byte[] message = new byte[readBuf.remaining()];
                    readBuf.get(message);
                    serverReceived.add(message);
                    progressed = true;
                }

                readBuf.clear();
                if (clientChannel.read(readBuf) > 0) {
                    readBuf.flip();
                    byte[] message = new byte[readBuf.remaining()];
                    readBuf.get(message);
                    clientReceived.add(message);
                    progressed = true;
                }

                // The DTLS engine has no retransmission timer: when the handshake stalls (a flight
                // was lost, e.g. under loopback buffer pressure), re-send it after a quiet period.
                if (progressed) {
                    lastProgress = System.currentTimeMillis();
                } else if (System.currentTimeMillis() - lastProgress > RETRANSMIT_STALL_MS) {
                    clientChannel.retransmit();
                    serverChannel.retransmit();
                    lastProgress = System.currentTimeMillis();
                }
            }

            // Message boundaries must be preserved: one datagram in, one message out.
            assertEquals(clientMessages.length, serverReceived.size());
            for (int i = 0; i < clientMessages.length; i++) {
                assertArrayEquals(clientMessages[i], serverReceived.get(i));
            }
            assertEquals(serverMessages.length, clientReceived.size());
            for (int i = 0; i < serverMessages.length; i++) {
                assertArrayEquals(serverMessages[i], clientReceived.get(i));
            }
        } finally {
            clientChannel.close();
            serverChannel.close();
        }
    }

    /**
     * A lost handshake flight must not abort the handshake: after a quiet period the stalled side
     * calls {@link SecureDatagramChannel#retransmit()} and the handshake completes. A lossy path is
     * simulated with a datagram proxy between the peers that deliberately drops the first
     * server-to-client datagram (a handshake flight).
     */
    @Test
    public void handshakeRecoversFromPacketLoss() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        try (DatagramChannel proxyChannel = boundLoopbackChannel()) {
            proxyChannel.configureBlocking(false);
            SocketAddress proxyAddress = proxyChannel.getLocalAddress();

            DatagramChannel rawClientChannel = boundLoopbackChannel();
            DatagramChannel rawServerChannel = boundLoopbackChannel();
            SocketAddress clientAddress = rawClientChannel.getLocalAddress();
            SocketAddress serverAddress = rawServerChannel.getLocalAddress();
            rawClientChannel.connect(proxyAddress);
            rawServerChannel.connect(proxyAddress);

            SecureDatagramChannel clientChannel = secureChannel(rawClientChannel, true);
            SecureDatagramChannel serverChannel = secureChannel(rawServerChannel, false);

            try (Selector clientSelector = selectorProvider.openSelector();
                 Selector serverSelector = selectorProvider.openSelector()) {

                clientChannel.register(clientSelector, SelectionKey.OP_READ);
                serverChannel.register(serverSelector, SelectionKey.OP_READ);

                byte[] ping = "ping over lossy path".getBytes();
                byte[] pong = "pong over lossy path".getBytes();
                boolean pingSent = false;
                boolean pongSent = false;
                byte[] pingReceived = null;
                byte[] pongReceived = null;
                boolean dropNextServerDatagram = true;

                ByteBuffer proxyBuf = ByteBuffer.allocate(64 * 1024);
                ByteBuffer readBuf = ByteBuffer.allocate(1024);

                long deadline = System.currentTimeMillis() + TEST_TIMEOUT_MS;
                long lastProgress = System.currentTimeMillis();

                while (pongReceived == null && System.currentTimeMillis() < deadline) {

                    // Proxy pump: forward datagrams between the peers, dropping the first
                    // server-to-client datagram to simulate a lost handshake flight.
                    for (;;) {
                        proxyBuf.clear();
                        SocketAddress sender = proxyChannel.receive(proxyBuf);
                        if (sender == null) {
                            break;
                        }
                        proxyBuf.flip();
                        if (sender.equals(clientAddress)) {
                            proxyChannel.send(proxyBuf, serverAddress);
                        } else if (dropNextServerDatagram) {
                            dropNextServerDatagram = false;
                        } else {
                            proxyChannel.send(proxyBuf, clientAddress);
                        }
                    }

                    clientSelector.select(10);
                    clientSelector.selectedKeys().clear();
                    serverSelector.selectNow();
                    serverSelector.selectedKeys().clear();

                    boolean progressed = false;

                    if (!pingSent) {
                        ByteBuffer writeBuf = ByteBuffer.wrap(ping);
                        clientChannel.write(writeBuf);
                        if (!writeBuf.hasRemaining()) {
                            pingSent = true;
                            progressed = true;
                        }
                    }

                    if (pingReceived == null) {
                        readBuf.clear();
                        if (serverChannel.read(readBuf) > 0) {
                            readBuf.flip();
                            pingReceived = new byte[readBuf.remaining()];
                            readBuf.get(pingReceived);
                            progressed = true;
                        }
                    } else if (!pongSent) {
                        ByteBuffer writeBuf = ByteBuffer.wrap(pong);
                        serverChannel.write(writeBuf);
                        if (!writeBuf.hasRemaining()) {
                            pongSent = true;
                            progressed = true;
                        }
                    }

                    readBuf.clear();
                    if (clientChannel.read(readBuf) > 0) {
                        readBuf.flip();
                        pongReceived = new byte[readBuf.remaining()];
                        readBuf.get(pongReceived);
                        progressed = true;
                    }

                    if (progressed) {
                        lastProgress = System.currentTimeMillis();
                    } else if (System.currentTimeMillis() - lastProgress > RETRANSMIT_STALL_MS) {
                        clientChannel.retransmit();
                        serverChannel.retransmit();
                        lastProgress = System.currentTimeMillis();
                    }
                }

                assertArrayEquals("handshake did not recover from the dropped flight", ping, pingReceived);
                assertArrayEquals(pong, pongReceived);
            } finally {
                clientChannel.close();
                serverChannel.close();
            }
        }
    }

    /**
     * A graceful {@link SecureDatagramChannel#close()} must transmit a {@code close_notify} alert
     * so the peer's next read reports {@code -1} rather than silence. Unlike TLS over TCP the alert
     * is a single datagram and delivery is best-effort, but over loopback it must arrive.
     */
    @Test
    public void closeSendsBestEffortCloseNotify() throws Exception {
        DelegatingSelectorProvider selectorProvider = new DelegatingSelectorProvider();

        DatagramChannel rawClientChannel = boundLoopbackChannel();
        DatagramChannel rawServerChannel = boundLoopbackChannel();
        rawClientChannel.connect(rawServerChannel.getLocalAddress());
        rawServerChannel.connect(rawClientChannel.getLocalAddress());

        SecureDatagramChannel clientChannel = secureChannel(rawClientChannel, true);
        SecureDatagramChannel serverChannel = secureChannel(rawServerChannel, false);

        try (Selector clientSelector = selectorProvider.openSelector();
             Selector serverSelector = selectorProvider.openSelector()) {

            clientChannel.register(clientSelector, SelectionKey.OP_READ);
            serverChannel.register(serverSelector, SelectionKey.OP_READ);

            // Drive a small data exchange to guarantee the DTLS handshake has completed.
            byte[] ping = "ping".getBytes();
            byte[] received = null;
            ByteBuffer readBuf = ByteBuffer.allocate(64);
            long deadline = System.currentTimeMillis() + TEST_TIMEOUT_MS;
            long lastProgress = System.currentTimeMillis();
            boolean pingSent = false;

            while (received == null && System.currentTimeMillis() < deadline) {
                clientSelector.select(10);
                clientSelector.selectedKeys().clear();
                serverSelector.selectNow();
                serverSelector.selectedKeys().clear();

                boolean progressed = false;

                if (!pingSent) {
                    ByteBuffer writeBuf = ByteBuffer.wrap(ping);
                    clientChannel.write(writeBuf);
                    if (!writeBuf.hasRemaining()) {
                        pingSent = true;
                        progressed = true;
                    }
                }

                readBuf.clear();
                if (serverChannel.read(readBuf) > 0) {
                    readBuf.flip();
                    received = new byte[readBuf.remaining()];
                    readBuf.get(received);
                    progressed = true;
                }

                // The client must also read to make handshake progress on the server's flights.
                readBuf.clear();
                clientChannel.read(readBuf);

                if (progressed) {
                    lastProgress = System.currentTimeMillis();
                } else if (System.currentTimeMillis() - lastProgress > RETRANSMIT_STALL_MS) {
                    clientChannel.retransmit();
                    serverChannel.retransmit();
                    lastProgress = System.currentTimeMillis();
                }
            }
            assertArrayEquals(ping, received);

            // Orderly shutdown: this must emit the close_notify alert before closing the socket.
            clientChannel.close();

            boolean sawClose = false;
            deadline = System.currentTimeMillis() + TEST_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                serverSelector.select(10);
                serverSelector.selectedKeys().clear();
                readBuf.clear();
                if (serverChannel.read(readBuf) < 0) {
                    sawClose = true;
                    break;
                }
            }
            assertTrue("server never observed the peer's close_notify", sawClose);
        } finally {
            clientChannel.close();
            serverChannel.close();
        }
    }
}
