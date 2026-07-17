/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.NotYetConnectedException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Verifies {@link DatagramChannel} decorator.
 *
 * @author Radoslav Husar
 */
public class SecureDatagramChannelTestCase {

    private DatagramChannel rawChannel;
    private SecureDatagramChannel secureChannel;
    private ExecutorService executor;

    @Before
    public void setUp() throws Exception {
        rawChannel = DatagramChannel.open();
        executor = Executors.newSingleThreadExecutor();
        SSLContext sslContext = SSLContext.getInstance("DTLS");
        sslContext.init(null, null, null);
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(true);
        secureChannel = new SecureDatagramChannel(rawChannel, engine, executor);
    }

    @After
    public void tearDown() throws Exception {
        secureChannel.close();
        executor.shutdownNow();
    }

    @Test
    public void delegate() {
        assertSame(rawChannel, secureChannel.delegate());
    }

    @Test
    public void isConnected() {
        assertFalse(secureChannel.isConnected());
        assertFalse(rawChannel.isConnected());
    }

    @Test
    public void bind() throws Exception {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        secureChannel.bind(address);

        assertEquals(rawChannel.getLocalAddress(), secureChannel.getLocalAddress());
    }

    @Test
    public void setAndGetOption() throws Exception {
        secureChannel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        assertEquals(rawChannel.getOption(StandardSocketOptions.SO_REUSEADDR), secureChannel.getOption(StandardSocketOptions.SO_REUSEADDR));
    }

    @Test
    public void supportedOptions() {
        assertEquals(rawChannel.supportedOptions(), secureChannel.supportedOptions());
    }

    @Test
    public void socket() {
        assertSame(rawChannel.socket(), secureChannel.socket());
    }

    @Test
    public void configureBlocking() throws Exception {
        secureChannel.configureBlocking(false);
        assertFalse(rawChannel.isBlocking());
        assertFalse(secureChannel.isBlocking());
    }

    @Test
    public void closeClosesDelegate() throws Exception {
        secureChannel.close();
        assertFalse(rawChannel.isOpen());
    }

    @Test(expected = NotYetConnectedException.class)
    public void readBeforeConnectThrows() throws Exception {
        secureChannel.read(ByteBuffer.allocate(16));
    }

    @Test(expected = NotYetConnectedException.class)
    public void writeBeforeConnectThrows() throws Exception {
        secureChannel.write(ByteBuffer.wrap("data".getBytes()));
    }

    @Test(expected = NotYetConnectedException.class)
    public void receiveBeforeConnectThrows() throws Exception {
        secureChannel.receive(ByteBuffer.allocate(16));
    }

    @Test(expected = NotYetConnectedException.class)
    public void sendBeforeConnectThrows() throws Exception {
        secureChannel.send(ByteBuffer.wrap("data".getBytes()), new InetSocketAddress(InetAddress.getLoopbackAddress(), 12345));
    }

    @Test
    public void sendToForeignAddressThrows() throws Exception {
        try (DatagramChannel peer = DatagramChannel.open()) {
            peer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            secureChannel.connect(peer.getLocalAddress());
            try {
                secureChannel.send(ByteBuffer.wrap("data".getBytes()), new InetSocketAddress(InetAddress.getLoopbackAddress(), 12345));
                fail("send to an address other than the connected peer must throw");
            } catch (AlreadyConnectedException expected) {
            }
        }
    }

    @Test
    public void readRejectsBlockingMode() throws Exception {
        try (DatagramChannel peer = DatagramChannel.open()) {
            peer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            secureChannel.connect(peer.getLocalAddress());
            // A freshly opened channel is in blocking mode, which is unsupported.
            assertTrue(secureChannel.isBlocking());
            assertThrows(IllegalBlockingModeException.class, () -> secureChannel.read(ByteBuffer.allocate(16)));
        }
    }

    @Test
    public void writeRejectsBlockingMode() throws Exception {
        try (DatagramChannel peer = DatagramChannel.open()) {
            peer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            secureChannel.connect(peer.getLocalAddress());
            assertTrue(secureChannel.isBlocking());
            assertThrows(IllegalBlockingModeException.class, () -> secureChannel.write(ByteBuffer.wrap("data".getBytes())));
        }
    }

    @Test
    public void connectConnectsDelegate() throws Exception {
        try (DatagramChannel peer = DatagramChannel.open()) {
            peer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            secureChannel.connect(peer.getLocalAddress());

            assertTrue(secureChannel.isConnected());
            assertTrue(rawChannel.isConnected());
            assertEquals(peer.getLocalAddress(), secureChannel.getRemoteAddress());
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void disconnectUnsupported() {
        secureChannel.disconnect();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void joinUnsupported() throws Exception {
        secureChannel.join(InetAddress.getByName("224.0.0.1"), null);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void sourceSpecificJoinUnsupported() throws Exception {
        secureChannel.join(InetAddress.getByName("224.0.0.1"), null, InetAddress.getLoopbackAddress());
    }
}
