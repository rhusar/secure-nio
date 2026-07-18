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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Verifies {@link SocketChannel} decorator.
 *
 * @author Radoslav Husar
 */
public class SecureSocketChannelTestCase {

    private SocketChannel rawChannel;
    private SecureSocketChannel secureChannel;
    private ExecutorService executor;

    @Before
    public void setUp() throws Exception {
        rawChannel = SocketChannel.open();
        executor = Executors.newSingleThreadExecutor();
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(true);
        secureChannel = new SecureSocketChannel(rawChannel, engine, executor);
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
    public void isConnectionPending() {
        assertFalse(secureChannel.isConnectionPending());
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
    public void readRejectsBlockingMode() {
        // A freshly opened channel is in blocking mode, which is unsupported.
        assertTrue(secureChannel.isBlocking());
        assertThrows(IllegalBlockingModeException.class, () -> secureChannel.read(ByteBuffer.allocate(16)));
    }

    @Test
    public void writeRejectsBlockingMode() {
        assertTrue(secureChannel.isBlocking());
        assertThrows(IllegalBlockingModeException.class, () -> secureChannel.write(ByteBuffer.allocate(16)));
    }

    @Test
    public void readRejectsReadOnlyBuffer() {
        assertThrows(IllegalArgumentException.class, () -> secureChannel.read(ByteBuffer.allocate(16).asReadOnlyBuffer()));
        assertThrows(IllegalArgumentException.class, () -> secureChannel.read(new ByteBuffer[]{ ByteBuffer.allocate(16).asReadOnlyBuffer() }, 0, 1));
    }

    @Test
    public void writeAcceptsReadOnlyBuffer() {
        // A read-only source is legal input to write; only the destination of a read must be writable.
        assertThrows(IllegalBlockingModeException.class, () -> secureChannel.write(ByteBuffer.allocate(16).asReadOnlyBuffer()));
    }

    @Test
    public void scatteringIoRejectsOutOfBoundsRange() {
        ByteBuffer[] buffers = new ByteBuffer[]{ ByteBuffer.allocate(16), ByteBuffer.allocate(16) };

        assertThrows(IndexOutOfBoundsException.class, () -> secureChannel.read(buffers, -1, 1));
        assertThrows(IndexOutOfBoundsException.class, () -> secureChannel.read(buffers, 0, 5));
        assertThrows(IndexOutOfBoundsException.class, () -> secureChannel.write(buffers, -1, 1));
        assertThrows(IndexOutOfBoundsException.class, () -> secureChannel.write(buffers, 0, 5));
    }

    @Test
    public void ioRejectsNullBuffer() {
        assertThrows(NullPointerException.class, () -> secureChannel.read((ByteBuffer) null));
        assertThrows(NullPointerException.class, () -> secureChannel.write((ByteBuffer) null));
    }

    @Test
    public void closeClosesDelegate() throws Exception {
        secureChannel.close();
        assertFalse(rawChannel.isOpen());
    }

    /**
     * A {@code close_notify} that cannot be produced or transmitted must be reported to the caller
     * rather than swallowed, but only after the raw socket has been closed so the failure does not
     * leak it.
     */
    @Test
    public void closeReportsCloseNotifyFailureAfterClosingDelegate() throws Exception {
        SocketChannel raw = SocketChannel.open();
        ExecutorService taskExecutor = Executors.newSingleThreadExecutor();
        try {
            SSLException wrapFailure = new SSLException("close_notify wrap failed");
            SSLEngine engine = new ZeroPlaintextSSLEngine(SSLContext.getDefault().createSSLEngine().getSession()) {
                @Override
                public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
                    throw wrapFailure;
                }

                @Override
                public boolean isOutboundDone() {
                    return false;
                }
            };
            SecureSocketChannel channel = new SecureSocketChannel(raw, engine, taskExecutor);

            SSLException thrown = assertThrows(SSLException.class, channel::close);
            assertSame(wrapFailure, thrown);
            assertFalse("raw channel leaked by failed close", raw.isOpen());
        } finally {
            taskExecutor.shutdownNow();
            raw.close();
        }
    }

    /**
     * The TLS engine is not thread-safe, so a {@code close()} racing an in-flight {@code write()}
     * must not drive the engine while the writer is still inside it. The writer parks inside
     * {@code wrap()} holding the channel lock; close must give up on the engine after its bounded
     * wait and still close the raw channel.
     */
    @Test
    public void closeDoesNotDriveEngineConcurrentlyWithInFlightWrite() throws Exception {
        SocketChannel raw = SocketChannel.open();
        ExecutorService taskExecutor = Executors.newSingleThreadExecutor();
        try {
            SSLEngine realEngine = SSLContext.getDefault().createSSLEngine();
            realEngine.setUseClientMode(true);
            BlockingSSLEngine engine = new BlockingSSLEngine(realEngine);
            SecureSocketChannel channel = new SecureSocketChannel(raw, engine, taskExecutor);
            channel.configureBlocking(false);

            Thread writer = new Thread(() -> {
                try {
                    channel.write(ByteBuffer.wrap("data".getBytes()));
                } catch (Exception expectedOnceClosed) {
                }
            });
            writer.start();
            try {
                assertTrue("writer never reached the engine", engine.awaitWrapEntered(5, TimeUnit.SECONDS));

                channel.close();
                assertFalse(raw.isOpen());
            } finally {
                engine.releaseWrap();
                writer.join(5000);
            }
            assertFalse("writer thread did not finish", writer.isAlive());
            assertFalse("engine was driven from two threads at once", engine.sawConcurrentAccess());
        } finally {
            taskExecutor.shutdownNow();
            raw.close();
        }
    }
}
