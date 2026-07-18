/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.SocketChannel;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLEngine;

/**
 * A {@link SocketChannel} decorator that transparently wraps a raw channel with TLS/SSL encryption
 * and decryption. All cryptographic operations are handled internally via {@link TLSByteChannel},
 * while non-I/O operations are delegated to the underlying raw channel.
 * <p>
 * Read and write operations are mutually exclusive — they share the same lock to serialize
 * concurrent access to the TLS engine, which is not thread-safe.
 * <p>
 * <strong>This channel supports non-blocking mode only.</strong> It is designed to be driven by a
 * {@link java.nio.channels.Selector}: each {@link #read(ByteBuffer)} or {@link #write(ByteBuffer)}
 * pumps the TLS engine opportunistically and hands control back so the selector can signal when the
 * socket is next readable or writable. In blocking mode the underlying {@code read()} would wait for
 * the peer to fill the ~16KB inbound buffer (a read of a small record would hang until far more data
 * arrived) and the read-after-write that pumps the handshake would block indefinitely. Both
 * {@link #read(ByteBuffer)} and {@link #write(ByteBuffer)} therefore reject blocking mode with an
 * {@link java.nio.channels.IllegalBlockingModeException}; call {@code configureBlocking(false)}
 * before performing I/O.
 * <p>
 * This channel cannot be directly registered with a {@link java.nio.channels.Selector}.
 * Instead, the underlying raw channel should be registered, with this secure channel
 * attached to the resulting {@link java.nio.channels.SelectionKey}:
 * <pre>{@code
 * SelectionKey key = secureChannel.delegate().register(selector, SelectionKey.OP_READ);
 * key.attach(secureChannel);
 * }</pre>
 *
 * @author Radoslav Husar
 */
public class SecureSocketChannel extends SocketChannel {

    /**
     * Bounded wait to acquire {@link #lock} on close, so a wedged lock holder (e.g. a stalled
     * delegated task) cannot block {@code close()} indefinitely.
     */
    private static final long CLOSE_LOCK_TIMEOUT_MILLIS = 1000;

    private final SocketChannel delegate;
    private final TLSByteChannel tlsChannel;
    private final ReentrantLock lock = new ReentrantLock();

    public SecureSocketChannel(SocketChannel delegate, SSLEngine engine, ExecutorService taskExecutor) {
        super(delegate.provider());
        this.delegate = delegate;
        this.tlsChannel = new TLSByteChannel(delegate, engine, taskExecutor);
    }

    /**
     * Returns the underlying raw (unencrypted) channel, for use with selector registration.
     */
    public SocketChannel delegate() {
        return delegate;
    }

    /**
     * Guards against blocking-mode I/O, which this channel does not support: a blocking read would
     * wait for the inbound buffer to fill rather than returning after a complete record, and the
     * read-after-write that pumps the handshake would block indefinitely.
     */
    private void requireNonBlocking() {
        if (isBlocking()) {
            throw new IllegalBlockingModeException();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalBlockingModeException if this channel is in blocking mode; only non-blocking
     *                                      mode is supported (see the class documentation)
     */
    @Override
    public int read(ByteBuffer dst) throws IOException {
        Objects.requireNonNull(dst);
        if (dst.isReadOnly()) {
            throw new IllegalArgumentException("Read-only buffer");
        }
        requireNonBlocking();
        lock.lock();
        try {
            int initialPosition = dst.position();
            int rawResult = tlsChannel.decrypt(dst);
            if (rawResult < 0) {
                return rawResult;
            }
            return dst.position() - initialPosition;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        Objects.checkFromIndexSize(offset, length, dsts.length);
        long totalRead = 0;
        for (int i = offset; i < offset + length; i++) {
            ByteBuffer region = dsts[i];
            if (region.hasRemaining()) {
                int read = this.read(region);
                if (read > 0) {
                    totalRead += read;
                    if (region.hasRemaining()) {
                        break;
                    }
                } else {
                    if (read < 0 && totalRead == 0) {
                        totalRead = -1;
                    }
                    break;
                }
            }
        }
        return totalRead;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalBlockingModeException if this channel is in blocking mode; only non-blocking
     *                                      mode is supported (see the class documentation)
     */
    @Override
    public int write(ByteBuffer src) throws IOException {
        Objects.requireNonNull(src);
        requireNonBlocking();
        lock.lock();
        try {
            int initialPosition = src.position();
            int rawResult = tlsChannel.encrypt(src);
            if (rawResult < 0) {
                return rawResult;
            }
            return src.position() - initialPosition;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        Objects.checkFromIndexSize(offset, length, srcs.length);
        long totalWritten = 0;
        for (int i = offset; i < offset + length; i++) {
            ByteBuffer region = srcs[i];
            if (region.hasRemaining()) {
                int written = this.write(region);
                if (written > 0) {
                    totalWritten += written;
                    if (region.hasRemaining()) {
                        break;
                    }
                } else {
                    if (written < 0 && totalWritten == 0) {
                        totalWritten = -1;
                    }
                    break;
                }
            }
        }
        return totalWritten;
    }

    @Override
    protected void implCloseSelectableChannel() throws IOException {
        // The TLS engine is not thread-safe, so driving it here must hold the same lock that
        // serializes read() and write() – close() can run concurrently with in-flight I/O on
        // another thread. The wait is bounded so a wedged lock holder cannot block close
        // indefinitely; on timeout the engine is left untouched (close_notify is best-effort
        // anyway) and only the raw socket is closed.
        boolean locked = false;
        try {
            locked = lock.tryLock(CLOSE_LOCK_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (!locked) {
            delegate.close();
            return;
        }
        try {
            try {
                // Announce closure with a close_notify alert while the raw socket is still open, so a
                // compliant peer does not mistake our shutdown for a truncation attack.
                tlsChannel.closeOutbound();
            } catch (Exception ignored) {
            } finally {
                delegate.close();
                tlsChannel.shutdown();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    protected void implConfigureBlocking(boolean block) throws IOException {
        delegate.configureBlocking(block);
    }

    @Override
    public boolean isConnected() {
        return delegate.isConnected();
    }

    @Override
    public boolean isConnectionPending() {
        return delegate.isConnectionPending();
    }

    @Override
    public boolean connect(SocketAddress remote) throws IOException {
        return delegate.connect(remote);
    }

    @Override
    public boolean finishConnect() throws IOException {
        return delegate.finishConnect();
    }

    @Override
    public SocketAddress getRemoteAddress() throws IOException {
        return delegate.getRemoteAddress();
    }

    @Override
    public SocketAddress getLocalAddress() throws IOException {
        return delegate.getLocalAddress();
    }

    @Override
    public SocketChannel bind(SocketAddress local) throws IOException {
        delegate.bind(local);
        return this;
    }

    @Override
    public <T> SocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        delegate.setOption(name, value);
        return this;
    }

    @Override
    public <T> T getOption(SocketOption<T> name) throws IOException {
        return delegate.getOption(name);
    }

    @Override
    public Set<SocketOption<?>> supportedOptions() {
        return delegate.supportedOptions();
    }

    @Override
    public SocketChannel shutdownInput() throws IOException {
        delegate.shutdownInput();
        return this;
    }

    @Override
    public SocketChannel shutdownOutput() throws IOException {
        delegate.shutdownOutput();
        return this;
    }

    @Override
    public Socket socket() {
        return delegate.socket();
    }
}
