/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.MembershipKey;
import java.nio.channels.NotYetConnectedException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLEngine;

/**
 * A {@link DatagramChannel} decorator that transparently wraps a raw channel with DTLS encryption
 * and decryption. All cryptographic operations are handled internally via {@link DTLSByteChannel},
 * while non-I/O operations are delegated to the underlying raw channel.
 * <p>
 * The channel operates in connected mode only: the DTLS session is bound to a single peer, so the
 * underlying channel must be {@linkplain #connect(SocketAddress) connected} before any secure I/O.
 * Consequently {@link #disconnect()} and multicast {@code join} are unsupported, and
 * {@link #send(ByteBuffer, SocketAddress)} only accepts the connected peer's address.
 * <p>
 * The engine must be created from an {@code SSLContext} of type {@code "DTLS"}. To avoid IP
 * fragmentation on MTU-limited paths, configure
 * {@link javax.net.ssl.SSLParameters#setMaximumPacketSize(int)} (for example {@code 1432} for
 * Ethernet-sized MTUs) on the engine before constructing this channel.
 * <p>
 * The DTLS engine has no handshake retransmission timer. When a selector-driven caller observes no
 * progress while {@link #isHandshaking()} — typically a {@code select(timeout)} that expires — it
 * must call {@link #retransmit()} to re-send the last handshake flight lost in transit. The
 * {@code close_notify} alert sent on {@link #close()} is a single datagram delivered best-effort.
 * <p>
 * Read and write operations are mutually exclusive — they share the same lock to serialize
 * concurrent access to the DTLS engine, which is not thread-safe.
 * <p>
 * <strong>This channel supports non-blocking mode only.</strong> The retransmission model above is
 * inherently selector-driven: a lost handshake flight is detected because a {@code select(timeout)}
 * expires with no progress, which is what prompts the caller to invoke {@link #retransmit()}. In
 * blocking mode the underlying {@code read()} would instead wait forever for a datagram that was
 * lost — the peer is meanwhile waiting for a retransmission that never comes — deadlocking the
 * handshake on the first dropped packet (an inevitability over UDP). Both {@link #read(ByteBuffer)}
 * and {@link #write(ByteBuffer)} therefore reject blocking mode with an
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
public class SecureDatagramChannel extends DatagramChannel {

    private final DatagramChannel delegate;
    private final DTLSByteChannel dtlsChannel;
    private final ReentrantLock lock = new ReentrantLock();

    public SecureDatagramChannel(DatagramChannel delegate, SSLEngine engine, ExecutorService taskExecutor) {
        super(delegate.provider());
        this.delegate = delegate;
        this.dtlsChannel = new DTLSByteChannel(delegate, engine, taskExecutor);
    }

    /**
     * Returns the underlying raw (unencrypted) channel, for use with selector registration.
     */
    public DatagramChannel delegate() {
        return delegate;
    }

    /**
     * Re-sends the last handshake flight. The DTLS engine has no retransmission timer, so callers
     * must invoke this when the handshake stalls — no datagram arrives within their select timeout
     * while {@link #isHandshaking()} — indicating a flight was lost. No-op when not handshaking.
     */
    public void retransmit() throws IOException {
        lock.lock();
        try {
            dtlsChannel.retransmit();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns whether the DTLS handshake is currently in progress.
     */
    public boolean isHandshaking() {
        lock.lock();
        try {
            return dtlsChannel.isHandshaking();
        } finally {
            lock.unlock();
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
        checkConnected();
        requireNonBlocking();
        lock.lock();
        try {
            return dtlsChannel.decrypt(dst);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        // A single datagram's plaintext is delivered into the first buffer with room; datagram
        // semantics discard what does not fit, so spreading across buffers is not attempted.
        for (int i = offset; i < offset + length; i++) {
            if (dsts[i].hasRemaining()) {
                return this.read(dsts[i]);
            }
        }
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalBlockingModeException if this channel is in blocking mode; only non-blocking
     *                                      mode is supported (see the class documentation)
     */
    @Override
    public int write(ByteBuffer src) throws IOException {
        checkConnected();
        requireNonBlocking();
        lock.lock();
        try {
            return dtlsChannel.encrypt(src);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
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
                    break;
                }
            }
        }
        return totalWritten;
    }

    @Override
    public SocketAddress receive(ByteBuffer dst) throws IOException {
        checkConnected();
        return this.read(dst) > 0 ? delegate.getRemoteAddress() : null;
    }

    @Override
    public int send(ByteBuffer src, SocketAddress target) throws IOException {
        checkConnected();
        if (!Objects.equals(target, delegate.getRemoteAddress())) {
            throw new AlreadyConnectedException();
        }
        return this.write(src);
    }

    @Override
    public DatagramChannel connect(SocketAddress remote) throws IOException {
        delegate.connect(remote);
        return this;
    }

    /**
     * @throws UnsupportedOperationException always — the DTLS session is bound to a single peer;
     *         close the channel instead
     */
    @Override
    public DatagramChannel disconnect() {
        throw new UnsupportedOperationException();
    }

    /**
     * @throws UnsupportedOperationException always — multicast is not supported over DTLS
     */
    @Override
    public MembershipKey join(InetAddress group, NetworkInterface interf) {
        throw new UnsupportedOperationException();
    }

    /**
     * @throws UnsupportedOperationException always — multicast is not supported over DTLS
     */
    @Override
    public MembershipKey join(InetAddress group, NetworkInterface interf, InetAddress source) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void implCloseSelectableChannel() throws IOException {
        try {
            // Announce closure with a best-effort close_notify alert while the raw socket is still
            // open; the single datagram may be lost, which DTLS peers must tolerate.
            dtlsChannel.closeOutbound();
        } catch (Exception ignored) {
        } finally {
            delegate.close();
            dtlsChannel.shutdown();
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
    public SocketAddress getRemoteAddress() throws IOException {
        return delegate.getRemoteAddress();
    }

    @Override
    public SocketAddress getLocalAddress() throws IOException {
        return delegate.getLocalAddress();
    }

    @Override
    public DatagramChannel bind(SocketAddress local) throws IOException {
        delegate.bind(local);
        return this;
    }

    @Override
    public <T> DatagramChannel setOption(SocketOption<T> name, T value) throws IOException {
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
    public DatagramSocket socket() {
        return delegate.socket();
    }

    private void checkConnected() {
        if (!delegate.isConnected()) {
            throw new NotYetConnectedException();
        }
    }

    /**
     * Guards against blocking-mode I/O, which this channel does not support: a blocking read would
     * wait forever for a datagram that may have been lost, with no {@code select} timeout to prompt
     * the {@link #retransmit()} the handshake needs to recover, deadlocking on the first dropped
     * packet.
     */
    private void requireNonBlocking() {
        if (isBlocking()) {
            throw new IllegalBlockingModeException();
        }
    }
}
