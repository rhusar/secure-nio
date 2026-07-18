/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

/**
 * Internal engine that orchestrates all TLS/SSL protocol mechanics: handshake state machines,
 * payload encryption, payload decryption, and delegated computational tasks.
 * <p>
 * This class wraps a raw {@link SocketChannel} and an {@link SSLEngine}, managing four internal
 * byte buffers for network inbound/outbound data and decryption/encryption scratchpads.
 *
 * @author Radoslav Husar
 */
final class TLSByteChannel {

    /** Empty source buffer used when wrapping the {@code close_notify} alert, which carries no payload. */
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    /**
     * Defensive bound on engine cycles per loop, mirroring {@link DTLSByteChannel}: the engine
     * normally guarantees progress, but records that decrypt to zero plaintext (TLS 1.3
     * {@code NewSessionTicket}, {@code KeyUpdate}) consume none of the caller's buffer, so a peer
     * streaming them could otherwise keep a thread inside the loop for as long as it keeps sending,
     * never returning to the selector and starving every other connection served by that thread.
     * When the bound is hit, control returns to the caller and processing resumes on the next read
     * or write.
     */
    private static final int MAX_ENGINE_LOOPS = 256;

    private final SocketChannel rawChannel;
    private final SSLEngine engine;
    private final ExecutorService taskExecutor;

    // Buffers are sized from the initial session and re-grown when the engine expands the
    // session's buffer sizes, which JSSE does upon receiving a record larger than the spec
    // maximum but within its large-record tolerance (twice the maximum, for interoperability
    // with old buggy stacks). The encryption scratchpad is exempt: it is only ever an empty
    // wrap source used to pump the handshake.
    private ByteBuffer networkInboundStore;
    private ByteBuffer networkOutboundStore;
    private ByteBuffer decryptionScratchpad;
    private final ByteBuffer encryptionScratchpad;

    TLSByteChannel(SocketChannel rawChannel, SSLEngine engine, ExecutorService taskExecutor) {
        this.rawChannel = rawChannel;
        this.engine = engine;
        this.taskExecutor = taskExecutor;

        SSLSession session = engine.getSession();
        int packetSize = session.getPacketBufferSize();
        int appSize = session.getApplicationBufferSize();

        this.networkInboundStore = ByteBuffer.allocate(packetSize);
        this.networkOutboundStore = ByteBuffer.allocate(packetSize);
        this.networkOutboundStore.flip();

        this.decryptionScratchpad = ByteBuffer.allocate(appSize);
        this.encryptionScratchpad = ByteBuffer.allocate(appSize);
        this.encryptionScratchpad.flip();
    }

    /**
     * Decrypts data from the network and deposits plaintext into the application region.
     *
     * @return total network bytes consumed, or -1 if end-of-stream
     */
    int decrypt(ByteBuffer applicationInputRegion) throws IOException {
        int startPosition = applicationInputRegion.position();

        // Drain residual decrypted data from previous cycle
        transferFromScratchpad(applicationInputRegion);

        int decrypted;
        int encrypted;
        int cycles = 0;

        // Each callee is internally capped at MAX_ENGINE_LOOPS, but this alternation re-enters
        // them whenever network progress was made, so it must be bounded as well or a sustained
        // zero-plaintext record stream would defeat those caps.
        do {
            decrypted = performDecryption();
            encrypted = performEncryption(encryptionScratchpad);
        } while ((decrypted > 0 || (encrypted > 0 && networkOutboundStore.hasRemaining() && networkInboundStore.hasRemaining()))
                && ++cycles < MAX_ENGINE_LOOPS);

        // Transfer newly decrypted data to the caller's buffer
        transferFromScratchpad(applicationInputRegion);

        // If end-of-stream was reached but plaintext was delivered to the caller in this call
        // (residual from a previous cycle and/or freshly decrypted bytes), report that byte count
        // now and defer the -1 to the next read. Returning -1 here would make the caller discard
        // the bytes already placed in their buffer, violating the ReadableByteChannel contract.
        if (decrypted < 0 && applicationInputRegion.position() > startPosition) {
            return applicationInputRegion.position() - startPosition;
        }

        return decrypted;
    }

    private void transferFromScratchpad(ByteBuffer destination) {
        if (decryptionScratchpad.position() > 0) {
            decryptionScratchpad.flip();
            int transferable = Math.min(decryptionScratchpad.remaining(), destination.remaining());
            if (transferable > 0) {
                int oldLimit = decryptionScratchpad.limit();
                decryptionScratchpad.limit(decryptionScratchpad.position() + transferable);
                destination.put(decryptionScratchpad);
                decryptionScratchpad.limit(oldLimit);
            }
            decryptionScratchpad.compact();
        }
    }

    /**
     * Encrypts application data and transmits it to the network.
     *
     * @return total network bytes sent, or -1 if the channel is closed
     */
    int encrypt(ByteBuffer applicationOutboundRegion) throws IOException {
        int encrypted = performEncryption(applicationOutboundRegion);
        performDecryption();
        return encrypted;
    }

    /**
     * Initiates an orderly TLS shutdown by transmitting a {@code close_notify} alert to the peer.
     * <p>
     * Per the TLS spec (RFC 5246 §7.2.1, RFC 8446 §6.1) a peer must announce its intent to close
     * with a {@code close_notify} alert; otherwise the connection looks like a truncation attack to
     * a compliant peer. {@link SSLEngine#closeOutbound()} queues that alert, which this method then
     * wraps and flushes to the network. The raw socket must remain open until the alert has been
     * transmitted, so this must be called <em>before</em> closing the underlying channel.
     */
    void closeOutbound() throws IOException {
        engine.closeOutbound();

        // Drain the close_notify alert queued by closeOutbound() to the network. wrap() emits it and
        // reports CLOSED; on a non-blocking channel that cannot accept it all right now this is
        // best-effort, since we must not block the close path indefinitely.
        while (!engine.isOutboundDone()) {
            networkOutboundStore.compact();
            SSLEngineResult result = engine.wrap(EMPTY, networkOutboundStore);
            networkOutboundStore.flip();

            if (networkOutboundStore.hasRemaining()) {
                int written = transmitToNetwork(networkOutboundStore);
                if (written < 0 || networkOutboundStore.hasRemaining()) {
                    // Peer gone or socket cannot drain further without blocking.
                    break;
                }
            }

            // A wrap that produced nothing and did not close cannot make progress by re-looping —
            // e.g. an engine wedged mid-handshake after a fatal error keeps reporting OK with zero
            // bytes while isOutboundDone() stays false, which would spin this loop forever.
            if (result.getStatus() == SSLEngineResult.Status.CLOSED || result.bytesProduced() == 0) {
                break;
            }
        }
    }

    /**
     * Shuts down the TLS engine. Faults are suppressed by design: {@code closeInbound()} throws an
     * {@code SSLException} whenever the peer's {@code close_notify} has not arrived, which is
     * routine on a locally initiated close and not actionable once the raw socket is gone.
     */
    void shutdown() {
        try {
            engine.closeInbound();
        } catch (Exception ignored) {
        }
        try {
            engine.closeOutbound();
        } catch (Exception ignored) {
        }
    }

    private int performDecryption() throws IOException {
        int totalReadFromNetwork = 0;
        int loops = 0;

        outer:
        do {
            // Phase 1: Ingest encrypted data from network
            int sessionBytesRead = 0;
            while (networkInboundStore.hasRemaining()) {
                int bytesFromNetwork = rawChannel.read(networkInboundStore);
                if (bytesFromNetwork <= 0) {
                    if (bytesFromNetwork < 0 && sessionBytesRead == 0 && totalReadFromNetwork == 0) {
                        // End-of-stream on the raw channel. Per the TLS spec (RFC 5246 §7.2.1,
                        // RFC 8446 §6.1), an EOF that arrives before the peer's close_notify alert
                        // must be treated as an error rather than a clean end-of-stream: an active
                        // attacker who cannot decrypt the traffic can still inject a TCP FIN/RST to
                        // silently truncate the tail of a message. closeInbound() raises an
                        // SSLException in exactly that case; if close_notify was already received it
                        // is a harmless no-op and we report the clean end-of-stream.
                        engine.closeInbound();
                        return bytesFromNetwork;
                    }
                    break;
                } else {
                    sessionBytesRead += bytesFromNetwork;
                }
            }

            // Phase 2: Attempt TLS decryption
            networkInboundStore.flip();
            try {
                if (!networkInboundStore.hasRemaining()) {
                    return totalReadFromNetwork;
                }

                totalReadFromNetwork += sessionBytesRead;

                SSLEngineResult result = engine.unwrap(networkInboundStore, decryptionScratchpad);

                // Phase 3: Interpret result
                switch (result.getStatus()) {
                    case OK:
                        switch (result.getHandshakeStatus()) {
                            case NEED_UNWRAP:
                                continue;
                            case NEED_WRAP:
                                break outer;
                            case NEED_TASK:
                                DelegatedTasks.run(engine, taskExecutor);
                                continue;
                            case NOT_HANDSHAKING:
                            case FINISHED:
                                continue;
                        }
                        break;

                    case BUFFER_OVERFLOW:
                        // If the scratchpad's capacity accommodates a full application record
                        // beyond the plaintext it already holds, the overflow only means that
                        // plaintext has not been drained yet — stop so the caller can drain it.
                        // Otherwise the engine expanded the session's application buffer size
                        // and the scratchpad must grow, or the record can never be unwrapped.
                        int applicationSize = engine.getSession().getApplicationBufferSize();
                        if (applicationSize + decryptionScratchpad.position() <= decryptionScratchpad.capacity()) {
                            break outer;
                        }
                        ByteBuffer enlargedScratchpad = ByteBuffer.allocate(applicationSize + decryptionScratchpad.position());
                        decryptionScratchpad.flip();
                        enlargedScratchpad.put(decryptionScratchpad);
                        decryptionScratchpad = enlargedScratchpad;
                        continue;

                    case CLOSED:
                        if (totalReadFromNetwork == 0) {
                            return -1;
                        } else {
                            return totalReadFromNetwork;
                        }

                    case BUFFER_UNDERFLOW:
                        // The engine expands the session's packet size upon seeing the header of
                        // a record larger than the buffer this store was sized from (tolerated up
                        // to twice the spec maximum, for interoperability with old buggy stacks).
                        // The store must grow along with it: at its original capacity the record
                        // could never fit, so every subsequent read would report underflow with
                        // the record's tail still pending in the kernel — a level-triggered
                        // selector would fire forever, spinning the CPU at 100% without progress.
                        int packetSize = engine.getSession().getPacketBufferSize();
                        if (packetSize > networkInboundStore.capacity()) {
                            ByteBuffer enlargedStore = ByteBuffer.allocate(packetSize);
                            enlargedStore.put(networkInboundStore);
                            enlargedStore.flip();
                            networkInboundStore = enlargedStore;
                            continue;
                        }
                        // A partial TLS record remains in the inbound buffer and the engine needs
                        // more bytes to decrypt it. If no new data arrived from the network this
                        // iteration, re-looping cannot make progress and would spin the CPU at 100%.
                        // This is remotely triggerable: a peer can send the first few bytes of a
                        // record header, then go quiet, pinning a server thread indefinitely (DoS).
                        // Return to the caller instead; decryption resumes once the selector signals
                        // that more readable data has arrived.
                        if (sessionBytesRead == 0) {
                            return totalReadFromNetwork;
                        }
                }
            } finally {
                networkInboundStore.compact();
            }
        } while (decryptionScratchpad.hasRemaining() && ++loops < MAX_ENGINE_LOOPS);

        return totalReadFromNetwork;
    }

    private int performEncryption(ByteBuffer applicationOutboundRegion) throws IOException {
        int totalWrittenToNetwork = 0;

        // Phase 1: Flush any previously encrypted but unsent data
        if (networkOutboundStore.hasRemaining()) {
            int flushed = transmitToNetwork(networkOutboundStore);
            if (flushed < 0) {
                return flushed;
            }
            totalWrittenToNetwork += flushed;
        }

        // Phase 2: Encrypt and transmit application data
        encryptCycle:
        for (int loops = 0; loops < MAX_ENGINE_LOOPS; loops++) {
            networkOutboundStore.compact();

            SSLEngineResult result = engine.wrap(applicationOutboundRegion, networkOutboundStore);

            networkOutboundStore.flip();

            // Phase 2a: Transmit any newly encrypted data
            if (networkOutboundStore.hasRemaining()) {
                int written = transmitToNetwork(networkOutboundStore);
                if (written < 0) {
                    if (totalWrittenToNetwork == 0) {
                        return written;
                    } else {
                        return totalWrittenToNetwork;
                    }
                } else {
                    totalWrittenToNetwork += written;
                }
            }

            // Phase 2b: Interpret result
            switch (result.getStatus()) {
                case OK:
                    switch (result.getHandshakeStatus()) {
                        case NEED_WRAP:
                            continue;
                        case NEED_UNWRAP:
                            break encryptCycle;
                        case NEED_TASK:
                            DelegatedTasks.run(engine, taskExecutor);
                            continue;
                        case NOT_HANDSHAKING:
                        case FINISHED:
                            if (applicationOutboundRegion.hasRemaining()) {
                                continue;
                            } else {
                                break encryptCycle;
                            }
                    }
                    break;

                case BUFFER_OVERFLOW:
                    // If the store's capacity accommodates a full packet beyond the unsent bytes
                    // it already holds, the overflow is due to that backlog — stop and wait for
                    // the socket to drain. Otherwise the engine expanded the session's packet
                    // size and the store must grow, or wrap could never make progress. (JSSE
                    // never wraps beyond the spec maximum the store was sized for, so the growth
                    // path is defensive.)
                    int packetSize = engine.getSession().getPacketBufferSize();
                    if (packetSize + networkOutboundStore.remaining() <= networkOutboundStore.capacity()) {
                        break encryptCycle;
                    }
                    ByteBuffer enlargedStore = ByteBuffer.allocate(packetSize + networkOutboundStore.remaining());
                    enlargedStore.put(networkOutboundStore);
                    enlargedStore.flip();
                    networkOutboundStore = enlargedStore;
                    continue;

                case BUFFER_UNDERFLOW, CLOSED:
                    break encryptCycle;
            }
        }

        return totalWrittenToNetwork;
    }

    private int transmitToNetwork(ByteBuffer sourceRegion) throws IOException {
        int totalWritten = 0;
        while (sourceRegion.hasRemaining()) {
            int written = rawChannel.write(sourceRegion);
            if (written == 0) {
                break;
            } else if (written < 0) {
                if (totalWritten == 0) {
                    return written;
                } else {
                    return totalWritten;
                }
            }
            totalWritten += written;
        }
        return totalWritten;
    }
}
