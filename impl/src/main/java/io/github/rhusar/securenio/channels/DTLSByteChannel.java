/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

/**
 * Internal engine that orchestrates all DTLS protocol mechanics: handshake state machines,
 * payload encryption, payload decryption, and delegated computational tasks.
 * <p>
 * This class wraps a raw connected {@link DatagramChannel} and a DTLS-mode {@link SSLEngine}.
 * Unlike its stream sibling {@link TLSByteChannel}, it preserves datagram and record boundaries:
 * each {@code wrap} produces exactly one datagram that is transmitted whole, and each
 * {@code decrypt} delivers at most one application record. When a peer coalesces several
 * application records into a single datagram, the surplus records are retained and delivered one
 * per subsequent {@code decrypt} call rather than concatenated into one read. There is no
 * partial-record accumulation (UDP delivers whole datagrams or nothing), no end-of-stream or
 * truncation handling (UDP has no EOF), and plaintext of a single record exceeding the caller's
 * buffer is discarded per standard datagram truncation semantics rather than carried over.
 * <p>
 * The DTLS engine has no retransmission timer of its own: when a handshake flight is lost, the
 * caller must invoke {@link #retransmit()} after a timeout to make the engine reproduce it.
 *
 * @author Radoslav Husar
 */
final class DTLSByteChannel {

    /** Empty source buffer used when wrapping handshake flights and alerts, which carry no payload. */
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    /**
     * Defensive bound on wrap/unwrap cycles per call, mirroring the JDK's own DTLS examples: the
     * engine normally guarantees progress, but a misbehaving peer must not be able to pin a thread
     * in an unbounded engine loop.
     */
    private static final int MAX_ENGINE_LOOPS = 256;

    private final DatagramChannel rawChannel;
    private final SSLEngine engine;
    private final ExecutorService taskExecutor;

    // Buffers are sized from the initial session and re-grown on BUFFER_OVERFLOW: the negotiated
    // session's buffer sizes can exceed the pre-handshake session's.
    /**
     * Holds at most one received datagram at a time. Records not yet unwrapped — the surplus of a
     * coalesced datagram — remain between its position and limit across {@code decrypt} calls.
     */
    private final ByteBuffer networkInboundStore;
    /** Holds at most one wrapped datagram awaiting transmission; never accumulates a second. */
    private ByteBuffer networkOutboundStore;
    private ByteBuffer decryptionScratchpad;

    DTLSByteChannel(DatagramChannel rawChannel, SSLEngine engine, ExecutorService taskExecutor) {
        this.rawChannel = rawChannel;
        this.engine = engine;
        this.taskExecutor = taskExecutor;

        SSLSession session = engine.getSession();

        this.networkInboundStore = ByteBuffer.allocate(session.getPacketBufferSize());
        this.networkInboundStore.flip();
        this.networkOutboundStore = ByteBuffer.allocate(session.getPacketBufferSize());
        this.networkOutboundStore.flip();

        this.decryptionScratchpad = ByteBuffer.allocate(session.getApplicationBufferSize());
    }

    /**
     * Receives and decrypts at most one datagram, depositing plaintext into the application region.
     * Handshake flights are processed transparently, including emitting responding flights.
     * <p>
     * At most one application record is delivered per call. When the datagram coalesces several
     * application records, the surplus is retained and delivered by subsequent calls — which drain
     * it before touching the network — so callers should keep reading until 0 is returned.
     *
     * @return plaintext bytes delivered, 0 if no datagram arrived or it carried only handshake
     *         records, or -1 if the peer has closed the session with a {@code close_notify} alert
     */
    int decrypt(ByteBuffer applicationInputRegion) throws IOException {
        if (engine.isInboundDone()) {
            return -1;
        }

        // Records retained from a previously received coalesced datagram are drained first; a new
        // datagram is received only once the store is empty.
        if (!networkInboundStore.hasRemaining()) {
            networkInboundStore.clear();
            int received = rawChannel.read(networkInboundStore);
            networkInboundStore.flip();

            // Nothing arrived (non-blocking read; UDP has no end-of-stream, so a negative return is
            // treated the same). Still enter the unwrap loop when the engine holds internally buffered
            // reordered records (NEED_UNWRAP_AGAIN) — those must be processed without new network data.
            if (received <= 0 && engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return 0;
            }
        }

        boolean closed = false;
        int loops = 0;

        unwrapLoop:
        while ((networkInboundStore.hasRemaining()
                || engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN)
                && loops++ < MAX_ENGINE_LOOPS) {

            SSLEngineResult result = engine.unwrap(networkInboundStore, decryptionScratchpad);

            switch (result.getStatus()) {
                case OK:
                    switch (result.getHandshakeStatus()) {
                        case NEED_TASK:
                            DelegatedTasks.run(engine, taskExecutor);
                            continue;
                        case NEED_WRAP:
                            // Emit the responding flight, then keep draining any records remaining
                            // in this datagram. If the flight could not be fully transmitted (a
                            // datagram is still pending), stop — wrapping further would merge
                            // datagrams; transmission resumes on the next write/flush/retransmit.
                            performEncryption(EMPTY);
                            if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                                break unwrapLoop;
                            }
                            continue;
                        default:
                            // NEED_UNWRAP, NEED_UNWRAP_AGAIN, FINISHED, NOT_HANDSHAKING: a datagram
                            // may carry a coalesced multi-record flight — keep draining. An
                            // application record instead ends the loop: it is delivered on its own,
                            // and any records after it stay in the store for the next call.
                            if (result.bytesProduced() > 0) {
                                break unwrapLoop;
                            }
                            continue;
                    }

                case BUFFER_UNDERFLOW:
                    // In DTLS this signals a truncated or garbage datagram, not a partial stream
                    // record — UDP delivers whole datagrams. Drop the rest of it.
                    networkInboundStore.position(networkInboundStore.limit());
                    break unwrapLoop;

                case BUFFER_OVERFLOW:
                    // The negotiated session needs a larger application buffer than the
                    // pre-handshake session it was sized from; grow and retry.
                    int applicationSize = engine.getSession().getApplicationBufferSize();
                    if (applicationSize + decryptionScratchpad.position() <= decryptionScratchpad.capacity()) {
                        break unwrapLoop;
                    }
                    ByteBuffer enlarged = ByteBuffer.allocate(applicationSize + decryptionScratchpad.position());
                    decryptionScratchpad.flip();
                    enlarged.put(decryptionScratchpad);
                    decryptionScratchpad = enlarged;
                    continue;

                case CLOSED:
                    closed = true;
                    break unwrapLoop;
            }
        }

        // The loop can exit still owing the peer a flight — e.g. a NEED_TASK transition that ends
        // in NEED_WRAP once the datagram is fully consumed (also the responding close_notify after
        // CLOSED). Emit it now, or the handshake deadlocks with both sides waiting.
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            performEncryption(EMPTY);
        }

        int delivered = transferToCaller(applicationInputRegion);
        if (closed && delivered == 0) {
            return -1;
        }
        return delivered;
    }

    /**
     * Encrypts application data into a single datagram and transmits it. During the handshake no
     * application data is consumed; instead any outstanding handshake flights are produced and sent.
     *
     * @return application bytes consumed (0 while the handshake is in progress or the socket
     *         buffer is full)
     */
    int encrypt(ByteBuffer applicationOutboundRegion) throws IOException {
        return performEncryption(applicationOutboundRegion);
    }

    /**
     * Re-produces and transmits the engine's previous handshake flight. The DTLS engine has no
     * timer, so the caller invokes this when its select timeout expires without handshake progress,
     * indicating the flight (or the peer's response) was lost. No-op when not handshaking.
     */
    void retransmit() throws IOException {
        if (!isHandshaking() || engine.isOutboundDone()) {
            return;
        }

        // The engine reproduces the previous flight one datagram per wrap and reports NEED_WRAP
        // while more of it remains. Stop on any other status: wrapping again while NEED_UNWRAP
        // would start reproducing the flight anew, spinning forever.
        for (int i = 0; i < MAX_ENGINE_LOOPS; i++) {
            if (!transmitPending()) {
                return;
            }

            networkOutboundStore.clear();
            SSLEngineResult result = engine.wrap(EMPTY, networkOutboundStore);
            networkOutboundStore.flip();

            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                DelegatedTasks.run(engine, taskExecutor);
                continue;
            }

            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                int packetSize = engine.getSession().getPacketBufferSize();
                if (packetSize <= networkOutboundStore.capacity()) {
                    return;
                }
                networkOutboundStore = ByteBuffer.allocate(packetSize);
                networkOutboundStore.flip();
                continue;
            }

            transmitPending();

            if (result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                return;
            }
        }
    }

    boolean isHandshaking() {
        return engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    /**
     * Initiates DTLS shutdown by transmitting a {@code close_notify} alert to the peer.
     * <p>
     * Unlike the stream variant there is no drain loop: the alert is a single datagram that may be
     * lost in transit, and DTLS peers must tolerate that — delivery is strictly best-effort.
     */
    void closeOutbound() throws IOException {
        engine.closeOutbound();

        // A pending datagram that cannot be sent right now also blocks the alert; give up rather
        // than merge them or block the close path.
        if (!transmitPending()) {
            return;
        }

        networkOutboundStore.clear();
        engine.wrap(EMPTY, networkOutboundStore);
        networkOutboundStore.flip();
        transmitPending();
    }

    /**
     * Shuts down the DTLS engine. Faults are suppressed by design: {@code closeInbound()} throws an
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

    private int performEncryption(ByteBuffer applicationOutboundRegion) throws IOException {
        int startPosition = applicationOutboundRegion.position();

        // While the engine awaits peer data there is nothing useful to wrap: application data
        // cannot be encrypted yet, and an empty wrap would re-produce the previous flight —
        // repeated writes would flood the peer with retransmissions. Retransmission on loss is
        // the caller's explicit decision via retransmit().
        SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
        if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                || handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
            transmitPending();
            return 0;
        }

        // A previously wrapped datagram must leave before another wrap: appending to it would merge
        // two datagrams into one send, and overwriting it would lose records.
        if (!transmitPending()) {
            return 0;
        }

        encryptCycle:
        for (int loops = 0; loops < MAX_ENGINE_LOOPS; loops++) {
            networkOutboundStore.clear();

            SSLEngineResult result = engine.wrap(applicationOutboundRegion, networkOutboundStore);

            networkOutboundStore.flip();

            // Transmit the wrapped datagram whole; a connected DatagramChannel write is
            // all-or-nothing, so an unsent datagram simply stays pending.
            boolean sent = transmitPending();

            switch (result.getStatus()) {
                case OK:
                    switch (result.getHandshakeStatus()) {
                        case NEED_TASK:
                            DelegatedTasks.run(engine, taskExecutor);
                            // Only keep wrapping if the engine still has output to produce;
                            // wrapping while it awaits peer data re-produces the previous flight.
                            if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                                    || engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                                break encryptCycle;
                            }
                            continue;
                        case NEED_WRAP:
                            // Handshake flights span multiple datagrams, one per wrap.
                            if (!sent) {
                                break encryptCycle;
                            }
                            continue;
                        case FINISHED:
                        case NOT_HANDSHAKING:
                            // If this wrap only completed the handshake, wrap the caller's payload
                            // now; a positive bytesProduced guarantees loop progress.
                            if (sent && result.bytesConsumed() == 0 && result.bytesProduced() > 0
                                    && applicationOutboundRegion.hasRemaining()) {
                                continue;
                            }
                            // Application data is one datagram per encrypt() call.
                            break encryptCycle;
                        default:
                            // NEED_UNWRAP, NEED_UNWRAP_AGAIN: the peer's turn — the caller reads next.
                            break encryptCycle;
                    }

                case BUFFER_OVERFLOW:
                    // The negotiated session produces larger datagrams than the pre-handshake
                    // session the buffer was sized from; grow and retry.
                    int packetSize = engine.getSession().getPacketBufferSize();
                    if (packetSize <= networkOutboundStore.capacity()) {
                        break encryptCycle;
                    }
                    networkOutboundStore = ByteBuffer.allocate(packetSize);
                    networkOutboundStore.flip();
                    continue;

                case BUFFER_UNDERFLOW, CLOSED:
                    break encryptCycle;
            }
        }

        return applicationOutboundRegion.position() - startPosition;
    }

    /**
     * Attempts to transmit the pending outbound datagram, if any.
     *
     * @return true if the outbound store is empty (nothing was pending, or it was sent whole)
     */
    private boolean transmitPending() throws IOException {
        if (networkOutboundStore.hasRemaining()) {
            rawChannel.write(networkOutboundStore);
        }
        return !networkOutboundStore.hasRemaining();
    }

    /**
     * Transfers decrypted plaintext to the caller's buffer. Excess plaintext that does not fit is
     * discarded, matching {@link DatagramChannel} truncation semantics.
     */
    private int transferToCaller(ByteBuffer destination) {
        decryptionScratchpad.flip();
        int transferable = Math.min(decryptionScratchpad.remaining(), destination.remaining());
        if (transferable > 0) {
            int oldLimit = decryptionScratchpad.limit();
            decryptionScratchpad.limit(decryptionScratchpad.position() + transferable);
            destination.put(decryptionScratchpad);
            decryptionScratchpad.limit(oldLimit);
        }
        decryptionScratchpad.clear();
        return transferable;
    }
}
