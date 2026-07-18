/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

/**
 * An {@link SSLEngine} stub for thread-pinning tests, modelling a peer that streams records which
 * decrypt to zero plaintext (TLS 1.3 {@code NewSessionTicket}, {@code KeyUpdate}): every
 * {@code unwrap()} consumes one small record's worth of ciphertext and produces nothing, reporting
 * a completed handshake throughout, and {@code wrap()} produces nothing. Buffer sizing is served
 * by a real pre-handshake {@link SSLSession}.
 *
 * @author Radoslav Husar
 */
class ZeroPlaintextSSLEngine extends SSLEngine {

    /** Ciphertext consumed per unwrap, standing in for one small zero-plaintext record. */
    private static final int RECORD_SIZE = 16;

    private final SSLSession session;
    private boolean outboundDone;

    ZeroPlaintextSSLEngine(SSLSession session) {
        this.session = session;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
        int consumed = Math.min(RECORD_SIZE, src.remaining());
        src.position(src.position() + consumed);
        return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, consumed, 0);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    @Override
    public Runnable getDelegatedTask() {
        return null;
    }

    @Override
    public void closeInbound() {
    }

    @Override
    public boolean isInboundDone() {
        return false;
    }

    @Override
    public void closeOutbound() {
        outboundDone = true;
    }

    @Override
    public boolean isOutboundDone() {
        return outboundDone;
    }

    @Override
    public void beginHandshake() {
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
    }

    @Override
    public void setUseClientMode(boolean mode) {
    }

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }
}
