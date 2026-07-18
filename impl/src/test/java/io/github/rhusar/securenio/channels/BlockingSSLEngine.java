/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * An {@link SSLEngine} decorator for concurrency tests. The first {@code wrap()} call parks on a
 * latch, keeping the calling thread (and thus the secure channel's lock) inside the engine until
 * {@link #releaseWrap()}. Every engine-driving entry point additionally records whether a second
 * thread entered while another was still inside – the race the channel's lock must prevent.
 *
 * @author Radoslav Husar
 */
class BlockingSSLEngine extends SSLEngine {

    private final SSLEngine delegate;
    private final CountDownLatch wrapEntered = new CountDownLatch(1);
    private final CountDownLatch wrapReleased = new CountDownLatch(1);
    private final AtomicBoolean firstWrap = new AtomicBoolean();
    private final AtomicBoolean insideEngine = new AtomicBoolean();
    private final AtomicBoolean concurrentAccess = new AtomicBoolean();

    BlockingSSLEngine(SSLEngine delegate) {
        this.delegate = delegate;
    }

    /**
     * Waits until a thread has entered {@code wrap()} and parked on the latch.
     */
    boolean awaitWrapEntered(long timeout, TimeUnit unit) throws InterruptedException {
        return wrapEntered.await(timeout, unit);
    }

    /**
     * Unparks the thread blocked in {@code wrap()}.
     */
    void releaseWrap() {
        wrapReleased.countDown();
    }

    /**
     * Returns whether two threads were ever inside the engine at the same time.
     */
    boolean sawConcurrentAccess() {
        return concurrentAccess.get();
    }

    private void enter() {
        if (!insideEngine.compareAndSet(false, true)) {
            concurrentAccess.set(true);
        }
    }

    private void exit() {
        insideEngine.set(false);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        enter();
        try {
            if (firstWrap.compareAndSet(false, true)) {
                wrapEntered.countDown();
                try {
                    wrapReleased.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return delegate.wrap(srcs, offset, length, dst);
        } finally {
            exit();
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        enter();
        try {
            return delegate.unwrap(src, dsts, offset, length);
        } finally {
            exit();
        }
    }

    @Override
    public void closeInbound() throws SSLException {
        enter();
        try {
            delegate.closeInbound();
        } finally {
            exit();
        }
    }

    @Override
    public void closeOutbound() {
        enter();
        try {
            delegate.closeOutbound();
        } finally {
            exit();
        }
    }

    @Override
    public Runnable getDelegatedTask() {
        return delegate.getDelegatedTask();
    }

    @Override
    public boolean isInboundDone() {
        return delegate.isInboundDone();
    }

    @Override
    public boolean isOutboundDone() {
        return delegate.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        delegate.beginHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return delegate.getHandshakeStatus();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }
}
