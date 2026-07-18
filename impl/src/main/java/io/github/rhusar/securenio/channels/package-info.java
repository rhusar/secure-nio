/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Secure NIO channel decorators that transparently add TLS and DTLS encryption to standard
 * {@link java.nio.channels} types.
 * <p>
 * The package provides drop-in replacements for the plain NIO channels:
 * {@link io.github.rhusar.securenio.channels.SecureSocketChannel} wraps a
 * {@link java.nio.channels.SocketChannel} with TLS,
 * {@link io.github.rhusar.securenio.channels.SecureServerSocketChannel} wraps a
 * {@link java.nio.channels.ServerSocketChannel} and accepts TLS-secured connections, and
 * {@link io.github.rhusar.securenio.channels.SecureDatagramChannel} wraps a
 * {@link java.nio.channels.DatagramChannel} with DTLS. All cryptographic operations are driven by a
 * {@link javax.net.ssl.SSLEngine} internally; application code reads and writes plaintext through the
 * familiar channel API while encrypted records flow over the underlying raw channel.
 * <p>
 * The secure channels support non-blocking mode only and are designed to be driven by a
 * {@link java.nio.channels.Selector}. Since a secure channel cannot itself be registered with a
 * selector, the underlying raw channel is registered instead, with the secure channel attached to the
 * resulting {@link java.nio.channels.SelectionKey}; alternatively, the
 * {@link io.github.rhusar.securenio.channels.spi} package provides a selector that accepts secure
 * channel registrations directly and performs this delegation automatically.
 *
 * @author Radoslav Husar
 */
package io.github.rhusar.securenio.channels;
