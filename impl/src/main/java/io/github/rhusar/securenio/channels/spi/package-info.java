/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Service-provider support for using secure channels with a {@link java.nio.channels.Selector}.
 * <p>
 * The JDK's selector implementation only accepts its own internal channel types, so the secure
 * channel decorators from the {@link io.github.rhusar.securenio.channels} package cannot be
 * registered with a system selector directly. The
 * {@link io.github.rhusar.securenio.channels.spi.DelegatingSelectorProvider} solves this by opening
 * selectors that delegate all operations to a real system selector while intercepting channel
 * registration: when a secure channel is registered, its underlying raw channel is registered with
 * the real selector instead, so the returned {@link java.nio.channels.SelectionKey} reflects the
 * readiness of the raw transport.
 *
 * @author Radoslav Husar
 */
package io.github.rhusar.securenio.channels.spi;
