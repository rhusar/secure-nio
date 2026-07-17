/*
 * Copyright Radoslav Husar and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.rhusar.securenio.channels;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

import javax.net.ssl.SSLEngine;

/**
 * Runs an {@link SSLEngine}'s delegated (potentially long-running) handshake tasks to completion.
 *
 * @author Radoslav Husar
 */
final class DelegatedTasks {

    /**
     * Runs the engine's delegated handshake tasks to completion.
     * <p>
     * Tasks are offloaded to the task executor and this method blocks until they finish. It must
     * not return while a task is still pending: until every task completes the engine's handshake
     * status stays {@code NEED_TASK}, so the wrap/unwrap loop that called this would make no progress
     * and spin the CPU at 100%. If the executor cannot accept a task (for example it has been shut
     * down, which otherwise surfaces as an unchecked {@link RejectedExecutionException} escaping a
     * read or write), the task is run inline so the handshake can still complete.
     */
    static void run(SSLEngine engine, ExecutorService taskExecutor) throws IOException {
        Runnable task;
        List<Future<?>> pending = null;
        while ((task = engine.getDelegatedTask()) != null) {
            try {
                Future<?> future = taskExecutor.submit(task);
                if (pending == null) {
                    pending = new ArrayList<>();
                }
                pending.add(future);
            } catch (RejectedExecutionException rejected) {
                // Executor unavailable (e.g. shut down): run the task inline rather than letting the
                // rejection escape or leaving the handshake permanently stuck on NEED_TASK.
                task.run();
            }
        }

        if (pending == null) {
            return;
        }

        for (Future<?> future : pending) {
            try {
                future.get();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while awaiting TLS handshake task completion", interrupted);
            } catch (ExecutionException failed) {
                throw new IOException("TLS handshake task failed", failed.getCause());
            }
        }
    }

    private DelegatedTasks() {
        // Static utility.
    }
}
