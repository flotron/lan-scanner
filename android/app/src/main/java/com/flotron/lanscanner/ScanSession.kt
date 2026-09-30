package com.flotron.lanscanner

import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** A stop signal belongs to one scan, never to the next scan using the same workers. */
internal class ScanSession(val generation: Long) {
    val cancelled = AtomicBoolean(false)
    fun check() {
        if (cancelled.get() || Thread.currentThread().isInterrupted) throw CancellationException()
    }

    fun <T> run(pool: ExecutorService, tasks: List<Callable<T>>, timeoutMs: Long, allowPartial: Boolean = false) {
        check()
        val futures = tasks.map { task -> pool.submit(Callable { check(); task.call() }) }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        try {
            while (futures.any { !it.isDone }) {
                check()
                if (System.nanoTime() >= deadline) {
                    if (allowPartial) return
                    throw TimeoutException("Scan batch timed out")
                }
                Thread.sleep(50)
            }
            check()
            futures.forEach { it.get() }
        } finally {
            futures.forEach { if (!it.isDone) it.cancel(true) }
            (pool as? ThreadPoolExecutor)?.purge()
        }
    }
}
