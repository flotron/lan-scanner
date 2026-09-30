package com.flotron.lanscanner

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger

class ScanSessionTest {
    @Test(timeout = 5000) fun stopCancelsActiveAndQueuedWorkAndAllowsNewScan() {
        val pool = Executors.newFixedThreadPool(2)
        val coordinator = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(2)
        val interrupted = CountDownLatch(2)
        val session = ScanSession(1)
        val started = AtomicInteger()
        try {
            val running = coordinator.submit(Callable {
                try {
                    session.run(pool, List(510) { Callable {
                        started.incrementAndGet()
                        entered.countDown()
                        try { CountDownLatch(1).await() } catch (e: InterruptedException) {
                            interrupted.countDown(); throw e
                        }
                    } }, 30_000)
                    false
                } catch (_: CancellationException) { true }
            })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            session.cancelled.set(true)
            assertTrue(running.get(2, TimeUnit.SECONDS))
            assertTrue(interrupted.await(2, TimeUnit.SECONDS))
            assertEquals(2, started.get())
            val next = AtomicInteger()
            ScanSession(2).run(pool, List(10) { Callable { next.incrementAndGet() } }, 1000)
            assertEquals(10, next.get())
        } finally { pool.shutdownNow(); coordinator.shutdownNow() }
    }

    @Test(timeout = 3000) fun optionalNamesHaveABoundedDeadline() {
        val pool = Executors.newSingleThreadExecutor()
        try {
            ScanSession(1).run(pool, listOf(Callable { CountDownLatch(1).await() }), 100, allowPartial = true)
            assertEquals(42, pool.submit(Callable { 42 }).get(1, TimeUnit.SECONDS))
        } finally { pool.shutdownNow() }
    }
}
