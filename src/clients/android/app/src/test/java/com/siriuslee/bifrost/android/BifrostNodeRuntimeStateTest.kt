package com.siriuslee.bifrost.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class BifrostNodeRuntimeStateTest {
  @Test
  fun stopClearsSessionsAndNextExecutorCallRecreatesWorkerPool() {
    val runtime = BifrostNodeRuntimeState()
    val firstExecutor = runtime.executor()
    val beforeStop = CountDownLatch(1)

    firstExecutor.execute { beforeStop.countDown() }
    assertTrue(beforeStop.await(2, TimeUnit.SECONDS))

    runtime.ameDacSessions[77L] = AmeDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AmeDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.markAmeDacSessionCompleted(99L, 1500)
    assertEquals(1, runtime.ameDacSessions.size)
    assertEquals(1, runtime.completedAmeDacSessions.size)

    runtime.stop()
    assertTrue(firstExecutor.isShutdown)
    assertEquals(0, runtime.ameDacSessions.size)
    assertEquals(0, runtime.completedAmeDacSessions.size)

    val secondExecutor = runtime.executor()
    assertNotSame(firstExecutor, secondExecutor)
    val afterStop = CountDownLatch(1)
    secondExecutor.execute { afterStop.countDown() }
    assertTrue(afterStop.await(2, TimeUnit.SECONDS))

    runtime.stop()
  }

  @Test
  fun pruneExpiredSessionsDropsOnlyStaleBindings() {
    val runtime = BifrostNodeRuntimeState()
    runtime.ameDacSessions[77L] = AmeDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AmeDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.ameDacSessions[88L] = AmeDacSession(
      peerName = "peer-b",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(5, 6, 7, 8),
      rootLaneId = 9L,
      remote = AmeDacPeer("127.0.0.1", 48376),
      createdAtMillis = 9_000,
    )
    runtime.markAmeDacSessionCompleted(99L, 1_000)
    runtime.markAmeDacSessionCompleted(111L, 9_000)

    runtime.pruneExpiredAmeDacSessions(nowMillis = 16_000, maxAgeMillis = 10_000)

    assertEquals(1, runtime.ameDacSessions.size)
    assertTrue(runtime.ameDacSessions.containsKey(88L))
    assertEquals(1, runtime.completedAmeDacSessions.size)
    assertTrue(runtime.completedAmeDacSessions.containsKey(111L))

    runtime.stop()
  }

  @Test
  fun consumeSessionRemovesSingleUseBinding() {
    val runtime = BifrostNodeRuntimeState()
    val session = AmeDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AmeDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.ameDacSessions[77L] = session

    assertTrue(runtime.consumeAmeDacSession(77L, session))
    assertEquals(0, runtime.ameDacSessions.size)
    assertTrue(!runtime.consumeAmeDacSession(77L, session))

    runtime.stop()
  }

  @Test
  fun completedSessionStateTracksRecentReplayFence() {
    val runtime = BifrostNodeRuntimeState()

    assertTrue(!runtime.isAmeDacSessionCompleted(77L))
    runtime.markAmeDacSessionCompleted(77L, 1_000)
    assertTrue(runtime.isAmeDacSessionCompleted(77L))

    runtime.pruneExpiredAmeDacSessions(nowMillis = 20_000, maxAgeMillis = 10_000)
    assertTrue(!runtime.isAmeDacSessionCompleted(77L))

    runtime.stop()
  }
}
