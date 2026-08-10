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

    runtime.aecDacSessions[77L] = AecDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AecDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.markAecDacSessionCompleted(99L, 1500)
    assertEquals(1, runtime.aecDacSessions.size)
    assertEquals(1, runtime.completedAecDacSessions.size)

    runtime.stop()
    assertTrue(firstExecutor.isShutdown)
    assertEquals(0, runtime.aecDacSessions.size)
    assertEquals(0, runtime.completedAecDacSessions.size)

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
    runtime.aecDacSessions[77L] = AecDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AecDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.aecDacSessions[88L] = AecDacSession(
      peerName = "peer-b",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(5, 6, 7, 8),
      rootLaneId = 9L,
      remote = AecDacPeer("127.0.0.1", 48376),
      createdAtMillis = 9_000,
    )
    runtime.markAecDacSessionCompleted(99L, 1_000)
    runtime.markAecDacSessionCompleted(111L, 9_000)

    runtime.pruneExpiredAecDacSessions(nowMillis = 16_000, maxAgeMillis = 10_000)

    assertEquals(1, runtime.aecDacSessions.size)
    assertTrue(runtime.aecDacSessions.containsKey(88L))
    assertEquals(1, runtime.completedAecDacSessions.size)
    assertTrue(runtime.completedAecDacSessions.containsKey(111L))

    runtime.stop()
  }

  @Test
  fun consumeSessionRemovesSingleUseBinding() {
    val runtime = BifrostNodeRuntimeState()
    val session = AecDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AecDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.aecDacSessions[77L] = session

    assertTrue(runtime.consumeAecDacSession(77L, session))
    assertEquals(0, runtime.aecDacSessions.size)
    assertTrue(!runtime.consumeAecDacSession(77L, session))

    runtime.stop()
  }

  @Test
  fun completedSessionStateTracksRecentReplayFence() {
    val runtime = BifrostNodeRuntimeState()

    assertTrue(!runtime.isAecDacSessionCompleted(77L))
    runtime.markAecDacSessionCompleted(77L, 1_000)
    assertTrue(runtime.isAecDacSessionCompleted(77L))

    runtime.pruneExpiredAecDacSessions(nowMillis = 20_000, maxAgeMillis = 10_000)
    assertTrue(!runtime.isAecDacSessionCompleted(77L))

    runtime.stop()
  }
}
