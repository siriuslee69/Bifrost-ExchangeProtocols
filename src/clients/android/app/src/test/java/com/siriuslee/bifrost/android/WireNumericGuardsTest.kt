package com.siriuslee.bifrost.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WireNumericGuardsTest {
  @Test
  fun wireU32GuardsAcceptFullRangeAndRejectSignedOverflow() {
    assertEquals(0L, requireWireU32("field", 0))
    assertEquals(0xffff_ffffL, requireWireU32("field", 0xffff_ffffL))
    assertEquals(-1, requireWireU32Int("field", 0xffff_ffffL))

    assertFails { requireWireU32("field", -1) }
    assertFails { requireWireU32("field", 0x1_0000_0000L) }
  }

  @Test
  fun wireByteArrayLengthRejectsUnsignedLengthsThatCannotFitJvmArrays() {
    assertEquals(Int.MAX_VALUE, requireWireByteArrayLen("payload length", Int.MAX_VALUE.toLong()))

    val failure = expectIllegalArgument {
      requireWireByteArrayLen("payload length", 0xffff_ffffL)
    }
    assertTrue(failure.message.orEmpty().contains("payload length out of range for byte-array length"))
  }

  @Test
  fun intBitsToWireU32PreservesUnsignedLaneBits() {
    assertEquals(0xffff_ffffL, intBitsToWireU32(-1))
    assertEquals(0xE0000001L, intBitsToWireU32(0xE0000001L.toInt()))
  }

  private fun expectIllegalArgument(block: () -> Unit): IllegalArgumentException {
    try {
      block()
    } catch (failure: IllegalArgumentException) {
      return failure
    }
    throw AssertionError("expected IllegalArgumentException")
  }

  private fun assertFails(block: () -> Unit) {
    var failed = false
    try {
      block()
    } catch (_: IllegalArgumentException) {
      failed = true
    }
    assertTrue(failed)
  }
}
