package com.siriuslee.bifrost.android

private const val maxWireU32 = 0xffff_ffffL
private const val maxWireU16 = 0xffff

internal fun requireWireU32(name: String, value: Long): Long {
  require(value in 0..maxWireU32) { "$name out of range for uint32" }
  return value
}

internal fun requireWireU32Int(name: String, value: Long): Int =
  requireWireU32(name, value).toInt()

// Wire lengths are unsigned u32 on the protocol, but JVM byte arrays and
// strings still require a signed Int length at the allocation boundary.
internal fun requireWireByteArrayLen(name: String, value: Long): Int {
  requireWireU32(name, value)
  require(value <= Int.MAX_VALUE.toLong()) { "$name out of range for byte-array length" }
  return value.toInt()
}

internal fun requireWireU16(name: String, value: Int): Int {
  require(value in 0..maxWireU16) { "$name out of range for uint16" }
  return value
}

internal fun intBitsToWireU32(value: Int): Long =
  value.toLong() and maxWireU32
