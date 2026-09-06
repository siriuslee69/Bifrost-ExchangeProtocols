## ------------------------------------------------------------
## LAN Message Tests <- BMSG parity and malformed input rejection
## ------------------------------------------------------------

import std/unittest

import ../../src/clients/shared/lan_message

suite "LAN BMSG codec":
  test "matches the Android BMSG v1 byte layout":
    var
      m: LanMessage = initLanMessage(lpTcp, "host-1", "Desktop", "hello phone",
        7'u64, 1000'u64)
      A: seq[byte] = encodeLanMessage(m)
      expected: seq[byte] = @[
        0x42'u8, 0x4d, 0x53, 0x47, 0x01, 0x00, 0x02, 0x00,
        0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x07, 0x00, 0x0b, 0x00, 0x00, 0x00
      ]
    for c in "host-1Desktophello phone":
      expected.add(byte(c))
    check A == expected
    check decodeLanMessage(A) == m

  test "ack and unicode text roundtrip":
    var
      m: LanMessage = initLanMessage(lpTcp, "phone", "Motorola", "frost signal", 9)
      ack: LanMessage = initLanAck(m, "host", "Desktop", 10)
    check decodeLanMessage(encodeLanMessage(ack)) == ack
    check ack.isAck

  test "malformed lengths and flags fail closed":
    var
      A: seq[byte] = encodeLanMessage(initLanMessage(lpTcp, "a", "b", "c", 1))
      B: seq[byte] = A
    A[7] = 0x80'u8
    expect ValueError:
      discard decodeLanMessage(A)
    B[28] = 2'u8
    expect ValueError:
      discard decodeLanMessage(B)
