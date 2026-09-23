## -------------------------------------------------------------------------
## XHKDF Tests <- the branch bit mask, and the bytes GB3HKDF always gave
## -------------------------------------------------------------------------
##
## The two vectors below were produced by GB3HKDF (commit 69e022a, before the
## rename). The default XHKDF mask {BLAKE3, Gimli} must reproduce them byte
## for byte, or a session between an old and a new build would derive different keys.
##
## Run under slim builds too (`nimble testMinimalAme`): without Gimli the
## default mask shrinks to BLAKE3 and the Gimli vectors are skipped.

import std/[strutils, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/symmetric
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level0/xhkdf
import runePragmas

const
  ikm: array[16, byte] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16]
  gb3Sequential80: string = "45A96ACE6D79E213B6F1C512A719EB73C4BC97CD1D8AA1" &
    "1CA1F7EC0D32B863099A5F114BABE09034857C0724C5FF48B76C229AEE715A286DF80A6" &
    "16D925FD4E40EB9EC689E8F816D9E895A6AA756CE53"
  gb3Memory40: string = "CBBEA418CE98B089C92741F870595B2E7AD7C8FFA86242A15" &
    "61AF28371C8CB2C65602E37ACE72E2D"

proc hex(A: openArray[byte]): string {.role: helper.} =
  ## A: bytes -> upper-case hex, two characters per byte.
  for b in A:
    result.add(b.toHex)

proc derive(B: set[XhkdfBranch]): ByteSeq {.role: helper.} =
  ## B: branch mask -> 32 bytes over one fixed input.
  result = deriveXhkdf(ikm, [9'u8, 9], [7'u8], 32,
    initXhkdfConfig(branches = B))

suite "XHKDF":
  # {.testKind: tkRegression, covers: "deriveXhkdf", pins: "GB3HKDF bytes".}
  test "the default mask derives exactly what GB3HKDF did":
    when xbGimli in xhkdfBranchesBuilt:
      check xhkdfDefaultBranches == {xbBlake3, xbGimli}
      check hex(deriveXhkdf(ikm, [9'u8, 9], [7'u8], 80)) == gb3Sequential80
      check hex(deriveXhkdf(ikm, [], [7'u8], 40, initXhkdfConfig(rounds = 2,
        mode = xhMemoryMixed, memoryBlocks = 8))) == gb3Memory40
    else:
      check xhkdfDefaultBranches == {xbBlake3}

  # {.testKind: tkUnit, covers: "xhkdfBranchMask".}
  test "the branch set is a one-byte bit mask":
    check sizeof(set[XhkdfBranch]) == 1
    check xhkdfBranchMask({xbBlake3}) == 0x01'u8
    check xhkdfBranchMask({xbBlake3, xbGimli}) == 0x05'u8
    check xhkdfBranchesFromMask(0x07'u8) == {xbBlake3, xbShake256, xbGimli}
    expect ValueError:
      discard xhkdfBranchesFromMask(0x08'u8)
    expect ValueError:
      discard xhkdfBranchesFromMask(0x00'u8)

  # {.testKind: tkEdgeCase, covers: "buildXhkdfInput".}
  test "two different masks never share an output":
    var
      A: seq[ByteSeq] = @[]
      i: int = 0
      j: int = 0
    A.add(derive({xbBlake3}))
    when xbShake256 in xhkdfBranchesBuilt:
      A.add(derive({xbShake256}))
      A.add(derive({xbBlake3, xbShake256}))
    when xbGimli in xhkdfBranchesBuilt:
      A.add(derive({xbGimli}))
      A.add(derive({xbBlake3, xbGimli}))
    while i < A.len:
      j = i + 1
      while j < A.len:
        check A[i] != A[j]
        j = j + 1
      i = i + 1

  # {.testKind: tkEdgeCase, covers: "initXhkdfConfig".}
  test "a branch this build left out is refused":
    expect ValueError:
      discard initXhkdfConfig(branches = {})
    when xbGimli notin xhkdfBranchesBuilt:
      expect ValueError:
        discard initXhkdfConfig(branches = {xbGimli})

  # {.testKind: tkUnit, covers: "xhkdfBranchesOf".}
  test "the layout's active KDF slots choose the branches":
    var
      L: AmeSuiteLayout = defaultAmeLayout([akaX25519])
    check xhkdfBranchesOf(L, fullAmeMaskTier(L)) == xhkdfDefaultBranches
