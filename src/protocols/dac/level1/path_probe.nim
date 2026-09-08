## -------------------------------------------------------
## DAC Path Probe <- reachability and path-mode discovery
## -------------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../../analysis_pragmas

const
  dacPathProbeLen* = 18
  dacPathProbeAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PathProbe | Flags = PathProbe | BodyLen = 18  |
+----------+----------+----------+----------+----------+
| ProbeId  | Mode     | UdpPort  | TcpPort  | Nonce    |
| u32      | u8       | u16      | u16      | 9 bytes  |
+----------+----------+----------+----------+----------+
"""

proc nonceIsZero(n: array[9, uint8]): bool {.role: parser.} =
  ## n: probe nonce.
  var
    i: int = 0
  result = true
  while i < n.len:
    if n[i] != 0'u8:
      return false
    i = i + 1

proc initDacPathProbe*(probeId: uint32, p: DacPathLane,
    udpPort, tcpPort: uint16, nonce: array[9, uint8]): DacPathProbe {.role: configurator.} =
  ## probeId: sender-selected probe id.
  ## p: path lane being tested.
  ## udpPort/tcpPort: candidate transport ports.
  ## nonce: caller- or OS-generated anti-replay nonce.
  if nonceIsZero(nonce):
    raise newException(ValueError, "DAC path probe nonce must not be all zero")
  result.probeId = probeId
  result.pathLane = p
  result.udpPort = udpPort
  result.tcpPort = tcpPort
  result.nonce = nonce

proc initDacPathProbe*(probeId: uint32, p: DacPathLane,
    udpPort, tcpPort: uint16): DacPathProbe {.role: configurator.} =
  ## probeId/p/udpPort/tcpPort: path probe fields.
  raise newException(ValueError, "DAC path probe nonce must be provided")

proc defaultDacProbeCount*(): uint8 {.role: configurator.} =
  ## defaultDacProbeCount: probes sent when a path first appears.
  result = 3'u8

proc defaultDacProbeAcceptCount*(): uint8 {.role: configurator.} =
  ## defaultDacProbeAcceptCount: replies needed before path is accepted.
  result = 2'u8

proc encodeDacPathProbe*(p: DacPathProbe): ByteSeq {.role: helper.} =
  ## p: path probe body to encode.
  var
    i: int = 0
  if nonceIsZero(p.nonce):
    raise newException(ValueError, "DAC path probe nonce must not be all zero")
  appendDacU32(result, p.probeId)
  result.add(uint8(ord(p.pathLane)))
  appendDacU16(result, p.udpPort)
  appendDacU16(result, p.tcpPort)
  while i < p.nonce.len:
    result.add(p.nonce[i])
    i = i + 1

proc decodeDacPathProbe*(A: openArray[uint8]): DacPathProbe {.role: parser.} =
  ## A: path probe body bytes.
  var
    nonce: array[9, uint8]
    i: int = 0
  if A.len != dacPathProbeLen:
    raise newException(ValueError, "DAC path probe body length mismatch")
  while i < nonce.len:
    nonce[i] = A[9 + i]
    i = i + 1
  result = initDacPathProbe(readDacU32(A, 0), dacPathLaneFromId(A[4]),
    readDacU16(A, 5), readDacU16(A, 7), nonce)
