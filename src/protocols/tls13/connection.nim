## -----------------------------------------------------------------------
## TLS 1.3 Connection <- transport-neutral record buffering and typed events
## -----------------------------------------------------------------------

import ../types
import ./[types, codec, records, key_schedule]
import ../../analysis_pragmas
import tyr/helpers/secure_memory

const
  tls13DefaultRecordBufferLimit* = 4 * tls13CiphertextLimit

type
  Tls13EventKind* = enum
    tekHandshake,
    tekApplicationData,
    tekAlert,
    tekClosed,
    tekError

  Tls13Event* {.role: truthState, tag: {tagTls, tagPacket}.} = object
    kind*: Tls13EventKind
    handshake*: Tls13Handshake
    data*: ByteSeq
    alertLevel*: byte
    alertDescription*: byte
    err*: string

  Tls13FeedStep* {.role: truthState, tag: {tagTls, tagParsing}.} = object
    events*: seq[Tls13Event]
    progressed*: bool
    needMore*: bool

  Tls13Connection* {.role: memory, tag: {tagTls, tagTransport}.} = object
    recordBuffer: ByteSeq
    handshakeBuffer: ByteSeq
    readKeys: Tls13TrafficKeys
    writeKeys: Tls13TrafficKeys
    readKeysInstalled: bool
    writeKeysInstalled: bool
    failed*: bool
    peerClosed*: bool
    localClosed*: bool
    maxRecordBuffer*: int
    maxHandshakeBuffer*: int
    readTrafficSecret: Tls13Secret
    writeTrafficSecret: Tls13Secret
    readTrafficSecretInstalled: bool
    writeTrafficSecretInstalled: bool

proc initTls13Connection*(maxRecordBuffer: int = tls13DefaultRecordBufferLimit,
    maxHandshakeBuffer: int = tls13DefaultHandshakeLimit): Tls13Connection {.
    role: truthBuilder, tag: {tagTls, tagTransport}.} =
  ## maxRecordBuffer/maxHandshakeBuffer: retained incomplete-input bounds.
  if maxRecordBuffer < tls13CiphertextLimit or maxHandshakeBuffer < 4:
    raise newException(ValueError, "TLS connection buffer limits are invalid")
  result.maxRecordBuffer = maxRecordBuffer
  result.maxHandshakeBuffer = maxHandshakeBuffer

proc installTls13ReadKeys*(C: var Tls13Connection, K: Tls13TrafficKeys) {.
    role: stateController, tag: {tagTls, tagCryptoBoundary}.} =
  ## C/K: connection and current peer traffic keys.
  C.readKeys = K
  C.readKeysInstalled = true

proc installTls13WriteKeys*(C: var Tls13Connection, K: Tls13TrafficKeys) {.
    role: stateController, tag: {tagTls, tagCryptoBoundary}.} =
  ## C/K: connection and current local traffic keys.
  C.writeKeys = K
  C.writeKeysInstalled = true

proc installTls13ReadTrafficSecret*(C: var Tls13Connection,
    S: Tls13Secret) {.role: stateController,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C/S: connection and peer application traffic secret.
  C.readTrafficSecret = S
  C.readKeys = deriveTls13TrafficKeys(S)
  C.readTrafficSecretInstalled = true
  C.readKeysInstalled = true

proc installTls13WriteTrafficSecret*(C: var Tls13Connection,
    S: Tls13Secret) {.role: stateController,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C/S: connection and local application traffic secret.
  C.writeTrafficSecret = S
  C.writeKeys = deriveTls13TrafficKeys(S)
  C.writeTrafficSecretInstalled = true
  C.writeKeysInstalled = true

proc applyPeerKeyUpdate(C: var Tls13Connection,
    H: Tls13Handshake): string {.role: stateController,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C/H: connection and authenticated post-handshake KeyUpdate.
  if H.body.len != 1 or H.body[0] notin {0'u8, 1'u8}:
    return "TLS KeyUpdate request value is invalid"
  if not C.readTrafficSecretInstalled:
    return "TLS KeyUpdate arrived without application traffic secret"
  C.readTrafficSecret = nextTls13TrafficSecret(C.readTrafficSecret)
  C.readKeys = deriveTls13TrafficKeys(C.readTrafficSecret)
  result = ""

proc clearTls13ConnectionSecrets*(C: var Tls13Connection) {.
    role: stateController, tag: {tagTls, tagCryptoBoundary}.} =
  ## C: connection whose retained plaintext and traffic material is retired.
  secureClearBytes(C.recordBuffer)
  secureClearBytes(C.handshakeBuffer)
  secureClearBytes(C.readKeys.key)
  secureClearBytes(C.readKeys.iv)
  secureClearBytes(C.writeKeys.key)
  secureClearBytes(C.writeKeys.iv)
  clearTls13Secret(C.readTrafficSecret)
  clearTls13Secret(C.writeTrafficSecret)
  C.readKeys.sequence = 0
  C.writeKeys.sequence = 0
  C.readKeysInstalled = false
  C.writeKeysInstalled = false
  C.readTrafficSecretInstalled = false
  C.writeTrafficSecretInstalled = false

proc tls13ReadSequence*(C: Tls13Connection): uint64 {.role: parser,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C: connection whose read sequence is observed for tests/metrics.
  result = C.readKeys.sequence

proc tls13WriteSequence*(C: Tls13Connection): uint64 {.role: parser,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C: connection whose write sequence is observed for tests/metrics.
  result = C.writeKeys.sequence

proc tls13ReadKeysInstalled*(C: Tls13Connection): bool {.role: parser,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C: connection whose peer traffic-key availability is queried.
  result = C.readKeysInstalled

proc tls13WriteKeysInstalled*(C: Tls13Connection): bool {.role: parser,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## C: connection whose local traffic-key availability is queried.
  result = C.writeKeysInstalled

proc dropPrefix(A: var ByteSeq, n: int) {.role: stateController,
    tag: {tagTls, tagParsing}.} =
  ## A/n: retained buffer and consumed prefix length.
  var
    remaining, i: int = 0
  if n < 0 or n > A.len:
    raise newException(ValueError, "TLS buffer consume length is invalid")
  remaining = A.len - n
  i = 0
  while i < remaining:
    A[i] = A[n + i]
    i = i + 1
  A.setLen(remaining)

proc errorEvent(C: var Tls13Connection, e: string): Tls13Event {.
    role: truthBuilder, tag: {tagTls, tagValidation}.} =
  ## C/e: failed connection and terminal error detail.
  C.failed = true
  result.kind = tekError
  result.err = e

proc parseAlert(C: var Tls13Connection, A: openArray[byte]): Tls13Event {.
    role: parser, tag: {tagTls, tagValidation}.} =
  ## C/A: connection and authenticated/plain alert bytes.
  if A.len != 2:
    return C.errorEvent("TLS alert must contain level and description")
  result.alertLevel = A[0]
  result.alertDescription = A[1]
  if A[1] == 0'u8:
    C.peerClosed = true
    result.kind = tekClosed
    return
  result.kind = tekAlert
  if A[0] == 2'u8:
    C.failed = true

proc drainHandshakeEvents(C: var Tls13Connection,
    E: var seq[Tls13Event]) {.role: orchestrator,
    tag: {tagTls, tagParsing}.} =
  ## C/E: connection handshake buffer and emitted complete messages.
  var
    R: Tls13HandshakeResult
    event: Tls13Event
  while C.handshakeBuffer.len > 0:
    R = decodeTls13Handshake(C.handshakeBuffer, C.maxHandshakeBuffer)
    if R.needMore:
      return
    if not R.ok:
      E.add(C.errorEvent(R.err))
      return
    event.kind = tekHandshake
    event.handshake = R.message
    if R.message.messageType == thtKeyUpdate:
      event.err = C.applyPeerKeyUpdate(R.message)
      if event.err.len > 0:
        E.add(C.errorEvent(event.err))
        return
    E.add(event)
    C.handshakeBuffer.dropPrefix(R.consumed)

proc routeContent(C: var Tls13Connection, t: Tls13ContentType,
    A: openArray[byte], E: var seq[Tls13Event]) {.role: orchestrator,
    tag: {tagTls, tagParsing}.} =
  ## C/t/A/E: connection, authenticated content type, bytes, and event output.
  var event: Tls13Event
  case t
  of tctHandshake:
    if C.handshakeBuffer.len > C.maxHandshakeBuffer - A.len:
      E.add(C.errorEvent("TLS handshake buffer exceeds maximum"))
      return
    C.handshakeBuffer.add(A)
    C.drainHandshakeEvents(E)
  of tctApplicationData:
    event.kind = tekApplicationData
    event.data = @A
    E.add(event)
  of tctAlert:
    E.add(C.parseAlert(A))
  of tctChangeCipherSpec:
    if A.len != 1 or A[0] != 1'u8:
      E.add(C.errorEvent("TLS compatibility ChangeCipherSpec is invalid"))

proc routeRecord(C: var Tls13Connection, R: Tls13Record,
    E: var seq[Tls13Event]) {.role: orchestrator,
    tag: {tagTls, tagParsing, tagCryptoBoundary}.} =
  ## C/R/E: connection, complete record, and emitted events.
  var opened: Tls13OpenResult
  if R.contentType != tctApplicationData:
    C.routeContent(R.contentType, R.fragment, E)
    return
  if not C.readKeysInstalled:
    E.add(C.errorEvent("TLS encrypted record arrived before read keys"))
    return
  opened = openTls13Record(C.readKeys, R)
  if not opened.ok:
    E.add(C.errorEvent(opened.err))
    return
  C.routeContent(opened.contentType, opened.content, E)

proc feedTls13One*(C: var Tls13Connection,
    A: openArray[byte]): Tls13FeedStep {.role: orchestrator,
    tag: {tagTls, tagTransport, tagParsing}.} =
  ## C/A: connection and new bytes; process at most one complete record.
  var R: Tls13RecordResult
  if C.failed:
    result.events.add(C.errorEvent("TLS connection is already failed"))
    return
  if C.peerClosed:
    result.events.add(C.errorEvent("TLS bytes arrived after peer close_notify"))
    return
  if A.len > C.maxRecordBuffer - C.recordBuffer.len:
    result.events.add(C.errorEvent("TLS record buffer exceeds maximum"))
    return
  C.recordBuffer.add(A)
  if C.recordBuffer.len == 0:
    result.needMore = true
    return
  R = decodeTls13Record(C.recordBuffer)
  if R.needMore:
    result.needMore = true
    return
  if not R.ok:
    result.events.add(C.errorEvent(R.err))
    return
  C.routeRecord(R.record, result.events)
  C.recordBuffer.dropPrefix(R.consumed)
  result.progressed = true

proc feedTls13*(C: var Tls13Connection, A: openArray[byte]): seq[Tls13Event] {.
    role: orchestrator, tag: {tagTls, tagTransport, tagParsing}.} =
  ## C/A: connection and arbitrary next transport bytes.
  var
    step: Tls13FeedStep = C.feedTls13One(A)
    i: int = 0
  while i < step.events.len:
    result.add(step.events[i])
    i = i + 1
  while step.progressed and not C.failed and not C.peerClosed:
    step = C.feedTls13One([])
    i = 0
    while i < step.events.len:
      result.add(step.events[i])
      i = i + 1

proc encodeTls13PlainHandshakeRecord*(A: openArray[byte]): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagTransport}.} =
  ## A: encoded pre-key handshake messages to place in one plaintext record.
  var R: Tls13Record
  if A.len > tls13PlaintextLimit:
    raise newException(ValueError, "TLS plaintext handshake record is too large")
  R.contentType = tctHandshake
  R.legacyVersion = tls13LegacyRecordVersion
  R.fragment = @A
  result = encodeTls13Record(R)

proc encodeTls13Protected*(C: var Tls13Connection, t: Tls13ContentType,
    A: openArray[byte], paddingLen: int = 0): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## C/t/A/paddingLen: write connection, inner type, bytes, and zero padding.
  var R: Tls13Record
  if C.failed or C.localClosed:
    raise newException(IOError, "TLS connection cannot write")
  if not C.writeKeysInstalled:
    raise newException(IOError, "TLS write keys are not installed")
  R = sealTls13Record(C.writeKeys, t, A, paddingLen)
  result = encodeTls13Record(R)

proc encodeTls13Application*(C: var Tls13Connection, A: openArray[byte],
    paddingLen: int = 0): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## C/A/paddingLen: connection and authenticated application bytes.
  result = C.encodeTls13Protected(tctApplicationData, A, paddingLen)

proc encodeTls13CloseNotify*(C: var Tls13Connection): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## C: connection to close cleanly with an encrypted close_notify alert.
  result = C.encodeTls13Protected(tctAlert, [byte 1, 0])
  C.localClosed = true

proc encodeTls13KeyUpdate*(C: var Tls13Connection,
    requestPeerUpdate: bool = false): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## C/requestPeerUpdate: rotate local application keys after encoding KeyUpdate.
  var
    H: Tls13Handshake
    encoded: ByteSeq = @[]
  if not C.writeTrafficSecretInstalled:
    raise newException(IOError, "TLS application traffic secret is not installed")
  H.messageType = thtKeyUpdate
  H.body = @[if requestPeerUpdate: 1'u8 else: 0'u8]
  encoded = encodeTls13Handshake(H)
  result = C.encodeTls13Protected(tctHandshake, encoded)
  C.writeTrafficSecret = nextTls13TrafficSecret(C.writeTrafficSecret)
  C.writeKeys = deriveTls13TrafficKeys(C.writeTrafficSecret)
