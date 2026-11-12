## -------------------------------------------------------------------------
## Archive Letters <- sealed for someone who is not online, with no answer
## -------------------------------------------------------------------------
##
## Someone offline cannot take part in a key exchange, so they leave PREKEYS
## on the server first: public keys anybody can seal to.
##
##   bob (before)                server               alice (later)
##   ------------                ------               -------------
##   newArchivePrekey x 100
##   public halves      ───────▶ keeps them
##   secret halves, sealed ────▶ in bob's vault
##                               takeOnce  ──────────▶ one public half
##                                                     sealArchiveLetter
##                               keeps it  ◀────────── letter
##   openArchiveLetter ◀──────── letter
##
## Both ends now hold the same FOMKE state, built from one KEM secret per slot
## (X25519 and ML-KEM-768 side by side: breaking one is not enough). A space
## secret can be derived from it (`deriveArchiveSpaceSecret`). The letter itself
## is sealed under a child of that state.
##
## ╭─ ❧ Def. 1: the letter 🌊
##
##   +-----+----------+-------+----------------------------------------+
##   | ver | prekeyId | slots | slots x (u16 + ciphertext | u16 + key) |
##   | u8  | u32      | u8    |                                        |
##   +-----+----------+-------+----------------------------------------+
##   | sealed record (level1/sealed.nim), to the end                   |
##   +-----------------------------------------------------------------+
##
## Def. 2 (context): the two names, the prekey id and every envelope go into the
##   key, so a changed byte anywhere gives a different key and nothing opens.
## Def. 3 (letter key): prekey id 0 is by agreement a key that is NOT used up:
##   a mail gateway seals every arriving mail to it. Weaker, because whoever
##   later steals its secret half opens all of them; a one-time prekey is
##   deleted after use and does not have that problem.
##
## Who wrote a letter is NOT proven by this file: anyone can seal to a public
## key. A letter that must say who wrote it carries a signature inside its body
## (level2/members.nim).

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/suites
import ../../ame/level1/algorithms
import ../../fomke/types
import ../../fomke/level3/ops
import ../types
import ../level1/keys
import ../level1/sealed
import ./account
import ../../byte_codec
import runePragmas

const
  archiveContactKems*: AmeKemAlgorithms = [akaX25519, akaMlKem768]
  archiveHybridMask = 0b11000000'u8
  archiveLetterLabel = "ARCHIVE-LETTER-v1"

type
  ArchivePrekey* {.role: truthState, tag: "archive|cryptoBoundary|types",
      expectedCount: [0, 200], lifeCycle: lcSession.} = object
    ## Both halves. The secret half is erased once a letter was opened with it.
    id*: uint32
    keys*: seq[AmeKemKeypair]

  ArchivePrekeyPublic* {.role: preparedData, tag: "archive|types".} = object
    ## What a sender needs.
    id*: uint32
    publicKeys*: seq[ByteSeq]

  ArchiveOpenedLetter* {.role: preparedData, tag: "archive|types".} = object
    ## What `openArchiveLetter` returns. ok = false means nothing else is set.
    ok*: bool
    body*: ByteSeq
    state*: FomkeState

  ArchiveSealedLetter* {.role: preparedData, tag: "archive|types".} = object
    ## What `sealArchiveLetter` returns: the bytes, and the sender's state.
    letter*: ByteSeq
    state*: FomkeState

proc contactLayout(): AmeSuiteLayout {.role: configurator.} =
  ## The slots both sides agree on.
  result = defaultAmeLayout(archiveContactKems)

proc contactTier(): AmeMaskTier {.role: configurator.} =
  ## Both KEM slots on, every other slot on its single choice.
  var
    L: AmeSuiteLayout = contactLayout()
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(archiveHybridMask,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc newArchivePrekey*(id: uint32): ArchivePrekey {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary".} =
  ## id: this prekey's number; 0 means a letter key (Def. 3).
  var
    i: int = 0
  result.id = id
  while i < int(archiveContactKems.length):
    result.keys.add(ameKemKeypair(archiveContactKems.algorithms[i]))
    i = i + 1

proc publicOf*(P: ArchivePrekey): ArchivePrekeyPublic {.role: parser,
    tag: "archive|appApi".} =
  ## P: the half that may be shown to anyone.
  result.id = P.id
  for k in P.keys:
    result.publicKeys.add(k.publicKey)

proc encodeArchivePrekeyPublic*(P: ArchivePrekeyPublic): ByteSeq {.
    role: dataWriter, tag: "archive|wire".} =
  ## P: prekeyId u32 | slots u8 | slots x u16 + public key.
  appendU32Le(result, P.id)
  result.add(uint8(P.publicKeys.len))
  for k in P.publicKeys:
    appendSizedArchive(result, k)

proc readU32Archive(A: openArray[uint8], o: int): uint32 {.role: parser, inline.} =
  ## A/o: four bytes at o, little-endian. The caller checked there are four.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc decodeArchivePrekeyPublic*(A: openArray[uint8]): ArchivePrekeyPublic {.
    role: parser, tag: "archive|wire".} =
  ## A: as encoded. Raises on anything malformed.
  var
    o: int = 5
    i: int = 0
  if A.len < 5 or int(A[4]) != int(archiveContactKems.length):
    raise newException(ValueError, "archive prekey has the wrong shape")
  result.id = readU32Archive(A, 0)
  while i < int(A[4]):
    result.publicKeys.add(takeSizedArchive(A, o))
    i = i + 1
  if o != A.len:
    raise newException(ValueError, "archive prekey has trailing bytes")

proc encodeArchivePrekey*(P: ArchivePrekey): ByteSeq {.role: dataWriter,
    tag: "archive|wire".} =
  ## P: both halves, for sealing into the owner's vault:
  ## prekeyId u32 | slots u8 | slots x (u16 + public | u16 + secret).
  appendU32Le(result, P.id)
  result.add(uint8(P.keys.len))
  for k in P.keys:
    appendSizedArchive(result, k.publicKey)
    appendSizedArchive(result, k.secretKey)

proc decodeArchivePrekey*(A: openArray[uint8]): ArchivePrekey {.role: parser,
    tag: "archive|wire".} =
  ## A: as encoded. Raises on anything malformed.
  var
    o: int = 5
    i: int = 0
    k: AmeKemKeypair = default(AmeKemKeypair)
  if A.len < 5 or int(A[4]) != int(archiveContactKems.length):
    raise newException(ValueError, "archive prekey has the wrong shape")
  result.id = readU32Archive(A, 0)
  while i < int(A[4]):
    k.publicKey = takeSizedArchive(A, o)
    k.secretKey = takeSizedArchive(A, o)
    result.keys.add(k)
    i = i + 1
  if o != A.len:
    raise newException(ValueError, "archive prekey has trailing bytes")

proc letterContext(fromName, toName: string, id: uint32,
    E: openArray[AmeKemEnvelope]): ByteSeq {.role: truthBuilder.} =
  ## fromName/toName/id/E: Def. 2, in a fixed order.
  appendAmeLabel(result, "ARCHIVE-LETTER-START-v1")
  appendSizedArchive(result, toBytesArchive(fromName))
  appendSizedArchive(result, toBytesArchive(toName))
  appendU32Le(result, id)
  for x in E:
    appendSizedArchive(result, x.ciphertext)
    appendSizedArchive(result, x.senderPublicKey)

proc letterKey(S: FomkeState): ByteSeq {.role: truthBuilder, inline.} =
  ## S: the state both ends built. The key this letter is sealed under.
  result = deriveFomkeTightChild(S, "ARCHIVE-LETTER-KEY-v1")

proc letterState(secrets: var seq[ByteSeq], role: FomkeRole, context: ByteSeq): FomkeState {.
    role: truthBuilder.} =
  ## secrets/role/context: one FOMKE state from one secret per slot.
  result = initFomke(secrets, archiveContactKems, contactLayout(), contactTier(),
    role, context, initXhkdfConfig(), fomkeDefaultReorderCeiling)

proc sealArchiveLetter*(P: ArchivePrekeyPublic, fromName, toName: string,
    body: openArray[uint8]): ArchiveSealedLetter {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## P: the receiver's public prekey. fromName/toName: the names both ends
  ## believe. body: what is sealed. Raises when P has the wrong shape.
  var
    secrets: seq[ByteSeq] = @[]
    E: seq[AmeKemEnvelope] = @[]
    cipher: AmeKemCipher = default(AmeKemCipher)
    key: ByteSeq = @[]
    i: int = 0
  if P.publicKeys.len != int(archiveContactKems.length):
    raise newException(ValueError, "archive prekey has the wrong shape")
  while i < P.publicKeys.len:
    cipher = sealAmeKem(archiveContactKems.algorithms[i], P.publicKeys[i])
    secrets.add(cipher.sharedSecret)
    E.add(cipher.envelope)
    i = i + 1
  result.state = letterState(secrets, frInitiator, letterContext(fromName,
    toName, P.id, E))
  key = letterKey(result.state)
  result.letter.add(archiveRecordVersion)
  appendU32Le(result.letter, P.id)
  result.letter.add(uint8(E.len))
  for x in E:
    appendSizedArchive(result.letter, x.ciphertext)
    appendSizedArchive(result.letter, x.senderPublicKey)
  appendAmeBytes(result.letter, sealArchiveRecord(key, archiveLetterLabel,
    toBytesArchive(toName), 0'u16, body))
  secureClearAmeBytes(key)

proc archiveLetterPrekeyId*(A: openArray[uint8]): tuple[ok: bool, id: uint32] {.
    role: parser, tag: "archive|appApi|wire".} =
  ## A: a letter. Which prekey it needs, before anything is opened.
  if A.len < 6 or A[0] != archiveRecordVersion:
    return
  result = (true, readU32Archive(A, 1))

proc readLetterEnvelopes(A: openArray[uint8], o: var int): seq[AmeKemEnvelope] {.
    role: parser.} =
  ## A/o: the slots of Def. 1. Raises when malformed.
  var
    i: int = 0
    e: AmeKemEnvelope = default(AmeKemEnvelope)
  if A.len < 6 or A[0] != archiveRecordVersion or
      int(A[5]) != int(archiveContactKems.length):
    raise newException(ValueError, "archive letter has the wrong shape")
  o = 6
  while i < int(A[5]):
    e.ciphertext = takeSizedArchive(A, o)
    e.senderPublicKey = takeSizedArchive(A, o)
    result.add(e)
    i = i + 1

proc openArchiveLetter*(P: ArchivePrekey, fromName, toName: string,
    A: openArray[uint8]): ArchiveOpenedLetter {.role: decryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## P: the prekey it was sealed to, secret half included. fromName/toName: as
  ## sealed. A: the letter. Nothing here raises: ok = false for a wrong prekey,
  ## a wrong name, or any changed byte.
  var
    E: seq[AmeKemEnvelope] = @[]
    secrets: seq[ByteSeq] = @[]
    held: AmeKemCipher = default(AmeKemCipher)
    key: ByteSeq = @[]
    o: int = 0
    i: int = 0
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  if P.keys.len != int(archiveContactKems.length) or
      archiveLetterPrekeyId(A).id != P.id:
    return
  try:
    E = readLetterEnvelopes(A, o)
    while i < E.len:
      held.envelope = E[i]
      secrets.add(openAmeKem(archiveContactKems.algorithms[i], held,
        P.keys[i].secretKey))
      i = i + 1
    result.state = letterState(secrets, frResponder, letterContext(fromName,
      toName, P.id, E))
  except CatchableError:
    return
  key = letterKey(result.state)
  opened = openArchiveRecord(key, archiveLetterLabel, toBytesArchive(toName),
    A.toOpenArray(o, A.len - 1))
  secureClearAmeBytes(key)
  if not opened.ok:
    return ArchiveOpenedLetter()
  result.ok = true
  result.body = opened.record.body
