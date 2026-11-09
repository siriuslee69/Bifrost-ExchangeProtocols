## Archive contact tests <- reaching someone offline, and what a message holds.
##
##   suite                what it holds down
##   -------------------  ----------------------------------------------------
##   "letters"            sealed with nobody home; a wrong prekey, name or byte
##                        opens nothing; the two ends agree on a space secret
##   "member signatures"  in a group, one member cannot write as another
##   "message bodies"     every kind, padding, every malformed length
##   "openings"           start, answer, read pointer
##   "file chunks"        moved or swapped chunks do not open; manifest
##   "login"              the auth hash and the decoy settings

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level3/handshake_identity
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level3/ops
import ../../src/protocols/archive

proc b(s: string): ByteSeq =
  ## s: its bytes.
  result = cast[ByteSeq](s)

proc spaceOf(secret: ByteSeq): ArchiveSpace =
  ## secret: a space with the contact layout.
  var
    L = defaultAmeLayout(archiveContactKems)
  result = ArchiveSpace(spaceId: newSeq[uint8](16), gen: 1, secret: secret,
    epochSize: 256, layout: L, tier: fullAmeMaskTier(L), tagLen: aatl16)

suite "letters":
  # {.testKind: tkIntegration, covers: "sealArchiveLetter|openArchiveLetter".}
  test "a letter sealed while nobody is home opens later":
    var
      p = newArchivePrekey(7)
      sent = sealArchiveLetter(p.publicOf(), "alice", "bob", b("hello"))
      got = openArchiveLetter(p, "alice", "bob", sent.letter)
    check got.ok and got.body == b("hello")
    check archiveLetterPrekeyId(sent.letter) == (true, 7'u32)

  # {.testKind: tkIntegration, covers: "deriveArchiveSpaceSecret|openArchiveLetter".}
  test "both ends derive the same space secret and never send it":
    var
      p = newArchivePrekey(1)
      id = newSeq[uint8](16)
      sent = sealArchiveLetter(p.publicOf(), "alice", "bob", b("x"))
      got = openArchiveLetter(p, "alice", "bob", sent.letter)
    check deriveArchiveSpaceSecret(sent.state, id, 1) ==
      deriveArchiveSpaceSecret(got.state, id, 1)

  # {.testKind: tkEdgeCase, covers: "openArchiveLetter".}
  test "another prekey, another name or another id opens nothing":
    var
      p = newArchivePrekey(7)
      other = newArchivePrekey(7)
      renumbered = p
      sent = sealArchiveLetter(p.publicOf(), "alice", "bob", b("x")).letter
    renumbered.id = 8
    check not openArchiveLetter(other, "alice", "bob", sent).ok
    check not openArchiveLetter(p, "mallory", "bob", sent).ok
    check not openArchiveLetter(p, "alice", "carol", sent).ok
    check not openArchiveLetter(renumbered, "alice", "bob", sent).ok

  # {.testKind: tkEdgeCase, covers: "openArchiveLetter".}
  test "every changed byte, and every shortened letter, is refused":
    var
      p = newArchivePrekey(7)
      sent = sealArchiveLetter(p.publicOf(), "a", "b", b("x")).letter
      i = 0
    while i < sent.len:
      var t = sent
      t[i] = t[i] xor 1'u8
      check not openArchiveLetter(p, "a", "b", t).ok
      check not openArchiveLetter(p, "a", "b", sent.toOpenArray(0, i - 1)).ok
      i = i + 97

  # {.testKind: tkProperty, covers: "sealArchiveLetter".}
  test "two letters to one prekey share nothing":
    var
      p = newArchivePrekey(1)
      x = sealArchiveLetter(p.publicOf(), "a", "b", b("same"))
      y = sealArchiveLetter(p.publicOf(), "a", "b", b("same"))
      id = newSeq[uint8](16)
    check x.letter != y.letter
    check deriveArchiveSpaceSecret(x.state, id, 1) !=
      deriveArchiveSpaceSecret(y.state, id, 1)

  # {.testKind: tkUnit, covers: "encodeArchivePrekey|decodeArchivePrekey".}
  test "a prekey saved and read back still opens":
    var
      p = newArchivePrekey(3)
      back = decodeArchivePrekey(encodeArchivePrekey(p))
      pub = decodeArchivePrekeyPublic(encodeArchivePrekeyPublic(p.publicOf()))
      sent = sealArchiveLetter(pub, "a", "b", b("x"))
    check openArchiveLetter(back, "a", "b", sent.letter).ok

suite "member signatures":
  # {.testKind: tkIntegration, covers: "signArchiveMember|openArchiveMember".}
  test "a member's record checks out with that member's keys only":
    var
      alice = initAmeIdentityKey("alice")
      carol = initAmeIdentityKey("carol")
      signed = signArchiveMember(alice, archiveMemberLogLabel, b("space"), b("sealed"))
      got = openArchiveMember(alice.signingKeys, archiveMemberLogLabel, b("space"), signed)
    check got.ok and got.sealed == b("sealed")
    check not openArchiveMember(carol.signingKeys, archiveMemberLogLabel, b("space"), signed).ok

  # {.testKind: tkEdgeCase, covers: "openArchiveMember".}
  test "a signature cannot be moved to another space, label or record":
    var
      alice = initAmeIdentityKey("alice")
      signed = signArchiveMember(alice, "log", b("space"), b("sealed"))
      changed = signed
    changed[^1] = changed[^1] xor 1'u8
    check not openArchiveMember(alice.signingKeys, "log", b("other"), signed).ok
    check not openArchiveMember(alice.signingKeys, "file", b("space"), signed).ok
    check not openArchiveMember(alice.signingKeys, "log", b("space"), changed).ok
    check not openArchiveMember(alice.signingKeys, "log", b("space"), []).ok

suite "message bodies":
  # {.testKind: tkUnit, covers: "encodeArchiveBody|decodeArchiveBody".}
  test "the documented bytes of a short text":
    check encodeArchiveBody(ArchiveBody(kind: abkText, timeMs: 1, text: "hi"), false) ==
      @[1'u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x69]

  # {.testKind: tkUnit, covers: "encodeArchiveBody|decodeArchiveBody".}
  test "every kind goes to bytes and back, padded in whole blocks":
    var
      p = ArchivePosition(gen: 1, lane: 9, epoch: 2, index: 3)
      f = ArchiveAttachment(fileId: newSeq[uint8](16), fileKey: newSeq[uint8](32),
        size: 5, name: "a.txt", media: "text/plain")
      B = @[ArchiveBody(kind: abkText, timeMs: 7, text: "hello"),
        ArchiveBody(kind: abkAttachment, timeMs: 7, file: f),
        ArchiveBody(kind: abkEdit, timeMs: 7, target: p, text: "new"),
        ArchiveBody(kind: abkDelete, timeMs: 7, target: p),
        ArchiveBody(kind: abkSeen, timeMs: 7, seen: @[p, p]),
        ArchiveBody(kind: abkLanes, timeMs: 7, lanes: @[1'u32, 2'u32])]
    for x in B:
      var A = encodeArchiveBody(x)
      check A.len mod archivePadBlock == 0
      check decodeArchiveBody(A) == x

  # {.testKind: tkEdgeCase, covers: "encodeArchiveBody".}
  test "a body that exactly fills a block gets one more block of filler":
    var A = encodeArchiveBody(ArchiveBody(kind: abkText, text: newString(54)))
    check A.len == 128 and A[^1] == 64'u8
    check decodeArchiveBody(A).text.len == 54

  # {.testKind: tkEdgeCase, covers: "decodeArchiveBody".}
  test "malformed bodies are refused":
    expect ValueError: discard decodeArchiveBody([])
    expect ValueError: discard decodeArchiveBody(newSeq[uint8](10))
    var A = encodeArchiveBody(ArchiveBody(kind: abkText, text: "x"))
    A[^1] = 200'u8
    expect ValueError: discard decodeArchiveBody(A)
    var C = encodeArchiveBody(ArchiveBody(kind: abkSeen), false)
    C[10] = 5'u8
    expect ValueError: discard decodeArchiveBody(C)

suite "openings":
  # {.testKind: tkUnit, covers: "encodeArchiveOpening|decodeArchiveOpening".}
  test "two members: the secret does not travel; a group: it does":
    var
      S = spaceOf(newSeq[uint8](32))
      two = decodeArchiveOpening(encodeArchiveOpening(S, false))
      group = decodeArchiveOpening(encodeArchiveOpening(S, true))
    check not two.carriedSecret and two.space.secret.len == 0
    check two.space.spaceId == S.spaceId and two.space.epochSize == 256'u16
    check group.carriedSecret and group.space.secret == S.secret

  # {.testKind: tkEdgeCase, covers: "decodeArchiveOpening".}
  test "a shortened opening is refused":
    var
      A = encodeArchiveOpening(spaceOf(newSeq[uint8](32)), true)
      n = 0
    while n < A.len:
      expect ValueError: discard decodeArchiveOpening(A.toOpenArray(0, n - 1))
      n = n + 1

  # {.testKind: tkUnit, covers: "encodeArchiveAnswer|decodeArchiveAnswer".}
  test "an answer goes to bytes and back":
    var a = decodeArchiveAnswer(encodeArchiveAnswer(newSeq[uint8](16), 2, true))
    check a.gen == 2'u16 and a.accept

  # {.testKind: tkUnit, covers: "encodeArchiveReadPointer|decodeArchiveReadPointer".}
  test "a read pointer goes to bytes and back":
    var P = @[ArchivePosition(gen: 1, lane: 2, epoch: 3, index: 4)]
    check decodeArchiveReadPointer(encodeArchiveReadPointer(P)) == P
    expect ValueError: discard decodeArchiveReadPointer([1'u8, 1, 0])

suite "file chunks":
  # {.testKind: tkEdgeCase, covers: "openArchiveFileChunk".}
  test "a chunk opens only at its own place in its own file":
    var
      key = newSeq[uint8](32)
      f1 = newSeq[uint8](16)
      f2 = f1
      A = sealArchiveFileChunk(key, f1, 3, b("data"))
    f2[0] = 1'u8
    check openArchiveFileChunk(key, f1, 3, A) == (true, b("data"))
    check not openArchiveFileChunk(key, f1, 4, A).ok
    check not openArchiveFileChunk(key, f2, 3, A).ok

  # {.testKind: tkUnit, covers: "sealArchiveFileManifest|openArchiveFileManifest".}
  test "a manifest says what the chunks add up to":
    var
      key = newSeq[uint8](32)
      f = newSeq[uint8](16)
      M = ArchiveFileManifest(size: 9, chunkBytes: 4, chunks: 3,
        hash: newSeq[uint8](32), name: "a.bin")
    check openArchiveFileManifest(key, f, sealArchiveFileManifest(key, f, M)) == (true, M)

  # {.testKind: tkEdgeCase, covers: "sealArchiveFileChunk".}
  test "a chunk over the limit is refused":
    expect ValueError:
      discard sealArchiveFileChunk(newSeq[uint8](32), newSeq[uint8](16), 0,
        newSeq[uint8](archiveFileChunkBytes + 1))

suite "login":
  # {.testKind: tkUnit, covers: "archiveAuthHash".}
  test "the auth hash is a fixed one-way image of the key":
    var
      a = newSeq[uint8](32)
      c = a
    c[0] = 1'u8
    check archiveAuthHash(a).len == 32 and archiveAuthHash(a) != a
    check archiveAuthHash(a) != archiveAuthHash(c)

  # {.testKind: tkEdgeCase, covers: "archiveDecoySettings".}
  test "an unknown name always gets the same settings, and they pass the client's floor":
    var s = b("a server secret that is long enough")
    check archiveDecoySettings(s, "ghost") == archiveDecoySettings(s, "ghost")
    check archiveDecoySettings(s, "ghost").userSalt != archiveDecoySettings(s, "other").userSalt
    check archiveSettingsError(archiveDecoySettings(s, "ghost")).len == 0
