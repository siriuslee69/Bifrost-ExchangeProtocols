## -------------------------------------------------------------------------
## Archive Keys <- from a password to the key of one stored record
## -------------------------------------------------------------------------
##
## Every key below is 32 bytes and comes from exactly one call, under its own
## label. No two jobs ever share a key.
##
##   password + userId + settings (userSalt, cost)
##            │
##         Argon2id                                   deriveArchiveLogin
##            │
##       login secret ──"ARCHIVE-AUTH-KEY-v1"──▶ authKey   (to the server)
##            └─────────"ARCHIVE-WRAP-KEY-v1"──▶ wrapKey   (opens the master)
##
##   master key: 32 random bytes                      newArchiveMasterKey
##            └──"ARCHIVE-SUB-KEY-v1" | name | keyGen──▶ one sub key per job
##                                                    deriveArchiveSubKey
##
##   FOMKE tight key of the members' session          deriveArchiveSpaceSecret
##            └──"ARCHIVE-SPACE-KEY-v1" | spaceId | gen──▶ space secret
##   space secret
##            └──"ARCHIVE-EPOCH-KEY-v1" | spaceId | gen | lane | epoch──▶ K_e
##                                                    deriveArchiveEpochKey
##
## Why the password does not make the master key itself: a password change
## then reseals ONE record (the master key) instead of every record the
## account holds. Why there are two keys from the password: the server must
## be able to check who logs in, and must never be able to open the master
## key. It sees the auth key's hash only.
##
## ⚠️ The password must be normalised (Unicode NFKC) by the caller before it
## comes here: "ä" typed as one code point and as a + ¨ are different bytes,
## and would make different keys. Bifrost carries no Unicode tables.

import std/unicode

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg

import ../../types
import ../../ame/level0/bytes
import ../../ame/level1/symmetric
import ../../fomke/types
import ../../fomke/level0/xhkdf
import ../../fomke/level1/chain_send
import ../types
import ../../byte_codec
import runePragmas
import var_invariants

when aspArgon2 in ameSymBuilt:
  import tyr/kdfs/argon2 as tyr_argon2

proc archiveRandom*(n: int): ByteSeq {.role: dataFetcher,
    tag: "archive|cryptoBoundary", needs: n > 0, gives: result.len == n.} =
  ## n: fresh random bytes from the system.
  result = tyr_random.cryptoRand(tyr_alg.raSystem, n)

proc newArchivePasswordSettings*(memoryKiB: uint32 = archiveDefaultMemoryKiB,
    passes: uint32 = archiveMinPasses,
    parallelism: uint8 = 1'u8): ArchivePasswordSettings {.role: configurator,
    tag: "archive|appApi".} =
  ## memoryKiB/passes/parallelism: the Argon2id cost; a fresh userSalt is
  ## made. Called once at sign-up and again at a password change.
  result.memoryKiB = memoryKiB
  result.passes = passes
  result.parallelism = parallelism
  result.userSalt = archiveRandom(archiveKeyBytes)

proc archiveSettingsError*(S: ArchivePasswordSettings): string {.role: parser,
    tag: "archive|sanitizer".} =
  ## S: settings, perhaps from a server. "" when they may be used. The lowest
  ## values are built in: a server cannot talk a device into a cheap guess.
  if S.userSalt.len != archiveKeyBytes:
    return "archive userSalt must be 32 bytes"
  if S.memoryKiB < archiveMinMemoryKiB:
    return "archive Argon2id memory is below the built-in minimum (64 MiB)"
  if S.passes < archiveMinPasses:
    return "archive Argon2id passes are below the built-in minimum (3)"
  if S.parallelism == 0'u8:
    return "archive Argon2id parallelism must be at least 1"
  result = ""

proc archiveLabelInfo(label: string, fields: openArray[ByteSeq]): ByteSeq {.
    role: helper, tag: "archive|kdf".} =
  ## label/fields: one derivation's context. Each field carries its length,
  ## so two different splits of the same bytes never give the same input.
  appendAmeLabel(result, label)
  for f in fields:
    appendU32Le(result, uint32(f.len))
    appendAmeBytes(result, f)

proc archiveKey(ikm: openArray[uint8], label: string,
    fields: openArray[ByteSeq], outLen: int = archiveKeyBytes): ByteSeq {.
    role: truthBuilder, tag: "archive|cryptoBoundary|kdf",
    needs: ikm.len > 0 and outLen > 0.} =
  ## ikm/label/fields/outLen: one XHKDF call; the only way a key is made here.
  var
    info: ByteSeq = archiveLabelInfo(label, fields)
  result = deriveXhkdf(ikm, @[], info, outLen)

proc toBytesArchive*(s: string): ByteSeq {.role: helper, tag: "archive".} =
  ## s: the bytes of a text, as they are.
  result = @(s.toOpenArrayByte(0, s.len - 1))

proc archiveText(A: openArray[uint8]): string {.role: helper, inline.} =
  ## A: bytes read as a text, unchanged.
  result = newString(A.len)
  for i, b in A: result[i] = char(b)

proc u16Bytes(v: uint16): ByteSeq {.role: helper, inline.} =
  ## v: two bytes, little-endian.
  appendU16Le(result, v)

proc u32Bytes(v: uint32): ByteSeq {.role: helper, inline.} =
  ## v: four bytes, little-endian.
  appendU32Le(result, v)

proc runArchiveArgon2(password, salt: openArray[uint8],
    S: ArchivePasswordSettings): ByteSeq {.role: math,
    tag: "archive|cryptoBoundary|kdf".} =
  ## password/salt/S: the slow, memory-hard step. 32 bytes out.
  when aspArgon2 in ameSymBuilt:
    result = tyr_argon2.argon2idTyrHash(password, salt, int(S.passes),
      int(S.memoryKiB), int(S.parallelism), archiveKeyBytes)
  else:
    raise newException(ValueError, "this build has no Argon2id; add argon2 " &
      "to -d:bifrostSymmetric= or omit the flag")

proc deriveArchiveLogin*(password: openArray[uint8], userId: string,
    S: ArchivePasswordSettings): ArchiveLoginKeys {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|kdf",
    needs: password.len > 0 and userId.len > 0.} =
  ## password: UTF-8, already NFKC-normalised by the caller (see the top).
  ## userId: the account's name; never changes.
  ## S: the settings stored for this account.
  ##
  ##   salt = userSalt | len(userId) | userId
  var
    salt: ByteSeq = @[]
    secret: ByteSeq = @[]
    err: string = archiveSettingsError(S)
  if err.len > 0:
    raise newException(ValueError, err)
  if validateUtf8(archiveText(password)) != -1:
    raise newException(ValueError, "archive password is not valid UTF-8")
  appendAmeBytes(salt, S.userSalt)
  appendU32Le(salt, uint32(userId.len))
  appendAmeBytes(salt, userId.toOpenArrayByte(0, userId.len - 1))
  secret = runArchiveArgon2(password, salt, S)
  result.authKey = archiveKey(secret, "ARCHIVE-AUTH-KEY-v1", [])
  result.wrapKey = archiveKey(secret, "ARCHIVE-WRAP-KEY-v1", [])
  secureClearAmeBytes(secret)
  secureClearAmeBytes(salt)

proc clearArchiveLogin*(K: var ArchiveLoginKeys) {.role: actor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## K: both keys erased.
  secureClearAmeBytes(K.authKey)
  secureClearAmeBytes(K.wrapKey)

proc newArchiveMasterKey*(): ByteSeq {.role: dataFetcher,
    tag: "archive|appApi|cryptoBoundary".} =
  ## 32 random bytes. Made once at sign-up, and again at a full key change.
  result = archiveRandom(archiveKeyBytes)

proc deriveArchiveSubKey*(masterKey: openArray[uint8], name: string,
    keyGen: uint16): ByteSeq {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|kdf",
    needs: masterKey.len == archiveKeyBytes and name.len > 0.} =
  ## masterKey/name/keyGen: one sub key per job. `name` says the job
  ## ("vault", "devices", "lanes", "settings" ...); `keyGen` counts full key
  ## changes, so a new master gives new sub keys even for the same names.
  result = archiveKey(masterKey, "ARCHIVE-SUB-KEY-v1",
    [toBytesArchive(name), u16Bytes(keyGen)])

proc deriveArchiveSpaceSecret*(S: FomkeState, spaceId: openArray[uint8],
    gen: uint16): ByteSeq {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|fomke|kdf",
    needs: spaceId.len == archiveSpaceIdBytes.} =
  ## S: the members' live FOMKE state (both ends hold the same tight key).
  ## spaceId/gen: which space, which generation.
  ##
  ## A child of the tight key under its own label, like SK: a secret that is
  ## STORED (wrapped in each member's vault) must never be a key a rotation
  ## also uses. Knowing it tells nothing about TK or any FOMKE message key.
  var
    extra: ByteSeq = @[]
  appendAmeBytes(extra, spaceId)
  appendU16Le(extra, gen)
  result = deriveFomkeTightChild(S, "ARCHIVE-SPACE-KEY-v1", extra)

proc deriveArchiveEpochKey*(spaceId, secret: openArray[uint8], gen: uint16,
    lane, epoch: uint32): ByteSeq {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|kdf",
    needs: secret.len == archiveKeyBytes.} =
  ## spaceId/secret/gen/lane/epoch: the key of one epoch on one lane.
  ## Derived, never stored: every member makes the same one when needed.
  result = archiveKey(secret, "ARCHIVE-EPOCH-KEY-v1", [@spaceId,
    u16Bytes(gen), u32Bytes(lane), u32Bytes(epoch)])

proc deriveArchiveBlock*(key: openArray[uint8], label: string,
    fields: openArray[ByteSeq], outLen: int): ByteSeq {.role: truthBuilder,
    tag: "archive|cryptoBoundary|kdf".} =
  ## key/label/fields/outLen: one key block (nonce + cipher keys + MAC keys)
  ## for sealing one record. Used by ./sealed and ./log only.
  result = archiveKey(key, label, fields, outLen)
