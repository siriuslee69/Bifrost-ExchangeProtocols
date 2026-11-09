## -------------------------------------------------------------------------
## Archive Login <- what a server keeps to check a password it never sees
## -------------------------------------------------------------------------
##
##   device: password ─Argon2id─▶ login secret ─▶ authKey ───▶ sent over the link
##   server: hash(authKey) is on file; the two are compared
##
## Def. 1 (auth hash): what the server stores. The authKey comes out of a slow
##   derivation and has 256 bits, so a fast hash is enough here: there is nothing
##   left to guess cheaply. The server learns nothing that opens the master key,
##   because the wrap key comes from a different label.
## Def. 2 (decoy settings): asked for the settings of a name it does not know, a
##   server answers with settings made from a secret of its own and that name.
##   The same name always gets the same answer, so nobody can tell which names
##   have accounts by asking twice.

import ../../types
import ../../ame/level1/symmetric/blake3
import ../types
import ../level1/keys
import runePragmas
import var_invariants

proc archiveAuthHash*(authKey: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|kdf",
    needs: authKey.len == archiveKeyBytes.} =
  ## authKey: Def. 1. 32 bytes.
  result = blake3AmeHash(toBytesArchive("ARCHIVE-AUTH-HASH-v1") & @authKey,
    archiveKeyBytes)

proc archiveDecoySettings*(serverSecret: openArray[uint8],
    userId: string): ArchivePasswordSettings {.role: truthBuilder,
    tag: "archive|appApi|cryptoBoundary|kdf".} =
  ## serverSecret/userId: Def. 2. Looks like the settings of a real account.
  result.memoryKiB = archiveDefaultMemoryKiB
  result.passes = archiveMinPasses
  result.parallelism = 1'u8
  result.userSalt = blake3AmeMac(serverSecret,
    toBytesArchive("ARCHIVE-DECOY-v1") & toBytesArchive(userId), archiveKeyBytes)
