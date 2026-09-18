## -------------------------------------------------------------------------
## AME Secret Stack <- what a KEM slot has agreed, all of it, folded together
## -------------------------------------------------------------------------
##
## A slot does not hold the secret it last agreed. It holds EVERYTHING it has
## ever agreed, so each exchange makes the next one harder to unpick rather
## than simply replacing what came before:
##
##   first exchange   stack = H( binder, slot, algorithm, 1, secret1 )
##   rotation         stack = H( H(stack), binder, slot, algorithm, 2, secret2 )
##   rotation         stack = H( H(stack), binder, slot, algorithm, 3, secret3 )
##
## `H` is the tier's hash overlay -- every switched-on hash slot, XORed --
## so breaking one hash primitive is not enough here either.
##
## ╭─ ❧ what this file is for 🌊
##
## One place owns the whole life of `AmeExchangeState.stackedSecrets`: what
## goes into it, and what comes back out for a key to be built from. The two
## used to sit in different files, which is how the meaning of those bytes
## could change on one side without the other noticing.
##
##   applyAmeExchange()      an exchange arrives and is absorbed
##   buildAmeExchangeSeed()  the accumulated secrets are handed to a KDF
##   ameStackDepth()         how many exchanges the shallowest slot has seen
##
## Nothing here ever reaches a wire. These bytes are hashed into keys and
## erased; the wire carries ciphertexts and public keys, which is a different
## file's problem entirely.

import ../../types
import ../types
import ../level0/bytes
import ./exchange_paths
import ./suites
import runePragmas

proc carryAmeStack(L: AmeSuiteLayout, t: AmeMaskTier,
    previous: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|exchange|kdf".} =
  ## L/t/previous: what a slot had accumulated, hashed before it is carried
  ## into the next exchange.
  ##
  ## Hashed on its own first, rather than dropped straight into the seed
  ## below. The two are equally sound -- everything in that seed is
  ## length-prefixed either way -- but this way the value that sits next to
  ## freshly arrived KEM material is an IMAGE of the stack rather than the
  ## stack itself, so nothing about the accumulated secret is ever placed
  ## beside bytes an attacker had a hand in choosing.
  ##
  ## An empty stack carries nothing. That is the first exchange on a slot, and
  ## the binder beside it is what makes even that one depend on more than the
  ## KEM.
  var
    seed: ByteSeq = @[]
  if previous.len == 0:
    return
  appendAmeLabel(seed, "AME-SECRET-STACK-CARRY-v1")
  appendAmeU32(seed, uint32(previous.len))
  appendAmeBytes(seed, previous)
  result = hashAmeTier(L, t, seed, ameProtectionKeyLen)
  secureClearAmeBytes(seed)

proc stackAmeSecret*(L: AmeSuiteLayout, t: AmeMaskTier,
    previous, binder, fresh: openArray[uint8], slot: int,
    algorithm: AmeKemAlgorithm, generation: uint32): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|exchange|kdf".} =
  ## L/t: layout and target tier, so the stack is bound to the slot selection
  ## it was built under and hashed by every hash primitive that tier switches
  ## on -- breaking one of them is not enough here either.
  ## previous: what this slot had accumulated, or empty on its first exchange.
  ## binder: what the provisioned secret contributes, or empty where there is
  ## none.
  ## fresh: the shared secret this exchange just produced.
  ## slot/algorithm/generation: which slot this is, which KEM it ran, and how
  ## many exchanges it has now absorbed.
  ##
  ## ╭─ ❧ what stacking is for 🌊
  ##
  ## A slot used to hold the secret it last agreed, and a rotation threw the
  ## old one away:
  ##
  ##   epoch 1   key = KDF( ... secret1 ... )
  ##   epoch 2   key = KDF( ... secret2 ... )      secret1 gone, and irrelevant
  ##
  ## So an attacker who recovered secret2 -- a KEM broken years from now, a bad
  ## random number, a machine with a flaw -- read epoch 2, and the work that
  ## went into epoch 1 protected nothing.
  ##
  ## Now the slot holds everything it has ever agreed, folded together:
  ##
  ##   epoch 1   stack1 = H( binder, 1, secret1 )
  ##   epoch 2   stack2 = H( H(stack1), binder, 2, secret2 )
  ##   epoch 3   stack3 = H( H(stack2), binder, 3, secret3 )
  ##
  ## secret2 on its own is now worth nothing: the key hangs off stack2, and
  ## stack1 cannot be reached from secret2. To follow the session an attacker
  ## needs EVERY exchange it has ever done, and the provisioned secret beneath
  ## all of them. Each rotation makes that harder, and none of them make it
  ## easier.
  ##
  ## ╭─ ❧ what it does not cost 🍣
  ##
  ## Forward secrecy is exactly what it was. The old stack is erased the
  ## instant the new one is built, and the new one is a one-way image of it, so
  ## a machine seized today still cannot read yesterday. What changes is only
  ## what an attacker needs in order to read TOMORROW.
  var
    seed: ByteSeq = @[]
    carried: ByteSeq = carryAmeStack(L, t, previous)
  if fresh.len == 0:
    raise newException(ValueError, "AME exchange shared secret is empty")
  appendAmeLabel(seed, "AME-SECRET-STACK-v1")
  appendAmeU32(seed, uint32(carried.len))
  appendAmeBytes(seed, carried)
  appendAmeU32(seed, uint32(binder.len))
  appendAmeBytes(seed, binder)
  seed.add(uint8(slot))
  seed.add(uint8(ord(algorithm)))
  appendAmeU32(seed, generation)
  appendAmeU32(seed, uint32(fresh.len))
  appendAmeBytes(seed, fresh)
  result = hashAmeTier(L, t, seed, ameProtectionKeyLen)
  secureClearAmeBytes(seed)
  secureClearAmeBytes(carried)

proc applyAmeExchange*(S: var AmeExchangeState, L: AmeSuiteLayout,
    r: AmeExchangeRequest, sharedSecrets: openArray[ByteSeq],
    binder: openArray[uint8] = []) {.role: actor,
    tag: "cryptoBoundary|exchange".} =
  ## S/L/r/sharedSecrets: the selected slots absorb what this exchange
  ## produced; slots the mask left alone keep what they had.
  ## binder: the provisioned secret's contribution, empty where there is none.
  ##
  ## Absorb, not replace. See `stackAmeSecret` for what that buys and why it
  ## costs no forward secrecy.
  var
    stacked: ByteSeq = @[]
    i: int = 0
    j: int = 0
  discard initAmeExchangeRequest(S.algorithms, r.targetTier, r.exchangeMask)
  if not kemLayoutsEquivalent(S.algorithms, L.kems):
    raise newException(ValueError, "AME exchange layout and state differ")
  if sharedSecrets.len != selectedAlgorithmCount(r):
    raise newException(ValueError, "AME exchange shared-secret count mismatch")
  while i < int(S.algorithms.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      if sharedSecrets[j].len == 0:
        raise newException(ValueError, "AME exchange shared secret is empty")
      if S.generation[i] == high(uint32):
        raise newException(ValueError, "AME exchange generation is exhausted")
      stacked = stackAmeSecret(L, r.targetTier, S.stackedSecrets[i], binder,
        sharedSecrets[j], i, S.algorithms.algorithms[i], S.generation[i] + 1'u32)
      secureClearAmeBytes(S.stackedSecrets[i])
      S.stackedSecrets[i] = stacked
      S.generation[i] = S.generation[i] + 1'u32
      S.activeMask = S.activeMask or slotMask(i)
      j = j + 1
    i = i + 1

proc buildAmeExchangeSeed*(S: AmeExchangeState,
    selectedMask: uint8): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|exchange|kdf".} =
  ## S/selectedMask: the chosen slots' accumulated secrets, each bound to its
  ## position, its algorithm, and how deep its stack is.
  ##
  ## The label says v3 because the bytes changed meaning in place: what sits
  ## here is now a slot's whole history rather than its latest agreement. An
  ## endpoint built before that change and one built after would derive
  ## different keys from the same exchange, and the version is what makes that
  ## a refusal rather than a silent mismatch.
  var i: int = 0
  if selectedMask == 0'u8 or (selectedMask and not S.activeMask) != 0'u8:
    raise newException(ValueError, "AME selected KEM secret is unavailable")
  appendAmeLabel(result, "AME-EXCHANGE-SELECTION-v3")
  result.add(S.algorithms.length)
  result.add(selectedMask)
  while i < int(S.algorithms.length):
    if algorithmSlotSelected(selectedMask, i):
      if S.generation[i] == 0'u32 or S.stackedSecrets[i].len == 0:
        raise newException(ValueError, "AME selected KEM secret is unavailable")
      result.add(uint8(i))
      result.add(uint8(ord(S.algorithms[i])))
      appendAmeU32(result, S.generation[i])
      appendAmeU32(result, uint32(S.stackedSecrets[i].len))
      appendAmeBytes(result, S.stackedSecrets[i])
    i = i + 1

proc ameStackDepth*(S: AmeExchangeState, selectedMask: uint8): uint32 {.
    role: parser, tag: "appApi|exchange".} =
  ## S/selectedMask: how many exchanges the SHALLOWEST chosen slot has
  ## absorbed. The weakest link is the honest answer: a tier is only as deep
  ## as the slot an attacker would pick to work on.
  ##
  ## Worth reading before deciding to rotate again, and worth saying out loud:
  ## depth only grows with FRESH key material. Rotating without a new exchange
  ## hashes a value an attacker could hash just as easily, and buys nothing.
  var
    i: int = 0
  result = high(uint32)
  while i < int(S.algorithms.length):
    if algorithmSlotSelected(selectedMask, i):
      result = min(result, S.generation[i])
    i = i + 1
  if result == high(uint32):
    result = 0'u32

