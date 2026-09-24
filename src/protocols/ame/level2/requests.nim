## -------------------------------------------------------------------------
## AME Requests <- "one more exchange" and "change algorithms", by name
## -------------------------------------------------------------------------
##
## Builds the request a side sends to ask for something; it changes nothing
## by itself. The four steps that carry it out (request -> reply or deny ->
## epoch-ready) live in session.nim and framing.nim:
##
##   S                  requests.nim                  framing.nim
##   (current layout)   ameAddExchangeRequest(S, ..)  beginAme*ExchangeFrame
##                      ameChangeRequest(S, ..)  ---> answer / finish / confirm

import ../types
import ../level1/exchange_paths
import ../level1/suites
import ../../config
import ./session
import runePragmas

## ╭⟢ asking for more key material or a change, by algorithm name
##
## Two kinds of request, both answered "yes" (reply) or "no" (deny):
##
##   more key material   "run one more LightSaber exchange now"
##                       -> ameAddExchangeRequest(S, [akaLightSaber])
##   a change            "switch on Gimli as a second cipher"
##                       -> ameChangeRequest(S, ameSelection(S, ciphers =
##                            [acaXChaCha20, acaGimli]))
##
## Nothing already agreed is thrown away. A KEM exchange ADDS its secret to
## that KEM's stack, which already holds a one-way image of every secret it
## produced before; the next epoch's keys come from FOMKE's carried secret
## plus those stacks:
##
##   stack(LightSaber)  = image of every LightSaber secret so far
##   one more exchange  -> stack' = image of (stack, fresh secret)
##   carried secret + all stacks  -> XHKDF -> new FOMKE keys
##
## Only old MESSAGE keys are erased (that is forward secrecy). A true fresh
## start, with none of the old secrets, is a new handshake.
##
## A request is built from the algorithms themselves; which bit each one
## sits on is worked out against the session's layout (always in wire-id
## order, so both ends agree on it). A family left out keeps its current
## selection. Naming an algorithm twice selects two instances of it (a
## layout may hold X25519 twice; each has its own keys). A KEM the change
## newly switches on always runs an exchange; `exchanges` adds more.
##
## Proof: by default the request is tagged under the session's own secret
## (the AM1P way, see "proving an in-session exchange"); `signed = true`
## signs it instead. Either way it travels encrypted.

proc ameManualTierId(S: AmeSession): uint32 {.role: helper.} =
  ## S: a tier id for a selection asked for by name. Kept apart from the
  ## small ids a tier path uses, so the two can never be mistaken.
  result = 0x8000_0000'u32 or (S.auth.current.epochId + 1'u32)

proc keepOrSelect[P, E](family: P, current: uint8,
    want: openArray[E]): uint8 {.role: helper.} =
  ## family/current/want: the new bits for one family -- the current ones
  ## when nothing is named.
  if want.len == 0:
    return current
  result = ameSelectionMask(family, want)

proc ameSelection*(S: AmeSession,
    kems: openArray[AmeKemAlgorithm] = [],
    ciphers: openArray[AmeCipherAlgorithm] = [],
    macs: openArray[AmeMacAlgorithm] = [],
    hashes: openArray[AmeHashAlgorithm] = [],
    signatures: openArray[AmeSignatureAlgorithm] = [],
    kdfs: openArray[AmeKdfAlgorithm] = []): AmeMaskTier {.
    role: configurator, tag: "appApi".} =
  ## S/kems/.../kdfs: the algorithms to have switched on after the change,
  ## family by family -> the selection to ask for. Every named algorithm
  ## must be in the session's layout.
  var
    L: AmeSuiteLayout = S.auth.current.layout
    now: AmeTierMasks = S.auth.current.tier.masks
  result = initAmeMaskTier(L, ameManualTierId(S), initAmeTierMasks(
    keepOrSelect(L.kems, now.kem, kems),
    keepOrSelect(L.ciphers, now.cipher, ciphers),
    keepOrSelect(L.macs, now.mac, macs),
    keepOrSelect(L.hashes, now.hash, hashes),
    keepOrSelect(L.signatures, now.signature, signatures),
    keepOrSelect(L.kdfs, now.kdf, kdfs)))

proc ameChangeRequest*(S: AmeSession, target: AmeMaskTier,
    exchanges: openArray[AmeKemAlgorithm] = [],
    signed: bool = currentBifrostConfig().ameSignedExchanges):
    AmeExchangeRequest {.role: configurator, tag: "appApi".} =
  ## S/target: a request to switch to `target`.
  ## exchanges: KEMs (already on) that run one more exchange as well; every
  ## KEM `target` newly switches on runs one anyway.
  ## signed: prove with signatures instead of the session tag.
  var
    L: AmeSuiteLayout = S.auth.current.layout
    fresh: uint8 = target.masks.kem and not S.auth.current.tier.masks.kem
    proof: AmeExchangeProof = aepSession
  if exchanges.len > 0:
    fresh = fresh or ameSelectionMask(L.kems, exchanges)
  if signed:
    proof = aepSignatures
  result = initAmeExchangeRequest(L.kems, target, fresh, S.pendingParams,
    proof)

proc ameAddExchangeRequest*(S: AmeSession,
    exchanges: openArray[AmeKemAlgorithm],
    signed: bool = currentBifrostConfig().ameSignedExchanges):
    AmeExchangeRequest {.role: configurator, tag: "appApi".} =
  ## S/exchanges: one more exchange for each named KEM -- new key material
  ## for the session, nothing else changes.
  ## signed: prove with signatures instead of the session tag.
  ##
  ##   ameAddExchangeRequest(S, [akaLightSaber])          one KEM
  ##   ameAddExchangeRequest(S, [akaX25519, akaX25519])   both X25519 instances
  result = ameChangeRequest(S, S.auth.current.tier, exchanges, signed)

