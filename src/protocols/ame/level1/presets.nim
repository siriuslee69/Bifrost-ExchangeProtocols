## -------------------------------------------------------------------------
## AME Presets <- the old fixed suites, written as slot selections
## -------------------------------------------------------------------------
##
## Bifrost used to ship two hand-built AEAD constructions with their own
## code, their own key schedules and their own wire formats:
##
##   TMEAEAD  XChaCha20, then AES-CTR, then Gimli over the payload, with a
##            Gimli tag and a Poly1305 tag XORed into one
##   GGAEAD   Gimli over the payload, with one Gimli-keyed tag
##
## Both are special cases of what the slot construction in `tier_aead.nim`
## does in general: run every switched-on cipher over the payload in turn,
## XOR every switched-on authenticator into one tag. So they are no longer
## separate code. They are two rows of bits:
##
##                 cipher slots                    MAC slots
##                 XCha  AES  Gimli                Gimli  Poly
##   TMEAEAD tier   1     1     1                    1     1
##   GGAEAD  tier   -     -     1                    1     -
##
## What this file gives back is that selection under a name, so a caller who
## wants what TMEAEAD did asks for it by name instead of assembling slot
## tables by hand and hoping the order matches.
##
## THE BYTES ARE NOT THE SAME. These presets pick the same primitives in the
## same order; they do not reproduce the old formats. The differences are
## deliberate and each one is the newer code being stricter:
##
##   - keys come from one derivation over the whole slot block, not from a
##     fixed five-key layout
##   - each cipher slot gets its own nonce slice, instead of AES borrowing a
##     nonce derived from the XChaCha one
##   - the Gimli authenticator is the keyed HMAC construction the MAC slot
##     defines, not the sponge's own tag call
##   - the tag length is whatever the session agreed, not a fixed 32
##
## Nothing sealed by the old code can be opened by these, and nothing should
## be: the old formats are gone from the library.

import ./suites
import ./symmetric
import ./signatures

import ../types
import ../../../analysis_pragmas

proc tmeAeadAmeCiphers*(): AmeCipherAlgorithms {.role: configurator.} =
  ## The three-cipher chain TMEAEAD ran, in TMEAEAD's order. A build that
  ## left out any of these primitives is refused here rather than at the
  ## first message.
  result = initAmeCipherAlgorithms([acaXChaCha20, acaAesCtr, acaGimli])

proc tmeAeadAmeMacs*(): AmeMacAlgorithms {.role: configurator.} =
  ## The two authenticators TMEAEAD XORed together.
  result = initAmeMacAlgorithms([amaGimli, amaPoly1305])

proc tmeAeadAmeLayout*(kems: AmeKemAlgorithms): AmeSuiteLayout {.
    role: configurator.} =
  ## kems: the KEM slots this deployment uses. Everything else is TMEAEAD's
  ## selection, with the default hash, signature and KDF slots -- families
  ## TMEAEAD never had an opinion about.
  result = initAmeSuiteLayout(kems, tmeAeadAmeCiphers(), tmeAeadAmeMacs(),
    initAmeHashAlgorithms([defaultAmeHashSlot()]),
    initAmeSignatureAlgorithms(defaultAmeSigSlots()),
    initAmeKdfAlgorithms(defaultAmeKdfSlots()))

proc ggAeadAmeCiphers*(): AmeCipherAlgorithms {.role: configurator.} =
  ## The single cipher GGAEAD ran.
  result = initAmeCipherAlgorithms([acaGimli])

proc ggAeadAmeMacs*(): AmeMacAlgorithms {.role: configurator.} =
  ## The single authenticator GGAEAD ran. `amaGimli` IS the keyed Gimli HMAC
  ## GGAEAD called directly, so this slot is the same primitive.
  result = initAmeMacAlgorithms([amaGimli])

proc ggAeadAmeLayout*(kems: AmeKemAlgorithms): AmeSuiteLayout {.
    role: configurator.} =
  ## kems: KEM slots, with GGAEAD's one-cipher one-MAC selection. The compact
  ## end of the range: one primitive doing each job, for a device that cannot
  ## afford three.
  result = initAmeSuiteLayout(kems, ggAeadAmeCiphers(), ggAeadAmeMacs(),
    initAmeHashAlgorithms([defaultAmeHashSlot()]),
    initAmeSignatureAlgorithms(defaultAmeSigSlots()),
    initAmeKdfAlgorithms(defaultAmeKdfSlots()))

proc presetAmeTier*(L: AmeSuiteLayout,
    tierId: uint32 = 1'u32): AmeMaskTier {.role: configurator.} =
  ## L/tierId: switch on every slot the preset layout defines.
  ##
  ## A preset layout holds exactly the slots its suite used and no spares, so
  ## "everything on" is the whole suite. Build a narrower tier by hand when
  ## the point is to start weak and rotate up.
  result = fullAmeMaskTier(L, tierId)
