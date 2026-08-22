## -------------------------------------------------------------------------
## AME <- Adaptive Message Encryption, and the flags that shrink it
## -------------------------------------------------------------------------
##
## One import gives the whole protocol:
##
##     import protocols/ame
##
## With no flags that is the full library, unchanged. Four flags cut it down
## for a small target, and NOTHING in your source has to change:
##
##     nim c -d:bifrostKems=kyber,x25519 -d:bifrostSigs=ed25519 \
##          -d:bifrostSymmetric=blake3,chacha20 -d:bifrostCarriers=dac fw.nim
##
##   flag                        decides                     default
##   -------------------------   -------------------------   -----------
##   -d:bifrostKems=<list>       which KEMs are compiled     all six
##   -d:bifrostSigs=<list>       which signatures exist      all four
##   -d:bifrostSymmetric=<list>  which primitives exist      all seven
##   -d:bifrostCarriers=<list>   which transports exist      both
##
##   KEM families:  x25519 kyber saber ntru frodo mceliece
##   Signatures:    ed25519 dilithium falcon sphincs
##   Primitives:    blake3 sha3 gimli chacha20 aes poly1305 argon2
##                  (blake3 is always compiled; AME needs it internally)
##   Carriers:      tcp  dac
##
## What each flag removes
## ----------------------
##
##   +-----------------------------+--------------------------------------+
##   | -d:bifrostKems=kyber        | the Saber, NTRU, Frodo, McEliece and |
##   |                             | X25519 implementations               |
##   +-----------------------------+--------------------------------------+
##   | -d:bifrostCarriers=dac      | Nim's stream sockets and TLS setup   |
##   +-----------------------------+--------------------------------------+
##   | -d:bifrostCarriers=tcp      | the DAC datagram transport, its peer |
##   |                             | registry, and DAC secure packages    |
##   +-----------------------------+--------------------------------------+
##
## Excluding something never changes the wire. All fifteen KEM slot numbers
## and both carrier tags keep their meaning, so a small node and a full node
## still understand each other whenever they share a KEM. What changes is
## what the small node can run: a slot it lacks is refused the moment a
## layout naming it is built or decoded, before any key material is touched.
##
## Choosing an algorithm or a carrier: three shapes
## ------------------------------------------------
##
##   by CONSTANT   ameKemKeypair(akaKyber768)     settled while compiling,
##                 client.send(payload)           no branch in the binary
##
##   by VALUE      ameKemKeypair(a)               one `case` while running,
##                 sealAmeFrame(S, c, payload)    for choices off the wire
##
##   by BUILD      -d:bifrostKems=kyber           decides what exists at all
##                 -d:bifrostCarriers=dac
##
## The first two share one name each. The compiler prefers the constant form
## whenever the argument is one, so ordinary code never picks a spelling.
##
## Where the detail lives
## ----------------------
##   protocols/ame/level1/algorithms  <- the KEM flag, in full
##   protocols/ame/level1/signatures  <- the signature flag, in full
##   protocols/ame/level1/symmetric   <- the symmetric flag, in full
##   protocols/ame/level2/carriers    <- the carrier flag, in full

import ./dac/build
import ./ame/types as ame_types
import ./ame/level0/protocols as ame_protocols
import ./ame/level1/algorithms as ame_algorithms
import ./ame/level1/signatures as ame_signatures
import ./ame/level1/symmetric as ame_symmetric
import ./ame/level1/exchange_paths as ame_exchange_paths
import ./ame/level1/suites as ame_suites
import ./ame/level1/derivation as ame_derivation
import ./ame/level1/tier_aead as ame_tier_aead
import ./ame/level1/path_triggers as ame_path_triggers
import ./ame/level1/compression as ame_compression
import ./ame/level2/protection as ame_protection
import ./ame/level2/agreement as ame_agreement
import ./ame/level2/trust as ame_trust
import ./ame/level2/wire as ame_wire
import ./ame/level2/carriers as ame_carriers
import ./ame/level3/handshake as ame_handshake
import ./ame/level3/handshake_wire as ame_handshake_wire
import ./ame/level3/handshake_transport as ame_handshake_transport

export ame_types
export ame_protocols
export ame_algorithms
export ame_signatures
export ame_symmetric
export ame_exchange_paths
export ame_suites
export ame_derivation
export ame_tier_aead
export ame_path_triggers
export ame_compression
export ame_protection
export ame_agreement
export ame_trust
export ame_wire
export ame_carriers
export ame_handshake
export ame_handshake_wire
export ame_handshake_transport

when acrDac in ameCarriersBuilt and dacAdaptiveBuilt:
  ## Secure packages are chunked, repaired transfers over DAC, so they need
  ## both the DAC carrier and the adaptive layer that plans and repairs them.
  ## The relay is what actually runs one: it holds a bounded set of peers, and
  ## joins the link loop to the session that authenticates every datagram.
  import ./ame/level3/dac_relay as ame_dac_relay
  import ./ame/level3/dac_endpoint as ame_dac_endpoint
  import ./ame/level3/secure_package as ame_secure_package
  export ame_dac_relay, ame_dac_endpoint, ame_secure_package

when acrTcp in ameCarriersBuilt:
  ## The stream-socket handshake driver. It owns a socket, so it only exists
  ## in a build that carries TCP at all.
  import ./ame/level3/handshake_tcp as ame_handshake_tcp
  export ame_handshake_tcp
