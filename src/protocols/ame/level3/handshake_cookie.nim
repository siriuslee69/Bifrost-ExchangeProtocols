## -------------------------------------------------------------------------
## AME Handshake Cookie <- proving you can receive where you claim to be
## -------------------------------------------------------------------------
##
## ╭─ ❧ the problem 🌊
##
## Answering a hello costs real work: one key encapsulation per switched-on
## slot, plus verifying and producing signatures. A machine sending holds
## with forged return addresses could make a server do that work all day and
## never listen to a word of the answers.
##
## ╭─ ❧ the answer ⟡
##
## Before doing any of that work, the server sends back a short tag and asks
## to see it again:
##
##   client --- hello ------------------------------>  server
##          <-- retry: "send that again with THIS" --
##   client --- hello, now carrying the cookie ----->   only now does the
##                                                      expensive work run
##
## Someone who cannot receive at the address they claimed never gets the
## cookie, so they never get past the first line.
##
## ╭─ ❧ why the server remembers nothing ʕ•́ᴥ•̀ʔっ♡
##
## It keeps no list of cookies it has issued. It cannot: a list is itself
## something a flood can grow. Instead the cookie IS its own proof --
##
##   cookie = [ timestamp | tag( secret, timestamp + address + session id ) ]
##
## -- so the server simply recomputes the tag when the cookie comes back. No
## state, nothing to exhaust, and one secret to rotate whenever convenient.
## Rotating it costs one retry for the clients mid-flight.
##
## The tag deliberately does NOT cover the hello's nonce or its key material.
## A cookie proves reachability and nothing else, so a client may retry with
## fresh key material without paying for a second round trip.

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg

import ../../types
import ../types
import ../level0/bytes
import ../level1/symmetric
import ./handshake_identity
import runePragmas

const
  ameCookieSecretLen* = 32
  ameCookieLifetimeSeconds* = 30'i64
    ## How long a cookie stays good. Long enough to survive one round trip on
    ## a slow link, short enough that a captured cookie is worthless later.

type
  ## A server's stateless anti-flood secret. Rotate it whenever convenient;
  ## the only cost of rotating is that cookies in flight stop verifying and
  ## those clients retry once.
  AmeCookieSecret* {.role: configurator.} = object
    key*: ByteSeq

##
## The cookie proves one thing: that whoever sent the hello can also receive
## at the address it came from. It is a timestamp plus a tag over that
## timestamp, the address, and the session id -- and deliberately NOT over
## the hello nonce or the key material.
##
## That omission is load-bearing. A client answering a retry builds a whole
## new hello, fresh KEM keys and all, so that a flood of forged addresses
## leaves the server holding nothing. A cookie bound to the first hello's
## nonce could never validate against the second one, which would make
## `requireCookie` a switch that rejects every client that obeys it.
##
## Nothing is lost by leaving the nonce out. The cookie is not what proves
## the hello is genuine -- the transcript hash is, and it covers every field
## either side ever sends.

proc initAmeCookieSecret*(): AmeCookieSecret {.role: dataFetcher.} =
  ## A fresh server-side secret. Never leaves the machine, never goes on the
  ## wire; only tags computed with it do.
  result.key = tyr_random.cryptoRand(tyr_alg.raSystem, ameCookieSecretLen)

proc cookieSubject(peerId: openArray[uint8], issuedAtUnix: int64,
    sessionId: uint64): ByteSeq {.role: truthBuilder.} =
  ## peerId: the caller's stable name for the remote address.
  ## issuedAtUnix: when the cookie was minted.
  ## sessionId: the session the cookie is bound to.
  appendAmeLabel(result, "AME-COOKIE-v2")
  appendHandshakeBytes(result, peerId)
  appendHandshakeI64(result, issuedAtUnix)
  appendAmeU64(result, sessionId)

proc issueAmeCookie*(secret: AmeCookieSecret, peerId: openArray[uint8],
    nowUnix: int64, sessionId: uint64): ByteSeq {.role: truthBuilder,
    tag: "appApi|cryptoBoundary".} =
  ## secret: this server's anti-flood secret.
  ## peerId: the address the hello came from, named however the caller names
  ##   addresses. It is the ONE thing the cookie is really about.
  ## nowUnix: the clock, stamped into the cookie so it can expire.
  ## sessionId: bound in, so a cookie cannot be moved to another session.
  ##
  ## Mint one cookie: a timestamp followed by a tag over that timestamp, the
  ## address and the session. The server keeps no record of having issued it
  ## -- it recomputes the tag when the cookie comes back.
  var
    subject: ByteSeq = @[]
  if secret.key.len != ameCookieSecretLen:
    raise newException(ValueError, "AME cookie secret is missing")
  subject = cookieSubject(peerId, nowUnix, sessionId)
  appendHandshakeI64(result, nowUnix)
  appendAmeBytes(result, ameMacTag(amaBlake3, secret.key, subject, 32))
  secureClearAmeBytes(subject)

proc ameCookieValid*(secret: AmeCookieSecret, peerId: openArray[uint8],
    nowUnix: int64, sessionId: uint64,
    cookie: openArray[uint8]): bool {.role: parser,
    tag: "appApi|cryptoBoundary|validation".} =
  ## secret/peerId/nowUnix/sessionId: exactly what `issueAmeCookie` was given.
  ## cookie: the 40 bytes that came back, or anything at all.
  ##
  ## False for a cookie that is the wrong length, too old, from another
  ## address, for another session, or minted under a different secret. There
  ## is no error to distinguish between those: every one of them means the
  ## same thing, which is "do the cheap retry, not the expensive work".
  var
    issuedAtUnix: int64 = 0'i64
    subject: ByteSeq = @[]
    expected: ByteSeq = @[]
    i: int = 0
  if secret.key.len != ameCookieSecretLen or cookie.len != 40:
    return
  while i < 8:
    issuedAtUnix = issuedAtUnix or
      cast[int64](uint64(cookie[i]) shl (8 * i))
    i = i + 1
  if nowUnix < issuedAtUnix or
      nowUnix - issuedAtUnix > ameCookieLifetimeSeconds:
    return
  subject = cookieSubject(peerId, issuedAtUnix, sessionId)
  expected = ameMacTag(amaBlake3, secret.key, subject, 32)
  result = constantTimeEqualAme(expected, cookie[8 .. 39])
  secureClearAmeBytes(subject)
  secureClearAmeBytes(expected)
