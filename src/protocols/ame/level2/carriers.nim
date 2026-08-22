## -------------------------------------------------------------------------
## AME Carriers <- which transports this build carries, and how to pick one
## -------------------------------------------------------------------------
##
## AME rides on one of two carriers:
##
##   tcp   one ordered stream. Nim's stream sockets, plus the TLS setup.
##   dac   Bifrost's own datagram transport, with its own peer registry.
##
## With no flag both are compiled, exactly as before. For a small target,
## name the one you use and the other's socket code never enters the build:
##
##     nim c -d:bifrostCarriers=dac firmware.nim
##
##   -d:bifrostCarriers=<list>   compiles          leaves out
##   -------------------------   ---------------   -----------------------
##   (omitted)                   both              nothing
##   tcp                         stream sockets    the DAC transport
##   dac                         DAC transport     std/net and TLS setup
##   tcp,dac                     both              nothing
##
## Three ways to say which carrier you mean
## ----------------------------------------
##
##   client.send(payload)            <- by TYPE. An AmeTcpClient sends over
##                                      TCP, an AmeDacClient over DAC; the
##                                      compiler picks, and costs nothing.
##
##   sealAmeFrame(S, carrier, p)     <- by VALUE. `carrier` may come from a
##                                      config file or a peer's hint, so one
##                                      `case` decides while running.
##
##   -d:bifrostCarriers=dac          <- by BUILD. Decides what exists at all.
##                                      A carrier left out raises here rather
##                                      than reaching a socket it lacks.

import std/strutils

import ../../types
import ../types
import ./session
import ../../../analysis_pragmas

export session

const
  bifrostCarriers* {.strdefine.}: string = ""
    ## Comma-separated carriers to compile. Empty (the default) is both.

proc parseAmeCarriers(s: string): set[AmeCarrier] {.role: parser.} =
  ## s: comma-separated carrier names from `-d:bifrostCarriers=`.
  ## Runs while compiling; an unknown name stops the build.
  var
    t: string = ""
  if s.strip().len == 0:
    return {acrTcp, acrDac}
  for raw in s.split(','):
    t = raw.strip()
    case t
    of "tcp": result.incl(acrTcp)
    of "dac": result.incl(acrDac)
    else:
      raise newException(ValueError, "unknown -d:bifrostCarriers entry '" & t &
        "' (expected: tcp, dac, or omit the flag for both)")
  if result == {}:
    raise newException(ValueError,
      "-d:bifrostCarriers= selected no carrier; omit the flag to keep both")

const
  ameCarriersBuilt* = parseAmeCarriers(bifrostCarriers)
    ## The carriers this build actually carries.

when acrTcp in ameCarriersBuilt:
  import ./carriers/tcp as ame_tcp
  export ame_tcp
when acrDac in ameCarriersBuilt:
  import ./carriers/dac as ame_dac
  export ame_dac

proc raiseExcludedCarrier(c: AmeCarrier) {.role: helper, noreturn, used.} =
  ## c: carrier this build left out.
  raise newException(ValueError, "AME carrier '" &
    (if c == acrTcp: "tcp" else: "dac") &
    "' is not in this build; add it to -d:bifrostCarriers= or omit the flag")

proc ameCarrierBuilt*(c: AmeCarrier): bool {.role: parser.} =
  ## c: carrier. True when this build can actually speak it.
  result = c in ameCarriersBuilt

proc sealAmeFrame*(S: var AmeSession, c: AmeCarrier,
    payload: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/c/payload: session, carrier chosen while running, and plaintext.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: result = sealAmeTcpFrame(S, payload)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: result = sealAmeDacFrame(S, payload)
    else: raiseExcludedCarrier(c)

proc openAmeFrame*(S: var AmeSession, c: AmeCarrier,
    frame: openArray[uint8]): AmeOpenResult {.role: orchestrator.} =
  ## S/c/frame: session, carrier chosen while running, and one received frame.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: result = openAmeTcpFrame(S, frame)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: result = openAmeDacFrame(S, frame)
    else: raiseExcludedCarrier(c)

proc beginAmeExchangeFrame*(S: var AmeSession, c: AmeCarrier,
    r: AmeExchangeRequest): ByteSeq {.role: orchestrator.} =
  ## S/c/r: initiator, carrier chosen while running, and the exact request.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: result = beginAmeTcpExchangeFrame(S, r)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: result = beginAmeDacExchangeFrame(S, r)
    else: raiseExcludedCarrier(c)

proc answerAmeExchangeFrame*(S: var AmeSession, c: AmeCarrier,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/c/frame: responder, carrier chosen while running, and the offer frame.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: result = answerAmeTcpExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: result = answerAmeDacExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)

proc finishAmeExchangeFrame*(S: var AmeSession, c: AmeCarrier,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/c/frame: initiator, carrier chosen while running, and the reply frame.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: result = finishAmeTcpExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: result = finishAmeDacExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)

proc confirmAmeExchangeFrame*(S: var AmeSession, c: AmeCarrier,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/c/frame: responder, carrier chosen while running, and epoch-ready.
  case c
  of acrTcp:
    when acrTcp in ameCarriersBuilt: confirmAmeTcpExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)
  of acrDac:
    when acrDac in ameCarriersBuilt: confirmAmeDacExchangeFrame(S, frame)
    else: raiseExcludedCarrier(c)
