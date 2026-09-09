## --------------------------------------------------------------------
## Bifrost Desktop <- Nim-WebUI direct LAN messenger over BMSG/TCP v1
## --------------------------------------------------------------------

import std/[json, net, nativesockets, os, strutils]

import webui

import runePragmas
import ../shared/lan_message
import ../../protocols/transport/[tcp_ops, types]

const
  DesktopPort = 48371'u16
  DesktopNodeId = "bifrost-desktop"
  DesktopNodeName = "Desktop"

var
  gListener: Socket
  gEvents: seq[JsonNode] = @[]
  gSequence: uint64 = 1'u64

proc sourceDirectory(): string {.role: helper, tag: "interop".} =
  ## Returns the folder containing this desktop entry point.
  result = parentDir(currentSourcePath())

proc webDirectory(): string {.role: helper, tag: "interop".} =
  ## Returns the desktop client's local HTML/CSS/JavaScript root.
  result = sourceDirectory() / "web"

proc addEvent(direction, peer, body: string, isAck: bool = false,
    error: bool = false) {.role: dataWriter, tag: "interop".} =
  ## direction/peer/body: browser-visible event facts.
  ## isAck/error: presentation state markers.
  var
    e: JsonNode = newJObject()
  e["direction"] = %direction
  e["peer"] = %peer
  e["body"] = %body
  e["ack"] = %isAck
  e["error"] = %error
  gEvents.add(e)
  if gEvents.len > 240:
    gEvents.delete(0)

proc nextSequence(): uint64 {.role: actor, tag: "interop".} =
  ## Returns and advances the desktop BMSG sequence number.
  result = gSequence
  gSequence = gSequence + 1'u64

proc localLanAddress(): string {.role: dataFetcher, tag: "networkSurface".} =
  ## Returns a useful LAN address for display without making it authoritative.
  try:
    result = $getPrimaryIPAddr()
  except CatchableError:
    result = "0.0.0.0"

proc openListener() {.role: orchestrator, tag: "networkSurface".} =
  ## Opens the nonblocking desktop BMSG listener on all LAN interfaces.
  gListener = listenTcp(initTcpAddress("0.0.0.0", DesktopPort))
  gListener.getFd().setBlocking(false)
  addEvent("info", "local", "listening on " & localLanAddress() & ":" & $DesktopPort)

proc closeSocket(s: Socket) {.role: helper, tag: "networkSurface".} =
  ## s: socket to close without masking an earlier operation result.
  try:
    s.close()
  except CatchableError:
    discard

proc handleClient(c: Socket) {.role: orchestrator, tag: "networkSurface".} =
  ## c: accepted one-message BMSG connection.
  var
    frame: TcpFrameResult
    m: LanMessage
    ack: LanMessage
    peer: string = "peer"
  try:
    peer = c.getPeerAddr()[0]
    frame = recvTcpFrame(c, 3000, uint32(LanMessageMaxBodyBytes))
    if not frame.ok:
      raise newException(IOError, frame.err)
    m = decodeLanMessage(frame.payload)
    if m.protocol != lpTcp:
      raise newException(ValueError, "desktop listener accepts TCP BMSG only")
    addEvent("in", m.senderName & " @ " & peer, m.body, m.isAck)
    if not m.isAck:
      ack = initLanAck(m, DesktopNodeId, DesktopNodeName, nextSequence())
      sendTcpFrame(c, encodeLanMessage(ack), uint32(LanMessageMaxBodyBytes))
  except CatchableError as e:
    addEvent("error", peer, e.msg, error = true)
  closeSocket(c)

proc pumpListener() {.role: orchestrator, tag: "networkSurface".} =
  ## Accepts all currently waiting clients without blocking the WebUI loop.
  var
    c: owned(Socket)
  while true:
    try:
      gListener.accept(c)
      handleClient(c)
    except CatchableError:
      break

proc sendMessage(host, body: string): JsonNode {.role: orchestrator, tag: "networkSurface".} =
  ## host/body: validated destination and user-authored UTF-8 message.
  var
    cleanHost: string = host.strip()
    cleanBody: string = body.strip()
    c: Socket
    frame: TcpFrameResult
    m: LanMessage
    ack: LanMessage
  result = newJObject()
  try:
    if cleanHost.len == 0:
      raise newException(ValueError, "peer IP is empty")
    if cleanBody.len == 0:
      raise newException(ValueError, "message is empty")
    m = initLanMessage(lpTcp, DesktopNodeId, DesktopNodeName, cleanBody,
      nextSequence())
    c = connectTcp(initTcpAddress(cleanHost, DesktopPort), 3500)
    sendTcpFrame(c, encodeLanMessage(m), uint32(LanMessageMaxBodyBytes))
    addEvent("out", cleanHost, cleanBody)
    frame = recvTcpFrame(c, 3500, uint32(LanMessageMaxBodyBytes))
    if not frame.ok:
      raise newException(IOError, "ack failed: " & frame.err)
    ack = decodeLanMessage(frame.payload)
    if not ack.isAck or ack.protocol != lpTcp:
      raise newException(ValueError, "peer returned an invalid acknowledgement")
    addEvent("in", ack.senderName & " @ " & cleanHost, ack.body, true)
    result["ok"] = %true
  except CatchableError as e:
    addEvent("error", cleanHost, e.msg, error = true)
    result["ok"] = %false
    result["error"] = %e.msg
  if not c.isNil:
    closeSocket(c)

proc drainEvents(): JsonNode {.role: dataFetcher, tag: "interop".} =
  ## Moves pending desktop events into one browser response.
  result = newJArray()
  for e in gEvents:
    result.add(e)
  gEvents.setLen(0)

proc handleInterop(raw: string): string {.role: parser, tag: "interop".} =
  ## raw: one JSON browser request.
  var
    request: JsonNode
    reply: JsonNode = newJObject()
  try:
    request = parseJson(raw)
    case request{"op"}.getStr("")
    of "status":
      reply["ok"] = %true
      reply["address"] = %(localLanAddress() & ":" & $DesktopPort)
      reply["name"] = %DesktopNodeName
    of "events":
      reply["ok"] = %true
      reply["events"] = drainEvents()
    of "send":
      reply = sendMessage(request{"host"}.getStr(""), request{"body"}.getStr(""))
    else:
      reply["ok"] = %false
      reply["error"] = %"unknown desktop operation"
  except CatchableError as e:
    reply["ok"] = %false
    reply["error"] = %e.msg
  result = $reply

proc runDesktop() {.role: metaOrchestrator, tag: "interop|networkSurface".} =
  ## Opens the LAN listener and desktop WebUI until the window closes.
  var
    w: Window = newWindow()
    shown: bool = false
  if not dirExists(webDirectory()):
    raise newException(IOError, "desktop web root is missing")
  openListener()
  w.bind("bifrostInterop", proc (e: Event): string =
    handleInterop(e.getString(0)))
  w.setSize(1120, 760)
  w.rootFolder = webDirectory()
  shown = w.show("index.html")
  if not shown:
    closeSocket(gListener)
    raise newException(IOError, "Bifrost desktop could not open a WebUI renderer")
  while w.shown():
    pumpListener()
    sleep(40)
  closeSocket(gListener)
  clean()

when isMainModule:
  runDesktop()
