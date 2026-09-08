## -----------------------------------------------------------------
## Android LAN IP Test <- host listener + Motorola instrumentation
## -----------------------------------------------------------------

import std/[monotimes, net, nativesockets, os, osproc, strutils, times]

import ../src/analysis_pragmas
import ../src/clients/shared/lan_message
import ../src/protocols/transport/[tcp_ops, types]

const
  HostPort = 49371'u16
  PhonePort = 49372'u16
  TestClass = "com.siriuslee.bifrost.android.DirectLanInstrumentedTest"
  TestRunner = "com.siriuslee.bifrost.android.test/androidx.test.runner.AndroidJUnitRunner"

type
  HostExchangeState = object
    phoneHost: string
    receivedBody: string
    callbackAck: string
    error: string

proc shellJoin(args: openArray[string]): string {.role: helper, metaTags: {tagInterop}.} =
  ## args: executable and arguments to quote for the local shell.
  var
    i: int = 0
  while i < args.len:
    if i > 0:
      result.add(' ')
    result.add(quoteShell(args[i]))
    i = i + 1

proc runChecked(args: openArray[string]): string {.role: orchestrator, metaTags: {tagInterop}.} =
  ## args: command and arguments that must exit successfully.
  var
    p: tuple[output: string, exitCode: int] = execCmdEx(shellJoin(args))
  if p.exitCode != 0:
    raise newException(OSError, p.output)
  result = p.output

proc localLanIpv4(): string {.role: dataFetcher, metaTags: {tagNetworkSurface}.} =
  ## Returns the source IPv4 address used for the default route.
  var
    p: tuple[output: string, exitCode: int] = execCmdEx("ip route get 1.1.1.1")
    A: seq[string] = @[]
    i: int = 0
  if p.exitCode != 0:
    raise newException(IOError, "cannot inspect the host route")
  A = p.output.splitWhitespace()
  while i + 1 < A.len:
    if A[i] == "src":
      return A[i + 1]
    i = i + 1
  raise newException(IOError, "default route has no source address")

proc androidApk(root, kind: string): string {.role: helper, metaTags: {tagInterop}.} =
  ## root: repository root. kind: target or test APK selector.
  if kind == "target":
    result = root / "src/clients/android/app/build/outputs/apk/debug/androidApp-debug.apk"
  else:
    result = root / "src/clients/android/app/build/outputs/apk/androidTest/debug/androidApp-debug-androidTest.apk"

proc androidWifiIpv4(serial: string): string {.role: dataFetcher, metaTags: {tagNetworkSurface}.} =
  ## serial: adb device whose active wlan0 IPv4 address is required.
  var
    output: string = runChecked(["adb", "-s", serial, "shell", "ip", "-4", "-o",
      "addr", "show", "dev", "wlan0"])
    A: seq[string] = output.splitWhitespace()
    i: int = 0
    slash: int = -1
  while i + 1 < A.len:
    if A[i] == "inet":
      slash = A[i + 1].find('/')
      if slash > 0:
        return A[i + 1][0 ..< slash]
    i = i + 1
  raise newException(IOError, "connected Android device has no wlan0 IPv4 address")

proc serveExchange(S: ptr HostExchangeState) {.thread, role: orchestrator, metaTags: {tagNetworkSurface}.} =
  ## S: cross-thread result state for one phone-to-host and host-to-phone pass.
  var
    server: Socket
    client: Socket
    incoming: TcpFrameResult
    m: LanMessage
    ack: LanMessage
    callback: Socket
    callbackFrame: TcpFrameResult
  try:
    server = listenTcp(initTcpAddress("0.0.0.0", HostPort))
    server.getFd().setBlocking(false)
    var
      deadline: MonoTime = getMonoTime() + initDuration(seconds = 30)
      accepted: bool = false
      connected: bool = false
    while getMonoTime() < deadline and not connected:
      try:
        callback = connectTcp(initTcpAddress(S.phoneHost, PhonePort), 500)
        connected = true
      except CatchableError:
        sleep(100)
    if not connected:
      raise newException(IOError, "timed out connecting to the phone listener")
    sendTcpFrame(callback, encodeLanMessage(initLanMessage(lpTcp, "desktop-test",
      "Desktop", "host-to-phone", 3)))
    callbackFrame = recvTcpFrame(callback, 10_000, uint32(LanMessageMaxBodyBytes))
    if not callbackFrame.ok:
      raise newException(IOError, callbackFrame.err)
    S.callbackAck = decodeLanMessage(callbackFrame.payload).body
    callback.close()
    while getMonoTime() < deadline and not accepted:
      try:
        client = acceptTcpClient(server)
        accepted = true
      except CatchableError:
        sleep(50)
    if not accepted:
      raise newException(IOError, "timed out waiting for the phone connection")
    S.phoneHost = client.getPeerAddr()[0]
    incoming = recvTcpFrame(client, 10_000, uint32(LanMessageMaxBodyBytes))
    if not incoming.ok:
      raise newException(IOError, incoming.err)
    m = decodeLanMessage(incoming.payload)
    S.receivedBody = m.body
    ack = initLanAck(m, "desktop-test", "Desktop", 2)
    sendTcpFrame(client, encodeLanMessage(ack))
    client.close()
    server.close()
  except CatchableError as e:
    S.error = e.msg

proc runLanTest(serial: string) {.role: metaOrchestrator, metaTags: {tagNetworkSurface}.} =
  ## serial: adb device serial for the physical Android endpoint.
  var
    root: string = parentDir(parentDir(currentSourcePath()))
    host: string = localLanIpv4()
    S: HostExchangeState
    worker: Thread[ptr HostExchangeState]
    output: string = ""
  if not fileExists(androidApk(root, "target")) or not fileExists(androidApk(root, "test")):
    raise newException(IOError, "Android APKs are missing; run nimble androidTest first")
  discard runChecked(["adb", "-s", serial, "install", "-r", androidApk(root, "target")])
  discard runChecked(["adb", "-s", serial, "install", "-r", androidApk(root, "test")])
  S.phoneHost = androidWifiIpv4(serial)
  createThread(worker, serveExchange, addr S)
  sleep(250)
  output = runChecked(["adb", "-s", serial, "shell", "am", "instrument", "-w",
    "-e", "class", TestClass,
    "-e", "bifrostHost", host,
    "-e", "bifrostHostPort", $HostPort,
    "-e", "bifrostPhonePort", $PhonePort,
    TestRunner])
  joinThread(worker)
  if S.error.len > 0:
    if S.callbackAck.len > 0 and S.error.contains("phone connection"):
      raise newException(IOError, S.error &
        ". Host-to-phone passed; allow TCP ports 48371 and 49371 in the NixOS firewall for phone-to-host traffic")
    raise newException(IOError, S.error)
  if S.receivedBody.len == 0 or not S.receivedBody.startsWith("phone-to-host-"):
    raise newException(ValueError, "host did not receive the phone message")
  if not S.callbackAck.startsWith("ack TCP #"):
    raise newException(ValueError, "phone did not acknowledge the host callback")
  stdout.write(output)
  echo "LAN PASS | host=", host, " | phone=", S.phoneHost,
    " | inbound=", S.receivedBody, " | callback=", S.callbackAck

when isMainModule:
  var
    serial: string = getEnv("ANDROID_SERIAL", "")
  if paramCount() >= 1:
    serial = paramStr(1)
  if serial.len == 0:
    raise newException(ValueError,
      "Android serial is required through ANDROID_SERIAL or the first argument")
  runLanTest(serial)
