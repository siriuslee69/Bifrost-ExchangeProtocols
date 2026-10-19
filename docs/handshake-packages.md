# Large AME handshakes over DAC

```nim
sendAmeHandshakeDac(socket, peer, encodeAmeServerHelloFrame(id, hello))
# A multi-peer server feeds each received datagram through:
var fed = feedAmeHandshakeDatagram(inbox, datagram, peerAddress)
# Only fed.ok AND fed.done may enter decodeAmeHandshakeFrame.
```

This adapter uses native DAC package planning, chunk scrambling and XOR
repair. It carries the original AME handshake bytes, including the original
sealed identities and transcript checks. It does not select another carrier
or change authentication. The small single-datagram driver remains useful
for builds without DAC's adaptive package layer.

```text
AME v4 header (26 bytes, integers little endian)
  kind 0x13 = HandshakePackage
  class Control, flags 0, root/lane 0
  original session id and original handshake step
       |
       +-- DAC message kind, u8
       +-- existing DAC manifest / chunk / parity body
```

Records up to 1200 bytes keep their ordinary AME handshake header. Larger
records are split into 1200-byte DAC chunks, with one XOR parity shard per
group. Every resulting datagram is at most 1280 bytes. A missing data shard
can be recovered from its group's parity. More loss causes an explicit
handshake failure; this adapter has no alternate-protocol retry.

Reassembly is bound to the source address, session id and handshake step.
The unauthenticated pool holds at most 16 incomplete records, each at most
512 KiB and 512 chunks, and expires inactive entries after 20 seconds when
the next shard is fed. Completed records must still pass the normal AME
handshake authentication. The DAC digest checks damage; it does not replace
the handshake's authentication.

`evaluation/tests/test_handshake_package.nim` checks small records, a 100 KB
record, a lost shard, damaged data, address separation and allocation limits.
It is included in `nimble test`.
