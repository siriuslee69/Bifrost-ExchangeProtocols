## -------------------------------------------------------------------------
## Secure Authority Package Example <- trust -> epoch -> repair -> plaintext
## -------------------------------------------------------------------------

import bifrost_exchange_protocols

const
  exampleKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

var
  authority: AmeAuthorityKey = initAmeAuthorityKey("example-root")
  root: AmeAuthorityRoot
  senderKey: AmeIdentityKey = initAmeIdentityKey("sender")
  receiverKey: AmeIdentityKey = initAmeIdentityKey("receiver")
  senderCert: AmeIdentityCertificate
  receiverCert: AmeIdentityCertificate
  layout: AmeSuiteLayout = defaultAmeLayout(exampleKems)
  tier: AmeMaskTier = fullAmeMaskTier(layout)
  path: AmeTierPath = initAmeTierPath(layout, [tier])
  client: AmeClientHandshake
  server: tuple[ok: bool, state: AmeServerHandshake, err: string]
  sender: AmeHandshakeResult
  receiver: AmeHandshakeResult
  plaintext: ByteSeq = newSeq[byte](8000)
  senderRelay: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 11'u64)
  receiverRelay: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 22'u64)
  senderPeer: DacLinkKey = initDacLinkKey("10.0.0.2", 7001'u16)
  receiverPeer: DacLinkKey = initDacLinkKey("10.0.0.1", 7000'u16)
  outgoing: AmeDacRelayStep
  step: AmeDacRelayStep
  restored: AmeSecurePackageResult
  delivered: int = 0
  dropped: int = 0

root = initAmeAuthorityRoot(authority)
## Certificates carry a serial, so one can be revoked without burning the
## name it was issued to.
senderCert = issueAmeIdentityCertificate(authority, senderKey, 1'u64,
  1'i64, 1000'i64)
receiverCert = issueAmeIdentityCertificate(authority, receiverKey, 2'u64,
  1'i64, 1000'i64)

## The hello names nobody. Both certificates travel inside sealed blocks, so
## an observer sees two nonces and some key material and never learns who is
## talking to whom.
client = beginAmeHandshake(1'u64, layout, tier)
server = answerAmeHandshake(client.hello, [path],
  initAmeCertificateAuthentication(root), receiverCert, receiverKey)
sender = finishAmeHandshake(client, server.state.serverHello,
  initAmeCertificateAuthentication(root), senderCert, senderKey, 10'i64)
receiver = acceptAmeHandshake(server.state, sender.finish,
  initAmeCertificateAuthentication(root), 10'i64)

for i in 0 ..< plaintext.len:
  plaintext[i] = uint8(i mod 251)

## The handshake gave both sides an epoch. That is what admits a peer to the
## relay: a datagram from any other address is dropped before it is parsed.
discard admitAmeDacPeer(senderRelay, senderPeer, initAmeSession(sender.auth,
  peerTrustRequired = false), 0'u32)
discard admitAmeDacPeer(receiverRelay, receiverPeer, initAmeSession(
  receiver.auth, peerTrustRequired = false), 0'u32)

## One call compresses, plans and sends. There is no package-level AEAD here:
## every datagram is sealed under the epoch, the manifest carrying the BLAKE3
## digest is itself sealed, and the receiver checks the assembled bytes
## against it. Nothing below this line touches a chunk by hand.
outgoing = sendAmeSecurePackage(senderRelay, senderPeer, 1'u64, plaintext,
  0'u32)

for i in 0 ..< outgoing.send.len:
  ## Drop one datagram in five, so the parity carried with the package has to
  ## do its job before the receiver can commit.
  if i mod 5 == 4:
    dropped = dropped + 1
    continue
  step = feedAmeDacDatagram(receiverRelay, receiverPeer, outgoing.send[i],
    uint32(i))
  delivered = delivered + 1
  if step.kind == adrPackageComplete:
    restored = openAmeSecurePackageStep(1'u64, step)

echo "trusted peer: ", sender.peerTrust.subjectKeyId
echo "datagrams:    ", delivered, " delivered, ", dropped, " dropped"
echo "restored:     ", restored.ok
echo "bytes:        ", restored.payload.len
