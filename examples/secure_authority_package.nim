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
  server: tuple[ok: bool, state: AmeServerHandshake,
    peerTrust: AmePeerTrustResult, err: string]
  sender: AmeHandshakeResult
  receiver: AmeHandshakeResult
  plaintext: ByteSeq = newSeq[byte](8000)
  plan: AmeSecurePackagePlan
  incoming: DacPackageReceiver
  restored: AmeSecurePackageResult

root = initAmeAuthorityRoot(authority)
senderCert = issueAmeIdentityCertificate(authority, senderKey, 1'i64, 1000'i64)
receiverCert = issueAmeIdentityCertificate(authority, receiverKey, 1'i64,
  1000'i64)
client = beginAmeHandshake(1'u64, layout, tier, senderCert, senderKey)
server = answerAmeHandshake(client.hello, [path], root, receiverCert,
  receiverKey, 10'i64)
sender = finishAmeHandshake(client, server.state.serverHello, root, senderKey,
  10'i64)
receiver = acceptAmeHandshake(server.state, sender.finish)

for i in 0 ..< plaintext.len:
  plaintext[i] = uint8(i mod 251)

plan = planAmeSecurePackage(sender.auth, 1'u64, plaintext,
  cleanLanDacDefaults())
incoming = initDacPackageReceiver(plan.package.manifest)
for chunk in plan.package.chunks:
  if chunk.chunkId != 1'u16:
    incoming.acceptDacPackageChunk(chunk)
discard incoming.repairGroup(plan.package.repairs[0])

restored = finishAmeSecurePackage(receiver.auth, incoming, plan.compression)
echo "trusted peer: ", sender.peerTrust.subjectKeyId
echo "restored:     ", restored.ok
echo "bytes:        ", restored.payload.len
