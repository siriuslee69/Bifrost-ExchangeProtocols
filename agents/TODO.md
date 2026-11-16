# To do

What is still to do in this repo. Rules: Agent-Conventions/WORKFLOW.md, section 8.
An item that is done is removed here and named in PROGRESS.md.

- [ ] TCP calls that wait with a timeout still go through Nim's own `select`: tcp_ops.nim `sock.recv(n, timeoutMs)` (line ~220), `sock.connect(host, port, timeoutMs)` (line ~280), and udp_ops.nim `connectUdp` (`sock.connect(..., timeoutMs)`, line ~304).
  why: Nim's wait keeps a table of 1024 sockets (64 on Windows). A TCP server or client whose process holds a socket numbered above 1023 overruns it: a build with glibc's fortify checks is stopped, another overwrites memory next to it. The UDP receive path and `readAvailableSocket` already wait through transport/wait_readable.nim. Nebel's UDP programs do not reach these calls with high numbers; a TCP server with over 1000 connections (a mail or web server built on Bifrost) does.
  start: grep -rn "recv(.*timeout\|connect(.*timeoutMs" src/protocols/transport/*.nim
  done when: no transport routine hands a timeout to std/net's recv, connect or accept; evaluation/tests/test_wait_readable.nim has a TCP case with a socket above 1023.
  needs: nobody (the user decided on 2026-11-16: later, when a TCP server with over 1000 connections exists; AME and DAC run over UDP and do not reach these calls with high numbers)
  plan: wait with `waitReadable` (readable) and a short non-blocking connect loop for the connect (it needs a "writable" wait beside the readable one), then read what is there. A TLS socket must still be read through its own `recv`: only the WAIT moves, never the read. Keep the error texts the callers match on. Run every tls13 and http test after.

- [ ] Teaching project: this repo has items in ../Vegvisir-TeachingPlan/plan/repos/Backbone.md (B2 and B3; B1 is done).
  why: the class room, room share and mail for teaching stand on them; their order across repos is kept in one place, not here.
  start: read ../Vegvisir-TeachingPlan/plan/STATUS.md, then the file above
  done when: that file holds no item for this repo.
  needs: user (B2 waits for D2); B3 is needs: nobody now — D3 answered 2026-11-12
  plan: ../Vegvisir-TeachingPlan/README.md, "How to use this repo": claim one item, do it here, close it there. B3 (Fjord imports Bifrost's smtp and mail) is ready to claim; its crypto uses Tyr's native Nim protocols, not libsodium/OpenSSL (D3 answer).

- [ ] rmGroup believes a claim from every neighbour unless the operator names the claimers.
  why: on a relay that admits neighbours the operator does not know, the first to say "that device is mine" may reach it, and its real server is refused afterwards.
  start: grep -n "setRelayGroupClaimers" -A12 src/protocols/relay/relay_node.nim
  done when: the user decided the start value.
  needs: user
  plan: recommended: keep the open start value for now (Nebel's hop daemon and three tests rely on it) and have Nebel's hop config name the claimers; flip the start value to "nobody may claim" in the same commit that moves Nebel's pin.

- [ ] Wire the enrollment trust (protocols/enrollment) into the group systems — the relay rmGroup and/or the archive spaces.
  why: groupMemberAllowed is a standalone primitive today; the relay GroupBook and the archive spaces still decide membership by identity strings, not by the enroller key + roster. The operator said this makes sense and deferred it (2026-11-13).
  start: grep -n "groupMemberAllowed" src/protocols/enrollment/level1/roster.nim; grep -n "groupAllows\|setGroup" src/protocols/relay/restriction_group.nim
  done when: the relay rmGroup and/or an archive space admits members through groupMemberAllowed (roster + enroller), with tests; the standalone primitive stays usable on its own.
  needs: nobody
  plan: bottom first. The relay GroupBook keys members by identity STRING while enrollment keys them by ameIdentityKeyId, so the caller must supply each member's public keys — give the relay a roster hook (like the restriction book's load/save) and gate group claims by groupMemberAllowed; then the archive space membership. Keep the protocol modules disk-free: the roster bytes come from the caller. Pick relay-first or archive-first when starting.

- [ ] The little-endian helpers of protocols/byte_codec.nim are also written in Fylgia-Utils (io/byte_utils.nim: appenders only), in Eir (private copies in ten files of its src), and in Nebel and Geist (Nebel's TODO.md, item 2).
  why: Bifrost now has ONE copy; the workspace still has five. A fix in one never reaches the others.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/dup-check.sh --workspace .
  done when: dup-check --workspace prints no ELSEWHERE for these helpers, and byte_codec.nim holds only what is specific to Bifrost (constantTimeEqual, isAllZero, readText).
  needs: nobody
  plan: after Nebel's item 2 puts the byte module into Fylgia-Utils (add readU16Le/readU32Le/readU64Le there; its own `ByteSeq` is the same type as ours, but a second symbol of that name makes every file that imports both ambiguous, so import with `from ... import`), Bifrost imports it and byte_codec loses its copies. Bifrost kept its own copy now because its src imports no Fylgia module yet and Fylgia has no readers.

- [ ] Otter lists six oversized files: ame/level3/handshake_dac.nim (296 code lines, 10 routines), bfx2/reader.nim (397), ame/level3/handshake_tcp.nim (4 routines, avg 43 lines), tls13/controlled_handshake.nim (3 routines, avg 54 lines), tools/run_tls13_openssl_interop.nim and tools/run_tls13_openssl_client_interop.nim.
  why: long routines are where a missed case hides; controlled_handshake.nim's three routines are the whole TLS handshake driver.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A8 "OVERSIZED FILES"
  done when: Otter no longer lists them.
  needs: nobody
  plan: controlled_handshake.nim first (cut each routine into the steps its comments already name; test_tls13_foundation and the interop tasks cover it).

- [ ] Otter lists 52 LAYOUT places (routines far from the one that calls them, mostly in ame/level1 and ame/level2) and 32 FAMILIES (groups of routines that differ in one type or one case).
  why: a reader has to jump through hundreds of lines to follow one routine.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A30 "LAYOUT"
  done when: those two headings are gone, or each remaining line is answered in docs (a misreading of Otter, with the reason).
  needs: nobody
  plan: one file per pass, the longest spread first (ame/level2/epochs.nim: five routines spread over 494 lines). FAMILIES that are `case`-style dispatchers over build flags (ame/level1/symmetric) may stay: say so in the file's header.

- [ ] Otter lists 20 routines without a role, 35 dead and 30 never-set configurator fields, 13 entries written and never read (AmeSession.lastExchangeDenial, the chunk tasks' ok and err fields) and 7 unused public routines (sendAmeHandshakeDac, recvAmeHandshakeDac, dumpDelivered, dumpWaiting, openDacListenerShared, applyRelayLoad, clearArchiveSpace).
  why: dead fields and routines are claims nobody checks.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A12 "ROLES\|CONFIG\|STATE\|DEAD CODE"
  done when: each is used, deleted or written down as meant for callers outside this repo (the README's public surface).
  needs: nobody
  plan: ask Nebel and Eris (grep their src) before deleting an exported routine; delete the unread chunk-task fields and AmeSession.lastExchangeDenial if nothing reads them.

- [ ] Otter reports SECRETS candidates and 5 EMBEDDED CODE strings, mostly test fixtures and documentation tables.
  why: a real key would hide among the false alarms.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A10 "SECRETS\|EMBEDDED"
  done when: every line was looked at; real keys are removed, the rest are built at run time or marked as samples (see Otter's TODO.md, SECRETS item).
  needs: nobody
  plan: DONE 2026-11-12: every src/ candidate was looked at and marked `# otter:allow` — they are key-DERIVATION LABELS or a mode name, not keys (archive/level1/keys.nim, ame/level3/handshake_transcript.nim, fomke/level1/chain.nim, fomke/level1/jump.nim); test_attack_surface.nim's canary and test_xhkdf.nim's published vectors are marked too. REMAINING: the test fixtures (test_chunkyaead, test_mitm_and_loss, test_tls13_webpki, test_config_exact, tls_test_support, test_smtp, test_transport_ops, lowmem_probe, test_ame_tcp_handshake, test_task_contract, tools/*) and docs/chat-archive.md:188 (derivation labels in a diagram). NOTE: a fixture file that uses `let` must have its `let` turned into `var` blocks first, or nim-check flags the file the moment it is touched (test_chunkyaead was backed out for this reason). The two python-looking EMBEDDED blocks in dac/types.nim and dac/level3/link.nim are ASCII tables in doc comments — say so, do not hide them.
