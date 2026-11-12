# To do

What is still to do in this repo. Rules: Agent-Conventions/WORKFLOW.md, section 8.
An item that is done is removed here and named in PROGRESS.md.

- [ ] Teaching project: this repo has items in ../Vegvisir-TeachingPlan/plan/repos/Backbone.md (B2 and B3; B1 is done).
  why: the class room, room share and mail for teaching stand on them; their order across repos is kept in one place, not here.
  start: read ../Vegvisir-TeachingPlan/plan/STATUS.md, then the file above
  done when: that file holds no item for this repo.
  needs: user (B2 waits for D2, B3 for D3)
  plan: ../Vegvisir-TeachingPlan/README.md, "How to use this repo": claim one item, do it here, close it there.

- [ ] src/ holds about 39 700 lines of Nim (limit 15 000) and BORDERS.md names no planned cut.
  why: a repo this size has more than one job, and every reader pays for all of them.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/repo-check.sh . | grep SIZE
  done when: BORDERS.md has a `planned cut:` line the user agreed to, or the cut is made.
  needs: user
  plan: recommended cuts, bottom first: (1) tls13/ + http/ + smtp/ + mail/ -> a repo of "other people's protocols" (they share no key or frame with AME, and a relay never needs them); (2) clients/ (the Android app and the desktop demo, with its tokens.css, docs/ui-plan.md and test_ui_contrast) -> their own app repo, since a client is never a library (WORKFLOW 2, Def. 2, question 3). AME, FOMKE, DAC, relay, dump and archive stay: they change together. tls13/, http/ and mail/ import protocols/byte_codec.nim: before cut (1) is made, byte_codec moves to Fylgia-Utils (see the item about the little-endian helpers) or the new repo imports it from here.

- [ ] rmGroup believes a claim from every neighbour unless the operator names the claimers.
  why: on a relay that admits neighbours the operator does not know, the first to say "that device is mine" may reach it, and its real server is refused afterwards.
  start: grep -n "setRelayGroupClaimers" -A12 src/protocols/relay/relay_node.nim
  done when: the user decided the start value.
  needs: user
  plan: recommended: keep the open start value for now (Nebel's hop daemon and three tests rely on it) and have Nebel's hop config name the claimers; flip the start value to "nobody may claim" in the same commit that moves Nebel's pin.

- [ ] The hook types of the restriction book still answer "" for success: RelayBookSave (relay_node.nim) returns a string, and the string is read in feedRelayRestriction.
  why: the same defect the twelve routines had, one step lower: a hook that forgets to return its error text reads as "saved".
  start: grep -n "RelayBookSave\|bookSave" src/protocols/relay/relay_node.nim; ../Nebel-DecentralizedDB/src/nebel/restriction_book.nim builds the pair
  done when: RelayBookSave answers tuple[ok: bool, err: string] (RelayBookLoad already does); test_relay_restriction and Nebel's restriction_book follow.
  needs: nobody
  plan: change the type, feedRelayRestriction and the test hooks in one commit; Nebel follows in the pass that moves its Bifrost pin (its TODO.md, the item about the next Bifrost pin).

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

- [ ] Otter reports 56 SECRETS candidates and 5 EMBEDDED CODE strings, mostly test fixtures and documentation tables.
  why: a real key would hide among the false alarms.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A10 "SECRETS\|EMBEDDED"
  done when: every line was looked at; real keys are removed, the rest are built at run time or marked as samples (see Otter's TODO.md, SECRETS item).
  needs: nobody
  plan: look at evaluation/tests/test_tls13_webpki.nim (four hits on one fixture name) and docs/chat-archive.md:188 first. The two python-looking blocks in dac/types.nim and dac/level3/link.nim are ASCII tables in doc comments.
