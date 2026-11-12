# To do

What is still to do in this repo. Rules: Agent-Conventions/WORKFLOW.md, section 8.
An item that is done is removed here and named in PROGRESS.md.

- [ ] Teaching project: this repo has items in ../Vegvisir-TeachingPlan/plan/repos/Backbone.md (B1 to B3).
  why: the class room, room share and mail for teaching stand on them; their order across repos is kept in one place, not here.
  start: read ../Vegvisir-TeachingPlan/plan/STATUS.md, then the file above
  done when: that file holds no item for this repo.
  needs: nobody
  plan: ../Vegvisir-TeachingPlan/README.md, "How to use this repo": claim one item, do it here, close it there.

- [ ] Eight exported relay routines answer "" for success: setRelayRestriction, attachRestrictionBook (relay_node.nim), checkRestrictionMode, applyRestrictionUpdate (restriction.nim), fromServerControl (super_fast_control.nim), addSuperFastVip, setSuperFastRestriction (super_fast_udp.nim), and openAmeHelloOffer (ame/level3/handshake_transcript.nim).
  why: a caller reads `if x.len == 0` as "nothing came back"; one forgotten check and a refused restriction mode looks like one that is on.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/repo-check.sh . | grep -A9 "ERROR STYLE"
  done when: repo-check prints no ERROR STYLE; nimble test passes.
  needs: nobody
  plan: this is item B1 of ../Vegvisir-TeachingPlan/plan/repos/Backbone.md. Answer with tuple[ok: bool, err: string]; Nebel calls the first two and follows when it moves its pin (its own TODO.md names the order).

- [ ] The same routine body stands in several places (TWINS, SAME SHAPE): constantTimeTagEqual / constantTimeFinishedEqual (tls13), maybeEnableDualStackWildcard (tcp_ops, udp_ops), the zero-digest checks (dac), the little-endian appenders and readers (ame/level0/bytes, dac/level0/body_codec, transport/stream_framing), the secret-row clearers, failClient / failServer (tls13).
  why: a fix in one copy never reaches the other. Two of them compare secrets in constant time; a careless edit to one copy would not show in the other's tests.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/dup-check.sh .
  done when: dup-check prints nothing for this repo.
  needs: nobody
  plan: keep ONE of each in the lowest module both callers already import (protocols/types or ame/level0/bytes), export it, delete the others. The byte appenders are also in Nebel and Geist: move those to Fylgia-Utils in the same pass.

- [ ] repo-check lists evaluation/tests/test_otter_catalog.nim under ORPHAN TESTS, but it is not a test: it is the list of entries for Otter's test window, and it starts `nimble test` itself.
  why: the line stays in every check as a FIX, and adding the file to the test task would make the suite start itself.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/repo-check.sh . | grep -A2 "ORPHAN TESTS"
  done when: repo-check prints no ORPHAN TESTS.
  needs: nobody
  plan: move it out of the test_ name (evaluation/otter_catalog.nim) and point the Otter test window task at the new name; check that `nimble` still opens the window with the three suites listed.

- [ ] src/ holds about 39 500 lines of Nim (limit 15 000) and BORDERS.md names no planned cut.
  why: a repo this size has more than one job, and every reader pays for all of them.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/repo-check.sh . | grep SIZE
  done when: BORDERS.md has a `planned cut:` line the user agreed to, or the cut is made.
  needs: user
  plan: recommended cuts, bottom first: (1) tls13/ + http/ + smtp/ + mail/ -> a repo of "other people's protocols" (they share no key or frame with AME, and a relay never needs them); (2) clients/ (the Android app and the desktop demo) -> their own app repo, since a client is never a library (WORKFLOW 2, Def. 2, question 3). AME, FOMKE, DAC, relay, dump and archive stay: they change together.

- [ ] The desktop demo types 20 colours where they are used and names two fields twice (src/clients/desktop/web/).
  why: a typed colour does not switch with the theme; a label and a placeholder say the same word twice.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/ui-check.sh .
  done when: ui-check prints no COLOURS and no NAMED TWICE.
  needs: nobody
  plan: a tokens.css with the roles of UI.md 6; the two labels go, the placeholders stay. Best done after the clients/ cut above.

- [ ] rmGroup believes a claim from every neighbour unless the operator names the claimers.
  why: on a relay that admits neighbours the operator does not know, the first to say "that device is mine" may reach it, and its real server is refused afterwards.
  start: grep -n "setRelayGroupClaimers" -A12 src/protocols/relay/relay_node.nim
  done when: the user decided the start value.
  needs: user
  plan: recommended: keep the open start value for now (Nebel's hop daemon and three tests rely on it) and have Nebel's hop config name the claimers; flip the start value to "nobody may claim" in the same commit that moves Nebel's pin.
