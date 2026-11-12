# Borders

job: turn keys and bytes into sealed bytes and back, and say in which order messages go. Whatever two machines must compute the same way lives here.
not its job: keeping anything on a disk -> Geist. Sockets that stay open, daemons, accounts, who is online -> Nebel. A product window or app -> the apps.
never imports: geist, nebel, null_query
may be imported by: Nebel, the apps

planned cut: none — operator decision 2026-11-12. The generic protocols (tls13, http, smtp, mail) stay even though they add lines: they are "what two machines must compute the same way", which is this repo's job. src/clients/ stays too, because those are MULTI-DEVICE TEST clients, not a product app (see below). No second job grew here; the size is the wire job plus its test harness.

A relay or a protocol that needs something kept takes two hooks (load, save) from its
caller. `protocols/dump` is the hand-over point: received bytes wait there until the
caller says they are stored.

## src/clients/ are test clients, not an app

The Android app and the desktop demo under `src/clients/` exist to test a connection
and a data transfer between SEVERAL machines (or VMs). That is not a local test you
can run on one box: it needs two or more devices talking to each other. So they are
part of the test harness, not a product client, and they stay in this repo by the
operator's decision (2026-11-12). Do not propose cutting them out again, and do not
grow them into a product app — a real window or app belongs in its own repo.
`src/clients/README.md` repeats this at the folder itself.

One exception, added 2026-11-13: `src/clients/cli/enrollment.nim` is an OPERATOR
tool, not a test client and not an app. It is the command line a library is allowed
to have: it lets the operator admit public keys into a group-enrollment roster
(`protocols/enrollment`). It is the only part of enrollment that touches a disk;
the protocol module itself stays bytes-in, bytes-out.
