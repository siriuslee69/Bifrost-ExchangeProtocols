# Borders

job: turn keys and bytes into sealed bytes and back, and say in which order messages go. Whatever two machines must compute the same way lives here.
not its job: keeping anything on a disk -> Geist. Sockets that stay open, daemons, accounts, who is online -> Nebel. Drawing anything -> the apps.
never imports: geist, nebel, null_query
may be imported by: Nebel, the apps

A relay or a protocol that needs something kept takes two hooks (load, save) from its
caller. `protocols/dump` is the hand-over point: received bytes wait there until the
caller says they are stored.
