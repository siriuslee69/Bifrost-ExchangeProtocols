# Progress

Commit Message: Add explicit AME authentication mode foundation

Features (Planned):
- Shared authentication adapter and AM1M PSK path
- Mode-bound handshake records and session proofs
- Transport and evaluation coverage

Features (Done):
- Added AME authentication mode enum and PSK configurator/proof helpers.
- Documented the shared exchange intent in code comments.

Features (In Progress):
- Wiring PSK proofs into the handshake wire and FOMKE exchange path.

Notes:
- Handshake module compiles after the foundation change.
