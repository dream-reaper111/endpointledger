# Security model

Analyze only evidence you are authorized to possess. EndpointLedger is offline and read-only. It does not execute binaries, commands, scheduled tasks, or payloads. Imported logs and XML are untrusted. Use a restricted analysis host for hostile material. Reports can contain usernames, hostnames, IPs, and paths; protect them as sensitive incident evidence.

No API or authentication exists in this CLI milestone. Evidence origin and analyst are user-supplied, not independently verified. Hash-linked custody records show internal report integrity only, not legally certified chain of custody. The implementation does not access Windows endpoints or Linux journals directly. The current EVTX path needs optional `python-evtx` and has not been integration tested.
