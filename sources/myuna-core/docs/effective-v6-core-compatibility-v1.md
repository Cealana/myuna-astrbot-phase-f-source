# Effective v6 Core compatibility modules v1

Status: repository candidate; not integrated into the live conversation engine.

This layer keeps v6 runtime behavior out of the Definition prompt. It provides:

- a versioned `DefinitionProfile` for v5 and v6 runtime documents;
- whole-message `CommandParser` with Blueout priority and deterministic errors;
- explicit Myuna, Chryna, and dual persona routing;
- a reason-coded `ChrynaWakeController` with a 90/100 takeover threshold;
- independent Myuna and Chryna persona contracts and a typed dual composer;
- a read-only `RuntimeStateRegistry` and model-free `/Check` renderer;
- a version-scoped create-once `TestFlightStateStore`;
- an external authoritative `RelationshipContext` with conservative nickname fallback.

The v6 profile deliberately uses a concise always-loaded core. Large appearance,
movement, worldbuilding, parameter, memory, tooling, maintenance, motivation,
style-example, Chryna, and command references are selected only for the matching
turn. Unknown topic, persona, or command keys fail closed. This preserves the
complete immutable Definition tree without exceeding the conversation engine's
runtime prompt limit on every ordinary message.

These modules grant no capability. They do not call a provider, channel, memory,
tool, database, scheduler, vision system, or service manager. File-backed
TestFlight state writes only when a future caller supplies an explicitly
authorized state directory and invokes `activate_once`; this candidate does not
instantiate that store.

The next stage must integrate the modules into `conversation.py` while keeping
v5 behavior stable. That integration requires separate tests for command
bypass, provider call counts, dual-response failure, Definition profile tree
validation, capability honesty, and rollback to the selected v5 Core release.
