# Owner Profile v1 source foundation

Status: `local_read_service_ready_provider_egress_blocked`

`myuna_core.owner_profile` implements a strict read-only foundation for an Owner-authored
stable Profile plus an authenticated local Unix-socket retrieval service. The local service
is installed and can retrieve bounded sections, but real Profile context is not connected to
the conversation/provider path while the selected provider is external DeepSeek.

## Modules

- `contracts.py`: schema, bounds, immutable values, and typed errors.
- `loader.py`: exact TOML/JSON parsing, digest/receipt verification, and 0700/0600/type/uid
  checks with no symlink following.
- `retrieval.py`: deterministic Unicode-aware bounded relevance and source citations.
- `projection.py`: allowlisted content-free audit metadata in `owner_profile_read_v1`.
- `protocol.py` and `client.py`: strict bounded request/response framing for
  `owner_profile.retrieve_v1`.
- `authorization.py`: authenticated Owner/private/channel and provider-egress gates.
- `service.py`: read-only Unix-socket worker running as the dedicated Profile identity.
- `lifecycle.py` and `lifecycle_ledger.py`: immutable revision transitions and a private
  hash-chained metadata ledger for P07-B.
- `providers/local.py`: disabled-by-default single-attempt adapter for the exact privileged
  loopback endpoint `127.0.0.1:879`; it forbids proxy, redirect, credential and hostname
  variance. The model runtime and model bytes are not installed or selected by this source.

## Test boundary

All fixtures are explicitly synthetic and describe a fictional test role. Focused tests:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests \
  python3 -m unittest discover -s tests -p 'test_owner_profile*.py' -v
```

The conversation path must not request or inject real Profile context until a non-DeepSeek
provider is explicitly authorized and the authenticated Owner-private channel gate is
selected. The package does not write legacy Owner Memory v1/v2, session context, P08
temporal context, or capability runtime. P07-B channel writes, automatic extraction, model
writes and physical purge remain disabled.

The local-provider adapter is only a source candidate. A future activation must use a
dedicated service identity with narrowly granted `CAP_NET_BIND_SERVICE`, pin exact runtime
and model bytes in a content-free receipt, pass synthetic protocol/resource tests and receive
Owner approval for the local host impact before real Profile prompt use.
