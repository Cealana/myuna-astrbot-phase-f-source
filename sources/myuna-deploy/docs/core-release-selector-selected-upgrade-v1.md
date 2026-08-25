# Core Release Selector selected-to-selected upgrade v1

This contract closes the lifecycle gap between the first Selector activation
and later immutable Core upgrades.  It is deliberately separate from the old
R4C first-activation executor because the authoritative prestate now includes
an existing runtime binding, guard, selector drop-in, and selected release.

The pure contract binds:

- current and target immutable release evidence;
- exact old binding and drop-in inventory;
- exact target selector, `qq.env`, and channel credential drop-in payloads;
- exact Core and QQ Gateway service prestate;
- fixed activation and rollback sequences;
- a new activation digest that cannot reuse the first R4C transaction.

The initial consumer is the Telegram dual-client-auth Core release.  The same
contract is intended to support future v6/v7 Core releases without weakening
the existing content-addressed Selector boundary.

This R1 candidate is repository-only.  It does not include a live backend and
cannot install, select, start, stop, restart, reload, or call any service.
