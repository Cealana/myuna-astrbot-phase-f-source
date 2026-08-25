# ADR-038: Prompt Budget Policy v1

## Status

Repository candidate only. No runtime profile, Core release, Definition release,
service, channel, provider, memory component, or EnvironmentFile is changed by
this ADR.

## Decision

Prompt size is governed by a two-level contract:

- Core hard ceilings: 524,288 Definition characters and 700,000 total model
  input characters.
- Reviewed operational profiles: the initial v6/v7 candidate uses 300,000 and
  400,000 characters respectively.

The total-input profile must reserve at least 65,536 characters beyond the
Definition budget. Short-term history remains a separate policy and is not
expanded in this change.

## Why

The previous 110,000-character Definition limit already rejects a legitimate
v6 all-topic assembly, while ordinary selective routes remain substantially
smaller. Raising only that literal would couple future Definition growth to
another source edit and would leave the provider request validator at an
inconsistent 200,000-character ceiling.

Separating the budgets provides:

- enough room for modular v6/v7 Definition growth;
- explicit capacity for conversation and repair messages;
- a reviewed operating profile below the hard safety ceiling;
- consistent enforcement at configuration, prompt assembly, and provider
  request boundaries;
- no implied change to the currently active 12-message channel windows.

## Non-goals

- No token estimator or tokenizer is introduced.
- No provider model or routing policy is changed.
- No prompt document is loaded solely because capacity exists.
- No QQ or Telegram history limit is changed.
- No v6 activation is authorized.

## Activation prerequisites

Before a runtime profile is applied, deployment evidence must bind the exact
Core and Definition releases, the measured route matrix, provider context
support, selected EnvironmentFile values, tests, rollback target, and explicit
approval digest.
