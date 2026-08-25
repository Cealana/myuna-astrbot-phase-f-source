# ADR-011: Escalate frozen checklist overload to DeepSeek Pro

Status: accepted for staging; production activation remains unauthorized  
Recorded: 2026-07-15 (Asia/Shanghai)

## Context

The manifest-bound routed Golden suite sent ordinary cases to DeepSeek Flash
and Definition/canon conflicts plus important relationship boundaries to
DeepSeek Pro. Flash remained suitable for routine chat, but repeatedly answered
the `checklist_overload_smallest_step` case with two simultaneous actions even
after the prompt explicitly required exactly one smallest immediate action.

This is not a reason to route every checklist to Pro. The relevant task class is
the narrower state where the user has many obligations, is frozen, and needs
deadline triage plus one executable next step.

## Decision

Add `checklist_overload` to the Pro staging task classes. Map the approved Golden
category `checklist` to this task class only for the overload/frozen scenario.
Ordinary lists, reminders, formatting and low-risk planning remain on the Flash
default route.

Keep `dev-v1.json` immutable as evidence for the earlier runs. Introduce
`dev-v2.json` as a new capability manifest whose only routing-policy expansion
is the `checklist_overload` Pro task class and whose source ADR list includes
this decision.

## Non-decision

The memory-honesty case produced a semantically correct response equivalent to
"no available record" while missing a literal keyword auto-check. This ADR does
not change routing or prompts merely to chase that substring. Keyword checks
remain triage signals; manual semantic review and deterministic capability
guards remain authoritative.

## Safety boundary

This change does not activate Myuna Core, a Definition release, real memory,
tools, AstrBot, or any listener. It only changes model selection within a
user-approved synthetic Golden evaluation. All staging authorizations remain
false and the one-repair maximum remains unchanged.
