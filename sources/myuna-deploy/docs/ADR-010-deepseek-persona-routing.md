# ADR-010: DeepSeek routing for Myuna persona workloads

Status: accepted for staging implementation; production activation is not authorized  
Recorded: 2026-07-15 (Asia/Shanghai)

## Context

The approved Myuna Definition v5 Golden contract was evaluated against three
DeepSeek profiles:

- `deepseek-v4-flash`, non-thinking, across all 12 cases and four iterations.
- `deepseek-v4-flash`, thinking enabled with high reasoning effort, across five
  difficult cases.
- `deepseek-v4-pro`, non-thinking, across the same five difficult cases.

The runs were synthetic staging evaluations. They did not load a production
Definition release, start Myuna Core, write personal memory, call tools, or
authorize external side effects.

## Decision

Use DeepSeek Flash/non-thinking as the default model for ordinary Myuna
conversation and low-to-medium complexity tasks.

Escalate to DeepSeek Pro for task classes where the current evidence shows a
material benefit:

- Definition changes and personality regression review.
- Canon, Workbench, or version conflicts that require precedence judgment.
- Important relationship pacing or boundary decisions.
- Repeated Flash failures or output that remains invalid after one repair.
- Other high-consequence cases selected by the policy router.

Do not use Flash thinking/high as the primary persona-conflict escalation path
at this time. In this evaluation it was slower and did not reliably resolve the
Definition conflict or inactive-memory honesty case. It remains available for
future task-specific experiments rather than being removed.

## Mandatory controls

Every model-generated response claiming Myuna capabilities must pass a
deterministic capability guard. The guard must be derived from a versioned
runtime capability manifest, not inferred from aspirational Definition examples.

The staging implementation may perform at most one bounded, explicitly audited
repair when the capability guard or required schema fails. If the repaired
response still fails, the request must fail closed or escalate; it must not be
returned as a normal Myuna response.

Golden keyword checks are useful triage signals but are not the release verdict.
The release gate requires semantic/manual review plus deterministic checks.

No DeepSeek or OpenAI model may:

- approve or activate a Definition release;
- grant itself memory, tools, perception, or system privileges;
- approve a dangerous tool action;
- write long-term memory during Shadow Mode or Golden evaluation;
- bypass provider budget, audit, or routing policy.

## Evidence summary

| Profile | Scope | Result |
|---|---:|---|
| Flash/non-thinking | 12 cases | Appropriate default, but requires capability guard and bounded repair |
| Flash thinking/high | 5 difficult cases | No reliable persona-conflict advantage in this sample |
| Pro/non-thinking | 5 difficult cases | Best manual semantic result after guarded repair; preferred escalation |

The full run artifacts are stored under the protected Golden evaluation paths
and summarized in `GOLDEN_EVALUATION_RESULTS.md` in the engineering handoff.

## Consequences

- Model names remain registry/configuration values and are not hard-coded in
  Myuna Core business logic.
- Request counts, tokens, actual cost, conservative budget accounting, route
  reason, repairs, downgrade/escalation, and evaluation result remain separate
  audit fields.
- The next staging step is a runtime capability manifest and a policy router
  implementing this ADR behind disabled/inactive service gates.
- A later model or prompt version can replace these choices after comparable
  regression evidence and a new ADR.

## Activation boundary

This ADR authorizes staging engineering and further synthetic tests only. It
does not approve Definition v5 as a production release, enable Myuna Core,
enable real conversation routing, import personal memory, expose a port, or
enable AstrBot/QQ.
