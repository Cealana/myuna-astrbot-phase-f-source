# P16 reality and lexical trigger audit v1

Status: source-only synthetic contract. It neither identifies a historical incident nor changes the public `myuna.user-visible-fault.v1` taxonomy.

## Frozen path inventory

Generation13 ordinary Telegram text takes this path:

`private/plain ingress -> signed envelope -> auth and durable claim -> rate limit -> external epoch -> egress safety -> Profile retrieval/projection -> LiveHybridConversationEngine -> provider adapter -> hybrid structural reply validation -> provenance and delivery preparation -> Gateway structural response validation`.

The Telegram plugin always adds `hybrid_external_generation=true` for admitted ordinary text. With generation13 hybrid enabled, this path calls `LiveHybridConversationEngine.converse_external`; it does not call the `DevConversationEngine` post-generation reality/recent-event validator. QQ and legacy/non-hybrid/local conversation continue through `DevConversationEngine`.

## Content-free trigger matrix

| Boundary | Category-only matcher | Direct failure or fallback | Effect when accepted | Expected stage/latency |
|---|---|---|---|---|
| Telegram ingress | private/plain/non-bot/account shape | reject without Core call | none | immediate channel ingress |
| Telegram ingress | blank or over 4000 code points | reject without Core call | none | immediate channel ingress |
| Telegram ingress | leading ASCII command prefix | unknown commands are not forwarded; only typed Diary/Benchmark/Temporal/Check grammars pass | command routing only | immediate channel ingress |
| Telegram ingress | Unicode punctuation, relational pronouns, ordinary CJK | no lexical rejection | forwarded unchanged | immediate, then downstream |
| Signed envelope/runtime | schema, exact fields, signature, age, channel, instance, consent, identity, replay and rate limit | typed early rejection or gateway degradation | none | normally under 5 seconds |
| External egress | classifier unavailable, credential-assignment shape, explicit forwarded-private shape, content-free private flags | typed pre-provider rejection | none | normally under 5 seconds |
| Profile query | current-message head/tail bound to 256 code points; NFKC/casefold and ASCII/CJK token scoring | malformed/NUL query or Profile capability/service failure only | changes selected sections; no ordinary-word rejection | pre-provider |
| Prompt-injection boundary | ordinary user text remains an untrusted user-role message; visual text is always untrusted data | no ordinary substring blacklist | can change model behavior, never grants authority | provider path |
| Persona grounding | question/time/daily-life/real-observation/external-operation/anaphora categories | no hybrid rejection | adds or omits model guidance | pre-provider prompt assembly |
| Provider request | exact roles/fields, message count, character/token budget, model/route and response-format contract | typed pre-provider Core failure | constructs bounded provider payload | pre-provider |
| Provider transport | timeout, transport, HTTP class, budget/auth and retryability | typed provider failure | at most the configured bounded attempt policy | provider latency bucket |
| Hybrid reply | string, non-empty, at most 4000 code points, no NUL | one structural repair, then reply-contract failure | no semantic/reality judgment | provider/response path |
| Legacy reply | typed draft/schema, capability honesty, action/private/tool/identity/integrity guards | typed repair/fail-closed | reality-plausibility output rejection is explicitly disabled | post-provider |
| Gateway response | JSON, schema, exact keys, reply length, delivery token, pacing and provenance binding | gateway invalid-response degradation | none | post-Core |

The exact non-secret lexical fixtures live only in `tests/test_p16_telegram_trigger_audit_v1.py` and the Core offline tests. This document intentionally does not publish a trigger-word list.

## Exact branch inventory by source symbol

| Component | Exact source symbols | Direct-failure status |
|---|---|---|
| Telegram admission | `_TELEGRAM_ACCOUNT`, exact Diary/Benchmark/Temporal/Check parsers, `should_forward_private_plain_text` | account/private/plain/bot/blank/length and ASCII command-prefix decisions are direct ingress decisions; relational terms are not inspected |
| Telegram envelope | `_SAFE_INSTANCE`, nonce `fullmatch`, `build_signed_envelope`, `SignedChannelEnvelope.from_payload` | exact schema/identifier/signature/time/consent failures reject before Core/provider |
| Runtime commands | `diary_command_is_explicit`, `benchmark_intent_grants_profile_consent`, `parse_temporal_command` | `/Diary` is control-only; only exact `/Benchmark` grants Profile consent; command grammar does not classify ordinary relational text |
| External egress | `_CREDENTIAL_PATTERNS`, `_EXPLICIT_FORWARD_PATTERNS`, `EgressSafetySignals`, `enforce_external_egress_safety` | direct typed pre-provider failure; unchanged by this candidate |
| Profile query | `_bounded_profile_query`, `_validate_query`, `_ASCII_WORD`, `_CJK_RUN`, `_normalize`, `_tokens` | blank/NUL/out-of-contract query can fail; NFKC/casefold/token overlap only changes retrieval rank/selection |
| Persona grounding | `_QUESTION_MARKER`, `_RECENT_OR_PRESENT_TIME`, `_PERSONA_DAILY_LIFE`, `_DIRECT_PERSONA_REFERENCE`, `_ANAPHORIC_FOLLOW_UP`, `_REAL_WORLD_OBSERVATION`, `_EXTERNAL_OPERATION_OR_ASSET` | only chooses a prompt-guidance category; no direct hybrid failure |
| Legacy prompt/topic routing | `_IDENTITY_ANSWER_REQUEST_TERMS`, `_EXPLICIT_ASSISTANT_REUSE_REQUEST_TERMS`, `_APPEARANCE_TERMS`, `_MOVEMENT_TERMS`, `_MOTIVATION_TERMS`, `_WORLD_BUILDING_TERMS`, `_PARAMETER_TERMS`, `_MEMORY_POLICY_TERMS`, `_TOOLING_TERMS`, `_OWNER_PROFILE_*` | selects Definition topics, identity behavior or Profile retrieval mode; no ordinary input word directly becomes generic unavailable |
| Legacy action semantics | `_ACTION_REQUIRED_TERMS`, `_ACTION_BLOCK`, `_ACTION_MODE_TAG`, `_UNSUPPLIED_ACTION_STATE_TERMS`, `_OWNER_AUTHORED_MYUNA_ACTION`, `_DIRECT_MYUNA_ACTION_REQUEST_TERMS` and related render validators | can cause post-provider repair/fail-closed, not immediate pre-provider rejection; unchanged |
| Provider request | `validate_model_request`, `_ALLOWED_ROLES`, `MAX_MESSAGES`, model-input character policy, the response-format JSON instruction check | structural pre-provider failure only; response-format check is inactive for ordinary text requests |
| Provider response | `_FINISH_REASONS`, `_parse_success`, required string/integer/schema checks | typed invalid/provider response after a provider call; no input substring branch |
| Hybrid output | `HybridExternalGenerationCoordinator._valid_reply`, `_REPAIR_INSTRUCTION` | empty/type/length/NUL only, one repair; no reality matcher |
| Legacy output | `_parse_model_turn_draft_audited`, capability honesty, action layout, undefined-detail, runtime-truth, identity, echo and relationship validators | post-provider typed repair/fail-closed; only the reality/recent-event semantic validator is retired |
| Gateway Core response | `validate_core_failure_response`, `LoopbackCoreClient.chat`, plugin `decode_gateway_response`, `_validate_degradation` | HTTP/schema/exact-key/reply-size/provenance/delivery checks can degrade after Core; no semantic text matcher |

Special-character findings are exact: ordinary ingress strips leading/trailing Unicode whitespace for emptiness, but only an ASCII `/` after `lstrip()` selects command handling; CR/LF are excluded inside the supported command parameter grammars; the 4000 limit counts Python code points. NUL is not rejected by the outer ordinary-text admission but is rejected by the external-context/Profile contract before provider dispatch. The signed socket request and response also have independent byte limits.

## Owner-provided abstract categories

Synthetic minimal pairs cover shared ownership/relational possession, joint action, past versus future joint events, first/second/third-person co-reference, and prompt-injection-like phrasing. All category variants pass Telegram admission, preserve their exact Profile query, and reach the fake provider. None matches a direct lexical pre-provider failure. A credential-assignment-shaped control differs by one category marker and is rejected before Profile/provider calls, proving the oracle can distinguish a real lexical egress gate from ordinary relational language.

Therefore a sub-five-second failure associated with the abstract relational categories does not establish a word trigger. If independently proven pre-provider, the remaining admissible stages are envelope/release binding, replay/rate limit, external epoch or summary lifecycle, egress signals, Profile authorization/service, projection budget/provenance, or another typed Core pre-provider gate. The incident must remain unknown until a content-free stage receipt identifies one of them.

## Reality-plausibility retirement

Core source exposes `INFRASTRUCTURE_REALITY_PLAUSIBILITY_REJECTION_ENABLED=False` and `REALITY_PLAUSIBILITY_GUIDANCE_AUTHORITY=model_definition`. The two legacy post-generation reality/recent-event violation codes and their lexical output matchers are removed. Model prompt guidance remains in `persona_grounding.runtime_prompt_boundary` and `repair_prompt_boundary`. Structural reply parsing, capability honesty, unavailable external-action/data checks, egress safety, Profile/privacy, provenance, delivery and provider failure handling are unchanged.

This change cannot explain or repair the historical generation13 Telegram fallbacks because the active ordinary hybrid path already bypassed those legacy validators.

## Definition pointers

- Definition source main: commit `6773a6ac39b884ecb376d4d20e6b4a642347b670`, tree `8a29946f0b1b1dcb0912bc9d98ae4914e754d965` at audit time.
- V6 model boundary: `source-material/v6/extracted/myuna-skill-v6/references/16-hard-constraints-v6.md`, raw SHA-256 `b64339a99bf60cf1d13ec1e4fa903aa71fcd86ae7b2e96e9fc9a69cb885a3841`; Effective V6 overlay boundary `overlays/v6/effective-v6/files/references/22-ordinary-workbench-and-disclosure-boundary.md`, raw SHA-256 `721e71103c3046a366f329dd5983c6429bf5434b57268c8b298a722e68d4435f`.
- V7 Phase1 boundary: `overlays/v7/phase1-definition-only/files/references/26-v7-phase1-capability-boundary.md`, raw SHA-256 `f6b923c3c088a30a8ff70226e1f6a76f8d435b6f73b258be9ea05cb698ee2735`.

V7 has a source pointer and inherits the V6 hard/model boundaries through `V7_PROFILE`, but it has no stable typed declaration for “model guidance rather than infrastructure reality rejection”. That declaration is a P09 source-only follow-up; this P16 gate does not modify P09 paths.

## Safe correlation protocol

Owner reports only: CST or UTC timestamp, latency bucket (`<5s`, `5-30s`, `30-60s`, `>=60s`), and optionally one abstract category (`shared-possession`, `joint-action`, `past-joint-event`, `future-joint-intent`, `command-prefix`, `length/unicode`, `other`). Do not send message text, object/action detail, identity, Profile content, provider/model content, or logs. P16 correlation must use an opaque incident reference or fixed stage receipt; temporal proximity alone is not a root cause.
