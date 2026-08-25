# ADR-055: Owner Profile local provider boundary v1

Status: Owner selected the local route; exact runtime/model candidate pinned, activation pending

## Context

P07-A can retrieve a bounded Owner Profile locally, but the current Core implementation and
live route have only an external DeepSeek provider. P07 explicitly forbids sending the real
Profile to DeepSeek. The existing `local` and `openai` names in the Profile egress allowlist
were policy placeholders, not runnable provider implementations.

A plain high loopback port is not a sufficient privacy boundary: an unprivileged process can
bind it while the intended model service is stopped and receive a future private prompt.
Likewise, an OpenAI-compatible endpoint must not be allowed to redirect, use a proxy, resolve
an ambiguous hostname or select an unreceipted model dynamically.

## Decision

Core gains an additive `LocalOpenAIProvider` source adapter. It is disabled by default and
performs no startup probe, model download or network call merely by importing or configuring
the package.

The adapter accepts exactly `http://127.0.0.1:879/v1` and posts only to
`/v1/chat/completions`. Port 879 is intentionally privileged. The future model service must
run as a dedicated inert identity and receive only `CAP_NET_BIND_SERVICE` from systemd; Core
does not receive that capability. The transport disables environment proxies and redirects,
uses a literal IPv4 loopback address, rejects credentials/query/fragment/path drift and
independently revalidates the final endpoint before every call.

The source contract is:

- fixed Core alias `myuna-local-owner-v1`;
- one attempt, no automatic retry and a 1–300 second bounded timeout;
- at most 24,000 actual input characters and 4,096 output tokens;
- thinking and reasoning effort disabled;
- no Authorization header or external credential;
- strict single-choice UTF-8 JSON response with exact model alias, bounded transport body,
  typed content-free errors and no retained reasoning text; and
- content-free provider audit with zero monetary cost and no local budget ledger.

The alias is a policy handle, not model provenance. Activation must separately pin exact
runtime binary bytes, model file bytes, model digest, upstream revision, license, chat
template, context size and service unit in a private content-free receipt. The runtime may
not autoload or download a different model after activation.

## Runtime candidate

The source adapter is compatible with a reviewed OpenAI-style local endpoint. Current
read-only host assessment found no installed Ollama, llama.cpp, LocalAI, vLLM or LM Studio
runtime. The host has a Ryzen 5 5600X, approximately 32 GiB physical RAM, a WSL allocation of
approximately 17 GiB and an AMD Radeon RX 6650 XT. A small quantized model is plausible, but
latency, memory pressure and AMD acceleration are not yet verified.

The selected v1 candidate is llama.cpp `b10217` at commit
`ddd4ec1428a6201e18975ea52b07c71e0f9aef26`, using the official Ubuntu x64 CPU archive
`llama-b10217-bin-ubuntu-x64.tar.gz` (16,433,859 bytes, SHA-256
`b79145bfa48f4fef83e76e1cef7ef4fbdf966e497a2fd774f1107fc2a24500af`). The model is
`Qwen/Qwen3-4B-GGUF` commit `bc640142c66e1fdd12af0bd68f40445458f3869b`, file
`Qwen3-4B-Q4_K_M.gguf` (2,497,280,256 bytes, SHA-256
`7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`), licensed
Apache-2.0. CPU correctness remains the first gate; Vulkan or HIP offload is not selected.

The service contract pins 8,192 context tokens, one slot, six generation/batch threads,
reasoning off, Web UI and slot endpoints off, offline mode, prompt reuse off, runtime logging
off, an 8 GiB memory ceiling and the exact model alias. The service receives
`CAP_NET_BIND_SERVICE` solely to bind literal
loopback port 879, and systemd denies non-loopback IP traffic. Core receives no capability.

## Activation gates

Before any real Profile reaches the local model, Official must verify all of the following:

1. Owner selects the local-provider route and accepts the host resource impact.
2. Exact binary/model URLs, versions, licenses, byte sizes and SHA-256 digests are recorded
   before privileged installation.
3. The dedicated identity, privileged port capability, loopback-only bind, filesystem modes,
   no-proxy/no-redirect behavior, outbound-network policy and uninstall/rollback plan pass
   independent review.
4. Synthetic provider protocol, Unicode/Chinese behavior, context limit, timeout, malformed
   response, process crash and resource-pressure tests pass without Profile data.
5. A provider-only local probe passes before Profile retrieval is enabled.
6. Core/Gateway activation remains bounded and ends with one Owner-private E2E plus
   content-free audit review.

Until then, the accurate state remains
`LOCAL_PROVIDER_SOURCE_READY_RUNTIME_SELECTION_REQUIRED_PROVIDER_EGRESS_BLOCKED`.

## Rollback

Rollback disables Owner Profile retrieval and the local provider selection, restores the
prior Core/Gateway release and selector, and stops the dedicated model service. Runtime and
model artifacts, manifests and receipts remain preserved for review; deletion is not part of
ordinary rollback and requires a separately identified target.
