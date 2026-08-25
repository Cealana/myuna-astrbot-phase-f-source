# ADR-056: Owner Profile local-provider latency recovery v1

Status: accepted source candidate / not yet activated

## Context

P07 Owner Profile retrieval is correct and content-free audit confirms revision 2 is
selected without memory writes. The current CPU-only Qwen3 4B Q4_K_M provider does
not meet the Owner-channel deadline: the final measured request used the exact local
Definition section projection, 13,941 input characters, 22 messages and a 768-token
output ceiling, then failed at the provider's 120.1-second transport timeout.

The WSL runtime sees four physical cores and eight threads; llama.cpp already uses six
threads and has no CPU quota. The host has an AMD Radeon RX 6650 XT, but the pinned
official llama.cpp b10217 Ubuntu Vulkan build enumerates no devices in this WSL
environment. GPU activation is therefore not a verified recovery path.

## Decision

Keep the existing pinned llama.cpp b10217 CPU runtime, loopback endpoint, alias,
8,192-token context, one slot, sandbox and offline boundary. Replace only the model
artifact with `ggml-org/Qwen3-1.7B-GGUF` file `Qwen3-1.7B-Q4_K_M.gguf` at revision
`daeb8e2d528a760970442092f6bf1e55c3b659eb`:

- bytes: `1282439264`
- SHA-256: `d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5`
- upstream base model: `Qwen/Qwen3-1.7B`
- license: Apache-2.0

Core independently caps local-provider generation at 192 tokens. DeepSeek routes keep
their existing 768/4096 ceilings. Definition source text, Profile revision 2, Profile
retrieval bounds and the 128-message session store are unchanged.

## Privacy and activation boundary

The model download contains only a public artifact. The activator performs no model
generation, provider request, health endpoint request or Profile read. Readiness uses
the exact systemd process command and a TCP connect without sending application data.
Profile text, raw messages, identity, provider payloads and generated text remain
absent from receipts and audit projections. No encryption claim is introduced.

Activation verifies the current unit and 4B artifact, installs the new model under an
immutable content-addressed private path, quiesces both Owner gateways, restarts only
the local-provider service, verifies the exact process/model and loopback listener, and
restores both gateways. Core output-cap selection is a separate content-addressed Core
activation with its own rollback point.

## Rollback and acceptance

Rollback restores the exact prior unit bytes and 4B model selection, restarts only the
local-provider service and restores both gateways. Installed artifacts, backups and
receipts are retained.

Acceptance requires deterministic source tests, exact artifact size/digest, activator
preflight, active services with no restart loop, content-free receipts, the active Core
verifier, and one Owner Telegram request completing inside the channel deadline. A
timeout is a failed candidate and does not justify further blind prompt reduction.
