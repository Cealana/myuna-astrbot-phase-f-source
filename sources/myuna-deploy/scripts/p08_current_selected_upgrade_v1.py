#!/usr/bin/env python3
"""P08-only forward-continuity repair from the restored current selection.

This controller owns one materially new, source-derived incident.  It never
reuses the accepted post-target repair, the consumed pre-stop backup rejection,
or any consumed protocol/runtime rejection whose bounded convergence restored
the predecessor.  Readiness observes only opaque-state metadata; exact state
bytes are copied and hashed only after the new incident has been durably claimed
and before the first unit stop.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Callable, Mapping, Sequence

import p08_existing_state_upgrade_v1 as upgrade
import p08_forward_continuity_orchestration_v1 as continuity
import p08_formal_preflight_launcher_v1 as formal_launcher
import p08_post_target_action_v1 as post


STRATEGY_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-strategy.v13"
PLAN_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-plan.v13"
READINESS_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-readiness.v13"
JOURNAL_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-journal.v13"
LEDGER_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-ledger.v13"
RECEIPT_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-receipt.v13"
STATE_BINDING_SCHEMA = (
    "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-state-binding.v13"
)
CLI_RESULT_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-cli-result.v13"
INCIDENT_SCHEMA = "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-incident.v13"
PRESTATE_REJECTION_SCHEMA = (
    "myuna.p08-current-selected-protocol-acceptance-repair-prestate-rejection.v1"
)

PREDECESSOR_RELEASE_DIGEST = (
    "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
)
PREDECESSOR_MANIFEST_SHA256 = (
    "8ab396cd1333d74110169f712ccadf4f7efb7488dd320255bbd6b9a2e986a7a4"
)
PREDECESSOR_INSTALLED_INVENTORY_SHA256 = (
    "a3fc5583b45c28f208cf74777d4aed33afe5d031ed7ec0f30e85da88969d9ef0"
)
PREDECESSOR_CORE_COMMIT = "065ef4b647f63925ae20bb564007c127433c0b81"
PREDECESSOR_DEPLOY_COMMIT = "552aeee5c962979722ae33b1eb8bc152367a3df7"
PREDECESSOR_CLIENT_SHA256 = (
    "900070b3556722e6e435f58af67d8dc42395e8dfbe765522c37711375183dff7"
)
PREDECESSOR_SELECTOR_SHA256 = (
    "8695f581a33c2247149c4e9d39da1cc04be7fb133a4a9d985caf26709a606326"
)
PREDECESSOR_SELECTOR_ENV_SHA256 = (
    "26a8cf72d81470727d91b93e5b26ee54322675a1700c27c6740f552025ba50ce"
)
PREDECESSOR_SERVICE_UNIT_SHA256 = (
    "699662ffc743518be4a499c0598259ac686b17f531671c969a3de73311fd44f8"
)
PREDECESSOR_SOCKET_UNIT_SHA256 = upgrade.SOCKET_UNIT_SHA256
PREDECESSOR_PLAN_DIGEST = (
    "9d77911d8502538f4b4580051bb7dbc9bae75d884de5455c004b83e8ffe82953"
)

ACCEPTED_INCIDENT_DIGEST = (
    "febee8222f43701d755fc8958dfae526bbfe068e329080f398cee34c8f503cb0"
)
ACCEPTED_PLAN_SHA256 = (
    "dfa3a090f9c6e83cda044d1d74cfd1a83a25f0de4970c8af0311099aace3a638"
)
ACCEPTED_LEDGER_SHA256 = (
    "d423150800f18d139f73c08c74a6b7218b7b292f849ebf7d3f43510213f99058"
)
ACCEPTED_JOURNAL_SHA256 = (
    "fd955ae8f0098656a64bd60f60d0d0d3da8deebea5debef14ff21c77535bbc6e"
)
ACCEPTED_RECEIPT_SHA256 = (
    "cd3b350852ca7b52ee43d16dd7d33db6f99f8337e6321bc9e4be3ce250f48ce5"
)
ACCEPTED_STATE_BINDING_SHA256 = (
    "bcfbd9c139c6aea94348d491b0e4f109e233bcaae4d574c4cc91918cde085947"
)
ACCEPTED_PUBLIC_MANIFEST_SHA256 = (
    "97903a8d406e796c002289471db4337a42409b0042a4c88453fce50fefa17f6d"
)
ACCEPTED_STATE_MANIFEST_SHA256 = (
    "15b3eb553db8bce6220680636c66871679bc963eb4b46f40a0c3ecd31fb5a8da"
)
ACCEPTED_EVIDENCE_ROOT = (
    post.POST_ACTION_EVIDENCE_ROOT / "incidents" / ACCEPTED_INCIDENT_DIGEST
)

FAILED_INCIDENT_DIGEST = (
    "7b9dd551736f351fb291001a0e10f5e1250a3d11490601aef0d98f5c8dd23933"
)
FAILED_PLAN_DIGEST = (
    "fcc409b7281176d7d0a514eca5f59b9214f78a8ef50b2a7e179a5985a3accb1f"
)
FAILED_PLAN_SHA256 = (
    "336ea57a3af4747834d8c401f49448166bdb9cf5178579586f4ff35d6081e312"
)
FAILED_LEDGER_SHA256 = (
    "911f27a17fa306d5148185940c81ab551b5e765969ee1b6e95d145823ca7680f"
)
FAILED_JOURNAL_SHA256 = (
    "480301f4ec57f30a5de121ea1a12747618fe574b9d166324962719370eec4eb1"
)
FAILED_PUBLIC_MANIFEST_SHA256 = (
    "47367243041ae9620b0542c04a4daf2934b276fe8366d5eaa1a0042096067d28"
)
FAILED_STRATEGY_DIGEST = (
    "d3c5fb2192929cf9bf4a2cebb471a8b44dc75f1b38845883df4ca57cc7608b41"
)
FAILED_CONTROLLER_SHA256 = (
    "17fb18eb87c8bce0808430af99a2aaeb3dea685bb5ca0bb465feb3b83d959372"
)
FAILED_TARGET_RELEASE_DIGEST = (
    "84481fcd18651c97e5ca144701de38e47c1f72038de21295648286c976e37fe7"
)
FAILED_PLAN_SCHEMA = "myuna.p08-current-selected-upgrade-plan.v1"
FAILED_LEDGER_SCHEMA = "myuna.p08-current-selected-upgrade-ledger.v1"
FAILED_JOURNAL_SCHEMA = "myuna.p08-current-selected-upgrade-journal.v1"
FAILED_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-upgrade-v1/incidents"
) / FAILED_INCIDENT_DIGEST

TERMINAL_INCIDENT_DIGEST = (
    "be9f6fd719e564036e6cc20b2f5153da39c9bfc5a459939f5ba8965f1ee4b586"
)
TERMINAL_PLAN_DIGEST = (
    "76f826a1614f1c63fab391359d3527fa81ec6f93aa144baac5996455734a8c0c"
)
TERMINAL_PLAN_SHA256 = (
    "17f191e6b96c2ebf77a195e04da36157eb025c5272e7a4c173d6b9e6216f4658"
)
TERMINAL_LEDGER_SHA256 = (
    "d8b981550c33a6e52fb0b822159b0a46286433ac3b06fb89d3a915b050c1704c"
)
TERMINAL_JOURNAL_SHA256 = (
    "1f46a3a34cb72a750e36d00b818c4e0604cc92a1e2613b453b7e1594d22746be"
)
TERMINAL_RECEIPT_SHA256 = (
    "5a79864ef7c75827a67151e272db56f2a54d572ad4cc03be261e8692c0549497"
)
TERMINAL_STATE_BINDING_SHA256 = (
    "8e096f3fab5a34bc4d0993cea59e8b584f251a452228dba7354e8ac8a8bf058d"
)
TERMINAL_PUBLIC_MANIFEST_SHA256 = (
    "47367243041ae9620b0542c04a4daf2934b276fe8366d5eaa1a0042096067d28"
)
AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256 = (
    "55d3a3f91a20848fd9f66603f3684b4068401d2fd419d61094ce58ef39188eeb"
)
TERMINAL_STATE_MANIFEST_SHA256 = (
    AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
)
TERMINAL_STRATEGY_DIGEST = (
    "1c2b273f2eb8f05d6d89c741ea8fdb8b4e79938bf5b741530c0e5ff5e9504e27"
)
TERMINAL_CONTROLLER_SHA256 = (
    "666eaf1bedaf5f34d43d6fe65250597e966d456461abdd538792f97edf676b85"
)
TERMINAL_TARGET_RELEASE_DIGEST = (
    "1de82e440cadc15a559f8a40dd73e0c527d584356c44684eff90199250ea4b92"
)
TERMINAL_PLAN_SCHEMA = "myuna.p08-current-selected-mode-repair-plan.v1"
TERMINAL_LEDGER_SCHEMA = "myuna.p08-current-selected-mode-repair-ledger.v1"
TERMINAL_JOURNAL_SCHEMA = "myuna.p08-current-selected-mode-repair-journal.v1"
TERMINAL_RECEIPT_SCHEMA = "myuna.p08-current-selected-mode-repair-receipt.v1"
TERMINAL_STATE_BINDING_SCHEMA = (
    "myuna.p08-current-selected-mode-repair-state-binding.v1"
)
TERMINAL_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-mode-repair-v1/incidents"
) / TERMINAL_INCIDENT_DIGEST

PRESTATE_REJECTION_HANDOFF_SHA256 = (
    "46c5102165f9c60b859baedf1c98911caa4b28da3ed8d4afa0f061137fb23c3e"
)
PRESTATE_REJECTION_CONTROLLER_SHA256 = (
    "e586d9fb789ee5f4f485805048ef49eebf2aa386c86efb787a370a0bf6cd68d4"
)
PRESTATE_REJECTION_STRATEGY_DIGEST = (
    "b4ed6b06335fc7bdbe378e95ae132cb9dbb5d674d9a286ea4986b800d0a71cc7"
)
PRESTATE_REJECTION_TARGET_RELEASE_DIGEST = (
    "6d0fa2255f043724f027a3bdd9f024989c6d8e9d4383ef2202d68edd95670224"
)
PRESTATE_REJECTION_EXPECTED_STATE_MANIFEST_SHA256 = (
    "55d3a3f92c788ffaf52e42d86ce781e6a2dcde01ce8138016bb5c1e9400f2eeb"
)

NONZERO_STAGE_T0_HANDOFF_SHA256 = (
    "834965b619cb4f02993da9513866bde04ceb409b7d5d82f6ec0612fa51386515"
)
SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256 = (
    "4e982b63dc9c6f6658cc508c06aaf55b9607e364d6a73ca1d55f25ab452037c1"
)
P07_INTEGRATION_SCHEMA = "myuna.p07-p08-single-nonce-integration.v1"
P07_INTEGRATION_HANDOFF_SHA256 = (
    "75a5e6f051f9b0d6c681437244158adbbe1b958d6556b90bd6ca78a50f1b8cf0"
)
P07_INTEGRATION_DEPLOY_COMMIT = "31d16fcb949db2a68aa49e44c8225d646fae5d1b"
P07_RUNTIME_RELEASE_DIGEST = (
    "efadbf864a9bf22899406325d61600790eb270818688f2358e4d01736e22f920"
)
P07_RUNTIME_MANIFEST_SHA256 = (
    "7b49c45e2cdf3dfdce4234dbcfe7a8a502036cbf684dd6e0d43cae44ae62de1b"
)
P07_TRANSACTIONAL_BUNDLE_DIGEST = (
    "e32a54b18793d7741bc3333f512f279a0b800193c0547ccca3b1ea05fd28c451"
)
P07_BUNDLE_MANIFEST_SHA256 = (
    "5ed4d11d7f571ccbdd7813673dad31ea66f79421e1238a5732e82bab10ed8bf2"
)
P07_RUNTIME_PROJECTION_DIGEST = (
    "5cf84d84dd8666132a8ec42fae7ae7164cfb84c92636e5c3a664527117e505c0"
)
P07_RUNTIME_BINDING_DIGEST = (
    "8b635f359dedb115b110c6b1e05ca552d8ea84dc548be6a865f0e7d7b05a9a08"
)
P07_SERVICE_IDENTITY_DIGEST = (
    "309d42b40544364c1ca755ac220ee19dd06d71f2c22cf59e524265c0d67398cd"
)
P07_ARTIFACT_ROOT_CONTRACT_DIGEST = (
    "ab69130f54e1cf65a928cd7c14dee8d563830722290bee167ba51f5bb30fcacc"
)
P07_PLUGIN_DIGEST = (
    "df77aee013205b0006232e1f7e91e478efc553952fa6f52820d5d118d5d1eb7e"
)
P07_PLUGIN_MANIFEST_SHA256 = (
    "3bb83ffe9316e4652e2ed5441207b272183a9c0a5427a7c8a11bb2adc33cab56"
)
P07_PLUGIN_BINDING_DIGEST = (
    "45d3dd32bf40514067e1f14427a472971471c1a9603356a6f879328a8bdece1b"
)
P07_IMMUTABLE_REFERENCE_DIGEST = (
    "ba08db64563018faff7c419f7cd2935453325c35c99a51843a1f0f3775e3c1fb"
)
P07_FRESH_STRATEGY_DIGEST = (
    "65ccdde154d05237891ce4b6cd2e161d177ad1af5d46428d77d08fe4db89f9f5"
)
P07_BOUND_HELPER_SHA256 = (
    "8adf67ea5e740961ee8c973e31a018a20631589e331808b7e0c244332c31b495"
)
P07_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST = (
    "2ddeae3a6af8fc03d1ea68834570f0538567bd10a0cf9748a4d9a72318d30f7f"
)
V2_TERMINAL_INCIDENT_DIGEST = (
    "0831b1c7d0c64d03fab0c79727304f013a6541319d71e63135344b014b84c647"
)
V2_TERMINAL_PLAN_DIGEST = (
    "64b2c633e1138712bf839fdef616fdb7adb57f7c88865a0e62f48699abe08790"
)
V2_TERMINAL_PLAN_SHA256 = (
    "437b24fb76003b0c412bcdadf4979aa3027e891eb651eb3365efddeb31c8905e"
)
V2_TERMINAL_LEDGER_SHA256 = (
    "993e3196f573b812dc7c3fe237ed0553f2c58f1999f58edf136b7740b822cd9e"
)
V2_TERMINAL_JOURNAL_SHA256 = (
    "ace509ef93ce74d15c47d7c3713dc9ee82a8100664d65c3900f60676b0b90641"
)
V2_TERMINAL_RECEIPT_SHA256 = (
    "007f38af8a7e7a3d5b725d90389135b9466002cf4fb76ef9024364df30ef926a"
)
V2_TERMINAL_STATE_BINDING_SHA256 = (
    "9ffe3615f7208ea58e1b2ed258a0559142a14a6d81dae7e009a11c776d42aab5"
)
V2_TERMINAL_PUBLIC_MANIFEST_SHA256 = TERMINAL_PUBLIC_MANIFEST_SHA256
V2_TERMINAL_STATE_MANIFEST_SHA256 = AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
V2_TERMINAL_TARGET_RELEASE_DIGEST = (
    "0aeb94e19c54ef3ec9808e4724fc5215131d9bd15ff971bb06d677fb13359352"
)
V2_TERMINAL_CONTROLLER_SHA256 = (
    "bcd7f2063aa00679c828643ac713dd8a8d21b010b6f71830de64b1fbf9cd86e5"
)
V2_TERMINAL_STRATEGY_DIGEST = (
    "7b6ae86e299416d7beca5033708225390a2edc4d8ebe9b2ba18a1379f2047997"
)
V2_TERMINAL_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-protocol-acceptance-repair-v2/incidents"
) / V2_TERMINAL_INCIDENT_DIGEST

V4_TERMINAL_HANDOFF_SHA256 = (
    "64ddae2d5d811827c1a50551e54847aec5be071d6995ef6fcca1fb9e0d002e09"
)
V4_TERMINAL_INCIDENT_DIGEST = (
    "00456f72a12bbd7b9751fe083a8d42caf77160cc2c700410d941dc984d9eddce"
)
V4_TERMINAL_PLAN_DIGEST = (
    "dcf9d41a071e9fc548e3dc948cb7bf5286190386d9d13f8e1113720a68de7012"
)
V4_TERMINAL_PLAN_SHA256 = (
    "58c5b50042c658b702f8f30a8ab9a9a8021d215d1ed533c8bf60f79de240f6ba"
)
V4_TERMINAL_LEDGER_SHA256 = (
    "8f46c7a5507004ea4821ce2bf1b2580203964af9be33a5302bb4d1172054c0bf"
)
V4_TERMINAL_JOURNAL_SHA256 = (
    "66d69f8e63e8fd7d556f9e69abeedc498a243f2f58542324697f492aebfd04df"
)
V4_TERMINAL_RECEIPT_SHA256 = (
    "1d28834c83abe07b1ce3adf66ef9394c7b687c3296daeaf736f85efbb59b2e75"
)
V4_TERMINAL_STATE_BINDING_SHA256 = (
    "32afd88447051b0220027e19029a295387fa5b9e70a10d7b121d512c7377d9a1"
)
V4_TERMINAL_PUBLIC_MANIFEST_SHA256 = TERMINAL_PUBLIC_MANIFEST_SHA256
V4_TERMINAL_STATE_MANIFEST_SHA256 = AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
V4_TERMINAL_TARGET_RELEASE_DIGEST = (
    "c26843886522314e4b58300284bf03bd7129a0d91ab86dc3dc076c7a6bc5ae2e"
)
V4_TERMINAL_CONTROLLER_SHA256 = (
    "b8d1d8545dcf84f17590f4a5c90a586a767f00c47a6a9b0c10daa12ceab94e63"
)
V4_TERMINAL_STRATEGY_DIGEST = (
    "a3eef8e399a203fa6590af6c4903408d0d90b07586a68a919e78c164227b775f"
)
V4_TERMINAL_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-protocol-acceptance-repair-v4/incidents"
) / V4_TERMINAL_INCIDENT_DIGEST

P08_TRUSTED_TIME_T0_HANDOFF_SHA256 = (
    "342f0c59898b0b64c0eb793f93d8d4d340a106ee1b828379c3a7030c22fe9cc1"
)
P10B_TRUSTED_TIME_T0_HANDOFF_SHA256 = (
    "9a2adac89779375c524e921284b751aa2b9b4f2bd6f439c8fe1ac99cdbfcbb9d"
)
V5_TERMINAL_HANDOFF_SHA256 = (
    "46d1c11167ac1b531eb45fd394cafa74a53e0fc61d8d964b5b04e57facfe3673"
)
V5_TERMINAL_INCIDENT_DIGEST = (
    "e4ac524463fa42cba9773170f1b838e7cee005e19b7833eb9fb0214dc971036b"
)
V5_TERMINAL_PLAN_DIGEST = (
    "ee15b616747fe1deed3132c04109703448bfd11db08e1b298f3d3e9948ac02e3"
)
V5_TERMINAL_PLAN_SHA256 = (
    "855d474a561925759086b3efa409813fe4cda0efa492a08bacb33c9007b6be8f"
)
V5_TERMINAL_LEDGER_SHA256 = (
    "49f28bc745a159eea7572152be9f0b76f7d6f3659982000583c4b7977875194e"
)
V5_TERMINAL_JOURNAL_SHA256 = (
    "d14572a786a9418318f2419d6444a48c3e269d09a6321de9fe0f2e374cd0366a"
)
V5_TERMINAL_RECEIPT_SHA256 = (
    "d725002a1fd2f864a803a44341a4497fcd9cdae426a6395e1acb91b7fd0b1461"
)
V5_TERMINAL_STATE_BINDING_SHA256 = (
    "04f4e62ea0011b768f3c08b0e29534536cadced03b581f02e6844768780b7697"
)
V5_TERMINAL_PUBLIC_MANIFEST_SHA256 = TERMINAL_PUBLIC_MANIFEST_SHA256
V5_TERMINAL_STATE_MANIFEST_SHA256 = AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
V5_TERMINAL_TARGET_RELEASE_DIGEST = (
    "346eb33496125d37b4f79dd43716a59c334be82729054f610c2cd367982d0f47"
)
V5_TERMINAL_CONTROLLER_SHA256 = (
    "d0ec1d912a2f006c656441f2b1336898029091ad74e87b96f6efa700124e5fe2"
)
V5_TERMINAL_STRATEGY_DIGEST = (
    "3c1291895a0c7105cd6e4875323896526fc415af2c7736c0bd3ce54cff7355c3"
)
V5_TERMINAL_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-status-runtime-repair-v5/incidents"
) / V5_TERMINAL_INCIDENT_DIGEST

V6_T1_HANDOFF_SHA256 = (
    "2fce401086b878994ff1204a865149175e118107c94370a54cbe30341d3608ed"
)
V6_T2_TERMINAL_HANDOFF_SHA256 = (
    "5c46943e640c427b82377b31b63b601d902c10d12a3bf32d20f5ae0003447524"
)
V6_CAPTURE_T0_HANDOFF_SHA256 = (
    "89cae6450532e953ef592f281c68d9da3fda3b09b300ade4770bb554a39ef43e"
)
V6_TARGET_RELEASE_DIGEST = (
    "5c77db46b56402662d323a9fb8710ecf9a1031cd1df9a52d798cd90d2a1e7050"
)
V6_TARGET_MANIFEST_SHA256 = (
    "a2f7574ced41ae3d23d6ffcea48a7ac8c95c1cd85837d3de49c54f2a6b9e9adc"
)
V6_FUTURE_INSTALLED_INVENTORY_SHA256 = (
    "2c65b19c29c3982d7b80f83866e12462c6dbd5cc9cc16e4fdcb1c2aef31950b0"
)
V6_CONTROLLER_SHA256 = (
    "6a35f33868452ed67499356d927fb601e9a2aae2073071326b47ea3f3babdd94"
)
V6_STRATEGY_DIGEST = (
    "347da5377f30b71518193b28a345b13416705353181314bfaf29f4515c15b9c0"
)
V6_PLAN_DIGEST = (
    "bb256db4b59f63c8c585437a715c22c56272bff80186d32d84565064a1a0e7ca"
)
V6_INCIDENT_DIGEST = (
    "b08cab3afba90830e96484ce8f7c73077c12d06d49e54845256701dea3bf8a5e"
)
V6_FORMAL_1_STDOUT_SHA256 = (
    "79713fd494ac29305b3ce5e55f4637482a7533448d0f4a0bcebc20cfa7b76dec"
)
V6_FORMAL_2_STDERR_SHA256 = (
    "765fd2811f6b3c1147db09727e020e6404d375c243ca18209bedac94da6ce656"
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
V6_FORMAL_SEQUENCE = {
    "call_1": {
        "exit_code": 0,
        "status": "ready",
        "stderr_sha256": EMPTY_SHA256,
        "stderr_size": 0,
        "stdout_sha256": V6_FORMAL_1_STDOUT_SHA256,
        "stdout_size": 19407,
    },
    "call_2": {
        "exit_code": 1,
        "status": "indeterminate_rejected",
        "stderr_sha256": V6_FORMAL_2_STDERR_SHA256,
        "stderr_size": 109,
        "stdout_sha256": EMPTY_SHA256,
        "stdout_size": 0,
    },
    "calls_consumed": 2,
    "calls_maximum": 2,
    "reopen_authority": False,
}

V7_T1_HANDOFF_SHA256 = (
    "e97dae1af3287d515e84c685653bfe971568b3756b6371b10306dc25324a113f"
)
V7_T2_TERMINAL_HANDOFF_SHA256 = (
    "7ddcb07743373a35865775e7b9b937a9ac6c2218116e5ca31e21149f8a8f01af"
)
V7_CAPTURE_T0_HANDOFF_SHA256 = (
    "64e19a890fce3b095b307ce3d4f8288b0639b2d095a0a789770d0a3a2d6befdd"
)
V7_TARGET_RELEASE_DIGEST = (
    "036900e26391011626d63aecdd9183422a5801bd707b1f83736ae6a843cebd34"
)
V7_TARGET_MANIFEST_SHA256 = (
    "afa5f448e6356eb59125763cc4f61ffa9776af85f08efcb6b2553112dfbeb1f1"
)
V7_LAUNCHER_SHA256 = (
    "99312bb3e186af047db2fdf810e1b6da191027e8b89c312f87834f77df512967"
)
V7_CONTROLLER_SHA256 = (
    "3f1ac10270ead8612578f9087654111b2ec0e44d4a86b642464972cec0534d65"
)
V7_STRATEGY_DIGEST = (
    "bfe89004ebb9b31c410e91b99358b215a5363c70d6f2cd72a34135bcdab87eb3"
)
V7_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-formal-launcher-repair-v7"
)
V7_RESIDUE_ROOT_MODE = 0o700
V7_RESIDUE_ROOT_UID = 0
V7_RESIDUE_ROOT_GID = 0
V7_RESIDUE_ROOT_NLINK = 2
V7_RESIDUE_ROOT_SIZE = 4096
V7_RESIDUE_ROOT_MTIME_EPOCH = 1786342433
V7_RESIDUE_ROOT_CTIME_EPOCH = 1786342433
V7_PLAN_INPUT_SHA256 = EMPTY_SHA256
V7_PLAN_INPUT_SIZE = 0
V7_PREPARE_STDERR_SHA256 = (
    "286fa2bcbbbb5a162099d23a6f7f6f4ff03815fa1b1b74857a7e207830babf6e"
)
V7_PREPARE_STDERR_SIZE = 550
V7_PREPARE_CALL = {
    "action_calls": 0,
    "drift_checks": 0,
    "exit_code": 1,
    "formal_calls": 0,
    "incident_creations": 0,
    "live_mutations": 0,
    "plan_input_sha256": V7_PLAN_INPUT_SHA256,
    "plan_input_size": V7_PLAN_INPUT_SIZE,
    "prepare_calls": 1,
    "prepare_stderr_sha256": V7_PREPARE_STDERR_SHA256,
    "prepare_stderr_size": V7_PREPARE_STDERR_SIZE,
    "raw_stderr_read": False,
    "status": "indeterminate_rejected",
}

V8_T1_HANDOFF_SHA256 = (
    "e3e7b8335b956c8f203af7e05eeccfdb0c3116d5c87355dc38e662c6aa5283ec"
)
V8_T2_TERMINAL_HANDOFF_SHA256 = (
    "370fbcab3de185aad1ab61ba71a75c02b2afdb3b1e9c314ba8d9af30341a2c89"
)
V8_TIMEOUT_T0_HANDOFF_SHA256 = (
    "83ddd065c5d0a03b38d7c0933dcf335ce77988e994502e3cf46e7595dfcb1368"
)
V8_TARGET_RELEASE_DIGEST = (
    "32f8671cc1f2cfeab4c846d7951044587046ed70ffd264dd642f6f1d7ee470d3"
)
V8_TARGET_MANIFEST_SHA256 = (
    "5112a685430898358538b1d9cf42cfc6270f69d960d3458aed68a4e0d06571d4"
)
V8_LAUNCHER_SHA256 = (
    "84e958f4ca74e0458c4135701923ec39bfe1a387a7d423aca5384302385dbc1e"
)
V8_CONTROLLER_SHA256 = (
    "76992e81ca0ad888877ae1070ab4914d968b92846be9abe612cb87e58d8d4de4"
)
V8_STRATEGY_DIGEST = (
    "7f9a942cc6b4a0967db252a5593a240d88ec06e2aa8fd631520e1d409904e88e"
)
V8_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-prepare-capture-repair-v8"
)
V8_PREPARE_IDENTITY = (
    "f8e485a7c804464c4e947d2ad1976ab3b89073e627a2ff3677f59af24a0143ea"
)
V8_PREPARE_CAPTURE_IDENTITY = (
    "c8f6d1af3ed24b788acc3114900d5ef3c32601dce095fc79c854edd6b13f2f0a"
)
V8_PREPARE_PLAN_DIGEST = (
    "1501930beb63d922b2b0cc4985858c48e837f986706b8a6c1d3fe99b1d86bb75"
)
V8_PREPARE_FILES = {
    "CAPTURE.json": "c28289793cd4a1bd66ca5c0f85e658ea1b8b7902c2dee7d4ca51fd9ff93994c0",
    "CLAIM.json": "a164e02a056eafcfe4b3b75e051bbeab8b5ebed1233281287083121f322d376c",
    "PLAN.INPUT.json": "1b43140a0f2da777a7bf484d7189cefb647ce8689dac28dc23d08cb1028b0330",
    "PREPARE.json": "2d925fd63477b11aaa5fab3f101cb1798ba6b4282b36022a5a66a85ab1cf09ac",
    "RESULT.json": "ef0b4d323955ff39146eb78e1e69862f45aab412491c1ca4a81b56c4cab3ec58",
}
V8_FORMAL_SEQUENCE_IDENTITY = (
    "bc8fadca89493cc8ade2321867274bd95412e724bc3f2f53c43ff12a56a5d2db"
)
V8_FORMAL_CALL1_NONCE = (
    "cc1744c750a27a057529e34a72ee6e3a1e8e60b953d5b037c08bed5916f26e07"
)
V8_FORMAL_FILES = {
    "CALL-1.CAPTURE.json": "67118a3872589a93a8d65057532fc171ac9f1d0cada05c1c1e64b6a2b2f90e7d",
    "CALL-1.CLAIM.json": "c189b87009e1c97437b4acd0f039046084d0247dbf26026173bdcc2ab7b80f47",
    "SEQUENCE.json": "2782b8dacb6f69e36766c65a689942b202442600ddaf7f6634fc707aaa2981e8",
}
V8_FORMAL_STARTED_NS = 1786346918969963802
V8_FORMAL_ENDED_NS = 1786346949000440684
V8_FORMAL_TIMEOUT_SECONDS = 30
V8_FORMAL_SIGNAL = 9

V9_T1_HANDOFF_SHA256 = (
    "591144d0b9e7cd0f6c1d3e4b2f98274f0cdbc4f264849a665a9f39cdfe913859"
)
V9_T2_TERMINAL_HANDOFF_SHA256 = (
    "b6f6fae4a81535c82747efc026f4a7c688b8b51d0a36116c60389d02b5b106fc"
)
V9_TARGET_RELEASE_DIGEST = (
    "caa07af91857495e695482987161771bc5c2d22bd03e4d3781c2101f92be4c61"
)
V9_TARGET_MANIFEST_SHA256 = (
    "9f9c1e10a43292da9ab834394e4fe6cb778e3afa5065d44bb18bbc18ca68ebba"
)
V9_CONTROLLER_SHA256 = (
    "a0f6c36053309cb8eff35f70da6fbbde9e6d48feef10bb40221382737e7ade04"
)
V9_LAUNCHER_SHA256 = (
    "91c93bb85fa81004f0d20333a2bf0c27bd77480f85f89afd42f0665226198a34"
)
V9_STRATEGY_DIGEST = (
    "f79d03b1dc24d369aaf56ad99cc42854ff6c29c0c4f33065cfc20816826236f1"
)
V9_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-formal-timeout-repair-v9"
)
V9_PREPARE_IDENTITY = (
    "c1f0a37ed5528e25c16b708bb443026041d803557f21c5d501f52ab3c518c4dc"
)
V9_PREPARE_INVOCATION_IDENTITY = (
    "66c2de4d27d30ac062b0058a5c8c9b46cff3a69b4cd1e13227fe0f936c5880b8"
)
V9_PREPARE_CAPTURE_IDENTITY = (
    "5646db7f22c9c1843182216e825c90c65d2ac1c6ccb12d44aec3815213a028b9"
)
V9_PREPARE_RESULT_IDENTITY = (
    "98d4017648e982e7792ddc5da573d58515e87f573fc4e0bf0b0a73e25d14a50e"
)
V9_PLAN_DIGEST = (
    "73207a30c0ae98539b2c390473286a8e22abc8b0487705ee913e7197f02b8ddc"
)
V9_PLAN_SHA256 = (
    "0af3a8dda7a42521d911786464591b2556051381e88833ec84e9377503fa84a1"
)
V9_PREPARE_PHASE_TRACE_SHA256 = (
    "ebeb6cfe60e8038831bb2c8c55fe3f9aa23ccf2afc8b3855752cb65b96d05b53"
)
V9_PREPARE_FILES = {
    "CAPTURE.json": "eee10ad8bd23c921e90b7b6b92b6b5d9ce16beaa4c337dca093ba638e979a4cb",
    "CLAIM.json": "1703da943af90e4557d146ba62564b6ba406f6747d4c416f029116d757585b0b",
    "PLAN.INPUT.json": V9_PLAN_SHA256,
    "PREPARE.json": "c8d3bbbe1eed79f20208b6cd4d2ce34ab380f4bcd0cae053df3d4b08b062e471",
    "RESULT.json": "c48340c1eba99ff0e8ffe13ae023f8bb648fa8517ef940fb22e799c8d46cb504",
}
V9_FORMAL_SEQUENCE_IDENTITY = (
    "a73fb95a71f5927d9335b046474c444316538096a8337f6c2c94f56a012f3ebd"
)
V9_FORMAL_INVOCATION_IDENTITY = (
    "1b3019ab835536cecd5cd8a24474df6c4faf2c24734ca41b6702ca588c625f8d"
)
V9_FORMAL_RESULT_IDENTITY = (
    "dddada3cf3f6d86987cb29ed1341f28bbc7c20152ebb8cc6bccce8fa3c3d8a06"
)
V9_FORMAL_STDOUT_SHA256 = (
    "6535e710d34176bd0718bd4f1825f7f905e0a240f1fd29e9efabca5f18a58d1d"
)
V9_FORMAL_PHASE_TRACE_SHA256 = (
    "ee222081c2ea9573c7548cc78fd4598c0dd41acd6183b845e8af6d6f29910b94"
)
V9_FORMAL_CALL_NONCES = (
    "527298f728d5728cd755911dd8ad2f93206ecd9af4c58b693a38d30ae582d1e4",
    "29b802258b0736c217346684714234e105d9344072967a311449102fdca84709",
)
V9_FORMAL_FILES = {
    "CALL-1.CAPTURE.json": "e60247721e644a876a7ca726a5d0b8a31bf208b0795ccf7204169678d266a75f",
    "CALL-1.CLAIM.json": "1b2f0ce800139424c58324c5a0b5cce9a2b0966fe4a0f93da0c730c59800545b",
    "CALL-2.CAPTURE.json": "d94a6e28fc4893a7e5694e3df341e405fa5c6b53533e8d0223fe0246a3bb7793",
    "CALL-2.CLAIM.json": "18320aab51c56525fc592cc01c6c3f907fb5bb380a60ed0d978c668f792d61fa",
    "RESULT.json": "34648bf24bf8864a29634d9afed4d8da32d78d28fb8c6861952792d9dd8f0a97",
    "SEQUENCE.json": "f76de664efc766964899fbf917d8c2325c62b3a558d48e2cc90d4070feadf281",
}

V10_T1_HANDOFF_SHA256 = (
    "43b0bbcb9dabfb9af191ecb7daff1abe1059be59138094d6e14aac39481a6d6b"
)
V10_T2_TERMINAL_HANDOFF_SHA256 = (
    "f9eb7fac19973263cfa2cb49cbb77a2cde527bb8ec930f730adc3ddf9b257e5a"
)
V10_OWNERSHIP_T0_HANDOFF_SHA256 = (
    "98f1258112c18455cee8d1a6ab1a7e5821d3fbb7c0983ccea9341e4aeacc24e4"
)
V10_HOST_CLOCK_T0_HANDOFF_SHA256 = (
    "039a310841932b7ecacef3ac3ec671a0fc3fcca6ec404fcef45f13866f1c6ad5"
)
P08_POST_CORRECTION_T0_HANDOFF_SHA256 = (
    "367dbfdbb1a2d872bd5f4c19f1daba6e398a788051107b866cb60b16f1c109f7"
)
P10B_FORWARD_TRANSITION_T1_HANDOFF_SHA256 = (
    "129c409236049eb74bf1400dd4c2c1c5fad4106a10ed29217bc23f6f8a03cd7f"
)
V10_TARGET_RELEASE_DIGEST = (
    "7cbbdac78dae81b7488a3805654a7d7a0184e4815ba89ce4bbe91f95a4cbcdd0"
)
V10_TARGET_MANIFEST_SHA256 = (
    "d59f770ff502223d2a8d86e2842beb1a0d157b600544c48e4ada7de2fd5886d0"
)
V10_CONTROLLER_SHA256 = (
    "4f1fbcf0763387f7879a2dfd53b4630d1817e02f0866c79ed1be1dccbbc06ebe"
)
V10_LAUNCHER_SHA256 = (
    "02e709d4482ece7de2e0428d4a4ae2aefe1238f89c8c4537acddca374ed43d0d"
)
V10_STRATEGY_DIGEST = (
    "3f9af907d7b0a3cfd3fb3d1e354f5ea8f37e2f0f99d0c1991da51a5b30280093"
)
V10_PREPARE_IDENTITY = (
    "cc648b9ca6327b6eb7e36a46322261c248a4e1bda2068e54c50c7a1e13ab48f5"
)
V10_PREPARE_CAPTURE_IDENTITY = (
    "5aaf2799fc087597e959491d78517d76510370672f26778b51d7604ec7ca634e"
)
V10_PLAN_DIGEST = (
    "582594f5821e98dc383436016a4292446cb81d968cca0d640ee6817fdfcddcfc"
)
V10_PLAN_SHA256 = (
    "731c3767ee4b51bd3bd15b881008ab0fb91c0cd24ca22312d07168d574a62fb4"
)
V10_LEDGER_SHA256 = (
    "7ce06c27805c08c0727e4aa371b6069228400d7dedf7de0045e6bccca97add31"
)
V10_JOURNAL_SHA256 = (
    "4b088fb4802741cec5a0b1516bd87578d5198842397eea447b781ef87ef76207"
)
V10_RECEIPT_SHA256 = (
    "198bf47b665fa8d4c9d9cfe350e18864404d7037c138fabe037f3c3e63713ce2"
)
V10_STATE_BINDING_SHA256 = (
    "71b2a3277885f5c2d24f9dddcf236d83b48fd970facfa1828b7018de07c3b2ac"
)
V10_PUBLIC_MANIFEST_SHA256 = (
    "47367243041ae9620b0542c04a4daf2934b276fe8366d5eaa1a0042096067d28"
)
V10_STATE_MANIFEST_SHA256 = AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
V10_INCIDENT_DIGEST = (
    "196c322ac765f4dd460d8a2edab8253677ba3f6781f5b9d4273a4b7c6c3fb4ce"
)
V10_FORMAL_SEQUENCE_IDENTITY = (
    "9fe4cf42dd54bcf6f00f4f4f51b70c9047f76fd5bba3d723e0e8e5c680ddd54e"
)
V10_DRIFT_IDENTITY = (
    "5d984edeccfe4017ad946e9a50552461254c0b0e86e4aef936e55dfd022d1df8"
)
V10_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/p08-current-selected-drift-launcher-repair-v10"
)

V11_T1_HANDOFF_SHA256 = (
    "145b29d712cbac6e9cc5b658b53b2e6546352291c3f6efe6fed52da62343cc21"
)
V11_T2_TERMINAL_HANDOFF_SHA256 = (
    "584b0534656f02ed06138ce53053fda9be9125c95fac43a74bdebe8f95f4a34"
)
V11_CAPTURE_T0_HANDOFF_SHA256 = (
    "c33569621ce2951ed6eedd8149e7fba7539482180f480db84d465bed3b67939f"
)
V11_TARGET_RELEASE_DIGEST = (
    "730e5cea3154a23fc67dc61672b6b89dc804725dff877177adf851276b394cc7"
)
V11_TARGET_MANIFEST_SHA256 = (
    "b39571c306a19478c98f1d876cc8c8bc111d555f111a933a1d1bb36e54d3bc9c"
)
V11_CONTROLLER_SHA256 = (
    "f5a03e694aca005945fadf0067a843f075957dbf1b2892a7e600305843478b8b"
)
V11_LAUNCHER_SHA256 = (
    "ab3e3161f5c6fe8a89bb500927d3ee99d2f4291adcf0703a829311aba43beb78"
)
V11_STRATEGY_DIGEST = (
    "e45e3aa3b9e99def39ac3dd55e592303aeba80929ec4c4eff8c02db9422fbc0f"
)
V11_PREPARE_IDENTITY = (
    "759a0a53efc5d9d644af37de2239602f6e72ade1f96c2b27530a7d5869f9ad0a"
)
V11_PREPARE_CAPTURE_IDENTITY = (
    "a8393f7ae0d23bfbd4211afb3af4f9a00f093c2f2e07c339051f8241bed751f8"
)
V11_PLAN_DIGEST = (
    "f80e2e0ded97eeb34ff119dda2a47321c133f0a0902fec8aa2f195a876c4fb9f"
)
V11_PLAN_SHA256 = (
    "45f11664e102c031223e3f40a415dc667ecbcd320c54be11e10909ba45ef444d"
)
V11_PREPARE_FILES = {
    "CAPTURE.json": "de50e265ff02d58f764bca25ecbe3af3b2d76f413cf8fe21c00e0b301a419d53",
    "CLAIM.json": "b7051ae83c4079b178edde5ecbf1aaeb608cecf5da9e7d0cc4d79ec6427f2b02",
    "PLAN.INPUT.json": V11_PLAN_SHA256,
    "PREPARE.json": "28990909af59d25638a385e7b152b695b8de3988465a01cad4668969232d42db",
    "RESULT.json": "ccdabb79b978f7664ff4aed88ad3748b7de14f3d9342ae965de472ee402d0e93",
}
V11_FORMAL_SEQUENCE_IDENTITY = (
    "a10f8f1ff8159f7547b9d639763790d2580b35eb24122edb1c2fa63447de63e0"
)
V11_FORMAL_CALL_NONCE = (
    "a9e73718ac0eeabd2f8e389b168d1cb0b12c2a86dd64baa15bef49c672e59bc2"
)
V11_FORMAL_INVOCATION_IDENTITY = (
    "0a52aa7d6f53f8c697e31a3c5688220ab0010fe7162389309102d807d5ae90eb"
)
V11_FORMAL_STDOUT_SHA256 = (
    "15a8389b8145cc57bb2093d65bf2de0f4ae98abea8805b99bb38ae61b0a19009"
)
V11_FORMAL_PHASE_TRACE_SHA256 = (
    "b2e264489f526330ba21940ed0ec215c1bbaba7b3ad34835dff8848ebcd7bbd5"
)
V11_FORMAL_FILES = {
    "CALL-1.CAPTURE.json": "966d404cb31aa502c60b7125ae0b90387c8706ee9fcf39244b0ad95fffa6c7d5",
    "CALL-1.CLAIM.json": "80bfea8605f1355cc48f3ea465a375cd8c97c276e3f06e7b8dd1eed2e51301d7",
    "SEQUENCE.json": "37de204de5657959117ef836ae2dd26e4f55a8839bf080bf6c04b5d8d53eef88",
}
V11_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-forward-continuity-repair-v11"
)

V12_T1_HANDOFF_SHA256 = (
    "2867fee561acd61eee22bb77e14d8bb0141d36af2106c7177bb809e0548f316a"
)
V12_T2_TERMINAL_HANDOFF_SHA256 = (
    "b2fe6f4ccc691a823be1d88194769384a0ebe14c0810e521abab32aa9edaffe7"
)
V12_TARGET_RELEASE_DIGEST = (
    "865ccb9d4680fb2a8f86c7878c35332e37a6555168de52c23ba50ded903a74b6"
)
V12_TARGET_MANIFEST_SHA256 = (
    "e17447a18051d2138c4d082671ef5aedac0829637f4ce3c7361888f68cd8b49e"
)
V12_CONTROLLER_SHA256 = (
    "83643795b78b387d60cebf00f23b366c4741b50ec08474ac993e986d0de48c45"
)
V12_LAUNCHER_SHA256 = (
    "54839a39b27b7f1bfc806eb726f3193e9c6443456c55b3b2e77def7f392b71f2"
)
V12_STRATEGY_DIGEST = (
    "3761fb44f5a0c161ab9a31a3f01416210c418d2ef0e84fb448ddeeb456026aec"
)
V12_PREPARE_IDENTITY = (
    "dff85d78c8964a81c6ac97ef1f86029d2b5a142f5f4df98755a2b86d0d9b1a28"
)
V12_PREPARE_INVOCATION_IDENTITY = (
    "69f12dbfcb386aff7786baf2bbb1b8083a77e3f41dc452e8e3d475e5c664a222"
)
V12_PREPARE_RESULT_IDENTITY = (
    "f4aac8647758ed0be74ac3e619984a73305f1e16b63362482080af376ed2b7fe"
)
V12_PREPARE_FILES = {
    "CAPTURE.json": "1d536fa37618b53371eba720b72897dca82595985c1bc86265cf6f7466123974",
    "CLAIM.json": "f78808cb8d2a73c720f98dfaa74e56e4e95c7911e3183c174e7826d8f0b3fd01",
    "PREPARE.json": "92296a7c4a10b4130785ebc3ba5e4edd7ed475845b3baea833de9d3c1df568ea",
}
V12_EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-forward-continuity-capture-repair-v12"
)

ORIGIN_PLAN_DIGEST = post.COMPLETED_PLAN_DIGEST
ORIGIN_PLAN_SHA256 = post.COMPLETED_PLAN_SHA256
ORIGIN_JOURNAL_SHA256 = post.COMPLETED_JOURNAL_SHA256
ORIGIN_RECEIPT_SHA256 = post.COMPLETED_RECEIPT_SHA256
ORIGIN_EVIDENCE_ROOT = post.COMPLETED_EVIDENCE_ROOT

EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-forward-continuity-lineage-sha-repair-v13"
)
FORBIDDEN_PROGRAM_MUTATIONS = [
    "P01",
    "P07",
    "P09",
    "P10",
    "P15",
    "P16",
    "generation13",
    "owner_profile",
    "session_history",
]
READY_UNITS = {
    "service_active": "active",
    "socket_active": "active",
    "socket_enabled": "enabled",
}
JOURNAL_STAGES = (
    "prepared",
    "current_public_backed_up",
    "current_state_backed_up",
    "attempt_owned",
    "services_stopped",
    "release_installed",
    "forward_binding_durable",
    "forward_transition_committed",
    "public_applied",
    "target_started",
    "protocol_acceptance_called",
    "target_accepted",
)
Runner = Callable[[Sequence[str]], None]
AcceptanceRunner = Callable[[Path], Mapping[str, object]]
ForwardTransitionRunner = Callable[
    [Path, Mapping[str, object], Mapping[str, object], Path, Callable[[bytes], None]],
    Mapping[str, object],
]
ForwardReconcileRunner = Callable[
    [Path, Mapping[str, object], Mapping[str, object], Path],
    Mapping[str, object],
]
ForwardStateVerifier = Callable[
    [Path, Mapping[str, object], Mapping[str, object]], Mapping[str, object]
]
StageHook = Callable[[str], None]


class CurrentSelectedUpgradeRejected(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        action_failure_code: str | None = None,
        convergence_failure_code: str | None = None,
        content_free_failure_projection: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.action_failure_code = action_failure_code
        self.convergence_failure_code = convergence_failure_code
        self.content_free_failure_projection = content_free_failure_projection


class CanonicalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CurrentSelectedUpgradeRejected("controller_argument_rejected")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del status, message
        raise CurrentSelectedUpgradeRejected("controller_argument_rejected")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CurrentSelectedUpgradeRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _rooted(root: Path, absolute: Path) -> Path:
    return absolute if root == Path("/") else root / str(absolute).lstrip("/")


def _read_regular_bytes(path: Path, *, code: str, max_bytes: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= max_bytes,
            code,
        )
        chunks: list[bytes] = []
        observed = 0
        while observed < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - observed))
            require(bool(chunk), code)
            chunks.append(chunk)
            observed += len(chunk)
        require(not os.read(descriptor, 1), code)
        after = os.fstat(descriptor)
        require(
            observed == before.st_size
            and (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
            )
            == (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
            ),
            code,
        )
        return b"".join(chunks)
    except CurrentSelectedUpgradeRejected:
        raise
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected(code) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _digest_regular(path: Path, *, code: str, max_bytes: int) -> str:
    return digest_bytes(_read_regular_bytes(path, code=code, max_bytes=max_bytes))


def _load_json(path: Path, *, code: str) -> dict[str, object]:
    try:
        raw = _read_regular_bytes(
            path, code=code, max_bytes=upgrade.MAX_JSON_BYTES
        )
        payload = json.loads(raw.decode("utf-8", "strict"))
    except CurrentSelectedUpgradeRejected:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CurrentSelectedUpgradeRejected(code) from exc
    require(isinstance(payload, dict), code)
    return payload


def _source_controller_sha256(root: Path | None = None) -> str:
    path = (
        Path(__file__).resolve()
        if root is None
        else root / "scripts/p08_current_selected_upgrade_v1.py"
    )
    return upgrade.digest_file(path)


def prestate_rejection_contract() -> dict[str, object]:
    return {
        "action": "prepare",
        "action_calls": 0,
        "controller_sha256": PRESTATE_REJECTION_CONTROLLER_SHA256,
        "expected_terminal_state_manifest_sha256": (
            PRESTATE_REJECTION_EXPECTED_STATE_MANIFEST_SHA256
        ),
        "formal_preflight_calls": 0,
        "handoff_sha256": PRESTATE_REJECTION_HANDOFF_SHA256,
        "live_mutations": 0,
        "new_incident_namespaces": 0,
        "plan_creations": 0,
        "schema": PRESTATE_REJECTION_SCHEMA,
        "source_owned_prepare_calls": 1,
        "status": "terminal_lineage_identity_rejected",
        "strategy_digest": PRESTATE_REJECTION_STRATEGY_DIGEST,
        "target_release_digest": PRESTATE_REJECTION_TARGET_RELEASE_DIGEST,
        "terminal_state_manifest_sha256": (
            AUTHORITATIVE_TERMINAL_STATE_MANIFEST_SHA256
        ),
    }


def v7_prepare_residue_contract() -> dict[str, object]:
    body = {
        "content_opened": False,
        "evidence_root": str(V7_EVIDENCE_ROOT),
        "formal_calls": 0,
        "handoff_t0_sha256": V7_CAPTURE_T0_HANDOFF_SHA256,
        "handoff_t1_sha256": V7_T1_HANDOFF_SHA256,
        "handoff_t2_sha256": V7_T2_TERMINAL_HANDOFF_SHA256,
        "plan_input": {
            "gid": V7_RESIDUE_ROOT_GID,
            "mode": 0o600,
            "nlink": 1,
            "sha256": V7_PLAN_INPUT_SHA256,
            "size": V7_PLAN_INPUT_SIZE,
            "type": "regular",
            "uid": V7_RESIDUE_ROOT_UID,
        },
        "prepare_call": dict(V7_PREPARE_CALL),
        "prepare_stderr": {
            "gid": V7_RESIDUE_ROOT_GID,
            "mode": 0o600,
            "nlink": 1,
            "raw_content_read": False,
            "sha256": V7_PREPARE_STDERR_SHA256,
            "size": V7_PREPARE_STDERR_SIZE,
            "type": "regular",
            "uid": V7_RESIDUE_ROOT_UID,
        },
        "restore_authority": False,
        "root": {
            "ctime_epoch": V7_RESIDUE_ROOT_CTIME_EPOCH,
            "gid": V7_RESIDUE_ROOT_GID,
            "mode": V7_RESIDUE_ROOT_MODE,
            "mtime_epoch": V7_RESIDUE_ROOT_MTIME_EPOCH,
            "nlink": V7_RESIDUE_ROOT_NLINK,
            "size": V7_RESIDUE_ROOT_SIZE,
            "type": "directory",
            "uid": V7_RESIDUE_ROOT_UID,
        },
        "strategy_digest": V7_STRATEGY_DIGEST,
        "target_manifest_sha256": V7_TARGET_MANIFEST_SHA256,
        "target_release_digest": V7_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def v8_closed_sequence_contract() -> dict[str, object]:
    body = {
        "action_calls": 0,
        "content_opened": False,
        "controller_sha256": V8_CONTROLLER_SHA256,
        "evidence_root": str(V8_EVIDENCE_ROOT),
        "formal_call_1": {
            "call_nonce": V8_FORMAL_CALL1_NONCE,
            "ended_ns": V8_FORMAL_ENDED_NS,
            "raw_output_retained": False,
            "signal": V8_FORMAL_SIGNAL,
            "started_ns": V8_FORMAL_STARTED_NS,
            "status": "indeterminate",
            "stderr_sha256": EMPTY_SHA256,
            "stderr_size": 0,
            "stdout_sha256": EMPTY_SHA256,
            "stdout_size": 0,
            "timed_out": True,
            "timeout_seconds": V8_FORMAL_TIMEOUT_SECONDS,
        },
        "formal_calls_consumed": 1,
        "formal_calls_maximum": 2,
        "handoff_t0_sha256": V8_TIMEOUT_T0_HANDOFF_SHA256,
        "handoff_t1_sha256": V8_T1_HANDOFF_SHA256,
        "handoff_t2_sha256": V8_T2_TERMINAL_HANDOFF_SHA256,
        "incident_creations": 0,
        "launcher_sha256": V8_LAUNCHER_SHA256,
        "live_mutations": 0,
        "prepare": {
            "capture_identity": V8_PREPARE_CAPTURE_IDENTITY,
            "plan_digest": V8_PREPARE_PLAN_DIGEST,
            "prepare_identity": V8_PREPARE_IDENTITY,
            "status": "ready",
        },
        "reopen_authority": False,
        "restore_authority": False,
        "sequence_identity": V8_FORMAL_SEQUENCE_IDENTITY,
        "strategy_digest": V8_STRATEGY_DIGEST,
        "target_manifest_sha256": V8_TARGET_MANIFEST_SHA256,
        "target_release_digest": V8_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def v9_closed_sequence_contract() -> dict[str, object]:
    body = {
        "action_calls": 0,
        "controller_sha256": V9_CONTROLLER_SHA256,
        "drift_calls_consumed": 1,
        "drift_failure_category": "preentry_import_failure",
        "drift_reopen_authority": False,
        "evidence_root": str(V9_EVIDENCE_ROOT),
        "formal": {
            "calls_consumed": 2,
            "calls_maximum": 2,
            "invocation_identity_sha256": V9_FORMAL_INVOCATION_IDENTITY,
            "result_identity_sha256": V9_FORMAL_RESULT_IDENTITY,
            "sequence_identity": V9_FORMAL_SEQUENCE_IDENTITY,
            "status": "ready_identical_closed",
            "stdout_sha256": V9_FORMAL_STDOUT_SHA256,
        },
        "handoff_t1_sha256": V9_T1_HANDOFF_SHA256,
        "handoff_t2_sha256": V9_T2_TERMINAL_HANDOFF_SHA256,
        "incident_creations": 0,
        "launcher_sha256": V9_LAUNCHER_SHA256,
        "live_mutations": 0,
        "prepare": {
            "capture_identity_sha256": V9_PREPARE_CAPTURE_IDENTITY,
            "invocation_identity_sha256": V9_PREPARE_INVOCATION_IDENTITY,
            "plan_digest": V9_PLAN_DIGEST,
            "plan_sha256": V9_PLAN_SHA256,
            "prepare_identity": V9_PREPARE_IDENTITY,
            "result_identity_sha256": V9_PREPARE_RESULT_IDENTITY,
            "status": "ready",
        },
        "reopen_authority": False,
        "restore_authority": False,
        "strategy_digest": V9_STRATEGY_DIGEST,
        "target_manifest_sha256": V9_TARGET_MANIFEST_SHA256,
        "target_release_digest": V9_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def v10_terminal_contract() -> dict[str, object]:
    body = {
        "action_calls_consumed": 1,
        "controller_sha256": V10_CONTROLLER_SHA256,
        "drift_identity": V10_DRIFT_IDENTITY,
        "formal_sequence_identity": V10_FORMAL_SEQUENCE_IDENTITY,
        "handoff_t0_host_clock_sha256": V10_HOST_CLOCK_T0_HANDOFF_SHA256,
        "handoff_t0_ownership_sha256": V10_OWNERSHIP_T0_HANDOFF_SHA256,
        "handoff_t1_sha256": V10_T1_HANDOFF_SHA256,
        "handoff_t2_sha256": V10_T2_TERMINAL_HANDOFF_SHA256,
        "incident_digest": V10_INCIDENT_DIGEST,
        "journal_sha256": V10_JOURNAL_SHA256,
        "launcher_sha256": V10_LAUNCHER_SHA256,
        "ledger_sha256": V10_LEDGER_SHA256,
        "plan_digest": V10_PLAN_DIGEST,
        "plan_sha256": V10_PLAN_SHA256,
        "prepare_capture_identity": V10_PREPARE_CAPTURE_IDENTITY,
        "prepare_identity": V10_PREPARE_IDENTITY,
        "public_manifest_sha256": V10_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": V10_RECEIPT_SHA256,
        "reopen_authority": False,
        "restore_authority": False,
        "state_binding_sha256": V10_STATE_BINDING_SHA256,
        "state_manifest_sha256": V10_STATE_MANIFEST_SHA256,
        "status": "trusted_time_drift_exceeded_predecessor_restored",
        "strategy_digest": V10_STRATEGY_DIGEST,
        "target_manifest_sha256": V10_TARGET_MANIFEST_SHA256,
        "target_release_digest": V10_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def v11_closed_sequence_contract() -> dict[str, object]:
    body = {
        "action_calls_consumed": 0,
        "capture_t0_handoff_sha256": V11_CAPTURE_T0_HANDOFF_SHA256,
        "controller_sha256": V11_CONTROLLER_SHA256,
        "formal": {
            "call_1_nonce": V11_FORMAL_CALL_NONCE,
            "calls_consumed": 1,
            "calls_maximum": 2,
            "invocation_identity_sha256": V11_FORMAL_INVOCATION_IDENTITY,
            "phase_trace_sha256": V11_FORMAL_PHASE_TRACE_SHA256,
            "sequence_identity": V11_FORMAL_SEQUENCE_IDENTITY,
            "status": "closed_indeterminate",
            "stdout_sha256": V11_FORMAL_STDOUT_SHA256,
        },
        "launcher_sha256": V11_LAUNCHER_SHA256,
        "live_mutations": 0,
        "prepare": {
            "capture_identity_sha256": V11_PREPARE_CAPTURE_IDENTITY,
            "plan_digest": V11_PLAN_DIGEST,
            "plan_sha256": V11_PLAN_SHA256,
            "prepare_identity": V11_PREPARE_IDENTITY,
            "status": "ready",
        },
        "reopen_authority": False,
        "restore_authority": False,
        "strategy_digest": V11_STRATEGY_DIGEST,
        "t1_handoff_sha256": V11_T1_HANDOFF_SHA256,
        "t2_terminal_handoff_sha256": V11_T2_TERMINAL_HANDOFF_SHA256,
        "target_manifest_sha256": V11_TARGET_MANIFEST_SHA256,
        "target_release_digest": V11_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def v12_rejected_prepare_contract() -> dict[str, object]:
    body = {
        "action_calls_consumed": 0,
        "controller_sha256": V12_CONTROLLER_SHA256,
        "evidence_files": V12_PREPARE_FILES,
        "formal_calls_consumed": 0,
        "launcher_sha256": V12_LAUNCHER_SHA256,
        "live_mutations": 0,
        "prepare": {
            "invocation_identity_sha256": V12_PREPARE_INVOCATION_IDENTITY,
            "parsed_result_identity_sha256": V12_PREPARE_RESULT_IDENTITY,
            "prepare_identity": V12_PREPARE_IDENTITY,
            "result_detail": "typed_rejection:v11_closed_sequence_rejected",
            "status": "rejected",
        },
        "reopen_authority": False,
        "restore_authority": False,
        "strategy_digest": V12_STRATEGY_DIGEST,
        "t1_handoff_sha256": V12_T1_HANDOFF_SHA256,
        "t2_terminal_handoff_sha256": V12_T2_TERMINAL_HANDOFF_SHA256,
        "target_manifest_sha256": V12_TARGET_MANIFEST_SHA256,
        "target_release_digest": V12_TARGET_RELEASE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def p07_single_nonce_integration_contract() -> dict[str, object]:
    body = {
        "artifact_root_contract_digest": P07_ARTIFACT_ROOT_CONTRACT_DIGEST,
        "bound_helper_sha256": P07_BOUND_HELPER_SHA256,
        "bundle_manifest_sha256": P07_BUNDLE_MANIFEST_SHA256,
        "deploy_commit": P07_INTEGRATION_DEPLOY_COMMIT,
        "fresh_strategy_digest": P07_FRESH_STRATEGY_DIGEST,
        "handoff_sha256": P07_INTEGRATION_HANDOFF_SHA256,
        "immutable_reference_digest": P07_IMMUTABLE_REFERENCE_DIGEST,
        "max_attempts": 1,
        "plugin_binding_digest": P07_PLUGIN_BINDING_DIGEST,
        "plugin_digest": P07_PLUGIN_DIGEST,
        "plugin_manifest_sha256": P07_PLUGIN_MANIFEST_SHA256,
        "protocol_acceptance_contract_digest": (
            P07_PROTOCOL_ACCEPTANCE_CONTRACT_DIGEST
        ),
        "runtime_binding_digest": P07_RUNTIME_BINDING_DIGEST,
        "runtime_manifest_sha256": P07_RUNTIME_MANIFEST_SHA256,
        "runtime_projection_digest": P07_RUNTIME_PROJECTION_DIGEST,
        "runtime_release_digest": P07_RUNTIME_RELEASE_DIGEST,
        "schema": P07_INTEGRATION_SCHEMA,
        "service_identity_digest": P07_SERVICE_IDENTITY_DIGEST,
        "single_nonce_stage_t1_handoff_sha256": (
            SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256
        ),
        "transactional_bundle_digest": P07_TRANSACTIONAL_BUNDLE_DIGEST,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def strategy_contract(
    *,
    controller_sha256: str | None = None,
    formal_launcher_contract: Mapping[str, object] | None = None,
) -> dict[str, object]:
    controller = controller_sha256 or _source_controller_sha256()
    launcher_contract = (
        dict(formal_launcher_contract)
        if formal_launcher_contract is not None
        else formal_launcher.release_contract(Path(__file__).resolve().parents[1])
    )
    body = {
        "accepted_incident_digest": ACCEPTED_INCIDENT_DIGEST,
        "accepted_receipt_sha256": ACCEPTED_RECEIPT_SHA256,
        "controller_sha256": controller,
        "failed_incident_digest": FAILED_INCIDENT_DIGEST,
        "failed_journal_sha256": FAILED_JOURNAL_SHA256,
        "failed_ledger_sha256": FAILED_LEDGER_SHA256,
        "failed_plan_sha256": FAILED_PLAN_SHA256,
        "failed_public_manifest_sha256": FAILED_PUBLIC_MANIFEST_SHA256,
        "incident_namespace": str(EVIDENCE_ROOT / "incidents"),
        "formal_launcher": launcher_contract,
        "forward_continuity": continuity.contract(),
        "max_attempts": 1,
        "p08_post_correction_t0_handoff_sha256": (
            P08_POST_CORRECTION_T0_HANDOFF_SHA256
        ),
        "p10b_forward_transition_t1_handoff_sha256": (
            P10B_FORWARD_TRANSITION_T1_HANDOFF_SHA256
        ),
        "p08_trusted_time_t0_handoff_sha256": P08_TRUSTED_TIME_T0_HANDOFF_SHA256,
        "p10b_trusted_time_t0_handoff_sha256": P10B_TRUSTED_TIME_T0_HANDOFF_SHA256,
        "p07_single_nonce_integration": p07_single_nonce_integration_contract(),
        "predecessor_manifest_sha256": PREDECESSOR_MANIFEST_SHA256,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "prestate_rejection": prestate_rejection_contract(),
        "nonzero_stage_t0_handoff_sha256": NONZERO_STAGE_T0_HANDOFF_SHA256,
        "single_nonce_stage_t1_handoff_sha256": (
            SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256
        ),
        "schema": STRATEGY_SCHEMA,
        "terminal_incident_digest": TERMINAL_INCIDENT_DIGEST,
        "terminal_journal_sha256": TERMINAL_JOURNAL_SHA256,
        "terminal_plan_sha256": TERMINAL_PLAN_SHA256,
        "terminal_receipt_sha256": TERMINAL_RECEIPT_SHA256,
        "v2_terminal_incident_digest": V2_TERMINAL_INCIDENT_DIGEST,
        "v2_terminal_journal_sha256": V2_TERMINAL_JOURNAL_SHA256,
        "v2_terminal_ledger_sha256": V2_TERMINAL_LEDGER_SHA256,
        "v2_terminal_plan_digest": V2_TERMINAL_PLAN_DIGEST,
        "v2_terminal_plan_sha256": V2_TERMINAL_PLAN_SHA256,
        "v2_terminal_public_manifest_sha256": V2_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "v2_terminal_receipt_sha256": V2_TERMINAL_RECEIPT_SHA256,
        "v2_terminal_state_binding_sha256": V2_TERMINAL_STATE_BINDING_SHA256,
        "v2_terminal_state_manifest_sha256": V2_TERMINAL_STATE_MANIFEST_SHA256,
        "v4_terminal_handoff_sha256": V4_TERMINAL_HANDOFF_SHA256,
        "v4_terminal_incident_digest": V4_TERMINAL_INCIDENT_DIGEST,
        "v4_terminal_journal_sha256": V4_TERMINAL_JOURNAL_SHA256,
        "v4_terminal_ledger_sha256": V4_TERMINAL_LEDGER_SHA256,
        "v4_terminal_plan_digest": V4_TERMINAL_PLAN_DIGEST,
        "v4_terminal_plan_sha256": V4_TERMINAL_PLAN_SHA256,
        "v4_terminal_public_manifest_sha256": V4_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "v4_terminal_receipt_sha256": V4_TERMINAL_RECEIPT_SHA256,
        "v4_terminal_state_binding_sha256": V4_TERMINAL_STATE_BINDING_SHA256,
        "v4_terminal_state_manifest_sha256": V4_TERMINAL_STATE_MANIFEST_SHA256,
        "v5_terminal_handoff_sha256": V5_TERMINAL_HANDOFF_SHA256,
        "v5_terminal_incident_digest": V5_TERMINAL_INCIDENT_DIGEST,
        "v5_terminal_journal_sha256": V5_TERMINAL_JOURNAL_SHA256,
        "v5_terminal_ledger_sha256": V5_TERMINAL_LEDGER_SHA256,
        "v5_terminal_plan_digest": V5_TERMINAL_PLAN_DIGEST,
        "v5_terminal_plan_sha256": V5_TERMINAL_PLAN_SHA256,
        "v5_terminal_public_manifest_sha256": V5_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "v5_terminal_receipt_sha256": V5_TERMINAL_RECEIPT_SHA256,
        "v5_terminal_state_binding_sha256": V5_TERMINAL_STATE_BINDING_SHA256,
        "v5_terminal_state_manifest_sha256": V5_TERMINAL_STATE_MANIFEST_SHA256,
        "v6_capture_t0_handoff_sha256": V6_CAPTURE_T0_HANDOFF_SHA256,
        "v6_controller_sha256": V6_CONTROLLER_SHA256,
        "v6_formal_sequence": V6_FORMAL_SEQUENCE,
        "v6_future_installed_inventory_sha256": (
            V6_FUTURE_INSTALLED_INVENTORY_SHA256
        ),
        "v6_incident_digest": V6_INCIDENT_DIGEST,
        "v6_plan_digest": V6_PLAN_DIGEST,
        "v6_strategy_digest": V6_STRATEGY_DIGEST,
        "v6_t1_handoff_sha256": V6_T1_HANDOFF_SHA256,
        "v6_t2_terminal_handoff_sha256": V6_T2_TERMINAL_HANDOFF_SHA256,
        "v6_target_manifest_sha256": V6_TARGET_MANIFEST_SHA256,
        "v6_target_release_digest": V6_TARGET_RELEASE_DIGEST,
        "v7_capture_t0_handoff_sha256": V7_CAPTURE_T0_HANDOFF_SHA256,
        "v7_controller_sha256": V7_CONTROLLER_SHA256,
        "v7_launcher_sha256": V7_LAUNCHER_SHA256,
        "v7_prepare_residue": v7_prepare_residue_contract(),
        "v7_strategy_digest": V7_STRATEGY_DIGEST,
        "v7_t1_handoff_sha256": V7_T1_HANDOFF_SHA256,
        "v7_t2_terminal_handoff_sha256": V7_T2_TERMINAL_HANDOFF_SHA256,
        "v7_target_manifest_sha256": V7_TARGET_MANIFEST_SHA256,
        "v7_target_release_digest": V7_TARGET_RELEASE_DIGEST,
        "v8_closed_sequence": v8_closed_sequence_contract(),
        "v8_controller_sha256": V8_CONTROLLER_SHA256,
        "v8_launcher_sha256": V8_LAUNCHER_SHA256,
        "v8_strategy_digest": V8_STRATEGY_DIGEST,
        "v8_t0_handoff_sha256": V8_TIMEOUT_T0_HANDOFF_SHA256,
        "v8_t1_handoff_sha256": V8_T1_HANDOFF_SHA256,
        "v8_t2_terminal_handoff_sha256": V8_T2_TERMINAL_HANDOFF_SHA256,
        "v8_target_manifest_sha256": V8_TARGET_MANIFEST_SHA256,
        "v8_target_release_digest": V8_TARGET_RELEASE_DIGEST,
        "v9_closed_sequence": v9_closed_sequence_contract(),
        "v9_controller_sha256": V9_CONTROLLER_SHA256,
        "v9_launcher_sha256": V9_LAUNCHER_SHA256,
        "v9_strategy_digest": V9_STRATEGY_DIGEST,
        "v9_t1_handoff_sha256": V9_T1_HANDOFF_SHA256,
        "v9_t2_terminal_handoff_sha256": V9_T2_TERMINAL_HANDOFF_SHA256,
        "v9_target_manifest_sha256": V9_TARGET_MANIFEST_SHA256,
        "v9_target_release_digest": V9_TARGET_RELEASE_DIGEST,
        "v10_terminal": v10_terminal_contract(),
        "v11_closed_sequence": v11_closed_sequence_contract(),
        "v11_controller_sha256": V11_CONTROLLER_SHA256,
        "v11_launcher_sha256": V11_LAUNCHER_SHA256,
        "v11_strategy_digest": V11_STRATEGY_DIGEST,
        "v11_t0_handoff_sha256": V11_CAPTURE_T0_HANDOFF_SHA256,
        "v11_t1_handoff_sha256": V11_T1_HANDOFF_SHA256,
        "v11_t2_terminal_handoff_sha256": V11_T2_TERMINAL_HANDOFF_SHA256,
        "v11_target_manifest_sha256": V11_TARGET_MANIFEST_SHA256,
        "v11_target_release_digest": V11_TARGET_RELEASE_DIGEST,
        "v12_rejected_prepare": v12_rejected_prepare_contract(),
        "v12_controller_sha256": V12_CONTROLLER_SHA256,
        "v12_launcher_sha256": V12_LAUNCHER_SHA256,
        "v12_strategy_digest": V12_STRATEGY_DIGEST,
        "v12_t1_handoff_sha256": V12_T1_HANDOFF_SHA256,
        "v12_t2_terminal_handoff_sha256": V12_T2_TERMINAL_HANDOFF_SHA256,
        "v12_target_manifest_sha256": V12_TARGET_MANIFEST_SHA256,
        "v12_target_release_digest": V12_TARGET_RELEASE_DIGEST,
    }
    return {**body, "strategy_digest": digest_bytes(canonical(body))}


def release_contract(root: Path) -> dict[str, object]:
    controller = _source_controller_sha256(root)
    launcher_contract = formal_launcher.release_contract(root)
    return {
        "accepted_incident_digest": ACCEPTED_INCIDENT_DIGEST,
        "action": "upgrade",
        "action_state_binding_schema": STATE_BINDING_SCHEMA,
        "failed_incident_digest": FAILED_INCIDENT_DIGEST,
        "failed_restore_authority": False,
        "formal_launcher": launcher_contract,
        "forward_continuity": continuity.contract(),
        "incident_max_actions": 1,
        "journal_schema": JOURNAL_SCHEMA,
        "ledger_schema": LEDGER_SCHEMA,
        "live_execute_implemented": True,
        "max_attempts": 1,
        "plan_schema": PLAN_SCHEMA,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "prestate_rejection": prestate_rejection_contract(),
        "nonzero_stage_t0_handoff_sha256": NONZERO_STAGE_T0_HANDOFF_SHA256,
        "p07_single_nonce_integration": p07_single_nonce_integration_contract(),
        "readiness_schema": READINESS_SCHEMA,
        "receipt_schema": RECEIPT_SCHEMA,
        "sha256": controller,
        "source_path": "scripts/p08_current_selected_upgrade_v1.py",
        "strategy": strategy_contract(
            controller_sha256=controller,
            formal_launcher_contract=launcher_contract,
        ),
        "single_nonce_stage_t1_handoff_sha256": (
            SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256
        ),
        "terminal_incident_digest": TERMINAL_INCIDENT_DIGEST,
        "terminal_restore_authority": False,
        "v2_terminal_incident_digest": V2_TERMINAL_INCIDENT_DIGEST,
        "v2_terminal_restore_authority": False,
        "v4_terminal_incident_digest": V4_TERMINAL_INCIDENT_DIGEST,
        "v4_terminal_restore_authority": False,
        "v5_terminal_incident_digest": V5_TERMINAL_INCIDENT_DIGEST,
        "v5_terminal_restore_authority": False,
        "v6_capture_t0_handoff_sha256": V6_CAPTURE_T0_HANDOFF_SHA256,
        "v6_incident_digest": V6_INCIDENT_DIGEST,
        "v6_restore_authority": False,
        "v6_t2_terminal_handoff_sha256": V6_T2_TERMINAL_HANDOFF_SHA256,
        "v7_prepare_residue": v7_prepare_residue_contract(),
        "v7_restore_authority": False,
        "v7_t2_terminal_handoff_sha256": V7_T2_TERMINAL_HANDOFF_SHA256,
        "v8_closed_sequence": v8_closed_sequence_contract(),
        "v8_restore_authority": False,
        "v8_t2_terminal_handoff_sha256": V8_T2_TERMINAL_HANDOFF_SHA256,
        "v9_closed_sequence": v9_closed_sequence_contract(),
        "v9_restore_authority": False,
        "v9_t2_terminal_handoff_sha256": V9_T2_TERMINAL_HANDOFF_SHA256,
        "v11_closed_sequence": v11_closed_sequence_contract(),
        "v11_restore_authority": False,
        "v11_t2_terminal_handoff_sha256": V11_T2_TERMINAL_HANDOFF_SHA256,
        "v12_rejected_prepare": v12_rejected_prepare_contract(),
        "v12_restore_authority": False,
        "v12_t2_terminal_handoff_sha256": V12_T2_TERMINAL_HANDOFF_SHA256,
    }


def _accepted_evidence_path(root: Path) -> Path:
    return _rooted(root, ACCEPTED_EVIDENCE_ROOT)


def _failed_evidence_path(root: Path) -> Path:
    return _rooted(root, FAILED_EVIDENCE_ROOT)


def _terminal_evidence_path(root: Path) -> Path:
    return _rooted(root, TERMINAL_EVIDENCE_ROOT)


def _v2_terminal_evidence_path(root: Path) -> Path:
    return _rooted(root, V2_TERMINAL_EVIDENCE_ROOT)


def _v4_terminal_evidence_path(root: Path) -> Path:
    return _rooted(root, V4_TERMINAL_EVIDENCE_ROOT)


def _v5_terminal_evidence_path(root: Path) -> Path:
    return _rooted(root, V5_TERMINAL_EVIDENCE_ROOT)


def _v7_prepare_residue_path(root: Path) -> Path:
    return _rooted(root, V7_EVIDENCE_ROOT)


def _v8_closed_sequence_path(root: Path) -> Path:
    return _rooted(root, V8_EVIDENCE_ROOT)


def _v9_closed_sequence_path(root: Path) -> Path:
    return _rooted(root, V9_EVIDENCE_ROOT)


def _v11_closed_sequence_path(root: Path) -> Path:
    return _rooted(root, V11_EVIDENCE_ROOT)


def _v12_rejected_prepare_path(root: Path) -> Path:
    return _rooted(root, V12_EVIDENCE_ROOT)


def validate_v7_prepare_residue(root: Path) -> dict[str, object]:
    selected = _v7_prepare_residue_path(root)
    try:
        root_metadata = selected.lstat()
        names = sorted(entry.name for entry in os.scandir(selected))
        plan_metadata = (selected / "PLAN.INPUT.json").lstat()
        stderr_metadata = (selected / "PREPARE.STDERR.bin").lstat()
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("v7_prepare_residue_rejected") from exc
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == V7_RESIDUE_ROOT_MODE
        and root_metadata.st_uid == V7_RESIDUE_ROOT_UID
        and root_metadata.st_gid == V7_RESIDUE_ROOT_GID
        and root_metadata.st_nlink == V7_RESIDUE_ROOT_NLINK
        and root_metadata.st_size == V7_RESIDUE_ROOT_SIZE
        and int(root_metadata.st_mtime) == V7_RESIDUE_ROOT_MTIME_EPOCH
        and int(root_metadata.st_ctime) == V7_RESIDUE_ROOT_CTIME_EPOCH
        and names == ["PLAN.INPUT.json", "PREPARE.STDERR.bin"],
        "v7_prepare_residue_rejected",
    )
    for metadata, expected_size in (
        (plan_metadata, V7_PLAN_INPUT_SIZE),
        (stderr_metadata, V7_PREPARE_STDERR_SIZE),
    ):
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == V7_RESIDUE_ROOT_UID
            and metadata.st_gid == V7_RESIDUE_ROOT_GID
            and metadata.st_nlink == 1
            and metadata.st_size == expected_size,
            "v7_prepare_residue_rejected",
        )
    return {
        "content_opened": False,
        "contract_digest": v7_prepare_residue_contract()["contract_digest"],
        "evidence_root": str(V7_EVIDENCE_ROOT),
        "metadata_verified": True,
        "restore_authority": False,
    }


def validate_v8_closed_sequence(root: Path) -> dict[str, object]:
    selected = _v8_closed_sequence_path(root)
    prepare = selected / "prepare-captures" / V8_PREPARE_IDENTITY
    formal = selected / "formal-sequences" / V8_FORMAL_SEQUENCE_IDENTITY
    try:
        root_metadata = selected.lstat()
        prepare_parent = prepare.parent.lstat()
        formal_parent = formal.parent.lstat()
        prepare_metadata = prepare.lstat()
        formal_metadata = formal.lstat()
        root_names = sorted(entry.name for entry in os.scandir(selected))
        prepare_names = sorted(entry.name for entry in os.scandir(prepare))
        formal_names = sorted(entry.name for entry in os.scandir(formal))
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("v8_closed_sequence_rejected") from exc
    require(
        root_names == ["formal-sequences", "prepare-captures"]
        and prepare_names == sorted(V8_PREPARE_FILES)
        and formal_names == sorted(V8_FORMAL_FILES),
        "v8_closed_sequence_rejected",
    )
    for metadata in (
        root_metadata,
        prepare_parent,
        formal_parent,
        prepare_metadata,
        formal_metadata,
    ):
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "v8_closed_sequence_rejected",
        )
    for directory, expected in (
        (prepare, V8_PREPARE_FILES),
        (formal, V8_FORMAL_FILES),
    ):
        for name, expected_sha256 in expected.items():
            path = directory / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CurrentSelectedUpgradeRejected(
                    "v8_closed_sequence_rejected"
                ) from exc
            require(
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and metadata.st_nlink == 1
                and _digest_regular(
                    path,
                    code="v8_closed_sequence_rejected",
                    max_bytes=upgrade.MAX_JSON_BYTES,
                )
                == expected_sha256,
                "v8_closed_sequence_rejected",
            )
    prepare_capture = _load_json(
        prepare / "CAPTURE.json", code="v8_closed_sequence_rejected"
    )
    prepare_result = _load_json(
        prepare / "RESULT.json", code="v8_closed_sequence_rejected"
    )
    formal_capture = _load_json(
        formal / "CALL-1.CAPTURE.json", code="v8_closed_sequence_rejected"
    )
    require(
        prepare_capture.get("schema") == "myuna.p08-prepare-capture.v1"
        and prepare_capture.get("prepare_identity") == V8_PREPARE_IDENTITY
        and prepare_capture.get("status") == "ready"
        and prepare_capture.get("timed_out") is False
        and prepare_capture.get("raw_output_retained") is False
        and prepare_result.get("schema")
        == "myuna.p08-prepare-capture-result.v1"
        and prepare_result.get("prepare_identity") == V8_PREPARE_IDENTITY
        and prepare_result.get("capture_identity_sha256")
        == V8_PREPARE_CAPTURE_IDENTITY
        and prepare_result.get("plan_digest") == V8_PREPARE_PLAN_DIGEST
        and prepare_result.get("status") == "ready"
        and prepare_result.get("persistent_product_mutation") is False
        and formal_capture.get("schema")
        == "myuna.p08-formal-preflight-capture.v2"
        and formal_capture.get("sequence_identity")
        == V8_FORMAL_SEQUENCE_IDENTITY
        and formal_capture.get("call_index") == 1
        and formal_capture.get("call_nonce") == V8_FORMAL_CALL1_NONCE
        and formal_capture.get("status") == "indeterminate"
        and formal_capture.get("timed_out") is True
        and formal_capture.get("signal") == V8_FORMAL_SIGNAL
        and formal_capture.get("started_ns") == V8_FORMAL_STARTED_NS
        and formal_capture.get("ended_ns") == V8_FORMAL_ENDED_NS
        and formal_capture.get("stdout_size") == 0
        and formal_capture.get("stderr_size") == 0
        and formal_capture.get("stdout_sha256") == EMPTY_SHA256
        and formal_capture.get("stderr_sha256") == EMPTY_SHA256
        and formal_capture.get("raw_output_retained") is False,
        "v8_closed_sequence_rejected",
    )
    return {
        "contract_digest": v8_closed_sequence_contract()["contract_digest"],
        "evidence_root": str(V8_EVIDENCE_ROOT),
        "formal_calls_consumed": 1,
        "metadata_verified": True,
        "prepare_status": "ready",
        "reopen_authority": False,
        "restore_authority": False,
        "sequence_status": "closed_timeout",
    }


def validate_v9_closed_sequence(root: Path) -> dict[str, object]:
    selected = _v9_closed_sequence_path(root)
    prepare = selected / "prepare-captures" / V9_PREPARE_IDENTITY
    formal = selected / "formal-sequences" / V9_FORMAL_SEQUENCE_IDENTITY
    try:
        directories = (
            selected.lstat(),
            prepare.parent.lstat(),
            prepare.lstat(),
            formal.parent.lstat(),
            formal.lstat(),
        )
        root_names = sorted(entry.name for entry in os.scandir(selected))
        prepare_names = sorted(entry.name for entry in os.scandir(prepare))
        formal_names = sorted(entry.name for entry in os.scandir(formal))
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("v9_closed_sequence_rejected") from exc
    require(
        root_names == ["formal-sequences", "prepare-captures"]
        and prepare_names == sorted(V9_PREPARE_FILES)
        and formal_names == sorted(V9_FORMAL_FILES),
        "v9_closed_sequence_rejected",
    )
    for metadata in directories:
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "v9_closed_sequence_rejected",
        )
    for directory, expected in (
        (prepare, V9_PREPARE_FILES),
        (formal, V9_FORMAL_FILES),
    ):
        for name, expected_sha256 in expected.items():
            path = directory / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CurrentSelectedUpgradeRejected(
                    "v9_closed_sequence_rejected"
                ) from exc
            require(
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and metadata.st_nlink == 1
                and _digest_regular(
                    path,
                    code="v9_closed_sequence_rejected",
                    max_bytes=upgrade.MAX_JSON_BYTES,
                )
                == expected_sha256,
                "v9_closed_sequence_rejected",
            )
    prepare_capture = _load_json(
        prepare / "CAPTURE.json", code="v9_closed_sequence_rejected"
    )
    prepare_result = _load_json(
        prepare / "RESULT.json", code="v9_closed_sequence_rejected"
    )
    plan = _load_json(
        prepare / "PLAN.INPUT.json", code="v9_closed_sequence_rejected"
    )
    formal_captures = [
        _load_json(
            formal / f"CALL-{call_index}.CAPTURE.json",
            code="v9_closed_sequence_rejected",
        )
        for call_index in (1, 2)
    ]
    formal_result = _load_json(
        formal / "RESULT.json", code="v9_closed_sequence_rejected"
    )
    require(
        prepare_capture.get("schema") == "myuna.p08-prepare-capture.v2"
        and prepare_capture.get("status") == "ready"
        and prepare_capture.get("prepare_identity") == V9_PREPARE_IDENTITY
        and prepare_capture.get("invocation_identity_sha256")
        == V9_PREPARE_INVOCATION_IDENTITY
        and prepare_capture.get("parsed_result_identity_sha256")
        == V9_PREPARE_RESULT_IDENTITY
        and prepare_capture.get("stdout_sha256") == V9_PLAN_SHA256
        and prepare_capture.get("stdout_size") == 28_958
        and prepare_capture.get("stderr_size") == 0
        and prepare_capture.get("phase_liveness_event_count") == 5
        and prepare_capture.get("phase_liveness_last_phase")
        == formal_launcher.PHASE_CANONICAL_SERIALIZATION
        and prepare_capture.get("phase_liveness_trace_sha256")
        == V9_PREPARE_PHASE_TRACE_SHA256
        and prepare_capture.get("raw_output_retained") is False
        and prepare_capture.get("timed_out") is False
        and prepare_result.get("schema")
        == "myuna.p08-prepare-capture-result.v2"
        and prepare_result.get("status") == "ready"
        and prepare_result.get("prepare_identity") == V9_PREPARE_IDENTITY
        and prepare_result.get("capture_identity_sha256")
        == V9_PREPARE_CAPTURE_IDENTITY
        and prepare_result.get("plan_digest") == V9_PLAN_DIGEST
        and prepare_result.get("plan_sha256") == V9_PLAN_SHA256
        and prepare_result.get("persistent_product_mutation") is False
        and plan.get("schema")
        == "myuna.p08-current-selected-formal-timeout-repair-plan.v9"
        and plan.get("plan_digest") == V9_PLAN_DIGEST,
        "v9_closed_sequence_rejected",
    )
    for call_index, capture in enumerate(formal_captures, start=1):
        require(
            capture.get("schema") == "myuna.p08-formal-preflight-capture.v3"
            and capture.get("status") == "ready"
            and capture.get("sequence_identity") == V9_FORMAL_SEQUENCE_IDENTITY
            and capture.get("call_index") == call_index
            and capture.get("call_nonce") == V9_FORMAL_CALL_NONCES[call_index - 1]
            and capture.get("invocation_identity_sha256")
            == V9_FORMAL_INVOCATION_IDENTITY
            and capture.get("parsed_result_identity_sha256")
            == V9_FORMAL_RESULT_IDENTITY
            and capture.get("stdout_sha256") == V9_FORMAL_STDOUT_SHA256
            and capture.get("stdout_size") == 29_253
            and capture.get("stderr_size") == 0
            and capture.get("phase_liveness_event_count") == 6
            and capture.get("phase_liveness_last_phase")
            == formal_launcher.PHASE_CANONICAL_SERIALIZATION
            and capture.get("phase_liveness_trace_sha256")
            == V9_FORMAL_PHASE_TRACE_SHA256
            and capture.get("canonical_result") is True
            and capture.get("process_created") is True
            and capture.get("exit_code") == 0
            and capture.get("timed_out") is False
            and capture.get("termination_escalated") is False
            and capture.get("drain_completed") is True
            and capture.get("raw_output_retained") is False,
            "v9_closed_sequence_rejected",
        )
    require(
        formal_result.get("schema")
        == "myuna.p08-formal-preflight-sequence-result.v3"
        and formal_result.get("status") == "ready"
        and formal_result.get("calls") == 2
        and formal_result.get("sequence_identity") == V9_FORMAL_SEQUENCE_IDENTITY
        and formal_result.get("invocation_identity_sha256")
        == V9_FORMAL_INVOCATION_IDENTITY
        and formal_result.get("result_identity_sha256")
        == V9_FORMAL_RESULT_IDENTITY
        and formal_result.get("stdout_sha256") == V9_FORMAL_STDOUT_SHA256
        and formal_result.get("persistent_product_mutation") is False,
        "v9_closed_sequence_rejected",
    )
    return {
        "contract_digest": v9_closed_sequence_contract()["contract_digest"],
        "drift_calls_consumed": 1,
        "drift_status": "preentry_import_failure_closed",
        "evidence_root": str(V9_EVIDENCE_ROOT),
        "formal_calls_consumed": 2,
        "metadata_verified": True,
        "prepare_status": "ready",
        "reopen_authority": False,
        "restore_authority": False,
        "sequence_status": "closed_drift_preentry_failure",
    }


def validate_v11_closed_sequence(root: Path) -> dict[str, object]:
    selected = _v11_closed_sequence_path(root)
    prepare = selected / "prepare-captures" / V11_PREPARE_IDENTITY
    formal = selected / "formal-sequences" / V11_FORMAL_SEQUENCE_IDENTITY
    try:
        directories = (
            selected.lstat(),
            prepare.parent.lstat(),
            prepare.lstat(),
            formal.parent.lstat(),
            formal.lstat(),
        )
        root_names = sorted(entry.name for entry in os.scandir(selected))
        prepare_names = sorted(entry.name for entry in os.scandir(prepare))
        formal_names = sorted(entry.name for entry in os.scandir(formal))
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("v11_closed_sequence_rejected") from exc
    require(
        root_names == ["formal-sequences", "prepare-captures"]
        and prepare_names == sorted(V11_PREPARE_FILES)
        and formal_names == sorted(V11_FORMAL_FILES),
        "v11_closed_sequence_rejected",
    )
    for metadata in directories:
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "v11_closed_sequence_rejected",
        )
    for directory, expected in (
        (prepare, V11_PREPARE_FILES),
        (formal, V11_FORMAL_FILES),
    ):
        for name, expected_sha256 in expected.items():
            path = directory / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CurrentSelectedUpgradeRejected(
                    "v11_closed_sequence_rejected"
                ) from exc
            require(
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and metadata.st_nlink == 1
                and _digest_regular(
                    path,
                    code="v11_closed_sequence_rejected",
                    max_bytes=upgrade.MAX_JSON_BYTES,
                )
                == expected_sha256,
                "v11_closed_sequence_rejected",
            )
    prepare_capture = _load_json(
        prepare / "CAPTURE.json", code="v11_closed_sequence_rejected"
    )
    prepare_result = _load_json(
        prepare / "RESULT.json", code="v11_closed_sequence_rejected"
    )
    plan = _load_json(
        prepare / "PLAN.INPUT.json", code="v11_closed_sequence_rejected"
    )
    formal_capture = _load_json(
        formal / "CALL-1.CAPTURE.json", code="v11_closed_sequence_rejected"
    )
    require(
        prepare_capture.get("schema") == "myuna.p08-prepare-capture.v2"
        and prepare_capture.get("status") == "ready"
        and prepare_capture.get("prepare_identity") == V11_PREPARE_IDENTITY
        and prepare_capture.get("raw_output_retained") is False
        and prepare_capture.get("timed_out") is False
        and prepare_capture.get("stderr_size") == 0
        and prepare_result.get("schema")
        == "myuna.p08-prepare-capture-result.v2"
        and prepare_result.get("status") == "ready"
        and prepare_result.get("prepare_identity") == V11_PREPARE_IDENTITY
        and prepare_result.get("capture_identity_sha256")
        == V11_PREPARE_CAPTURE_IDENTITY
        and prepare_result.get("plan_digest") == V11_PLAN_DIGEST
        and prepare_result.get("plan_sha256") == V11_PLAN_SHA256
        and prepare_result.get("persistent_product_mutation") is False
        and plan.get("schema")
        == "myuna.p08-current-selected-forward-continuity-repair-plan.v11"
        and plan.get("plan_digest") == V11_PLAN_DIGEST
        and formal_capture.get("schema")
        == "myuna.p08-formal-preflight-capture.v3"
        and formal_capture.get("sequence_identity")
        == V11_FORMAL_SEQUENCE_IDENTITY
        and formal_capture.get("call_index") == 1
        and formal_capture.get("call_nonce") == V11_FORMAL_CALL_NONCE
        and formal_capture.get("invocation_identity_sha256")
        == V11_FORMAL_INVOCATION_IDENTITY
        and formal_capture.get("status") == "indeterminate"
        and formal_capture.get("canonical_result") is False
        and formal_capture.get("parsed_result_identity_sha256") is None
        and formal_capture.get("process_created") is True
        and formal_capture.get("exit_code") == 0
        and formal_capture.get("timed_out") is False
        and formal_capture.get("termination_escalated") is False
        and formal_capture.get("drain_completed") is True
        and formal_capture.get("stdout_size") == 39_400
        and formal_capture.get("stdout_sha256") == V11_FORMAL_STDOUT_SHA256
        and formal_capture.get("stderr_size") == 0
        and formal_capture.get("stderr_sha256") == EMPTY_SHA256
        and formal_capture.get("phase_liveness_event_count") == 6
        and formal_capture.get("phase_liveness_last_phase")
        == formal_launcher.PHASE_CANONICAL_SERIALIZATION
        and formal_capture.get("phase_liveness_trace_sha256")
        == V11_FORMAL_PHASE_TRACE_SHA256
        and formal_capture.get("phase_liveness_error") is None
        and formal_capture.get("raw_output_retained") is False,
        "v11_closed_sequence_rejected",
    )
    return {
        "contract_digest": v11_closed_sequence_contract()["contract_digest"],
        "evidence_root": str(V11_EVIDENCE_ROOT),
        "formal_calls_consumed": 1,
        "metadata_verified": True,
        "prepare_status": "ready",
        "reopen_authority": False,
        "restore_authority": False,
        "sequence_status": "closed_indeterminate",
    }


def validate_v12_rejected_prepare(root: Path) -> dict[str, object]:
    selected = _v12_rejected_prepare_path(root)
    prepare_root = selected / "prepare-captures"
    prepare = prepare_root / V12_PREPARE_IDENTITY
    try:
        directories = (selected.lstat(), prepare_root.lstat(), prepare.lstat())
        root_names = sorted(entry.name for entry in os.scandir(selected))
        prepare_root_names = sorted(entry.name for entry in os.scandir(prepare_root))
        prepare_names = sorted(entry.name for entry in os.scandir(prepare))
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("v12_rejected_prepare_rejected") from exc
    require(
        root_names == ["prepare-captures"]
        and prepare_root_names == [V12_PREPARE_IDENTITY]
        and prepare_names == sorted(V12_PREPARE_FILES),
        "v12_rejected_prepare_rejected",
    )
    for metadata in directories:
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "v12_rejected_prepare_rejected",
        )
    for name, expected_sha256 in V12_PREPARE_FILES.items():
        path = prepare / name
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CurrentSelectedUpgradeRejected(
                "v12_rejected_prepare_rejected"
            ) from exc
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == 0
            and metadata.st_gid == 0
            and metadata.st_nlink == 1
            and _digest_regular(
                path,
                code="v12_rejected_prepare_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == expected_sha256,
            "v12_rejected_prepare_rejected",
        )
    capture = _load_json(
        prepare / "CAPTURE.json", code="v12_rejected_prepare_rejected"
    )
    require(
        capture.get("schema") == "myuna.p08-prepare-capture.v2"
        and capture.get("prepare_identity") == V12_PREPARE_IDENTITY
        and capture.get("invocation_identity_sha256")
        == V12_PREPARE_INVOCATION_IDENTITY
        and capture.get("parsed_result_identity_sha256")
        == V12_PREPARE_RESULT_IDENTITY
        and capture.get("target_release_digest") == V12_TARGET_RELEASE_DIGEST
        and capture.get("status") == "rejected"
        and capture.get("canonical_result") is True
        and capture.get("result_detail")
        == "typed_rejection:v11_closed_sequence_rejected"
        and capture.get("process_created") is True
        and capture.get("exit_code") == 2
        and capture.get("timed_out") is False
        and capture.get("termination_escalated") is False
        and capture.get("drain_completed") is True
        and capture.get("stderr_size") == 0
        and capture.get("stderr_sha256") == EMPTY_SHA256
        and capture.get("raw_output_retained") is False,
        "v12_rejected_prepare_rejected",
    )
    return {
        "contract_digest": v12_rejected_prepare_contract()["contract_digest"],
        "evidence_root": str(V12_EVIDENCE_ROOT),
        "formal_calls_consumed": 0,
        "metadata_verified": True,
        "prepare_identity": V12_PREPARE_IDENTITY,
        "prepare_status": "rejected",
        "reopen_authority": False,
        "restore_authority": False,
        "sequence_status": "closed_prepare_rejected",
    }


def _origin_evidence_path(root: Path) -> Path:
    return _rooted(root, ORIGIN_EVIDENCE_ROOT)


def _validate_origin_context(root: Path) -> dict[str, object]:
    evidence = _origin_evidence_path(root)
    expected = {
        "PLAN.json": ORIGIN_PLAN_SHA256,
        "JOURNAL.json": ORIGIN_JOURNAL_SHA256,
        "RECEIPT.json": ORIGIN_RECEIPT_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="origin_evidence_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "origin_evidence_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="origin_plan_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="origin_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="origin_receipt_rejected")
    identity = plan.get("identity")
    predecessor = plan.get("predecessor")
    active_gateway = plan.get("active_gateway_runtime")
    require(
        plan.get("schema") == upgrade.PLAN_SCHEMA
        and plan.get("plan_digest") == ORIGIN_PLAN_DIGEST
        and isinstance(identity, dict)
        and isinstance(predecessor, dict)
        and isinstance(active_gateway, dict)
        and journal.get("stage") == "target_verified"
        and receipt.get("status") == "target_verified"
        and receipt.get("state_bytes_preserved") is True,
        "origin_evidence_rejected",
    )
    for key in ("service_uid", "service_gid", "telegram_uid"):
        require(type(identity.get(key)) is int and int(identity[key]) >= 0, "origin_identity_rejected")
    require(
        predecessor.get("release_digest") == upgrade.PREDECESSOR_RELEASE_DIGEST
        and predecessor.get("release_path")
        == str(upgrade.RELEASE_ROOT / upgrade.PREDECESSOR_RELEASE_DIGEST),
        "origin_predecessor_rejected",
    )
    return {
        "active_gateway_runtime": active_gateway,
        "identity": identity,
        "predecessor": predecessor,
    }


def validate_accepted_lineage(root: Path) -> dict[str, object]:
    evidence = _accepted_evidence_path(root)
    expected = {
        "JOURNAL.json": ACCEPTED_JOURNAL_SHA256,
        "LEDGER.json": ACCEPTED_LEDGER_SHA256,
        "PLAN.json": ACCEPTED_PLAN_SHA256,
        "RECEIPT.json": ACCEPTED_RECEIPT_SHA256,
        "STATE_BINDING.json": ACCEPTED_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": ACCEPTED_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": ACCEPTED_STATE_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="accepted_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "accepted_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="accepted_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="accepted_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="accepted_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="accepted_receipt_rejected")
    binding = _load_json(evidence / "STATE_BINDING.json", code="accepted_state_binding_rejected")
    incident = plan.get("incident")
    repair_target = plan.get("repair_target")
    require(
        plan.get("schema") == post.REPAIR_PLAN_SCHEMA
        and plan.get("plan_digest") == PREDECESSOR_PLAN_DIGEST
        and plan.get("action") == "repair"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == ACCEPTED_INCIDENT_DIGEST
        and isinstance(repair_target, dict)
        and repair_target.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and repair_target.get("release_manifest_sha256") == PREDECESSOR_MANIFEST_SHA256
        and ledger.get("schema") == post.REPAIR_LEDGER_SCHEMA
        and ledger.get("action") == "repair"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and journal.get("schema") == post.REPAIR_JOURNAL_SCHEMA
        and journal.get("stage") == "target_accepted"
        and receipt.get("schema") == post.REPAIR_RECEIPT_SCHEMA
        and receipt.get("status") == "repair_target_accepted"
        and receipt.get("state_bytes_preserved") is True
        and binding.get("schema") == post.ACTION_STATE_BINDING_SCHEMA
        and binding.get("plan_digest") == PREDECESSOR_PLAN_DIGEST
        and binding.get("state_descriptor_sha256") == ACCEPTED_STATE_MANIFEST_SHA256,
        "accepted_lineage_rejected",
    )
    return {
        "accepted_incident_digest": ACCEPTED_INCIDENT_DIGEST,
        "journal_sha256": ACCEPTED_JOURNAL_SHA256,
        "ledger_sha256": ACCEPTED_LEDGER_SHA256,
        "plan_digest": PREDECESSOR_PLAN_DIGEST,
        "plan_sha256": ACCEPTED_PLAN_SHA256,
        "public_manifest_sha256": ACCEPTED_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": ACCEPTED_RECEIPT_SHA256,
        "state_binding_sha256": ACCEPTED_STATE_BINDING_SHA256,
        "state_manifest_sha256": ACCEPTED_STATE_MANIFEST_SHA256,
        "status": "target_accepted",
    }


def validate_failed_lineage(root: Path) -> dict[str, object]:
    evidence = _failed_evidence_path(root)
    expected = {
        "JOURNAL.json": FAILED_JOURNAL_SHA256,
        "LEDGER.json": FAILED_LEDGER_SHA256,
        "PLAN.json": FAILED_PLAN_SHA256,
        "current-public/PUBLIC.json": FAILED_PUBLIC_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="failed_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "failed_lineage_identity_rejected",
    )
    require(
        not (evidence / "RECEIPT.json").exists()
        and not (evidence / "current-state").exists(),
        "failed_lineage_restore_authority_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="failed_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="failed_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="failed_journal_rejected")
    manifest = _load_json(
        evidence / "current-public/PUBLIC.json",
        code="failed_public_manifest_rejected",
    )
    incident = plan.get("incident")
    strategy = plan.get("strategy")
    current = plan.get("current_target")
    target = plan.get("target")
    require(
        plan.get("schema") == FAILED_PLAN_SCHEMA
        and plan.get("plan_digest") == FAILED_PLAN_DIGEST
        and plan.get("action") == "upgrade"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == FAILED_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == FAILED_STRATEGY_DIGEST
        and strategy.get("controller_sha256") == FAILED_CONTROLLER_SHA256
        and isinstance(current, dict)
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == FAILED_TARGET_RELEASE_DIGEST
        and ledger.get("schema") == FAILED_LEDGER_SCHEMA
        and ledger.get("action") == "upgrade"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and ledger.get("incident_digest") == FAILED_INCIDENT_DIGEST
        and ledger.get("plan_digest") == FAILED_PLAN_DIGEST
        and journal.get("schema") == FAILED_JOURNAL_SCHEMA
        and journal.get("stage") == "prepared"
        and journal.get("events") == ["prepared"]
        and journal.get("plan_digest") == FAILED_PLAN_DIGEST,
        "failed_lineage_rejected",
    )
    public = current.get("public") if isinstance(current, dict) else None
    require(
        isinstance(public, dict)
        and set(public)
        == {
            str(upgrade.SELECTOR_JSON),
            str(upgrade.SELECTOR_ENV),
            str(upgrade.UNIT_ROOT / upgrade.SERVICE),
            str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        },
        "failed_public_manifest_rejected",
    )
    expected_manifest = {
        text: {
            **projection,
            "backup_name": digest_bytes(text.encode("ascii")),
        }
        for text, projection in sorted(public.items())
        if isinstance(projection, dict)
    }
    require(
        len(expected_manifest) == len(public) and manifest == expected_manifest,
        "failed_public_manifest_rejected",
    )
    backup = evidence / "current-public"
    root_metadata = backup.lstat()
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
        and root_metadata.st_uid == os.geteuid()
        and root_metadata.st_gid == os.getegid(),
        "failed_public_backup_rejected",
    )
    manifest_metadata = (backup / "PUBLIC.json").lstat()
    require(
        stat.S_ISREG(manifest_metadata.st_mode)
        and not stat.S_ISLNK(manifest_metadata.st_mode)
        and manifest_metadata.st_nlink == 1
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o600
        and manifest_metadata.st_uid == os.geteuid()
        and manifest_metadata.st_gid == os.getegid()
        and manifest_metadata.st_size == len(canonical(manifest)),
        "failed_public_manifest_rejected",
    )
    expected_files = {"PUBLIC.json"}
    mode_mismatches: list[str] = []
    for text, projection in sorted(public.items()):
        assert isinstance(projection, dict)
        name = digest_bytes(text.encode("ascii"))
        expected_files.add(name)
        path = backup / name
        metadata = path.lstat()
        expected_mode = int(projection["mode"])
        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != expected_mode:
            mode_mismatches.append(text)
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == projection["uid"]
            and metadata.st_gid == projection["gid"]
            and metadata.st_size == projection["size"]
            and _digest_regular(
                path,
                code="failed_public_backup_rejected",
                max_bytes=upgrade.MAX_SOURCE_BYTES,
            )
            == projection["sha256"]
            and actual_mode
            == (0o600 if expected_mode == 0o644 else expected_mode),
            "failed_public_backup_rejected",
        )
    observed: set[str] = set()
    for path in backup.rglob("*"):
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "failed_public_backup_rejected",
        )
        observed.add(path.relative_to(backup).as_posix())
    require(
        observed == expected_files
        and mode_mismatches
        == [
            str(upgrade.UNIT_ROOT / upgrade.SERVICE),
            str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        ],
        "failed_public_backup_rejected",
    )
    return {
        "incident_digest": FAILED_INCIDENT_DIGEST,
        "journal_sha256": FAILED_JOURNAL_SHA256,
        "ledger_sha256": FAILED_LEDGER_SHA256,
        "plan_digest": FAILED_PLAN_DIGEST,
        "plan_sha256": FAILED_PLAN_SHA256,
        "public_manifest_sha256": FAILED_PUBLIC_MANIFEST_SHA256,
        "restore_authority": False,
        "status": "prestop_public_backup_mode_rejected",
    }


def terminal_evidence_identity_contract() -> dict[str, str]:
    return {
        "JOURNAL.json": TERMINAL_JOURNAL_SHA256,
        "LEDGER.json": TERMINAL_LEDGER_SHA256,
        "PLAN.json": TERMINAL_PLAN_SHA256,
        "RECEIPT.json": TERMINAL_RECEIPT_SHA256,
        "STATE_BINDING.json": TERMINAL_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": TERMINAL_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": TERMINAL_STATE_MANIFEST_SHA256,
    }


def validate_terminal_evidence_identities(
    observed: Mapping[str, object],
) -> dict[str, str]:
    expected = terminal_evidence_identity_contract()
    require(
        observed == expected
        and all(
            isinstance(value, str) and upgrade.HEX64.fullmatch(value) is not None
            for value in observed.values()
        ),
        "terminal_lineage_identity_rejected",
    )
    return expected


def validate_terminal_lineage(root: Path) -> dict[str, object]:
    evidence = _terminal_evidence_path(root)
    expected = terminal_evidence_identity_contract()
    observed = {
        name: _digest_regular(
            evidence / name,
            code="terminal_lineage_identity_rejected",
            max_bytes=upgrade.MAX_JSON_BYTES,
        )
        for name in expected
    }
    require(
        validate_terminal_evidence_identities(observed) == expected,
        "terminal_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="terminal_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="terminal_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="terminal_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="terminal_receipt_rejected")
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="terminal_state_binding_rejected"
    )
    incident = plan.get("incident")
    strategy = plan.get("strategy")
    current = plan.get("current_target")
    target = plan.get("target")
    expected_events = [
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
        "release_installed",
        "public_applied",
        "target_started",
        "protocol_acceptance_called",
        "convergence_owned",
        "predecessor_restored",
    ]
    require(
        plan.get("schema") == TERMINAL_PLAN_SCHEMA
        and plan.get("plan_digest") == TERMINAL_PLAN_DIGEST
        and plan.get("action") == "upgrade"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == TERMINAL_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == TERMINAL_STRATEGY_DIGEST
        and strategy.get("controller_sha256") == TERMINAL_CONTROLLER_SHA256
        and isinstance(current, dict)
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == TERMINAL_TARGET_RELEASE_DIGEST
        and ledger.get("schema") == TERMINAL_LEDGER_SCHEMA
        and ledger.get("action") == "upgrade"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and ledger.get("incident_digest") == TERMINAL_INCIDENT_DIGEST
        and ledger.get("plan_digest") == TERMINAL_PLAN_DIGEST
        and journal.get("schema") == TERMINAL_JOURNAL_SCHEMA
        and journal.get("stage") == "predecessor_restored"
        and journal.get("events") == expected_events
        and journal.get("plan_digest") == TERMINAL_PLAN_DIGEST
        and receipt.get("schema") == TERMINAL_RECEIPT_SCHEMA
        and receipt.get("status") == "action_failed_predecessor_restored"
        and receipt.get("action_failure_code") == "protocol_acceptance_failed"
        and receipt.get("convergence_failure_code") is None
        and receipt.get("incident_digest") == TERMINAL_INCIDENT_DIGEST
        and receipt.get("plan_digest") == TERMINAL_PLAN_DIGEST
        and receipt.get("predecessor_release_digest") == PREDECESSOR_RELEASE_DIGEST
        and receipt.get("target_release_digest") == TERMINAL_TARGET_RELEASE_DIGEST
        and receipt.get("state_bytes_preserved") is True
        and receipt.get("private_content_parsed") is False
        and receipt.get("channel_called") is False
        and receipt.get("model_called") is False
        and receipt.get("other_program_mutated") is False
        and binding.get("schema") == TERMINAL_STATE_BINDING_SCHEMA
        and binding.get("plan_digest") == TERMINAL_PLAN_DIGEST
        and binding.get("state_descriptor_sha256")
        == TERMINAL_STATE_MANIFEST_SHA256,
        "terminal_lineage_rejected",
    )
    return {
        "incident_digest": TERMINAL_INCIDENT_DIGEST,
        "journal_sha256": TERMINAL_JOURNAL_SHA256,
        "ledger_sha256": TERMINAL_LEDGER_SHA256,
        "plan_digest": TERMINAL_PLAN_DIGEST,
        "plan_sha256": TERMINAL_PLAN_SHA256,
        "public_manifest_sha256": TERMINAL_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": TERMINAL_RECEIPT_SHA256,
        "restore_authority": False,
        "state_binding_sha256": TERMINAL_STATE_BINDING_SHA256,
        "state_manifest_sha256": TERMINAL_STATE_MANIFEST_SHA256,
        "status": "protocol_acceptance_failed_predecessor_restored",
    }


def validate_v2_terminal_lineage(root: Path) -> dict[str, object]:
    """Bind the latest consumed v2 failure without granting restore authority."""

    evidence = _v2_terminal_evidence_path(root)
    expected = {
        "JOURNAL.json": V2_TERMINAL_JOURNAL_SHA256,
        "LEDGER.json": V2_TERMINAL_LEDGER_SHA256,
        "PLAN.json": V2_TERMINAL_PLAN_SHA256,
        "RECEIPT.json": V2_TERMINAL_RECEIPT_SHA256,
        "STATE_BINDING.json": V2_TERMINAL_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": V2_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": V2_TERMINAL_STATE_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="v2_terminal_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "v2_terminal_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="v2_terminal_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="v2_terminal_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="v2_terminal_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="v2_terminal_receipt_rejected")
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="v2_terminal_state_binding_rejected"
    )
    incident = plan.get("incident")
    strategy = plan.get("strategy")
    current = plan.get("current_target")
    target = plan.get("target")
    expected_events = [
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
        "release_installed",
        "public_applied",
        "target_started",
        "protocol_acceptance_called",
        "convergence_owned",
        "predecessor_restored",
    ]
    require(
        plan.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-plan.v2"
        and plan.get("plan_digest") == V2_TERMINAL_PLAN_DIGEST
        and plan.get("action") == "upgrade"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == V2_TERMINAL_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == V2_TERMINAL_STRATEGY_DIGEST
        and strategy.get("controller_sha256") == V2_TERMINAL_CONTROLLER_SHA256
        and isinstance(current, dict)
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == V2_TERMINAL_TARGET_RELEASE_DIGEST
        and ledger.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-ledger.v2"
        and ledger.get("action") == "upgrade"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and ledger.get("incident_digest") == V2_TERMINAL_INCIDENT_DIGEST
        and ledger.get("plan_digest") == V2_TERMINAL_PLAN_DIGEST
        and journal.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-journal.v2"
        and journal.get("stage") == "predecessor_restored"
        and journal.get("events") == expected_events
        and journal.get("plan_digest") == V2_TERMINAL_PLAN_DIGEST
        and receipt.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-receipt.v2"
        and receipt.get("status") == "action_failed_predecessor_restored"
        and receipt.get("action_failure_code") == "protocol_acceptance_failed"
        and receipt.get("convergence_failure_code") is None
        and receipt.get("incident_digest") == V2_TERMINAL_INCIDENT_DIGEST
        and receipt.get("plan_digest") == V2_TERMINAL_PLAN_DIGEST
        and receipt.get("predecessor_release_digest") == PREDECESSOR_RELEASE_DIGEST
        and receipt.get("target_release_digest") == V2_TERMINAL_TARGET_RELEASE_DIGEST
        and receipt.get("state_bytes_preserved") is True
        and receipt.get("private_content_parsed") is False
        and receipt.get("channel_called") is False
        and receipt.get("model_called") is False
        and receipt.get("other_program_mutated") is False
        and binding.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-state-binding.v2"
        and binding.get("plan_digest") == V2_TERMINAL_PLAN_DIGEST
        and binding.get("state_descriptor_sha256")
        == V2_TERMINAL_STATE_MANIFEST_SHA256,
        "v2_terminal_lineage_rejected",
    )
    return {
        "incident_digest": V2_TERMINAL_INCIDENT_DIGEST,
        "journal_sha256": V2_TERMINAL_JOURNAL_SHA256,
        "ledger_sha256": V2_TERMINAL_LEDGER_SHA256,
        "plan_digest": V2_TERMINAL_PLAN_DIGEST,
        "plan_sha256": V2_TERMINAL_PLAN_SHA256,
        "public_manifest_sha256": V2_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": V2_TERMINAL_RECEIPT_SHA256,
        "restore_authority": False,
        "state_binding_sha256": V2_TERMINAL_STATE_BINDING_SHA256,
        "state_manifest_sha256": V2_TERMINAL_STATE_MANIFEST_SHA256,
        "status": "protocol_acceptance_failed_predecessor_restored",
    }


def validate_v4_terminal_lineage(root: Path) -> dict[str, object]:
    """Bind the consumed v4 runtime rejection without restore authority."""

    evidence = _v4_terminal_evidence_path(root)
    expected = {
        "JOURNAL.json": V4_TERMINAL_JOURNAL_SHA256,
        "LEDGER.json": V4_TERMINAL_LEDGER_SHA256,
        "PLAN.json": V4_TERMINAL_PLAN_SHA256,
        "RECEIPT.json": V4_TERMINAL_RECEIPT_SHA256,
        "STATE_BINDING.json": V4_TERMINAL_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": V4_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": V4_TERMINAL_STATE_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="v4_terminal_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "v4_terminal_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="v4_terminal_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="v4_terminal_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="v4_terminal_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="v4_terminal_receipt_rejected")
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="v4_terminal_state_binding_rejected"
    )
    incident = plan.get("incident")
    strategy = plan.get("strategy")
    current = plan.get("current_target")
    target = plan.get("target")
    expected_events = [
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
        "release_installed",
        "public_applied",
        "target_started",
        "protocol_acceptance_called",
        "convergence_owned",
        "predecessor_restored",
    ]
    require(
        plan.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-plan.v4"
        and plan.get("plan_digest") == V4_TERMINAL_PLAN_DIGEST
        and plan.get("action") == "upgrade"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == V4_TERMINAL_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == V4_TERMINAL_STRATEGY_DIGEST
        and strategy.get("controller_sha256") == V4_TERMINAL_CONTROLLER_SHA256
        and isinstance(current, dict)
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == V4_TERMINAL_TARGET_RELEASE_DIGEST
        and ledger.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-ledger.v4"
        and ledger.get("action") == "upgrade"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and ledger.get("incident_digest") == V4_TERMINAL_INCIDENT_DIGEST
        and ledger.get("plan_digest") == V4_TERMINAL_PLAN_DIGEST
        and journal.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-journal.v4"
        and journal.get("stage") == "predecessor_restored"
        and journal.get("events") == expected_events
        and journal.get("plan_digest") == V4_TERMINAL_PLAN_DIGEST
        and receipt.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-receipt.v4"
        and receipt.get("status") == "action_failed_predecessor_restored"
        and receipt.get("action_failure_code") == "protocol_acceptance_failed"
        and receipt.get("convergence_failure_code") is None
        and receipt.get("incident_digest") == V4_TERMINAL_INCIDENT_DIGEST
        and receipt.get("plan_digest") == V4_TERMINAL_PLAN_DIGEST
        and receipt.get("predecessor_release_digest") == PREDECESSOR_RELEASE_DIGEST
        and receipt.get("target_release_digest") == V4_TERMINAL_TARGET_RELEASE_DIGEST
        and receipt.get("state_bytes_preserved") is True
        and receipt.get("private_content_parsed") is False
        and receipt.get("channel_called") is False
        and receipt.get("model_called") is False
        and receipt.get("other_program_mutated") is False
        and binding.get("schema")
        == "myuna.p08-current-selected-protocol-acceptance-repair-state-binding.v4"
        and binding.get("plan_digest") == V4_TERMINAL_PLAN_DIGEST
        and binding.get("state_descriptor_sha256")
        == V4_TERMINAL_STATE_MANIFEST_SHA256,
        "v4_terminal_lineage_rejected",
    )
    return {
        "handoff_sha256": V4_TERMINAL_HANDOFF_SHA256,
        "incident_digest": V4_TERMINAL_INCIDENT_DIGEST,
        "journal_sha256": V4_TERMINAL_JOURNAL_SHA256,
        "ledger_sha256": V4_TERMINAL_LEDGER_SHA256,
        "plan_digest": V4_TERMINAL_PLAN_DIGEST,
        "plan_sha256": V4_TERMINAL_PLAN_SHA256,
        "public_manifest_sha256": V4_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": V4_TERMINAL_RECEIPT_SHA256,
        "restore_authority": False,
        "state_binding_sha256": V4_TERMINAL_STATE_BINDING_SHA256,
        "state_manifest_sha256": V4_TERMINAL_STATE_MANIFEST_SHA256,
        "status": "server_status_runtime_rejected_predecessor_restored",
    }


def validate_v5_terminal_lineage(root: Path) -> dict[str, object]:
    """Bind the consumed v5 trusted-time rejection without restore authority."""

    evidence = _v5_terminal_evidence_path(root)
    expected = {
        "JOURNAL.json": V5_TERMINAL_JOURNAL_SHA256,
        "LEDGER.json": V5_TERMINAL_LEDGER_SHA256,
        "PLAN.json": V5_TERMINAL_PLAN_SHA256,
        "RECEIPT.json": V5_TERMINAL_RECEIPT_SHA256,
        "STATE_BINDING.json": V5_TERMINAL_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": V5_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": V5_TERMINAL_STATE_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="v5_terminal_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "v5_terminal_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="v5_terminal_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="v5_terminal_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="v5_terminal_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="v5_terminal_receipt_rejected")
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="v5_terminal_state_binding_rejected"
    )
    incident = plan.get("incident")
    strategy = plan.get("strategy")
    current = plan.get("current_target")
    target = plan.get("target")
    expected_events = [
        "prepared",
        "current_public_backed_up",
        "current_state_backed_up",
        "attempt_owned",
        "services_stopped",
        "release_installed",
        "public_applied",
        "target_started",
        "protocol_acceptance_called",
        "convergence_owned",
        "predecessor_restored",
    ]
    require(
        plan.get("schema")
        == "myuna.p08-current-selected-status-runtime-repair-plan.v5"
        and plan.get("plan_digest") == V5_TERMINAL_PLAN_DIGEST
        and plan.get("action") == "upgrade"
        and plan.get("single_bounded_action") is True
        and isinstance(incident, dict)
        and incident.get("incident_digest") == V5_TERMINAL_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == V5_TERMINAL_STRATEGY_DIGEST
        and strategy.get("controller_sha256") == V5_TERMINAL_CONTROLLER_SHA256
        and isinstance(current, dict)
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == V5_TERMINAL_TARGET_RELEASE_DIGEST
        and ledger.get("schema")
        == "myuna.p08-current-selected-status-runtime-repair-ledger.v5"
        and ledger.get("action") == "upgrade"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and ledger.get("incident_digest") == V5_TERMINAL_INCIDENT_DIGEST
        and ledger.get("plan_digest") == V5_TERMINAL_PLAN_DIGEST
        and journal.get("schema")
        == "myuna.p08-current-selected-status-runtime-repair-journal.v5"
        and journal.get("stage") == "predecessor_restored"
        and journal.get("events") == expected_events
        and journal.get("plan_digest") == V5_TERMINAL_PLAN_DIGEST
        and receipt.get("schema")
        == "myuna.p08-current-selected-status-runtime-repair-receipt.v5"
        and receipt.get("status") == "action_failed_predecessor_restored"
        and receipt.get("action_failure_code") == "protocol_acceptance_failed"
        and receipt.get("convergence_failure_code") is None
        and receipt.get("incident_digest") == V5_TERMINAL_INCIDENT_DIGEST
        and receipt.get("plan_digest") == V5_TERMINAL_PLAN_DIGEST
        and receipt.get("predecessor_release_digest") == PREDECESSOR_RELEASE_DIGEST
        and receipt.get("target_release_digest") == V5_TERMINAL_TARGET_RELEASE_DIGEST
        and receipt.get("state_bytes_preserved") is True
        and receipt.get("private_content_parsed") is False
        and receipt.get("channel_called") is False
        and receipt.get("model_called") is False
        and receipt.get("other_program_mutated") is False
        and binding.get("schema")
        == "myuna.p08-current-selected-status-runtime-repair-state-binding.v5"
        and binding.get("plan_digest") == V5_TERMINAL_PLAN_DIGEST
        and binding.get("state_descriptor_sha256")
        == V5_TERMINAL_STATE_MANIFEST_SHA256,
        "v5_terminal_lineage_rejected",
    )
    return {
        "handoff_sha256": V5_TERMINAL_HANDOFF_SHA256,
        "incident_digest": V5_TERMINAL_INCIDENT_DIGEST,
        "journal_sha256": V5_TERMINAL_JOURNAL_SHA256,
        "ledger_sha256": V5_TERMINAL_LEDGER_SHA256,
        "plan_digest": V5_TERMINAL_PLAN_DIGEST,
        "plan_sha256": V5_TERMINAL_PLAN_SHA256,
        "public_manifest_sha256": V5_TERMINAL_PUBLIC_MANIFEST_SHA256,
        "receipt_sha256": V5_TERMINAL_RECEIPT_SHA256,
        "restore_authority": False,
        "state_binding_sha256": V5_TERMINAL_STATE_BINDING_SHA256,
        "state_manifest_sha256": V5_TERMINAL_STATE_MANIFEST_SHA256,
        "status": "trusted_time_rejected_predecessor_restored",
    }


def validate_v10_terminal_lineage(root: Path) -> dict[str, object]:
    evidence = _rooted(root, V10_EVIDENCE_ROOT) / "incidents" / V10_INCIDENT_DIGEST
    expected = {
        "JOURNAL.json": V10_JOURNAL_SHA256,
        "LEDGER.json": V10_LEDGER_SHA256,
        "PLAN.json": V10_PLAN_SHA256,
        "RECEIPT.json": V10_RECEIPT_SHA256,
        "STATE_BINDING.json": V10_STATE_BINDING_SHA256,
        "current-public/PUBLIC.json": V10_PUBLIC_MANIFEST_SHA256,
        "current-state/STATE.json": V10_STATE_MANIFEST_SHA256,
    }
    require(
        all(
            _digest_regular(
                evidence / name,
                code="v10_terminal_lineage_identity_rejected",
                max_bytes=upgrade.MAX_JSON_BYTES,
            )
            == value
            for name, value in expected.items()
        ),
        "v10_terminal_lineage_identity_rejected",
    )
    plan = _load_json(evidence / "PLAN.json", code="v10_terminal_plan_rejected")
    ledger = _load_json(evidence / "LEDGER.json", code="v10_terminal_ledger_rejected")
    journal = _load_json(evidence / "JOURNAL.json", code="v10_terminal_journal_rejected")
    receipt = _load_json(evidence / "RECEIPT.json", code="v10_terminal_receipt_rejected")
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="v10_terminal_state_binding_rejected"
    )
    incident = plan.get("incident")
    target = plan.get("target")
    strategy = plan.get("strategy")
    require(
        plan.get("schema")
        == "myuna.p08-current-selected-drift-launcher-repair-plan.v10"
        and plan.get("plan_digest") == V10_PLAN_DIGEST
        and isinstance(incident, dict)
        and incident.get("incident_digest") == V10_INCIDENT_DIGEST
        and isinstance(strategy, dict)
        and strategy.get("strategy_digest") == V10_STRATEGY_DIGEST
        and isinstance(target, dict)
        and target.get("release_digest") == V10_TARGET_RELEASE_DIGEST
        and target.get("release_manifest_sha256") == V10_TARGET_MANIFEST_SHA256
        and ledger.get("schema")
        == "myuna.p08-current-selected-drift-launcher-repair-ledger.v10"
        and ledger.get("attempts") == 1
        and ledger.get("consumed") is True
        and journal.get("schema")
        == "myuna.p08-current-selected-drift-launcher-repair-journal.v10"
        and journal.get("stage") == "predecessor_restored"
        and receipt.get("schema")
        == "myuna.p08-current-selected-drift-launcher-repair-receipt.v10"
        and receipt.get("status") == "action_failed_predecessor_restored"
        and receipt.get("action_failure_code") == "protocol_acceptance_failed"
        and receipt.get("state_bytes_preserved") is True
        and binding.get("schema")
        == "myuna.p08-current-selected-drift-launcher-repair-state-binding.v10"
        and binding.get("plan_digest") == V10_PLAN_DIGEST
        and binding.get("state_descriptor_sha256") == V10_STATE_MANIFEST_SHA256,
        "v10_terminal_lineage_rejected",
    )
    return v10_terminal_contract()


def validate_predecessor_release(
    root: Path, *, live_installed: bool = True
) -> dict[str, object]:
    manifest, release_digest = upgrade._validate_release_manifest(
        root, require_named_digest=True
    )
    rows = post._release_metadata_inventory(root)
    installed_digest = digest_bytes(
        canonical(post._installed_inventory_from_source(rows, live=live_installed))
    )
    require(
        release_digest == PREDECESSOR_RELEASE_DIGEST
        and upgrade.digest_file(root / "manifest.json") == PREDECESSOR_MANIFEST_SHA256
        and installed_digest == PREDECESSOR_INSTALLED_INVENTORY_SHA256
        and manifest.get("core_commit") == PREDECESSOR_CORE_COMMIT
        and manifest.get("deploy_commit") == PREDECESSOR_DEPLOY_COMMIT
        and isinstance(manifest.get("gateway_client"), dict)
        and manifest["gateway_client"].get("sha256") == PREDECESSOR_CLIENT_SHA256
        and upgrade.digest_file(root / upgrade.SERVICE_UNIT_PATH)
        == PREDECESSOR_SERVICE_UNIT_SHA256
        and upgrade.digest_file(root / upgrade.SOCKET_UNIT_PATH)
        == PREDECESSOR_SOCKET_UNIT_SHA256,
        "predecessor_release_rejected",
    )
    return manifest


def _expected_selector() -> dict[str, object]:
    return {
        "core_commit": PREDECESSOR_CORE_COMMIT,
        "deploy_commit": PREDECESSOR_DEPLOY_COMMIT,
        "gateway_client_sha256": upgrade.PREDECESSOR_CLIENT_SHA256,
        "gateway_manifest_digest": upgrade.ACTIVE_GATEWAY_MANIFEST_DIGEST,
        "plan_digest": PREDECESSOR_PLAN_DIGEST,
        "plugin_digest": upgrade.ACTIVE_PLUGIN_DIGEST,
        "release_digest": PREDECESSOR_RELEASE_DIGEST,
        "release_path": str(upgrade.RELEASE_ROOT / PREDECESSOR_RELEASE_DIGEST),
        "schema": upgrade.SELECTOR_SCHEMA,
    }


def capture_current_target(
    *,
    root: Path,
    origin: Mapping[str, object],
    unit_state: Mapping[str, object] | None,
) -> dict[str, object]:
    expected = {
        upgrade.SELECTOR_JSON: (PREDECESSOR_SELECTOR_SHA256, 0o600),
        upgrade.SELECTOR_ENV: (PREDECESSOR_SELECTOR_ENV_SHA256, 0o600),
        upgrade.UNIT_ROOT / upgrade.SERVICE: (PREDECESSOR_SERVICE_UNIT_SHA256, 0o644),
        upgrade.UNIT_ROOT / upgrade.SOCKET: (PREDECESSOR_SOCKET_UNIT_SHA256, 0o644),
    }
    public: dict[str, dict[str, object]] = {}
    for absolute, (expected_digest, expected_mode) in expected.items():
        projection = upgrade._file_projection(_rooted(root, absolute))
        require(
            projection.get("sha256") == expected_digest
            and projection.get("mode") == expected_mode
            and (root != Path("/") or (projection.get("uid") == 0 and projection.get("gid") == 0)),
            "current_public_rejected",
        )
        public[str(absolute)] = projection
    selector = _load_json(_rooted(root, upgrade.SELECTOR_JSON), code="current_selector_rejected")
    require(selector == _expected_selector(), "current_selector_rejected")
    validate_predecessor_release(
        _rooted(root, upgrade.RELEASE_ROOT / PREDECESSOR_RELEASE_DIGEST),
        live_installed=root == Path("/"),
    )
    if unit_state is None:
        require(root == Path("/"), "synthetic_unit_state_required")
        units = upgrade._validate_unit_state(upgrade._capture_unit_state())
    else:
        require(root != Path("/"), "synthetic_unit_state_rejected")
        units = upgrade._validate_unit_state(unit_state)
    identity = origin.get("identity")
    require(isinstance(identity, dict), "origin_identity_rejected")
    state = upgrade.describe_opaque_state_metadata(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    return {
        "public": public,
        "release_digest": PREDECESSOR_RELEASE_DIGEST,
        "release_manifest_sha256": PREDECESSOR_MANIFEST_SHA256,
        "state": state,
        "units": units,
    }


def validate_target_release(
    *, root: Path, compatibility_predecessor: Path
) -> tuple[dict[str, object], str, dict[str, object]]:
    manifest, release_digest = upgrade.validate_target_release(
        root=root,
        predecessor_release=compatibility_predecessor,
        expected_core_commit=continuity.CORE_COMMIT,
    )
    contract = release_contract(root)
    require(
        manifest.get("current_selected_upgrade_contract") == contract,
        "target_upgrade_contract_rejected",
    )
    require(
        manifest.get("p07_single_nonce_integration")
        == p07_single_nonce_integration_contract(),
        "target_p07_integration_contract_rejected",
    )
    require(
        manifest.get("forward_continuity_contract") == continuity.contract(),
        "target_forward_continuity_contract_rejected",
    )
    rows = post._release_metadata_inventory(root)
    launcher_binding = manifest.get("formal_preflight_launcher_contract")
    require(isinstance(launcher_binding, dict), "target_formal_launcher_rejected")
    launcher_contract = launcher_binding.get("launcher")
    source_binding = launcher_binding.get("source_binding")
    require(
        isinstance(launcher_contract, dict)
        and isinstance(source_binding, dict)
        and launcher_contract == contract["formal_launcher"],
        "target_formal_launcher_rejected",
    )
    identity = {
        "controller_sha256": contract["sha256"],
        "formal_launcher_contract_digest": launcher_contract["contract_digest"],
        "forward_continuity_contract_digest": continuity.contract()[
            "contract_digest"
        ],
        "installed_inventory_sha256": digest_bytes(
            canonical(post._installed_inventory_from_source(rows, live=True))
        ),
        "manifest_sha256": upgrade.digest_file(root / "manifest.json"),
        "server_rejection_contract_sha256": digest_bytes(
            canonical(manifest["service_contract"]["rejection_subprojection"])
        ),
        "server_status_runtime_contract_sha256": digest_bytes(
            canonical(
                manifest["service_contract"]["runtime_rejection_subprojection"]
            )
        ),
        "source_inventory_sha256": digest_bytes(canonical(rows)),
        "source_binding_digest": source_binding["binding_digest"],
        "status_stage_contract_sha256": digest_bytes(
            canonical(manifest["gateway_status_runtime"]["stage_projection"])
        ),
        "status_runtime_stage_contract_sha256": digest_bytes(
            canonical(
                manifest["gateway_status_runtime"]["status_runtime_subprojection"]
            )
        ),
        "trusted_time_capability_source_identity": manifest[
            "trusted_time_capability_contract"
        ]["source_identity"],
    }
    return manifest, release_digest, identity


def _incident(strategy: Mapping[str, object]) -> dict[str, object]:
    body = {
        "accepted_incident_digest": ACCEPTED_INCIDENT_DIGEST,
        "failed_incident_digest": FAILED_INCIDENT_DIGEST,
        "nonzero_stage_t0_handoff_sha256": NONZERO_STAGE_T0_HANDOFF_SHA256,
        "p07_integration_handoff_sha256": P07_INTEGRATION_HANDOFF_SHA256,
        "prestate_rejection_handoff_sha256": PRESTATE_REJECTION_HANDOFF_SHA256,
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "schema": INCIDENT_SCHEMA,
        "single_nonce_stage_t1_handoff_sha256": (
            SINGLE_NONCE_STAGE_T1_HANDOFF_SHA256
        ),
        "strategy_digest": strategy["strategy_digest"],
        "terminal_incident_digest": TERMINAL_INCIDENT_DIGEST,
        "v2_terminal_incident_digest": V2_TERMINAL_INCIDENT_DIGEST,
        "v4_terminal_incident_digest": V4_TERMINAL_INCIDENT_DIGEST,
        "v5_terminal_incident_digest": V5_TERMINAL_INCIDENT_DIGEST,
        "v6_capture_t0_handoff_sha256": V6_CAPTURE_T0_HANDOFF_SHA256,
        "v6_incident_digest": V6_INCIDENT_DIGEST,
        "v6_t2_terminal_handoff_sha256": V6_T2_TERMINAL_HANDOFF_SHA256,
        "v7_prepare_residue_contract_digest": v7_prepare_residue_contract()[
            "contract_digest"
        ],
        "v7_t2_terminal_handoff_sha256": V7_T2_TERMINAL_HANDOFF_SHA256,
        "v8_closed_sequence_contract_digest": v8_closed_sequence_contract()[
            "contract_digest"
        ],
        "v8_t0_handoff_sha256": V8_TIMEOUT_T0_HANDOFF_SHA256,
        "v8_t2_terminal_handoff_sha256": V8_T2_TERMINAL_HANDOFF_SHA256,
        "v9_closed_sequence_contract_digest": v9_closed_sequence_contract()[
            "contract_digest"
        ],
        "v9_t1_handoff_sha256": V9_T1_HANDOFF_SHA256,
        "v9_t2_terminal_handoff_sha256": V9_T2_TERMINAL_HANDOFF_SHA256,
        "v10_terminal_contract_digest": v10_terminal_contract()[
            "contract_digest"
        ],
        "v11_closed_sequence_contract_digest": v11_closed_sequence_contract()[
            "contract_digest"
        ],
        "v12_rejected_prepare_contract_digest": v12_rejected_prepare_contract()[
            "contract_digest"
        ],
    }
    return {**body, "incident_digest": digest_bytes(canonical(body))}


def _plan(body: Mapping[str, object]) -> dict[str, object]:
    raw = dict(body)
    return {
        **raw,
        "plan_digest": digest_bytes(canonical(raw)),
        "schema": PLAN_SCHEMA,
    }


IMMUTABLE_LINEAGE_VALIDATORS = (
    (
        "accepted_predecessor_lineage",
        validate_accepted_lineage,
        "accepted_lineage_drifted",
    ),
    (
        "failed_predecessor_lineage",
        validate_failed_lineage,
        "failed_lineage_drifted",
    ),
    (
        "terminal_predecessor_lineage",
        validate_terminal_lineage,
        "terminal_lineage_drifted",
    ),
    (
        "v2_terminal_predecessor_lineage",
        validate_v2_terminal_lineage,
        "v2_terminal_lineage_drifted",
    ),
    (
        "v4_terminal_predecessor_lineage",
        validate_v4_terminal_lineage,
        "v4_terminal_lineage_drifted",
    ),
    (
        "v5_terminal_predecessor_lineage",
        validate_v5_terminal_lineage,
        "v5_terminal_lineage_drifted",
    ),
    (
        "v7_prepare_residue_lineage",
        validate_v7_prepare_residue,
        "v7_prepare_residue_drifted",
    ),
    (
        "v8_closed_sequence_lineage",
        validate_v8_closed_sequence,
        "v8_closed_sequence_drifted",
    ),
    (
        "v9_closed_sequence_lineage",
        validate_v9_closed_sequence,
        "v9_closed_sequence_drifted",
    ),
    (
        "v10_terminal_lineage",
        validate_v10_terminal_lineage,
        "v10_terminal_lineage_drifted",
    ),
    (
        "v11_closed_sequence_lineage",
        validate_v11_closed_sequence,
        "v11_closed_sequence_lineage_drifted",
    ),
    (
        "v12_rejected_prepare_lineage",
        validate_v12_rejected_prepare,
        "v12_rejected_prepare_lineage_drifted",
    ),
)


def _capture_immutable_lineages(root: Path) -> dict[str, object]:
    return {
        plan_key: validator(root)
        for plan_key, validator, _ in IMMUTABLE_LINEAGE_VALIDATORS
    }


def _verify_immutable_lineages(
    root: Path, plan: Mapping[str, object]
) -> None:
    for plan_key, validator, code in IMMUTABLE_LINEAGE_VALIDATORS:
        require(validator(root) == plan.get(plan_key), code)


def prepare_plan(
    *,
    target_release: Path,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    origin = _validate_origin_context(root)
    lineages = _capture_immutable_lineages(root)
    formal_launcher.emit_phase(formal_launcher.PHASE_SOURCE_LINEAGE)
    predecessor = origin["predecessor"]
    assert isinstance(predecessor, dict)
    compatibility_predecessor = _rooted(root, Path(str(predecessor["release_path"])))
    manifest, release_digest, identity = validate_target_release(
        root=target_release, compatibility_predecessor=compatibility_predecessor
    )
    formal_launcher.emit_phase(formal_launcher.PHASE_TARGET_VALIDATION_PASS1)
    current = capture_current_target(root=root, origin=origin, unit_state=unit_state)
    formal_launcher.emit_phase(formal_launcher.PHASE_CURRENT_PUBLIC_SNAPSHOT)
    destination = _rooted(root, upgrade.RELEASE_ROOT / release_digest)
    require(not destination.exists() and not destination.is_symlink(), "target_release_preexisting")
    strategy = strategy_contract()
    incident = _incident(strategy)
    target = {
        "controller_sha256": identity["controller_sha256"],
        "core_commit": manifest["core_commit"],
        "deploy_commit": manifest["deploy_commit"],
        "formal_launcher_contract_digest": identity[
            "formal_launcher_contract_digest"
        ],
        "forward_continuity_contract_digest": identity[
            "forward_continuity_contract_digest"
        ],
        "installed_inventory_sha256": identity["installed_inventory_sha256"],
        "release_digest": release_digest,
        "release_manifest_sha256": identity["manifest_sha256"],
        "release_source": str(target_release.resolve()),
        "release_target": str(upgrade.RELEASE_ROOT / release_digest),
        "server_rejection_contract_sha256": identity["server_rejection_contract_sha256"],
        "server_status_runtime_contract_sha256": identity[
            "server_status_runtime_contract_sha256"
        ],
        "source_inventory_sha256": identity["source_inventory_sha256"],
        "source_binding_digest": identity["source_binding_digest"],
        "status_stage_contract_sha256": identity["status_stage_contract_sha256"],
        "status_runtime_stage_contract_sha256": identity[
            "status_runtime_stage_contract_sha256"
        ],
        "trusted_time_capability_source_identity": identity[
            "trusted_time_capability_source_identity"
        ],
    }
    allowed = [
        str(target["release_target"]),
        str(upgrade.SELECTOR_JSON),
        str(upgrade.SELECTOR_ENV),
        str(upgrade.UNIT_ROOT / upgrade.SERVICE),
        str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        str(EVIDENCE_ROOT / "incidents" / incident["incident_digest"]),
    ]
    return _plan(
        {
            "action": "upgrade",
            "allowed_mutation_paths": allowed,
            "current_target": current,
            "forbidden_program_mutations": FORBIDDEN_PROGRAM_MUTATIONS,
            "incident": incident,
            **lineages,
            "opaque_content_read_deferred_to_action_owned_backup": True,
            "opaque_state_policy": "preserve_forward_authoritative_bytes_no_restore",
            "prestate_rejection_lineage": prestate_rejection_contract(),
            "single_bounded_action": True,
            "strategy": strategy,
            "target": target,
        }
    )


def _validate_state_metadata(value: object) -> dict[str, object]:
    try:
        return post._validate_state_metadata_projection(value)
    except post.PostTargetRejected as exc:
        raise CurrentSelectedUpgradeRejected(exc.code) from exc


def validate_plan(payload: Mapping[str, object]) -> dict[str, object]:
    raw = dict(payload)
    plan_digest = raw.pop("plan_digest", None)
    require(raw.pop("schema", None) == PLAN_SCHEMA, "plan_schema_rejected")
    require(
        isinstance(plan_digest, str)
        and upgrade.HEX64.fullmatch(plan_digest) is not None
        and plan_digest == digest_bytes(canonical(raw)),
        "plan_digest_rejected",
    )
    require(
        set(raw)
        == {
            "accepted_predecessor_lineage",
            "action",
            "allowed_mutation_paths",
            "current_target",
            "failed_predecessor_lineage",
            "forbidden_program_mutations",
            "incident",
            "opaque_content_read_deferred_to_action_owned_backup",
            "opaque_state_policy",
            "prestate_rejection_lineage",
            "single_bounded_action",
            "strategy",
            "target",
            "terminal_predecessor_lineage",
            "v2_terminal_predecessor_lineage",
            "v4_terminal_predecessor_lineage",
            "v5_terminal_predecessor_lineage",
            "v7_prepare_residue_lineage",
            "v8_closed_sequence_lineage",
            "v9_closed_sequence_lineage",
            "v10_terminal_lineage",
            "v11_closed_sequence_lineage",
            "v12_rejected_prepare_lineage",
        }
        and raw.get("action") == "upgrade"
        and raw.get("forbidden_program_mutations") == FORBIDDEN_PROGRAM_MUTATIONS
        and raw.get("single_bounded_action") is True
        and raw.get("opaque_content_read_deferred_to_action_owned_backup") is True
        and raw.get("opaque_state_policy")
        == "preserve_forward_authoritative_bytes_no_restore",
        "plan_scope_rejected",
    )
    require(
        raw.get("prestate_rejection_lineage") == prestate_rejection_contract(),
        "prestate_rejection_lineage_rejected",
    )
    require(
        raw.get("v7_prepare_residue_lineage")
        == {
            "content_opened": False,
            "contract_digest": v7_prepare_residue_contract()["contract_digest"],
            "evidence_root": str(V7_EVIDENCE_ROOT),
            "metadata_verified": True,
            "restore_authority": False,
        },
        "v7_prepare_residue_lineage_rejected",
    )
    require(
        raw.get("v8_closed_sequence_lineage")
        == {
            "contract_digest": v8_closed_sequence_contract()["contract_digest"],
            "evidence_root": str(V8_EVIDENCE_ROOT),
            "formal_calls_consumed": 1,
            "metadata_verified": True,
            "prepare_status": "ready",
            "reopen_authority": False,
            "restore_authority": False,
            "sequence_status": "closed_timeout",
        },
        "v8_closed_sequence_lineage_rejected",
    )
    require(
        raw.get("v9_closed_sequence_lineage")
        == {
            "contract_digest": v9_closed_sequence_contract()["contract_digest"],
            "drift_calls_consumed": 1,
            "drift_status": "preentry_import_failure_closed",
            "evidence_root": str(V9_EVIDENCE_ROOT),
            "formal_calls_consumed": 2,
            "metadata_verified": True,
            "prepare_status": "ready",
            "reopen_authority": False,
            "restore_authority": False,
            "sequence_status": "closed_drift_preentry_failure",
        },
        "v9_closed_sequence_lineage_rejected",
    )
    require(
        raw.get("v10_terminal_lineage") == v10_terminal_contract(),
        "v10_terminal_lineage_rejected",
    )
    require(
        raw.get("v11_closed_sequence_lineage")
        == {
            "contract_digest": v11_closed_sequence_contract()["contract_digest"],
            "evidence_root": str(V11_EVIDENCE_ROOT),
            "formal_calls_consumed": 1,
            "metadata_verified": True,
            "prepare_status": "ready",
            "reopen_authority": False,
            "restore_authority": False,
            "sequence_status": "closed_indeterminate",
        },
        "v11_closed_sequence_lineage_rejected",
    )
    require(
        raw.get("v12_rejected_prepare_lineage")
        == {
            "contract_digest": v12_rejected_prepare_contract()["contract_digest"],
            "evidence_root": str(V12_EVIDENCE_ROOT),
            "formal_calls_consumed": 0,
            "metadata_verified": True,
            "prepare_identity": V12_PREPARE_IDENTITY,
            "prepare_status": "rejected",
            "reopen_authority": False,
            "restore_authority": False,
            "sequence_status": "closed_prepare_rejected",
        },
        "v12_rejected_prepare_lineage_rejected",
    )
    strategy = raw.get("strategy")
    incident = raw.get("incident")
    require(
        isinstance(strategy, dict)
        and strategy == strategy_contract()
        and isinstance(incident, dict)
        and incident == _incident(strategy),
        "strategy_identity_rejected",
    )
    accepted = raw.get("accepted_predecessor_lineage")
    require(
        isinstance(accepted, dict)
        and accepted
        == {
            "accepted_incident_digest": ACCEPTED_INCIDENT_DIGEST,
            "journal_sha256": ACCEPTED_JOURNAL_SHA256,
            "ledger_sha256": ACCEPTED_LEDGER_SHA256,
            "plan_digest": PREDECESSOR_PLAN_DIGEST,
            "plan_sha256": ACCEPTED_PLAN_SHA256,
            "public_manifest_sha256": ACCEPTED_PUBLIC_MANIFEST_SHA256,
            "receipt_sha256": ACCEPTED_RECEIPT_SHA256,
            "state_binding_sha256": ACCEPTED_STATE_BINDING_SHA256,
            "state_manifest_sha256": ACCEPTED_STATE_MANIFEST_SHA256,
            "status": "target_accepted",
        },
        "accepted_lineage_rejected",
    )
    failed = raw.get("failed_predecessor_lineage")
    require(
        isinstance(failed, dict)
        and failed
        == {
            "incident_digest": FAILED_INCIDENT_DIGEST,
            "journal_sha256": FAILED_JOURNAL_SHA256,
            "ledger_sha256": FAILED_LEDGER_SHA256,
            "plan_digest": FAILED_PLAN_DIGEST,
            "plan_sha256": FAILED_PLAN_SHA256,
            "public_manifest_sha256": FAILED_PUBLIC_MANIFEST_SHA256,
            "restore_authority": False,
            "status": "prestop_public_backup_mode_rejected",
        },
        "failed_lineage_rejected",
    )
    terminal = raw.get("terminal_predecessor_lineage")
    require(
        isinstance(terminal, dict)
        and terminal
        == {
            "incident_digest": TERMINAL_INCIDENT_DIGEST,
            "journal_sha256": TERMINAL_JOURNAL_SHA256,
            "ledger_sha256": TERMINAL_LEDGER_SHA256,
            "plan_digest": TERMINAL_PLAN_DIGEST,
            "plan_sha256": TERMINAL_PLAN_SHA256,
            "public_manifest_sha256": TERMINAL_PUBLIC_MANIFEST_SHA256,
            "receipt_sha256": TERMINAL_RECEIPT_SHA256,
            "restore_authority": False,
            "state_binding_sha256": TERMINAL_STATE_BINDING_SHA256,
            "state_manifest_sha256": TERMINAL_STATE_MANIFEST_SHA256,
            "status": "protocol_acceptance_failed_predecessor_restored",
        },
        "terminal_lineage_rejected",
    )
    v2_terminal = raw.get("v2_terminal_predecessor_lineage")
    require(
        isinstance(v2_terminal, dict)
        and v2_terminal
        == {
            "incident_digest": V2_TERMINAL_INCIDENT_DIGEST,
            "journal_sha256": V2_TERMINAL_JOURNAL_SHA256,
            "ledger_sha256": V2_TERMINAL_LEDGER_SHA256,
            "plan_digest": V2_TERMINAL_PLAN_DIGEST,
            "plan_sha256": V2_TERMINAL_PLAN_SHA256,
            "public_manifest_sha256": V2_TERMINAL_PUBLIC_MANIFEST_SHA256,
            "receipt_sha256": V2_TERMINAL_RECEIPT_SHA256,
            "restore_authority": False,
            "state_binding_sha256": V2_TERMINAL_STATE_BINDING_SHA256,
            "state_manifest_sha256": V2_TERMINAL_STATE_MANIFEST_SHA256,
            "status": "protocol_acceptance_failed_predecessor_restored",
        },
        "v2_terminal_lineage_rejected",
    )
    v4_terminal = raw.get("v4_terminal_predecessor_lineage")
    require(
        isinstance(v4_terminal, dict)
        and v4_terminal
        == {
            "handoff_sha256": V4_TERMINAL_HANDOFF_SHA256,
            "incident_digest": V4_TERMINAL_INCIDENT_DIGEST,
            "journal_sha256": V4_TERMINAL_JOURNAL_SHA256,
            "ledger_sha256": V4_TERMINAL_LEDGER_SHA256,
            "plan_digest": V4_TERMINAL_PLAN_DIGEST,
            "plan_sha256": V4_TERMINAL_PLAN_SHA256,
            "public_manifest_sha256": V4_TERMINAL_PUBLIC_MANIFEST_SHA256,
            "receipt_sha256": V4_TERMINAL_RECEIPT_SHA256,
            "restore_authority": False,
            "state_binding_sha256": V4_TERMINAL_STATE_BINDING_SHA256,
            "state_manifest_sha256": V4_TERMINAL_STATE_MANIFEST_SHA256,
            "status": "server_status_runtime_rejected_predecessor_restored",
        },
        "v4_terminal_lineage_rejected",
    )
    v5_terminal = raw.get("v5_terminal_predecessor_lineage")
    require(
        isinstance(v5_terminal, dict)
        and v5_terminal
        == {
            "handoff_sha256": V5_TERMINAL_HANDOFF_SHA256,
            "incident_digest": V5_TERMINAL_INCIDENT_DIGEST,
            "journal_sha256": V5_TERMINAL_JOURNAL_SHA256,
            "ledger_sha256": V5_TERMINAL_LEDGER_SHA256,
            "plan_digest": V5_TERMINAL_PLAN_DIGEST,
            "plan_sha256": V5_TERMINAL_PLAN_SHA256,
            "public_manifest_sha256": V5_TERMINAL_PUBLIC_MANIFEST_SHA256,
            "receipt_sha256": V5_TERMINAL_RECEIPT_SHA256,
            "restore_authority": False,
            "state_binding_sha256": V5_TERMINAL_STATE_BINDING_SHA256,
            "state_manifest_sha256": V5_TERMINAL_STATE_MANIFEST_SHA256,
            "status": "trusted_time_rejected_predecessor_restored",
        },
        "v5_terminal_lineage_rejected",
    )
    current = raw.get("current_target")
    require(
        isinstance(current, dict)
        and set(current) == {"public", "release_digest", "release_manifest_sha256", "state", "units"}
        and current.get("release_digest") == PREDECESSOR_RELEASE_DIGEST
        and current.get("release_manifest_sha256") == PREDECESSOR_MANIFEST_SHA256
        and current.get("units") == READY_UNITS
        and isinstance(current.get("public"), dict)
        and set(current["public"])
        == {
            str(upgrade.SELECTOR_JSON),
            str(upgrade.SELECTOR_ENV),
            str(upgrade.UNIT_ROOT / upgrade.SERVICE),
            str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        },
        "current_target_rejected",
    )
    _validate_state_metadata(current["state"])
    target = raw.get("target")
    require(
        isinstance(target, dict)
        and set(target)
        == {
            "controller_sha256",
            "core_commit",
            "deploy_commit",
            "formal_launcher_contract_digest",
            "forward_continuity_contract_digest",
            "installed_inventory_sha256",
            "release_digest",
            "release_manifest_sha256",
            "release_source",
            "release_target",
            "server_rejection_contract_sha256",
            "server_status_runtime_contract_sha256",
            "source_inventory_sha256",
            "source_binding_digest",
            "status_stage_contract_sha256",
            "status_runtime_stage_contract_sha256",
            "trusted_time_capability_source_identity",
        }
        and target.get("core_commit") == continuity.CORE_COMMIT
        and upgrade.SAFE_COMMIT.fullmatch(str(target.get("deploy_commit"))) is not None
        and upgrade.HEX64.fullmatch(str(target.get("release_digest"))) is not None
        and target.get("release_target")
        == str(upgrade.RELEASE_ROOT / str(target.get("release_digest")))
        and Path(str(target.get("release_source"))).is_absolute()
        and Path(str(target.get("release_source"))).name == target.get("release_digest")
        and all(
            upgrade.HEX64.fullmatch(str(target.get(key))) is not None
            for key in (
                "controller_sha256",
                "formal_launcher_contract_digest",
                "forward_continuity_contract_digest",
                "installed_inventory_sha256",
                "release_manifest_sha256",
                "server_rejection_contract_sha256",
                "server_status_runtime_contract_sha256",
                "source_inventory_sha256",
                "source_binding_digest",
                "status_stage_contract_sha256",
                "status_runtime_stage_contract_sha256",
                "trusted_time_capability_source_identity",
            )
        )
        and target.get("controller_sha256") == strategy.get("controller_sha256"),
        "target_identity_rejected",
    )
    expected_paths = [
        str(target["release_target"]),
        str(upgrade.SELECTOR_JSON),
        str(upgrade.SELECTOR_ENV),
        str(upgrade.UNIT_ROOT / upgrade.SERVICE),
        str(upgrade.UNIT_ROOT / upgrade.SOCKET),
        str(EVIDENCE_ROOT / "incidents" / incident["incident_digest"]),
    ]
    require(raw.get("allowed_mutation_paths") == expected_paths, "allowed_paths_rejected")
    return {**raw, "plan_digest": plan_digest, "schema": PLAN_SCHEMA}


def verify_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    plan = validate_plan(payload)
    origin = _validate_origin_context(root)
    _verify_immutable_lineages(root, plan)
    phase_role = os.environ.get(formal_launcher.PHASE_ROLE_ENV)
    if phase_role == formal_launcher.ROLE_DRIFT:
        formal_launcher.emit_phase(formal_launcher.PHASE_SOURCE_LINEAGE)
    require(
        capture_current_target(root=root, origin=origin, unit_state=unit_state)
        == plan["current_target"],
        "current_target_drifted",
    )
    if phase_role == formal_launcher.ROLE_DRIFT:
        formal_launcher.emit_phase(formal_launcher.PHASE_CURRENT_PUBLIC_SNAPSHOT)
    predecessor = origin["predecessor"]
    target = plan["target"]
    assert isinstance(predecessor, dict) and isinstance(target, dict)
    source = Path(str(target["release_source"]))
    manifest, release_digest, identity = validate_target_release(
        root=source,
        compatibility_predecessor=_rooted(root, Path(str(predecessor["release_path"]))),
    )
    require(
        release_digest == target["release_digest"]
        and manifest.get("core_commit") == target["core_commit"]
        and manifest.get("deploy_commit") == target["deploy_commit"]
        and identity["controller_sha256"] == target["controller_sha256"]
        and identity["formal_launcher_contract_digest"]
        == target["formal_launcher_contract_digest"]
        and identity["forward_continuity_contract_digest"]
        == target["forward_continuity_contract_digest"]
        and identity["installed_inventory_sha256"] == target["installed_inventory_sha256"]
        and identity["manifest_sha256"] == target["release_manifest_sha256"]
        and identity["server_rejection_contract_sha256"]
        == target["server_rejection_contract_sha256"]
        and identity["server_status_runtime_contract_sha256"]
        == target["server_status_runtime_contract_sha256"]
        and identity["source_inventory_sha256"] == target["source_inventory_sha256"]
        and identity["source_binding_digest"] == target["source_binding_digest"]
        and identity["status_stage_contract_sha256"]
        == target["status_stage_contract_sha256"]
        and identity["status_runtime_stage_contract_sha256"]
        == target["status_runtime_stage_contract_sha256"]
        and identity["trusted_time_capability_source_identity"]
        == target["trusted_time_capability_source_identity"]
        and not _rooted(root, Path(str(target["release_target"]))).exists(),
        "target_drifted",
    )
    formal_launcher.emit_phase(
        formal_launcher.PHASE_TARGET_VALIDATION_PASS1
        if phase_role == formal_launcher.ROLE_DRIFT
        else formal_launcher.PHASE_TARGET_VALIDATION_PASS2
    )
    return plan


def preflight(
    *,
    target_release: Path,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    plan = prepare_plan(target_release=target_release, root=root, unit_state=unit_state)
    verified = verify_plan(plan, root=root, unit_state=unit_state)
    require(verified == plan, "preflight_mixed")
    return {
        "forward_continuity": continuity.readiness(
            plan_digest=str(verified["plan_digest"]),
            strategy_digest=str(verified["strategy"]["strategy_digest"]),
        ),
        "opaque_content_read": False,
        "opaque_content_read_deferred_to_action_owned_backup": True,
        "persistent_mutation": False,
        "plan": verified,
        "plan_digest": verified["plan_digest"],
        "schema": READINESS_SCHEMA,
        "status": "ready",
    }


def _evidence_path(root: Path, plan: Mapping[str, object]) -> Path:
    incident = plan.get("incident")
    require(isinstance(incident, dict), "incident_identity_rejected")
    return _rooted(
        root,
        EVIDENCE_ROOT / "incidents" / str(incident["incident_digest"]),
    )


def _validate_owned_directory(path: Path, *, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected(code) from exc
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid(),
        code,
    )


def _validate_owned_file(
    path: Path, payload: bytes, *, code: str, mode: int = 0o600
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and metadata.st_size == len(payload)
        and upgrade.digest_file(path) == digest_bytes(payload),
        code,
    )


def _ensure_evidence_parent(root: Path) -> Path:
    base = _rooted(root, EVIDENCE_ROOT)
    require(base.parent.is_dir() and not base.parent.is_symlink(), "evidence_parent_rejected")
    for path in (base, base / "incidents"):
        try:
            os.mkdir(path, 0o700)
            upgrade._fsync_directory(path.parent)
        except FileExistsError:
            pass
        except OSError as exc:
            raise CurrentSelectedUpgradeRejected("evidence_parent_rejected") from exc
        _validate_owned_directory(path, code="evidence_parent_rejected")
    return base / "incidents"


def _claim_evidence(root: Path, plan: Mapping[str, object]) -> Path:
    parent = _ensure_evidence_parent(root)
    evidence = _evidence_path(root, plan)
    require(evidence.parent == parent, "evidence_path_rejected")
    try:
        os.mkdir(evidence, 0o700)
        upgrade._fsync_directory(parent)
    except FileExistsError as exc:
        raise CurrentSelectedUpgradeRejected("incident_already_consumed") from exc
    except OSError as exc:
        raise CurrentSelectedUpgradeRejected("evidence_create_rejected") from exc
    _validate_owned_directory(evidence, code="evidence_create_rejected")
    return evidence


def _journal_payload(plan: Mapping[str, object], events: Sequence[str]) -> dict[str, object]:
    require(events and len(events) == len(set(events)), "journal_sequence_rejected")
    selected = tuple(events)
    if "convergence_owned" not in selected:
        require(selected == JOURNAL_STAGES[: len(selected)], "journal_sequence_rejected")
    else:
        index = selected.index("convergence_owned")
        require(
            index >= 4
            and selected[:index] == JOURNAL_STAGES[:index]
            and selected[index:]
            in {
                ("convergence_owned",),
                ("convergence_owned", "predecessor_restored"),
                ("convergence_owned", "convergence_failed"),
            },
            "journal_sequence_rejected",
        )
    return {
        "action": "upgrade",
        "attempts": 1,
        "events": list(events),
        "plan_digest": plan["plan_digest"],
        "schema": JOURNAL_SCHEMA,
        "stage": events[-1],
    }


def _write_journal(path: Path, plan: Mapping[str, object], events: Sequence[str]) -> None:
    payload = canonical(_journal_payload(plan, events))
    if path.exists():
        upgrade._atomic_write(
            path,
            payload,
            mode=0o600,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
    else:
        upgrade._exclusive_write(path, payload, mode=0o600)


def _load_journal(path: Path, plan: Mapping[str, object]) -> dict[str, object]:
    payload = _load_json(path, code="journal_rejected")
    events = payload.get("events")
    require(
        isinstance(events, list)
        and all(isinstance(item, str) for item in events)
        and payload == _journal_payload(plan, events),
        "journal_rejected",
    )
    return payload


def _public_adapter(plan: Mapping[str, object]) -> dict[str, object]:
    current = plan.get("current_target")
    require(isinstance(current, dict), "current_target_rejected")
    return {"public_prestate": current["public"]}


def _origin_identity(origin: Mapping[str, object]) -> dict[str, object]:
    identity = origin.get("identity")
    require(isinstance(identity, dict), "origin_identity_rejected")
    return identity


def _verify_state_metadata(
    *, root: Path, plan: Mapping[str, object], origin: Mapping[str, object]
) -> dict[str, object]:
    current = plan.get("current_target")
    require(isinstance(current, dict), "current_target_rejected")
    expected = _validate_state_metadata(current.get("state"))
    identity = _origin_identity(origin)
    observed = upgrade.describe_opaque_state_metadata(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    require(observed == expected, "opaque_state_metadata_drifted")
    return observed


def _state_binding(plan: Mapping[str, object], exact: Mapping[str, object]) -> dict[str, object]:
    current = plan.get("current_target")
    require(isinstance(current, dict), "state_binding_rejected")
    metadata = _validate_state_metadata(current.get("state"))
    return {
        "backup_path": "current-state",
        "content_bytes_read": True,
        "content_read_deferred_from_readiness": True,
        "restore_authority_after_forward_commit": False,
        "restore_authority_before_forward_commit": True,
        "metadata_projection_sha256": digest_bytes(canonical(metadata)),
        "plan_digest": plan["plan_digest"],
        "schema": STATE_BINDING_SCHEMA,
        "state_descriptor_sha256": digest_bytes(canonical(exact)),
    }


def _stage_state_backup(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    identity = _origin_identity(origin)
    _verify_state_metadata(root=root, plan=plan, origin=origin)
    source = _rooted(root, upgrade.STATE_ROOT)
    exact = upgrade.describe_opaque_state(
        source,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    _verify_state_metadata(root=root, plan=plan, origin=origin)
    upgrade.backup_opaque_state(
        source=source,
        backup=evidence / "current-state",
        expected=exact,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    _verify_state_metadata(root=root, plan=plan, origin=origin)
    binding = _state_binding(plan, exact)
    upgrade._exclusive_write(
        evidence / "STATE_BINDING.json", canonical(binding), mode=0o600
    )
    _load_state_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    return exact


def _load_state_backup(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    identity = _origin_identity(origin)
    exact = _load_json(
        evidence / "current-state/STATE.json", code="state_backup_manifest_rejected"
    )
    binding = _load_json(
        evidence / "STATE_BINDING.json", code="state_binding_rejected"
    )
    require(binding == _state_binding(plan, exact), "state_binding_rejected")
    _validate_owned_file(
        evidence / "STATE_BINDING.json",
        canonical(binding),
        code="state_binding_rejected",
    )
    upgrade.validate_opaque_backup(
        backup=evidence / "current-state",
        expected=exact,
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    return exact


def _verify_state_matches_backup(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
) -> dict[str, object]:
    exact = _load_state_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    identity = _origin_identity(origin)
    _verify_state_metadata(root=root, plan=plan, origin=origin)
    observed = upgrade.describe_opaque_state(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
        expected_gid=int(identity["service_gid"]),
    )
    require(observed == exact, "action_owned_state_drifted")
    return exact


def stage_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> Path:
    """Consume the max-one incident and durably own every pre-stop artifact."""

    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan = verify_plan(payload, root=root, unit_state=unit_state)
    evidence = _claim_evidence(root, plan)
    upgrade._exclusive_write(evidence / "PLAN.json", canonical(plan), mode=0o600)
    ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": plan["incident"]["incident_digest"],
        "plan_digest": plan["plan_digest"],
        "schema": LEDGER_SCHEMA,
    }
    upgrade._exclusive_write(evidence / "LEDGER.json", canonical(ledger), mode=0o600)
    _write_journal(evidence / "JOURNAL.json", plan, ["prepared"])
    origin = _validate_origin_context(root)
    _verify_immutable_lineages(root, plan)
    upgrade._copy_public_backup(root, evidence / "current-public", _public_adapter(plan))
    _write_journal(
        evidence / "JOURNAL.json", plan, ["prepared", "current_public_backed_up"]
    )
    _stage_state_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    _write_journal(
        evidence / "JOURNAL.json",
        plan,
        ["prepared", "current_public_backed_up", "current_state_backed_up"],
    )
    _write_journal(
        evidence / "JOURNAL.json",
        plan,
        [
            "prepared",
            "current_public_backed_up",
            "current_state_backed_up",
            "attempt_owned",
        ],
    )
    require(
        verify_plan(plan, root=root, unit_state=unit_state) == plan,
        "staged_pre_stop_drifted",
    )
    return evidence


def _validate_staged_evidence(
    payload: Mapping[str, object],
    *,
    root: Path,
    verify_current: bool,
    unit_state: Mapping[str, object] | None,
) -> tuple[dict[str, object], dict[str, object], Path]:
    plan = (
        verify_plan(payload, root=root, unit_state=unit_state)
        if verify_current
        else validate_plan(payload)
    )
    origin = _validate_origin_context(root)
    _verify_immutable_lineages(root, plan)
    evidence = _evidence_path(root, plan)
    _validate_owned_directory(evidence, code="staged_evidence_rejected")
    _validate_owned_file(evidence / "PLAN.json", canonical(plan), code="staged_plan_rejected")
    ledger = {
        "action": "upgrade",
        "attempts": 1,
        "consumed": True,
        "incident_digest": plan["incident"]["incident_digest"],
        "plan_digest": plan["plan_digest"],
        "schema": LEDGER_SCHEMA,
    }
    _validate_owned_file(evidence / "LEDGER.json", canonical(ledger), code="ledger_rejected")
    require(
        _load_json(evidence / "PLAN.json", code="staged_plan_rejected") == plan
        and _load_json(evidence / "LEDGER.json", code="ledger_rejected") == ledger,
        "staged_evidence_rejected",
    )
    journal = _load_journal(evidence / "JOURNAL.json", plan)
    require(
        (
            journal.get("stage") == "attempt_owned"
            if verify_current
            else "attempt_owned" in journal["events"]
        ),
        "staged_evidence_rejected",
    )
    upgrade._validate_public_backup(evidence / "current-public", _public_adapter(plan))
    if verify_current:
        _verify_state_matches_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    else:
        _load_state_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    return plan, origin, evidence


def verify_staged_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], Path]:
    plan, _, evidence = _validate_staged_evidence(
        payload, root=root, verify_current=True, unit_state=unit_state
    )
    return plan, evidence


def _install_target(
    *, root: Path, plan: Mapping[str, object], origin: Mapping[str, object]
) -> Path:
    target = plan.get("target")
    require(isinstance(target, dict), "target_identity_rejected")
    source = Path(str(target["release_source"]))
    source_rows = post._release_metadata_inventory(source)
    require(
        digest_bytes(canonical(source_rows)) == target["source_inventory_sha256"],
        "target_source_inventory_drifted",
    )
    adapter = {
        "active_gateway_runtime": origin["active_gateway_runtime"],
        "identity": origin["identity"],
        "plan_digest": plan["plan_digest"],
        "predecessor": origin["predecessor"],
        "state_prestate": {},
        "target": target,
    }
    installed = upgrade._install_release(
        root, adapter, expected_core_commit=continuity.CORE_COMMIT
    )
    rows = post._release_metadata_inventory(installed)
    require(
        rows == post._installed_inventory_from_source(source_rows, live=root == Path("/")),
        "installed_inventory_rejected",
    )
    if root == Path("/"):
        require(
            digest_bytes(canonical(rows)) == target["installed_inventory_sha256"],
            "installed_inventory_rejected",
        )
    validate_target_release(
        root=installed,
        compatibility_predecessor=_rooted(
            root, Path(str(origin["predecessor"]["release_path"]))
        ),
    )
    return installed


def _apply_target(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    installed: Path,
    exact_state: Mapping[str, object],
) -> dict[str, object]:
    adapter = {
        "active_gateway_runtime": origin["active_gateway_runtime"],
        "identity": origin["identity"],
        "plan_digest": plan["plan_digest"],
        "predecessor": origin["predecessor"],
        "state_prestate": exact_state,
        "target": plan["target"],
    }
    upgrade._apply_target_public(root, installed, adapter)
    return adapter


def _verify_predecessor_restored(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    unit_state: Mapping[str, object] | None,
) -> None:
    observed = capture_current_target(root=root, origin=origin, unit_state=unit_state)
    expected = dict(plan["current_target"])
    observed_state = observed.pop("state")
    expected_state = expected.pop("state")
    require(observed == expected, "predecessor_restore_rejected")

    def security_shape(value: object) -> dict[str, object]:
        selected = _validate_state_metadata(value)
        root_value = selected["root"]
        files = selected["files"]
        assert isinstance(root_value, dict) and isinstance(files, list)
        return {
            "root": {
                key: root_value[key]
                for key in ("gid", "mode", "nlink", "path_role", "type", "uid")
            },
            "files": [
                {
                    key: row[key]
                    for key in ("gid", "mode", "nlink", "path_role", "type", "uid")
                }
                for row in files
                if isinstance(row, dict)
            ],
        }

    require(
        security_shape(observed_state) == security_shape(expected_state),
        "predecessor_restore_rejected",
    )


def _forward_provider(
    *, root: Path, origin: Mapping[str, object]
) -> continuity.ProviderPort:
    identity = _origin_identity(origin)
    return continuity.provider_for_state(
        _rooted(root, upgrade.STATE_ROOT),
        expected_uid=int(identity["service_uid"]),
    )


def _default_forward_transition_runner(
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
    persist_protected: Callable[[bytes], None],
) -> Mapping[str, object]:
    del evidence
    strategy = plan.get("strategy")
    incident = plan.get("incident")
    require(isinstance(strategy, dict) and isinstance(incident, dict), "forward_binding_rejected")
    return continuity.transition(
        _forward_provider(root=root, origin=origin),
        action_owned=True,
        plan_digest=str(plan["plan_digest"]),
        strategy_digest=str(strategy["strategy_digest"]),
        incident_digest=str(incident["incident_digest"]),
        persist_protected=persist_protected,
    )


def _default_forward_reconcile_runner(
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
) -> Mapping[str, object]:
    strategy = plan.get("strategy")
    require(isinstance(strategy, dict), "forward_binding_rejected")
    protected = _load_json(
        evidence / "FORWARD_BINDING.PRIVATE.json",
        code="forward_binding_rejected",
    )
    return continuity.reconcile(
        _forward_provider(root=root, origin=origin),
        protected,
        action_owned=True,
        plan_digest=str(plan["plan_digest"]),
        strategy_digest=str(strategy["strategy_digest"]),
    )


def _default_forward_state_verifier(
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
) -> Mapping[str, object]:
    del plan
    return continuity.validate_forward_state(_forward_provider(root=root, origin=origin))


def _rollback_once(
    *,
    root: Path,
    plan: Mapping[str, object],
    origin: Mapping[str, object],
    evidence: Path,
    runner: Runner,
    unit_state: Mapping[str, object] | None,
    forward_state_possible: bool,
    forward_state_verifier: ForwardStateVerifier,
) -> None:
    upgrade._stop(runner)
    upgrade._restore_public(root, evidence / "current-public", _public_adapter(plan))
    if forward_state_possible:
        forward_state_verifier(root, plan, origin)
    else:
        _verify_state_matches_backup(root=root, plan=plan, origin=origin, evidence=evidence)
    post._start_service_then_socket(runner)
    _verify_predecessor_restored(
        root=root,
        plan=plan,
        origin=origin,
        unit_state=unit_state,
    )
    if forward_state_possible:
        forward_state_verifier(root, plan, origin)


def _receipt(
    *,
    plan: Mapping[str, object],
    status: str,
    acceptance_projection_sha256: str | None = None,
    action_failure_code: str | None = None,
    convergence_failure_code: str | None = None,
    content_free_failure_projection: Mapping[str, object] | None = None,
    forward_continuity_result: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "acceptance_projection_sha256": acceptance_projection_sha256,
        "action": "upgrade",
        "action_failure_code": action_failure_code,
        "channel_called": False,
        "convergence_failure_code": convergence_failure_code,
        "incident_digest": plan["incident"]["incident_digest"],
        "forward_continuity_result": (
            None
            if forward_continuity_result is None
            else dict(forward_continuity_result)
        ),
        "model_called": False,
        "other_program_mutated": False,
        "plan_digest": plan["plan_digest"],
        "predecessor_release_digest": PREDECESSOR_RELEASE_DIGEST,
        "private_content_parsed": False,
        "protocol_acceptance_failure": (
            dict(content_free_failure_projection)
            if content_free_failure_projection is not None
            else None
        ),
        "schema": RECEIPT_SCHEMA,
        "state_bytes_restored": False,
        "state_bytes_preserved": True,
        "trusted_time_state_rollback": False,
        "status": status,
        "target_release_digest": plan["target"]["release_digest"],
    }


def execute_staged_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
    runner: Runner = upgrade._run,
    acceptance_runner: AcceptanceRunner = post._run_content_free_acceptance,
    forward_transition_runner: ForwardTransitionRunner = (
        _default_forward_transition_runner
    ),
    forward_state_verifier: ForwardStateVerifier = _default_forward_state_verifier,
    stage_hook: StageHook | None = None,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan, origin, evidence = _validate_staged_evidence(
        payload, root=root, verify_current=True, unit_state=unit_state
    )
    require(not (evidence / "RECEIPT.json").exists(), "action_replay_rejected")
    journal_path = evidence / "JOURNAL.json"
    journal = _load_journal(journal_path, plan)
    events = list(journal["events"])

    def advance(stage: str) -> None:
        events.append(stage)
        _write_journal(journal_path, plan, events)
        if stage_hook is not None:
            stage_hook(stage)

    exact_state = _verify_state_matches_backup(
        root=root, plan=plan, origin=origin, evidence=evidence
    )
    forward_result: Mapping[str, object] | None = None
    forward_state_possible = False
    try:
        upgrade._stop(runner)
        advance("services_stopped")
        require(
            _verify_state_matches_backup(root=root, plan=plan, origin=origin, evidence=evidence)
            == exact_state,
            "action_owned_state_drifted",
        )
        installed = _install_target(root=root, plan=plan, origin=origin)
        advance("release_installed")

        def persist_forward_binding(raw: bytes) -> None:
            upgrade._exclusive_write(
                evidence / "FORWARD_BINDING.PRIVATE.json", raw, mode=0o600
            )
            advance("forward_binding_durable")

        forward_result = forward_transition_runner(
            root, plan, origin, evidence, persist_forward_binding
        )
        require(
            forward_result.get("state_effect") == "committed"
            and forward_result.get("status")
            in {"committed", "committed_reconciled"},
            "forward_transition_rejected",
        )
        upgrade._exclusive_write(
            evidence / "FORWARD_RESULT.json",
            canonical(forward_result),
            mode=0o600,
        )
        forward_state_possible = True
        advance("forward_transition_committed")
        forward_state_verifier(root, plan, origin)
        identity = _origin_identity(origin)
        active_state = upgrade.describe_opaque_state(
            _rooted(root, upgrade.STATE_ROOT),
            expected_uid=int(identity["service_uid"]),
            expected_gid=int(identity["service_gid"]),
        )
        adapter = _apply_target(
            root=root,
            plan=plan,
            origin=origin,
            installed=installed,
            exact_state=active_state,
        )
        advance("public_applied")
        post._start_service_then_socket(runner)
        advance("target_started")
        forward_state_verifier(root, plan, origin)
        upgrade._verify_target(root, adapter)
        advance("protocol_acceptance_called")
        acceptance_sha256 = post._validate_content_free_acceptance(
            acceptance_runner(installed)
        )
        advance("target_accepted")
        receipt = _receipt(
            plan=plan,
            status="upgrade_target_accepted",
            acceptance_projection_sha256=acceptance_sha256,
            forward_continuity_result=forward_result,
        )
        upgrade._exclusive_write(evidence / "RECEIPT.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as action_error:
        forward_state_possible = forward_state_possible or (
            isinstance(forward_result, Mapping)
            and forward_result.get("state_effect") == "committed"
        ) or getattr(action_error, "state_effect", "none") in {
            "ambiguous",
            "committed",
        }
        action_code = str(getattr(action_error, "code", "action_failed"))
        failure_projection: Mapping[str, object] | None = None
        candidate_projection = getattr(
            action_error, "content_free_failure_projection", None
        )
        if isinstance(candidate_projection, Mapping):
            try:
                nonce = candidate_projection.get("invocation_nonce")
                if not isinstance(nonce, str):
                    raise ValueError("invalid_content_free_status_rejection")
                failure_projection = post.temporal_gateway.parse_content_free_status_rejection(
                    candidate_projection,
                    expected_invocation_nonce=nonce,
                ).projection()
            except ValueError:
                failure_projection = None
        try:
            advance("convergence_owned")
            _rollback_once(
                root=root,
                plan=plan,
                origin=origin,
                evidence=evidence,
                runner=runner,
                unit_state=unit_state,
                forward_state_possible=forward_state_possible,
                forward_state_verifier=forward_state_verifier,
            )
            advance("predecessor_restored")
            failure = _receipt(
                plan=plan,
                status="action_failed_predecessor_restored",
                action_failure_code=action_code,
                content_free_failure_projection=failure_projection,
                forward_continuity_result=(
                    forward_result
                    if forward_result is not None
                    else getattr(action_error, "projection", None)
                ),
            )
            upgrade._exclusive_write(evidence / "RECEIPT.json", canonical(failure), mode=0o600)
        except Exception as convergence_error:
            convergence_code = str(getattr(convergence_error, "code", "convergence_failed"))
            try:
                if "convergence_owned" in events and "predecessor_restored" not in events:
                    advance("convergence_failed")
                failure = _receipt(
                    plan=plan,
                    status="action_failed_convergence_failed",
                    action_failure_code=action_code,
                    convergence_failure_code=convergence_code,
                    content_free_failure_projection=failure_projection,
                )
                upgrade._exclusive_write(
                    evidence / "RECEIPT.json", canonical(failure), mode=0o600
                )
            except Exception:
                pass
            raise CurrentSelectedUpgradeRejected(
                "action_failed_convergence_failed",
                action_failure_code=action_code,
                convergence_failure_code=convergence_code,
            ) from convergence_error
        raise CurrentSelectedUpgradeRejected(
            "action_failed_predecessor_restored",
            action_failure_code=action_code,
            content_free_failure_projection=failure_projection,
        ) from action_error


def recover_interrupted_plan(
    payload: Mapping[str, object],
    *,
    root: Path = Path("/"),
    unit_state: Mapping[str, object] | None = None,
    runner: Runner = upgrade._run,
    forward_reconcile_runner: ForwardReconcileRunner = (
        _default_forward_reconcile_runner
    ),
    forward_state_verifier: ForwardStateVerifier = _default_forward_state_verifier,
) -> dict[str, object]:
    if root == Path("/"):
        require(os.geteuid() == 0, "root_required")
    plan, origin, evidence = _validate_staged_evidence(
        payload, root=root, verify_current=False, unit_state=unit_state
    )
    require(not (evidence / "RECEIPT.json").exists(), "recovery_replay_rejected")
    journal = _load_journal(evidence / "JOURNAL.json", plan)
    events = list(journal["events"])
    require(
        journal.get("stage") != "target_accepted" and "attempt_owned" in events,
        "interrupted_before_attempt_no_recovery",
    )
    require("convergence_owned" not in events, "recovery_already_consumed")
    forward_result: Mapping[str, object] | None = None
    binding_exists = (evidence / "FORWARD_BINDING.PRIVATE.json").exists()
    forward_committed = "forward_transition_committed" in events
    try:
        if binding_exists and "forward_binding_durable" not in events:
            require(events[-1] == "release_installed", "forward_binding_stage_rejected")
            events.append("forward_binding_durable")
            _write_journal(evidence / "JOURNAL.json", plan, events)
        if binding_exists and "forward_transition_committed" not in events:
            forward_result = forward_reconcile_runner(root, plan, origin, evidence)
            upgrade._exclusive_write(
                evidence / "FORWARD_RECONCILIATION.json",
                canonical(forward_result),
                mode=0o600,
            )
            if forward_result.get("status") == "committed":
                events.append("forward_transition_committed")
                forward_committed = True
                _write_journal(evidence / "JOURNAL.json", plan, events)
            else:
                require(
                    forward_result.get("status") == "not_committed",
                    "forward_reconcile_rejected",
                )
        _write_journal(
            evidence / "JOURNAL.json", plan, [*events, "convergence_owned"]
        )
        _rollback_once(
            root=root,
            plan=plan,
            origin=origin,
            evidence=evidence,
            runner=runner,
            unit_state=unit_state,
            forward_state_possible=forward_committed,
            forward_state_verifier=forward_state_verifier,
        )
        _write_journal(
            evidence / "JOURNAL.json",
            plan,
            [*events, "convergence_owned", "predecessor_restored"],
        )
        receipt = _receipt(
            plan=plan,
            status="interrupted_action_predecessor_restored",
            action_failure_code="interrupted_action",
            forward_continuity_result=forward_result,
        )
        upgrade._exclusive_write(evidence / "RECEIPT.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as convergence_error:
        convergence_code = str(getattr(convergence_error, "code", "convergence_failed"))
        try:
            _write_journal(
                evidence / "JOURNAL.json",
                plan,
                [*events, "convergence_owned", "convergence_failed"],
            )
        except Exception:
            pass
        receipt = _receipt(
            plan=plan,
            status="interrupted_action_convergence_failed",
            action_failure_code="interrupted_action",
            convergence_failure_code=convergence_code,
            forward_continuity_result=forward_result,
        )
        try:
            upgrade._exclusive_write(evidence / "RECEIPT.json", canonical(receipt), mode=0o600)
        except Exception:
            pass
        raise CurrentSelectedUpgradeRejected(
            "interrupted_action_convergence_failed",
            action_failure_code="interrupted_action",
            convergence_failure_code=convergence_code,
        ) from convergence_error


def execute_live_plan(payload: Mapping[str, object]) -> dict[str, object]:
    stage_plan(payload, root=Path("/"))
    return execute_staged_plan(payload, root=Path("/"))


def recover_live_plan(payload: Mapping[str, object]) -> dict[str, object]:
    return recover_interrupted_plan(payload, root=Path("/"))


def _cli_rejection(
    code: str, *, category: str, may_have_action_effects: bool
) -> dict[str, object]:
    safe_code = code if upgrade.SAFE_CODE.fullmatch(code) is not None else "upgrade_rejected"
    return {
        "category": category,
        "code": safe_code,
        "opaque_content_read": may_have_action_effects,
        "persistent_mutation": may_have_action_effects,
        "retryable": False,
        "schema": CLI_RESULT_SCHEMA,
        "status": "rejected",
    }


def main(argv: Sequence[str] | None = None) -> int:
    command: str | None = None
    try:
        parser = CanonicalArgumentParser(add_help=False)
        commands = parser.add_subparsers(
            dest="command", required=True, parser_class=CanonicalArgumentParser
        )
        for name in ("prepare", "preflight"):
            selected = commands.add_parser(name, add_help=False)
            selected.add_argument("--target-release", type=Path, required=True)
            selected.add_argument("--synthetic-root", type=Path)
        for name in ("verify", "execute", "recover"):
            selected = commands.add_parser(name, add_help=False)
            selected.add_argument("--plan", type=Path, required=True)
            selected.add_argument("--synthetic-root", type=Path)
        values = parser.parse_args(argv)
        command = values.command
        if values.command in {"prepare", "preflight", "verify"}:
            phase_role = os.environ.get(formal_launcher.PHASE_ROLE_ENV)
            if phase_role is not None:
                require(
                    phase_role
                    == (
                        formal_launcher.ROLE_PREPARE
                        if values.command == "prepare"
                        else formal_launcher.ROLE_FORMAL
                        if values.command == "preflight"
                        else formal_launcher.ROLE_DRIFT
                    ),
                    "phase_liveness_role_rejected",
                )
            formal_launcher.emit_phase(formal_launcher.PHASE_STARTUP)
        if values.command in {"prepare", "preflight"}:
            root = values.synthetic_root or Path("/")
            require(
                values.synthetic_root is None or root != Path("/"),
                "synthetic_root_rejected",
            )
            result = (
                prepare_plan(target_release=values.target_release, root=root, unit_state=READY_UNITS)
                if values.command == "prepare" and root != Path("/")
                else prepare_plan(target_release=values.target_release)
                if values.command == "prepare"
                else preflight(target_release=values.target_release, root=root, unit_state=READY_UNITS)
                if root != Path("/")
                else preflight(target_release=values.target_release)
            )
        else:
            plan = _load_json(values.plan, code="plan_input_rejected")
            if values.command == "verify":
                result = verify_plan(
                    plan,
                    root=values.synthetic_root or Path("/"),
                    unit_state=READY_UNITS if values.synthetic_root else None,
                )
            elif values.command == "execute":
                require(values.synthetic_root is None, "synthetic_execute_rejected")
                result = execute_live_plan(plan)
            else:
                require(values.synthetic_root is None, "synthetic_recover_rejected")
                result = recover_live_plan(plan)
        if values.command in {"prepare", "preflight", "verify"}:
            formal_launcher.emit_phase(
                formal_launcher.PHASE_CANONICAL_SERIALIZATION
            )
        print(canonical(result).decode("ascii"))
        return 0
    except (
        CurrentSelectedUpgradeRejected,
        upgrade.UpgradeRejected,
        post.PostTargetRejected,
        formal_launcher.LauncherRejected,
    ) as exc:
        print(canonical(_cli_rejection(
            str(getattr(exc, "code", "upgrade_rejected")),
            category="typed_rejection",
            may_have_action_effects=command in {"execute", "recover"},
        )).decode("ascii"))
        return 2
    except Exception:
        print(canonical(_cli_rejection(
            "unexpected_controller_failure",
            category="unexpected_controller_failure",
            may_have_action_effects=command in {"execute", "recover"},
        )).decode("ascii"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
