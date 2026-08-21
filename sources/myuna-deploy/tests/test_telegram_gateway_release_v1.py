from __future__ import annotations

import copy
from datetime import datetime, timezone
import errno
import json
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import tarfile
import unittest
from unittest import mock

import build_telegram_gateway_release_v1 as builder


ROOT = Path(__file__).resolve().parents[1]


class TelegramGatewayReleaseTests(unittest.TestCase):
    @staticmethod
    def _receipt_substitutions() -> dict[str, object]:
        return {
            "source_commit": "0" * 40,
            "tools": [],
            "base_digest": "sha256:" + "0" * 64,
            "base_config_digest": "sha256:" + "1" * 64,
            "base_child_manifest_digest": "sha256:" + "2" * 64,
            "stage_sha256": "0" * 64,
            "platform": {"architecture": "arm64", "os": "linux"},
            "repository": "forged/repository",
            "image_id": "sha256:" + "f" * 64,
        }

    @staticmethod
    def _receipt_shape() -> dict[str, object]:
        layer_digests = [f"sha256:{ordinal:064x}" for ordinal in range(1, 10)]
        layers = [
            {
                "compressed_digest": digest,
                "compressed_size": ordinal,
                "diff_id": diff_id,
            }
            for ordinal, (digest, diff_id) in enumerate(
                zip(
                    layer_digests,
                    (*builder.ASTRBOT_BASE_DIFF_IDS, "sha256:" + "f" * 64),
                    strict=True,
                ),
                start=1,
            )
        ]
        manifest_digest = "sha256:" + "a" * 64
        return {
            "archive_sha256": "b" * 64,
            "archive_size": 1,
            "base_child_manifest_digest": builder.ASTRBOT_BASE_CHILD_MANIFEST_DIGEST,
            "base_config_digest": builder.ASTRBOT_BASE_CONFIG_DIGEST,
            "base_digest": builder.ASTRBOT_BASE_DIGEST,
            "base_diff_ids": list(builder.ASTRBOT_BASE_DIFF_IDS),
            "config_digest": "sha256:" + "c" * 64,
            "dockerfile_sha256": builder.ASTRBOT_DOCKERFILE_SHA256,
            "image_id": manifest_digest,
            "image_reference": f"{builder.ASTRBOT_IMAGE_REPOSITORY}@{manifest_digest}",
            "index_digest": "sha256:" + "d" * 64,
            "layers": layers,
            "manifest_digest": manifest_digest,
            "platform": {"architecture": "amd64", "os": "linux"},
            "repository": builder.ASTRBOT_IMAGE_REPOSITORY,
            "schema": builder.ASTRBOT_IMAGE_SCHEMA,
            "source_commit": builder.ASTRBOT_SOURCE_COMMIT,
            "source_date_epoch": builder.ASTRBOT_SOURCE_DATE_EPOCH,
            "stage_sha256": builder.ASTRBOT_STAGE_SHA256,
            "tag_reference": f"{builder.ASTRBOT_IMAGE_REPOSITORY}:{builder.ASTRBOT_IMAGE_TAG}",
            "timestamp": datetime.fromtimestamp(
                builder.ASTRBOT_SOURCE_DATE_EPOCH,
                tz=timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {"name": name, "path": path, "version": version, "sha256": digest}
                for name, path, version, digest in builder.ASTRBOT_TOOL_IDENTITIES
            ],
        }

    @staticmethod
    def _patch_tar_member(
        handle: object,
        original: tarfile.TarInfo,
        name: str,
        payload: bytes,
    ) -> None:
        allocation = (original.size + 511) // 512 * 512
        if len(payload) > allocation:
            raise AssertionError("mutated fixture exceeds original tar allocation")
        replacement = tarfile.TarInfo(name)
        replacement.type = tarfile.REGTYPE
        replacement.size = len(payload)
        replacement.mode = original.mode
        replacement.uid = original.uid
        replacement.gid = original.gid
        replacement.uname = original.uname
        replacement.gname = original.gname
        replacement.mtime = original.mtime
        header = replacement.tobuf(format=tarfile.USTAR_FORMAT)
        handle.seek(original.offset)
        handle.write(header)
        handle.seek(original.offset_data)
        handle.write(payload)
        handle.write(b"\0" * (allocation - len(payload)))

    @classmethod
    def _rewrite_config_fixture(
        cls,
        source_archive: Path,
        destination_archive: Path,
        receipt: dict[str, object],
        config_bytes: bytes,
    ) -> dict[str, object]:
        config_name = f"blobs/sha256/{str(receipt['config_digest']).removeprefix('sha256:')}"
        manifest_name = f"blobs/sha256/{str(receipt['manifest_digest']).removeprefix('sha256:')}"
        with tarfile.open(source_archive, mode="r:") as archive:
            members = {member.name: member for member in archive.getmembers()}
            manifest = json.loads(archive.extractfile(members[manifest_name]).read())
            index = json.loads(archive.extractfile(members["index.json"]).read())
            docker_manifest = json.loads(archive.extractfile(members["manifest.json"]).read())
        if not destination_archive.exists():
            shutil.copyfile(source_archive, destination_archive)
        else:
            with source_archive.open("rb") as source, destination_archive.open("r+b") as target:
                for name in (config_name, manifest_name, "index.json", "manifest.json"):
                    member = members[name]
                    allocation = (member.size + 511) // 512 * 512
                    source.seek(member.offset)
                    target.seek(member.offset)
                    target.write(source.read(512 + allocation))

        config_digest = f"sha256:{builder.sha256(config_bytes).hexdigest()}"
        manifest["config"]["digest"] = config_digest
        manifest["config"]["size"] = len(config_bytes)
        manifest_bytes = builder._canonical_json(manifest)
        manifest_digest = f"sha256:{builder.sha256(manifest_bytes).hexdigest()}"
        index["manifests"][0]["digest"] = manifest_digest
        index["manifests"][0]["size"] = len(manifest_bytes)
        index["manifests"][0]["annotations"]["io.containerd.image.name"] = (
            f"docker.io/{builder.ASTRBOT_IMAGE_REPOSITORY}@{manifest_digest}"
        )
        index_bytes = builder._canonical_json(index)
        docker_manifest[0]["Config"] = (
            f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
        )
        docker_manifest_bytes = builder._canonical_json(docker_manifest)

        with destination_archive.open("r+b") as handle:
            cls._patch_tar_member(
                handle,
                members[config_name],
                f"blobs/sha256/{config_digest.removeprefix('sha256:')}",
                config_bytes,
            )
            cls._patch_tar_member(
                handle,
                members[manifest_name],
                f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}",
                manifest_bytes,
            )
            cls._patch_tar_member(handle, members["index.json"], "index.json", index_bytes)
            cls._patch_tar_member(
                handle,
                members["manifest.json"],
                "manifest.json",
                docker_manifest_bytes,
            )

        forged = copy.deepcopy(receipt)
        forged.update(
            {
                "archive_sha256": "0" * 64,
                "archive_size": destination_archive.stat().st_size,
                "config_digest": config_digest,
                "image_id": manifest_digest,
                "image_reference": (
                    f"{builder.ASTRBOT_IMAGE_REPOSITORY}@{manifest_digest}"
                ),
                "index_digest": f"sha256:{builder.sha256(index_bytes).hexdigest()}",
                "manifest_digest": manifest_digest,
            }
        )
        return forged

    @staticmethod
    def _config_authority_matrix(valid: dict[str, object]) -> list[tuple[int, str, bytes]]:
        cases: list[tuple[int, str, bytes]] = []

        def locate(value: object, path: tuple[object, ...]) -> tuple[object, object]:
            current = value
            for key in path[:-1]:
                current = current[key]  # type: ignore[index]
            return current, path[-1]

        def replace(row: int, label: str, path: tuple[object, ...], replacement: object) -> None:
            changed = copy.deepcopy(valid)
            parent, key = locate(changed, path)
            parent[key] = replacement  # type: ignore[index]
            cases.append((row, label, builder._canonical_json(changed)))

        def remove(row: int, label: str, path: tuple[object, ...]) -> None:
            changed = copy.deepcopy(valid)
            parent, key = locate(changed, path)
            del parent[key]  # type: ignore[index]
            cases.append((row, label, builder._canonical_json(changed)))

        config = valid["config"]
        rootfs = valid["rootfs"]
        history = valid["history"]
        assert isinstance(config, dict) and isinstance(rootfs, dict) and isinstance(history, list)

        for label, value in (
            ("value", ["python", "substituted.py"]),
            ("element_type", ["python", True]),
            ("order", list(reversed(config["Cmd"]))),
            ("empty", []),
            ("null", None),
        ):
            replace(1, label, ("config", "Cmd"), value)
        remove(1, "absent", ("config", "Cmd"))

        for label, value in (("changed", "/tmp"), ("empty", ""), ("null", None)):
            replace(2, label, ("config", "WorkingDir"), value)
        remove(2, "absent", ("config", "WorkingDir"))

        env = config["Env"]
        assert isinstance(env, list)
        for label, value in (
            ("value", ["PATH=/forged", *env[1:]]),
            ("reorder", list(reversed(env))),
            ("duplicate", [env[0], *env]),
            ("add", [*env, "MYUNA_FORGED=1"]),
            ("remove", env[:-1]),
            ("empty", []),
            ("null", None),
        ):
            replace(3, label, ("config", "Env"), value)
        remove(3, "absent", ("config", "Env"))

        absent_fields = {
            4: ("User", (None, "", "1000", {})),
            5: ("Entrypoint", (None, [], ["python"], "python")),
            6: ("Labels", (None, {}, {"owner": "forged"})),
            8: ("Volumes", (None, {}, {"/data": {}})),
            9: ("StopSignal", (None, "", "SIGTERM")),
            10: ("Healthcheck", (None, {}, {"Test": ["NONE"]})),
            11: ("Shell", (None, [], ["/bin/sh", "-c"])),
            12: ("OnBuild", (None, [], ["RUN true"])),
        }
        for row, (field, values) in absent_fields.items():
            for ordinal, value in enumerate(values, start=1):
                replace(row, f"variant_{ordinal}", ("config", field), value)

        exposed = config["ExposedPorts"]
        for label, value in (
            ("changed", {"6186/tcp": {}}),
            ("extra", {**exposed, "6186/tcp": {}}),
            ("empty", {}),
            ("null", None),
        ):
            replace(7, label, ("config", "ExposedPorts"), value)
        remove(7, "absent", ("config", "ExposedPorts"))

        for label, value in (("flip", False), ("non_bool", 1), ("null", None)):
            replace(13, label, ("config", "ArgsEscaped"), value)
        remove(13, "absent", ("config", "ArgsEscaped"))
        for label, value in (("null", None), ("empty", ""), ("value", "forged")):
            replace(14, label, ("config", "unexpected"), value)
        for label, value in (("null", None), ("empty", {}), ("wrong_type", [])):
            replace(15, label, ("config",), value)
        remove(15, "absent", ("config",))

        for label, value in (("value", "arm64"), ("case", "AMD64"), ("null", None), ("wrong_type", [])):
            replace(16, label, ("architecture",), value)
        remove(16, "absent", ("architecture",))
        for label, value in (("value", "windows"), ("case", "Linux"), ("null", None), ("wrong_type", [])):
            replace(17, label, ("os",), value)
        remove(17, "absent", ("os",))

        for label, value in (("changed", "forged"), ("null", None), ("wrong_type", [])):
            replace(18, label, ("rootfs", "type"), value)
        remove(18, "absent", ("rootfs", "type"))
        replace(18, "unknown", ("rootfs", "unexpected"), None)

        diff_ids = rootfs["diff_ids"]
        assert isinstance(diff_ids, list)
        for label, value in (
            ("change", ["sha256:" + "0" * 64, *diff_ids[1:]]),
            ("reorder", list(reversed(diff_ids))),
            ("duplicate", [diff_ids[0], *diff_ids]),
            ("remove", diff_ids[:-1]),
            ("add", [*diff_ids, "sha256:" + "1" * 64]),
            ("uppercase", [str(diff_ids[0]).upper(), *diff_ids[1:]]),
            ("wrong_type", "layers"),
        ):
            replace(19, label, ("rootfs", "diff_ids"), value)

        overlay = diff_ids[-1]
        for label, value in (
            ("change", [*diff_ids[:-1], "sha256:" + "2" * 64]),
            ("omit", diff_ids[:-1]),
            ("duplicate", [*diff_ids, overlay]),
            ("non_last", [*diff_ids[:-2], overlay, diff_ids[-2]]),
            ("receipt_self_consistent", [*diff_ids[:-1], "sha256:" + "3" * 64]),
        ):
            replace(20, label, ("rootfs", "diff_ids"), value)

        for label, value in (
            ("changed", "2026-08-20T20:39:28Z"),
            ("timezone", "2026-08-20T20:39:27+00:00"),
            ("fractional", "2026-08-20T20:39:27.0Z"),
            ("null", None),
            ("empty", ""),
        ):
            replace(21, label, ("created",), value)
        remove(21, "absent", ("created",))

        for label, value in (
            ("reorder", [history[1], history[0], *history[2:]]),
            ("drop", history[1:]),
            ("duplicate", [history[0], *history]),
            ("prepend", [{"created_by": "forged"}, *history]),
            ("insert", [*history[:2], {"created_by": "forged"}, *history[2:]]),
        ):
            replace(22, label, ("history",), value)

        inherited_fields = {
            23: (0, "created_by", ("forged", None, [], "__absent__")),
            24: (0, "created", ("2026-06-23T00:00:01Z", "2026-06-23T00:00:00+00:00", None, [], "__absent__")),
            25: (0, "comment", ("forged", "", None, [], "__absent__")),
        }
        for row, (index, field, values) in inherited_fields.items():
            for ordinal, value in enumerate(values, start=1):
                if value == "__absent__":
                    remove(row, f"absent_{ordinal}", ("history", index, field))
                else:
                    replace(row, f"variant_{ordinal}", ("history", index, field), value)

        for label, value in (("flip", False), ("bool_to_int", 1), ("null", None)):
            replace(26, label, ("history", 1, "empty_layer"), value)
        remove(26, "absent_where_present", ("history", 1, "empty_layer"))
        replace(26, "add_where_absent", ("history", 0, "empty_layer"), True)
        for label, value in (("null", None), ("empty", ""), ("value", "forged")):
            replace(27, label, ("history", 0, "author"), value)
            replace(28, label, ("history", 0, "unexpected"), value)

        for label, value in (
            ("not_last", [*history[:-2], history[-1], history[-2]]),
            ("multiple", [*history, history[-1]]),
            ("missing", history[:-1]),
        ):
            replace(29, label, ("history",), value)
        for row, field, values in (
            (30, "created_by", ("forged", None, [], "__absent__")),
            (31, "created", ("2026-08-20T20:39:28Z", "2026-08-20T20:39:27+00:00", None, "__absent__")),
            (32, "comment", ("forged", "", None, "__absent__")),
        ):
            for ordinal, value in enumerate(values, start=1):
                if value == "__absent__":
                    remove(row, f"absent_{ordinal}", ("history", -1, field))
                else:
                    replace(row, f"variant_{ordinal}", ("history", -1, field), value)
        for label, field, value in (
            ("empty_layer", "empty_layer", True),
            ("author", "author", "forged"),
            ("unknown_null", "unexpected", None),
            ("unknown_empty", "unexpected", {}),
            ("unknown_value", "unexpected", "forged"),
        ):
            replace(33, label, ("history", -1, field), value)

        for label, value in (("null", None), ("empty_string", ""), ("empty_list", []), ("empty_object", {}), ("value", "forged")):
            replace(34, label, ("unexpected",), value)
        for key in sorted(valid):
            remove(35, f"remove_{key}", (key,))

        noncanonical = builder._canonical_json(valid) + b" "
        cases.append((36, "noncanonical_bytes", noncanonical))
        if {row for row, _, _ in cases} != set(range(1, 37)):
            raise AssertionError("config authority matrix is incomplete")
        return cases

    def test_release_is_deterministic_complete_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = builder.build_release(ROOT, Path(first))
            two = builder.build_release(ROOT, Path(second))
            self.assertEqual(one, two)
            self.assertEqual(
                {entry["destination"] for entry in one["files"]},
                {destination for _, destination, _ in builder.COMPONENTS},
            )
            for output in (Path(first), Path(second)):
                release = output / one["release_digest"]
                manifest = output / f"{one['release_digest']}{builder.MANIFEST_SUFFIX}"
                self.assertTrue(builder.verify_release(output, one))
                self.assertEqual(release.stat().st_mode & 0o777, 0o555)
                self.assertEqual(manifest.stat().st_mode & 0o777, 0o444)
                self.assertEqual(json.loads(manifest.read_text()), one)
                actual = {
                    path.relative_to(release).as_posix()
                    for path in release.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(
                    actual,
                    {destination for _, destination, _ in builder.COMPONENTS},
                )
                self.assertFalse(any("__pycache__" in part for path in actual for part in Path(path).parts))

    def test_missing_symlink_and_extra_plugin_source_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            for relative, _, _ in builder.COMPONENTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            missing = root / builder.COMPONENTS[0][0]
            missing.unlink()
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder.build_release_document(root)

    def test_astrbot_overlay_is_exact_ustar_single_file(self) -> None:
        stage = b"content-free-stage\n"
        first = builder._overlay_tar(stage, builder.ASTRBOT_SOURCE_DATE_EPOCH)
        second = builder._overlay_tar(stage, builder.ASTRBOT_SOURCE_DATE_EPOCH)
        self.assertEqual(first, second)
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), 1)
            member = members[0]
            self.assertEqual(member.name, builder.ASTRBOT_STAGE_DESTINATION)
            self.assertTrue(member.isfile())
            self.assertEqual(member.mode, 0o644)
            self.assertEqual((member.uid, member.gid), (0, 0))
            self.assertEqual((member.uname, member.gname), ("", ""))
            self.assertEqual(member.mtime, builder.ASTRBOT_SOURCE_DATE_EPOCH)
            self.assertEqual(member.pax_headers, {})
            self.assertEqual(archive.extractfile(member).read(), stage)

    def test_astrbot_tool_source_epoch_and_output_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            work.mkdir()
            output = root / "output.tar"
            output.write_bytes(b"occupied")
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder.build_deterministic_astrbot_archive(
                    base_archive=root / "missing.tar",
                    astrbot_source_root=root,
                    work_root=work,
                    output_archive=output,
                    source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                    source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                    tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                )
            output.unlink()
            for wrong_commit, wrong_epoch, wrong_tools in (
                ("0" * 40, builder.ASTRBOT_SOURCE_DATE_EPOCH, builder.ASTRBOT_TOOL_IDENTITIES),
                (builder.ASTRBOT_SOURCE_COMMIT, builder.ASTRBOT_SOURCE_DATE_EPOCH + 1, builder.ASTRBOT_TOOL_IDENTITIES),
                (builder.ASTRBOT_SOURCE_COMMIT, builder.ASTRBOT_SOURCE_DATE_EPOCH, tuple()),
            ):
                with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                    builder.build_deterministic_astrbot_archive(
                        base_archive=root / "missing.tar",
                        astrbot_source_root=root,
                        work_root=work,
                        output_archive=output,
                        source_commit=wrong_commit,
                        source_date_epoch=wrong_epoch,
                        tool_identities=wrong_tools,
                    )

    def test_output_basename_rejects_ambiguous_values_before_any_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            work.mkdir()
            unrelated = root / "unrelated"
            unrelated.write_bytes(b"unchanged")
            expected_names = {"unrelated", "work"}

            malformed: tuple[tuple[str, object], ...] = (
                ("nul_prefix", root / "\0prefix.tar"),
                ("nul_middle", root / "candidate\0suffix.tar"),
                ("nul_suffix", root / "candidate.tar\0"),
                ("parent_nul", root / "parent\0suffix" / "candidate.tar"),
                ("str", str(root / "string.tar")),
                ("bytes", os.fsencode(root / "bytes.tar")),
                ("pure_path", PurePosixPath(root / "pure.tar")),
                ("unencodable_surrogate", root / f"candidate-{chr(0xD800)}.tar"),
            )
            for category, output in malformed:
                with self.subTest(category=category):
                    with (
                        mock.patch.object(
                            builder,
                            "_observe_tool_identities",
                            side_effect=AssertionError(
                                "malformed output must reject before tool observation"
                            ),
                        ),
                        mock.patch.object(
                            builder.os,
                            "open",
                            side_effect=AssertionError(
                                "malformed output must reject before output FD open"
                            ),
                        ) as open_mock,
                        mock.patch.object(
                            builder.os,
                            "close",
                            side_effect=AssertionError(
                                "malformed output must open no descriptor"
                            ),
                        ) as close_mock,
                        mock.patch.object(
                            builder,
                            "_LINKAT",
                            side_effect=AssertionError(
                                "malformed output must reject before publication"
                            ),
                        ) as linkat_mock,
                        mock.patch.object(
                            builder.tarfile,
                            "open",
                            side_effect=AssertionError(
                                "malformed output must reject before archive access"
                            ),
                        ),
                        mock.patch.object(
                            builder.subprocess,
                            "run",
                            side_effect=AssertionError(
                                "malformed output must reject before subprocess"
                            ),
                        ),
                    ):
                        with self.assertRaisesRegex(
                            builder.TelegramGatewayReleaseRejected,
                            "deterministic image output rejected",
                        ):
                            builder.build_deterministic_astrbot_archive(
                                base_archive=root / "missing.tar",
                                astrbot_source_root=root,
                                work_root=work,
                                output_archive=output,
                                source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                                source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                                tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                            )
                    open_mock.assert_not_called()
                    close_mock.assert_not_called()
                    linkat_mock.assert_not_called()
                    self.assertEqual({path.name for path in root.iterdir()}, expected_names)
                    self.assertEqual(unrelated.read_bytes(), b"unchanged")

            encoded_malformed: tuple[tuple[str, object], ...] = (
                ("empty", b""),
                ("dot", b"."),
                ("dotdot", b".."),
                ("separator", b"nested/candidate.tar"),
                ("nul", b"candidate\0suffix.tar"),
                ("non_bytes", bytearray(b"candidate.tar")),
                ("non_roundtrip", b"different.tar"),
            )
            real_fsencode = builder.os.fsencode
            for category, encoded in encoded_malformed:
                with self.subTest(category=category):
                    output = root / f"encoded-{category}.tar"
                    basename_calls: list[str] = []

                    def substitute_basename(value: object) -> object:
                        if value == output.name:
                            basename_calls.append(value)
                            return encoded
                        return real_fsencode(value)

                    with (
                        mock.patch.object(builder.os, "fsencode", side_effect=substitute_basename),
                        mock.patch.object(
                            builder,
                            "_observe_tool_identities",
                            side_effect=AssertionError(
                                "ambiguous encoding must reject before tool observation"
                            ),
                        ),
                        mock.patch.object(
                            builder.os,
                            "open",
                            side_effect=AssertionError(
                                "ambiguous encoding must reject before output FD open"
                            ),
                        ) as open_mock,
                        mock.patch.object(
                            builder,
                            "_LINKAT",
                            side_effect=AssertionError(
                                "ambiguous encoding must reject before publication"
                            ),
                        ) as linkat_mock,
                    ):
                        with self.assertRaisesRegex(
                            builder.TelegramGatewayReleaseRejected,
                            "deterministic image output rejected",
                        ):
                            builder.build_deterministic_astrbot_archive(
                                base_archive=root / "missing.tar",
                                astrbot_source_root=root,
                                work_root=work,
                                output_archive=output,
                                source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                                source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                                tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                            )
                    self.assertEqual(basename_calls, [output.name])
                    open_mock.assert_not_called()
                    linkat_mock.assert_not_called()
                    self.assertEqual({path.name for path in root.iterdir()}, expected_names)

            for name in ("candidate-文件.tar", f"candidate-{chr(0xDC80)}.tar"):
                with self.subTest(valid_roundtrip=name):
                    output = root / name
                    basename_calls: list[str] = []
                    real_observe = builder._observe_tool_identities

                    def record_valid_basename(value: object) -> bytes:
                        if value == output.name:
                            basename_calls.append(value)
                        return real_fsencode(value)

                    with (
                        mock.patch.object(builder.os, "fsencode", side_effect=record_valid_basename),
                        mock.patch.object(
                            builder,
                            "_observe_tool_identities",
                            side_effect=RuntimeError("validated output basename"),
                        ) as observe_mock,
                        mock.patch.object(
                            builder.os,
                            "open",
                            side_effect=AssertionError(
                                "marker must stop before descriptor open"
                            ),
                        ),
                        mock.patch.object(
                            builder,
                            "_LINKAT",
                            side_effect=AssertionError(
                                "marker must stop before publication"
                            ),
                        ) as linkat_mock,
                    ):
                        with self.assertRaisesRegex(RuntimeError, "validated output basename"):
                            builder.build_deterministic_astrbot_archive(
                                base_archive=root / "missing.tar",
                                astrbot_source_root=root,
                                work_root=work,
                                output_archive=output,
                                source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                                source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                                tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                            )
                    self.assertEqual(basename_calls, [output.name])
                    self.assertEqual(observe_mock.call_count, 1)
                    linkat_mock.assert_not_called()
                    self.assertEqual({path.name for path in root.iterdir()}, expected_names)

    def test_astrbot_tool_identity_is_observed_and_fail_closed(self) -> None:
        observed, descriptors = builder._observe_tool_identities(
            builder.ASTRBOT_TOOL_IDENTITIES
        )
        self.assertEqual(observed, builder.ASTRBOT_TOOL_IDENTITIES)
        self.assertEqual(descriptors, ())
        self.assertEqual(
            [entry[1] for entry in observed],
            ["/usr/bin/docker", "/usr/bin/python3.12"],
        )
        for entry in observed:
            self.assertEqual(len(entry[3]), 64)
            self.assertEqual(entry[3], entry[3].lower())

        adversarial = []
        for ordinal in range(2):
            truncated = [list(entry) for entry in observed]
            truncated[ordinal][3] = truncated[ordinal][3][:-1]
            adversarial.append((f"tool_{ordinal}_digest_63", truncated))
            different = [list(entry) for entry in observed]
            different[ordinal][3] = "0" * 64
            adversarial.append((f"tool_{ordinal}_different_64", different))
            uppercase = [list(entry) for entry in observed]
            uppercase[ordinal][3] = uppercase[ordinal][3].upper()
            adversarial.append((f"tool_{ordinal}_uppercase", uppercase))
            changed_path = [list(entry) for entry in observed]
            changed_path[ordinal][1] += ".substituted"
            adversarial.append((f"tool_{ordinal}_path", changed_path))
        adversarial.append(("swapped", [list(observed[1]), list(observed[0])]))
        adversarial.append(("wrong_type", [list(observed[0]), list(observed[1])]))
        adversarial[-1][1][1][2] = True
        for category, values in adversarial:
            claim = tuple(tuple(entry) for entry in values)
            with self.subTest(category=category):
                with mock.patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=AssertionError("invalid claim must reject before execution"),
                ):
                    with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                        builder._observe_tool_identities(claim)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker = root / "docker"
            python = root / "python3.12"
            shutil.copyfile(observed[0][1], docker)
            shutil.copyfile(observed[1][1], python)
            docker.chmod(0o755)
            python.chmod(0o755)
            local_identities = (
                (observed[0][0], docker.as_posix(), observed[0][2], observed[0][3]),
                (observed[1][0], python.as_posix(), observed[1][2], observed[1][3]),
            )
            replacement = root / "docker-replacement"
            shutil.copyfile(docker, replacement)
            replacement.chmod(0o755)

            def replace_path_during_version(*args: object, **kwargs: object) -> object:
                os.replace(replacement, docker)
                return builder.subprocess.CompletedProcess(
                    args[0],
                    0,
                    stdout=(builder._ASTRBOT_TOOL_VERSION_OUTPUTS[0] + "\n").encode(),
                )

            with (
                mock.patch.object(builder, "ASTRBOT_TOOL_IDENTITIES", local_identities),
                mock.patch.object(
                    builder,
                    "_ASTRBOT_TOOL_SIZES",
                    (docker.stat().st_size, python.stat().st_size),
                ),
                mock.patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=replace_path_during_version,
                ),
            ):
                with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                    builder._observe_tool_identities(local_identities)

            docker_inplace = root / "docker-inplace"
            python_inplace = root / "python-inplace"
            shutil.copyfile(observed[0][1], docker_inplace)
            shutil.copyfile(observed[1][1], python_inplace)
            docker_inplace.chmod(0o755)
            python_inplace.chmod(0o755)
            inplace_identities = (
                (
                    observed[0][0],
                    docker_inplace.as_posix(),
                    observed[0][2],
                    observed[0][3],
                ),
                (
                    observed[1][0],
                    python_inplace.as_posix(),
                    observed[1][2],
                    observed[1][3],
                ),
            )

            def mutate_bytes_during_version(*args: object, **kwargs: object) -> object:
                with docker_inplace.open("r+b") as handle:
                    handle.seek(-1, os.SEEK_END)
                    byte = handle.read(1)
                    handle.seek(-1, os.SEEK_END)
                    handle.write(bytes((byte[0] ^ 1,)))
                return builder.subprocess.CompletedProcess(
                    args[0],
                    0,
                    stdout=(builder._ASTRBOT_TOOL_VERSION_OUTPUTS[0] + "\n").encode(),
                )

            with (
                mock.patch.object(builder, "ASTRBOT_TOOL_IDENTITIES", inplace_identities),
                mock.patch.object(
                    builder,
                    "_ASTRBOT_TOOL_SIZES",
                    (docker_inplace.stat().st_size, python_inplace.stat().st_size),
                ),
                mock.patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=mutate_bytes_during_version,
                ),
            ):
                with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                    builder._observe_tool_identities(inplace_identities)

    def test_current_python_execution_entity_is_part_of_tool_authority(self) -> None:
        observed, retained = builder._observe_tool_identities(
            builder.ASTRBOT_TOOL_IDENTITIES,
            retain=True,
        )
        try:
            self.assertEqual(observed, builder.ASTRBOT_TOOL_IDENTITIES)
            self.assertEqual(len(retained), 3)
            configured = os.fstat(retained[1])
            current = os.fstat(retained[2])
            self.assertEqual(
                (current.st_dev, current.st_ino, current.st_mode, current.st_size),
                (configured.st_dev, configured.st_ino, configured.st_mode, configured.st_size),
            )
            self.assertEqual(
                os.readlink("/proc/self/exe"),
                builder.ASTRBOT_TOOL_IDENTITIES[1][1],
            )
        finally:
            for descriptor in retained:
                os.close(descriptor)

        for category, executable in (
            ("empty", ""),
            ("relative", "python3.12"),
            ("different_absolute", "/usr/local/bin/python3.12"),
        ):
            with self.subTest(sys_executable=category):
                with (
                    mock.patch.object(builder.sys, "executable", executable),
                    mock.patch.object(
                        builder.subprocess,
                        "run",
                        side_effect=AssertionError("execution-entity rejection must precede subprocess"),
                    ),
                ):
                    with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                        builder._observe_tool_identities(builder.ASTRBOT_TOOL_IDENTITIES)

        real_readlink = builder.os.readlink

        def substituted_proc_link(path: object) -> str:
            if os.fspath(path) == "/proc/self/exe":
                return builder.ASTRBOT_TOOL_IDENTITIES[1][1] + " (deleted)"
            return real_readlink(path)

        with (
            mock.patch.object(builder.os, "readlink", side_effect=substituted_proc_link),
            mock.patch.object(
                builder.subprocess,
                "run",
                side_effect=AssertionError("execution-entity rejection must precede subprocess"),
            ),
        ):
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder._observe_tool_identities(builder.ASTRBOT_TOOL_IDENTITIES)

    def test_public_verifier_and_loader_retain_tool_authority_until_return(self) -> None:
        real_observe = builder._observe_tool_identities
        retained_by_entry: list[tuple[int, ...]] = []

        def record_observation(*args: object, **kwargs: object) -> object:
            result = real_observe(*args, **kwargs)
            if kwargs.get("retain") is True and not kwargs.get("retained_fds"):
                self.assertEqual(len(result[1]), 3)
                retained_by_entry.append(result[1])
            return result

        missing = Path("missing-canonical-astra-archive.tar")
        with mock.patch.object(builder, "_observe_tool_identities", side_effect=record_observation):
            self.assertFalse(
                builder.verify_deterministic_astrbot_archive(missing, self._receipt_shape())
            )
        verifier_descriptors = retained_by_entry.pop()
        for descriptor in verifier_descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

        with mock.patch.object(builder, "_observe_tool_identities", side_effect=record_observation):
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder.load_and_verify_deterministic_astrbot_archive(
                    missing,
                    self._receipt_shape(),
                    docker_binary=Path(builder.ASTRBOT_TOOL_IDENTITIES[0][1]),
                )
        loader_descriptors = retained_by_entry.pop()
        for descriptor in loader_descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        self.assertEqual(retained_by_entry, [])

    def test_anonymous_output_publishes_exact_inode_and_never_replaces_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent_descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            output_descriptor = -1
            second_descriptor = -1
            try:
                output_descriptor = os.open(
                    ".",
                    os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                os.write(output_descriptor, b"owned-output")
                os.fsync(output_descriptor)
                original = os.fstat(output_descriptor)
                self.assertFalse((root / "candidate.tar").exists())
                builder.ctypes.set_errno(0)
                self.assertEqual(
                    builder._LINKAT(
                        output_descriptor,
                        b"",
                        parent_descriptor,
                        b"candidate.tar",
                        builder._AT_EMPTY_PATH,
                    ),
                    0,
                )
                os.fsync(parent_descriptor)
                published = os.stat(
                    "candidate.tar",
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                self.assertEqual(
                    (published.st_dev, published.st_ino),
                    (original.st_dev, original.st_ino),
                )
                self.assertEqual((root / "candidate.tar").read_bytes(), b"owned-output")

                second_descriptor = os.open(
                    ".",
                    os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                os.write(second_descriptor, b"unknown-replacement")
                os.fsync(second_descriptor)
                builder.ctypes.set_errno(0)
                self.assertEqual(
                    builder._LINKAT(
                        second_descriptor,
                        b"",
                        parent_descriptor,
                        b"candidate.tar",
                        builder._AT_EMPTY_PATH,
                    ),
                    -1,
                )
                self.assertEqual(builder.ctypes.get_errno(), errno.EEXIST)
                self.assertEqual((root / "candidate.tar").read_bytes(), b"owned-output")
            finally:
                if second_descriptor >= 0:
                    os.close(second_descriptor)
                if output_descriptor >= 0:
                    os.close(output_descriptor)
                os.close(parent_descriptor)
            with self.assertRaises(OSError):
                os.fstat(second_descriptor)
            with self.assertRaises(OSError):
                os.fstat(output_descriptor)
            with self.assertRaises(OSError):
                os.fstat(parent_descriptor)
            self.assertEqual((root / "candidate.tar").read_bytes(), b"owned-output")

    def test_astrbot_receipt_authority_rejects_substitution_before_archive_or_docker(self) -> None:
        substitutions = self._receipt_substitutions()
        for field, value in substitutions.items():
            with self.subTest(field=field):
                forged = self._receipt_shape()
                forged[field] = value
                with mock.patch.object(
                    builder,
                    "_sha256_file",
                    side_effect=AssertionError("receipt rejection must precede archive access"),
                ):
                    self.assertFalse(
                        builder.verify_deterministic_astrbot_archive(Path("missing.tar"), forged)
                    )

        malformed = []
        for field in self._receipt_shape():
            missing = self._receipt_shape()
            missing.pop(field)
            malformed.append((f"missing_{field}", missing))
        unknown = self._receipt_shape()
        unknown["unexpected"] = "value"
        malformed.append(("unknown", unknown))
        for field in self._receipt_shape():
            wrong_type = self._receipt_shape()
            wrong_type[field] = True
            malformed.append((f"wrong_type_{field}", wrong_type))
        duplicate_layer = self._receipt_shape()
        duplicate_layer["layers"][1] = dict(duplicate_layer["layers"][0])
        malformed.append(("duplicate", duplicate_layer))
        noncanonical = self._receipt_shape()
        noncanonical["archive_sha256"] = "B" * 64
        malformed.append(("noncanonical", noncanonical))
        for category, forged in malformed:
            with self.subTest(category=category):
                with mock.patch.object(
                    builder,
                    "_sha256_file",
                    side_effect=AssertionError("receipt rejection must precede archive access"),
                ):
                    self.assertFalse(
                        builder.verify_deterministic_astrbot_archive(Path("missing.tar"), forged)
                    )

        canonical_tools = self._receipt_shape()["tools"]
        tool_forgery_rows = []
        for ordinal in range(2):
            for category, value in (
                ("digest_63", canonical_tools[ordinal]["sha256"][:-1]),
                ("different_64", "0" * 64),
                ("uppercase", canonical_tools[ordinal]["sha256"].upper()),
                ("path", canonical_tools[ordinal]["path"] + ".substituted"),
            ):
                tools = copy.deepcopy(canonical_tools)
                tools[ordinal]["sha256" if category != "path" else "path"] = value
                tool_forgery_rows.append((f"tool_{ordinal}_{category}", tools))
        tool_forgery_rows.append(("tools_swapped", list(reversed(canonical_tools))))
        for category, tools in tool_forgery_rows:
            with self.subTest(category=category):
                forged = self._receipt_shape()
                forged["tools"] = tools
                with mock.patch.object(
                    builder,
                    "_sha256_file",
                    side_effect=AssertionError("tool rejection must precede archive access"),
                ):
                    self.assertFalse(
                        builder.verify_deterministic_astrbot_archive(Path("missing.tar"), forged)
                    )

        fake_docker = Path(builder.ASTRBOT_TOOL_IDENTITIES[0][1])
        for field, value in substitutions.items():
            with self.subTest(pre_docker=field):
                forged = self._receipt_shape()
                forged[field] = value

                def identity_only(path: Path) -> tuple[str, int]:
                    if path == fake_docker:
                        return builder.ASTRBOT_TOOL_IDENTITIES[0][3], 1
                    raise AssertionError("receipt rejection must precede archive access")

                with (
                    mock.patch.object(builder, "_sha256_file", side_effect=identity_only),
                    mock.patch.object(
                        builder.subprocess,
                        "run",
                        side_effect=AssertionError(
                            "receipt rejection must precede Docker subprocess"
                        ),
                    ),
                ):
                    with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                        builder.load_and_verify_deterministic_astrbot_archive(
                            Path("missing.tar"),
                            forged,
                            docker_binary=fake_docker,
                        )

    @unittest.skipUnless(
        os.environ.get("MYUNA_ASTRBOT_BASE_ARCHIVE_1")
        and os.environ.get("MYUNA_ASTRBOT_BASE_ARCHIVE_2")
        and os.environ.get("MYUNA_ASTRBOT_SOURCE_ROOT_1")
        and os.environ.get("MYUNA_ASTRBOT_SOURCE_ROOT_2"),
        "deterministic AstrBot integration inputs are not configured",
    )
    def test_two_independent_astrbot_archives_are_byte_exact(self) -> None:
        base_archives = (
            Path(os.environ["MYUNA_ASTRBOT_BASE_ARCHIVE_1"]),
            Path(os.environ["MYUNA_ASTRBOT_BASE_ARCHIVE_2"]),
        )
        source_roots = (
            Path(os.environ["MYUNA_ASTRBOT_SOURCE_ROOT_1"]),
            Path(os.environ["MYUNA_ASTRBOT_SOURCE_ROOT_2"]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_observe = builder._observe_tool_identities
            real_open = builder.os.open
            real_close = builder.os.close
            real_fsync = builder.os.fsync
            real_linkat = builder._LINKAT
            real_private_verify = builder._verify_deterministic_astrbot_archive_under_authority
            receipts = []
            archive_identities = []
            for ordinal, (base_archive, source_root) in enumerate(
                zip(base_archives, source_roots, strict=True),
                start=1,
            ):
                work = root / f"work-{ordinal}"
                work.mkdir()
                archive = root / f"candidate-{ordinal}.tar"
                authority_calls: list[
                    tuple[bool, tuple[int, ...], tuple[int, ...]]
                ] = []
                parent_descriptors: list[int] = []
                output_descriptors: list[int] = []
                close_counts: dict[int, int] = {}
                nested_output_verification: list[bool] = []

                def record_build_authority(*args: object, **kwargs: object) -> object:
                    result = real_observe(*args, **kwargs)
                    authority_calls.append(
                        (
                            kwargs.get("retain") is True,
                            kwargs.get("retained_fds", ()),
                            result[1],
                        )
                    )
                    return result

                def record_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    if (
                        os.fspath(path) == os.fspath(archive.parent)
                        and flags & os.O_DIRECTORY
                    ):
                        parent_descriptors.append(descriptor)
                    elif (
                        os.fspath(path) == "."
                        and flags & os.O_TMPFILE
                        and dir_fd in parent_descriptors
                    ):
                        output_descriptors.append(descriptor)
                    return descriptor

                def record_close(descriptor: int) -> None:
                    if descriptor in {*parent_descriptors, *output_descriptors}:
                        close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                    real_close(descriptor)

                def record_private_verify(
                    archive_path: Path,
                    receipt: dict[str, object],
                    **kwargs: object,
                ) -> bool:
                    if output_descriptors and archive_path == Path(
                        f"/proc/self/fd/{output_descriptors[0]}"
                    ):
                        self.assertFalse(archive.exists())
                        os.fstat(parent_descriptors[0])
                        os.fstat(output_descriptors[0])
                        nested_output_verification.append(True)
                    return real_private_verify(archive_path, receipt, **kwargs)

                with (
                    mock.patch.object(
                        builder,
                        "_observe_tool_identities",
                        side_effect=record_build_authority,
                    ),
                    mock.patch.object(builder.os, "open", side_effect=record_open),
                    mock.patch.object(builder.os, "close", side_effect=record_close),
                    mock.patch.object(
                        builder,
                        "_verify_deterministic_astrbot_archive_under_authority",
                        side_effect=record_private_verify,
                    ),
                ):
                    receipt = builder.build_deterministic_astrbot_archive(
                        base_archive=base_archive,
                        astrbot_source_root=source_root,
                        work_root=work,
                        output_archive=archive,
                        source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                        source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                        tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                    )
                self.assertGreaterEqual(len(authority_calls), 10)
                self.assertTrue(all(call[0] for call in authority_calls))
                acquired = authority_calls[0][2]
                self.assertEqual(len(acquired), 3)
                self.assertEqual(authority_calls[0][1], ())
                self.assertTrue(
                    all(call[1] == acquired and call[2] == acquired for call in authority_calls[1:])
                )
                self.assertEqual(len(parent_descriptors), 1)
                self.assertEqual(len(output_descriptors), 1)
                self.assertEqual(nested_output_verification, [True])
                self.assertEqual(close_counts[parent_descriptors[0]], 1)
                self.assertEqual(close_counts[output_descriptors[0]], 1)
                for descriptor in acquired:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                for descriptor in (*parent_descriptors, *output_descriptors):
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                self.assertTrue(builder.verify_deterministic_astrbot_archive(archive, receipt))
                receipts.append(receipt)
                archive_identities.append(builder._sha256_file(archive))
            self.assertEqual(receipts, [receipts[0], receipts[0]])
            self.assertEqual(archive_identities[0], archive_identities[1])
            self.assertEqual(
                archive_identities[0],
                ("6b0e6db3717a654628db0e831c7cc969ab3609d753d4b2f69ac92f249eb86259", 644167680),
            )
            self.assertEqual(len(receipts[0]["layers"]), 9)
            self.assertEqual(receipts[0]["dockerfile_sha256"], builder.ASTRBOT_DOCKERFILE_SHA256)
            self.assertEqual(receipts[0]["image_id"], receipts[0]["manifest_digest"])
            self.assertEqual(
                receipts[0]["image_id"],
                "sha256:ef2d2f966745b6d2e05b3286698bf6601a9a2c478f762b6b0df9703eee48d214",
            )
            copied_python = root / "python3.12-copy"
            shutil.copyfile(builder.ASTRBOT_TOOL_IDENTITIES[1][1], copied_python)
            copied_python.chmod(0o755)
            copied_output = root / "copied-interpreter-output.tar"
            receipt_path = root / "receipt.json"
            receipt_path.write_bytes(builder._canonical_json(receipts[0]))
            script = "\n".join(
                (
                    "import json,pathlib,sys,tempfile",
                    f"sys.path.insert(0,{str((ROOT / 'scripts').resolve())!r})",
                    "import build_telegram_gateway_release_v1 as builder",
                    f"receipt=json.loads(pathlib.Path({str(receipt_path)!r}).read_text(encoding='ascii'))",
                    f"assert builder.verify_deterministic_astrbot_archive(pathlib.Path({str(root / 'candidate-1.tar')!r}),receipt) is False",
                    f"work=pathlib.Path({str(root / 'copied-work')!r});work.mkdir()",
                    "try:",
                    " builder.build_deterministic_astrbot_archive(",
                    f"  base_archive=pathlib.Path({str(base_archives[0])!r}),",
                    f"  astrbot_source_root=pathlib.Path({str(source_roots[0])!r}),",
                    "  work_root=work,",
                    f"  output_archive=pathlib.Path({str(copied_output)!r}),",
                    "  source_commit=builder.ASTRBOT_SOURCE_COMMIT,",
                    "  source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,",
                    "  tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,",
                    " )",
                    "except builder.TelegramGatewayReleaseRejected as exc:",
                    " assert str(exc)=='deterministic image tool identity rejected'",
                    "else:",
                    " raise AssertionError('copied interpreter was accepted')",
                    "print('COPIED_PYTHON_ENTITY_REJECTED')",
                )
            )
            copied = builder.subprocess.run(
                [copied_python.as_posix(), "-I", "-B", "-c", script],
                stdout=builder.subprocess.PIPE,
                stderr=builder.subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(copied.returncode, 0, copied.stderr.decode("utf-8", errors="replace"))
            self.assertEqual(copied.stdout, b"COPIED_PYTHON_ENTITY_REJECTED\n")
            self.assertFalse(copied_output.exists())

            late_output = root / "late-authority-output.tar"
            late_work = root / "late-authority-work"
            late_work.mkdir()
            builder_descriptors: list[tuple[int, ...]] = []
            replace_after_output = os.environ.get("PYTHONHASHSEED") == "29"
            replacement_sentinel = b"unknown-output-replacement"
            replacement_attempts: list[tuple[int, int]] = []

            def reject_after_output(*args: object, **kwargs: object) -> object:
                result = real_observe(*args, **kwargs)
                if kwargs.get("retain") is True and not kwargs.get("retained_fds"):
                    builder_descriptors.append(result[1])
                if late_output.exists():
                    if replace_after_output:
                        original = late_output.lstat()
                        late_output.unlink()
                        for ordinal in range(128):
                            replacement_descriptor = os.open(
                                late_output,
                                os.O_WRONLY
                                | os.O_CREAT
                                | os.O_EXCL
                                | os.O_CLOEXEC
                                | os.O_NOFOLLOW,
                                0o600,
                            )
                            try:
                                replacement = os.fstat(replacement_descriptor)
                                replacement_attempts.append(
                                    (replacement.st_dev, replacement.st_ino)
                                )
                                self.assertNotEqual(
                                    (replacement.st_dev, replacement.st_ino),
                                    (original.st_dev, original.st_ino),
                                )
                                if ordinal == 127:
                                    os.write(replacement_descriptor, replacement_sentinel)
                                    os.fsync(replacement_descriptor)
                            finally:
                                os.close(replacement_descriptor)
                            if ordinal != 127:
                                late_output.unlink()
                    raise builder.TelegramGatewayReleaseRejected(
                        "injected late tool authority drift"
                    )
                return result

            with mock.patch.object(
                builder,
                "_observe_tool_identities",
                side_effect=reject_after_output,
            ):
                expected_error = "deterministic image output publication ambiguous"
                with self.assertRaisesRegex(builder.TelegramGatewayReleaseRejected, expected_error):
                    builder.build_deterministic_astrbot_archive(
                        base_archive=base_archives[0],
                        astrbot_source_root=source_roots[0],
                        work_root=late_work,
                        output_archive=late_output,
                        source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                        source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                        tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                    )
            if replace_after_output:
                self.assertEqual(len(replacement_attempts), 128)
                self.assertEqual(late_output.read_bytes(), replacement_sentinel)
            else:
                self.assertEqual(
                    builder._sha256_file(late_output),
                    (
                        "6b0e6db3717a654628db0e831c7cc969ab3609d753d4b2f69ac92f249eb86259",
                        644167680,
                    ),
                )
            self.assertEqual(len(builder_descriptors), 1)
            for descriptor in builder_descriptors[0]:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            real_write_tar_file = builder._write_tar_file

            def synthetic_copy_layer(
                archive: tarfile.TarFile,
                member: tarfile.TarInfo,
                destination: Path,
                expected_digest: str,
            ) -> None:
                del archive, member, expected_digest
                destination.write_bytes(b"synthetic-source-layer")

            def synthetic_recompress_layer(
                source: Path,
                raw: Path,
                destination: Path,
                expected_diff_id: str,
            ) -> tuple[str, int]:
                self.assertTrue(source.is_file())
                raw.write_bytes(b"synthetic-raw-layer")
                payload = expected_diff_id.encode("ascii")
                destination.write_bytes(payload)
                return f"sha256:{builder.sha256(payload).hexdigest()}", len(payload)

            def run_synthetic_output_failure(
                label: str,
                output: Path,
                *,
                observer: object = real_observe,
                verifier: object = real_private_verify,
                writer: object = real_write_tar_file,
                publisher: object = real_linkat,
                fsync: object = real_fsync,
                expect_descriptors: bool = True,
            ) -> BaseException:
                work = root / f"synthetic-{label}-work"
                work.mkdir()
                parent_descriptors: list[int] = []
                output_descriptors: list[int] = []
                close_counts: dict[int, int] = {}

                def record_synthetic_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    if (
                        os.fspath(path) == os.fspath(output.parent)
                        and flags & os.O_DIRECTORY
                    ):
                        parent_descriptors.append(descriptor)
                    elif (
                        os.fspath(path) == "."
                        and flags & os.O_TMPFILE
                        and dir_fd in parent_descriptors
                    ):
                        output_descriptors.append(descriptor)
                    return descriptor

                def record_synthetic_close(descriptor: int) -> None:
                    if descriptor in {*parent_descriptors, *output_descriptors}:
                        close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                    real_close(descriptor)

                caught: BaseException | None = None
                with (
                    mock.patch.object(
                        builder,
                        "_copy_member_to_file",
                        side_effect=synthetic_copy_layer,
                    ),
                    mock.patch.object(
                        builder,
                        "_recompress_layer",
                        side_effect=synthetic_recompress_layer,
                    ),
                    mock.patch.object(builder, "_observe_tool_identities", side_effect=observer),
                    mock.patch.object(
                        builder,
                        "_verify_deterministic_astrbot_archive_under_authority",
                        side_effect=verifier,
                    ),
                    mock.patch.object(builder, "_write_tar_file", side_effect=writer),
                    mock.patch.object(builder, "_LINKAT", side_effect=publisher),
                    mock.patch.object(builder.os, "open", side_effect=record_synthetic_open),
                    mock.patch.object(builder.os, "close", side_effect=record_synthetic_close),
                    mock.patch.object(builder.os, "fsync", side_effect=fsync),
                ):
                    try:
                        builder.build_deterministic_astrbot_archive(
                            base_archive=base_archives[0],
                            astrbot_source_root=source_roots[0],
                            work_root=work,
                            output_archive=output,
                            source_commit=builder.ASTRBOT_SOURCE_COMMIT,
                            source_date_epoch=builder.ASTRBOT_SOURCE_DATE_EPOCH,
                            tool_identities=builder.ASTRBOT_TOOL_IDENTITIES,
                        )
                    except BaseException as exc:
                        caught = exc
                self.assertIsNotNone(caught)
                self.assertEqual(len(parent_descriptors), 1 if expect_descriptors else 0)
                self.assertEqual(len(output_descriptors), 1 if expect_descriptors else 0)
                for descriptor in (*parent_descriptors, *output_descriptors):
                    self.assertEqual(close_counts[descriptor], 1)
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                return caught

            def accept_synthetic_verification(*args: object, **kwargs: object) -> bool:
                del args, kwargs
                return True

            missing_output = root / "missing-name-output.tar"

            def remove_name_after_output(*args: object, **kwargs: object) -> object:
                result = real_observe(*args, **kwargs)
                if missing_output.exists():
                    missing_output.unlink()
                    raise builder.TelegramGatewayReleaseRejected("injected missing output name")
                return result

            missing_error = run_synthetic_output_failure(
                "missing-name",
                missing_output,
                observer=remove_name_after_output,
                verifier=accept_synthetic_verification,
            )
            self.assertIsInstance(missing_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(missing_error),
                "deterministic image output publication ambiguous",
            )
            self.assertFalse(missing_output.exists())

            replaced_output = root / "different-inode-output.tar"
            replaced_sentinel = b"different-inode-replacement"

            def replace_name_after_output(*args: object, **kwargs: object) -> object:
                result = real_observe(*args, **kwargs)
                if replaced_output.exists():
                    original = replaced_output.lstat()
                    replaced_output.unlink()
                    replaced_output.write_bytes(replaced_sentinel)
                    replacement = replaced_output.lstat()
                    self.assertNotEqual(
                        (replacement.st_dev, replacement.st_ino),
                        (original.st_dev, original.st_ino),
                    )
                    raise builder.TelegramGatewayReleaseRejected(
                        "injected different output object"
                    )
                return result

            replaced_error = run_synthetic_output_failure(
                "different-inode",
                replaced_output,
                observer=replace_name_after_output,
                verifier=accept_synthetic_verification,
            )
            self.assertIsInstance(replaced_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(replaced_error),
                "deterministic image output publication ambiguous",
            )
            self.assertEqual(replaced_output.read_bytes(), replaced_sentinel)

            preexisting_output = root / "preexisting-output.tar"
            preexisting_sentinel = b"preexisting-output"
            preexisting_output.write_bytes(preexisting_sentinel)
            preexisting_error = run_synthetic_output_failure(
                "preexisting",
                preexisting_output,
                verifier=accept_synthetic_verification,
                expect_descriptors=False,
            )
            self.assertIsInstance(preexisting_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(preexisting_error),
                "deterministic image output rejected",
            )
            self.assertEqual(preexisting_output.read_bytes(), preexisting_sentinel)

            concurrent_output = root / "concurrent-output.tar"
            concurrent_sentinel = b"concurrent-output"

            def create_concurrent_target(
                old_descriptor: int,
                old_path: bytes,
                parent_descriptor: int,
                new_path: bytes,
                flags: int,
            ) -> int:
                replacement_descriptor = real_open(
                    new_path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                try:
                    os.write(replacement_descriptor, concurrent_sentinel)
                    real_fsync(replacement_descriptor)
                finally:
                    real_close(replacement_descriptor)
                return real_linkat(
                    old_descriptor,
                    old_path,
                    parent_descriptor,
                    new_path,
                    flags,
                )

            concurrent_error = run_synthetic_output_failure(
                "concurrent",
                concurrent_output,
                publisher=create_concurrent_target,
                verifier=accept_synthetic_verification,
            )
            self.assertIsInstance(concurrent_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(concurrent_error),
                "deterministic image output publication rejected",
            )
            self.assertEqual(concurrent_output.read_bytes(), concurrent_sentinel)

            lost_return_output = root / "lost-return-output.tar"

            def publish_then_lose_return(*args: object) -> int:
                self.assertEqual(real_linkat(*args), 0)
                builder.ctypes.set_errno(errno.EIO)
                return -1

            lost_return_error = run_synthetic_output_failure(
                "lost-return",
                lost_return_output,
                publisher=publish_then_lose_return,
                verifier=accept_synthetic_verification,
            )
            self.assertIsInstance(lost_return_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(lost_return_error),
                "deterministic image output publication rejected",
            )
            self.assertTrue(lost_return_output.is_file())

            parent_fsync_output = root / "parent-fsync-output.tar"

            def fail_parent_fsync_after_publication(descriptor: int) -> None:
                if parent_fsync_output.exists():
                    raise OSError("injected parent fsync failure")
                real_fsync(descriptor)

            parent_fsync_error = run_synthetic_output_failure(
                "parent-fsync",
                parent_fsync_output,
                verifier=accept_synthetic_verification,
                fsync=fail_parent_fsync_after_publication,
            )
            self.assertIsInstance(parent_fsync_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(parent_fsync_error),
                "deterministic image output publication ambiguous",
            )
            self.assertTrue(parent_fsync_output.is_file())

            short_output = root / "short-write-output.tar"

            def reject_tar_write(*args: object, **kwargs: object) -> None:
                del args, kwargs
                self.assertFalse(short_output.exists())
                raise OSError("injected short write")

            short_error = run_synthetic_output_failure(
                "short-write",
                short_output,
                writer=reject_tar_write,
            )
            self.assertIsInstance(short_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(str(short_error), "deterministic image output rejected")
            self.assertFalse(short_output.exists())

            nested_output = root / "nested-verifier-output.tar"

            def reject_nested_verification(*args: object, **kwargs: object) -> bool:
                del args, kwargs
                self.assertFalse(nested_output.exists())
                return False

            nested_error = run_synthetic_output_failure(
                "nested-verifier",
                nested_output,
                verifier=reject_nested_verification,
            )
            self.assertIsInstance(nested_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(
                str(nested_error),
                "deterministic image verification rejected",
            )
            self.assertFalse(nested_output.exists())

            post_output = root / "post-verifier-output.tar"
            verifier_passed = False

            def accept_nested_verification(*args: object, **kwargs: object) -> bool:
                nonlocal verifier_passed
                del args, kwargs
                verifier_passed = True
                return True

            def reject_after_verification(*args: object, **kwargs: object) -> object:
                result = real_observe(*args, **kwargs)
                if verifier_passed:
                    raise builder.TelegramGatewayReleaseRejected(
                        "injected post-verifier drift"
                    )
                return result

            post_error = run_synthetic_output_failure(
                "post-verifier",
                post_output,
                observer=reject_after_verification,
                verifier=accept_nested_verification,
            )
            self.assertIsInstance(post_error, builder.TelegramGatewayReleaseRejected)
            self.assertEqual(str(post_error), "injected post-verifier drift")
            self.assertFalse(post_output.exists())

            self.assertNotEqual(receipts[0]["config_digest"], receipts[0]["manifest_digest"])
            self.assertEqual(
                receipts[0]["base_diff_ids"],
                list(builder.ASTRBOT_BASE_DIFF_IDS),
            )
            expected_overlay = builder.sha256(
                builder._overlay_tar(
                    (source_roots[0] / builder.ASTRBOT_STAGE_SOURCE).read_bytes(),
                    builder.ASTRBOT_SOURCE_DATE_EPOCH,
                )
            ).hexdigest()
            self.assertEqual(receipts[0]["layers"][-1]["diff_id"], f"sha256:{expected_overlay}")
            first_archive = root / "candidate-1.tar"
            before_identity = builder._sha256_file(first_archive)
            before_metadata = first_archive.lstat()

            archive_hash_observed = False
            verifier_descriptors: list[tuple[int, ...]] = []
            real_hash_file = builder._sha256_file

            def record_archive_hash(path: Path) -> tuple[str, int]:
                nonlocal archive_hash_observed
                result = real_hash_file(path)
                if path == first_archive:
                    archive_hash_observed = True
                return result

            def reject_after_archive_hash(*args: object, **kwargs: object) -> object:
                result = real_observe(*args, **kwargs)
                if kwargs.get("retain") is True and not kwargs.get("retained_fds"):
                    verifier_descriptors.append(result[1])
                if archive_hash_observed and kwargs.get("retained_fds"):
                    raise builder.TelegramGatewayReleaseRejected(
                        "injected verifier authority drift"
                    )
                return result

            with (
                mock.patch.object(builder, "_sha256_file", side_effect=record_archive_hash),
                mock.patch.object(
                    builder,
                    "_observe_tool_identities",
                    side_effect=reject_after_archive_hash,
                ),
            ):
                self.assertFalse(
                    builder.verify_deterministic_astrbot_archive(
                        first_archive,
                        receipts[0],
                    )
                )
            self.assertEqual(len(verifier_descriptors), 1)
            for descriptor in verifier_descriptors[0]:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(builder._sha256_file(first_archive), before_identity)

            config_name = (
                "blobs/sha256/"
                + str(receipts[0]["config_digest"]).removeprefix("sha256:")
            )
            with tarfile.open(first_archive, mode="r:") as archive:
                valid_config_bytes = archive.extractfile(config_name).read()
            valid_config = json.loads(valid_config_bytes)
            self.assertEqual(
                valid_config_bytes,
                builder._reconstruct_astrbot_final_config(
                    str(receipts[0]["layers"][-1]["diff_id"])
                ),
            )
            matrix = self._config_authority_matrix(valid_config)
            self.assertEqual({row for row, _, _ in matrix}, set(range(1, 37)))
            self.assertEqual(matrix[0][0:2], (1, "value"))
            forged_archive = root / "forged-config.tar"
            for row, category, forged_config_bytes in matrix:
                with self.subTest(config_authority_row=row, category=category):
                    forged = self._rewrite_config_fixture(
                        first_archive,
                        forged_archive,
                        receipts[0],
                        forged_config_bytes,
                    )
                    fake_hash = str(forged["archive_sha256"])
                    fake_size = int(forged["archive_size"])
                    with (
                        mock.patch.object(
                            builder,
                            "_observe_tool_identities",
                            return_value=(builder.ASTRBOT_TOOL_IDENTITIES, ()),
                        ),
                        mock.patch.object(
                            builder,
                            "_sha256_file",
                            return_value=(fake_hash, fake_size),
                        ),
                        mock.patch.object(
                            builder.subprocess,
                            "run",
                            side_effect=AssertionError(
                                "config rejection must precede Docker subprocess"
                            ),
                        ),
                    ):
                        self.assertFalse(
                            builder.verify_deterministic_astrbot_archive(
                                forged_archive,
                                forged,
                            )
                        )

            first_cmd = self._rewrite_config_fixture(
                first_archive,
                forged_archive,
                receipts[0],
                matrix[0][2],
            )
            fake_docker = Path(builder.ASTRBOT_TOOL_IDENTITIES[0][1])

            def config_load_identity(path: Path) -> tuple[str, int]:
                if path == fake_docker:
                    return builder.ASTRBOT_TOOL_IDENTITIES[0][3], 1
                if path == forged_archive:
                    return str(first_cmd["archive_sha256"]), int(first_cmd["archive_size"])
                raise AssertionError("unexpected identity read")

            with (
                mock.patch.object(
                    builder,
                    "_observe_tool_identities",
                    return_value=(builder.ASTRBOT_TOOL_IDENTITIES, ()),
                ),
                mock.patch.object(builder, "_sha256_file", side_effect=config_load_identity),
                mock.patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=AssertionError(
                        "exact Cmd substitution must reject before Docker subprocess"
                    ),
                ),
            ):
                with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                    builder.load_and_verify_deterministic_astrbot_archive(
                        forged_archive,
                        first_cmd,
                        docker_binary=fake_docker,
                    )
            forged_archive.unlink()

            for field, value in self._receipt_substitutions().items():
                with self.subTest(actual_archive_substitution=field):
                    forged = dict(receipts[0])
                    forged[field] = value
                    self.assertFalse(
                        builder.verify_deterministic_astrbot_archive(first_archive, forged)
                    )
            self.assertEqual(builder._sha256_file(first_archive), before_identity)
            after_metadata = first_archive.lstat()
            self.assertEqual(
                (
                    after_metadata.st_dev,
                    after_metadata.st_ino,
                    after_metadata.st_mode,
                    after_metadata.st_uid,
                    after_metadata.st_gid,
                    after_metadata.st_size,
                    after_metadata.st_mtime_ns,
                ),
                (
                    before_metadata.st_dev,
                    before_metadata.st_ino,
                    before_metadata.st_mode,
                    before_metadata.st_uid,
                    before_metadata.st_gid,
                    before_metadata.st_size,
                    before_metadata.st_mtime_ns,
                ),
            )

        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            for relative, _, _ in builder.COMPONENTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            selected = root / builder.COMPONENTS[-1][0]
            selected.unlink()
            os.symlink(root / builder.COMPONENTS[-2][0], selected)
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder.build_release_document(root)

        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            for relative, _, _ in builder.COMPONENTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            plugin = root / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            (plugin / "extra.py").write_text("forbidden", encoding="utf-8")
            with self.assertRaises(builder.TelegramGatewayReleaseRejected):
                builder.build_release_document(root)


if __name__ == "__main__":
    unittest.main()
