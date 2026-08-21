from __future__ import annotations

import ctypes
from datetime import datetime, timezone
from hashlib import sha256
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


_AT_EMPTY_PATH = 0x1000
_LINKAT = ctypes.CDLL(None, use_errno=True).linkat
_LINKAT.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
)
_LINKAT.restype = ctypes.c_int


SCHEMA = "myuna.telegram-gateway-release.v1"
MANIFEST_SUFFIX = ".manifest.json"
ASTRBOT_IMAGE_SCHEMA = "myuna.astrbot-deterministic-oci.v1"
ASTRBOT_BASE_DIGEST = "sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4"
ASTRBOT_BASE_CONFIG_DIGEST = "sha256:22885e6b04fc8cb22e4bdb45c6139d0fae6860258e8398c016e74214c11427ff"
ASTRBOT_BASE_CHILD_MANIFEST_DIGEST = "sha256:aaaa2c0b8467e86c72f5d5ba5fea1a921ab64fdee4b5354150332ef5c156c765"
ASTRBOT_BASE_DIFF_IDS = (
    "sha256:3edb2192497af6e965b9b7e57dc6dbdce1f3ea721d14a98110419d4ded523298",
    "sha256:1899ce896d030c84bb2f6e1ac89ea6cb680a1b0999818590493f1f53740b36ed",
    "sha256:96499d37fade3a1a8732c225117f8b813dc83892c7a9d1dc577a2610e0cc3fa6",
    "sha256:aa898a312ca08ceee46584cc10e708ca5b2d0d558b1d7a44c35a8634aecc6065",
    "sha256:888ab1ffcf54bda3cf77adfde35f638b1900bb6406e24f571fcce64c154d97cc",
    "sha256:5ac6527c91c436cc971f79c234c2d82761528d33436c790e46c9f7c77656142e",
    "sha256:208adbab41fe29076a96974609d20a04b5223ee4c65f15b9896260313226bd68",
    "sha256:0b8ea21f615436e2f81b3c52c21a9b0c816da0457f71008ed2de483769fe2b94",
)
ASTRBOT_SOURCE_COMMIT = "2d617544d883ea6c31ec40fcce59d4cfaa904dd1"
ASTRBOT_SOURCE_DATE_EPOCH = 1787258367
ASTRBOT_STAGE_SOURCE = "astrbot/core/pipeline/respond/stage.py"
ASTRBOT_STAGE_DESTINATION = "AstrBot/astrbot/core/pipeline/respond/stage.py"
ASTRBOT_STAGE_SHA256 = "fa86aff7bc0582fd0977d24e2a8b3a022dffbfe56bc9a582bc1f1d6a647a11ce"
ASTRBOT_DOCKERFILE_SHA256 = "e490319c82e667b9eec9c1f8db2f4166df63d772258b1919556b7873732d6631"
ASTRBOT_IMAGE_REPOSITORY = "myuna/astrbot-phase-f-deterministic"
ASTRBOT_IMAGE_TAG = "candidate"
ASTRBOT_HISTORY_CREATED_BY = (
    "COPY astrbot/core/pipeline/respond/stage.py "
    "/AstrBot/astrbot/core/pipeline/respond/stage.py # myuna deterministic overlay"
)
_ASTRBOT_BASE_CONFIG_SEMANTIC_SHA256 = (
    "3685b89a0c215420d04b61d3a0abf777c6a196e8f691c5b8d62ec2ff0a05abbe"
)
_ASTRBOT_BASE_CONFIG_SEMANTIC_JSON = b'{"architecture":"amd64","config":{"ArgsEscaped":true,"Cmd":["python","main.py"],"Env":["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305","PYTHON_VERSION=3.12.13","PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684"],"ExposedPorts":{"6185/tcp":{}},"WorkingDir":"/AstrBot"},"created":"2026-07-14T01:39:51.134145083Z","history":[{"comment":"debuerreotype 0.17","created":"2026-06-23T00:00:00Z","created_by":"# debian.sh --arch \'amd64\' out/ \'trixie\' \'@1782172800\'"},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"ENV LANG=C.UTF-8","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"RUN /bin/sh -c set -eux; \\tapt-get update; \\tapt-get install -y --no-install-recommends \\t\\tca-certificates \\t\\tnetbase \\t\\ttzdata \\t; \\tapt-get dist-clean # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"ENV GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"ENV PYTHON_VERSION=3.12.13","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:01:30.196097531Z","created_by":"ENV PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:10:24.407263012Z","created_by":"RUN /bin/sh -c set -eux; \\t\\tsavedAptMark=\\"$(apt-mark showmanual)\\"; \\tapt-get update; \\tapt-get install -y --no-install-recommends \\t\\tdpkg-dev \\t\\tgcc \\t\\tgnupg \\t\\tlibbluetooth-dev \\t\\tlibbz2-dev \\t\\tlibc6-dev \\t\\tlibdb-dev \\t\\tlibffi-dev \\t\\tlibgdbm-dev \\t\\tliblzma-dev \\t\\tlibncursesw5-dev \\t\\tlibreadline-dev \\t\\tlibsqlite3-dev \\t\\tlibssl-dev \\t\\tmake \\t\\ttk-dev \\t\\tuuid-dev \\t\\twget \\t\\txz-utils \\t\\tzlib1g-dev \\t; \\t\\twget -O python.tar.xz \\"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz\\"; \\techo \\"$PYTHON_SHA256 *python.tar.xz\\" | sha256sum -c -; \\twget -O python.tar.xz.asc \\"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc\\"; \\tGNUPGHOME=\\"$(mktemp -d)\\"; export GNUPGHOME; \\tgpg --batch --keyserver hkps://keys.openpgp.org --recv-keys \\"$GPG_KEY\\"; \\tgpg --batch --verify python.tar.xz.asc python.tar.xz; \\tgpgconf --kill all; \\trm -rf \\"$GNUPGHOME\\" python.tar.xz.asc; \\tmkdir -p /usr/src/python; \\ttar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \\trm python.tar.xz; \\t\\tcd /usr/src/python; \\tgnuArch=\\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\\"; \\t./configure \\t\\t--build=\\"$gnuArch\\" \\t\\t--enable-loadable-sqlite-extensions \\t\\t--enable-optimizations \\t\\t--enable-option-checking=fatal \\t\\t--enable-shared \\t\\t$(test \\"${gnuArch%%-*}\\" != \'riscv64\' && echo \'--with-lto\') \\t\\t--with-ensurepip \\t; \\tnproc=\\"$(nproc)\\"; \\tEXTRA_CFLAGS=\\"$(dpkg-buildflags --get CFLAGS)\\"; \\tLDFLAGS=\\"$(dpkg-buildflags --get LDFLAGS)\\"; \\tLDFLAGS=\\"${LDFLAGS:-} -Wl,--strip-all\\"; \\tarch=\\"$(dpkg --print-architecture)\\"; arch=\\"${arch##*-}\\"; \\tcase \\"$arch\\" in \\t\\tamd64|arm64) \\t\\t\\tEXTRA_CFLAGS=\\"${EXTRA_CFLAGS:-} -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer\\"; \\t\\t\\t;; \\t\\ti386) \\t\\t\\t;; \\t\\t*) \\t\\t\\tEXTRA_CFLAGS=\\"${EXTRA_CFLAGS:-} -fno-omit-frame-pointer\\"; \\t\\t\\t;; \\tesac; \\tmake -j \\"$nproc\\" \\t\\t\\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\\" \\t\\t\\"LDFLAGS=${LDFLAGS:-}\\" \\t; \\trm python; \\tmake -j \\"$nproc\\" \\t\\t\\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\\" \\t\\t\\"LDFLAGS=${LDFLAGS:-} -Wl,-rpath=\'\\\\$\\\\$ORIGIN/../lib\'\\" \\t\\tpython \\t; \\tmake install; \\t\\tcd /; \\trm -rf /usr/src/python; \\t\\tfind /usr/local -depth \\t\\t\\\\( \\t\\t\\t\\\\( -type d -a \\\\( -name test -o -name tests -o -name idle_test \\\\) \\\\) \\t\\t\\t-o \\\\( -type f -a \\\\( -name \'*.pyc\' -o -name \'*.pyo\' -o -name \'libpython*.a\' \\\\) \\\\) \\t\\t\\\\) -exec rm -rf \'{}\' + \\t; \\t\\tldconfig; \\t\\tapt-mark auto \'.*\' > /dev/null; \\tapt-mark manual $savedAptMark; \\tfind /usr/local -type f -executable -not \\\\( -name \'*tkinter*\' \\\\) -exec ldd \'{}\' \';\' \\t\\t| awk \'/=>/ { so = $(NF-1); if (index(so, \\"/usr/local/\\") == 1) { next }; gsub(\\"^/(usr/)?\\", \\"\\", so); printf \\"*%s\\\\n\\", so }\' \\t\\t| sort -u \\t\\t| xargs -rt dpkg-query --search \\t\\t| awk \'sub(\\":$\\", \\"\\", $1) { print $1 }\' \\t\\t| sort -u \\t\\t| xargs -r apt-mark manual \\t; \\tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \\tapt-get dist-clean; \\t\\texport PYTHONDONTWRITEBYTECODE=1; \\tpython3 --version; \\tpip3 --version # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:10:24.522489311Z","created_by":"RUN /bin/sh -c set -eux; \\tfor src in idle3 pip3 pydoc3 python3 python3-config; do \\t\\tdst=\\"$(echo \\"$src\\" | tr -d 3)\\"; \\t\\t[ -s \\"/usr/local/bin/$src\\" ]; \\t\\t[ ! -e \\"/usr/local/bin/$dst\\" ]; \\t\\tln -svT \\"$src\\" \\"/usr/local/bin/$dst\\"; \\tdone # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-06-24T02:10:24.522489311Z","created_by":"CMD [\\"python3\\"]","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:38:43.038926503Z","created_by":"WORKDIR /AstrBot"},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:38:43.282477294Z","created_by":"COPY . /AstrBot/ # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:39:26.76027961Z","created_by":"RUN /bin/sh -c apt-get update && apt-get install -y --no-install-recommends     gcc     build-essential     python3-dev     libffi-dev     libssl-dev     ca-certificates     bash     ffmpeg     libavcodec-extra     curl     gnupg     git     ripgrep     && curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -     && apt-get install -y --no-install-recommends nodejs     && apt-get clean     && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:39:51.134145083Z","created_by":"RUN /bin/sh -c python -m pip install uv     && echo \\"3.12\\" > .python-version     && uv lock     && uv export --format requirements.txt --output-file requirements.txt --frozen     && uv pip install -r requirements.txt --no-cache-dir --system     && uv pip install socksio uv pilk --no-cache-dir --system # buildkit"},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:39:51.134145083Z","created_by":"EXPOSE [6185/tcp]","empty_layer":true},{"comment":"buildkit.dockerfile.v0","created":"2026-07-14T01:39:51.134145083Z","created_by":"CMD [\\"python\\" \\"main.py\\"]","empty_layer":true}],"os":"linux","rootfs":{"diff_ids":["sha256:3edb2192497af6e965b9b7e57dc6dbdce1f3ea721d14a98110419d4ded523298","sha256:1899ce896d030c84bb2f6e1ac89ea6cb680a1b0999818590493f1f53740b36ed","sha256:96499d37fade3a1a8732c225117f8b813dc83892c7a9d1dc577a2610e0cc3fa6","sha256:aa898a312ca08ceee46584cc10e708ca5b2d0d558b1d7a44c35a8634aecc6065","sha256:888ab1ffcf54bda3cf77adfde35f638b1900bb6406e24f571fcce64c154d97cc","sha256:5ac6527c91c436cc971f79c234c2d82761528d33436c790e46c9f7c77656142e","sha256:208adbab41fe29076a96974609d20a04b5223ee4c65f15b9896260313226bd68","sha256:0b8ea21f615436e2f81b3c52c21a9b0c816da0457f71008ed2de483769fe2b94"],"type":"layers"}}'
ASTRBOT_TOOL_IDENTITIES = (
    (
        "docker",
        "/usr/bin/docker",
        "29.1.3",
        "7ed12b00293d64742419a6601ae97960a367a0ce97c88b06e3278cc0a409557b",
    ),
    (
        "python",
        "/usr/bin/python3.12",
        "3.12.3",
        "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
    ),
)
_ASTRBOT_TOOL_VERSION_OUTPUTS = (
    "Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2",
    "Python 3.12.3",
)
_ASTRBOT_TOOL_SIZES = (31369824, 8020928)
OCI_LAYOUT_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
COMPONENTS = (
    (
        "channels/astrbot-telegram/compose.dev.yml",
        "channels/astrbot-telegram/compose.dev.yml",
        0o444,
    ),
    (
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/README.md",
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/README.md",
        0o444,
    ),
    (
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py",
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py",
        0o444,
    ),
    (
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/metadata.yaml",
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/metadata.yaml",
        0o444,
    ),
    (
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py",
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/protocol.py",
        0o444,
    ),
    (
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/telegram_media_metadata_protocol.py",
        "channels/astrbot-telegram/plugin/myuna_telegram_gateway/telegram_media_metadata_protocol.py",
        0o444,
    ),
)


class TelegramGatewayReleaseRejected(RuntimeError):
    """Release source or materialization was rejected."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TelegramGatewayReleaseRejected("deterministic image input rejected") from exc


def _reconstruct_astrbot_final_config(overlay_diff_id: str) -> bytes:
    """Rebuild the only accepted final config from frozen base semantics."""
    if (
        type(overlay_diff_id) is not str
        or not overlay_diff_id.startswith("sha256:")
        or len(overlay_diff_id) != 71
        or any(character not in "0123456789abcdef" for character in overlay_diff_id[7:])
        or sha256(_ASTRBOT_BASE_CONFIG_SEMANTIC_JSON).hexdigest()
        != _ASTRBOT_BASE_CONFIG_SEMANTIC_SHA256
    ):
        raise TelegramGatewayReleaseRejected("deterministic image config rejected")
    base = _load_json_bytes(
        _ASTRBOT_BASE_CONFIG_SEMANTIC_JSON,
        require_canonical=True,
    )
    if (
        type(base) is not dict
        or type(base.get("rootfs")) is not dict
        or type(base["rootfs"].get("diff_ids")) is not list
        or type(base.get("history")) is not list
    ):
        raise TelegramGatewayReleaseRejected("deterministic image config rejected")
    rebuilt = json.loads(_canonical_json(base).decode("ascii"))
    timestamp = datetime.fromtimestamp(
        ASTRBOT_SOURCE_DATE_EPOCH,
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rebuilt["created"] = timestamp
    rebuilt["rootfs"]["diff_ids"].append(overlay_diff_id)
    rebuilt["history"].append(
        {
            "comment": "myuna deterministic Phase F response-pipeline overlay",
            "created": timestamp,
            "created_by": ASTRBOT_HISTORY_CREATED_BY,
        }
    )
    return _canonical_json(rebuilt)


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("deterministic image input rejected") from exc
    return digest.hexdigest(), size


def _require_empty_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
        entries = list(path.iterdir())
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("deterministic image work root rejected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or entries:
        raise TelegramGatewayReleaseRejected("deterministic image work root rejected")


def _require_astrbot_source(source_root: Path) -> bytes:
    stage = _regular_source(source_root / ASTRBOT_STAGE_SOURCE)
    dockerfile = _regular_source(source_root / "Dockerfile")
    if sha256(stage).hexdigest() != ASTRBOT_STAGE_SHA256:
        raise TelegramGatewayReleaseRejected("AstrBot stage source rejected")
    if sha256(dockerfile).hexdigest() != ASTRBOT_DOCKERFILE_SHA256:
        raise TelegramGatewayReleaseRejected("AstrBot Dockerfile source rejected")
    return stage


def _observe_tool_identities(
    tool_identities: object,
    *,
    retain: bool = False,
    retained_fds: tuple[int, ...] | None = None,
) -> tuple[tuple[tuple[str, str, str, str], ...], tuple[int, ...]]:
    """Bind the running Python entity and exact held build-tool bytes."""
    if type(tool_identities) is not tuple or tool_identities != ASTRBOT_TOOL_IDENTITIES:
        raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")
    if type(retain) is not bool:
        raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")
    for entry in tool_identities:
        if (
            type(entry) is not tuple
            or len(entry) != 4
            or any(type(item) is not str for item in entry)
            or len(entry[3]) != 64
            or any(character not in "0123456789abcdef" for character in entry[3])
        ):
            raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")

    owned = retained_fds is None
    if not owned and (
        type(retained_fds) is not tuple
        or len(retained_fds) != len(ASTRBOT_TOOL_IDENTITIES) + 1
        or any(type(fd) is not int or fd < 0 for fd in retained_fds)
    ):
        raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")
    descriptors: list[int] = [] if owned else list(retained_fds)
    keep_open = False

    try:
        if owned:
            for _, path_text, _, _ in ASTRBOT_TOOL_IDENTITIES:
                path = Path(path_text)
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")
                descriptor = os.open(
                    path,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
                descriptors.append(descriptor)
            descriptors.append(os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC))

        def hash_descriptor(descriptor: int) -> str:
            digest = sha256()
            os.lseek(descriptor, 0, os.SEEK_SET)
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return digest.hexdigest()

        configured_python = ASTRBOT_TOOL_IDENTITIES[1]
        configured_python_path = Path(configured_python[1])
        python_descriptor = descriptors[1]
        current_descriptor = descriptors[2]
        python_metadata = os.fstat(python_descriptor)
        current_metadata = os.fstat(current_descriptor)
        current_target = os.readlink("/proc/self/exe")
        if (
            type(sys.executable) is not str
            or not sys.executable
            or not Path(sys.executable).is_absolute()
            or Path(sys.executable).resolve(strict=True) != configured_python_path
            or current_target != configured_python[1]
            or current_target.endswith(" (deleted)")
            or not stat.S_ISREG(current_metadata.st_mode)
            or (current_metadata.st_dev, current_metadata.st_ino)
            != (python_metadata.st_dev, python_metadata.st_ino)
            or (
                current_metadata.st_mode,
                current_metadata.st_size,
            )
            != (
                python_metadata.st_mode,
                python_metadata.st_size,
            )
            or hash_descriptor(current_descriptor) != configured_python[3]
            or tuple(sys.version_info[:3])
            != tuple(int(part) for part in configured_python[2].split("."))
        ):
            raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")

        for entry, expected_output, expected_size, descriptor in zip(
            ASTRBOT_TOOL_IDENTITIES,
            _ASTRBOT_TOOL_VERSION_OUTPUTS,
            _ASTRBOT_TOOL_SIZES,
            descriptors[: len(ASTRBOT_TOOL_IDENTITIES)],
            strict=True,
        ):
            _, path_text, expected_version, expected_digest = entry
            path = Path(path_text)
            path_metadata = path.lstat()
            before = os.fstat(descriptor)
            if (
                stat.S_ISLNK(path_metadata.st_mode)
                or not stat.S_ISREG(path_metadata.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or (path_metadata.st_dev, path_metadata.st_ino)
                != (before.st_dev, before.st_ino)
                or before.st_size != expected_size
            ):
                raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")

            first_digest = hash_descriptor(descriptor)
            version = subprocess.run(
                [f"/proc/self/fd/{descriptor}", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=5,
                pass_fds=(descriptor,),
            )
            after = os.fstat(descriptor)
            path_after = path.lstat()
            second_digest = hash_descriptor(descriptor)
            output = version.stdout.decode("utf-8", errors="strict").strip()
            if (
                version.returncode != 0
                or output != expected_output
                or expected_version not in output
                or first_digest != expected_digest
                or second_digest != expected_digest
                or stat.S_ISLNK(path_after.st_mode)
                or not stat.S_ISREG(path_after.st_mode)
                or (path_after.st_dev, path_after.st_ino)
                != (after.st_dev, after.st_ino)
                or (before.st_dev, before.st_ino, before.st_mode, before.st_size)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_size)
            ):
                raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected")

        result = tuple(ASTRBOT_TOOL_IDENTITIES)
        if retain:
            keep_open = True
            return result, tuple(descriptors)
        return result, ()
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError) as exc:
        raise TelegramGatewayReleaseRejected("deterministic image tool identity rejected") from exc
    finally:
        if owned and not keep_open:
            for descriptor in descriptors:
                os.close(descriptor)


def _archive_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        if member.name in members or member.issym() or member.islnk():
            raise TelegramGatewayReleaseRejected("base image archive rejected")
        if not (member.isfile() or member.isdir()):
            raise TelegramGatewayReleaseRejected("base image archive rejected")
        if member.name.startswith("/") or ".." in Path(member.name).parts:
            raise TelegramGatewayReleaseRejected("base image archive rejected")
        members[member.name] = member
    return members


def _read_archive_file(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    maximum: int,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile() or member.size < 0 or member.size > maximum:
        raise TelegramGatewayReleaseRejected("base image archive rejected")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise TelegramGatewayReleaseRejected("base image archive rejected")
    value = extracted.read(maximum + 1)
    if len(value) != member.size:
        raise TelegramGatewayReleaseRejected("base image archive rejected")
    return value


def _load_json_bytes(value: bytes, *, require_canonical: bool = False) -> object:
    try:
        decoded = value.decode("utf-8")
        loaded = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelegramGatewayReleaseRejected("base image metadata rejected") from exc
    if require_canonical and _canonical_json(loaded) != value:
        raise TelegramGatewayReleaseRejected("base image metadata rejected")
    return loaded


def _copy_member_to_file(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    expected_digest: str,
) -> None:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise TelegramGatewayReleaseRejected("base image layer rejected")
    digest = sha256()
    size = 0
    with destination.open("xb") as output:
        while chunk := extracted.read(1024 * 1024):
            output.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    if size != member.size or f"sha256:{digest.hexdigest()}" != expected_digest:
        raise TelegramGatewayReleaseRejected("base image layer rejected")


def _recompress_layer(source: Path, raw: Path, destination: Path, expected_diff_id: str) -> tuple[str, int]:
    raw_digest = sha256()
    try:
        with source.open("rb") as compressed, gzip.GzipFile(fileobj=compressed, mode="rb") as reader, raw.open("xb") as output:
            while chunk := reader.read(1024 * 1024):
                output.write(chunk)
                raw_digest.update(chunk)
        if f"sha256:{raw_digest.hexdigest()}" != expected_diff_id:
            raise TelegramGatewayReleaseRejected("base image DiffID rejected")
        with raw.open("rb") as reader, destination.open("xb") as compressed_output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=compressed_output,
                mtime=0,
            ) as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise TelegramGatewayReleaseRejected("base image layer rejected") from exc
    digest, size = _sha256_file(destination)
    return f"sha256:{digest}", size


def _overlay_tar(stage: bytes, epoch: int) -> bytes:
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(ASTRBOT_STAGE_DESTINATION)
        info.type = tarfile.REGTYPE
        info.size = len(stage)
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = epoch
        archive.addfile(info, io.BytesIO(stage))
    return target.getvalue()


def _write_tar_bytes(archive: tarfile.TarFile, name: str, value: bytes, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.REGTYPE
    info.size = len(value)
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    archive.addfile(info, io.BytesIO(value))


def _write_tar_file(archive: tarfile.TarFile, name: str, source: Path, size: int, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.REGTYPE
    info.size = size
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    with source.open("rb") as handle:
        archive.addfile(info, handle)


def build_deterministic_astrbot_archive(
    *,
    base_archive: Path,
    astrbot_source_root: Path,
    work_root: Path,
    output_archive: Path,
    source_commit: str,
    source_date_epoch: int,
    tool_identities: object,
) -> dict[str, object]:
    """Build under one retained tool-authority transaction."""
    try:
        if type(output_archive) is not type(Path()):
            raise TypeError("output archive must be an exact platform Path")
        output_parent = output_archive.parent
        output_parent_text = os.fspath(output_parent)
        output_basename_text = output_archive.name
        if type(output_parent_text) is not str or type(output_basename_text) is not str:
            raise TypeError("output path must contain exact strings")
        output_basename = os.fsencode(output_basename_text)
        output_parent_bytes = os.fsencode(output_parent_text)
        if type(output_basename) is not bytes or type(output_parent_bytes) is not bytes:
            raise TypeError("output path encoding rejected")
        if (
            output_basename in {b"", b".", b".."}
            or b"\0" in output_basename
            or b"/" in output_basename
            or os.fsdecode(output_basename) != output_basename_text
            or b"\0" in output_parent_bytes
            or os.fsdecode(output_parent_bytes) != output_parent_text
        ):
            raise ValueError("output path encoding rejected")
        frozen_output_path = output_parent / output_basename_text
        if frozen_output_path.exists() or frozen_output_path.is_symlink():
            raise ValueError("output path already exists")
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise TelegramGatewayReleaseRejected("deterministic image output rejected") from exc
    tools, retained_fds = _observe_tool_identities(tool_identities, retain=True)
    try:
        return _build_deterministic_astrbot_archive_under_authority(
            base_archive=base_archive,
            astrbot_source_root=astrbot_source_root,
            work_root=work_root,
            output_parent=output_parent,
            output_basename=output_basename,
            source_commit=source_commit,
            source_date_epoch=source_date_epoch,
            tool_identities=tool_identities,
            tools=tools,
            retained_fds=retained_fds,
        )
    finally:
        for descriptor in retained_fds:
            os.close(descriptor)


def _build_deterministic_astrbot_archive_under_authority(
    *,
    base_archive: Path,
    astrbot_source_root: Path,
    work_root: Path,
    output_parent: Path,
    output_basename: bytes,
    source_commit: str,
    source_date_epoch: int,
    tool_identities: object,
    tools: tuple[tuple[str, str, str, str], ...],
    retained_fds: tuple[int, ...],
) -> dict[str, object]:
    """Implement the build while the public wrapper holds exact descriptors."""
    _observe_tool_identities(
        tool_identities,
        retain=True,
        retained_fds=retained_fds,
    )
    _require_empty_directory(work_root)
    if type(source_commit) is not str or source_commit != ASTRBOT_SOURCE_COMMIT:
        raise TelegramGatewayReleaseRejected("AstrBot source identity rejected")
    if type(source_date_epoch) is not int or source_date_epoch != ASTRBOT_SOURCE_DATE_EPOCH:
        raise TelegramGatewayReleaseRejected("AstrBot source epoch rejected")
    stage = _require_astrbot_source(astrbot_source_root)
    _observe_tool_identities(
        tool_identities,
        retain=True,
        retained_fds=retained_fds,
    )
    base_metadata = base_archive.lstat()
    if stat.S_ISLNK(base_metadata.st_mode) or not stat.S_ISREG(base_metadata.st_mode):
        raise TelegramGatewayReleaseRejected("base image archive rejected")

    layer_files: list[tuple[str, Path, int, str]] = []
    try:
        with tarfile.open(base_archive, mode="r:") as archive:
            members = _archive_members(archive)
            index_document = _load_json_bytes(
                _read_archive_file(archive, members, "index.json", maximum=1024 * 1024)
            )
            if type(index_document) is not dict or type(index_document.get("manifests")) is not list:
                raise TelegramGatewayReleaseRejected("base image index rejected")
            base_descriptor = next(
                (
                    entry
                    for entry in index_document["manifests"]
                    if type(entry) is dict and entry.get("digest") == ASTRBOT_BASE_DIGEST
                ),
                None,
            )
            if base_descriptor is None or base_descriptor.get("mediaType") != OCI_LAYOUT_MEDIA_TYPE:
                raise TelegramGatewayReleaseRejected("base image index rejected")
            base_index_name = f"blobs/sha256/{ASTRBOT_BASE_DIGEST.removeprefix('sha256:')}"
            base_index_bytes = _read_archive_file(archive, members, base_index_name, maximum=1024 * 1024)
            if f"sha256:{sha256(base_index_bytes).hexdigest()}" != ASTRBOT_BASE_DIGEST:
                raise TelegramGatewayReleaseRejected("base image index rejected")
            base_index = _load_json_bytes(base_index_bytes)
            if type(base_index) is not dict or type(base_index.get("manifests")) is not list:
                raise TelegramGatewayReleaseRejected("base image index rejected")
            child_descriptor = next(
                (
                    entry
                    for entry in base_index["manifests"]
                    if type(entry) is dict
                    and entry.get("digest") == ASTRBOT_BASE_CHILD_MANIFEST_DIGEST
                    and entry.get("platform") == {"architecture": "amd64", "os": "linux"}
                ),
                None,
            )
            if child_descriptor is None or child_descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
                raise TelegramGatewayReleaseRejected("base image platform rejected")
            child_name = f"blobs/sha256/{ASTRBOT_BASE_CHILD_MANIFEST_DIGEST.removeprefix('sha256:')}"
            child_bytes = _read_archive_file(archive, members, child_name, maximum=1024 * 1024)
            if f"sha256:{sha256(child_bytes).hexdigest()}" != ASTRBOT_BASE_CHILD_MANIFEST_DIGEST:
                raise TelegramGatewayReleaseRejected("base image manifest rejected")
            child = _load_json_bytes(child_bytes)
            if type(child) is not dict or child.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
                raise TelegramGatewayReleaseRejected("base image manifest rejected")
            config_descriptor = child.get("config")
            layers = child.get("layers")
            if (
                type(config_descriptor) is not dict
                or config_descriptor.get("digest") != ASTRBOT_BASE_CONFIG_DIGEST
                or config_descriptor.get("mediaType") != OCI_CONFIG_MEDIA_TYPE
                or type(layers) is not list
                or len(layers) != len(ASTRBOT_BASE_DIFF_IDS)
            ):
                raise TelegramGatewayReleaseRejected("base image manifest rejected")
            config_name = f"blobs/sha256/{ASTRBOT_BASE_CONFIG_DIGEST.removeprefix('sha256:')}"
            config_bytes = _read_archive_file(archive, members, config_name, maximum=1024 * 1024)
            if f"sha256:{sha256(config_bytes).hexdigest()}" != ASTRBOT_BASE_CONFIG_DIGEST:
                raise TelegramGatewayReleaseRejected("base image config rejected")
            base_config = _load_json_bytes(config_bytes)
            if (
                type(base_config) is not dict
                or _canonical_json(base_config) != _ASTRBOT_BASE_CONFIG_SEMANTIC_JSON
            ):
                raise TelegramGatewayReleaseRejected("base image config rejected")

            for ordinal, (descriptor, expected_diff_id) in enumerate(zip(layers, ASTRBOT_BASE_DIFF_IDS, strict=True)):
                if (
                    type(descriptor) is not dict
                    or descriptor.get("mediaType") != OCI_LAYER_MEDIA_TYPE
                    or type(descriptor.get("digest")) is not str
                    or type(descriptor.get("size")) is not int
                    or type(descriptor.get("size")) is bool
                    or descriptor["size"] <= 0
                ):
                    raise TelegramGatewayReleaseRejected("base image layer rejected")
                member_name = f"blobs/sha256/{descriptor['digest'].removeprefix('sha256:')}"
                member = members.get(member_name)
                if member is None or not member.isfile() or member.size != descriptor["size"]:
                    raise TelegramGatewayReleaseRejected("base image layer rejected")
                source_layer = work_root / f"source-{ordinal}.tar.gz"
                raw_layer = work_root / f"raw-{ordinal}.tar"
                canonical_layer = work_root / f"canonical-{ordinal}.tar.gz"
                _copy_member_to_file(archive, member, source_layer, descriptor["digest"])
                digest, size = _recompress_layer(source_layer, raw_layer, canonical_layer, expected_diff_id)
                layer_files.append((digest, canonical_layer, size, expected_diff_id))
                source_layer.unlink()
                raw_layer.unlink()
    except (OSError, tarfile.TarError) as exc:
        raise TelegramGatewayReleaseRejected("base image archive rejected") from exc
    _observe_tool_identities(
        tool_identities,
        retain=True,
        retained_fds=retained_fds,
    )

    overlay_raw = _overlay_tar(stage, source_date_epoch)
    overlay_diff_id = f"sha256:{sha256(overlay_raw).hexdigest()}"
    overlay_path = work_root / "overlay.tar.gz"
    try:
        with overlay_path.open("xb") as compressed_output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=compressed_output,
                mtime=0,
            ) as writer:
                writer.write(overlay_raw)
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("overlay materialization rejected") from exc
    overlay_digest_value, overlay_size = _sha256_file(overlay_path)
    layer_files.append((f"sha256:{overlay_digest_value}", overlay_path, overlay_size, overlay_diff_id))
    _observe_tool_identities(
        tool_identities,
        retain=True,
        retained_fds=retained_fds,
    )

    timestamp = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    config_bytes = _reconstruct_astrbot_final_config(overlay_diff_id)
    config_digest = f"sha256:{sha256(config_bytes).hexdigest()}"
    layer_descriptors = [
        {"digest": digest, "mediaType": OCI_LAYER_MEDIA_TYPE, "size": size}
        for digest, _, size, _ in layer_files
    ]
    manifest_document = {
        "config": {
            "digest": config_digest,
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "size": len(config_bytes),
        },
        "layers": layer_descriptors,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    manifest_bytes = _canonical_json(manifest_document)
    manifest_digest = f"sha256:{sha256(manifest_bytes).hexdigest()}"
    image_reference = f"{ASTRBOT_IMAGE_REPOSITORY}@{manifest_digest}"
    tag_reference = f"{ASTRBOT_IMAGE_REPOSITORY}:{ASTRBOT_IMAGE_TAG}"
    index_document = {
        "manifests": [
            {
                "annotations": {
                    "io.containerd.image.name": f"docker.io/{image_reference}",
                    "org.opencontainers.image.ref.name": ASTRBOT_IMAGE_TAG,
                },
                "digest": manifest_digest,
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "platform": {"architecture": "amd64", "os": "linux"},
                "size": len(manifest_bytes),
            }
        ],
        "mediaType": OCI_LAYOUT_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    index_bytes = _canonical_json(index_document)
    docker_manifest_bytes = _canonical_json(
        [
            {
                "Config": f"blobs/sha256/{config_digest.removeprefix('sha256:')}",
                "Layers": [
                    f"blobs/sha256/{digest.removeprefix('sha256:')}"
                    for digest, _, _, _ in layer_files
                ],
                "RepoTags": [tag_reference],
            }
        ]
    )
    fixed_files = {
        "blobs/sha256/" + config_digest.removeprefix("sha256:"): config_bytes,
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"): manifest_bytes,
        "index.json": index_bytes,
        "manifest.json": docker_manifest_bytes,
        "oci-layout": _canonical_json({"imageLayoutVersion": "1.0.0"}),
    }
    layer_by_name = {
        "blobs/sha256/" + digest.removeprefix("sha256:"): (path, size)
        for digest, path, size, _ in layer_files
    }
    _observe_tool_identities(
        tool_identities,
        retain=True,
        retained_fds=retained_fds,
    )
    output_parent.mkdir(parents=True, exist_ok=True)
    parent_descriptor = -1
    output_descriptor = -1
    output_published = False
    try:
        parent_descriptor = os.open(
            output_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        output_descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
            0o666,
            dir_fd=parent_descriptor,
        )
        output_metadata = os.fstat(output_descriptor)
        if not stat.S_ISREG(output_metadata.st_mode):
            raise TelegramGatewayReleaseRejected("deterministic image output rejected")
        writer_descriptor = os.dup(output_descriptor)
        try:
            with os.fdopen(writer_descriptor, "wb") as output_handle:
                writer_descriptor = -1
                with tarfile.open(
                    fileobj=output_handle,
                    mode="w:",
                    format=tarfile.USTAR_FORMAT,
                ) as outer:
                    for name in sorted([*fixed_files, *layer_by_name]):
                        if name in fixed_files:
                            _write_tar_bytes(outer, name, fixed_files[name], source_date_epoch)
                        else:
                            path, size = layer_by_name[name]
                            _write_tar_file(outer, name, path, size, source_date_epoch)
        finally:
            if writer_descriptor >= 0:
                os.close(writer_descriptor)
        os.fsync(output_descriptor)
        os.fsync(parent_descriptor)

        _observe_tool_identities(
            tool_identities,
            retain=True,
            retained_fds=retained_fds,
        )
        held_output_path = Path(f"/proc/self/fd/{output_descriptor}")
        archive_digest, archive_size = _sha256_file(held_output_path)
        receipt: dict[str, object] = {
            "archive_sha256": archive_digest,
            "archive_size": archive_size,
            "base_child_manifest_digest": ASTRBOT_BASE_CHILD_MANIFEST_DIGEST,
            "base_config_digest": ASTRBOT_BASE_CONFIG_DIGEST,
            "base_digest": ASTRBOT_BASE_DIGEST,
            "base_diff_ids": list(ASTRBOT_BASE_DIFF_IDS),
            "config_digest": config_digest,
            "dockerfile_sha256": ASTRBOT_DOCKERFILE_SHA256,
            # Docker 29 with the containerd image store exposes the loaded OCI
            # manifest digest as .Id; the independently verified config descriptor
            # remains bound separately by config_digest.
            "image_id": manifest_digest,
            "image_reference": image_reference,
            "index_digest": f"sha256:{sha256(index_bytes).hexdigest()}",
            "layers": [
                {
                    "compressed_digest": digest,
                    "compressed_size": size,
                    "diff_id": diff_id,
                }
                for digest, _, size, diff_id in layer_files
            ],
            "manifest_digest": manifest_digest,
            "platform": {"architecture": "amd64", "os": "linux"},
            "repository": ASTRBOT_IMAGE_REPOSITORY,
            "schema": ASTRBOT_IMAGE_SCHEMA,
            "source_commit": source_commit,
            "source_date_epoch": source_date_epoch,
            "stage_sha256": ASTRBOT_STAGE_SHA256,
            "tag_reference": tag_reference,
            "timestamp": timestamp,
            "tools": [
                {"name": name, "path": path, "version": version, "sha256": digest}
                for name, path, version, digest in tools
            ],
        }
        if not _verify_deterministic_astrbot_archive_under_authority(
            held_output_path,
            receipt,
            retained_fds=retained_fds,
        ):
            raise TelegramGatewayReleaseRejected("deterministic image verification rejected")
        _observe_tool_identities(
            tool_identities,
            retain=True,
            retained_fds=retained_fds,
        )
        ctypes.set_errno(0)
        publication_result = _LINKAT(
            output_descriptor,
            b"",
            parent_descriptor,
            output_basename,
            _AT_EMPTY_PATH,
        )
        if publication_result != 0:
            publication_errno = ctypes.get_errno()
            raise TelegramGatewayReleaseRejected(
                "deterministic image output publication rejected"
            ) from OSError(publication_errno, os.strerror(publication_errno))
        output_published = True
        os.fsync(parent_descriptor)
        _observe_tool_identities(
            tool_identities,
            retain=True,
            retained_fds=retained_fds,
        )
        current_output = os.stat(
            output_basename,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        held_output = os.fstat(output_descriptor)
        if (
            not stat.S_ISREG(current_output.st_mode)
            or (current_output.st_dev, current_output.st_ino)
            != (held_output.st_dev, held_output.st_ino)
        ):
            raise TelegramGatewayReleaseRejected(
                "deterministic image output publication ambiguous"
            )
        return receipt
    except BaseException as exc:
        if output_published:
            raise TelegramGatewayReleaseRejected(
                "deterministic image output publication ambiguous"
            ) from exc
        if isinstance(exc, (OSError, tarfile.TarError)):
            raise TelegramGatewayReleaseRejected("deterministic image output rejected") from exc
        raise
    finally:
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def verify_deterministic_astrbot_archive(archive_path: Path, receipt: dict[str, object]) -> bool:
    """Verify under one retained tool-authority transaction."""
    retained_fds: tuple[int, ...] = ()
    try:
        if not _verify_deterministic_astrbot_archive_under_authority(
            archive_path,
            receipt,
            retained_fds=(),
            validate_only=True,
        ):
            return False
        _, retained_fds = _observe_tool_identities(
            ASTRBOT_TOOL_IDENTITIES,
            retain=True,
        )
        return _verify_deterministic_astrbot_archive_under_authority(
            archive_path,
            receipt,
            retained_fds=retained_fds,
        )
    except TelegramGatewayReleaseRejected:
        return False
    finally:
        for descriptor in retained_fds:
            os.close(descriptor)


def _verify_deterministic_astrbot_archive_under_authority(
    archive_path: Path,
    receipt: dict[str, object],
    *,
    retained_fds: tuple[int, ...],
    validate_only: bool = False,
) -> bool:
    """Implement verification using the caller's still-held descriptors."""
    try:
        if type(validate_only) is not bool:
            return False
        receipt_keys = {
            "archive_sha256",
            "archive_size",
            "base_child_manifest_digest",
            "base_config_digest",
            "base_digest",
            "base_diff_ids",
            "config_digest",
            "dockerfile_sha256",
            "image_id",
            "image_reference",
            "index_digest",
            "layers",
            "manifest_digest",
            "platform",
            "repository",
            "schema",
            "source_commit",
            "source_date_epoch",
            "stage_sha256",
            "tag_reference",
            "timestamp",
            "tools",
        }
        if type(receipt) is not dict or set(receipt) != receipt_keys:
            return False

        def is_digest(value: object, *, prefixed: bool) -> bool:
            if type(value) is not str:
                return False
            hexadecimal = value.removeprefix("sha256:") if prefixed else value
            return (
                len(hexadecimal) == 64
                and (not prefixed or value == f"sha256:{hexadecimal}")
                and all(character in "0123456789abcdef" for character in hexadecimal)
            )

        expected_timestamp = datetime.fromtimestamp(
            ASTRBOT_SOURCE_DATE_EPOCH,
            tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        expected_tools = [
            {"name": name, "path": path, "version": version, "sha256": digest}
            for name, path, version, digest in ASTRBOT_TOOL_IDENTITIES
        ]
        if (
            receipt["schema"] != ASTRBOT_IMAGE_SCHEMA
            or type(receipt["schema"]) is not str
            or receipt["source_commit"] != ASTRBOT_SOURCE_COMMIT
            or type(receipt["source_commit"]) is not str
            or receipt["source_date_epoch"] != ASTRBOT_SOURCE_DATE_EPOCH
            or type(receipt["source_date_epoch"]) is not int
            or receipt["timestamp"] != expected_timestamp
            or type(receipt["timestamp"]) is not str
            or receipt["base_digest"] != ASTRBOT_BASE_DIGEST
            or type(receipt["base_digest"]) is not str
            or receipt["base_config_digest"] != ASTRBOT_BASE_CONFIG_DIGEST
            or type(receipt["base_config_digest"]) is not str
            or receipt["base_child_manifest_digest"] != ASTRBOT_BASE_CHILD_MANIFEST_DIGEST
            or type(receipt["base_child_manifest_digest"]) is not str
            or receipt["base_diff_ids"] != list(ASTRBOT_BASE_DIFF_IDS)
            or type(receipt["base_diff_ids"]) is not list
            or any(type(value) is not str for value in receipt["base_diff_ids"])
            or receipt["stage_sha256"] != ASTRBOT_STAGE_SHA256
            or type(receipt["stage_sha256"]) is not str
            or receipt["dockerfile_sha256"] != ASTRBOT_DOCKERFILE_SHA256
            or type(receipt["dockerfile_sha256"]) is not str
            or receipt["repository"] != ASTRBOT_IMAGE_REPOSITORY
            or type(receipt["repository"]) is not str
            or receipt["platform"] != {"architecture": "amd64", "os": "linux"}
            or type(receipt["platform"]) is not dict
            or set(receipt["platform"]) != {"architecture", "os"}
            or any(type(value) is not str for value in receipt["platform"].values())
            or receipt["tools"] != expected_tools
            or type(receipt["tools"]) is not list
            or any(
                type(tool) is not dict
                or set(tool) != {"name", "path", "version", "sha256"}
                or any(type(value) is not str for value in tool.values())
                or not is_digest(tool["sha256"], prefixed=False)
                for tool in receipt["tools"]
            )
        ):
            return False

        layers = receipt["layers"]
        if (
            type(layers) is not list
            or len(layers) != len(ASTRBOT_BASE_DIFF_IDS) + 1
            or any(
                type(layer) is not dict
                or set(layer) != {"compressed_digest", "compressed_size", "diff_id"}
                or not is_digest(layer["compressed_digest"], prefixed=True)
                or type(layer["compressed_size"]) is not int
                or layer["compressed_size"] <= 0
                or not is_digest(layer["diff_id"], prefixed=True)
                for layer in layers
            )
            or [layer["diff_id"] for layer in layers[:-1]] != list(ASTRBOT_BASE_DIFF_IDS)
            or len({layer["compressed_digest"] for layer in layers}) != len(layers)
            or len({layer["diff_id"] for layer in layers}) != len(layers)
        ):
            return False

        manifest_digest = receipt["manifest_digest"]
        config_digest = receipt["config_digest"]
        if (
            not is_digest(receipt["archive_sha256"], prefixed=False)
            or type(receipt["archive_size"]) is not int
            or receipt["archive_size"] <= 0
            or not is_digest(config_digest, prefixed=True)
            or not is_digest(manifest_digest, prefixed=True)
            or not is_digest(receipt["index_digest"], prefixed=True)
            or receipt["image_id"] != manifest_digest
            or type(receipt["image_id"]) is not str
            or receipt["image_reference"] != f"{ASTRBOT_IMAGE_REPOSITORY}@{manifest_digest}"
            or type(receipt["image_reference"]) is not str
            or receipt["tag_reference"] != f"{ASTRBOT_IMAGE_REPOSITORY}:{ASTRBOT_IMAGE_TAG}"
            or type(receipt["tag_reference"]) is not str
        ):
            return False

        if validate_only:
            return True

        claimed_tools = tuple(
            (tool["name"], tool["path"], tool["version"], tool["sha256"])
            for tool in receipt["tools"]
        )
        observed_tools, observed_fds = _observe_tool_identities(
            claimed_tools,
            retain=True,
            retained_fds=retained_fds,
        )
        if observed_tools != ASTRBOT_TOOL_IDENTITIES:
            return False
        if observed_fds != retained_fds:
            return False

        digest, size = _sha256_file(archive_path)
        _observe_tool_identities(
            claimed_tools,
            retain=True,
            retained_fds=retained_fds,
        )
        if digest != receipt["archive_sha256"] or size != receipt["archive_size"]:
            return False
        with tarfile.open(archive_path, mode="r:") as archive:
            members = _archive_members(archive)
            names = set(members)
            required = {"index.json", "manifest.json", "oci-layout"}
            required.update(
                f"blobs/sha256/{str(item['compressed_digest']).removeprefix('sha256:')}"
                for item in layers
            )
            required.add(f"blobs/sha256/{config_digest.removeprefix('sha256:')}")
            required.add(f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}")
            if names != required or any(not member.isfile() for member in members.values()):
                return False
            for member in members.values():
                if (
                    member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != receipt["source_date_epoch"]
                    or member.pax_headers
                ):
                    return False
            index_bytes = _read_archive_file(archive, members, "index.json", maximum=1024 * 1024)
            if f"sha256:{sha256(index_bytes).hexdigest()}" != receipt["index_digest"]:
                return False
            config_name = f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
            config_bytes = _read_archive_file(archive, members, config_name, maximum=1024 * 1024)
            if f"sha256:{sha256(config_bytes).hexdigest()}" != config_digest:
                return False
            manifest_name = f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}"
            manifest_bytes = _read_archive_file(archive, members, manifest_name, maximum=1024 * 1024)
            if f"sha256:{sha256(manifest_bytes).hexdigest()}" != manifest_digest:
                return False
            manifest = _load_json_bytes(manifest_bytes, require_canonical=True)
            expected_manifest = {
                "config": {
                    "digest": config_digest,
                    "mediaType": OCI_CONFIG_MEDIA_TYPE,
                    "size": len(config_bytes),
                },
                "layers": [
                    {
                        "digest": layer["compressed_digest"],
                        "mediaType": OCI_LAYER_MEDIA_TYPE,
                        "size": layer["compressed_size"],
                    }
                    for layer in layers
                ],
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "schemaVersion": 2,
            }
            if manifest != expected_manifest or manifest_bytes != _canonical_json(expected_manifest):
                return False

            index = _load_json_bytes(index_bytes, require_canonical=True)
            expected_index = {
                "manifests": [
                    {
                        "annotations": {
                            "io.containerd.image.name": f"docker.io/{receipt['image_reference']}",
                            "org.opencontainers.image.ref.name": ASTRBOT_IMAGE_TAG,
                        },
                        "digest": manifest_digest,
                        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                        "platform": {"architecture": "amd64", "os": "linux"},
                        "size": len(manifest_bytes),
                    }
                ],
                "mediaType": OCI_LAYOUT_MEDIA_TYPE,
                "schemaVersion": 2,
            }
            if index != expected_index or index_bytes != _canonical_json(expected_index):
                return False

            docker_manifest_bytes = _read_archive_file(
                archive,
                members,
                "manifest.json",
                maximum=1024 * 1024,
            )
            expected_docker_manifest = [
                {
                    "Config": config_name,
                    "Layers": [
                        f"blobs/sha256/{layer['compressed_digest'].removeprefix('sha256:')}"
                        for layer in layers
                    ],
                    "RepoTags": [receipt["tag_reference"]],
                }
            ]
            if (
                _load_json_bytes(docker_manifest_bytes, require_canonical=True)
                != expected_docker_manifest
                or docker_manifest_bytes != _canonical_json(expected_docker_manifest)
            ):
                return False
            layout_bytes = _read_archive_file(archive, members, "oci-layout", maximum=1024)
            expected_layout = {"imageLayoutVersion": "1.0.0"}
            if (
                _load_json_bytes(layout_bytes, require_canonical=True) != expected_layout
                or layout_bytes != _canonical_json(expected_layout)
            ):
                return False

            # Fail a substituted complete config before layer decompression. A
            # successful result is still authorized only by the later check
            # using the independently recomputed overlay DiffID.
            if config_bytes != _reconstruct_astrbot_final_config(layers[-1]["diff_id"]):
                return False

            observed_diff_ids: list[str] = []
            for item in layers:
                name = f"blobs/sha256/{item['compressed_digest'].removeprefix('sha256:')}"
                member = members[name]
                if member.size != item["compressed_size"]:
                    return False
                extracted = archive.extractfile(member)
                if extracted is None:
                    return False
                compressed = extracted.read()
                if f"sha256:{sha256(compressed).hexdigest()}" != item["compressed_digest"]:
                    return False
                raw = gzip.decompress(compressed)
                observed_diff_id = f"sha256:{sha256(raw).hexdigest()}"
                if observed_diff_id != item["diff_id"]:
                    return False
                observed_diff_ids.append(observed_diff_id)
            overlay = layers[-1]
            overlay_name = f"blobs/sha256/{overlay['compressed_digest'].removeprefix('sha256:')}"
            overlay_handle = archive.extractfile(members[overlay_name])
            if overlay_handle is None:
                return False
            overlay_data = gzip.decompress(overlay_handle.read())
            with tarfile.open(fileobj=io.BytesIO(overlay_data), mode="r:") as overlay_archive:
                overlay_members = overlay_archive.getmembers()
                if len(overlay_members) != 1:
                    return False
                member = overlay_members[0]
                if (
                    member.name != ASTRBOT_STAGE_DESTINATION
                    or not member.isfile()
                    or member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != receipt["source_date_epoch"]
                    or member.pax_headers
                ):
                    return False
                content = overlay_archive.extractfile(member)
                if content is None or sha256(content.read()).hexdigest() != ASTRBOT_STAGE_SHA256:
                    return False
            expected_config_bytes = _reconstruct_astrbot_final_config(observed_diff_ids[-1])
            if config_bytes != expected_config_bytes:
                return False
        _observe_tool_identities(
            claimed_tools,
            retain=True,
            retained_fds=retained_fds,
        )
    except (
        AttributeError,
        EOFError,
        IndexError,
        KeyError,
        OSError,
        TelegramGatewayReleaseRejected,
        TypeError,
        ValueError,
        gzip.BadGzipFile,
        tarfile.TarError,
    ):
        return False
    return True


def load_and_verify_deterministic_astrbot_archive(
    archive_path: Path,
    receipt: dict[str, object],
    *,
    docker_binary: Path,
) -> dict[str, object]:
    """Load the verified archive twice and bind the exact local digest identity."""
    if docker_binary.as_posix() != ASTRBOT_TOOL_IDENTITIES[0][1]:
        raise TelegramGatewayReleaseRejected("Docker identity rejected")
    retained_fds: tuple[int, ...] = ()
    try:
        if not _verify_deterministic_astrbot_archive_under_authority(
            archive_path,
            receipt,
            retained_fds=(),
            validate_only=True,
        ):
            raise TelegramGatewayReleaseRejected("deterministic image verification rejected")
        _, retained_fds = _observe_tool_identities(
            ASTRBOT_TOOL_IDENTITIES,
            retain=True,
        )
        if not _verify_deterministic_astrbot_archive_under_authority(
            archive_path,
            receipt,
            retained_fds=retained_fds,
        ):
            raise TelegramGatewayReleaseRejected("deterministic image verification rejected")
        claimed_tools = tuple(
            (tool["name"], tool["path"], tool["version"], tool["sha256"])
            for tool in receipt["tools"]
        )
        _observe_tool_identities(
            claimed_tools,
            retain=True,
            retained_fds=retained_fds,
        )
        docker_descriptor = retained_fds[0]
        docker_executable = f"/proc/self/fd/{docker_descriptor}"

        def run_docker(arguments: list[str], *, capture: bool) -> subprocess.CompletedProcess[bytes]:
            _observe_tool_identities(
                claimed_tools,
                retain=True,
                retained_fds=retained_fds,
            )
            result = subprocess.run(
                [docker_executable, *arguments],
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                pass_fds=retained_fds,
            )
            _observe_tool_identities(
                claimed_tools,
                retain=True,
                retained_fds=retained_fds,
            )
            return result

        reference = str(receipt["image_reference"])
        before = run_docker(["image", "inspect", reference], capture=False)
        if before.returncode == 0:
            raise TelegramGatewayReleaseRejected("deterministic image target already exists")
        observed = None
        for _ in range(2):
            loaded = run_docker(
                ["image", "load", "--input", str(archive_path)],
                capture=False,
            )
            if loaded.returncode != 0:
                raise TelegramGatewayReleaseRejected("deterministic image load rejected")
            inspected = run_docker(["image", "inspect", reference], capture=True)
            if inspected.returncode != 0:
                raise TelegramGatewayReleaseRejected("deterministic image digest resolution rejected")
            try:
                values = json.loads(inspected.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TelegramGatewayReleaseRejected("deterministic image inspect rejected") from exc
            if type(values) is not list or len(values) != 1 or type(values[0]) is not dict:
                raise TelegramGatewayReleaseRejected("deterministic image inspect rejected")
            current = values[0]
            if (
                current.get("Id") != receipt["image_id"]
                or reference not in current.get("RepoDigests", [])
                or current.get("Architecture") != "amd64"
                or current.get("Os") != "linux"
                or current.get("RootFS", {}).get("Layers")
                != [item["diff_id"] for item in receipt["layers"]]
                or current.get("Config", {}).get("Cmd") != ["python", "main.py"]
                or current.get("Config", {}).get("WorkingDir") != "/AstrBot"
                or current.get("Config", {}).get("User") not in (None, "")
                or current.get("Config", {}).get("Entrypoint") not in (None, [])
            ):
                raise TelegramGatewayReleaseRejected("deterministic image inspect rejected")
            signature = _canonical_json(
                {
                    "config": current.get("Config"),
                    "id": current.get("Id"),
                    "repo_digests": current.get("RepoDigests"),
                    "rootfs": current.get("RootFS"),
                }
            )
            if observed is not None and signature != observed:
                raise TelegramGatewayReleaseRejected("deterministic image idempotence rejected")
            observed = signature
        _observe_tool_identities(
            claimed_tools,
            retain=True,
            retained_fds=retained_fds,
        )
        return {
            "image_id": receipt["image_id"],
            "image_reference": reference,
            "loads": 2,
            "status": "verified",
        }
    finally:
        for descriptor in retained_fds:
            os.close(descriptor)


def _regular_source(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("release source rejected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TelegramGatewayReleaseRejected("release source rejected")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("release source rejected") from exc


def _require_complete_plugin(source_root: Path) -> None:
    plugin = source_root / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
    try:
        metadata = plugin.lstat()
    except OSError as exc:
        raise TelegramGatewayReleaseRejected("release source rejected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TelegramGatewayReleaseRejected("release source rejected")
    expected = {
        Path(source).name
        for source, _, _ in COMPONENTS
        if "/plugin/myuna_telegram_gateway/" in source
    }
    actual = set()
    for item in plugin.iterdir():
        item_metadata = item.lstat()
        if stat.S_ISLNK(item_metadata.st_mode) or not stat.S_ISREG(item_metadata.st_mode):
            raise TelegramGatewayReleaseRejected("release source rejected")
        actual.add(item.name)
    if actual != expected:
        raise TelegramGatewayReleaseRejected("release source rejected")


def build_release_document(source_root: Path) -> dict[str, object]:
    _require_complete_plugin(source_root)
    files = []
    for source, destination, mode in COMPONENTS:
        content = _regular_source(source_root / source)
        files.append(
            {
                "destination": destination,
                "mode": f"{mode:04o}",
                "sha256": sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    core = {"files": files, "schema": SCHEMA}
    canonical = json.dumps(
        core,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return {**core, "release_digest": sha256(canonical).hexdigest()}


def _chmod_directories(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        os.chmod(directory, 0o555)
    os.chmod(root, 0o555)


def build_release(source_root: Path, output_root: Path) -> dict[str, object]:
    document = build_release_document(source_root)
    digest = str(document["release_digest"])
    output_root.mkdir(parents=True, exist_ok=True)
    release = output_root / digest
    manifest = output_root / f"{digest}{MANIFEST_SUFFIX}"
    if release.exists() or release.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise TelegramGatewayReleaseRejected("release output rejected")

    temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=output_root))
    manifest_temporary = output_root / f".{digest}.manifest.tmp"
    try:
        for source, destination, mode in COMPONENTS:
            target = temporary / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_regular_source(source_root / source))
            os.chmod(target, mode)
        _chmod_directories(temporary)
        manifest_bytes = json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("ascii") + b"\n"
        manifest_temporary.write_bytes(manifest_bytes)
        os.chmod(manifest_temporary, 0o444)
        os.replace(temporary, release)
        os.replace(manifest_temporary, manifest)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        try:
            manifest_temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return document


def verify_release(output_root: Path, document: dict[str, object]) -> bool:
    digest = document.get("release_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    release = output_root / digest
    manifest = output_root / f"{digest}{MANIFEST_SUFFIX}"
    try:
        if stat.S_IMODE(release.lstat().st_mode) != 0o555:
            return False
        loaded = json.loads(manifest.read_text(encoding="ascii"))
        if loaded != document or stat.S_IMODE(manifest.lstat().st_mode) != 0o444:
            return False
        expected_files = {entry[1] for entry in COMPONENTS}
        actual_files = {
            path.relative_to(release).as_posix()
            for path in release.rglob("*")
            if path.is_file()
        }
        if actual_files != expected_files:
            return False
        for entry in document["files"]:
            path = release / entry["destination"]
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                return False
            if stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8):
                return False
            content = path.read_bytes()
            if len(content) != entry["size"] or sha256(content).hexdigest() != entry["sha256"]:
                return False
        for directory in [release, *[p for p in release.rglob("*") if p.is_dir()]]:
            if stat.S_IMODE(directory.lstat().st_mode) != 0o555:
                return False
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
    return True


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    try:
        document = build_release(args.source_root, args.output_root)
        if not verify_release(args.output_root, document):
            raise TelegramGatewayReleaseRejected("release verification rejected")
    except TelegramGatewayReleaseRejected:
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {"release_digest": document["release_digest"], "status": "built"},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
