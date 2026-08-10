"""Setuptools hook for byte-for-byte reproducible source distributions."""

from __future__ import annotations

import gzip
import os
import stat
import tarfile
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

from setuptools import setup
from setuptools.command.sdist import sdist


class ReproducibleSdist(sdist):
    """Normalize archive metadata when ``SOURCE_DATE_EPOCH`` is supplied."""

    def make_archive(
        self,
        base_name: str | os.PathLike[str],
        format: str,
        root_dir: str | os.PathLike[str] | bytes | os.PathLike[bytes] | None = None,
        base_dir: str | None = None,
        owner: str | None = None,
        group: str | None = None,
    ) -> str:
        epoch_text = os.environ.get("SOURCE_DATE_EPOCH")
        if format != "gztar" or epoch_text is None:
            return super().make_archive(base_name, format, root_dir, base_dir, owner, group)

        try:
            epoch = int(epoch_text)
        except ValueError as exc:
            raise ValueError("SOURCE_DATE_EPOCH must be an unsigned decimal integer") from exc
        if not 0 <= epoch <= 4_294_967_295:
            raise ValueError("SOURCE_DATE_EPOCH must fit the gzip 32-bit timestamp field")

        archive_path = Path(f"{os.fspath(base_name)}.tar.gz")
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        source_root = Path(os.fsdecode(root_dir)) if root_dir is not None else Path.cwd()
        source_name = base_dir or Path(os.fspath(base_name)).name
        source_path = source_root / source_name
        if Path(source_name).name != source_name or source_name in {"", ".", ".."}:
            raise ValueError(f"unsafe source-distribution root name: {source_name!r}")
        if not source_path.is_dir() or source_path.is_symlink():
            raise ValueError(
                f"source-distribution staging root is not a real directory: {source_path}"
            )

        normalized_paths: dict[str, str] = {}
        for directory, directory_names, file_names in os.walk(source_path, followlinks=False):
            directory_names.sort()
            file_names.sort()
            current = Path(directory)
            for name in [*directory_names, *file_names]:
                item = current / name
                relative = item.relative_to(source_path).as_posix()
                normalized = unicodedata.normalize("NFC", relative)
                previous = normalized_paths.get(normalized)
                if normalized != relative:
                    raise ValueError(
                        f"source-distribution path is not NFC-normalized: {relative!r}"
                    )
                if previous is not None and previous != relative:
                    raise ValueError(
                        "source-distribution paths collide after NFC normalization: "
                        f"{previous!r}, {relative!r}"
                    )
                normalized_paths[normalized] = relative

                metadata = item.lstat()
                mode = metadata.st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError(
                        f"source distribution contains a link or special file: {relative!r}"
                    )
                if stat.S_ISREG(mode) and metadata.st_nlink != 1:
                    raise ValueError(
                        f"source distribution contains a hard-linked file: {relative!r}"
                    )

        def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.pax_headers = {}
            if info.isdir():
                info.mode = 0o755
            elif info.isfile():
                info.mode = 0o755 if info.mode & 0o111 else 0o644
            else:
                raise ValueError(f"unexpected source-distribution member type: {info.name!r}")
            return info

        with (
            archive_path.open("xb") as raw_archive,
            gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw_archive,
                mtime=epoch,
            ) as compressed_archive,
            tarfile.open(
                fileobj=compressed_archive,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as archive,
        ):
            archive.add(source_path, arcname=source_name, filter=normalize)

        return str(archive_path)


# Setuptools' public setup callable intentionally has a dynamic signature.
_setup: Callable[..., Any] = setup
_setup(cmdclass={"sdist": ReproducibleSdist})
