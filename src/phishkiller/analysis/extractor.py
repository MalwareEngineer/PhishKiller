"""Archive extraction with security protections."""

import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractionResult:
    extracted_dir: str
    file_list: list[str] = field(default_factory=list)
    file_count: int = 0
    total_size: int = 0
    errors: list[str] = field(default_factory=list)


MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500 MB total
MAX_FILE_COUNT = 10_000
MAX_SINGLE_FILE = 50 * 1024 * 1024  # 50 MB per file


class ArchiveExtractor:
    """Extract archive files with path traversal protection and size limits."""

    def extract(self, archive_path: str, output_dir: str) -> ExtractionResult:
        """Extract an archive to the output directory.

        Supports: .zip, .tar.gz, .tar.bz2, .tgz, .tar
        """
        archive_path_obj = Path(archive_path)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        suffix = archive_path_obj.suffix.lower()
        suffixes = "".join(s.lower() for s in archive_path_obj.suffixes[-2:])

        if suffix == ".zip":
            return self._extract_zip(archive_path, output_dir)
        elif suffixes in (".tar.gz", ".tar.bz2") or suffix in (".tgz", ".tar"):
            return self._extract_tar(archive_path, output_dir)
        elif suffix == ".rar":
            return self._extract_rar(archive_path, output_dir)
        else:
            return ExtractionResult(
                extracted_dir=output_dir,
                errors=[f"Unsupported archive format: {suffix}"],
            )

    def _extract_zip(self, archive_path: str, output_dir: str) -> ExtractionResult:
        result = ExtractionResult(extracted_dir=output_dir)
        output_path = Path(output_dir).resolve()

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if result.file_count >= MAX_FILE_COUNT:
                        result.errors.append("Max file count exceeded")
                        break

                    # Path traversal check
                    target = (output_path / info.filename).resolve()
                    if not str(target).startswith(str(output_path)):
                        result.errors.append(
                            f"Skipped path traversal attempt: {info.filename}"
                        )
                        continue

                    # Skip directories
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue

                    # Size checks
                    if info.file_size > MAX_SINGLE_FILE:
                        result.errors.append(
                            f"Skipped oversized file: {info.filename} "
                            f"({info.file_size} bytes)"
                        )
                        continue
                    if result.total_size + info.file_size > MAX_EXTRACTED_SIZE:
                        result.errors.append("Total extraction size exceeded")
                        break

                    # Extract
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(target, "wb") as dst:
                        dst.write(src.read())

                    result.file_list.append(info.filename)
                    result.file_count += 1
                    result.total_size += info.file_size

        except zipfile.BadZipFile as e:
            result.errors.append(f"Bad ZIP file: {e}")
        except Exception as e:
            result.errors.append(f"ZIP extraction error: {e}")

        return result

    def _extract_tar(self, archive_path: str, output_dir: str) -> ExtractionResult:
        result = ExtractionResult(extracted_dir=output_dir)
        output_path = Path(output_dir).resolve()

        try:
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    if result.file_count >= MAX_FILE_COUNT:
                        result.errors.append("Max file count exceeded")
                        break

                    # Path traversal check
                    target = (output_path / member.name).resolve()
                    if not str(target).startswith(str(output_path)):
                        result.errors.append(
                            f"Skipped path traversal attempt: {member.name}"
                        )
                        continue

                    # Skip symlinks and special files
                    if member.issym() or member.islnk():
                        result.errors.append(
                            f"Skipped symlink: {member.name}"
                        )
                        continue

                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue

                    if not member.isfile():
                        continue

                    # Size checks
                    if member.size > MAX_SINGLE_FILE:
                        result.errors.append(
                            f"Skipped oversized file: {member.name}"
                        )
                        continue
                    if result.total_size + member.size > MAX_EXTRACTED_SIZE:
                        result.errors.append("Total extraction size exceeded")
                        break

                    target.parent.mkdir(parents=True, exist_ok=True)
                    f = tf.extractfile(member)
                    if f:
                        with open(target, "wb") as dst:
                            dst.write(f.read())

                    result.file_list.append(member.name)
                    result.file_count += 1
                    result.total_size += member.size

        except tarfile.TarError as e:
            result.errors.append(f"TAR extraction error: {e}")
        except Exception as e:
            result.errors.append(f"Extraction error: {e}")

        return result

    def _extract_rar(self, archive_path: str, output_dir: str) -> ExtractionResult:
        result = ExtractionResult(extracted_dir=output_dir)

        try:
            import rarfile

            output_path = Path(output_dir).resolve()

            with rarfile.RarFile(archive_path, "r") as rf:
                for info in rf.infolist():
                    if result.file_count >= MAX_FILE_COUNT:
                        result.errors.append("Max file count exceeded")
                        break

                    if info.is_dir():
                        continue

                    target = (output_path / info.filename).resolve()
                    if not str(target).startswith(str(output_path)):
                        result.errors.append(
                            f"Skipped path traversal attempt: {info.filename}"
                        )
                        continue

                    if info.file_size > MAX_SINGLE_FILE:
                        result.errors.append(
                            f"Skipped oversized file: {info.filename}"
                        )
                        continue
                    if result.total_size + info.file_size > MAX_EXTRACTED_SIZE:
                        result.errors.append("Total extraction size exceeded")
                        break

                    target.parent.mkdir(parents=True, exist_ok=True)
                    with rf.open(info) as src, open(target, "wb") as dst:
                        dst.write(src.read())

                    result.file_list.append(info.filename)
                    result.file_count += 1
                    result.total_size += info.file_size

        except ImportError:
            result.errors.append("rarfile package not installed")
        except Exception as e:
            result.errors.append(f"RAR extraction error: {e}")

        return result
