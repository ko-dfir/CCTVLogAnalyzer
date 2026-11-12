"""Read-only decoding of Dahua XVR/NVR configuration backups.

A Dahua configuration export (configFileExport.backup) starts with the marker
"MWPZWJGS" and a version byte, followed by Base64 text. The decoded bytes are
AES-ECB encrypted with a fixed key per device family (HCVR, XVR or NVR). The
plaintext holds a version byte, a little-endian payload length, the payload
and the MD5 of everything before it as 32 hex characters, which confirms the
family and the integrity of the payload. The payload is a .tar.gz of the
recorder's Config folder, mostly compact JSON.

The source file is only read; extracted files go to a new output folder.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import struct
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

MAGIC = b"MWPZWJGS"
FAMILIES = {"hcvr": "DahuaHCVR", "xvr": "DahuaXVR", "nvr": "DahuaNVR"}
MAX_UNCOMPRESSED_SIZE = 512 * 1024 * 1024


class DahuaBackupError(ValueError):
    """The file is not a decodable Dahua configuration backup."""


def is_dahua_backup(path: str | Path) -> bool:
    with open(path, "rb") as handle:
        head = handle.read(9)
    return len(head) == 9 and head[:8] == MAGIC and head[8] in (1, ord("1"))


def family_key(family: str) -> bytes:
    source = FAMILIES[family]
    obfuscated = bytes(ord(char) ^ index for index, char in enumerate(source, 1))
    return hashlib.md5(obfuscated).hexdigest().encode("ascii")


def _aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def decrypt_backup(data: bytes, family: str = "auto") -> tuple[str, bytes]:
    """Return (family, payload) once the stored MD5 matches."""
    if len(data) < 10 or data[:8] != MAGIC or data[8] not in (1, ord("1")):
        raise DahuaBackupError("Not a Dahua XVR/NVR configuration backup.")
    try:
        ciphertext = base64.b64decode(data[9:].rstrip(b"\0"), validate=True)
    except binascii.Error as exc:
        raise DahuaBackupError(f"The Base64 body is damaged: {exc}") from exc
    if not ciphertext or len(ciphertext) % 16:
        raise DahuaBackupError("The encrypted payload length is not a multiple of 16 bytes.")
    for name in (FAMILIES if family == "auto" else (family,)):
        plain = _aes_ecb_decrypt(ciphertext, family_key(name))
        if len(plain) < 37 or plain[0] != 1:
            continue
        size = struct.unpack_from("<I", plain, 1)[0]
        end = 5 + size
        if size == 0 or end + 32 > len(plain):
            continue
        if plain[end:end + 32].lower() != hashlib.md5(plain[:end]).hexdigest().encode("ascii"):
            continue
        return name, plain[5:end]
    raise DahuaBackupError(
        "The integrity check failed for every known device family "
        f"({', '.join(FAMILIES.values())}). Contact Dahua about this model's backup format.")


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (not name or "\\" in name or path.is_absolute()
            or any(part in (".", "..") or ":" in part for part in path.parts)):
        raise DahuaBackupError(f"Unsafe archive path: {name!r}")
    return path


def _unique_folder(parent: Path, stem: str) -> Path:
    candidate, number = parent / stem, 2
    while candidate.exists():
        candidate, number = parent / f"{stem}-{number}", number + 1
    return candidate


def decode_backup(path: str | Path, output_parent: str | Path, family: str = "auto") -> dict:
    """Decrypt, verify and extract into a new folder under OUTPUT_PARENT.

    Writes the archive members, a .pretty.json copy of each JSON file and
    manifest.json, and returns the manifest with its "output_folder".
    Nothing is written unless the payload decrypts, verifies and unpacks.
    """
    source = Path(path)
    data = source.read_bytes()
    family, payload = decrypt_backup(data, family)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
            archive_data = compressed.read(MAX_UNCOMPRESSED_SIZE + 1)
    except (OSError, EOFError) as exc:
        raise DahuaBackupError(f"The verified payload is not a gzip archive: {exc}") from exc
    if len(archive_data) > MAX_UNCOMPRESSED_SIZE:
        raise DahuaBackupError("The decompressed archive exceeds the size limit.")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:")
    except tarfile.TarError as exc:
        raise DahuaBackupError(f"The verified payload is not a tar archive: {exc}") from exc
    with archive:
        members = archive.getmembers()
        if not members or sum(member.size for member in members) > MAX_UNCOMPRESSED_SIZE:
            raise DahuaBackupError("The archive is empty or too large.")
        for member in members:
            _safe_member_path(member.name)
            if not (member.isfile() or member.isdir()):
                raise DahuaBackupError(f"Unsupported archive entry: {member.name!r}")

        folder = _unique_folder(Path(output_parent), f"{source.name}-config")
        folder.mkdir(parents=True)
        files = []
        for member in members:
            destination = folder.joinpath(*_safe_member_path(member.name).parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = archive.extractfile(member).read()
            destination.write_bytes(content)
            entry = {
                "path": member.name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "mtime_utc": datetime.fromtimestamp(member.mtime, timezone.utc).isoformat(timespec="seconds"),
            }
            # Dahua configuration files usually have no extension and hold compact JSON.
            if content.lstrip().startswith((b"{", b"[")):
                try:
                    parsed = json.loads(content.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    pretty = destination.with_name(destination.name + ".pretty.json")
                    pretty.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    entry["pretty_json"] = member.name + ".pretty.json"
            files.append(entry)

    manifest = {
        "source": str(source),
        "source_size": len(data),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "decoded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "format": "Dahua MWPZWJGS configuration backup",
        "device_family": family.upper(),
        "method": "Base64, AES-ECB with the device-family key, MD5-verified payload, tar.gz",
        "payload_md5_verified": True,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "file_count": len(files),
        "pretty_json_count": sum("pretty_json" in item for item in files),
        "files": files,
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest["output_folder"] = str(folder)
    return manifest
