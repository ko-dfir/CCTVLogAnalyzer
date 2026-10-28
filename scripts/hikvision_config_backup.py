"""Read-only inspection and decoding of Hikvision configuration backups.

A configuration export ("Export configuration file" on the recorder) is a
fixed 113,444-byte header followed by the configuration sections. The header
and every section are AES-128-ECB encrypted with the export code, ASCII and
zero-padded to 16 bytes, without key derivation or salt. Each decrypted section
is a sequence of raw LZMA1 streams holding the configuration as UTF-8 text.

The header is mostly zero bytes, and ECB encrypts equal blocks equally, so an
encrypted header repeats one block thousands of times. That makes a backup
recognisable before the export code is known. Header bytes 48-63 decrypt to
the tail of the first section name "sysReserve.cfg", a known-plaintext block
that hashcat mode 26401 can attack when the code is unknown.

The source file is only read; decoded sections go to a new output folder.
"""

from __future__ import annotations

import collections
import hashlib
import json
import lzma
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAGIC = 20150909
RECORD_SIZE = 2268
MAX_SECTIONS = 50
HEADER_SIZE = 44 + MAX_SECTIONS * RECORD_SIZE
MAX_CODE_LENGTH = 16
HASHCAT_MODE = 26401
KNOWN_BLOCK3 = b"eserve.cfg".ljust(16, b"\0")
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 25, "lc": 0, "lp": 0, "pb": 2}]
MAX_STREAM = 32 * 1024 * 1024
MAX_SECTION = 128 * 1024 * 1024
MIN_REPEAT_RATIO = 0.5
SECTION_NAME = re.compile(r"[A-Za-z0-9_.-]{1,60}\.cfg")
OLDER_FIRMWARE_TOOLS = (
    "https://github.com/WormChickenWizard/hikvision-decrypter",
    "https://github.com/rafayahmed317/hikvision-decryptor",
)
FIRMWARE_NOTE = (
    "Tested with backups from Hikvision firmware 4.x and later. It is not known "
    "whether backups from earlier firmware use the same format. For older firmware, see "
    + " and ".join(OLDER_FIRMWARE_TOOLS) + "."
)


class BackupError(ValueError):
    """The file is not a decodable configuration backup."""


class WrongCodeError(BackupError):
    """The export code does not open this backup."""


@dataclass(frozen=True)
class BackupInfo:
    path: str
    size: int
    sha256: str
    valid: bool
    reason: str
    repeat_ratio: float


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_backup(path: str | Path) -> BackupInfo:
    """Recognise a configuration backup without the export code."""
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as handle:
        header = handle.read(HEADER_SIZE)
    sha256 = _sha256(path)
    if size < HEADER_SIZE:
        return BackupInfo(str(path), size, sha256, False,
                          f"The file is {size:,} bytes; a configuration backup has a "
                          f"{HEADER_SIZE:,}-byte header followed by its sections.", 0.0)
    blocks = collections.Counter(header[i:i + 16] for i in range(0, HEADER_SIZE - 15, 16))
    block, count = blocks.most_common(1)[0]
    ratio = count / (HEADER_SIZE // 16)
    if block == bytes(16):
        return BackupInfo(str(path), size, sha256, False,
                          "The header is not encrypted (it holds plain zero blocks).", ratio)
    if ratio < MIN_REPEAT_RATIO:
        return BackupInfo(str(path), size, sha256, False,
                          "The header does not have the repeated encrypted blocks of a "
                          "configuration backup.", ratio)
    return BackupInfo(str(path), size, sha256, True,
                      "Encrypted Hikvision configuration backup header recognised.", ratio)


def code_key(code: str) -> bytes:
    if not isinstance(code, str) or not code:
        raise ValueError("Enter the export code.")
    if not all(32 <= ord(ch) < 127 for ch in code):
        raise ValueError("The export code must use printable ASCII characters.")
    if len(code) > MAX_CODE_LENGTH:
        raise ValueError(f"The export code is at most {MAX_CODE_LENGTH} characters.")
    return code.encode("ascii").ljust(16, b"\0")


def _decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB over the whole 16-byte blocks; a trailing remainder stays as is."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    n = len(data) // 16 * 16
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data[:n]) + decryptor.finalize() + data[n:]


def verify_code(path: str | Path, code: str) -> bool:
    """True if CODE decrypts the header marker, section count and zero padding."""
    key = code_key(code)
    with open(path, "rb") as handle:
        head = handle.read(48)
    if len(head) < 48:
        return False
    plain = _decrypt(head, key)
    count = struct.unpack_from("<I", plain, 40)[0]
    return (struct.unpack_from("<I", plain, 0)[0] == MAGIC and plain[8:16] == bytes(8)
            and 1 <= count <= MAX_SECTIONS)


def hashcat_line(path: str | Path) -> str:
    """Hash line for hashcat mode 26401: ciphertext:known plaintext."""
    with open(path, "rb") as handle:
        head = handle.read(64)
    if len(head) < 64:
        raise BackupError("The file is too short to be a configuration backup.")
    return f"{head[48:64].hex()}:{KNOWN_BLOCK3.hex()}"


def hashcat_instructions(line: str, hash_file: str = "hikvision_backup.hash") -> str:
    return f"""Recovering the export code with hashcat

The export code is the AES-128 key itself (ASCII, zero-padded, no key
derivation), so hashcat mode {HASHCAT_MODE} "AES-128-ECB NOKDF (PT = $salt,
key = $pass)" tests candidates directly. Codes longer than {MAX_CODE_LENGTH}
characters cannot exist.

1. Save this line as {hash_file}:

   {line}

2. Run one or more attacks (hashcat 6.2.6 or later), for example:

   Numeric codes, 1 to 10 digits:
     hashcat -m {HASHCAT_MODE} -a 3 {hash_file} ?d?d?d?d?d?d?d?d?d?d --increment

   Lower case letters and digits, up to 8 characters:
     hashcat -m {HASHCAT_MODE} -a 3 -1 ?l?d {hash_file} ?1?1?1?1?1?1?1?1 --increment

   Wordlist with rules:
     hashcat -m {HASHCAT_MODE} -a 0 {hash_file} wordlist.txt -r rules/best64.rule

3. Show a recovered code:

     hashcat -m {HASHCAT_MODE} {hash_file} --show

   The code follows the last colon of the output. Open the backup again in
   CCTV Log Analyzer and enter it to decode the configuration.

Notes
- Every backup exported with the same code has the same hash line, so one
  recovered code opens all of them.
- The known plaintext is the end of the first section name "sysReserve.cfg".
  A device with a different first section produces a line that cannot match.
- Short or numeric codes fall in seconds to minutes on a GPU. Long random
  codes (10 or more mixed characters) are beyond practical search; ask the
  device owner or check case notes for the code instead.
- Tested with backups from firmware 4.x and later. It is not known whether
  backups from earlier firmware use the same format; for older firmware see
  {OLDER_FIRMWARE_TOOLS[0]}
  {OLDER_FIRMWARE_TOOLS[1]}
"""


def decode_streams(data: bytes) -> tuple[bytes, list[dict[str, int]]]:
    """Decompress concatenated raw LZMA1 streams."""
    pos, parts, streams, total = 0, [], [], 0
    while pos < len(data):
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=LZMA_FILTERS)
        plain = decompressor.decompress(data[pos:], max_length=MAX_STREAM + 1)
        if len(plain) > MAX_STREAM or not decompressor.eof:
            raise BackupError(f"LZMA stream at offset {pos} did not finish within the limit.")
        consumed = len(data) - pos - len(decompressor.unused_data)
        if consumed <= 0:
            raise BackupError(f"No compressed input consumed at offset {pos}.")
        streams.append({"input_offset": pos, "input_length": consumed, "output_length": len(plain)})
        parts.append(plain)
        total += len(plain)
        if total > MAX_SECTION:
            raise BackupError("A decompressed section exceeds the size limit.")
        pos += consumed
    return b"".join(parts), streams


def _unique_folder(parent: Path, stem: str) -> Path:
    candidate = parent / stem
    number = 2
    while candidate.exists():
        candidate = parent / f"{stem}-{number}"
        number += 1
    return candidate


def decode_backup(path: str | Path, code: str, output_parent: str | Path) -> dict:
    """Decode every section into a new folder under OUTPUT_PARENT.

    Writes decoded/<section>.cfg.txt and manifest.json, and returns the
    manifest with its "output_folder". Nothing is written unless every
    section decrypts, matches its stored byte sum and decompresses.
    """
    source = Path(path)
    key = code_key(code)
    data = source.read_bytes()
    if len(data) < HEADER_SIZE:
        raise BackupError("The file is shorter than the configuration backup header.")
    if not verify_code(source, code):
        raise WrongCodeError("The export code does not open this backup.")
    header = _decrypt(data[:HEADER_SIZE], key)
    count = struct.unpack_from("<I", header, 40)[0]

    sections, names, pos = [], set(), HEADER_SIZE
    for index in range(count):
        record = header[44 + index * RECORD_SIZE:44 + (index + 1) * RECORD_SIZE]
        name = record[:64].split(b"\0", 1)[0].decode("ascii", "replace")
        size, byte_sum = struct.unpack_from("<II", record, 104)
        if not SECTION_NAME.fullmatch(name) or name.lower() in names:
            raise BackupError(f"Invalid or duplicate section name at index {index}.")
        if size < 1 or pos + size > len(data):
            raise BackupError(f"Section {name} lies outside the file.")
        names.add(name.lower())
        compressed = _decrypt(data[pos:pos + size], key)
        if sum(compressed) & 0xFFFFFFFF != byte_sum:
            raise BackupError(f"Section {name} does not match its stored checksum.")
        try:
            plain, streams = decode_streams(compressed)
            plain.decode("utf-8")
        except (lzma.LZMAError, UnicodeDecodeError) as exc:
            raise BackupError(f"Section {name} could not be decoded: {exc}") from exc
        try:
            ET.fromstring(plain)
            strict_xml = True
        except ET.ParseError:
            strict_xml = False
        sections.append({
            "index": index,
            "name": name,
            "source_offset": pos,
            "compressed_size": size,
            "stored_byte_sum": byte_sum,
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "decoded_size": len(plain),
            "decoded_sha256": hashlib.sha256(plain).hexdigest(),
            "streams": streams,
            "strict_xml": strict_xml,
            "output": f"decoded/{name}.txt",
            "_plain": plain,
        })
        pos += size

    trailing = data[pos:]
    folder = _unique_folder(Path(output_parent), f"{source.name}-config")
    decoded = folder / "decoded"
    decoded.mkdir(parents=True)
    for section in sections:
        (decoded / f"{section['name']}.txt").write_bytes(section.pop("_plain"))
    manifest = {
        "source": str(source),
        "source_size": len(data),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "decoded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": "AES-128-ECB, key = zero-padded ASCII export code; raw LZMA1 streams",
        "export_code_verified": True,
        "section_count": count,
        "all_checksums_valid": True,
        "indexed_end": pos,
        "trailing_bytes": len(trailing),
        "trailing_bytes_all_zero": not any(trailing),
        "hashcat_mode": HASHCAT_MODE,
        "hashcat_line": hashcat_line(source),
        "sections": sections,
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest["output_folder"] = str(folder)
    return manifest
