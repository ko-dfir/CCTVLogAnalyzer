"""Dahua XVR/NVR configuration backups, built synthetically (no device data)."""

import base64
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scripts import dahua_config_backup as dcb

FILES = {
    "Config/Config1": json.dumps({"General": [{"MachineName": "DEMO-XVR"}],
                                  "ChannelTitle": [{"Name": "Entrance"}]}).encode(),
    "Config/IntelConfig1": b'{"Rules": []}',
    "Config/VideoStandardConfig": b"\x00\x00\x00\x01",
}


def make_tgz(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(content), 1790841600
            archive.addfile(info, io.BytesIO(content))
    return raw.getvalue()


def build_backup(family="xvr", files=FILES, payload=None, break_md5=False):
    payload = make_tgz(files) if payload is None else payload
    body = b"\x01" + struct.pack("<I", len(payload)) + payload
    digest = hashlib.md5(body).hexdigest().encode()
    if break_md5:
        digest = b"0" * 32
    plain = body + digest
    plain += bytes(-len(plain) % 16)
    encryptor = Cipher(algorithms.AES(dcb.family_key(family)), modes.ECB()).encryptor()
    return dcb.MAGIC + b"\x01" + base64.b64encode(encryptor.update(plain) + encryptor.finalize()) + b"\x00"


class DahuaConfigBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_detection(self):
        self.assertTrue(dcb.is_dahua_backup(self.write("a.backup", build_backup())))
        self.assertFalse(dcb.is_dahua_backup(self.write("b", b"\x00" * 64)))
        self.assertFalse(dcb.is_dahua_backup(self.write("c", b"MWPZ")))

    def test_both_families_round_trip(self):
        for family in ("hcvr", "xvr", "nvr"):
            path = self.write(f"{family}.backup", build_backup(family))
            manifest = dcb.decode_backup(path, self.root / family)
            folder = Path(manifest["output_folder"])
            self.assertEqual(manifest["device_family"], family.upper())
            self.assertEqual(manifest["file_count"], 3)
            self.assertEqual(manifest["pretty_json_count"], 2)
            for name, content in FILES.items():
                self.assertEqual((folder / name).read_bytes(), content)
            pretty = json.loads((folder / "Config/Config1.pretty.json").read_text(encoding="utf-8"))
            self.assertEqual(pretty["General"][0]["MachineName"], "DEMO-XVR")
            stored = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(stored["payload_md5_verified"])
            self.assertEqual({f["path"] for f in stored["files"]}, set(FILES))
            self.assertNotIn("output_folder", stored)

    def test_explicit_wrong_family_fails(self):
        path = self.write("x.backup", build_backup("xvr"))
        with self.assertRaises(dcb.DahuaBackupError):
            dcb.decode_backup(path, self.root / "out", family="nvr")

    def test_integrity_failure_writes_nothing(self):
        path = self.write("bad.backup", build_backup(break_md5=True))
        out = self.root / "out"
        out.mkdir()
        with self.assertRaisesRegex(dcb.DahuaBackupError, "integrity") as caught:
            dcb.decode_backup(path, out)
        self.assertEqual(list(out.iterdir()), [])
        for name in ("DahuaHCVR", "DahuaXVR", "DahuaNVR"):
            self.assertIn(name, str(caught.exception))

    def test_unsafe_archive_paths_are_refused(self):
        for name in ("../escape", "/abs/path", "Config/C:evil"):
            path = self.write("unsafe.backup", build_backup(files={name: b"{}"}))
            out = self.root / "unsafe-out"
            with self.assertRaisesRegex(dcb.DahuaBackupError, "Unsafe"):
                dcb.decode_backup(path, out)
            self.assertFalse(out.exists())

    def test_damaged_body_is_reported(self):
        path = self.write("damaged.backup", dcb.MAGIC + b"\x01" + b"not base64!!" + b"\x00")
        with self.assertRaises(dcb.DahuaBackupError):
            dcb.decode_backup(path, self.root / "out")

    def test_second_decode_uses_a_new_folder(self):
        path = self.write("cfg.backup", build_backup())
        first = dcb.decode_backup(path, self.root)["output_folder"]
        second = dcb.decode_backup(path, self.root)["output_folder"]
        self.assertTrue(second.endswith("cfg.backup-config-2"))
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
