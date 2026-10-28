"""Hikvision configuration backups, built synthetically (no device data)."""

import json
import lzma
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scripts import hikvision_config_backup as hcb

SECTIONS = {
    "sysReserve.cfg": b"<sysReserve><value>1</value></sysReserve>",
    "network.cfg": b"<network><ip>[49][48][46][48][46][48][46][49][0]</ip></network>" * 40,
    "user.cfg": "<user><name>examiner</name><note>café</note></user>".encode("utf-8"),
}


def encrypt(data, key):
    n = len(data) // 16 * 16
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data[:n]) + encryptor.finalize() + data[n:]


def compress(data, chunks=2):
    step = max(1, len(data) // chunks)
    out = b""
    for start in range(0, len(data), step):
        part = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=hcb.LZMA_FILTERS)
        out += part.compress(data[start:start + step]) + part.flush()
    return out


def build_backup(code="7391", sections=SECTIONS, corrupt_checksum=False):
    key = code.encode("ascii").ljust(16, b"\0")
    header = bytearray(hcb.HEADER_SIZE)
    struct.pack_into("<I", header, 0, hcb.MAGIC)
    struct.pack_into("<I", header, 4, 0x01020304)
    struct.pack_into("<I", header, 40, len(sections))
    body = b""
    for index, (name, text) in enumerate(sections.items()):
        compressed = compress(text)
        record = 44 + index * hcb.RECORD_SIZE
        header[record:record + len(name)] = name.encode("ascii")
        byte_sum = sum(compressed) + (1 if corrupt_checksum and index == 1 else 0)
        struct.pack_into("<II", header, record + 104, len(compressed), byte_sum)
        body += encrypt(compressed, key)
    return encrypt(bytes(header), key) + body + bytes(64)


class ConfigBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_backup_is_recognised_without_the_code(self):
        info = hcb.inspect_backup(self.write("backup", build_backup()))
        self.assertTrue(info.valid, info.reason)
        self.assertGreater(info.repeat_ratio, 0.9)
        self.assertEqual(len(info.sha256), 64)

    def test_other_files_are_rejected(self):
        short = hcb.inspect_backup(self.write("short", b"\x01" * 1000))
        random = hcb.inspect_backup(self.write("random", os.urandom(hcb.HEADER_SIZE + 512)))
        plain = hcb.inspect_backup(self.write("zeros", bytes(hcb.HEADER_SIZE + 512)))
        self.assertFalse(short.valid)
        self.assertFalse(random.valid)
        self.assertFalse(plain.valid)
        self.assertIn("not encrypted", plain.reason)

    def test_code_verification(self):
        path = self.write("backup", build_backup("Secret-99"))
        self.assertTrue(hcb.verify_code(path, "Secret-99"))
        self.assertFalse(hcb.verify_code(path, "secret-99"))
        self.assertFalse(hcb.verify_code(path, "7391"))
        for bad in ("", "x" * 17, "café"):
            with self.assertRaises(ValueError):
                hcb.verify_code(path, bad)

    def test_decode_round_trip_writes_sections_and_manifest(self):
        path = self.write("backup", build_backup())
        manifest = hcb.decode_backup(path, "7391", self.root)
        folder = Path(manifest["output_folder"])
        self.assertEqual(folder.name, "backup-config")
        self.assertEqual(manifest["section_count"], 3)
        self.assertTrue(manifest["trailing_bytes_all_zero"])
        for name, text in SECTIONS.items():
            self.assertEqual((folder / "decoded" / f"{name}.txt").read_bytes(), text)
        stored = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual([s["name"] for s in stored["sections"]], list(SECTIONS))
        self.assertTrue(stored["sections"][0]["strict_xml"])
        self.assertGreaterEqual(len(stored["sections"][1]["streams"]), 2)
        self.assertNotIn("7391", json.dumps(stored))
        self.assertNotIn("output_folder", stored)

    def test_second_decode_uses_a_new_folder(self):
        path = self.write("backup", build_backup())
        first = hcb.decode_backup(path, "7391", self.root)["output_folder"]
        second = hcb.decode_backup(path, "7391", self.root)["output_folder"]
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith("backup-config-2"))

    def test_wrong_code_writes_nothing(self):
        path = self.write("backup", build_backup())
        out = self.root / "out"
        out.mkdir()
        with self.assertRaises(hcb.WrongCodeError):
            hcb.decode_backup(path, "4321", out)
        self.assertEqual(list(out.iterdir()), [])

    def test_checksum_mismatch_writes_nothing(self):
        path = self.write("backup", build_backup(corrupt_checksum=True))
        out = self.root / "out"
        out.mkdir()
        with self.assertRaisesRegex(hcb.BackupError, "network.cfg"):
            hcb.decode_backup(path, "7391", out)
        self.assertEqual(list(out.iterdir()), [])

    def test_unsafe_section_names_are_refused(self):
        path = self.write("backup", build_backup(sections={"sysReserve.cfg": b"<a/>", "..\\x.cfg": b"<b/>"}))
        with self.assertRaisesRegex(hcb.BackupError, "section name"):
            hcb.decode_backup(path, "7391", self.root / "out")

    def test_hashcat_line_matches_mode_26401(self):
        path = self.write("backup", build_backup("hik"))
        line = hcb.hashcat_line(path)
        cipher_hex, plain_hex = line.split(":")
        self.assertEqual(plain_hex, hcb.KNOWN_BLOCK3.hex())
        # hashcat 26401: AES-128-ECB(key = zero-padded password, data = salt) == hash
        self.assertEqual(encrypt(bytes.fromhex(plain_hex), b"hik".ljust(16, b"\0")).hex(), cipher_hex)
        self.assertIn(line, hcb.hashcat_instructions(line))
        self.assertIn("-m 26401", hcb.hashcat_instructions(line))

    def test_hashcat_self_test_vector(self):
        # Self-test pair from hashcat's module_26401 (password "hashcat").
        cipher_hex, plain_hex = "e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724".split(":")
        self.assertEqual(encrypt(bytes.fromhex(plain_hex), hcb.code_key("hashcat")).hex(), cipher_hex)

    def test_older_firmware_tools_are_referenced(self):
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        for url in hcb.OLDER_FIRMWARE_TOOLS:
            self.assertIn(url, hcb.FIRMWARE_NOTE)
            self.assertIn(url, hcb.hashcat_instructions("a:b"))
            self.assertIn(url, readme)
        self.assertIn("4.x", hcb.FIRMWARE_NOTE)

    def test_same_code_gives_the_same_hash_line(self):
        first = self.write("a", build_backup("2580"))
        second = self.write("b", build_backup("2580", sections={"sysReserve.cfg": b"<other/>"}))
        self.assertEqual(hcb.hashcat_line(first), hcb.hashcat_line(second))


class ConfigBackupDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_hashcat_dialog_shows_and_saves_the_line(self):
        from scripts.config_backup_dialog import HashcatDialog
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "backup"
            path.write_bytes(build_backup())
            dialog = HashcatDialog(str(path))
            self.assertEqual(dialog.line_edit.text(), hcb.hashcat_line(path))
            self.assertIn("hashcat -m 26401", dialog.instructions.toPlainText())
            target = Path(folder) / "backup.hash"
            dialog.write_hash_file(str(target))
            self.assertEqual(target.read_text(encoding="ascii"), dialog.line + "\n")
            dialog.request_code()
            self.assertTrue(dialog.enter_code_requested)


if __name__ == "__main__":
    unittest.main()
