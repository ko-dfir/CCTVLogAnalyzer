"""Open, validate and decode a Hikvision configuration backup.

Flow: choose the backup, recognise it without the code, ask whether the
export code is known. With the code: verify it, choose an output folder and
decode. Without it: show the hashcat mode 26401 line and instructions.
"""

import os

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout,
)

from scripts.hikvision_config_backup import (
    FIRMWARE_NOTE, MAX_CODE_LENGTH, BackupError, WrongCodeError, decode_backup, hashcat_instructions,
    hashcat_line, inspect_backup, verify_code,
)


class HashcatDialog(QDialog):
    """Hash line and instructions for recovering an unknown export code."""

    def __init__(self, backup_path, parent=None):
        super().__init__(parent)
        self.backup_path = backup_path
        self.enter_code_requested = False
        self.saved_path = None
        self.line = hashcat_line(backup_path)
        self.setWindowTitle("Recover the export code with hashcat")
        self.resize(760, 620)

        layout = QVBoxLayout(self)
        intro = QLabel(f"Hashcat mode 26401 line for <b>{os.path.basename(backup_path)}</b>:")
        intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(intro)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.line_edit = QLineEdit(self.line)
        self.line_edit.setReadOnly(True)
        self.line_edit.setFont(mono)
        layout.addWidget(self.line_edit)

        self.instructions = QPlainTextEdit(hashcat_instructions(self.line))
        self.instructions.setReadOnly(True)
        self.instructions.setFont(mono)
        layout.addWidget(self.instructions, 1)

        buttons = QHBoxLayout()
        self.btn_copy = QPushButton("Copy hash line")
        self.btn_copy.clicked.connect(self.copy_line)
        self.btn_save = QPushButton("Save hash file…")
        self.btn_save.clicked.connect(self.save_hash_file)
        self.btn_code = QPushButton("I have the code now…")
        self.btn_code.clicked.connect(self.request_code)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.reject)
        buttons.addWidget(self.btn_copy)
        buttons.addWidget(self.btn_save)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_code)
        buttons.addWidget(btn_close)
        layout.addLayout(buttons)

    def copy_line(self):
        QGuiApplication.clipboard().setText(self.line)
        self.btn_copy.setText("Copied")

    def save_hash_file(self):
        suggested = os.path.join(os.path.dirname(self.backup_path),
                                 os.path.basename(self.backup_path) + ".hash")
        path, _ = QFileDialog.getSaveFileName(self, "Save hashcat hash file", suggested,
                                              "Hash files (*.hash *.txt);;All Files (*.*)")
        if path:
            self.write_hash_file(path)

    def write_hash_file(self, path):
        with open(path, "w", encoding="ascii", newline="\n") as handle:
            handle.write(self.line + "\n")
        self.saved_path = path
        self.btn_save.setText("Saved")

    def request_code(self):
        self.enter_code_requested = True
        self.accept()


def ask_export_code(parent, backup_path):
    """Prompt until the code opens the backup; None if cancelled."""
    prompt = f"Export code (1-{MAX_CODE_LENGTH} characters):"
    while True:
        code, ok = QInputDialog.getText(parent, "Export code", prompt, QLineEdit.EchoMode.Password)
        if not ok:
            return None
        try:
            if verify_code(backup_path, code):
                return code
            prompt = ("That code does not open this backup. Try again.\n"
                      "(Backups from firmware older than 4.x may use a different format.)")
        except ValueError as exc:
            prompt = f"{exc} Try again:"


def decode_with_code(parent, backup_path, code, log=None, start_dir=""):
    """Choose an output folder and decode; returns the manifest or None."""
    folder = QFileDialog.getExistingDirectory(parent, "Choose where to save the decoded configuration",
                                              start_dir or os.path.dirname(backup_path))
    if not folder:
        return None
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        manifest = decode_backup(backup_path, code, folder)
    except (BackupError, OSError) as exc:
        QApplication.restoreOverrideCursor()
        QMessageBox.warning(parent, "Decoding failed", f"{exc}\n\n{FIRMWARE_NOTE}")
        if log:
            log(f"[Config backup] Decoding failed: {exc}")
        return None
    QApplication.restoreOverrideCursor()
    output = manifest["output_folder"]
    if log:
        log(f"[Config backup] Decoded {manifest['section_count']} sections of "
            f"{backup_path} (SHA-256 {manifest['source_sha256']}) to {output}")
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Information)
    box.setWindowTitle("Configuration decoded")
    box.setText(f"Decoded {manifest['section_count']} sections; every stored checksum matched.")
    box.setInformativeText(f"Saved to:\n{output}\n\nThe decoded files contain the device settings "
                           "in clear text, including stored credentials. Handle them as evidence.")
    open_button = box.addButton("Open folder", QMessageBox.ButtonRole.ActionRole)
    box.addButton(QMessageBox.StandardButton.Close)
    box.exec()
    if box.clickedButton() is open_button:
        QDesktopServices.openUrl(QUrl.fromLocalFile(output))
    return manifest


def run_config_backup(parent, log=None, start_dir=""):
    """Full interactive flow; returns the decode manifest or None."""
    path, _ = QFileDialog.getOpenFileName(parent, "Select Hikvision configuration backup", start_dir,
                                          "All Files (*)")
    if not path:
        return None
    try:
        info = inspect_backup(path)
    except OSError as exc:
        QMessageBox.warning(parent, "Cannot read file", str(exc))
        return None
    if log:
        log(f"[Config backup] {path}: {info.size:,} bytes, SHA-256 {info.sha256}; {info.reason}")
    if not info.valid:
        QMessageBox.warning(parent, "Not a configuration backup",
                            f"{os.path.basename(path)} is not a Hikvision configuration backup.\n\n{info.reason}"
                            f"\n\n{FIRMWARE_NOTE}")
        return None

    answer = QMessageBox.question(
        parent, "Configuration backup recognised",
        f"{os.path.basename(path)}\n{info.size:,} bytes\nSHA-256 {info.sha256}\n\n"
        "This is an encrypted Hikvision configuration backup.\n"
        f"{FIRMWARE_NOTE}\n\n"
        "Do you have the export code it was saved with?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
        QMessageBox.StandardButton.Yes)
    if answer == QMessageBox.StandardButton.Cancel:
        return None
    if answer == QMessageBox.StandardButton.No:
        dialog = HashcatDialog(path, parent)
        dialog.exec()
        if log and dialog.saved_path:
            log(f"[Config backup] Hashcat hash file saved to {dialog.saved_path}")
        if not dialog.enter_code_requested:
            return None

    code = ask_export_code(parent, path)
    if code is None:
        return None
    try:
        return decode_with_code(parent, path, code, log, start_dir)
    except WrongCodeError as exc:
        QMessageBox.warning(parent, "Decoding failed", str(exc))
        return None
