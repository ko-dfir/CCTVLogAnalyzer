import os
import sqlite3

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QDate
from PySide6.QtWidgets import QApplication

import cctv_log_analyzer as ui


@pytest.fixture
def viewer(monkeypatch):
    application = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui.recents, "recent", lambda _limit: [])
    window = ui.CCTVLogAnalyzerWindow()
    yield window
    window.close()
    application.processEvents()


def load(window, database, table):
    window.current_db, window.current_table = str(database), table
    window.setup_table_columns()
    window.reset_and_populate()


def test_range_uses_earliest_and_latest_valid_log_times(viewer, tmp_path):
    database = tmp_path / "Extracted_Logs_TVT.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE tvt_logs (timestamp TEXT, time_unix INTEGER, event TEXT)")
        conn.executemany("INSERT INTO tvt_logs VALUES (?, ?, ?)", [
            ("2021-08-03 10:00:00 UTC", 1627984800, "first valid"),
            ("2024-07-17 18:30:00 UTC", 1721241000, "last valid"),
            ("2022-01-01 00:00:00 UTC", 1640995200, "middle"),
            ("", None, "damaged record without timestamp"),
            ("N/A (Uninitialized)", 0, "uninitialised"),
            ("N/A (Uninitialized)", 4294967295, "uninitialised 0xFFFFFFFF"),
        ])
    load(viewer, database, "tvt_logs")
    assert viewer.date_from.date() == QDate(2021, 8, 3)
    assert viewer.date_to.date() == QDate(2024, 7, 17)
    tip = viewer.date_enabled.toolTip()
    assert "2021-08-03 to 2024-07-17" in tip and "3 record(s) without a valid timestamp" in tip


def test_text_only_timestamps_ignore_placeholders(viewer, tmp_path):
    database = tmp_path / "text.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE log (timestamp TEXT, event TEXT)")
        conn.executemany("INSERT INTO log VALUES (?, ?)", [
            ("2023-04-26 13:21:10 UTC", "a"), ("2023-12-12 08:00:00 UTC", "b"),
            ("N/A (Uninitialized)", "c"), ("", "d"), ("unknown", "e"),
        ])
    load(viewer, database, "log")
    assert viewer.date_from.date() == QDate(2023, 4, 26)
    assert viewer.date_to.date() == QDate(2023, 12, 12)


def test_clear_restores_the_full_evidence_range(viewer, tmp_path):
    database = tmp_path / "dahua.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE dahua_logs (timestamp TEXT, time_unix INTEGER)")
        conn.executemany("INSERT INTO dahua_logs VALUES (?, ?)", [
            ("2025-10-03 07:41:38 UTC", 1759477298), ("2025-10-09 21:00:00 UTC", 1760043600)])
    load(viewer, database, "dahua_logs")
    viewer.date_from.setDate(QDate(2025, 10, 5))
    assert viewer.date_enabled.isChecked()
    viewer.clear_filters()
    assert not viewer.date_enabled.isChecked()
    assert viewer.date_from.date() == QDate(2025, 10, 3)
    assert viewer.date_to.date() == QDate(2025, 10, 9)
