# Changelog

## 1.01 — 2026-10-18

Initial public release of CCTV Log Analyzer, the successor of
[HikvisionLogAnalyzer](https://github.com/theAtropos4n6/HikvisionLogAnalyzer).

### Evidence and detection

- Raw/DD images (including split `.001/.002/...` sets), EnCase E01 images and
  read-only physical drives.
- Recorder brand identified from on-disk structures, never from file names:
  Hikvision (HIKFAT/`RATS`), Dahua (GPT/XFS) and TVT (`mlogtype:` records).
  iCatch disks are identified from their hourly recording index; no usable
  logs were found on them, so no extraction is offered.
- Physical Drive checks for Administrator rights, offers Restart as
  Administrator, verifies the drive identity and refuses the disk that holds
  the application's own data. Disks without a partition table are supported.

### Extraction

- Hikvision: `RATS` record carving from the declared and residual log regions,
  SDK event mapping and payload decoding.
- Dahua: XFS traversal that preserves every SQLite database and builds a
  normalized UTC timeline with plain-language explanations of each JSON field.
- TVT: structured `mlogtype:` record parsing with original types, SDK type
  interpretation and parsed payload fields.
- Recovered record bytes and absolute image offsets for Hikvision and TVT.
- Byte-accurate progress and cooperative cancellation of long extractions.
- Case folders with a unique workspace per run, manifest and UTC audit log.

### Analysis

- Searchable, paginated results with per-column filters, category, source
  database and TVT `mlogtype` filters.
- Date filter initialised to the earliest and latest valid log times of the
  evidence.
- Result rows show short summaries; the record details window shows every
  field, the full text and the recovered bytes.
- Hikvision Security Audit, Camera / Motion and Log Statistics views.
- Read-only entropy survey for unrecognized images, covering every byte or a
  selected range.

### Reports

- CSV export and multi-page HTML reports with a shared search index.
- Per-report choice of records, fields and log types, plus title, logo,
  metadata and page size.

### Application

- System, Dark and Light themes; the System theme follows Windows.
- Configurable fonts and recent-evidence history.
- Windows installer for the current user or for all users.
- Licensed under GPL-3.0, with third-party notices for all bundled components.
