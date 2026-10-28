# CCTV Log Analyzer 1.02 — screenshot set

Thirteen screenshots of the running application: 1-10 captured on 2026-10-17
and 11-13 on 2026-10-28.
All source images, records, users and recorder identifiers are synthetic DEMO data.

All PNGs were captured using the application's native QWidget.grab export.
They contain only the client area of the main window or active dialog, without
the mouse cursor, window decorations or desktop. Image dimensions vary to fit
each view.

1. `01-tvt-dark-overview.png` — TVT parsed records, case workspace, column filters and pagination.
2. `02-tvt-config-filter.png` — original TVT mlogtype filter restricted to configuration events.
3. `03-tvt-record-hex.png` — double-click inspector with recovered record bytes and logical offsets.
4. `04-report-config-selection.png` — report record selection with only config events checked and exact count.
5. `05-report-column-selection.png` — report column selection and investigation-summary preset.
6. `06-hikvision-log-explanation.png` — Hikvision record, SDK identifiers, interpretation and source offset.
7. `07-dahua-source-database-filter.png` — normalized Dahua records filtered to a single demo source database.
8. `08-settings-appearance-reports.png` — appearance, fonts, recent history and report defaults.
9. `09-tvt-light-theme.png` — parsed TVT records with the light theme.
10. `10-full-image-entropy-survey.png` — complete scan of a small demo image and interpreted entropy results.
11. `11-config-backup-recognised.png` — Config Backup recognising an encrypted demo configuration backup before the export code is entered.
12. `12-config-backup-hashcat.png` — hashcat mode 26401 hash line and instructions when the export code is unknown.
13. `13-config-backup-decoded.png` — demo backup decoded with its export code, every stored checksum verified.

TVT and Hikvision fixtures were parsed by the production engines. The Dahua
sample demonstrates normalization of synthetic exported SQLite databases; its
image is a detection-signature fixture, not a functional XFS filesystem. These
screenshots illustrate the UI, not validation against real recorder evidence.
The Config Backup screenshots use a synthetic backup encrypted with a demo code
and decoded by the production module; the output folder shown is a demo path.
The screenshots were taken with an isolated settings/history profile.
