# Build notes

## Toolchain

- CPython 3.13 (64-bit) with the Microsoft C++ build tools.
- Nuitka 4.2.2 standalone mode with the PySide6 plugin.
- PySide6/Shiboken6 6.11.2; the complete runtime dependency set is locked in
  `requirements-runtime-snapshot.txt` and installed by `requirements-build.txt`.
- Inno Setup 7 for the installer.

## Building

Keep the source and the build virtual environment in short paths; PySide6
contains deep package paths that exceed the Windows 260-character limit inside
nested folders. The build venv defaults to `%LOCALAPPDATA%\CCTVBuild\venv`.

```powershell
$env:CCTV_BUILD_VENV = 'C:\cctvbuild\venv'  # optional override
$env:CCTV_BUILD_DIAGNOSTIC = '1'            # optional: visible console
.\build.bat --exe-only                     # executable only, no installer
```

`build.bat` without `--exe-only` also builds the installer and requires Inno
Setup. The executable is written to `dist/cctv_log_analyzer.dist/CCTVLogAnalyzer.exe`
and the installer to `installer-output/`.

The display version is `1.01`; the four-part `windows_version` (`1.1.0.0`) in
`version.json` is passed to Nuitka and Inno Setup, because Windows numeric
version fields cannot carry the leading zero in `01`.

## Qt signal connections

Qt signals in the PySide6 UI are connected to bound methods declared with
[`@Slot`](https://doc.qt.io/qtforpython-6/tutorials/basictutorial/signals_and_slots.html),
never to lambdas, which keeps signal handling reliable in Nuitka-compiled
builds. `tests/test_compiled_startup_safety.py` enforces this rule.

## Diagnostics

Application logs are written to `%LOCALAPPDATA%\CCTVLogAnalyzer\logs`:
`app.log`, `error.log` and `native-crash.log`. Native faults bypass Python
exception handlers and are recorded only in `native-crash.log` through a
persistent file descriptor, so an empty `error.log` does not rule out a fault.

## Verifying a build

Compilation success alone is not runtime validation. Launch the generated
executable, confirm the main window opens, then exercise column resize, move
and scroll, the filters, the report dialogs and both pagination controls. Do
not mix Qt DLLs from another build into a fresh standalone directory.

When reporting a build problem, include `app.log`, `error.log`,
`native-crash.log`, the timestamped build log, `build-logs/nuitka-report.xml`
and the exact package versions.
