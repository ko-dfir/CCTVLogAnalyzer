# Third-party notices

CCTV Log Analyzer is licensed under the GNU General Public License v3.0 (see
`LICENSE`). The Windows build includes the third-party components listed below,
each distributed under its own license. Full license texts are in the
`licenses/` folder of this repository and of the installed application.

| Component | Version | License | Copyright / source | License text |
|---|---|---|---|---|
| Python runtime and standard library | 3.13 | Python Software Foundation License v2 | Python Software Foundation — https://www.python.org | `licenses/Python-3.13.txt` |
| Qt (Core, Gui, Widgets, Network, Svg, Pdf and plugins) | 6, as bundled with PySide6 6.11.2 | LGPL-3.0 | The Qt Company Ltd. and other contributors — https://code.qt.io | `licenses/LGPL-3.0.txt`, `licenses/GPL-3.0.txt` |
| PySide6 / Shiboken6 (Qt for Python) | 6.11.2 | LGPL-3.0 | The Qt Company Ltd. — https://code.qt.io/cgit/pyside/pyside-setup.git | `licenses/LGPL-3.0.txt`, `licenses/GPL-3.0.txt` |
| libewf-python (pyewf) | 20240506 | LGPL-3.0-or-later | Joachim Metz — https://github.com/libyal/libewf | `licenses/LGPL-3.0.txt`, `licenses/GPL-3.0.txt` |
| dissect.xfs | 3.13 | AGPL-3.0-or-later | Fox-IT, part of NCC Group Plc — https://github.com/fox-it/dissect.xfs | `licenses/AGPL-3.0.txt`, `licenses/dissect-COPYRIGHT.txt` |
| dissect.cstruct | 4.7 | Apache-2.0 | Fox-IT, part of NCC Group Plc — https://github.com/fox-it/dissect.cstruct | `licenses/Apache-2.0.txt`, `licenses/dissect-COPYRIGHT.txt` |
| dissect.util | 3.24 | Apache-2.0 | Fox-IT, part of NCC Group Plc — https://github.com/fox-it/dissect.util | `licenses/Apache-2.0.txt`, `licenses/dissect-COPYRIGHT.txt` |
| Nuitka runtime library | 4.2.2 | AGPL-3.0 with the Nuitka Runtime Library Exception | Kay Hayen — https://github.com/Nuitka/Nuitka | `licenses/Nuitka-Runtime-Library-Exception.txt` |

## Components bundled with the Python runtime

The Python Windows distribution includes OpenSSL (`libssl`, `libcrypto`),
libffi, SQLite, bzip2, xz/liblzma and zlib, and the Microsoft Visual C++
runtime (`vcruntime140`, `msvcp140`). Their notices and the terms for the
Microsoft redistributable files are included in `licenses/Python-3.13.txt`.

## Components bundled with Qt

Qt itself contains third-party code (for example PCRE2, HarfBuzz, FreeType,
libpng, libjpeg and PDFium). Their licenses and attributions are listed by the
Qt Project at https://doc.qt.io/qt-6/licenses-used-in-qt.html.

## Notes on the LGPL components

Qt, PySide6/Shiboken6 and pyewf are installed as separate dynamic libraries
(`Qt6*.dll`, `pyside6.abi3.dll`, `shiboken6.abi3.dll`, `pyewf.pyd` and the Qt
plugins) in the application folder. They may be replaced with compatible
modified versions. Their complete corresponding source code is available from
the source locations listed above.

## Notes on the AGPL components

dissect.xfs is licensed under the AGPL-3.0, which is compatible with the
GPL-3.0 under which this project is distributed (GPL-3.0 section 13). The
complete source code of CCTV Log Analyzer is available at
https://github.com/ko-dfir/CCTVLogAnalyzer. The Nuitka runtime library is
covered by the Nuitka Runtime Library Exception, so compiling with Nuitka does
not change the license of this program.
