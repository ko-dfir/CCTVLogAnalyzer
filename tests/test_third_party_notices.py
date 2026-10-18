from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES = (ROOT / 'THIRD_PARTY_NOTICES.md').read_text(encoding='utf-8')

# Every runtime dependency the installer bundles must be named in the notices.
REQUIRED_COMPONENTS = ('Python', 'Qt', 'PySide6', 'libewf-python', 'dissect.xfs',
                       'dissect.cstruct', 'dissect.util', 'Nuitka', 'OpenSSL')


def test_notices_name_every_bundled_component():
    for component in REQUIRED_COMPONENTS:
        assert component in NOTICES, component


def test_every_referenced_license_text_exists():
    referenced = {part.strip('` ') for part in NOTICES.split('`')
                  if part.startswith('licenses/') and not part.endswith('/')}
    assert referenced, 'notices reference no license files'
    for name in referenced:
        path = ROOT / name
        assert path.is_file() and path.stat().st_size > 500, name


def test_runtime_requirements_are_covered_by_notices():
    names = {'pyside6': 'PySide6', 'dissect.xfs': 'dissect.xfs', 'libewf-python': 'libewf-python'}
    for line in (ROOT / 'requirements.txt').read_text(encoding='utf-8').splitlines():
        package = line.split('==')[0].strip().lower()
        if package:
            assert names.get(package, package) in NOTICES, package


def test_build_installs_notices_and_license_texts():
    build = (ROOT / 'build.bat').read_text(encoding='utf-8')
    assert '"%~dp0THIRD_PARTY_NOTICES.md"=THIRD_PARTY_NOTICES.md' in build
    assert '"%~dp0LICENSE"=LICENSE.txt' in build
    assert '--include-data-dir="%~dp0licenses"=licenses' in build
