from pathlib import Path

import scripts.logging_config as logging_config
import scripts.recents as recents
from scripts.versioning import version_info

ROOT = Path(__file__).resolve().parent.parent


def test_product_name_and_per_user_folders():
    assert version_info()['product_name'] == 'CCTV Log Analyzer'
    assert logging_config.APP_NAME == 'CCTVLogAnalyzer'
    assert recents.APP_DIR_NAME == 'CCTVLogAnalyzer'


def test_installer_and_build_use_the_product_name():
    script = (ROOT / 'installer' / 'CCTVLogAnalyzer.iss').read_text(encoding='utf-8')
    assert '#define MyAppExeName "CCTVLogAnalyzer.exe"' in script
    assert 'OutputBaseFilename=CCTVLogAnalyzer-{#MyAppVersion}-Setup' in script
    assert 'Source: "..\\dist\\cctv_log_analyzer.dist\\*"' in script
    assert '{localappdata}\\CCTVLogAnalyzer' in script
    build = (ROOT / 'build.bat').read_text(encoding='utf-8')
    assert '--output-filename=CCTVLogAnalyzer.exe' in build
    assert 'installer\\CCTVLogAnalyzer.iss' in build
