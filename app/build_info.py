from pathlib import Path

BUILD_REVISION_FILE = Path(__file__).with_name('_build_revision.txt')


def get_build_revision() -> str:
    try:
        revision = BUILD_REVISION_FILE.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        return 'unknown'
    return revision or 'unknown'
