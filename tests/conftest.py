import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
for p in (ROOT, ROOT / "tests"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture(autouse=True)
def _isolated_installer_state(tmp_path, monkeypatch):
    """No test may write the installer's default backup folder into the real user state directory.

    The state directory is inside tmp_path (not created up front), so a tree snapshot of tmp_path also
    proves the default backup location was left untouched.
    """
    monkeypatch.setenv("CIV4DBG_STATE_DIR", str(tmp_path / "_state"))
