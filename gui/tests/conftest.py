"""Make the repo root importable so tests can use ``gui.*`` and ``llm_connector.*``.

Run the tests from anywhere: ``python -m pytest gui/tests -q``.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


import gc

import pytest


@pytest.fixture(scope="session", autouse=True)
def _tidy_qt_at_exit():
    """Delete leftover widgets in order before Python shuts down; otherwise Qt can crash on exit."""
    yield
    from PyQt5.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        return
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.processEvents()
    gc.collect()
    app.processEvents()
