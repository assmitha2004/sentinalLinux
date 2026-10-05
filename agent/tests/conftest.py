import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from capability_detector import Context  # noqa: E402


@pytest.fixture
def ctx(tmp_path):
    cfg = config.load(path=None)
    cfg["agent"]["state_dir"] = str(tmp_path / "state")
    return Context(cfg)
