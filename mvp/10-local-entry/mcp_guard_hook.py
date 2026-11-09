"""Launcher for local_entry.hook; client configs point here, so no PYTHONPATH is needed."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for folder in (ROOT / "src", ROOT / "mvp" / "08-decision-controls", HERE):
    sys.path.insert(0, str(folder))

from local_entry.hook import main  # noqa: E402

raise SystemExit(main())
