"""Test bootstrap: import the package from the checkout, not from site-packages."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
