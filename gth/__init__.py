"""GTH passive wireless evidence tools."""
__version__ = '1.7.0'

# Use the bundled, pinned parser. No network install is needed.
import sys
from pathlib import Path
_vendor = str(Path(__file__).resolve().parent.parent / 'vendor')
if _vendor not in sys.path:
    sys.path.insert(0, _vendor)
