"""Shield service checks."""
from sraverify.core.discovery import import_check_modules

import_check_modules(f"{__name__}.checks")
