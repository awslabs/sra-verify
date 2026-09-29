"""Entry point for ``python -m sraverify``; equivalent to the ``sraverify`` console script."""
import sys

from sraverify.cli import main

sys.exit(main())
