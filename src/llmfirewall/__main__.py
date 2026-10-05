"""Executable module entrypoint for python -m llmfirewall."""

import sys
from llmfirewall.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
