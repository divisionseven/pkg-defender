# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""PyInstaller binary entry point — breaks circular import bug.

When PyInstaller loads this file as ``__main__``, it does a single canonical
import of ``pkg_defender.cli.main``.  All command modules then find
``pkg_defender.cli.main`` already in ``sys.modules`` and register on the
*same* ``cli`` object that ``run_cli()`` uses.
"""

from pkg_defender.cli.main import run_cli

if __name__ == "__main__":
    run_cli()
