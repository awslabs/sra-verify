"""Import-time discovery of service packages and check modules.

A check module's presence on disk is its registration: importing the module
executes its class body, which fires ``SecurityCheck.__init_subclass__`` and
adds the check to the registry. Nothing here needs an import list or a
dictionary to keep in sync.

Both functions resolve their target by name through ``importlib``, so no
``core`` module declares a static import of a service package -- the
dependency edge from ``core`` toward ``services`` exists only at run time.

Neither function issues an AWS API call, so importing the ``services``
package requires no credentials. Import failures -- including a service
package with no ``checks`` subpackage -- propagate unchanged, so a catalog
defect stops the process before any AWS call or output file.

Re-importing a package in one process is a no-op: ``sys.modules`` short
circuits both the package ``__init__`` that calls into this module and any
individual module import below, so no check is registered twice.
"""

from __future__ import annotations

import importlib
import pkgutil

from sraverify.core.logging import logger

#: Only modules whose name begins with this are treated as check modules.
CHECK_MODULE_PREFIX = "sra_"


def import_check_modules(package_name: str) -> list[str]:
    """Import every ``sra_*`` module in *package_name*, sorted by name.

    Importing a check module executes its class body, which fires
    ``SecurityCheck.__init_subclass__`` and registers the check.

    Subpackages and modules that do not start with ``sra_`` are skipped.

    Args:
        package_name: Dotted name of the ``checks`` package to scan, normally
            passed as ``f"{__name__}.checks"`` from a service ``__init__.py``.

    Returns:
        The imported module names in import order -- ascending lexicographic
        -- or an empty list when no module matches.

    Raises:
        Exception: Whatever importing the package or one of its check modules
            raises, unchanged. A missing ``checks`` subpackage surfaces here
            as ``ModuleNotFoundError``.
    """
    package = importlib.import_module(package_name)
    names = sorted(
        name
        for _finder, name, is_pkg in pkgutil.iter_modules(package.__path__)
        if not is_pkg and name.startswith(CHECK_MODULE_PREFIX)
    )
    imported: list[str] = []
    for name in names:
        importlib.import_module(f"{package_name}.{name}")
        imported.append(name)
    logger.debug(f"Discovery: imported {len(imported)} check modules from {package_name}")
    return imported


def import_service_packages(package_name: str) -> list[str]:
    """Import every service subpackage of *package_name*, sorted by name.

    Each service ``__init__.py`` in turn calls :func:`import_check_modules`,
    so this single call populates the whole catalog. Non-package modules at
    the ``services`` level are skipped.

    Args:
        package_name: Dotted name of the ``services`` package to scan,
            normally passed as ``__name__`` from ``services/__init__.py``.

    Returns:
        The imported subpackage names in import order -- ascending
        lexicographic -- or an empty list when the package holds no
        subpackage.

    Raises:
        Exception: Whatever importing the package or one of its service
            subpackages raises, unchanged.
    """
    package = importlib.import_module(package_name)
    names = sorted(
        name
        for _finder, name, is_pkg in pkgutil.iter_modules(package.__path__)
        if is_pkg
    )
    for name in names:
        importlib.import_module(f"{package_name}.{name}")
    logger.debug(f"Discovery: imported {len(names)} service packages")
    return names
