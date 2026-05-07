"""Static standard-library module detection."""

import sys
import sysconfig
import pkgutil
from pathlib import Path


def _load_stdlib_names():
    # Prefer the explicit set available in Python>=3.10
    if hasattr(sys, "stdlib_module_names"):
        return set(sys.stdlib_module_names)
    # fallback: enumerate modules in the stdlib directory
    names = set()
    stdlib_path = sysconfig.get_paths().get("stdlib")
    if stdlib_path:
        for finder, name, ispkg in pkgutil.iter_modules([stdlib_path]):
            names.add(name)
    # include builtins as a fallback
    names.update(sys.builtin_module_names)
    return names


_STDLIB_NAMES = _load_stdlib_names()


def is_stdlib_module(name: str) -> bool:
    """Return True if *name* refers to a standard library module.

    Only the top-level portion of the name is considered (i.e. `json` in
    `json.encoder`).
    """
    if not isinstance(name, str) or not name:
        return False
    root = name.split(".")[0]
    return root in _STDLIB_NAMES
