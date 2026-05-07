"""File utilities for path normalization, metadata extraction, and helper functions."""

from pathlib import Path
import hashlib


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def normalize_path(path, root):
    """Return a POSIX-style path relative to `root`.

    The returned path uses forward slashes, removes redundant `..` segments,
    and is deterministic across platforms.  If the file lies outside the root,
    the absolute path (in POSIX form) is returned.
    """
    p = Path(path).resolve()
    rootp = Path(root).resolve()
    try:
        rel = p.relative_to(rootp)
    except Exception:
        rel = p
    return rel.as_posix()


def script_metadata(path):
    """Gather static metadata for a script file.

    Returns a dict with keys:
    - file_size_bytes
    - line_count
    - sha256
    - language (extension-derived)
    """
    p = Path(path)
    info = {}
    try:
        st = p.stat()
        info["file_size_bytes"] = st.st_size
    except Exception:
        info["file_size_bytes"] = None
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        text = ""
    info["line_count"] = text.count("\n") + (1 if text else 0)
    info["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    info["language"] = p.suffix.lstrip(".").lower() or "unknown"
    return info


def normalize_package_name(name):
    """Return a normalized version of a package/library name.

    Normalization is lowercase and whitespace-stripped.  It is used for
    deduplication and registry keys; the original string may be preserved in
    node metadata if desired.
    """
    if not isinstance(name, str):
        return name
    return name.strip().lower()

