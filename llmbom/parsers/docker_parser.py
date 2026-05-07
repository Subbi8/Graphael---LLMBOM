def parse_dockerfile(path):
    """Simple Dockerfile parser that returns base image and pip installs.

    Currently only scans ``FROM`` and ``RUN pip install`` lines and
    returns a dictionary with keys ``base_image`` and ``packages``.
    """
    result = {"base_image": None, "packages": []}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.upper().startswith("FROM "):
                    result["base_image"] = line.split()[1]
                elif line.startswith("RUN") and "pip install" in line:
                    # naive split
                    parts = line.split("pip install")[-1]
                    for pkg in parts.split():
                        if pkg and not pkg.startswith("-"):
                            result["packages"].append(pkg)
    except Exception:
        pass
    return result
