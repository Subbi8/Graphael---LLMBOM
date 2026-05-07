def parse_requirements(path):
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    deps.append(line.split("==")[0])
    except Exception:
        pass

    return deps
