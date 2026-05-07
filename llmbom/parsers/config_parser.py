import json
import yaml


def parse_config(path):
    """Load a YAML or JSON config file and return its contents as a dict.

    This helper is used by extractors to identify hyperparameters, model
    references, etc.  Unsupported formats return an empty dict.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
            if path.lower().endswith(".json"):
                return json.loads(text)
            else:
                # assume yaml
                return yaml.safe_load(text) or {}
    except Exception:
        return {}
