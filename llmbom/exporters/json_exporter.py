"""Legacy flat JSON exporter.

Used by the older ``generate_llmbom.py`` script; still maintained for
backward compatibility.  It simply dumps whatever data structure the
builder returned.
"""

import json


class JSONExporter:
    @staticmethod
    def export(data, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
