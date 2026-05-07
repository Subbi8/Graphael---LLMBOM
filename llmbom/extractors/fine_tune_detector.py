import os
import re
import json

FINE_TUNE_PATTERNS = {
    "LoRA": r'LoraConfig|lora_config',
    "PEFT": r'from peft',
    "SFT": r'SFTTrainer',
    "PPO": r'PPOTrainer',
    "RLHF": r'RLTrainer|reinforcement',
}


class FineTuneDetector:
    def __init__(self, path):
        self.path = path
        self.methods = set()

    def extract(self):
        for root, _, files in os.walk(self.path):
            for file in files:
                if file.endswith((".py", ".ipynb")):
                    self._scan(os.path.join(root, file))
        return list(self.methods)

    def _scan(self, path):
        content = self._read_file(path)
        for method, pattern in FINE_TUNE_PATTERNS.items():
            if re.search(pattern, content):
                self.methods.add(method)

    def _read_file(self, path):
        if path.endswith(".ipynb"):
            with open(path, "r", encoding="utf-8") as f:
                notebook = json.load(f)
                return "".join(
                    "".join(cell.get("source", []))
                    for cell in notebook.get("cells", [])
                    if cell.get("cell_type") == "code"
                )
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
