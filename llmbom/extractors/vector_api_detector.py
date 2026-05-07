import os
import re
import json

VECTOR_CONFIG_PATTERNS = {
    "FAISS": r'FAISS\((.*?)\)',
    "Pinecone": r'Pinecone\((.*?)\)',
    "Chroma": r'Chroma\((.*?)\)'
}

API_PATTERNS = {
    "OpenAI": r'OpenAI\((.*?)\)',
    "Anthropic": r'Anthropic\((.*?)\)'
}


class InfraDetector:
    def __init__(self, path):
        self.path = path
        self.vector_configs = []
        self.api_calls = []

    def extract(self):
        for root, _, files in os.walk(self.path):
            for file in files:
                if file.endswith((".py", ".ipynb")):
                    self._scan(os.path.join(root, file))
        return self.vector_configs, self.api_calls

    def _scan(self, path):
        content = self._read_file(path)

        for name, pattern in VECTOR_CONFIG_PATTERNS.items():
            for match in re.findall(pattern, content, re.DOTALL):
                self.vector_configs.append({
                    "type": "vector_db",
                    "name": name,
                    "config_snippet": match.strip(),
                })

        for name, pattern in API_PATTERNS.items():
            for match in re.findall(pattern, content, re.DOTALL):
                self.api_calls.append({
                    "type": "api",
                    "name": name,
                    "config_snippet": match.strip(),
                })

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
