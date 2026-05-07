class LLMBOMNode:
    def __init__(self, node_type: str, name: str, metadata: dict = None):
        # id is assigned externally by graph to ensure determinism
        self.id = None
        self.type = node_type
        self.name = name
        self.metadata = metadata or {}

    def to_dict(self):
        base = {
            "id": self.id,
            "type": self.type,
            "name": self.name,
        }
        if self.metadata:
            base["metadata"] = self.metadata
        return base
