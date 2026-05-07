class LLMBOMEdge:
    def __init__(self, source_id: str, target_id: str, edge_type: str):
        self.source = source_id
        self.target = target_id
        self.type = edge_type

    def to_dict(self):
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
        }
