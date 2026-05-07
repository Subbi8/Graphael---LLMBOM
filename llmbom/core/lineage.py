from .schema import EdgeType


class LineageEngine:

    def __init__(self, graph):
        self.graph = graph

    def link_fine_tune(self, child_model_id, base_model_id):
        self.graph.add_edge(
            child_model_id,
            base_model_id,
            EdgeType.FINE_TUNED_FROM,
        )

    def link_quantization(self, quant_model_id, parent_model_id):
        self.graph.add_edge(
            quant_model_id,
            parent_model_id,
            EdgeType.QUANTIZED_FROM,
        )
