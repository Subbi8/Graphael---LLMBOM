import json


class GraphExporter:

    @staticmethod
    def export(graph_dict, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(graph_dict, f, indent=4)
