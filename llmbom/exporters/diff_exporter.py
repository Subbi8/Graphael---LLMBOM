"""Diff exporter for comparing two LLMBOM JSON graphs.

Compares old and new LLMBOM outputs and generates a delta report showing:
- Added nodes/edges
- Removed nodes/edges
- Changed nodes/edges
- Summary statistics
"""

import json
from typing import Dict, List, Set, Tuple, Any


class DiffExporter:
    """Compare two LLMBOM JSON graphs and generate a diff report."""

    def __init__(self, old_graph: Dict, new_graph: Dict):
        """Initialize with old and new LLMBOM graphs.
        
        Args:
            old_graph: Original LLMBOM JSON graph (dict with 'nodes' and 'edges')
            new_graph: Updated LLMBOM JSON graph (dict with 'nodes' and 'edges')
        """
        self.old_graph = old_graph
        self.new_graph = new_graph

        # Build node/edge lookup maps
        self.old_nodes = {n['id']: n for n in old_graph.get('nodes', [])}
        self.new_nodes = {n['id']: n for n in new_graph.get('nodes', [])}

        self.old_edges = {
            (e['source'], e['target'], e['type']): e
            for e in old_graph.get('edges', [])
        }
        self.new_edges = {
            (e['source'], e['target'], e['type']): e
            for e in new_graph.get('edges', [])
        }

    def compute_diff(self) -> Dict[str, Any]:
        """Compute differences between old and new graphs.
        
        Returns:
            dict with keys: added_nodes, removed_nodes, changed_nodes,
                            added_edges, removed_edges, changed_edges,
                            summary
        """
        diff = {
            'added_nodes': self._diff_nodes_added(),
            'removed_nodes': self._diff_nodes_removed(),
            'changed_nodes': self._diff_nodes_changed(),
            'added_edges': self._diff_edges_added(),
            'removed_edges': self._diff_edges_removed(),
            'changed_edges': self._diff_edges_changed(),
            'summary': self._compute_summary(),
        }
        return diff

    def _diff_nodes_added(self) -> List[Dict]:
        """Find nodes added in new graph."""
        added = []
        for node_id, node in self.new_nodes.items():
            if node_id not in self.old_nodes:
                added.append(node)
        return sorted(added, key=lambda n: (n['type'], n['name']))

    def _diff_nodes_removed(self) -> List[Dict]:
        """Find nodes removed from old graph."""
        removed = []
        for node_id, node in self.old_nodes.items():
            if node_id not in self.new_nodes:
                removed.append(node)
        return sorted(removed, key=lambda n: (n['type'], n['name']))

    def _diff_nodes_changed(self) -> List[Dict]:
        """Find nodes that exist in both but with changes."""
        changed = []
        for node_id, old_node in self.old_nodes.items():
            if node_id in self.new_nodes:
                new_node = self.new_nodes[node_id]
                # Check what fields changed
                field_changes = {}
                all_keys = set(old_node.keys()) | set(new_node.keys())
                for key in sorted(all_keys):
                    old_val = old_node.get(key)
                    new_val = new_node.get(key)
                    if old_val != new_val:
                        field_changes[key] = {
                            'old': old_val,
                            'new': new_val,
                        }
                if field_changes:
                    changed.append({
                        'id': node_id,
                        'type': old_node['type'],
                        'name': old_node['name'],
                        'field_changes': field_changes,
                    })
        return sorted(changed, key=lambda c: (c['type'], c['name']))

    def _diff_edges_added(self) -> List[Dict]:
        """Find edges added in new graph."""
        added = []
        for edge_key, edge in self.new_edges.items():
            if edge_key not in self.old_edges:
                added.append(edge)
        return sorted(added, key=lambda e: (e['type'], e['source'], e['target']))

    def _diff_edges_removed(self) -> List[Dict]:
        """Find edges removed from old graph."""
        removed = []
        for edge_key, edge in self.old_edges.items():
            if edge_key not in self.new_edges:
                removed.append(edge)
        return sorted(removed, key=lambda e: (e['type'], e['source'], e['target']))

    def _diff_edges_changed(self) -> List[Dict]:
        """Find edges that exist in both but with changes."""
        changed = []
        for edge_key, old_edge in self.old_edges.items():
            if edge_key in self.new_edges:
                new_edge = self.new_edges[edge_key]
                # Check what fields changed (excluding source/target/type)
                field_changes = {}
                all_keys = set(old_edge.keys()) | set(new_edge.keys())
                for key in sorted(all_keys):
                    if key not in ('source', 'target', 'type'):
                        old_val = old_edge.get(key)
                        new_val = new_edge.get(key)
                        if old_val != new_val:
                            field_changes[key] = {
                                'old': old_val,
                                'new': new_val,
                            }
                if field_changes:
                    changed.append({
                        'source': old_edge['source'],
                        'target': old_edge['target'],
                        'type': old_edge['type'],
                        'field_changes': field_changes,
                    })
        return sorted(changed, key=lambda c: (c['type'], c['source'], c['target']))

    def _compute_summary(self) -> Dict[str, Any]:
        """Compute summary statistics."""
        added_nodes = self._diff_nodes_added()
        removed_nodes = self._diff_nodes_removed()
        changed_nodes = self._diff_nodes_changed()
        added_edges = self._diff_edges_added()
        removed_edges = self._diff_edges_removed()
        changed_edges = self._diff_edges_changed()

        old_node_count = len(self.old_nodes)
        new_node_count = len(self.new_nodes)
        old_edge_count = len(self.old_edges)
        new_edge_count = len(self.new_edges)

        # Count by type
        old_nodes_by_type = {}
        new_nodes_by_type = {}
        for node in self.old_nodes.values():
            ntype = node['type']
            old_nodes_by_type[ntype] = old_nodes_by_type.get(ntype, 0) + 1
        for node in self.new_nodes.values():
            ntype = node['type']
            new_nodes_by_type[ntype] = new_nodes_by_type.get(ntype, 0) + 1

        return {
            'old_graph_nodes': old_node_count,
            'new_graph_nodes': new_node_count,
            'node_delta': new_node_count - old_node_count,
            'nodes_by_type_old': old_nodes_by_type,
            'nodes_by_type_new': new_nodes_by_type,
            'old_graph_edges': old_edge_count,
            'new_graph_edges': new_edge_count,
            'edge_delta': new_edge_count - old_edge_count,
            'added_nodes_count': len(added_nodes),
            'removed_nodes_count': len(removed_nodes),
            'changed_nodes_count': len(changed_nodes),
            'added_edges_count': len(added_edges),
            'removed_edges_count': len(removed_edges),
            'changed_edges_count': len(changed_edges),
        }

    @staticmethod
    def export(diff_result: Dict[str, Any], output_path: str):
        """Export diff result to JSON file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(diff_result, f, indent=2, sort_keys=True)

    @staticmethod
    def load_graph(json_path: str) -> Dict:
        """Load a LLMBOM JSON graph from file."""
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def compare_files(old_json_path: str, new_json_path: str) -> Dict[str, Any]:
        """Load two LLMBOM JSON files and compute their diff.
        
        Args:
            old_json_path: path to original LLMBOM output
            new_json_path: path to updated LLMBOM output
            
        Returns:
            diff dict
        """
        old_graph = DiffExporter.load_graph(old_json_path)
        new_graph = DiffExporter.load_graph(new_json_path)
        exporter = DiffExporter(old_graph, new_graph)
        return exporter.compute_diff()
