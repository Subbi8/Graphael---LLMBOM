class NodeRegistry:
    """Registry enforcing uniqueness of nodes using normalized names.

    The registry key is `(node_type, normalized_name)`.  Normalization is a
    simple lowercase/strip transformation; additional metadata ("original_name")
    is preserved when the normalized form differs from the input.  This keeps
    the graph free of duplicate logical packages (e.g. ``OpenAI`` vs ``openai``)
    while still retaining the raw import string.
    """

    def __init__(self):
        self._index = {}

    def get_or_create(self, graph, node_type, name, metadata=None):
        from llmbom.utils.file_utils import normalize_package_name

        norm = normalize_package_name(name)
        key = (node_type, norm)

        if key in self._index:
            return self._index[key]

        # attach original name metadata if normalization changed it
        meta = {} if metadata is None else dict(metadata)
        if norm != name:
            meta.setdefault("original_name", name)
        # store normalized name under metadata for reference as well
        meta.setdefault("normalized_name", norm)

        node_id = graph._create_node(node_type, norm, meta if meta else None)
        self._index[key] = node_id
        return node_id
