"""Schema defining structural node and edge types.

Only structural types are allowed. Semantic classification is deferred to
analytical layers.
"""


class NodeType:
    """Structural node types only."""
    SCRIPT = "SCRIPT"
    LIBRARY = "LIBRARY"
    CONFIG = "CONFIG"


class EdgeType:
    """Relationship types between nodes."""
    DEPENDS_ON = "DEPENDS_ON"
    CONFIGURES = "CONFIGURES"
    LOADS = "LOADS"
    SAVES = "SAVES"
    CONTAINS = "CONTAINS"

