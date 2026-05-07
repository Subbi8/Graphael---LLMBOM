import ast
from typing import List, Set, Optional


def _parse_file(path: str) -> Optional[ast.AST]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return ast.parse(f.read(), filename=path)
    except Exception:
        return None


def extract_imports(path: str) -> List[str]:
    """Return a list of top‑level module names imported in the file."""
    tree = _parse_file(path)
    if tree is None:
        return []
    libs: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                libs.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                libs.add(node.module.split(".")[0])
    return list(libs)


def extract_models(path: str) -> List[str]:
    """Find calls to ``from_pretrained`` and return model identifiers."""
    tree = _parse_file(path)
    if tree is None:
        return []
    found: List[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if name == "from_pretrained":
                # first positional string arg
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        found.append(arg.value)
                    else:
                        found.append("<unknown>")
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def extract_datasets(path: str) -> List[str]:
    """Find calls to ``load_dataset`` and return dataset identifiers."""
    tree = _parse_file(path)
    if tree is None:
        return []
    found: List[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if name == "load_dataset":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        found.append(arg.value)
                    else:
                        found.append("<unknown>")
            self.generic_visit(node)

    Visitor().visit(tree)
    return found
