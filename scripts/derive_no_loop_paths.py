#!/usr/bin/env python3
"""Derive — never enumerate by hand — the call paths that reach
``kag_common.metering.schedule_cost_event``, and decide the fate of the
``NoRunningLoopError`` that ``METERING_REQUIRE_LOOP=true`` makes it raise.

WHY THIS EXISTS. Three successive revisions of the sibling PR (``w2v_common#188``)
stated the affected call sites in PROSE and all three were wrong — 15 vs 16
sites, 9 vs 10 in one repo, "12 of 15" vs "13 of 16". A hand-written population
is a guess with a number attached. This walks the AST instead.

WHAT IT DOES. For every repo root given on the command line:

  1. Find the LEAF calls: ``schedule_cost_event(...)`` where that name was
     imported from ``kag_common.metering``, plus ``<mod>.schedule_cost_event(...)``
     where ``<mod>`` is an imported module (never a bare attribute — resolving on
     the attribute name alone fabricates hops, which is exactly the error the
     sibling PR had to correct in 6 of 25 citations).
  2. Walk UP from the enclosing function to every in-repo caller, transitively,
     until a frame that no in-repo module calls: that frame is an ENTRY POINT and
     the (entry -> ... -> leaf) chain is one PATH.
  3. UNION the ``except`` handlers that lexically enclose the call at EVERY hop.
  4. Classify the path:
       ESCAPES    nothing on the path catches a ``RuntimeError``; the raise
                  leaves the entry frame.
       CONVERTED  a handler catches it and raises something else (e.g. FastAPI
                  ``HTTPException``) — the customer sees a 500, not the drop.
       SWALLOWED  a handler catches it and does not re-raise. The escalation flag
                  is INERT on this path.

⚠️ LIMITS — THE WALK FAILS OPEN, SO EVERY COUNT IS A FLOOR.
An unresolvable hop is DROPPED SILENTLY rather than raised: a dynamic dispatch, a
call through a variable, an instance method, a relative import this script's
root-guessing does not reconstruct, a decorator that re-wraps the frame. None of
those can be seen statically, so a real path can be missing from the output
entirely. Read every number below as "at least this many".

Four constructs additionally CORRUPT the verdict rather than merely hiding a
path, so they are reported separately and must be read before the table is
trusted:

  * ``contextlib.suppress(Exception)``  — swallows without an ``except`` node, so
    a path this script calls ESCAPES would actually be SWALLOWED.
  * ``gather(..., return_exceptions=True)`` — the exception becomes a RETURN
    VALUE; no handler is involved and the caller may never look at it.
  * a bare ``raise`` inside a matching handler — the script sees a handler and
    would say CONVERTED/SWALLOWED, but the original exception continues, i.e.
    ESCAPES.
  * ``except <Narrow>`` ordered BEFORE ``except Exception`` in one ``try`` — only
    the first matching clause runs, so a later broad clause the union counted is
    dead for this exception. Reported in its ONLY dangerous form: a clause that
    catches a ``RuntimeError`` subclass placed before a broad one. Flagging every
    narrow-before-broad pair instead yields dozens of hits with no bearing here.

⭐ Report what is found, not what is hoped: "present but not on any path" is a
different and more useful answer than "absent".

Usage:
    python scripts/derive_no_loop_paths.py <repo_root> [<repo_root> ...]
"""

from __future__ import annotations

import ast
import pathlib
import sys
from collections import defaultdict

LEAF = "schedule_cost_event"
LEAF_MODULE = "kag_common.metering"

#: Exception names whose handler catches a ``RuntimeError`` subclass.
CATCHES_RUNTIME_ERROR = {
    "RuntimeError",
    "Exception",
    "BaseException",
    "NoRunningLoopError",
}

#: A raise of one of these inside a matching handler is a CONVERSION, not an
#: escape: the caller sees a different exception type.
CONVERSION_TYPES = {"HTTPException", "StarletteHTTPException"}


# --------------------------------------------------------------------------- #
# module index


def _module_names(root: pathlib.Path, path: pathlib.Path) -> list[str]:
    """Every dotted name this file could plausibly be imported as."""
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    names = []
    if parts:
        names.append(".".join(parts))
        if parts[0] in {"src", "app"}:  # pythonpath=["src"] is the house layout
            names.append(".".join(parts[1:]))
    return [n for n in names if n]


def index_repo(root: pathlib.Path) -> tuple[dict, dict]:
    """Return (module_name -> path, path -> parsed tree)."""
    modules: dict[str, pathlib.Path] = {}
    trees: dict[pathlib.Path, ast.Module] = {}
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError, UnicodeDecodeError:
            continue  # FAILS OPEN — see LIMITS
        trees[path] = tree
        for name in _module_names(root, path):
            modules.setdefault(name, path)
    return modules, trees


# --------------------------------------------------------------------------- #
# per-file symbol tables


class FileFacts:
    """Imports, function definitions, and enclosing-handler spans for one file."""

    def __init__(self, path: pathlib.Path, tree: ast.Module) -> None:
        self.path = path
        self.tree = tree
        self.from_imports: dict[str, str] = {}  # local name -> source module
        self.module_aliases: dict[str, str] = {}  # local name -> module
        self.functions: dict[str, ast.AST] = {}  # qualname -> node
        self.parents: dict[ast.AST, ast.AST] = {}
        self._walk()

    def _walk(self) -> None:
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    self.from_imports[alias.asname or alias.name] = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name

        def visit(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    qual = f"{prefix}{child.name}"
                    self.functions[qual] = child
                    visit(child, f"{qual}.")
                elif isinstance(child, ast.ClassDef):
                    visit(child, f"{prefix}{child.name}.")
                else:
                    visit(child, prefix)

        visit(self.tree, "")

    def enclosing_function(self, node: ast.AST) -> tuple[str | None, ast.AST | None]:
        cur = node
        while cur in self.parents:
            cur = self.parents[cur]
            if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef):
                for qual, fn in self.functions.items():
                    if fn is cur:
                        return qual, cur
        return None, None

    def handlers_between(self, node: ast.AST, stop: ast.AST | None) -> list[ast.Try]:
        """Every ``try`` whose BODY lexically encloses ``node``, up to ``stop``."""
        out: list[ast.Try] = []
        cur, prev = node, node
        while cur in self.parents:
            parent = self.parents[cur]
            if isinstance(parent, ast.Try) and any(prev is s for s in parent.body):
                out.append(parent)
            if parent is stop:
                break
            prev, cur = parent, parent
        return out


# --------------------------------------------------------------------------- #
# classification


def _handler_names(handler: ast.ExceptHandler) -> set[str]:
    if handler.type is None:
        return {"BaseException"}
    nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    names = set()
    for n in nodes:
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            names.add(n.attr)
    return names


def _handler_reraises(handler: ast.ExceptHandler) -> str | None:
    """'bare' | 'convert:<Type>' | 'other' | None (no raise at all)."""
    for node in ast.walk(handler):
        if isinstance(node, ast.Raise):
            if node.exc is None:
                return "bare"
            target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            name = (
                target.id
                if isinstance(target, ast.Name)
                else target.attr
                if isinstance(target, ast.Attribute)
                else ""
            )
            return f"convert:{name}" if name in CONVERSION_TYPES else "other"
    return None


def classify(tries: list[ast.Try]) -> tuple[str, str]:
    """Fate of a RuntimeError subclass raised inside these (innermost-first) trys."""
    for node in tries:
        for handler in node.handlers:
            names = _handler_names(handler)
            if not (names & CATCHES_RUNTIME_ERROR):
                continue
            kind = _handler_reraises(handler)
            if kind == "bare":
                return "ESCAPES", f"bare re-raise in except {sorted(names)} @{handler.lineno}"
            if kind and kind.startswith("convert:"):
                return "CONVERTED", f"except {sorted(names)} -> {kind[8:]} @{handler.lineno}"
            if kind == "other":
                return "CONVERTED", f"except {sorted(names)} -> raise @{handler.lineno}"
            return "SWALLOWED", f"except {sorted(names)}, no re-raise @{handler.lineno}"
    return "ESCAPES", "no handler on the path catches a RuntimeError"


# --------------------------------------------------------------------------- #
# corrupting constructs


def scan_constructs(trees: dict[pathlib.Path, ast.Module], root: pathlib.Path) -> dict:
    found = defaultdict(list)
    for path, tree in trees.items():
        rel = path.relative_to(root)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name == "suppress":
                    args = {getattr(a, "id", "") for a in node.args}
                    if args & {"Exception", "BaseException", "RuntimeError"}:
                        found["suppress(Exception)"].append(f"{rel}:{node.lineno}")
                if name == "gather":
                    for kw in node.keywords:
                        if kw.arg == "return_exceptions" and getattr(kw.value, "value", False):
                            found["gather(return_exceptions=True)"].append(f"{rel}:{node.lineno}")
            if isinstance(node, ast.Try):
                # ⚠️ ONLY the dangerous ordering. "any narrow before any broad" is
                # the overwhelmingly common Python idiom and flagging it produces
                # dozens of hits with no bearing on this exception. What actually
                # corrupts the verdict is a clause that catches a RuntimeError
                # SUBCLASS placed before a broad clause: the broad one is then
                # dead for this exception, so a union that counted it is wrong.
                seen_runtime_narrow = False
                for handler in node.handlers:
                    names = _handler_names(handler)
                    broad = bool(names & {"Exception", "BaseException"})
                    if broad and seen_runtime_narrow:
                        found["RuntimeError-clause before broad clause"].append(
                            f"{rel}:{node.lineno}"
                        )
                    if not broad and names & CATCHES_RUNTIME_ERROR:
                        seen_runtime_narrow = True
                    if _handler_reraises(handler) == "bare" and names & CATCHES_RUNTIME_ERROR:
                        found["bare-raise handler"].append(f"{rel}:{handler.lineno}")
    return found


# --------------------------------------------------------------------------- #
# the walk


def leaf_calls(facts: FileFacts) -> list[ast.Call]:
    out = []
    direct = facts.from_imports.get(LEAF) == LEAF_MODULE
    for node in ast.walk(facts.tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == LEAF and direct:
            out.append(node)
        elif isinstance(func, ast.Attribute) and func.attr == LEAF:
            base = func.value
            # ⚠️ REQUIRE an imported MODULE. Resolving on the bare attribute name
            # is what fabricated 6 hops in the sibling PR.
            if isinstance(base, ast.Name) and base.id in facts.module_aliases:
                if LEAF_MODULE in facts.module_aliases[base.id]:
                    out.append(node)
    return out


def callers_of(
    target_module: str, target_func: str, all_facts: dict, modules: dict
) -> list[tuple[pathlib.Path, ast.Call]]:
    """In-repo call sites of ``target_module.target_func``."""
    hits = []
    simple = target_func.split(".")[-1]
    target_path = modules.get(target_module)
    for path, facts in all_facts.items():
        src = facts.from_imports.get(simple)
        imported = src is not None and modules.get(src) == target_path
        # ⚠️ A SAME-FILE call needs no import. Omitting this case truncated the
        # hirag_service chain at its private wrapper and under-counted the
        # population — the walk stopped one frame early and reported it as an
        # entry point.
        same_module = path == target_path and simple in facts.functions
        for node in ast.walk(facts.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == simple and (imported or same_module):
                hits.append((path, node))
            elif isinstance(func, ast.Attribute) and func.attr == simple:
                base = func.value
                if isinstance(base, ast.Name) and base.id in facts.module_aliases:
                    if modules.get(facts.module_aliases[base.id]) == modules.get(target_module):
                        hits.append((path, node))
    return hits


def walk_repo(root: pathlib.Path) -> tuple[list[dict], dict, int]:
    modules, trees = index_repo(root)
    all_facts = {p: FileFacts(p, t) for p, t in trees.items()}
    path_to_module = {}
    for name, p in modules.items():
        path_to_module.setdefault(p, name)

    paths: list[dict] = []
    textual = 0
    for path, facts in all_facts.items():
        if LEAF in path.read_text(encoding="utf-8", errors="ignore"):
            textual += 1
        for call in leaf_calls(facts):
            fn_qual, fn_node = facts.enclosing_function(call)
            tries = facts.handlers_between(call, fn_node)
            frontier = [
                {
                    "chain": [f"{path.relative_to(root)}:{call.lineno} {fn_qual or '<module>'}"],
                    "tries": list(tries),
                    "module": path_to_module.get(path),
                    "func": fn_qual,
                }
            ]
            seen: set[tuple[str, str]] = set()
            while frontier:
                item = frontier.pop()
                if item["func"] is None or item["module"] is None:
                    paths.append(item)  # module-level call: this frame IS the entry
                    continue
                key = (item["module"], item["func"])
                if key in seen:
                    paths.append(item)  # recursion guard — FAILS OPEN
                    continue
                seen.add(key)
                ups = callers_of(item["module"], item["func"], all_facts, modules)
                ups = [(p, c) for p, c in ups if p != path or c is not call]
                if not ups:
                    paths.append(item)  # no in-repo caller: ENTRY POINT
                    continue
                for up_path, up_call in ups:
                    up_facts = all_facts[up_path]
                    up_qual, up_node = up_facts.enclosing_function(up_call)
                    frontier.append(
                        {
                            "chain": [
                                f"{up_path.relative_to(root)}:{up_call.lineno} "
                                f"{up_qual or '<module>'}",
                                *item["chain"],
                            ],
                            "tries": [
                                *up_facts.handlers_between(up_call, up_node),
                                *item["tries"],
                            ],
                            "module": path_to_module.get(up_path),
                            "func": up_qual,
                        }
                    )
    return paths, scan_constructs(trees, root), textual


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    totals: dict[str, int] = defaultdict(int)
    for raw in argv[1:]:
        root = pathlib.Path(raw).resolve()
        paths, constructs, textual = walk_repo(root)
        print(f"\n=== {root.name}  ({textual} files mention {LEAF!r}) ===")
        if not paths:
            print("  no resolvable call path to the leaf")
        for item in paths:
            # innermost handler first
            verdict, why = classify(item["tries"])
            item["test"] = any(
                frag.startswith("tests/") or "/tests/" in frag for frag in item["chain"]
            )
            bucket = "TEST" if item["test"] else verdict
            totals[bucket] += 1
            totals["SITES" if not item["test"] else "TEST_SITES"] += 1
            print(
                f"  [{verdict:9s}]{' [TEST-ROOTED]' if item['test'] else ''} "
                f"{' -> '.join(item['chain'])}"
            )
            print(f"              {why}")
        # ⭐ A construct only CORRUPTS the verdict if it sits in a file on one of
        # the derived paths. Repo-wide presence is reported too, because
        # "present but not on any path" is a different and more useful answer
        # than "absent" — and it is the answer the sibling repo had to give.
        on_path_files = {frag.split(":")[0] for item in paths for frag in item["chain"]}
        print("  -- corrupting constructs (repo-wide / of those, on a derived path) --")
        for label in (
            "suppress(Exception)",
            "gather(return_exceptions=True)",
            "bare-raise handler",
            "RuntimeError-clause before broad clause",
        ):
            hits = constructs.get(label, [])
            on_path = [h for h in hits if h.split(":")[0] in on_path_files]
            note = "absent" if not hits else f"{on_path[:6]}" if on_path else "none on a path"
            print(f"     {label:34s} {len(hits):3d} / {len(on_path):3d}  {note}")
    print("\n=== TOTALS (FLOORS — the walk fails open) ===")
    print(
        f"  PRODUCTION SITES: {totals['SITES']}   ESCAPES: {totals['ESCAPES']}   "
        f"CONVERTED: {totals['CONVERTED']}   SWALLOWED: {totals['SWALLOWED']}"
    )
    print(f"  test-rooted paths (reported, not counted above): {totals['TEST_SITES']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
