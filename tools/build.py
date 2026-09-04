from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SOURCE_DIR = ROOT / "upstream" / "pywidevine" / "pywidevine"
COMPAT_DIR = SRC / "compat"
BUNDLE_OUTPUT = SRC / "pywidevine_bundled.py"
PLUGIN_OUTPUT = ROOT / "widevine.py"
PLUGIN_SOURCE = SRC / "widevine_standalone.py"

MODULE_ORDER = [
    "exceptions.py",
    "key.py",
    "session.py",
    "device.py",
    "pssh.py",
    "utils.py",
    "cdm.py",
    "remotecdm.py",
    "__init__.py",
]

COMPAT_MODULES = [
    "protobuf.py",
    "construct.py",
    "pymp4.py",
    "license_protocol.py",
]

INTERNAL_MODULES = {
    "pywidevine",
    "pywidevine_bundled",
    "construct",
    "pymp4",
    "google.protobuf",
}


def _rewrite_source(source: str, *, filename: str | None = None) -> str:
    source = source.replace("\r\n", "\n")

    source = _comment_module_docstring(source)

    source = re.sub(
        r"^from __future__ import annotations\s*\n?",
        "",
        source,
        count=1,
    )

    source = _remove_all(source)

    source = source.replace(
        "construct.ConstructError",
        "ConstructError",
    )

    if filename == "device.py":
        source = _rewrite_device(source)

    return source


def _rewrite_plugin(source: str) -> str:
    source = re.sub(
        r"^from __future__ import annotations\s*\n?",
        "",
        source,
        count=1,
        flags=re.MULTILINE,
    )

    source = re.sub(
        r"^from pywidevine_bundled import .*\n",
        "",
        source,
        flags=re.MULTILINE,
    )

    return source


def _rewrite_device(source: str) -> str:
    # Remove the Construct imports. Their required functionality is
    # provided by src/compat/construct.py.
    source = re.sub(
        r"^from construct import .*\n",
        "",
        source,
        flags=re.MULTILINE,
    )

    # Remove pywidevine's Construct-based _Structures definition.
    # _Structures is provided by src/compat/construct.py instead.
    start = source.find("class _Structures:")
    end = source.find("\n\nclass Device:", start)

    if start == -1 or end == -1:
        raise RuntimeError(
            "Unable to locate _Structures in device.py",
        )

    return source[:start] + "# _Structures provided by compatibility module." + source[end:]


def _remove_all(source: str) -> str:
    tree = ast.parse(source)

    lines = source.splitlines(keepends=True)

    nodes = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
    ]

    for node in reversed(nodes):
        del lines[node.lineno - 1 : node.end_lineno]

    return "".join(lines)


def _extract_imports(source: str) -> tuple[str, list[str]]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)

    imports: list[str] = []
    remove_ranges: list[tuple[int, int]] = []

    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue

        remove_ranges.append(
            (node.lineno - 1, node.end_lineno),
        )

        # Relative imports inside compat/upstream modules refer to code that
        # will exist in this generated module.
        if isinstance(node, ast.ImportFrom) and node.level:
            continue

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""

            if _is_internal_import(module):
                continue

        elif isinstance(node, ast.Import):
            # "import pywidevine" is internal too.
            external_names = [alias for alias in node.names if not _is_internal_import(alias.name)]

            if not external_names:
                continue

            node = ast.Import(names=external_names)

        imports.append(ast.unparse(node))

    for start, end in reversed(remove_ranges):
        del lines[start:end]

    return "".join(lines).lstrip("\n"), imports


def _is_internal_import(module: str) -> bool:
    return any(module == internal or module.startswith(f"{internal}.") for internal in INTERNAL_MODULES)


def _comment_module_docstring(source: str) -> str:
    tree = ast.parse(source)

    if not (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        return source

    node = tree.body[0]
    lines = source.splitlines(keepends=True)
    docstring_lines = lines[node.lineno - 1 : node.end_lineno]

    docstring = "".join(docstring_lines).strip()

    if docstring.startswith(('"""', "'''")):
        docstring = docstring[3:]
    if docstring.endswith(('"""', "'''")):
        docstring = docstring[:-3]

    commented = [f"# {line}" if line else "#" for line in docstring.splitlines()]

    lines[node.lineno - 1 : node.end_lineno] = [
        "\n".join(commented) + "\n",
    ]

    return "".join(lines)


def _format_output(path: Path) -> None:
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError(f"ruff is required to build {path.name}")

    subprocess.run(
        [
            ruff,
            "check",
            "--select",
            "I",
            "--fix",
            "--quiet",
            str(path),
        ],
        cwd=ROOT,
        check=True,
    )

    subprocess.run(
        [
            ruff,
            "format",
            "--quiet",
            str(path),
        ],
        cwd=ROOT,
        check=True,
    )


def _bundle_pywidevine() -> tuple[set[str], list[tuple[str, str]]]:
    sections: list[tuple[str, str]] = []
    imports: set[str] = set()

    for filename in COMPAT_MODULES:
        path = COMPAT_DIR / filename

        if not path.exists():
            raise SystemExit(f"Missing compatibility file: {path}")

        source = _rewrite_source(
            path.read_text(encoding="utf-8"),
        )
        source, source_imports = _extract_imports(source)

        imports.update(source_imports)
        sections.append(
            (f"compat/{filename}", source),
        )

    for filename in MODULE_ORDER:
        path = SOURCE_DIR / filename

        if not path.exists():
            raise SystemExit(f"Missing source file: {path}")

        source = _rewrite_source(
            path.read_text(encoding="utf-8"),
            filename=filename,
        )
        source, source_imports = _extract_imports(source)

        imports.update(source_imports)
        sections.append(
            (str(path.relative_to(SOURCE_DIR)), source),
        )

    return imports, sections


def _write_bundle(
    imports: set[str],
    sections: list[tuple[str, str]],
) -> None:
    print(f"Building {BUNDLE_OUTPUT.relative_to(ROOT)}...")

    lines: list[str] = [
        "# THIS FILE IS AUTO-GENERATED.",
        "# DO NOT EDIT THIS FILE DIRECTLY.",
        "",
        '"""',
        "Bundled pywidevine implementation.",
        "",
        "This file contains modified portions of pywidevine,",
        "Copyright (c) rlaphoenix.",
        "",
        "pywidevine is licensed under the terms of GNU General Public License, Version 3.0.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
    ]

    lines.extend(sorted(imports))

    for name, source in sections:
        lines.extend([
            f"# --- begin {name} ---",
            source.rstrip(),
            "",
        ])

    lines.extend([
        "__all__ = [",
        '    "Cdm",',
        '    "RemoteCdm",',
        '    "Device",',
        '    "DeviceTypes",',
        '    "Key",',
        '    "PSSH",',
        '    "Session",',
        "]",
        "",
    ])

    BUNDLE_OUTPUT.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    _format_output(BUNDLE_OUTPUT)

    print(f"Built {BUNDLE_OUTPUT.relative_to(ROOT)} successfully")


def _write_plugin(
    imports: set[str],
    sections: list[tuple[str, str]],
) -> None:
    print(f"Building {PLUGIN_OUTPUT.relative_to(ROOT)}...")

    plugin_source = _rewrite_plugin(
        PLUGIN_SOURCE.read_text(encoding="utf-8"),
    )

    plugin_source, plugin_imports = _extract_imports(plugin_source)

    all_imports = sorted(imports | set(plugin_imports))

    lines = [
        "# THIS FILE IS AUTO-GENERATED.",
        "# DO NOT EDIT THIS FILE DIRECTLY.",
        "",
        '"""',
        "streamlink-plugin-widevine.",
        "",
        "This file contains modified portions of pywidevine,",
        "Copyright (c) rlaphoenix.",
        "",
        "pywidevine is licensed under the terms of GNU General Public License, Version 3.0.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
    ]

    lines.extend(all_imports)
    lines.extend([
        "",
        plugin_source.rstrip(),
        "",
        "# ============================================================================",
        "# Bundled pywidevine implementation.",
        "# ============================================================================",
        "",
    ])

    for name, source in sections:
        lines.extend([
            f"# --- begin {name} ---",
            source.rstrip(),
            "",
        ])

    PLUGIN_OUTPUT.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    _format_output(PLUGIN_OUTPUT)

    print(f"Built {PLUGIN_OUTPUT.relative_to(ROOT)} successfully")


def build() -> None:
    if not SOURCE_DIR.exists():
        raise SystemExit(f"Source directory not found: {SOURCE_DIR}")

    imports, sections = _bundle_pywidevine()

    _write_bundle(imports, sections)
    _write_plugin(imports, sections)


if __name__ == "__main__":
    build()
