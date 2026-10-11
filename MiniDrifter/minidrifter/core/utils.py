# -*- coding: utf-8 -*-
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def try_json(path: Path) -> Any:
    try:
        return json.loads(read_text(path))
    except Exception:
        return None


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def line_no(text: str, idx: int) -> int:
    return text.count('\n', 0, max(0, idx)) + 1


def short_snippet(text: str, idx: int, radius: int = 180) -> str:
    s = max(0, idx - radius)
    e = min(len(text), idx + radius)
    return re.sub(r'\s+', ' ', text[s:e]).strip()


def stable_id(prefix: str, *parts: object) -> str:
    raw = '||'.join(str(p) for p in parts)
    h = hashlib.sha1(raw.encode('utf-8', errors='ignore')).hexdigest()[:12]
    return f'{prefix}_{h}'


def normalize_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def iter_files(root: Path, suffixes: Optional[Iterable[str]] = None) -> List[Path]:
    if suffixes is None:
        return [p for p in root.rglob('*') if p.is_file()]
    suffixes = set(suffixes)
    return [p for p in root.rglob('*') if p.is_file() and p.suffix in suffixes]


def extract_input(input_path: str | Path) -> Tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    """Return a directory root. If input is zip, extract to a temp directory."""
    p = Path(input_path).expanduser().resolve()
    if p.is_dir():
        return p, None
    if p.is_file() and p.suffix.lower() == '.zip':
        td = tempfile.TemporaryDirectory(prefix='MiniDrifter_src_')
        with zipfile.ZipFile(p, 'r') as zf:
            zf.extractall(td.name)
        root = Path(td.name)
        # If the zip contains a single top-level directory, use it.
        children = [c for c in root.iterdir() if c.name != '__MACOSX']
        if len(children) == 1 and children[0].is_dir():
            return children[0], td
        return root, td
    if p.is_file() and p.suffix.lower() in {'.rar', '.7z'}:
        # RAR extraction normally requires an external backend such as unrar/bsdtar/7z.
        # We support it when the environment provides the backend, and fail with a precise message otherwise.
        td = tempfile.TemporaryDirectory(prefix='MiniDrifter_src_')
        if p.suffix.lower() == '.rar':
            try:
                import rarfile  # type: ignore
                with rarfile.RarFile(p) as rf:
                    rf.extractall(td.name)
            except Exception as exc:
                td.cleanup()
                raise RuntimeError('RAR input requires a working extraction backend such as unrar or bsdtar. Extract the mini-program first or install the backend.') from exc
        else:
            td.cleanup()
            raise RuntimeError('7z input is not extracted by the built-in backend. Extract it first or pass a directory/zip.')
        root = Path(td.name)
        children = [c for c in root.iterdir() if c.name != '__MACOSX']
        if len(children) == 1 and children[0].is_dir():
            return children[0], td
        return root, td
    raise FileNotFoundError(f'Input path is neither a directory nor a supported archive: {p}')


def split_args(arg_text: str) -> List[str]:
    """Lightweight JS argument splitter respecting brackets and strings."""
    args, cur = [], []
    depth = 0
    quote = None
    esc = False
    for ch in arg_text:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            cur.append(ch)
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            args.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur or arg_text.strip():
        args.append(''.join(cur).strip())
    return args


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    quote = None
    esc = False
    for i in range(open_idx, len(text)):
        ch = text[i]
        if quote:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i
    return -1


def extract_object_keys(expr: str) -> List[str]:
    """Extract likely object literal keys from a JS expression."""
    keys = []
    for m in re.finditer(r'([A-Za-z_$][\w$]*)\s*:', expr):
        k = m.group(1)
        if k not in {'if', 'for', 'while', 'switch', 'function', 'return'}:
            keys.append(k)
    # shorthand object literal fields within { a, b }
    if expr.strip().startswith('{'):
        inner = expr.strip()[1:-1] if expr.strip().endswith('}') else expr.strip()[1:]
        for part in split_args(inner):
            if re.fullmatch(r'[A-Za-z_$][\w$]*', part):
                keys.append(part)
    return list(dict.fromkeys(keys))


def js_string_value(expr: str) -> Optional[str]:
    expr = expr.strip()
    if (expr.startswith("'") and expr.endswith("'")) or (expr.startswith('"') and expr.endswith('"')):
        return expr[1:-1]
    return None


def tokenise_identifier(s: str) -> List[str]:
    s = re.sub(r'https?://', ' ', s)
    parts = re.split(r'[^A-Za-z0-9]+', s)
    out = []
    for part in parts:
        if not part:
            continue
        # split camel case conservatively
        camel = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+', part)
        out.extend([x.lower() for x in camel if x])
    return out
