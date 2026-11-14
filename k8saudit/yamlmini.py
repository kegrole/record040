"""A tiny indentation-based YAML subset parser (standard library only).

Supported subset:
* nested mappings and block sequences, including sequences of mappings;
* block scalars: literal ``|`` and folded ``>`` (``-``/``+`` chomping);
* single- and double-quoted scalars;
* inline flow sequences such as ``[a, b, c]``;
* full-line comments and trailing comments;
* ``---`` document separators via :func:`load_all`.

Unsupported YAML features (anchors, tags, flow mappings, ...) are outside the
subset needed by the auditor and intentionally not implemented.
"""

from __future__ import annotations

import re


class YAMLError(ValueError):
    """Raised when input cannot be parsed by the subset parser."""


class _Line:
    __slots__ = ("indent", "text", "raw", "number")

    def __init__(self, indent: int, text: str, raw: str, number: int) -> None:
        self.indent = indent
        self.text = text
        self.raw = raw
        self.number = number


_BLOCK_HEADER = re.compile(r"^[|>][-+]?[0-9]*$")
_ATOM_TRUE = {"true", "yes"}
_ATOM_FALSE = {"false", "no"}
_ATOM_NULL = {"null", "~", "none", ""}


def _strip_comment(raw_line: str) -> str:
    """Remove a trailing/full-line ``#`` comment that is not quoted."""
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(raw_line):
        if in_double:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_double = False
            continue
        if in_single:
            if char == "'":
                in_single = False
            continue
        if char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "#" and (index == 0 or raw_line[index - 1] in " \\t"):
            return raw_line[:index].strip()
    return raw_line.strip()


def _tokenize(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        stripped = _strip_comment(raw_line)
        if not stripped:
            # Blank lines are retained because block scalars care about them.
            lines.append(_Line(-1, "", raw_line.rstrip(), number))
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        lines.append(_Line(indent, stripped, raw_line.rstrip(), number))
    return lines


def _skip_blank(lines: list[_Line], index: int) -> int:
    while index < len(lines) and lines[index].text == "":
        index += 1
    return index


def _split_inline(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    start = 0
    for index, char in enumerate(text):
        if in_double:
            if char == '"':
                in_double = False
            continue
        if in_single:
            if char == "'":
                in_single = False
            continue
        if char == '"':
            in_double = True
        elif char == "'":
            in_single = True
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_double_quoted(text: str) -> str:
    result: list[str] = []
    escaped = False
    for char in text[1:-1]:
        if escaped:
            mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                       '"': '"', "0": "\0", "/": "/"}
            result.append(mapping.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            result.append(char)
    return "".join(result)


def _parse_scalar(text: str):
    text = text.strip()
    if not text:
        return None
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return _parse_double_quoted(text)
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if text[0] == "[" and text[-1] == "]":
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in _split_inline(inner)]
    lowered = text.lower()
    if lowered in _ATOM_TRUE:
        return True
    if lowered in _ATOM_FALSE:
        return False
    if lowered in _ATOM_NULL:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_key(text: str) -> tuple[str, str]:
    in_single = False
    in_double = False
    for index, char in enumerate(text):
        if in_double:
            if char == '"':
                in_double = False
            continue
        if in_single:
            if char == "'":
                in_single = False
            continue
        if char == '"':
            in_double = True
        elif char == "'":
            in_single = True
        elif char == ":" and (index + 1 == len(text) or text[index + 1] == " "):
            return text[:index].strip(), text[index + 1:].strip()
    raise YAMLError(f"expected 'key: value' mapping entry: {text!r}")


def _read_block_scalar(lines: list[_Line], index: int, parent_indent: int,
                       mode: str, chomp: str) -> tuple[str, int]:
    block: list[_Line] = []
    cursor = index
    while cursor < len(lines):
        line = lines[cursor]
        if line.text == "":
            block.append(line)
            cursor += 1
            continue
        if line.indent <= parent_indent:
            break
        block.append(line)
        cursor += 1

    content = [line for line in block if line.text != ""]
    if not content:
        return "", cursor
    block_indent = min(line.indent for line in content)
    raw_lines = [
        "" if line.text == "" else line.raw[block_indent:]
        for line in block
    ]

    if mode == "|":
        body = "\n".join(raw_lines)
    else:
        folded: list[str] = []
        for line in raw_lines:
            if line == "":
                folded.append("\n")
            elif folded and not folded[-1].endswith("\n"):
                folded.append(" ")
                folded.append(line)
            else:
                folded.append(line)
        body = "".join(folded)

    if chomp == "strip":
        body = body.rstrip("\n")
    elif chomp == "keep":
        if not body.endswith("\n"):
            body += "\n"
    else:  # clip: exactly one trailing newline
        body = body.rstrip("\n") + "\n"
    return body, cursor


def _parse_map(lines: list[_Line], index: int, indent: int) -> tuple[dict, int]:
    result: dict = {}
    cursor = index
    while cursor < len(lines):
        cursor = _skip_blank(lines, cursor)
        if cursor >= len(lines):
            break
        line = lines[cursor]
        if line.indent != indent or line.text.startswith("- "):
            break
        raw_key, rest = _split_key(line.text)
        key = _parse_scalar(raw_key) if raw_key[:1] in ("'", '"') else raw_key
        cursor += 1
        if rest == "":
            child_index = _skip_blank(lines, cursor)
            if child_index < len(lines) and lines[child_index].indent > indent:
                value, cursor = _parse_node(lines, child_index,
                                           lines[child_index].indent)
            else:
                value = None
        elif _BLOCK_HEADER.match(rest):
            mode = rest[0]
            chomp = "clip"
            for marker in rest[1:]:
                if marker == "-":
                    chomp = "strip"
                elif marker == "+":
                    chomp = "keep"
            value, cursor = _read_block_scalar(lines, cursor, indent, mode, chomp)
        else:
            value = _parse_scalar(rest)
        result[key] = value
    return result, cursor


def _parse_list(lines: list[_Line], index: int, indent: int) -> tuple[list, int]:
    items: list = []
    cursor = index
    while cursor < len(lines):
        cursor = _skip_blank(lines, cursor)
        if cursor >= len(lines):
            break
        line = lines[cursor]
        if line.indent != indent or not line.text.startswith("- "):
            break
        rest = line.text[2:]
        cursor += 1
        if not rest.strip():
            child_index = _skip_blank(lines, cursor)
            if child_index < len(lines) and lines[child_index].indent > indent:
                value, cursor = _parse_node(lines, child_index,
                                           lines[child_index].indent)
            else:
                value = None
            items.append(value)
            continue
        try:
            _split_key(rest)
        except YAMLError:
            items.append(_parse_scalar(rest))
            continue
        lead = len(rest) - len(rest.lstrip(" "))
        content_indent = indent + 2 + lead
        sub_lines = [_Line(content_indent, rest.strip(), rest.strip(), line.number)]
        lookahead = cursor
        while lookahead < len(lines):
            upcoming = lines[lookahead]
            if upcoming.text != "" and upcoming.indent < content_indent:
                break
            sub_lines.append(upcoming)
            lookahead += 1
        value, sub_cursor = _parse_map(sub_lines, 0, content_indent)
        if sub_cursor != len(sub_lines):
            raise YAMLError(
                f"malformed sequence item starting on line {line.number}"
            )
        items.append(value)
        cursor = lookahead
    return items, cursor


def _parse_node(lines: list[_Line], index: int, indent: int):
    index = _skip_blank(lines, index)
    if index >= len(lines):
        return None, index
    line = lines[index]
    if line.text.startswith("- "):
        return _parse_list(lines, index, line.indent)
    return _parse_map(lines, index, line.indent)


def load_all(text: str) -> list:
    """Parse all ``---`` separated documents in *text*."""
    documents: list = []
    chunks = re.split(r"(?m)^---[ \t]*$", text)
    for chunk in chunks:
        lines = _tokenize(chunk)
        if not any(line.text for line in lines):
            continue
        value, _ = _parse_node(lines, 0, lines[_skip_blank(lines, 0)].indent)
        documents.append(value)
    return documents


def loads(text: str):
    """Parse the first document in *text*."""
    documents = load_all(text)
    if not documents:
        return None
    return documents[0]
