"""Plain-text hex-encoded key file format with PEM-style markers."""

import re


PUBLIC_BEGIN = "-----BEGIN RSA-OAEP PUBLIC KEY-----"
PUBLIC_END = "-----END RSA-OAEP PUBLIC KEY-----"
PRIVATE_BEGIN = "-----BEGIN RSA-OAEP PRIVATE KEY-----"
PRIVATE_END = "-----END RSA-OAEP PRIVATE KEY-----"

_PUBLIC_FIELDS = ("n", "e")
_PRIVATE_REQUIRED = ("n", "d")
_PRIVATE_OPTIONAL = ("p", "q", "dP", "dQ", "qInv")
_FIELD_PATTERN = re.compile(r"^([A-Za-z]+)\s*=\s*([0-9a-fA-F]+)\s*$")


def _hex(value):
    """Return value as a lowercase hex string with an even number of digits."""
    if value < 0:
        raise ValueError("cannot encode a negative integer in this format")
    text = format(value, "x")
    if len(text) % 2 != 0:
        text = "0" + text
    return text


def save_public_key(path, public_key):
    """Write a public key to disk."""
    lines = [PUBLIC_BEGIN, "# Bits: " + str(public_key["n"].bit_length())]
    for field in _PUBLIC_FIELDS:
        lines.append(field + "=" + _hex(public_key[field]))
    lines.append(PUBLIC_END)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def save_private_key(path, private_key):
    """Write a private key to disk, including any CRT parameters that are present."""
    lines = [PRIVATE_BEGIN, "# Bits: " + str(private_key["n"].bit_length())]
    for field in _PRIVATE_REQUIRED:
        lines.append(field + "=" + _hex(private_key[field]))
    for field in _PRIVATE_OPTIONAL:
        if field in private_key:
            lines.append(field + "=" + _hex(private_key[field]))
    lines.append(PRIVATE_END)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def load_key(path):
    """Read a key file and return a dictionary describing its contents.

    The returned dict carries a "type" entry of either "public" or "private"
    plus the integer fields parsed from the file.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if PUBLIC_BEGIN in text and PUBLIC_END in text:
        key_type = "public"
        required = _PUBLIC_FIELDS
    elif PRIVATE_BEGIN in text and PRIVATE_END in text:
        key_type = "private"
        required = _PRIVATE_REQUIRED
    else:
        raise ValueError("unrecognized key file format")
    fields = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("---"):
            continue
        match = _FIELD_PATTERN.match(line)
        if not match:
            continue
        name = match.group(1)
        fields[name] = int(match.group(2), 16)
    for field in required:
        if field not in fields:
            raise ValueError("missing required field in key file: " + field)
    fields["type"] = key_type
    return fields


def to_public_key(loaded):
    """Build a public-key dict suitable for the RSA primitives."""
    if loaded.get("type") != "public":
        raise ValueError("expected a public key")
    return {"n": loaded["n"], "e": loaded["e"]}


def to_private_key(loaded):
    """Build a private-key dict suitable for the RSA primitives.

    Includes CRT parameters when they are available.
    """
    if loaded.get("type") != "private":
        raise ValueError("expected a private key")
    out = {"n": loaded["n"], "d": loaded["d"]}
    for field in _PRIVATE_OPTIONAL:
        if field in loaded:
            out[field] = loaded[field]
    return out
