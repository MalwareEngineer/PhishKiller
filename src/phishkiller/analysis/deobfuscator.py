"""Deobfuscation engine — PHP eval-chain unwrapping, HTML empty-tag stripping,
and JS XOR+base64+eval decoding.

PHP handles:
  1. eval(base64_decode("..."))
  2. eval(gzinflate(base64_decode("...")))
  3. eval(gzinflate(str_rot13(base64_decode("..."))))
  4. eval(str_rot13("..."))
  5. Nested combinations up to MAX_RECURSION_DEPTH layers
  6. chr() concatenation patterns

JS handles:
  7. atob() → charCodeAt()^KEY → eval() chains
  8. base64 string → byte-level XOR → eval()

Does NOT execute PHP or JS. Only applies known inverse functions in Python.
"""

import base64
import codecs
import re
import zlib
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

MAX_RECURSION_DEPTH = 100
MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB


@dataclass
class DeobfuscationResult:
    original_content: str
    deobfuscated_content: str
    layers_unwrapped: int
    techniques_found: list[str] = field(default_factory=list)
    success: bool = True
    error: str | None = None


def _url_decode(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="ignore")
    return unquote_to_bytes(data)


class PHPDeobfuscator:
    """Recursive PHP deobfuscator using pattern matching and inverse functions."""

    # Match eval() calls containing known decode functions
    EVAL_PATTERN = re.compile(
        r"eval\s*\(\s*"
        r"((?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13"
        r"|rawurldecode|urldecode|convert_uudecode|hex2bin|strrev)"
        r"\s*\(.*?\))"
        r"\s*\)\s*;",
        re.DOTALL | re.IGNORECASE,
    )

    # Match function names in nested chains
    NESTED_FUNC_PATTERN = re.compile(
        r"(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13"
        r"|rawurldecode|urldecode|convert_uudecode|hex2bin|strrev)\s*\(",
        re.IGNORECASE,
    )

    # Match chr() concatenation: chr(72).chr(101).chr(108)...
    CHR_CONCAT_PATTERN = re.compile(
        r"(?:chr\s*\(\s*(\d+)\s*\)\s*\.?\s*){3,}",
        re.IGNORECASE,
    )
    CHR_SINGLE_PATTERN = re.compile(r"chr\s*\(\s*(\d+)\s*\)", re.IGNORECASE)

    # Map PHP function names to Python equivalents
    DECODERS: dict[str, callable] = {
        "base64_decode": lambda data: base64.b64decode(data),
        "gzinflate": lambda data: zlib.decompress(data, -zlib.MAX_WBITS),
        "gzuncompress": lambda data: zlib.decompress(data),
        "gzdecode": lambda data: zlib.decompress(data, zlib.MAX_WBITS | 16),
        "str_rot13": lambda data: codecs.encode(
            data if isinstance(data, str) else data.decode("utf-8", errors="ignore"),
            "rot_13",
        ).encode("utf-8"),
        "rawurldecode": lambda data: _url_decode(data),
        "urldecode": lambda data: _url_decode(data),
        "hex2bin": lambda data: bytes.fromhex(
            data if isinstance(data, str) else data.decode("ascii")
        ),
        "strrev": lambda data: (
            data[::-1] if isinstance(data, (str, bytes)) else data
        ),
    }

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Recursively deobfuscate PHP content."""
        techniques_found: list[str] = []
        current = content
        layers = 0

        for _ in range(MAX_RECURSION_DEPTH):
            previous = current

            # Try eval() unwrapping
            current, found = self._unwrap_eval_layer(current)
            techniques_found.extend(found)

            # Try chr() concatenation resolution
            current, chr_found = self._resolve_chr_concat(current)
            if chr_found:
                techniques_found.append("chr_concat")

            if current == previous:
                break
            layers += 1

            if len(current) > MAX_OUTPUT_SIZE:
                return DeobfuscationResult(
                    original_content=content[:1000],
                    deobfuscated_content=current[:MAX_OUTPUT_SIZE],
                    layers_unwrapped=layers,
                    techniques_found=list(set(techniques_found)),
                    success=False,
                    error="Output size exceeded limit",
                )

        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=current,
            layers_unwrapped=layers,
            techniques_found=list(set(techniques_found)),
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)

    def _unwrap_eval_layer(self, content: str) -> tuple[str, list[str]]:
        techniques: list[str] = []
        result = content

        for match in self.EVAL_PATTERN.finditer(content):
            inner_expr = match.group(1)
            try:
                decoded, funcs_used = self._decode_expression(inner_expr)
                if decoded and decoded != inner_expr:
                    decoded_str = (
                        decoded.decode("utf-8", errors="ignore")
                        if isinstance(decoded, bytes)
                        else decoded
                    )
                    result = result.replace(match.group(0), decoded_str)
                    techniques.extend(funcs_used)
            except Exception:
                continue

        return result, techniques

    def _decode_expression(
        self, expression: str
    ) -> tuple[bytes | str | None, list[str]]:
        """Decode a nested function expression from inside out."""
        funcs_used: list[str] = []

        # Extract chain of function names (outermost first)
        func_chain: list[str] = []
        for m in self.NESTED_FUNC_PATTERN.finditer(expression):
            func_chain.append(m.group(1).lower())

        # Find the innermost string argument
        string_match = re.search(r'["\']([^"\']*)["\']', expression)
        if not string_match:
            return None, []

        data: bytes | str = string_match.group(1)

        # Apply functions from innermost to outermost (reverse order)
        for func_name in reversed(func_chain):
            decoder = self.DECODERS.get(func_name)
            if not decoder:
                continue
            try:
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="ignore")
                data = decoder(data)
                funcs_used.append(func_name)
            except Exception:
                break

        return data, funcs_used

    def _resolve_chr_concat(self, content: str) -> tuple[str, bool]:
        """Replace chr(N).chr(N)... patterns with the decoded string."""
        changed = False

        def replace_chr_chain(match: re.Match) -> str:
            nonlocal changed
            chars = self.CHR_SINGLE_PATTERN.findall(match.group(0))
            try:
                result = "".join(chr(int(c)) for c in chars)
                changed = True
                return f'"{result}"'
            except (ValueError, OverflowError):
                return match.group(0)

        result = self.CHR_CONCAT_PATTERN.sub(replace_chr_chain, content)
        return result, changed


class HTMLDeobfuscator:
    """Strip empty inline HTML tags used for string-splitting obfuscation.

    AiTM PhaaS kits insert empty tags between characters to defeat
    text-based IOC extraction and YARA rules::

        P<b></b>a<b></b>ss<b></b>wo<b></b>rd  →  Password

    Only activates when 10+ empty tags are found (legitimate HTML rarely
    has that many).
    """

    # Match empty inline tags — allows optional attributes and whitespace.
    EMPTY_INLINE_TAG = re.compile(
        r"<(b|i|em|strong|span|u|s|small|mark|abbr|cite|code|sub|sup)"
        r"(?:\s+[^>]*)?\s*>\s*</\1\s*>",
        re.IGNORECASE,
    )

    MIN_OCCURRENCES = 10

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Strip empty inline tags if the file looks obfuscated."""
        matches = self.EMPTY_INLINE_TAG.findall(content)
        if len(matches) < self.MIN_OCCURRENCES:
            return DeobfuscationResult(
                original_content=content[:1000],
                deobfuscated_content=content,
                layers_unwrapped=0,
                techniques_found=[],
                success=True,
            )

        cleaned = self.EMPTY_INLINE_TAG.sub("", content)
        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=cleaned,
            layers_unwrapped=1,
            techniques_found=["empty_tag_splitting"],
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)


class JSDeobfuscator:
    """Deobfuscate JavaScript XOR+base64+eval chains.

    Covers common phishing-kit obfuscation patterns:
      - atob(encoded) → split('') → map(c => c.charCodeAt(0) ^ KEY) → eval
      - Base64 string embedded in array rotation (parseInt loader)
      - document.write / eval of XOR-decoded payload

    Returns the decoded plaintext (often JS that contains URLs to external
    phishing infrastructure).
    """

    # Match atob('...') calls with long base64 payloads
    ATOB_PATTERN = re.compile(
        r"""atob\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]""",
        re.IGNORECASE,
    )

    # Match XOR key in charCodeAt(0) ^ KEY patterns
    # Handles both direct call and bracket notation:
    #   c.charCodeAt(0) ^ 0xAD
    #   c["charCodeAt"](0) ^ 0xAD
    XOR_CHARCODE_PATTERN = re.compile(
        r"""charCodeAt['"]\s*\]\s*\(\s*0?\s*\)\s*\^\s*(0x[0-9a-fA-F]+|\d+)"""
        r"""|charCodeAt\s*\(\s*0?\s*\)\s*\^\s*(0x[0-9a-fA-F]+|\d+)""",
    )

    # Match large base64 strings in JS string arrays / variables
    JS_BASE64_STRING = re.compile(
        r"""['"]([A-Za-z0-9+/=]{40,})['"]""",
    )

    # URL pattern for extracted decoded content
    URL_PATTERN = re.compile(
        r"""https?://[^\s"'<>\]\)\\]+""",
        re.IGNORECASE,
    )

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Attempt JS deobfuscation of content."""
        techniques: list[str] = []
        decoded_parts: list[str] = []

        # Try XOR+base64 pattern (the most common in AiTM kits)
        decoded = self._try_xor_base64(content)
        if decoded:
            techniques.append("js_xor_base64")
            decoded_parts.append(decoded)
            # Recursively try to decode the output (may be another layer)
            inner = self._try_xor_base64(decoded)
            if inner:
                techniques.append("js_xor_base64_nested")
                decoded_parts.append(inner)

        # Try plain atob('...') without XOR (simpler obfuscation)
        for m in self.ATOB_PATTERN.finditer(content):
            try:
                raw = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                if len(raw) > 10 and raw.isprintable():
                    if raw not in decoded_parts:
                        decoded_parts.append(raw)
                        techniques.append("js_atob")
            except Exception:
                continue

        # Try base64 strings found in decoded layers (handles atob(variable)
        # where the variable holds a base64 string assigned elsewhere)
        for part in list(decoded_parts):
            for m in self.JS_BASE64_STRING.finditer(part):
                try:
                    raw = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                    # Use replace to strip whitespace before printable check
                    stripped = raw.replace("\n", "").replace("\r", "").replace("\t", "")
                    if len(raw) > 10 and stripped.isprintable() and raw not in decoded_parts:
                        decoded_parts.append(raw)
                        techniques.append("js_base64_var")
                except Exception:
                    continue

        if not decoded_parts:
            return DeobfuscationResult(
                original_content=content[:1000],
                deobfuscated_content=content,
                layers_unwrapped=0,
                techniques_found=[],
                success=True,
            )

        # Build the deobfuscated output: decoded layers concatenated
        deob_content = "\n\n".join(decoded_parts)
        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=deob_content,
            layers_unwrapped=len(decoded_parts),
            techniques_found=list(set(techniques)),
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)

    def extract_urls(self, content: str) -> list[str]:
        """Extract URLs from decoded JS content."""
        result = self.deobfuscate(content)
        return self.URL_PATTERN.findall(result.deobfuscated_content)

    def _try_xor_base64(self, content: str) -> str | None:
        """Try to decode atob(payload) → charCodeAt ^ KEY pattern.

        Pattern:
          atob('base64string').split('').map(c => c.charCodeAt(0) ^ 0xAD)
          → new TextDecoder().decode(new Uint8Array(bytes))
          → eval(decoded)
        """
        # Find XOR key (may be in group 1 or group 2 depending on alternation)
        xor_match = self.XOR_CHARCODE_PATTERN.search(content)
        if not xor_match:
            return None

        key_str = xor_match.group(1) or xor_match.group(2)
        if not key_str:
            return None
        xor_key = int(key_str, 16) if key_str.startswith("0x") else int(key_str)
        if xor_key < 1 or xor_key > 255:
            return None

        # Find base64 payloads and try each with the XOR key
        for b64_match in self.JS_BASE64_STRING.finditer(content):
            b64_str = b64_match.group(1)
            try:
                raw_bytes = base64.b64decode(b64_str)
                decoded_bytes = bytes(b ^ xor_key for b in raw_bytes)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                # Validate: should contain printable text, URLs, or JS keywords
                if len(decoded_str) > 20 and (
                    self.URL_PATTERN.search(decoded_str)
                    or "function" in decoded_str.lower()
                    or "document" in decoded_str.lower()
                    or "var " in decoded_str
                    or "const " in decoded_str
                    or "let " in decoded_str
                    or "window." in decoded_str
                ):
                    return decoded_str
            except Exception:
                continue

        return None
