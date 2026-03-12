"""PHP deobfuscation engine — recursive unwrapping of common obfuscation chains.

Handles:
  1. eval(base64_decode("..."))
  2. eval(gzinflate(base64_decode("...")))
  3. eval(gzinflate(str_rot13(base64_decode("..."))))
  4. eval(str_rot13("..."))
  5. Nested combinations up to MAX_RECURSION_DEPTH layers
  6. chr() concatenation patterns

Does NOT execute PHP. Only applies known inverse functions in Python.
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
