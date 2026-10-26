"""Fuzz harness for the validators that guard outbound requests
(cx_client.safe_endpoint / safe_tenant).

Properties checked on every input:
  * the only exception either function raises is CxApiError;
  * safe_endpoint only ever returns an https URL whose host is a Checkmarx
    One host, with no credentials, query or fragment;
  * safe_tenant only ever returns a single, URL-safe path segment.

Run with Atheris (Linux, or clang with libFuzzer):
    pip install atheris && python fuzz/fuzz_input_validation.py
Without Atheris it falls back to a fixed number of random/mutated inputs:
    python fuzz/fuzz_input_validation.py [iterations]
"""
import os
import random
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.pop("CX_ALLOWED_HOSTS", None)

import cx_client  # noqa: E402

_SEEDS = [
    "https://iam.checkmarx.net", "https://eu.ast.checkmarx.net/", "https://ast.checkmarx.net:443/x?y#z",
    "https://iam.checkmarx.net@evil.com", "https://evil.com#.checkmarx.net", "https://checkmarx.net.evil.com",
    "https://u:p@ast.checkmarx.net", "http://ast.checkmarx.net", "https://[::1]", "https://ast.checkmarx.net.",
    "https://AST.CHECKMARX.NET", "https://ast.checkmarx.net\\@evil.com", "https://ast.checkmarx.net%2f@evil.com",
    "ps_na_tenant", "../admin", "a/b", "t?x", "t%2fx",
]


def check(text: str) -> None:
    try:
        url = cx_client.safe_endpoint(text)
    except cx_client.CxApiError:
        pass
    else:
        parts = urlsplit(url)
        host = parts.hostname or ""
        assert parts.scheme == "https", url
        assert host == "checkmarx.net" or host.endswith(".checkmarx.net"), url
        assert not (parts.username or parts.password or parts.query or parts.fragment), url

    try:
        segment = cx_client.safe_tenant(text)
    except cx_client.CxApiError:
        pass
    else:
        assert segment and all(c.isalnum() or c in "_.-" for c in segment) and ".." not in segment, segment


def _mutate(rng: random.Random, text: str) -> str:
    alphabet = "abc.:/@?#%\\[]-_ \t\n\x00" + "".join(chr(rng.randrange(32, 0x3000)) for _ in range(4))
    chars = list(text)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(3)
        pos = rng.randrange(len(chars) + 1)
        if op == 0:
            chars.insert(pos, rng.choice(alphabet))
        elif op == 1 and chars:
            del chars[min(pos, len(chars) - 1)]
        else:
            chars[pos:pos] = list(rng.choice(_SEEDS))
    return "".join(chars)


def main() -> None:
    try:
        import atheris
    except ImportError:
        iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
        rng = random.Random(0)
        for seed in _SEEDS:
            check(seed)
        for _ in range(iterations):
            check(_mutate(rng, rng.choice(_SEEDS)))
        print(f"atheris not installed; {iterations} mutated inputs checked, no property violations")
        return

    def one_input(data: bytes) -> None:
        check(atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(256))

    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
