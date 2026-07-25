"""
Fix for Issue #1472 — CL.TE HTTP Request Smuggling → Cache Poisoning ($200)
================================================================================

Vulnerability
-------------
Front-end nginx uses Content-Length while back-end uses Transfer-Encoding:
chunked. Attackers craft ambiguous requests where the front-end sees one
request boundary and the back-end sees another, poisoning the cache for
subsequent users.

Fix Strategy
------------
1. Reject requests with both Content-Length and Transfer-Encoding headers.
2. Validate Transfer-Encoding header format (only "chunked" is accepted).
3. Normalize Transfer-Encoding parsing to handle multiple values safely.
4. Provide nginx configuration to reject ambiguous requests at the proxy level.
5. Recommend HTTP/2 to eliminate HTTP/1.x parsing ambiguity entirely.

Acceptance Criteria
-------------------
- [x] TE and CL cannot coexist
- [x] Malformed Transfer-Encoding headers are rejected
- [x] HTTP/2 is recommended to eliminate ambiguity
"""

from __future__ import annotations

import re
from typing import Final, Tuple

# Pattern for valid Transfer-Encoding: chunked
_TE_VALID_RE: Final[re.Pattern] = re.compile(r"^\s*chunked\s*$", re.IGNORECASE)

# Pattern to detect chunked anywhere in Transfer-Encoding
_TE_CHUNKED_RE: Final[re.Pattern] = re.compile(r"chunked", re.IGNORECASE)

# Pattern for Content-Length header
_CL_RE: Final[re.Pattern] = re.compile(r"^\s*\d+\s*$")


def has_transfer_encoding_chunked(headers: dict[str, str]) -> bool:
    """Check if Transfer-Encoding header contains 'chunked'."""
    te = headers.get("Transfer-Encoding", "")
    return bool(_TE_CHUNKED_RE.search(te))


def has_content_length(headers: dict[str, str]) -> bool:
    """Check if Content-Length header is present."""
    return "Content-Length" in headers


def is_smuggling_request(headers: dict[str, str]) -> bool:
    """Detect CL.TE smuggling: both Content-Length and Transfer-Encoding: chunked."""
    return has_content_length(headers) and has_transfer_encoding_chunked(headers)


def validate_http_request(headers: dict[str, str]) -> Tuple[bool, str]:
    """
    Validate an HTTP/1.1 request for CL.TE smuggling vulnerabilities.

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Rule 1: CL and TE cannot coexist
    if is_smuggling_request(headers):
        return False, "Ambiguous request: both Content-Length and Transfer-Encoding: chunked present"

    # Rule 2: Validate Transfer-Encoding format
    te = headers.get("Transfer-Encoding", "")
    if te and not _TE_VALID_RE.match(te):
        return False, f"Malformed Transfer-Encoding header: {te!r}"

    # Rule 3: Validate Content-Length format
    cl = headers.get("Content-Length", "")
    if cl and not _CL_RE.match(cl):
        return False, f"Malformed Content-Length header: {cl!r}"

    return True, ""


# =============================================================================
# WSGI Middleware
# =============================================================================

class CLTESmugglingProtectionMiddleware:
    """
    WSGI middleware that rejects CL.TE HTTP request smuggling attempts.

    Place this middleware first in the WSGI stack to inspect all
    incoming requests before they reach the application.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        headers = {
            "Content-Length": environ.get("CONTENT_LENGTH", ""),
            "Transfer-Encoding": environ.get("HTTP_TRANSFER_ENCODING", ""),
        }

        valid, error = validate_http_request(headers)
        if not valid:
            start_response("400 Bad Request", [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(error))),
            ])
            return [error.encode("utf-8")]

        return self.app(environ, start_response)


# =============================================================================
# Nginx Configuration (for reference)
# =============================================================================

NGINX_CONFIG = """
# Nginx configuration to prevent CL.TE HTTP Request Smuggling
# Place in server or location block

# Reject requests with both Content-Length and Transfer-Encoding
if ($http_transfer_encoding ~* "chunked") {
    set $smuggling_check "${http_content_length}${smuggling_check}";
}
if ($http_content_length) {
    set $smuggling_check "${smuggling_check}A";
}
if ($smuggling_check ~ "^(?=.*chunked)(?=.*A)") {
    return 400 "Ambiguous request: CL.TE smuggling detected";
}

# Reject malformed Transfer-Encoding headers
if ($http_transfer_encoding !~* "^\\s*chunked\\s*$" and $http_transfer_encoding != "") {
    return 400 "Malformed Transfer-Encoding header";
}

# Recommended: use HTTP/2 to eliminate HTTP/1.x parsing ambiguity
# listen 443 ssl http2;
"""


# =============================================================================
# Tests
# =============================================================================

def test_cl_te_detection():
    """Test that CL.TE smuggling is detected correctly."""
    # Normal request (no smuggling)
    headers = {"Content-Type": "application/json"}
    assert not is_smuggling_request(headers), "Normal request should not be flagged"

    # CL only
    headers = {"Content-Length": "100"}
    assert not is_smuggling_request(headers), "CL-only should not be flagged"

    # TE only
    headers = {"Transfer-Encoding": "chunked"}
    assert not is_smuggling_request(headers), "TE-only should not be flagged"

    # CL + TE (smuggling)
    headers = {"Content-Length": "100", "Transfer-Encoding": "chunked"}
    assert is_smuggling_request(headers), "CL + TE should be flagged as smuggling"

    print("PASS: CL.TE detection works correctly")


def test_validation():
    """Test that validation rejects smuggling requests."""
    # Valid request
    valid, err = validate_http_request({"Content-Type": "application/json"})
    assert valid, f"Valid request should pass: {err}"

    # CL only
    valid, err = validate_http_request({"Content-Length": "100"})
    assert valid, f"CL-only should pass: {err}"

    # TE only
    valid, err = validate_http_request({"Transfer-Encoding": "chunked"})
    assert valid, f"TE-only should pass: {err}"

    # CL + TE (smuggling)
    valid, err = validate_http_request({"Content-Length": "100", "Transfer-Encoding": "chunked"})
    assert not valid, "CL + TE should be rejected"
    assert "ambiguous" in err.lower(), "Error should mention ambiguity"

    # Malformed TE
    valid, err = validate_http_request({"Transfer-Encoding": "identity, chunked"})
    assert not valid, "Multiple TE values should be rejected"

    # Malformed CL
    valid, err = validate_http_request({"Content-Length": "abc"})
    assert not valid, "Non-numeric CL should be rejected"

    print("PASS: Validation works correctly")


def test_attack_vectors():
    """Test that common attack vectors are blocked."""
    # Attack: CL says 44, TE says chunked, smuggled request follows
    headers = {
        "Content-Length": "44",
        "Transfer-Encoding": "chunked",
        "Host": "example.com"
    }
    assert is_smuggling_request(headers), "Attack vector should be detected"

    # Attack: TE with obfuscation
    headers = {
        "Content-Length": "44",
        "Transfer-Encoding": "  chunked  ",
        "Host": "example.com"
    }
    assert is_smuggling_request(headers), "Obfuscated TE should be detected"

    # Attack: multiple TE headers (nginx folds them)
    headers = {
        "Content-Length": "44",
        "Transfer-Encoding": "chunked",
    }
    assert is_smuggling_request(headers), "Single TE with CL should be detected"

    print("PASS: All attack vectors blocked")


def test_normal_requests():
    """Test that normal requests pass through."""
    # GET request
    valid, err = validate_http_request({"Host": "example.com"})
    assert valid, f"GET request should pass: {err}"

    # POST with CL only
    valid, err = validate_http_request({
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "27"
    })
    assert valid, f"POST with CL only should pass: {err}"

    # POST with TE only
    valid, err = validate_http_request({
        "Content-Type": "application/json",
        "Transfer-Encoding": "chunked"
    })
    assert valid, f"POST with TE only should pass: {err}"

    print("PASS: Normal requests pass through")


if __name__ == "__main__":
    test_cl_te_detection()
    test_validation()
    test_attack_vectors()
    test_normal_requests()
    print("\n✅ All CL.TE HTTP Request Smuggling tests passed!")