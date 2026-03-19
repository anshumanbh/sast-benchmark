"""Shared vulnerability taxonomy helpers."""

from __future__ import annotations


CWE_TO_VULN_CLASS: dict[str, str] = {
    "CWE-22": "pathtraversal",
    "CWE-23": "pathtraversal",
    "CWE-36": "pathtraversal",
    "CWE-78": "commandinjection",
    "CWE-77": "commandinjection",
    "CWE-20": "commandinjection",
    "CWE-441": "commandinjection",
    "CWE-184": "commandinjection",
    "CWE-918": "ssrf",
    "CWE-94": "codeexec",
    "CWE-95": "codeexec",
    "CWE-96": "codeexec",
    "CWE-287": "authbypass",
    "CWE-306": "authbypass",
    "CWE-863": "brokenauthz",
    "CWE-862": "brokenauthz",
    "CWE-269": "brokenauthz",
    "CWE-200": "secretdisclosure",
    "CWE-522": "secretdisclosure",
    "CWE-265": "sandboxescape",
    "CWE-693": "sandboxescape",
    "CWE-400": "abuse",
}
