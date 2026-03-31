"""Shared vulnerability taxonomy helpers."""

from __future__ import annotations


# Maps CWE IDs to one or more vulnerability classes.  A CWE can belong to
# multiple classes (e.g. CWE-22 is pathtraversal but also sandboxescape when
# the traversal breaks an isolation boundary).
CWE_TO_VULN_CLASS: dict[str, list[str]] = {
    # pathtraversal
    "CWE-22": ["pathtraversal", "sandboxescape"],
    "CWE-23": ["pathtraversal"],
    "CWE-36": ["pathtraversal"],
    "CWE-59": ["pathtraversal", "sandboxescape"],
    # commandinjection
    "CWE-78": ["commandinjection"],
    "CWE-77": ["commandinjection"],
    "CWE-20": ["commandinjection", "codeexec"],
    "CWE-441": ["commandinjection"],
    "CWE-184": ["commandinjection"],
    "CWE-367": ["commandinjection"],
    "CWE-426": ["commandinjection"],
    # sqlinjection
    "CWE-89": ["sqlinjection"],
    # ssrf
    "CWE-918": ["ssrf"],
    # codeexec
    "CWE-94": ["codeexec"],
    "CWE-95": ["codeexec"],
    "CWE-96": ["codeexec"],
    "CWE-829": ["codeexec"],
    # authbypass
    "CWE-287": ["authbypass"],
    "CWE-289": ["authbypass"],
    "CWE-306": ["authbypass"],
    # brokenauthz
    "CWE-863": ["brokenauthz"],
    "CWE-862": ["brokenauthz"],
    "CWE-269": ["brokenauthz", "sandboxescape"],
    "CWE-285": ["brokenauthz"],
    "CWE-284": ["brokenauthz"],
    # secretdisclosure
    "CWE-200": ["secretdisclosure"],
    "CWE-522": ["secretdisclosure"],
    "CWE-116": ["secretdisclosure"],
    # csrf
    "CWE-352": ["csrf"],
    # sandboxescape
    "CWE-265": ["sandboxescape"],
    "CWE-693": ["sandboxescape"],
    # abuse
    "CWE-400": ["abuse"],
    # xss
    "CWE-79": ["xss"],
}
