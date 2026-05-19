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
    # CWE-20 (Improper Input Validation) is intentionally broad: existing
    # OpenClaw/Ghost cases use it for injection/codeexec, while the new
    # Cosmos cases use it for chain-halt-from-malformed-input (abuse) and
    # for incorrect signer-set/vote validation (brokenauthz).
    "CWE-20": ["commandinjection", "codeexec", "abuse", "brokenauthz"],
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
    # Improper handling of exceptional conditions — used by GHSA-47ww-ff84-4jrg
    # (x/group EndBlocker panic that halts the chain) and similar DoS-from-
    # unhandled-error advisories. A scanner reporting CWE-755 on a chain-halt
    # bug should count as detecting the abuse class.
    "CWE-755": ["abuse"],
    # Specific abuse-class CWEs used by the Cosmos advisories. Each is a
    # more precise classification than the umbrella CWE-400, and a scanner
    # reporting only the specific advisory CWE should still satisfy the
    # abuse class match.
    "CWE-129": ["abuse"],   # Improper validation of array index (panic-on-bad-index)
    "CWE-190": ["abuse"],   # Integer overflow (DoS via overflow)
    "CWE-345": ["abuse"],   # Insufficient verification of data authenticity (BFT time inconsistency)
    "CWE-369": ["abuse"],   # Divide by zero (panic)
    "CWE-502": ["abuse"],   # Deserialization of untrusted data (non-deterministic unmarshal → halt)
    "CWE-674": ["abuse"],   # Uncontrolled recursion (stack overflow)
    # Specific brokenauthz-class CWEs used by the Cosmos advisories.
    "CWE-696": ["brokenauthz"],  # Incorrect behavior order (callback ordering / reentrancy window)
    "CWE-841": ["brokenauthz"],  # Improper enforcement of behavioral workflow (state transition skip)
    # xss
    "CWE-79": ["xss"],
}
