"""
OBSERVER — OWASP Top 10 Detectors Registry
"""
from scanner.owasp.a01_access_control import AccessControlDetector
from scanner.owasp.a02_crypto import CryptoDetector
from scanner.owasp.a03_injection import InjectionDetector
from scanner.owasp.a04_insecure_design import InsecureDesignDetector
from scanner.owasp.a05_misconfig import SecurityMisconfigDetector
from scanner.owasp.a06_vulnerable_components import VulnerableComponentsDetector
from scanner.owasp.a07_auth_failures import AuthFailuresDetector
from scanner.owasp.a08_integrity import IntegrityFailuresDetector
from scanner.owasp.a09_logging import LoggingFailuresDetector
from scanner.owasp.a10_ssrf import SSRFDetector

DETECTOR_REGISTRY = {
    "A01": AccessControlDetector,
    "A02": CryptoDetector,
    "A03": InjectionDetector,
    "A04": InsecureDesignDetector,
    "A05": SecurityMisconfigDetector,
    "A06": VulnerableComponentsDetector,
    "A07": AuthFailuresDetector,
    "A08": IntegrityFailuresDetector,
    "A09": LoggingFailuresDetector,
    "A10": SSRFDetector,
}
