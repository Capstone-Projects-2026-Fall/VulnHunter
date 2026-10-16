"""Mock data for basic demo gui - not a sample output"""
from dataclasses import dataclass


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    location: str
    status: str


@dataclass
class ScanRecord:
    repo: str
    model: str
    mode: str
    date: str
    findings: list
    output: list


# MOCK DATA
SAMPLE_FINDINGS = [
    Finding("VULN-001", "High", "Hardcoded API key", "src/config/settings.py:12", "Open"),
    Finding("VULN-002", "High", "Admin password is admin", "src/auth/login.py:58", "PR open"),
    Finding("VULN-003", "Medium", "Debug mode left on in production", "src/server/app.py:31", "Merged"),
    Finding("VULN-004", "Low", "Mock Mock Mock", "src/utils/mock.py:7", "Verified"),
]

SAMPLE_OUTPUT = [
    "# sample output, not a real scan",
    "recon: mapping entry points",
    "hunt: tracing inputs to sinks",
    "disprove: testing candidates against counterexamples",
    "report: writing results",
]
