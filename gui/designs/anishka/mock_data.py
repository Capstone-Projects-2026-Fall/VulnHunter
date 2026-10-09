"""Mock data for basic demo gui - not a sample output"""
from dataclasses import dataclass


@dataclass
class Finding:
    id: str
    severity: str
    title: str
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
    Finding("VULN-001", "High", "Hardcoded API key", "Open"),
    Finding("VULN-002", "High", "Admin password is admin", "PR open"),
    Finding("VULN-003", "Medium", "Debug mode left on in production", "Merged"),
    Finding("VULN-004", "Low", "Mock Mock Mock", "Verified"),
]

SAMPLE_OUTPUT = [
    "# sample output, not a real scan",
    "$ /vulnhunt",
    "recon: mapping entry points",
    "hunt: tracing inputs to sinks",
    "verify: disproving candidates",
    "report: writing results",
]
