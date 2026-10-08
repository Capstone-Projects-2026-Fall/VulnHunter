# Mock Data for the dashboard.py file in the gui folder

from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    id: str
    severity: str
    title: str
    file_path: str
    line: int
    status: str          # Open, In Progress, Verified
    exploit_path: str

@dataclass
class ScanRecord:
    repo: str
    model: str
    mode: str
    date: str
    findings: List[Finding] = field(default_factory=list)
    output: List[str] = field(default_factory=list)

# Dashboard summary metrics (Pi-hole style stat cards)
DASHBOARD_STATS = {
    "repos_scanned": 14,
    "total_findings": 42,
    "verified_fixes": 38,
    "falsified_flaws": 119  # Blocked by the Falsification Engine
}

SAMPLE_FINDINGS = [
    Finding(
        id="VH-2026-001",
        severity="Critical",
        title="Remote Code Execution via deserialization sink",
        file_path="src/api/handler.py",
        line=142,
        status="Open",
        exploit_path="Entry: POST /api/v1/load -> Pickle load"
    ),
    Finding(
        id="VH-2026-002",
        severity="High",
        title="SQL Injection across unescaped search parameter",
        file_path="src/db/queries.py",
        line=87,
        status="Verified",
        exploit_path="Entry: GET /search?q= -> Raw SQL format string"
    ),
    Finding(
        id="VH-2026-003",
        severity="Medium",
        title="Path Traversal in static file loader",
        file_path="src/server/static.py",
        line=45,
        status="Open",
        exploit_path="Entry: GET /files?path= -> os.path.join traversal"
    ),
]

SAMPLE_OUTPUT = [
    "[*] Initializing VulnHunter agent framework...",
    "[*] Target repository loaded: sample-web-app",
    "[*] Phase 1: Recon & entry point mapping...",
    "[*] Phase 2: Parallel Hunt initiated across sinks...",
    "[!] Potential defect flagged at src/api/handler.py:142",
    "[*] Phase 3: Adversarial Disprove engine active...",
    "[+] Exploit path confirmed viable. Finding: VH-2026-001",
    "[*] Scan cycle complete. Emitted actionable findings."
]

# Preset target repositories for the dashboard dropdown
SAMPLE_REPOS = [
    "sample-web-app",
    "payment-service",
    "user-auth-api",
    "inventory-system",
    "local-test-repo"
]