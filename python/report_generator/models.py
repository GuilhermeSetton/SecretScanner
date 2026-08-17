from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class ScanSummary:
    files_scanned: int
    findings: int
    errors: int
    critical: int
    high: int
    medium: int
    low: int
    duration_ms: int
    scanner_version: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    severity: str
    confidence: str
    file: str
    line: int
    column: int
    field_path: str
    match: str
    resource: Optional[str] = None
    kind: Optional[str] = None


@dataclass(frozen=True)
class ScanError:
    file: str
    message: str


@dataclass(frozen=True)
class ScanReport:
    schema_version: str
    summary: ScanSummary
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
