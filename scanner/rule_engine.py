from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from collections import Counter

from scanner.models import Finding
from scanner.manifest_parser import scan_manifest
from scanner.resource_scanner import scan_resources
from scanner.code_scanner import scan_code


ScannerFunction = Callable[[Path], List[Finding]]
ProgressCallback = Optional[Callable[[str], None]]


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}


class RuleEngine:
    """
    Central engine that runs all scanner modules and returns final findings.
    """

    def __init__(self, extracted_app_path: Path):
        self.extracted_app_path = extracted_app_path

        self.scanners: List[Tuple[str, ScannerFunction]] = [
            ("Manifest Scanner", scan_manifest),
            ("Resource and Secret Scanner", scan_resources),
            ("Code Scanner", scan_code),
        ]

        self.scanner_counts: Dict[str, int] = {}
        self.findings: List[Finding] = []

    def run(self, progress_callback: ProgressCallback = None) -> List[Finding]:
        all_findings: List[Finding] = []

        for scanner_name, scanner_function in self.scanners:
            if progress_callback:
                progress_callback(f"Running {scanner_name}...")

            try:
                scanner_findings = scanner_function(self.extracted_app_path)
                self.scanner_counts[scanner_name] = len(scanner_findings)
                all_findings.extend(scanner_findings)

            except Exception as error:
                self.scanner_counts[scanner_name] = 1

                all_findings.append(
                    Finding(
                        rule_id="SCANNER_EXECUTION_ERROR",
                        title=f"{scanner_name} failed",
                        severity="High",
                        file_path=str(self.extracted_app_path),
                        evidence=str(error),
                        impact="One scanner module failed, so some security checks may not have been completed.",
                        recommendation="Review the scanner error and verify that the extracted APK folder has the expected structure.",
                        category="Engine",
                    )
                )

        cleaned_findings = self.remove_duplicate_findings(all_findings)
        sorted_findings = self.sort_findings(cleaned_findings)

        self.findings = sorted_findings
        return self.findings

    def remove_duplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        unique_findings: List[Finding] = []
        seen_keys = set()

        for finding in findings:
            duplicate_key = (
                finding.rule_id,
                finding.file_path,
                finding.evidence,
            )

            if duplicate_key in seen_keys:
                continue

            seen_keys.add(duplicate_key)
            unique_findings.append(finding)

        return unique_findings

    def sort_findings(self, findings: List[Finding]) -> List[Finding]:
        return sorted(
            findings,
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity, 99),
                finding.category,
                finding.rule_id,
            ),
        )

    def get_scanner_counts(self) -> Dict[str, int]:
        return self.scanner_counts

    def build_summary(self) -> Dict[str, object]:
        severity_counts = Counter(finding.severity for finding in self.findings)
        category_counts = Counter(finding.category for finding in self.findings)

        return {
            "total_findings": len(self.findings),
            "severity_counts": {
                "Critical": severity_counts.get("Critical", 0),
                "High": severity_counts.get("High", 0),
                "Medium": severity_counts.get("Medium", 0),
                "Low": severity_counts.get("Low", 0),
            },
            "category_counts": dict(category_counts),
            "scanner_counts": self.scanner_counts,
        }