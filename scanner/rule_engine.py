from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from collections import Counter

from scanner.models import Finding
from scanner.manifest_parser import scan_manifest
from scanner.resource_scanner import scan_resources
from scanner.code_scanner import scan_code
from scanner.severity_engine import SeverityEngine


ScannerFunction = Callable[[Path], List[Finding]]
ProgressCallback = Optional[Callable[[str], None]]


class RuleEngine:
    """
    Central engine that runs all scanner modules and returns final findings.

    Responsibilities:
    1. Run manifest scanner.
    2. Run resource/secret scanner.
    3. Run code scanner.
    4. Handle scanner errors safely.
    5. Remove duplicated findings.
    6. Send findings to severity engine.
    7. Return final sorted findings.
    8. Build scanner execution statistics.
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
        self.risk_summary: Dict[str, object] = {}

    def run(self, progress_callback: ProgressCallback = None) -> List[Finding]:
        """
        Runs all scanner modules and returns cleaned, scored, and sorted findings.
        """
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

        severity_engine = SeverityEngine(cleaned_findings)
        processed_findings = severity_engine.process()

        self.findings = processed_findings
        self.risk_summary = severity_engine.build_risk_summary()

        return self.findings

    def remove_duplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Removes exact duplicate findings.
        """
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

    def get_scanner_counts(self) -> Dict[str, int]:
        """
        Returns how many findings each scanner module produced.
        """
        return self.scanner_counts

    def get_risk_summary(self) -> Dict[str, object]:
        """
        Returns calculated risk summary.
        """
        return self.risk_summary

    def build_summary(self) -> Dict[str, object]:
        """
        Builds a summary from the final scored findings.
        """
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
            "risk_summary": self.risk_summary,
        }