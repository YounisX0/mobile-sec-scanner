from typing import Dict, List
from collections import Counter

from scanner.models import Finding


VALID_SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
    "informational": "Low",
}


SEVERITY_RISK_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}


SEVERITY_RISK_LEVELS = {
    "Critical": "Very High Risk",
    "High": "High Risk",
    "Medium": "Moderate Risk",
    "Low": "Low Risk",
}


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}


class SeverityEngine:
    """
    Normalizes and enriches security findings with severity scoring.

    Responsibilities:
    1. Validate severity names.
    2. Normalize severity values.
    3. Assign numeric risk scores.
    4. Assign readable risk levels.
    5. Sort findings by risk.
    6. Build a risk summary for the report.
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def process(self) -> List[Finding]:
        """
        Applies severity normalization and scoring to all findings.
        """
        processed_findings: List[Finding] = []

        for finding in self.findings:
            normalized_severity = self.normalize_severity(finding.severity)

            finding.severity = normalized_severity
            finding.risk_score = self.calculate_risk_score(finding)
            finding.risk_level = self.calculate_risk_level(finding)

            processed_findings.append(finding)

        return self.sort_by_risk(processed_findings)

    def normalize_severity(self, severity: str) -> str:
        """
        Converts any severity format into one of:
        Critical, High, Medium, Low.
        """
        if not severity:
            return "Low"

        cleaned = severity.strip().lower()

        return VALID_SEVERITIES.get(cleaned, "Low")

    def calculate_risk_score(self, finding: Finding) -> int:
        """
        Calculates numeric risk score.

        Base scores:
        Critical = 10
        High = 7
        Medium = 4
        Low = 1

        Small contextual adjustments are added for more realistic scoring.
        """
        base_score = SEVERITY_RISK_SCORES.get(finding.severity, 1)

        rule_id = finding.rule_id.upper()
        category = finding.category.lower()

        bonus = 0

        if "TOKEN" in rule_id or "PRIVATE_KEY" in rule_id:
            bonus += 1

        if "DEBUGGABLE" in rule_id:
            bonus += 1

        if "CLEARTEXT" in rule_id or "HTTP_URL" in rule_id:
            bonus += 1

        if category == "crypto" and ("ECB" in rule_id or "HARDCODED" in rule_id):
            bonus += 1

        final_score = base_score + bonus

        return min(final_score, 10)

    def calculate_risk_level(self, finding: Finding) -> str:
        """
        Converts numeric risk score into readable risk level.
        """
        score = finding.risk_score

        if score >= 9:
            return "Very High Risk"

        if score >= 7:
            return "High Risk"

        if score >= 4:
            return "Moderate Risk"

        return "Low Risk"

    def sort_by_risk(self, findings: List[Finding]) -> List[Finding]:
        """
        Sorts findings by:
        1. Highest risk score
        2. Severity order
        3. Category
        4. Rule ID
        """
        return sorted(
            findings,
            key=lambda finding: (
                -finding.risk_score,
                SEVERITY_ORDER.get(finding.severity, 99),
                finding.category,
                finding.rule_id,
            ),
        )

    def build_risk_summary(self) -> Dict[str, object]:
        """
        Builds an additional risk summary for the final report.
        """
        if not self.findings:
            return {
                "max_risk_score": 0,
                "average_risk_score": 0,
                "overall_risk_level": "No Risk Detected",
                "risk_level_counts": {},
            }

        risk_scores = [finding.risk_score for finding in self.findings]
        risk_level_counts = Counter(finding.risk_level for finding in self.findings)

        max_score = max(risk_scores)
        average_score = round(sum(risk_scores) / len(risk_scores), 2)

        return {
            "max_risk_score": max_score,
            "average_risk_score": average_score,
            "overall_risk_level": self.calculate_overall_risk_level(max_score),
            "risk_level_counts": dict(risk_level_counts),
        }

    def calculate_overall_risk_level(self, max_score: int) -> str:
        """
        Overall app risk is based on the highest detected risk.
        """
        if max_score >= 9:
            return "Very High Risk"

        if max_score >= 7:
            return "High Risk"

        if max_score >= 4:
            return "Moderate Risk"

        if max_score >= 1:
            return "Low Risk"

        return "No Risk Detected"