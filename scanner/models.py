from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file_path: str
    evidence: str
    impact: str
    recommendation: str
    category: str = "General"
    risk_score: int = 0
    risk_level: str = "Unrated"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)