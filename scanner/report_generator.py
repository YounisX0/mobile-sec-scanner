import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from html import escape

from jinja2 import Template

from scanner.models import Finding


def safe_app_name(extracted_app_path: Path) -> str:
    """
    Creates a safe app name based on the extracted folder name.
    """
    return extracted_app_path.name.replace(" ", "_")


def generate_report_files(
    extracted_app_path: Path,
    findings: List[Finding],
    summary: Dict[str, object],
    output_dir: Path = Path("reports"),
) -> Tuple[Path, Path]:
    """
    Generates both JSON and HTML reports.

    Returns:
        Tuple containing:
        - JSON report path
        - HTML report path
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    app_name = safe_app_name(extracted_app_path)
    scan_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    json_report_path = output_dir / f"{app_name}_security_report_{scan_timestamp}.json"
    html_report_path = output_dir / f"{app_name}_security_report_{scan_timestamp}.html"

    report_data = build_report_data(
        extracted_app_path=extracted_app_path,
        findings=findings,
        summary=summary,
        scan_timestamp=scan_timestamp,
    )

    write_json_report(json_report_path, report_data)
    write_html_report(html_report_path, report_data)

    return json_report_path, html_report_path


def build_report_data(
    extracted_app_path: Path,
    findings: List[Finding],
    summary: Dict[str, object],
    scan_timestamp: str,
) -> Dict[str, object]:
    """
    Builds the final report data object used by JSON and HTML reports.
    """
    return {
        "tool_name": "APKLab Security Scanner",
        "scan_timestamp": scan_timestamp,
        "app": {
            "name": extracted_app_path.name,
            "path": str(extracted_app_path),
        },
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json_report(report_path: Path, report_data: Dict[str, object]) -> None:
    """
    Writes the JSON report.
    """
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4, ensure_ascii=False)


def severity_badge_class(severity: str) -> str:
    severity = str(severity).lower()

    if severity == "critical":
        return "critical"

    if severity == "high":
        return "high"

    if severity == "medium":
        return "medium"

    if severity == "low":
        return "low"

    return "info"


def risk_badge_class(risk_level: str) -> str:
    risk_level = str(risk_level).lower()

    if "very high" in risk_level:
        return "risk-very-high"

    if "high" in risk_level:
        return "risk-high"

    if "moderate" in risk_level:
        return "risk-moderate"

    if "low" in risk_level:
        return "risk-low"

    return "risk-info"


def write_html_report(report_path: Path, report_data: Dict[str, object]) -> None:
    """
    Writes the HTML report using a Jinja2 template.
    """
    template = Template(HTML_TEMPLATE)

    app = report_data.get("app", {})
    findings = report_data.get("findings", [])
    summary = report_data.get("summary", {})

    if not isinstance(summary, dict):
        summary = {}

    severity_counts = summary.get("severity_counts", {})
    category_counts = summary.get("category_counts", {})
    scanner_counts = summary.get("scanner_counts", {})
    risk_summary = summary.get("risk_summary", {})

    if not isinstance(severity_counts, dict):
        severity_counts = {}

    if not isinstance(category_counts, dict):
        category_counts = {}

    if not isinstance(scanner_counts, dict):
        scanner_counts = {}

    if not isinstance(risk_summary, dict):
        risk_summary = {}

    rendered_html = template.render(
        tool_name=str(report_data.get("tool_name", "APKLab Security Scanner")),
        scan_timestamp=str(report_data.get("scan_timestamp", "")),
        app=app,
        findings=findings,
        total_findings=summary.get("total_findings", 0),
        severity_counts=severity_counts,
        category_counts=category_counts,
        scanner_counts=scanner_counts,
        risk_summary=risk_summary,
        severity_badge_class=severity_badge_class,
        risk_badge_class=risk_badge_class,
        escape=escape,
    )

    with report_path.open("w", encoding="utf-8") as file:
        file.write(rendered_html)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ escape(tool_name) }} Report</title>

    <style>
        :root {
            --bg-main: #020617;
            --bg-card: #0f172a;
            --bg-card-2: #111827;
            --bg-soft: #1e293b;
            --border: #334155;
            --border-soft: #475569;
            --text-main: #e5e7eb;
            --text-muted: #94a3b8;
            --cyan: #38bdf8;
            --blue: #60a5fa;
            --green: #22c55e;
            --yellow: #facc15;
            --orange: #f97316;
            --red: #ef4444;
            --purple: #c084fc;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, Helvetica, sans-serif;
            background: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }

        .container {
            width: min(1500px, 94%);
            margin: 28px auto;
        }

        .header {
            background:
                radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 34%),
                linear-gradient(135deg, #111827, #020617);
            padding: 28px;
            border-radius: 20px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            gap: 20px;
            align-items: flex-start;
            flex-wrap: wrap;
        }

        .header h1 {
            margin: 0;
            font-size: 34px;
            color: var(--cyan);
            letter-spacing: -0.5px;
        }

        .header p {
            margin: 8px 0 0 0;
            color: #cbd5e1;
        }

        .meta-box {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            padding: 14px 16px;
            border-radius: 14px;
            min-width: 280px;
        }

        .meta-box div {
            margin-bottom: 6px;
            color: var(--text-muted);
            font-size: 13px;
        }

        .meta-box strong {
            color: var(--text-main);
        }

        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px;
            margin-bottom: 24px;
        }

        .section h2 {
            margin: 0 0 16px 0;
            color: var(--cyan);
            font-size: 22px;
        }

        .section-description {
            margin-top: -8px;
            margin-bottom: 18px;
            color: var(--text-muted);
            font-size: 14px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--bg-card-2);
            border: 1px solid var(--border);
            padding: 18px;
            border-radius: 16px;
            min-height: 116px;
        }

        .card h3 {
            margin: 0;
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card .number {
            font-size: 34px;
            font-weight: bold;
            margin-top: 10px;
        }

        .card .label {
            color: var(--text-muted);
            margin-top: 6px;
            font-size: 13px;
        }

        .critical-text { color: var(--red); }
        .high-text { color: var(--orange); }
        .medium-text { color: var(--yellow); }
        .low-text { color: var(--green); }
        .cyan-text { color: var(--cyan); }
        .purple-text { color: var(--purple); }

        .small-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            overflow: hidden;
            border-radius: 12px;
        }

        .small-table th {
            background: var(--bg-soft);
            color: #f8fafc;
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }

        .small-table td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
            color: #dbeafe;
        }

        .small-table tr:last-child td {
            border-bottom: none;
        }

        .three-columns {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
        }

        .badge {
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
            white-space: nowrap;
        }

        .critical {
            background: #7f1d1d;
            color: #fecaca;
        }

        .high {
            background: #7c2d12;
            color: #fed7aa;
        }

        .medium {
            background: #713f12;
            color: #fef3c7;
        }

        .low {
            background: #14532d;
            color: #bbf7d0;
        }

        .info {
            background: #1e3a8a;
            color: #bfdbfe;
        }

        .risk-very-high {
            background: #7f1d1d;
            color: #fecaca;
        }

        .risk-high {
            background: #7c2d12;
            color: #fed7aa;
        }

        .risk-moderate {
            background: #713f12;
            color: #fef3c7;
        }

        .risk-low {
            background: #14532d;
            color: #bbf7d0;
        }

        .risk-info {
            background: #1e3a8a;
            color: #bfdbfe;
        }

        .finding-card {
            background: #020617;
            border: 1px solid var(--border);
            border-radius: 18px;
            margin-bottom: 18px;
            overflow: hidden;
        }

        .finding-header {
            padding: 16px 18px;
            background: linear-gradient(135deg, #111827, #0f172a);
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: flex-start;
            flex-wrap: wrap;
        }

        .finding-title {
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }

        .finding-index {
            width: 34px;
            height: 34px;
            border-radius: 10px;
            background: #1e293b;
            color: var(--cyan);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            flex: 0 0 auto;
        }

        .finding-title h3 {
            margin: 0;
            font-size: 17px;
            color: #f8fafc;
        }

        .finding-title p {
            margin: 5px 0 0 0;
            color: var(--text-muted);
            font-size: 13px;
        }

        .finding-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
            justify-content: flex-end;
        }

        .score-box {
            background: #0f172a;
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 5px 10px;
            font-size: 12px;
            color: #bfdbfe;
            font-weight: bold;
        }

        .finding-body {
            padding: 18px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }

        .field {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 14px;
            padding: 14px;
        }

        .field.full {
            grid-column: 1 / -1;
        }

        .field-label {
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            font-weight: bold;
        }

        .field-value {
            color: #e2e8f0;
            word-break: break-word;
            font-size: 14px;
        }

        .evidence {
            font-family: Consolas, Monaco, monospace;
            background: #020617;
            padding: 10px;
            border-radius: 10px;
            border: 1px solid #1e293b;
            color: #e2e8f0;
            word-break: break-word;
            white-space: pre-wrap;
        }

        .empty-state {
            padding: 28px;
            text-align: center;
            color: var(--text-muted);
            border: 1px dashed var(--border);
            border-radius: 16px;
        }

        .footer {
            text-align: center;
            color: #64748b;
            margin: 32px 0;
            font-size: 13px;
        }

        @media (max-width: 1100px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .three-columns {
                grid-template-columns: 1fr;
            }

            .finding-body {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 700px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 26px;
            }

            .container {
                width: 96%;
            }
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .header, .section, .card, .finding-card, .field, .meta-box {
                background: white !important;
                color: black !important;
                border: 1px solid #ccc;
            }

            .header h1, .section h2 {
                color: black;
            }

            .field-value, .small-table td {
                color: black;
            }

            .evidence {
                background: #f3f4f6;
                color: black;
                border: 1px solid #ccc;
            }
        }
    </style>
</head>

<body>
    <div class="container">

        <div class="header">
            <div class="header-top">
                <div>
                    <h1>{{ escape(tool_name) }}</h1>
                    <p>Android Static Security Analysis Report</p>
                </div>

                <div class="meta-box">
                    <div><strong>App:</strong> {{ escape(app.name) }}</div>
                    <div><strong>Path:</strong> {{ escape(app.path) }}</div>
                    <div><strong>Scan Time:</strong> {{ escape(scan_timestamp) }}</div>
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="number cyan-text">{{ total_findings }}</div>
                <div class="label">Detected security issues</div>
            </div>

            <div class="card">
                <h3>Overall Risk Level</h3>
                <div class="number purple-text" style="font-size: 24px;">
                    {{ escape(risk_summary.get("overall_risk_level", "Unknown")) }}
                </div>
                <div class="label">Based on highest detected risk</div>
            </div>

            <div class="card">
                <h3>Max Risk Score</h3>
                <div class="number critical-text">
                    {{ risk_summary.get("max_risk_score", 0) }}
                </div>
                <div class="label">Maximum score is 10</div>
            </div>

            <div class="card">
                <h3>Average Risk Score</h3>
                <div class="number high-text">
                    {{ risk_summary.get("average_risk_score", 0) }}
                </div>
                <div class="label">Average across all findings</div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="card">
                <h3>Critical</h3>
                <div class="number critical-text">{{ severity_counts.get("Critical", 0) }}</div>
                <div class="label">Immediate attention required</div>
            </div>

            <div class="card">
                <h3>High</h3>
                <div class="number high-text">{{ severity_counts.get("High", 0) }}</div>
                <div class="label">High-priority security issues</div>
            </div>

            <div class="card">
                <h3>Medium</h3>
                <div class="number medium-text">{{ severity_counts.get("Medium", 0) }}</div>
                <div class="label">Moderate risk findings</div>
            </div>

            <div class="card">
                <h3>Low</h3>
                <div class="number low-text">{{ severity_counts.get("Low", 0) }}</div>
                <div class="label">Low-priority findings</div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p class="section-description">
                This section summarizes the scan result, risk distribution, scanner module output, and finding categories.
            </p>

            <div class="three-columns">
                <div>
                    <h3>Scanner Module Results</h3>
                    <table class="small-table">
                        <thead>
                            <tr>
                                <th>Scanner Module</th>
                                <th>Findings</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for scanner_name, count in scanner_counts.items() %}
                            <tr>
                                <td>{{ escape(scanner_name) }}</td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div>
                    <h3>Findings by Category</h3>
                    <table class="small-table">
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Findings</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for category, count in category_counts.items() %}
                            <tr>
                                <td>{{ escape(category) }}</td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div>
                    <h3>Findings by Risk Level</h3>
                    <table class="small-table">
                        <thead>
                            <tr>
                                <th>Risk Level</th>
                                <th>Findings</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for risk_level, count in risk_summary.get("risk_level_counts", {}).items() %}
                            <tr>
                                <td>
                                    <span class="badge {{ risk_badge_class(risk_level) }}">
                                        {{ escape(risk_level) }}
                                    </span>
                                </td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>
            <p class="section-description">
                Each finding includes severity, risk score, affected file, evidence, impact, and recommended mitigation.
            </p>

            {% if findings|length == 0 %}
                <div class="empty-state">
                    No security findings were detected.
                </div>
            {% endif %}

            {% for finding in findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title">
                        <div class="finding-index">{{ loop.index }}</div>

                        <div>
                            <h3>{{ escape(finding.title) }}</h3>
                            <p>
                                Rule ID:
                                <strong>{{ escape(finding.rule_id) }}</strong>
                                |
                                Category:
                                <strong>{{ escape(finding.category) }}</strong>
                            </p>
                        </div>
                    </div>

                    <div class="finding-badges">
                        <span class="badge {{ severity_badge_class(finding.severity) }}">
                            {{ escape(finding.severity) }}
                        </span>

                        <span class="badge {{ risk_badge_class(finding.risk_level) }}">
                            {{ escape(finding.risk_level) }}
                        </span>

                        <span class="score-box">
                            Score: {{ finding.risk_score }}/10
                        </span>
                    </div>
                </div>

                <div class="finding-body">
                    <div class="field full">
                        <div class="field-label">Affected File</div>
                        <div class="field-value">{{ escape(finding.file_path) }}</div>
                    </div>

                    <div class="field full">
                        <div class="field-label">Evidence</div>
                        <div class="evidence">{{ escape(finding.evidence) }}</div>
                    </div>

                    <div class="field">
                        <div class="field-label">Security Impact</div>
                        <div class="field-value">{{ escape(finding.impact) }}</div>
                    </div>

                    <div class="field">
                        <div class="field-label">Recommended Mitigation</div>
                        <div class="field-value">{{ escape(finding.recommendation) }}</div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            Generated by APKLab Security Scanner
        </div>

    </div>
</body>
</html>
"""