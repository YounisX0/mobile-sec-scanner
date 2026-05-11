import re
from pathlib import Path
from typing import List, Dict, Pattern, Tuple, Optional

from scanner.models import Finding


TEXT_FILE_EXTENSIONS = {
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".html",
    ".js",
    ".css",
    ".yml",
    ".yaml",
    ".env",
    ".conf",
    ".config",
    ".cfg",
    ".ini",
}

MAX_TEXT_FILE_SIZE_BYTES = 2 * 1024 * 1024


IGNORED_DIRS = {
    "__pycache__",
    ".git",
    "build",
    "dist",
    "node_modules",
    "reports",
    "venv",
    ".gradle",
}


BENIGN_FILE_NAMES = {
    "license",
    "license.txt",
    "notice",
    "notice.txt",
    "readme",
    "readme.txt",
}


BENIGN_URL_PREFIXES = (
    "http://schemas.android.com/",
    "http://www.w3.org/",
    "http://xmlpull.org/",
    "http://www.apache.org/licenses/",
    "http://apache.org/licenses/",
    "http://creativecommons.org/",
    "http://opensource.org/",
    "http://www.slf4j.org/",
)


PLACEHOLDER_SECRET_VALUES = {
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "your_api_key",
    "your-token",
    "your_token",
    "changeme",
    "change_me",
    "example",
    "sample",
    "demo",
    "test",
    "null",
    "none",
    "true",
    "false",
}


SECRET_PATTERNS: List[Dict[str, object]] = [
    {
        "rule_id": "RESOURCE_GOOGLE_API_KEY",
        "title": "Possible Google API key found",
        "severity": "High",
        "category": "Secrets",
        "pattern": re.compile(r"AIza[0-9A-Za-z_\-]{20,45}"),
        "impact": "Hardcoded Google API keys may allow unauthorized access to Google services if restrictions are not properly configured.",
        "recommendation": "Move API keys to a secure backend or restrict the key by package name, SHA-1 certificate, API scope, and usage limits.",
        "mask": True,
    },
    {
        "rule_id": "RESOURCE_AWS_ACCESS_KEY",
        "title": "Possible AWS access key found",
        "severity": "Critical",
        "category": "Secrets",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "impact": "Hardcoded cloud access keys can allow unauthorized access to cloud resources.",
        "recommendation": "Remove the key from the application, rotate it immediately, and use backend-controlled credentials instead.",
        "mask": True,
    },
    {
        "rule_id": "RESOURCE_FIREBASE_URL",
        "title": "Firebase endpoint exposed",
        "severity": "Medium",
        "category": "Secrets",
        "pattern": re.compile(
            r"https?://[A-Za-z0-9\-_.]+(?:firebaseio\.com|firebaseapp\.com|firebasestorage\.googleapis\.com)[^\s\"'<>]*",
            re.IGNORECASE,
        ),
        "impact": "Exposed Firebase endpoints may reveal backend service usage and can become risky if database rules are weak.",
        "recommendation": "Ensure Firebase security rules are strict and avoid exposing sensitive endpoints unnecessarily.",
        "mask": False,
    },
    {
        "rule_id": "RESOURCE_BEARER_TOKEN",
        "title": "Bearer token found",
        "severity": "Critical",
        "category": "Secrets",
        "pattern": re.compile(r"Bearer\s+[A-Za-z0-9._\-~+/=]{15,}", re.IGNORECASE),
        "impact": "Hardcoded bearer tokens can allow direct unauthorized access to protected APIs.",
        "recommendation": "Remove hardcoded tokens immediately and rotate the exposed token from the provider dashboard.",
        "mask": True,
    },
    {
        "rule_id": "RESOURCE_JWT_TOKEN",
        "title": "JWT token found",
        "severity": "Critical",
        "category": "Secrets",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "impact": "Hardcoded JWT tokens may expose authenticated sessions or backend authorization data.",
        "recommendation": "Never store JWT tokens inside app resources. Generate tokens dynamically after authentication and rotate exposed credentials.",
        "mask": True,
    },
    {
        "rule_id": "RESOURCE_HARDCODED_SECRET_VALUE",
        "title": "Possible hardcoded secret value found",
        "severity": "High",
        "category": "Secrets",
        "pattern": re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|client[_\-]?secret|access[_\-]?token|auth[_\-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-@#$%^&*+.=/]{8,})"
        ),
        "impact": "Hardcoded secrets can be extracted from the APK and reused by attackers.",
        "recommendation": "Remove secrets from client-side files and store sensitive credentials on a secure backend service.",
        "mask": True,
        "value_group": 2,
    },
    {
        "rule_id": "RESOURCE_PRIVATE_KEY",
        "title": "Private key block found",
        "severity": "Critical",
        "category": "Secrets",
        "pattern": re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
        "impact": "Private keys embedded in an APK can be extracted and used to impersonate services or decrypt sensitive data.",
        "recommendation": "Remove private keys from the mobile application and rotate the affected key pair immediately.",
        "mask": False,
    },
    {
        "rule_id": "RESOURCE_HTTP_URL",
        "title": "Insecure HTTP URL found",
        "severity": "Medium",
        "category": "Network",
        "pattern": re.compile(r"http://[^\s\"'<>]+", re.IGNORECASE),
        "impact": "HTTP URLs may transmit data without encryption, making traffic vulnerable to interception or modification.",
        "recommendation": "Replace HTTP endpoints with HTTPS and enforce secure transport configuration.",
        "mask": False,
    },
]


def is_text_file(file_path: Path) -> bool:
    return file_path.suffix.lower() in TEXT_FILE_EXTENSIONS


def should_skip_file(file_path: Path) -> bool:
    if any(part in IGNORED_DIRS for part in file_path.parts):
        return True

    if file_path.name.lower() in BENIGN_FILE_NAMES:
        return True

    try:
        if file_path.stat().st_size > MAX_TEXT_FILE_SIZE_BYTES:
            return True
    except OSError:
        return True

    return False


def read_text_safely(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def get_line_number(content: str, position: int) -> int:
    return content.count("\n", 0, position) + 1


def mask_sensitive_value(value: str) -> str:
    value = value.strip()

    if len(value) <= 10:
        return "***"

    return f"{value[:6]}...{value[-4:]}"


def extract_secret_value(match, value_group: Optional[int]) -> str:
    if value_group is None:
        return match.group(0)

    try:
        return match.group(value_group)
    except IndexError:
        return match.group(0)


def is_placeholder_secret(value: str) -> bool:
    cleaned = value.strip().strip("\"'").lower()

    if cleaned in PLACEHOLDER_SECRET_VALUES:
        return True

    if cleaned.startswith("your_") or cleaned.startswith("your-"):
        return True

    if len(set(cleaned)) <= 2 and len(cleaned) > 8:
        return True

    return False


def build_evidence(match_text: str, should_mask: bool, line_number: int) -> str:
    clean_text = match_text.strip().replace("\n", " ")

    if should_mask:
        clean_text = mask_sensitive_value(clean_text)

    if len(clean_text) > 140:
        clean_text = clean_text[:140] + "..."

    return f"Line {line_number}: {clean_text}"


def is_benign_url(match_text: str) -> bool:
    clean_text = match_text.strip().lower()

    return any(
        clean_text.startswith(prefix.lower())
        for prefix in BENIGN_URL_PREFIXES
    )


def scan_resources(extracted_app_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen_findings = set()

    candidate_files = [
        file_path
        for file_path in extracted_app_path.rglob("*")
        if file_path.is_file()
        and is_text_file(file_path)
        and not should_skip_file(file_path)
    ]

    for file_path in candidate_files:
        content = read_text_safely(file_path)

        if not content:
            continue

        for rule in SECRET_PATTERNS:
            pattern: Pattern[str] = rule["pattern"]  # type: ignore
            value_group = rule.get("value_group")

            for match in pattern.finditer(content):
                match_text = match.group(0)

                if str(rule["rule_id"]) == "RESOURCE_HTTP_URL" and is_benign_url(match_text):
                    continue

                secret_value = extract_secret_value(
                    match=match,
                    value_group=value_group if isinstance(value_group, int) else None,
                )

                if str(rule["rule_id"]) == "RESOURCE_HARDCODED_SECRET_VALUE":
                    if is_placeholder_secret(secret_value):
                        continue

                line_number = get_line_number(content, match.start())

                evidence = build_evidence(
                    match_text=match_text,
                    should_mask=bool(rule["mask"]),
                    line_number=line_number,
                )

                duplicate_key: Tuple[str, str, str] = (
                    str(rule["rule_id"]),
                    str(file_path),
                    evidence,
                )

                if duplicate_key in seen_findings:
                    continue

                seen_findings.add(duplicate_key)

                findings.append(
                    Finding(
                        rule_id=str(rule["rule_id"]),
                        title=str(rule["title"]),
                        severity=str(rule["severity"]),
                        file_path=str(file_path),
                        evidence=evidence,
                        impact=str(rule["impact"]),
                        recommendation=str(rule["recommendation"]),
                        category=str(rule["category"]),
                    )
                )

    return findings