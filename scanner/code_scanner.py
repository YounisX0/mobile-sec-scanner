import re
from pathlib import Path
from typing import List, Dict, Pattern, Tuple

from scanner.models import Finding


CODE_FILE_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".smali",
    ".xml",
    ".js",
}


CODE_PATTERNS: List[Dict[str, object]] = [
    {
        "rule_id": "CODE_WEAK_HASH_MD5",
        "title": "Weak hash algorithm MD5 used",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(r"(?i)(MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']|getInstance\s*\(\s*[\"']MD5[\"']|MD5)"),
        "impact": "MD5 is cryptographically weak and should not be used for password hashing, integrity protection, or security-sensitive operations.",
        "recommendation": "Use stronger algorithms such as SHA-256 for hashing, or use password hashing algorithms like bcrypt, scrypt, or Argon2 for passwords.",
    },
    {
        "rule_id": "CODE_WEAK_HASH_SHA1",
        "title": "Weak hash algorithm SHA-1 used",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(r"(?i)(MessageDigest\.getInstance\s*\(\s*[\"']SHA-1[\"']|getInstance\s*\(\s*[\"']SHA1[\"']|SHA-1|SHA1)"),
        "impact": "SHA-1 is considered weak for collision resistance and should not be used in security-sensitive contexts.",
        "recommendation": "Use SHA-256 or stronger hashing algorithms where hashing is required.",
    },
    {
        "rule_id": "CODE_AES_ECB_MODE",
        "title": "AES ECB mode used",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(r"(?i)(AES/ECB|Cipher\.getInstance\s*\(\s*[\"']AES/ECB)"),
        "impact": "ECB mode does not provide semantic security and can reveal patterns in encrypted data.",
        "recommendation": "Use AES-GCM or AES-CBC with a random IV and proper authentication. Prefer AES-GCM where possible.",
    },
    {
        "rule_id": "CODE_DES_USAGE",
        "title": "DES or 3DES encryption used",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(r"(?i)(DESede|TripleDES|Cipher\.getInstance\s*\(\s*[\"']DES|Cipher\.getInstance\s*\(\s*[\"']DESede)"),
        "impact": "DES is obsolete and 3DES is deprecated for modern security requirements.",
        "recommendation": "Replace DES/3DES with modern authenticated encryption such as AES-GCM.",
    },
    {
        "rule_id": "CODE_HARDCODED_CRYPTO_KEY",
        "title": "Possible hardcoded cryptographic key",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(
            r"(?i)(secretkey|crypto_key|encryption_key|aes_key|private_key|key)\s*[:=]\s*[\"'][A-Za-z0-9_\-+/=]{8,}[\"']"
        ),
        "impact": "Hardcoded cryptographic keys can be extracted from the APK and used to decrypt protected data or impersonate services.",
        "recommendation": "Do not store cryptographic keys in client-side code. Use Android Keystore or backend-managed key material.",
    },
    {
        "rule_id": "CODE_HARDCODED_IV",
        "title": "Possible hardcoded initialization vector",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(
            r"(?i)(iv|initializationVector)\s*[:=]\s*[\"'][A-Za-z0-9_\-+/=]{8,}[\"']"
        ),
        "impact": "A fixed IV can weaken encryption and may allow attackers to detect repeated encrypted values.",
        "recommendation": "Generate a new random IV for every encryption operation and store it safely with the ciphertext.",
    },
    {
        "rule_id": "CODE_WEBVIEW_JAVASCRIPT_ENABLED",
        "title": "WebView JavaScript enabled",
        "severity": "Medium",
        "category": "WebView",
        "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "Enabling JavaScript in WebView can increase attack surface, especially if untrusted content is loaded.",
        "recommendation": "Enable JavaScript only when required and avoid loading untrusted content in WebView.",
    },
    {
        "rule_id": "CODE_WEBVIEW_FILE_ACCESS_ENABLED",
        "title": "WebView file access enabled",
        "severity": "High",
        "category": "WebView",
        "pattern": re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "File access in WebView may allow local file exposure or abuse when combined with unsafe content loading.",
        "recommendation": "Disable file access unless strictly required by setting setAllowFileAccess(false).",
    },
    {
        "rule_id": "CODE_WEBVIEW_UNIVERSAL_FILE_ACCESS",
        "title": "WebView universal access from file URLs enabled",
        "severity": "High",
        "category": "WebView",
        "pattern": re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "Universal access from file URLs can allow local files to access remote origins, increasing the risk of data exposure.",
        "recommendation": "Keep universal access from file URLs disabled unless there is a strong and controlled reason.",
    },
    {
        "rule_id": "CODE_SENSITIVE_LOGGING",
        "title": "Possible sensitive data logging",
        "severity": "Medium",
        "category": "Logging",
        "pattern": re.compile(
            r"(?i)(Log\.(d|e|i|v|w)\s*\([^;]*(password|token|secret|apikey|api_key|authorization|bearer)[^;]*\))"
        ),
        "impact": "Sensitive data written to logs may be exposed through logcat, debugging tools, or compromised devices.",
        "recommendation": "Remove sensitive values from logs and avoid logging authentication data or secrets.",
    },
    {
        "rule_id": "CODE_INSECURE_RANDOM",
        "title": "Insecure random generator used",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(r"new\s+Random\s*\(", re.IGNORECASE),
        "impact": "java.util.Random is not suitable for security-sensitive randomness such as tokens, keys, or IVs.",
        "recommendation": "Use SecureRandom for security-sensitive random values.",
    },
]


def is_code_file(file_path: Path) -> bool:
    return file_path.suffix.lower() in CODE_FILE_EXTENSIONS


def should_skip_file(file_path: Path) -> bool:
    ignored_parts = {
        "__pycache__",
        ".git",
        "build",
        "dist",
        "node_modules",
        "reports",
        "venv",
    }

    return any(part in ignored_parts for part in file_path.parts)


def read_text_safely(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def clean_evidence(match_text: str) -> str:
    evidence = match_text.strip().replace("\n", " ")

    if len(evidence) > 160:
        return evidence[:160] + "..."

    return evidence


def scan_code(extracted_app_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen_findings = set()

    candidate_files = [
        file_path
        for file_path in extracted_app_path.rglob("*")
        if file_path.is_file()
        and is_code_file(file_path)
        and not should_skip_file(file_path)
    ]

    for file_path in candidate_files:
        content = read_text_safely(file_path)

        if not content:
            continue

        for rule in CODE_PATTERNS:
            pattern: Pattern[str] = rule["pattern"]  # type: ignore

            for match in pattern.finditer(content):
                evidence = clean_evidence(match.group(0))

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