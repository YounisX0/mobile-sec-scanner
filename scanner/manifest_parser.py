from pathlib import Path
from typing import List, Optional
from defusedxml import ElementTree as ET

from scanner.models import Finding


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
}


def get_android_attr(element, attr_name: str) -> Optional[str]:
    return (
        element.attrib.get(f"{ANDROID_NS}{attr_name}")
        or element.attrib.get(f"android:{attr_name}")
        or element.attrib.get(attr_name)
    )


def find_manifest_file(extracted_app_path: Path) -> Optional[Path]:
    root_manifest = extracted_app_path / "AndroidManifest.xml"

    if root_manifest.exists():
        return root_manifest

    matches = list(extracted_app_path.rglob("AndroidManifest.xml"))

    if matches:
        return matches[0]

    return None


def component_has_launcher_intent(component) -> bool:
    for intent_filter in component.findall("intent-filter"):
        has_main = False
        has_launcher = False

        for action in intent_filter.findall("action"):
            action_name = get_android_attr(action, "name")
            if action_name == "android.intent.action.MAIN":
                has_main = True

        for category in intent_filter.findall("category"):
            category_name = get_android_attr(category, "name")
            if category_name == "android.intent.category.LAUNCHER":
                has_launcher = True

        if has_main and has_launcher:
            return True

    return False


def component_has_intent_filter(component) -> bool:
    return component.find("intent-filter") is not None


def scan_manifest(extracted_app_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    manifest_path = find_manifest_file(extracted_app_path)

    if manifest_path is None:
        findings.append(
            Finding(
                rule_id="MANIFEST_NOT_FOUND",
                title="AndroidManifest.xml not found",
                severity="High",
                file_path=str(extracted_app_path),
                evidence="No AndroidManifest.xml file was found in the extracted APK folder.",
                impact="The scanner cannot analyze application permissions, components, or security configuration without the manifest.",
                recommendation="Make sure the APK was correctly extracted using APKLab, Apktool, or Jadx.",
                category="Manifest",
            )
        )
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception as error:
        findings.append(
            Finding(
                rule_id="MANIFEST_PARSE_ERROR",
                title="Failed to parse AndroidManifest.xml",
                severity="High",
                file_path=str(manifest_path),
                evidence=str(error),
                impact="The scanner could not read the Android manifest, so important security checks were skipped.",
                recommendation="Verify that the manifest file is valid XML and was extracted correctly.",
                category="Manifest",
            )
        )
        return findings

    application = root.find("application")

    if application is not None:
        findings.extend(check_application_flags(application, manifest_path))
        findings.extend(check_exported_components(application, manifest_path))

    findings.extend(check_dangerous_permissions(root, manifest_path))

    return findings


def check_application_flags(application, manifest_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    allow_backup = get_android_attr(application, "allowBackup")
    debuggable = get_android_attr(application, "debuggable")
    cleartext = get_android_attr(application, "usesCleartextTraffic")

    if allow_backup == "true":
        findings.append(
            Finding(
                rule_id="MANIFEST_ALLOW_BACKUP_ENABLED",
                title="Application backup is enabled",
                severity="Medium",
                file_path=str(manifest_path),
                evidence='android:allowBackup="true"',
                impact="If backup is enabled, sensitive app data may be backed up and extracted from a device backup.",
                recommendation='Set android:allowBackup="false" unless the application has a clear secure backup requirement.',
                category="Manifest",
            )
        )

    if debuggable == "true":
        findings.append(
            Finding(
                rule_id="MANIFEST_DEBUGGABLE_ENABLED",
                title="Debuggable mode is enabled",
                severity="High",
                file_path=str(manifest_path),
                evidence='android:debuggable="true"',
                impact="A debuggable production app can expose internal logic and make reverse engineering or runtime inspection easier.",
                recommendation='Set android:debuggable="false" for release builds.',
                category="Manifest",
            )
        )

    if cleartext == "true":
        findings.append(
            Finding(
                rule_id="MANIFEST_CLEARTEXT_TRAFFIC_ENABLED",
                title="Cleartext network traffic is enabled",
                severity="High",
                file_path=str(manifest_path),
                evidence='android:usesCleartextTraffic="true"',
                impact="The application may allow unencrypted HTTP traffic, which can expose data to interception.",
                recommendation='Use HTTPS only and set android:usesCleartextTraffic="false".',
                category="Manifest",
            )
        )

    return findings


def check_exported_components(application, manifest_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    component_types = {
        "activity": "Exported activity detected",
        "service": "Exported service detected",
        "receiver": "Exported broadcast receiver detected",
        "provider": "Exported content provider detected",
    }

    for component_tag, default_title in component_types.items():
        for component in application.findall(component_tag):
            exported = get_android_attr(component, "exported")
            component_name = get_android_attr(component, "name") or "Unknown component"
            permission = get_android_attr(component, "permission")

            if exported != "true":
                continue

            is_launcher = component_tag == "activity" and component_has_launcher_intent(component)
            has_permission = permission is not None and permission.strip() != ""

            if is_launcher:
                severity = "Low"
                title = "Exported launcher activity detected"
                impact = "Launcher activities are normally exported so users can open the app. This is usually expected, but it should not expose sensitive logic directly."
                recommendation = "Keep launcher activity minimal and route sensitive actions behind authentication and validation."

            elif has_permission:
                severity = "Low"
                title = f"{default_title} with permission protection"
                impact = "The component is exported but protected by a permission. Risk depends on whether the permission is strong and correctly enforced."
                recommendation = "Verify that the protecting permission is not weak, overly broad, or accessible to untrusted apps."

            else:
                severity = "High" if component_tag in {"service", "provider"} else "Medium"
                title = default_title
                impact = "Exported components can be accessed by other applications. If not protected correctly, they may expose sensitive actions or data."
                recommendation = "Set android:exported=\"false\" unless external access is required. If exported is required, protect the component using permissions and strict input validation."

            evidence = f'{component_tag} {component_name} has android:exported="true"'

            if has_permission:
                evidence += f' and android:permission="{permission}"'

            findings.append(
                Finding(
                    rule_id=f"MANIFEST_EXPORTED_{component_tag.upper()}",
                    title=title,
                    severity=severity,
                    file_path=str(manifest_path),
                    evidence=evidence,
                    impact=impact,
                    recommendation=recommendation,
                    category="Manifest",
                )
            )

    return findings


def check_dangerous_permissions(root, manifest_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen_permissions = set()

    for permission in root.findall("uses-permission"):
        permission_name = get_android_attr(permission, "name")

        if not permission_name:
            continue

        if permission_name in seen_permissions:
            continue

        seen_permissions.add(permission_name)

        if permission_name in DANGEROUS_PERMISSIONS:
            findings.append(
                Finding(
                    rule_id="MANIFEST_DANGEROUS_PERMISSION",
                    title="Dangerous permission requested",
                    severity="Medium",
                    file_path=str(manifest_path),
                    evidence=f'<uses-permission android:name="{permission_name}" />',
                    impact="Dangerous permissions allow access to sensitive user data or device features. They increase application risk if not strictly required.",
                    recommendation="Remove unnecessary dangerous permissions and request only the minimum permissions needed for the app functionality.",
                    category="Manifest",
                )
            )

    return findings