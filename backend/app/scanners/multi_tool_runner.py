"""
Multi-tool SAST runner for SentinelAI Stage 2.

Tools supported (in priority order; per-tool failure isolation):
  - semgrep   (multi-language SAST)            -> JSON
  - bandit    (Python SAST)                    -> JSON
  - trivy     (filesystem + dependency CVE)    -> JSON
  - gitleaks  (secret detection in git hist)   -> JSON
  - bearer    (privacy + security SAST)       -> JSON
  - spotbugs  (Java/Kotlin byte-code SAST)     -> XML
  - ast_parser (in-process; always available) -> Python

Each tool is launched in a subprocess with a hard timeout. If the binary
isn't installed (FileNotFoundError) or times out, the runner records a tool
error and continues with the remaining real scanners. Each tool's output is
normalized to a uniform finding shape:

    {
        "finding_id": "SEM-001",
        "file_path": "app/api/routes/users.py",
        "line_number": 42,
        "title": "SQL Injection in User Lookup",
        "severity": "HIGH",  # CRITICAL | HIGH | MEDIUM | LOW
        "severity_summary": "...",
        "source": "semgrep",
        "cve_ids": ["CVE-2024-12345"],   # optional, for vuln/CVE findings
        "cvss_score": 8.1,                # optional
        "evidence": ["..."],
        "status": "UNVERIFIED",  # Stage 3 will flip this to CONFIRMED/REJECTED
    }

Findings are written to:
  - {workspace}/stage2_multi_hunter_findings.json
  - {workspace}/stage2_per_tool/{tool}.json  (one per tool, for audit)
"""
import json
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from app.scanners.ast_scanner import ASTScanner
from app.services.audit_log_service import AuditLogService
from app.services.llm_provider_service import LLMProviderService
from app.core.config import settings


# Per-tool invocation timeout (seconds). Tuned for large repos.
TOOL_TIMEOUT = 240


_TOOL_CONFIG = {
    "semgrep": ("SEMGREP_PATH", "semgrep", ["--version"]),
    "bandit": ("BANDIT_PATH", "bandit", ["--version"]),
    "trivy": ("TRIVY_PATH", "trivy", ["--version"]),
    "gitleaks": ("GITLEAKS_PATH", "gitleaks", ["version"]),
    "bearer": ("BEARER_PATH", "bearer", ["--version"]),
    "spotbugs": ("SPOTBUGS_PATH", "spotbugs", ["-version"]),
}


def _tool_command(tool_key: str) -> Optional[List[str]]:
    config_name, fallback, _ = _TOOL_CONFIG[tool_key]
    configured = getattr(settings, config_name, "").strip()
    executable = configured if configured else shutil.which(fallback)
    if not executable or not os.path.isfile(executable):
        return None
    return ["cmd", "/c", executable] if executable.lower().endswith((".bat", ".cmd")) else [executable]


def _scanner_environment() -> Dict[str, str]:
    """Build an isolated environment for externally installed scanners."""
    environment = os.environ.copy()
    # A backend launched with PYTHONPATH pointed at its virtualenv can otherwise
    # override dependencies used by separately installed scanner executables.
    environment.pop("PYTHONPATH", None)

    java_home = settings.JAVA_HOME.strip()
    java_bin = os.path.join(java_home, "bin")
    if java_home and os.path.isfile(os.path.join(java_bin, "java.exe")):
        environment["JAVA_HOME"] = java_home
        environment["PATH"] = java_bin + os.pathsep + environment.get("PATH", "")
    return environment


def get_scanner_status() -> Dict[str, Dict[str, Any]]:
    """Return availability and real version output for every configured scanner."""
    status: Dict[str, Dict[str, Any]] = {}
    for tool_key, (_, _, version_args) in _TOOL_CONFIG.items():
        command = _tool_command(tool_key)
        if command is None:
            status[tool_key] = {"status": "UNAVAILABLE", "version": None}
            continue
        try:
            completed = subprocess.run(
                [*command, *version_args],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env=_scanner_environment(),
            )
            output = (completed.stdout or completed.stderr).strip().splitlines()
            status[tool_key] = {"status": "AVAILABLE" if completed.returncode == 0 else "UNAVAILABLE", "version": output[0] if output else None, "path": command[-1]}
        except (OSError, subprocess.TimeoutExpired) as error:
            status[tool_key] = {"status": "UNAVAILABLE", "version": None, "detail": str(error)}
    status["ast_parser"] = {"status": "AVAILABLE", "version": "built-in"}
    return status


def _run_subprocess(cmd: List[str], cwd: str, timeout: int = TOOL_TIMEOUT) -> Optional[Dict[str, Any]]:
    """
    Run a command and return its JSON-parsed stdout, or None on failure.
    Failure includes: binary not found, non-zero exit, timeout, malformed JSON.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_scanner_environment(),
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            return None
        out = proc.stdout.strip()
        if not out:
            return None
        return json.loads(out)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception):
        return None


# ---------------------------------------------------------------------------
# Per-tool runners. Each returns a list of normalized findings.
# ---------------------------------------------------------------------------

def _run_semgrep(repo_path: str, target_paths: List[str]) -> List[Dict[str, Any]]:
    """Run semgrep with the security-audit ruleset if available."""
    executable = _tool_command("semgrep")
    if executable is None:
        raise RuntimeError("semgrep is unavailable.")

    cmd = [
        *executable, "scan",
        "--config=auto",
        "--json", "--quiet",
        "--no-git-ignore",
    ]
    # Scan the cloned repository root directly. Semgrep's --include expects
    # glob patterns, not a comma-joined file list; passing the selected files
    # there caused real repositories to be under-scanned.
    cmd.append(repo_path)

    raw = _run_subprocess(cmd, repo_path)
    if not raw:
        raise RuntimeError("semgrep execution failed or returned no output. Check semgrep installation and rules.")

    findings: List[Dict[str, Any]] = []
    for r in raw.get("results", []):
        sev = (r.get("extra", {}).get("severity") or "MEDIUM").upper()
        findings.append({
            "finding_id": f"SEM-{r.get('check_id', 'X').split('.')[-1][:40]}-{r.get('start', {}).get('line', 0)}",
            "file_path": r.get("path", ""),
            "line_number": int(r.get("start", {}).get("line", 0) or 0),
            "title": r.get("check_id", "semgrep rule"),
            "severity": sev,
            "severity_summary": r.get("extra", {}).get("message", "")[:500],
            "source": "semgrep",
            "evidence": [r.get("extra", {}).get("lines", "")[:500]],
            "status": "UNVERIFIED",
        })
    return findings


def _run_bandit(repo_path: str, target_paths: List[str]) -> List[Dict[str, Any]]:
    executable = _tool_command("bandit")
    if executable is None:
        raise RuntimeError("bandit is unavailable.")
    targets = target_paths or ["."]
    cmd = [*executable, "-r", *targets, "-f", "json", "-q"]
    raw = _run_subprocess(cmd, repo_path)
    if not raw:
        raise RuntimeError("bandit execution failed or returned no output. Check bandit installation.")
    findings: List[Dict[str, Any]] = []
    for r in raw.get("results", []):
        findings.append({
            "finding_id": f"BND-{r.get('test_id', 'X')}-{r.get('line_number', 0)}",
            "file_path": r.get("filename", ""),
            "line_number": int(r.get("line_number", 0) or 0),
            "title": r.get("test_name", "bandit finding"),
            "severity": (r.get("issue_severity") or "MEDIUM").upper(),
            "severity_summary": (r.get("issue_text") or "")[:500],
            "source": "bandit",
            "evidence": [r.get("code", "")[:500]],
            "status": "UNVERIFIED",
        })
    return findings


def _run_trivy(repo_path: str) -> List[Dict[str, Any]]:
    executable = _tool_command("trivy")
    if executable is None:
        raise RuntimeError("trivy is unavailable.")
    cmd = [
        *executable, "fs",
        "--format", "json",
        "--quiet",
        "--scanners", "vuln,secret,misconfig",
        repo_path,
    ]
    raw = _run_subprocess(cmd, repo_path)
    if not raw:
        raise RuntimeError("trivy execution failed or returned no output. Check trivy installation.")
    findings: List[Dict[str, Any]] = []
    for result in raw.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            findings.append({
                "finding_id": f"TRV-{v.get('VulnerabilityID', 'X')}-{result.get('Target', '')[:30]}",
                "file_path": result.get("Target", ""),
                "line_number": 0,
                "title": f"{v.get('VulnerabilityID', '')}: {v.get('Title', '')}",
                "severity": (v.get("Severity") or "MEDIUM").upper(),
                "severity_summary": (v.get("Description") or "")[:500],
                "source": "trivy",
                "cve_ids": [v.get("VulnerabilityID", "")] if v.get("VulnerabilityID", "").startswith("CVE") else [],
                "package_name": v.get("PkgName", ""),
                "package_version": v.get("InstalledVersion", ""),
                "dependency_type": result.get("Type", ""),
                "cvss_score": _extract_cvss(v),
                "cvss_vector": _extract_cvss_vector(v),
                "cvss_source": "Trivy/NVD" if _extract_cvss(v) is not None else None,
                "evidence": [f"Package: {v.get('PkgName', '')}@{v.get('InstalledVersion', '')}"],
                "status": "UNVERIFIED",
            })
        for s in result.get("Secrets", []) or []:
            findings.append({
                "finding_id": f"TRV-SEC-{s.get('RuleID', 'X')}-{result.get('Target', '')[:30]}",
                "file_path": result.get("Target", ""),
                "line_number": int(s.get("StartLine", 0) or 0),
                "title": f"Trivy secret rule: {s.get('RuleID', '')}",
                "severity": "HIGH",
                "severity_summary": (s.get("Match") or "")[:200],
                "source": "trivy",
                "evidence": [s.get("Match", "")[:200]],
                "status": "UNVERIFIED",
            })
    return findings


def _run_gitleaks(repo_path: str) -> List[Dict[str, Any]]:
    executable = _tool_command("gitleaks")
    if executable is None:
        raise RuntimeError("gitleaks is unavailable.")
    cmd = [
        *executable, "detect",
        "--source", repo_path,
        "--report-format", "json",
        "--no-git",  # tolerate non-git working copies
        "-q",
    ]
    raw_text = _run_subprocess_text(cmd, repo_path)
    if raw_text is None:
        raise RuntimeError("gitleaks execution failed or returned no output. Check gitleaks installation.")
    try:
        # gitleaks emits one JSON object per line (NDJSON)
        rows = [json.loads(line) for line in raw_text.splitlines() if line.strip().startswith("{")]
    except Exception as e:
        raise RuntimeError(f"gitleaks output parsing failed: {e}")
    findings: List[Dict[str, Any]] = []
    for r in rows:
        findings.append({
            "finding_id": f"GLK-{r.get('RuleID', 'X')}-{r.get('StartLine', 0)}",
            "file_path": r.get("File", ""),
            "line_number": int(r.get("StartLine", 0) or 0),
            "title": f"Secret leak: {r.get('RuleID', 'gitleaks')}",
            "severity": "CRITICAL",
            "severity_summary": (
                f"Detected {r.get('RuleID', 'secret')} pattern in "
                f"{r.get('File', '')}:{r.get('StartLine', 0)}"
            ),
            "source": "gitleaks",
            "evidence": [r.get("Match", "")[:200]],
            "status": "UNVERIFIED",
        })
    return findings


def _run_subprocess_text(cmd: List[str], cwd: str, timeout: int = TOOL_TIMEOUT) -> Optional[str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_scanner_environment(),
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def _run_bearer(repo_path: str, target_paths: List[str]) -> List[Dict[str, Any]]:
    executable = _tool_command("bearer")
    if executable is None:
        raise RuntimeError("bearer is unavailable.")
    cmd = [*executable, "scan", "--format", "json", "--quiet"]
    if target_paths:
        cmd.extend(target_paths)
    else:
        cmd.append(repo_path)
    raw = _run_subprocess(cmd, repo_path)
    if not raw:
        raise RuntimeError("bearer execution failed or returned no output. Check bearer installation.")
    findings: List[Dict[str, Any]] = []
    for f in raw.get("findings", []):
        findings.append({
            "finding_id": f"BRR-{f.get('id', 'X')}-{f.get('filename', '')[:30]}",
            "file_path": f.get("filename", ""),
            "line_number": int((f.get("line_number") or 0)),
            "title": f.get("title", "bearer finding"),
            "severity": (f.get("severity") or "MEDIUM").upper(),
            "severity_summary": (f.get("description") or "")[:500],
            "source": "bearer",
            "evidence": [f.get("code_snippet", "")[:500]],
            "status": "UNVERIFIED",
        })
    return findings


def _run_spotbugs(repo_path: str) -> List[Dict[str, Any]]:
    """SpotBugs operates on compiled .class files. If no target build dir
    exists in the repo we treat it as a no-op (return [])."""
    executable = _tool_command("spotbugs")
    if executable is None:
        raise RuntimeError("spotbugs is unavailable.")
    # Look for typical Java build output
    candidates = ["target/classes", "build/classes", "out"]
    classes_dir = None
    for c in candidates:
        p = os.path.join(repo_path, c)
        if os.path.isdir(p):
            classes_dir = p
            break
    if not classes_dir:
        return []
    cmd = [*executable, "-textui", "-xml", classes_dir]
    raw_text = _run_subprocess_text(cmd, repo_path)
    if not raw_text:
        raise RuntimeError("spotbugs execution failed or returned no output. Check spotbugs installation.")
    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError as error:
        raise RuntimeError(f"SpotBugs returned invalid XML: {error}") from error

    priority_to_severity = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}
    findings: List[Dict[str, Any]] = []
    for bug in root.findall(".//BugInstance"):
        source = bug.find("SourceLine")
        findings.append({
            "finding_id": f"SPB-{bug.get('type', 'UNKNOWN')}-{len(findings) + 1}",
            "file_path": (source.get("sourcepath", "") if source is not None else ""),
            "line_number": int(source.get("start", "0") or 0) if source is not None else 0,
            "title": bug.get("type", "SpotBugs finding"),
            "severity": priority_to_severity.get(bug.get("priority", ""), "MEDIUM"),
            "severity_summary": (bug.findtext("LongMessage") or bug.findtext("ShortMessage") or "")[:500],
            "source": "spotbugs",
            "evidence": [(bug.findtext("LongMessage") or "")[:500]],
            "status": "UNVERIFIED",
        })
    return findings


def _run_ast_parser(repo_path: str, target_paths: List[str]) -> List[Dict[str, Any]]:
    """In-process AST traversal. Always available and backed by source code."""
    findings: List[Dict[str, Any]] = []
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_path).replace("\\", "/")
            if target_paths and not any(rel == t or rel.startswith(t + "/") for t in target_paths):
                continue
            try:
                findings.extend(ASTScanner.scan_file(full, rel))
            except Exception as e:
                print(f"[MultiToolRunner] ASTScanner error on {rel}: {e}")
    return findings


def _extract_cvss(v: Dict[str, Any]) -> Optional[float]:
    """Best-effort CVSS score extraction from a Trivy vuln record."""
    score_str = v.get("CVSS", {}) or {}
    if isinstance(score_str, dict):
        for vendor in ("nvd", "redhat", "ghsa"):
            s = score_str.get(vendor, {})
            if isinstance(s, dict) and s.get("V3Score"):
                try:
                    return float(s["V3Score"])
                except (TypeError, ValueError):
                    continue
    try:
        if v.get("CVSS", {}).get("nvd", {}).get("V3Score"):
            return float(v["CVSS"]["nvd"]["V3Score"])
    except Exception:
        pass
    return None


def _extract_cvss_vector(v: Dict[str, Any]) -> str:
    """Return the scanner-supplied CVSS vector without synthesising one."""
    cvss = v.get("CVSS", {}) or {}
    if not isinstance(cvss, dict):
        return ""
    for vendor in ("nvd", "redhat", "ghsa"):
        data = cvss.get(vendor, {}) or {}
        if isinstance(data, dict) and data.get("V3Vector"):
            return str(data["V3Vector"])
    return ""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "semgrep": ("Semgrep (multi-language SAST)", _run_semgrep, "paths"),
    "bandit": ("Bandit (Python SAST)", _run_bandit, "paths"),
    "trivy": ("Trivy (filesystem + dep CVE)", _run_trivy, "repo"),
    "gitleaks": ("Gitleaks (secret detection)", _run_gitleaks, "repo"),
    "bearer": ("Bearer CLI (privacy + security SAST)", _run_bearer, "paths"),
    "spotbugs": ("SpotBugs (Java byte-code SAST)", _run_spotbugs, "repo"),
    "ast_parser": ("AST traversal parser (in-process)", _run_ast_parser, "paths"),
}


class MultiToolRunner:

    @classmethod
    def run_all(
        cls,
        scan_id: str,
        repository_path: str,
        workspace_path: str,
        selected_files: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_2_MULTI_HUNTER_SCAN",
            event_type="STAGE_START",
            message="Launching multi-tool SAST team (Semgrep, Bandit, Trivy, Gitleaks, Bearer, SpotBugs, AST)...",
        )

        settings = LLMProviderService.get_settings()
        enabled_tools = settings.get("enabled_tools", list(TOOL_REGISTRY.keys()))
        availability = get_scanner_status()

        target_paths = [item["path"] for item in (selected_files or []) if item.get("path")]

        per_tool_dir = os.path.join(workspace_path, "stage2_per_tool")
        os.makedirs(per_tool_dir, exist_ok=True)

        # Run every enabled tool in parallel. Each tool is wrapped so a single
        # crash (or a missing binary) cannot poison the rest of the scan.
        def _invoke(tool_key: str) -> tuple:
            display_name, runner, mode = TOOL_REGISTRY[tool_key]
            t0 = time.time()
            tool_status = availability.get(tool_key, {"status": "UNAVAILABLE"})
            if tool_status.get("status") != "AVAILABLE":
                AuditLogService.log_event(
                    scan_id=scan_id,
                    stage="STAGE_2_MULTI_HUNTER_SCAN",
                    event_type="TOOL_UNAVAILABLE",
                    message=f"{display_name} is unavailable on this host.",
                    tool_name=display_name,
                    payload=tool_status,
                )
                return tool_key, display_name, [], round(time.time() - t0, 2), tool_status
            try:
                if mode == "paths":
                    findings = runner(repository_path, target_paths)
                else:
                    findings = runner(repository_path)
            except Exception as e:
                findings = []
                AuditLogService.log_event(
                    scan_id=scan_id,
                    stage="STAGE_2_MULTI_HUNTER_SCAN",
                    event_type="TOOL_UNAVAILABLE",
                    message=f"{display_name} did not run: {e}",
                    tool_name=display_name,
                )
            elapsed = round(time.time() - t0, 2)
            return tool_key, display_name, findings, elapsed, tool_status

        all_findings: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(4, len(enabled_tools))) as pool:
            futures = {pool.submit(_invoke, k): k for k in enabled_tools if k in TOOL_REGISTRY}
            for fut in as_completed(futures):
                tool_key, display_name, findings, elapsed, tool_status = fut.result()
                # Per-tool JSON artifact
                try:
                    with open(os.path.join(per_tool_dir, f"{tool_key}.json"), "w", encoding="utf-8") as f:
                        json.dump(findings, f, indent=2)
                    with open(os.path.join(per_tool_dir, f"{tool_key}.status.json"), "w", encoding="utf-8") as f:
                        json.dump(tool_status, f, indent=2)
                except Exception as e:
                    print(f"[MultiToolRunner] Failed to write {tool_key}.json: {e}")
                all_findings.extend(findings)
                AuditLogService.log_event(
                    scan_id=scan_id,
                    stage="STAGE_2_MULTI_HUNTER_SCAN",
                    event_type="TOOL_COMPLETE",
                    message=(
                        f"{display_name} finished in {elapsed}s. "
                        f"Discovered {len(findings)} raw finding(s)."
                    ),
                    tool_name=display_name,
                )

        # Dedupe: same file:line from multiple tools = one finding (with both
        # sources listed). This is critical because the user explicitly asked
        # for "eliminate duplicate errors".
        deduped = _dedupe_by_file_line(all_findings)

        # Save consolidated stage2 output
        output_path = os.path.join(workspace_path, "stage2_multi_hunter_findings.json")
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(deduped, f, indent=2)
        except Exception as e:
            print(f"[MultiToolRunner] Error saving stage2 findings: {e}")

        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_2_MULTI_HUNTER_SCAN",
            event_type="STAGE_COMPLETE",
            message=(
                f"Stage 2 complete. {len(all_findings)} raw findings across "
                f"{len(enabled_tools)} tools; {len(deduped)} after dedupe."
            ),
        )

        return deduped


def _dedupe_by_file_line(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapse findings that point at the same file:line. The most-severe wins;
    the secondary sources get listed in `also_reported_by`.
    """
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    grouped: Dict[tuple, List[Dict[str, Any]]] = {}
    for f in findings:
        key = (f.get("file_path", ""), int(f.get("line_number", 0) or 0))
        grouped.setdefault(key, []).append(f)

    deduped: List[Dict[str, Any]] = []
    for (file_path, line_num), group in grouped.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue
        # Sort by severity (most severe first)
        group.sort(key=lambda f: severity_rank.get(f.get("severity", "MEDIUM").upper(), 5))
        primary = dict(group[0])
        primary["also_reported_by"] = [f.get("source", "?") for f in group[1:]]
        # Keep all evidence (concatenated, deduped)
        ev_seen: set = set()
        ev: List[str] = []
        for f in group:
            for e in f.get("evidence", []) or []:
                if e and e not in ev_seen:
                    ev_seen.add(e)
                    ev.append(e)
        primary["evidence"] = ev[:5]
        # Merge CVE ids
        cves: List[str] = []
        for f in group:
            for c in f.get("cve_ids", []) or []:
                if c and c not in cves:
                    cves.append(c)
        if cves:
            primary["cve_ids"] = cves
        deduped.append(primary)
    return deduped
