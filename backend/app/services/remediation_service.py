"""LLM-assisted remediation for completed scans using an isolated workspace."""
import json
import re
import shutil
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List

from app.services.llm_provider_service import LLMProviderService
from app.services.audit_log_service import AuditLogService


class RemediationService:
    """Apply validated patches only to the cloned workspace; never push user code."""
    MAX_FINDINGS_FOR_LLM = 20
    # Remediation prompts contain source and policy context; slow hosted models
    # are allowed to finish instead of being converted into evidence-only output.
    # Allow the dedicated primary model enough time to analyze repository
    # context and produce a complete, validated patch set.
    LLM_TIMEOUT_SECONDS = 600

    @classmethod
    def _call_llm_bounded(cls, prompt: str, system_prompt: str) -> Any:
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sentinel-remediation-llm")
        remediation_key = LLMProviderService.get_remediation_api_key()
        if not remediation_key:
            raise RuntimeError("REMEDIATION_OPENROUTER_API_KEY is not configured")
        future = executor.submit(
            LLMProviderService.call_llm,
            prompt,
            system_prompt,
            True,
            remediation_key,
            False,
            LLMProviderService.get_settings().get("remediation_model") or None,
        )
        try:
            result = future.result(timeout=cls.LLM_TIMEOUT_SECONDS)
        except FutureTimeout as exc:
            future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise TimeoutError(f"LLM remediation request exceeded {cls.LLM_TIMEOUT_SECONDS} seconds") from exc
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
            return result

    @staticmethod
    def _relevant_code(workspace: Path, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        repo = workspace / "repository"
        if not repo.is_dir():
            repo = workspace / "extracted_repository"
        if not repo.is_dir():
            return {}
        paths = {str(f.get("file_path", "")).replace("\\", "/").lstrip("./") for f in findings}
        result: Dict[str, str] = {}
        total_chars = 0
        for path in list(paths)[:8]:
            if not path or ".." in Path(path).parts:
                continue
            candidate = repo / path
            if not candidate.is_file() and path.startswith("codebase/"):
                candidate = repo / path.removeprefix("codebase/")
            if candidate.is_file() and candidate.stat().st_size <= 200_000:
                try:
                    snippet = candidate.read_text(encoding="utf-8", errors="ignore")[:12000]
                    if total_chars + len(snippet) > 60000:
                        break
                    result[path] = snippet
                    total_chars += len(snippet)
                except OSError:
                    pass
        return result

    @staticmethod
    def _apply_patches(repo: Path, patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        applied: List[Dict[str, Any]] = []
        cls_rejections: List[Dict[str, Any]] = []
        RemediationService._patch_rejections = cls_rejections
        for patch in patches:
            diff = patch.get("unified_diff")
            if not isinstance(diff, str) or not diff.strip():
                cls_rejections.append({"finding_id": patch.get("finding_id"), "reason": "empty unified diff"})
                continue
            # Models sometimes emit the absolute path they were shown in the
            # prompt. Normalize only paths that resolve inside this isolated
            # workspace; everything else (including traversal) remains blocked.
            try:
                normalized_lines = []
                repo_root = repo.resolve()
                for line in diff.splitlines():
                    if line.startswith(("--- ", "+++ ")):
                        prefix, rest = line[:4], line[4:]
                        parts = rest.split(maxsplit=1)
                        token = parts[0].replace("\\", "/")
                        suffix = f" {parts[1]}" if len(parts) > 1 else ""
                        raw = token[2:] if token.startswith(("a/", "b/")) else token
                        candidate = Path(raw)
                        if candidate.is_absolute():
                            try:
                                relative = candidate.resolve().relative_to(repo_root)
                            except ValueError as exc:
                                raise ValueError("patch path is outside the isolated workspace") from exc
                            raw = relative.as_posix()
                        if ".." in PurePosixPath(raw).parts:
                            raise ValueError("patch path traversal is not allowed")
                        marker = "a/" if prefix.startswith("---") else "b/"
                        line = f"{prefix}{marker}{raw}{suffix}"
                    normalized_lines.append(line)
                diff = "\n".join(normalized_lines) + "\n"
            except (OSError, ValueError) as exc:
                cls_rejections.append({"finding_id": patch.get("finding_id"), "reason": str(exc)})
                continue
            # --recount lets Git derive hunk offsets from the supplied context;
            # models often emit approximate @@ line numbers even when the
            # actual before/after lines are correct.
            check = subprocess.run(["git", "apply", "--recount", "--check", "--whitespace=nowarn", "-"], cwd=repo, input=diff, text=True, capture_output=True, timeout=30)
            if check.returncode != 0:
                cls_rejections.append({"finding_id": patch.get("finding_id"), "reason": (check.stderr or check.stdout or "git apply check failed").strip()[:500]})
                continue
            done = subprocess.run(["git", "apply", "--recount", "--whitespace=nowarn", "-"], cwd=repo, input=diff, text=True, capture_output=True, timeout=30)
            if done.returncode == 0:
                applied.append({"path": patch.get("path"), "finding_id": patch.get("finding_id"), "rationale": patch.get("rationale"), "validation": patch.get("validation")})
            else:
                cls_rejections.append({"finding_id": patch.get("finding_id"), "reason": (done.stderr or done.stdout or "git apply failed").strip()[:500]})
        return applied

    @staticmethod
    def _write_pdf(
        path: Path,
        scan_id: str,
        findings: List[Dict[str, Any]],
        policy: Dict[str, Any],
        applied: List[Dict[str, Any]],
        generated_at: str,
        recommendations: List[Dict[str, Any]] | None = None,
        patches: List[Dict[str, Any]] | None = None,
        llm_error: str | None = None,
    ) -> None:
        """Create a visually structured remediation report for the ZIP bundle."""
        from html import escape
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

        navy = colors.HexColor("#132238")
        orange = colors.HexColor("#FF6B1A")
        blue = colors.HexColor("#2563EB")
        ink = colors.HexColor("#172033")
        muted = colors.HexColor("#637083")
        pale = colors.HexColor("#F3F6FA")
        border = colors.HexColor("#DCE3EC")
        green = colors.HexColor("#087F5B")
        amber = colors.HexColor("#9A5B00")
        red = colors.HexColor("#B42318")

        def safe(value: Any, default: str = "Not provided") -> str:
            if value is None or str(value).strip() == "":
                value = default
            return escape(str(value)).replace("\n", "<br/>")

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=colors.white, alignment=TA_LEFT, spaceAfter=5))
        styles.add(ParagraphStyle(name="CoverMeta", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#D7E1EE")))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=navy, spaceBefore=15, spaceAfter=8, keepWithNext=True))
        styles.add(ParagraphStyle(name="CardTitle", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=navy, spaceAfter=4))
        styles.add(ParagraphStyle(name="BodyClean", parent=styles["BodyText"], fontSize=9, leading=13, textColor=ink, spaceAfter=4, wordWrap="CJK"))
        styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, leading=11, textColor=muted, wordWrap="CJK"))
        styles.add(ParagraphStyle(name="MetricLabel", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=muted, alignment=TA_CENTER))
        styles.add(ParagraphStyle(name="MetricValue", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=17, leading=20, textColor=navy, alignment=TA_CENTER))
        styles.add(ParagraphStyle(name="Badge", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white, alignment=TA_CENTER))
        styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontSize=9, leading=13, textColor=ink, wordWrap="CJK"))

        recommendation_rows = recommendations or []
        patch_rows = patches or []
        checks = policy.get("checks", []) if isinstance(policy.get("checks", []), list) else []
        failed_controls = sum(1 for item in checks if str(item.get("status", "")).upper() == "FAIL")
        status_label = "LLM ANALYSIS UNAVAILABLE" if llm_error else "LLM ANALYSIS COMPLETED"
        status_color = amber if llm_error else green

        def draw_page(canvas, doc):
            canvas.saveState()
            width, height = letter
            canvas.setFillColor(orange)
            canvas.rect(0, height - 7, width, 7, fill=1, stroke=0)
            canvas.setStrokeColor(border)
            canvas.setLineWidth(0.5)
            canvas.line(doc.leftMargin, 0.55 * inch, width - doc.rightMargin, 0.55 * inch)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(muted)
            canvas.drawString(doc.leftMargin, 0.36 * inch, f"SentinelAI  |  Scan {scan_id}")
            canvas.drawRightString(width - doc.rightMargin, 0.36 * inch, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(path), pagesize=letter, rightMargin=0.62 * inch, leftMargin=0.62 * inch,
            topMargin=0.72 * inch, bottomMargin=0.78 * inch,
            title=f"SentinelAI Remediation Report - {scan_id}", author="SentinelAI",
        )
        story: List[Any] = []
        cover = Table([[Paragraph("SENTINELAI  /  REMEDIATION", styles["CoverMeta"])],
                       [Paragraph("Remediation Report", styles["CoverTitle"])],
                       [Paragraph(f"Scan ID: {safe(scan_id)}<br/>Generated: {safe(generated_at)}", styles["CoverMeta"]) ]], colWidths=[7.26 * inch])
        cover.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), navy), ("BOX", (0, 0), (-1, -1), 0, navy),
            ("LINEBELOW", (0, -1), (-1, -1), 3, orange),
            ("LEFTPADDING", (0, 0), (-1, -1), 17), ("RIGHTPADDING", (0, 0), (-1, -1), 17),
            ("TOPPADDING", (0, 0), (-1, 0), 14), ("BOTTOMPADDING", (0, 0), (-1, 0), 3),
            ("TOPPADDING", (0, 1), (-1, 1), 2), ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
            ("TOPPADDING", (0, 2), (-1, 2), 3), ("BOTTOMPADDING", (0, 2), (-1, 2), 14),
        ]))
        story.extend([cover, Spacer(1, 13)])

        state_badge = Table([[Paragraph(safe(status_label), styles["Badge"])]], colWidths=[2.2 * inch])
        state_badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), status_color), ("BOX", (0, 0), (-1, -1), 0, status_color), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story.extend([state_badge, Spacer(1, 10)])

        metrics = [
            ("CONFIRMED FINDINGS", str(len(findings))),
            ("FAILED CONTROLS", str(failed_controls)),
            ("LLM RECOMMENDATIONS", str(len(recommendation_rows))),
            ("PATCHES APPLIED", str(len(applied))),
        ]
        metric_cells = [[Paragraph(label, styles["MetricLabel"]), Paragraph(value, styles["MetricValue"])] for label, value in metrics]
        metric_table = Table([metric_cells], colWidths=[1.815 * inch] * 4)
        metric_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), pale), ("BOX", (0, 0), (-1, -1), 0.6, border),
            ("INNERGRID", (0, 0), (-1, -1), 0.6, border), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.extend([metric_table, Spacer(1, 10)])
        summary = ("The original scan report is preserved. Proposed and applied changes below refer only to the isolated remediation workspace. "
                   "Run a new scan and the repository test suite before treating a finding as fixed.")
        callout = Table([[Paragraph(safe(summary), styles["Callout"])]], colWidths=[7.26 * inch])
        callout.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")), ("LINEBEFORE", (0, 0), (0, -1), 3, blue), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#C9DDFB")), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
        story.append(callout)

        if llm_error:
            error_box = Table([[Paragraph(f"<b>LLM error:</b> {safe(llm_error)}", styles["Callout"])]], colWidths=[7.26 * inch])
            error_box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF7E8")), ("LINEBEFORE", (0, 0), (0, -1), 3, amber), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#F4D49A")), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
            story.extend([Spacer(1, 8), error_box])

        story.append(Paragraph("Findings", styles["Section"]))
        if not findings:
            story.append(Paragraph("No confirmed findings were included in this remediation run.", styles["BodyClean"]))
        for index, finding in enumerate(findings, 1):
            title = finding.get("title") or finding.get("finding_id") or finding.get("id") or "Untitled finding"
            severity = str(finding.get("severity", "UNKNOWN")).upper()
            severity_color = red if severity in {"CRITICAL", "HIGH"} else amber if severity in {"MEDIUM", "WARNING"} else blue
            badge = Table([[Paragraph(safe(severity), styles["Badge"])]], colWidths=[0.9 * inch])
            badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), severity_color), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            metadata = f"<b>Location:</b> {safe(finding.get('file_path'))}:{safe(finding.get('line_number', ''))} &nbsp;&nbsp; <b>Scanner:</b> {safe(finding.get('source') or finding.get('tool') or finding.get('scanner'))}"
            content: List[Any] = [badge, Spacer(1, 5), Paragraph(f"{index}. {safe(title)}", styles["CardTitle"]), Paragraph(metadata, styles["SmallMuted"])]
            description = finding.get("description") or finding.get("summary")
            if description:
                content.extend([Spacer(1, 4), Paragraph(f"<b>Issue:</b> {safe(description)}", styles["BodyClean"])])
            remediation = finding.get("remediation") or finding.get("existing_remediation")
            if remediation:
                content.extend([Spacer(1, 2), Paragraph(f"<b>Suggested fix:</b> {safe(remediation)}", styles["BodyClean"])])
            evidence = finding.get("evidence")
            if evidence:
                e = evidence if isinstance(evidence, list) else [evidence]
                excerpt = "; ".join(str(item)[:500] for item in e[:2])
                content.extend([Spacer(1, 2), Paragraph(f"<b>Evidence:</b> {safe(excerpt)}", styles["SmallMuted"])])
            finding_card = Table([[content]], colWidths=[7.26 * inch])
            finding_card.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.white), ("BOX", (0, 0), (-1, -1), 0.7, border), ("LINEBEFORE", (0, 0), (0, -1), 3, severity_color), ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 11), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
            story.extend([KeepTogether([finding_card]), Spacer(1, 7)])

        story.append(Paragraph("LLM Recommendations", styles["Section"]))
        if recommendation_rows:
            for rec in recommendation_rows:
                target = rec.get("finding") if isinstance(rec.get("finding"), dict) else {}
                heading = target.get("title") or target.get("id") or "Recommendation"
                rec_body = [Paragraph(safe(heading), styles["CardTitle"])]
                for key, label in (("root_cause", "Root cause"), ("recommended_change", "Recommended change"), ("validation", "Validation"), ("residual_risk", "Residual risk")):
                    if rec.get(key):
                        rec_body.append(Paragraph(f"<b>{label}:</b> {safe(rec[key])}", styles["BodyClean"]))
                rec_card = Table([[rec_body]], colWidths=[7.26 * inch])
                rec_card.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFF")), ("BOX", (0, 0), (-1, -1), 0.6, border), ("LINEBEFORE", (0, 0), (0, -1), 3, blue), ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 11), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
                story.extend([rec_card, Spacer(1, 7)])
        else:
            story.append(Paragraph("The LLM did not return structured recommendations for this run. See the finding guidance above and the error status, if present.", styles["BodyClean"]))

        story.append(Paragraph("Patch proposals and applied changes", styles["Section"]))
        applied_ids = {item.get("finding_id") for item in applied}
        if patch_rows:
            for patch in patch_rows:
                patch_id = patch.get("finding_id")
                was_applied = patch_id in applied_ids
                label = "APPLIED TO ISOLATED COPY" if was_applied else "PROPOSED - NOT APPLIED"
                label_color = green if was_applied else amber
                patch_content = [Paragraph(f"{safe(patch_id or 'Patch')}  |  <font color=\"{label_color.hexval()}\"><b>{label}</b></font>", styles["CardTitle"])]
                patch_content.append(Paragraph(f"<b>File:</b> {safe(patch.get('path'))}", styles["SmallMuted"]))
                if patch.get("rationale"):
                    patch_content.append(Paragraph(f"<b>Why:</b> {safe(patch.get('rationale'))}", styles["BodyClean"]))
                if patch.get("validation"):
                    patch_content.append(Paragraph(f"<b>Validation:</b> {safe(patch.get('validation'))}", styles["BodyClean"]))
                patch_card = Table([[patch_content]], colWidths=[7.26 * inch])
                patch_card.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FBFCFE")), ("BOX", (0, 0), (-1, -1), 0.6, border), ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 11), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
                story.extend([patch_card, Spacer(1, 7)])
        else:
            story.append(Paragraph("No patch proposals were returned.", styles["BodyClean"]))
        if not applied:
            story.append(Paragraph("No changes were applied to the isolated codebase. A proposed patch does not count as a fix until it passes validation and a follow-up scan confirms the finding is resolved.", styles["SmallMuted"]))

        story.append(Paragraph("Compliance summary", styles["Section"]))
        story.append(Paragraph(f"{len(checks)} controls were evaluated in the source scan; {failed_controls} were marked failed. This remediation report does not claim that controls are resolved. Re-run policy checks against the patched copy to verify any improvement.", styles["BodyClean"]))
        doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)

    @staticmethod
    def _safe_scan_id(scan_id: str) -> str:
        if not re.fullmatch(r"SCAN-[A-Za-z0-9-]+", scan_id or ""):
            raise ValueError("Invalid scan identifier.")
        return scan_id

    @classmethod
    def _workspace(cls, scan_id: str) -> Path:
        safe_id = cls._safe_scan_id(scan_id)
        return Path(__file__).resolve().parents[2] / "runtime" / "workspaces" / safe_id

    @staticmethod
    def _finding_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": finding.get("finding_id") or finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "cvss_score": finding.get("cvss_score"),
            "cvss_vector": finding.get("cvss_vector"),
            "scanner": finding.get("source") or finding.get("tool") or finding.get("scanner"),
            "file_path": finding.get("file_path"),
            "line_number": finding.get("line_number"),
            "evidence": finding.get("evidence", [])[:3],
            "existing_remediation": finding.get("remediation"),
        }

    @staticmethod
    def _compact_policy_checks(policy: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
        """Keep only actionable, bounded control metadata for the LLM prompt.

        Scanner output, source maps, minified assets and generated reports are
        not proof of a compliance control and can otherwise inflate the prompt
        by hundreds of kilobytes.
        """
        compact: List[Dict[str, Any]] = []
        for check in policy.get("checks", []) if isinstance(policy.get("checks", []), list) else []:
            status = str(check.get("status", "")).upper()
            if status not in {"FAIL", "UNKNOWN", "PARTIAL"}:
                continue
            item = {k: check.get(k) for k in ("rule_id", "rule", "title", "status", "severity", "description") if check.get(k) is not None}
            evidence = check.get("evidence")
            if isinstance(evidence, list):
                safe = []
                for entry in evidence[:3]:
                    if isinstance(entry, dict):
                        path = str(entry.get("file", entry.get("path", ""))).lower()
                        if any(x in path for x in (".sarif", ".map", "results/", "scanner", "node_modules", "vendor")):
                            continue
                        safe.append({k: str(entry.get(k, ""))[:800] for k in ("file", "path", "line", "snippet", "reason") if entry.get(k) is not None})
                    elif isinstance(entry, str) and len(entry) < 1000:
                        safe.append(entry[:800])
                if safe:
                    item["evidence"] = safe
            compact.append(item)
            if len(compact) >= limit:
                break
        return compact

    @classmethod
    def _deterministic_items(cls, findings: List[Dict[str, Any]], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for finding in findings:
            summary = cls._finding_summary(finding)
            items.append({
                "finding": summary,
                "recommended_change": summary["existing_remediation"] or "Review the scanner evidence and implement a minimal, tested fix.",
                "validation": "Run the affected scanner again and execute the repository test suite.",
                "status": "MANUAL_REVIEW_REQUIRED",
            })
        for check in policy.get("checks", []):
            if str(check.get("status", "")).upper() == "FAIL":
                items.append({
                    "finding": {"id": check.get("rule_id"), "title": check.get("rule") or check.get("title"), "severity": check.get("severity", "MEDIUM")},
                    "recommended_change": "Implement the failed policy control and retain objective evidence in the repository or operational runbook.",
                    "validation": "Re-run SentinelAI compliance checks after the control is implemented.",
                    "status": "MANUAL_REVIEW_REQUIRED",
                })
        return items

    @classmethod
    def _llm_items(cls, findings: List[Dict[str, Any]], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ordered_findings = sorted(
            findings,
            key=lambda f: (severity_rank.get(str(f.get("severity", "MEDIUM")).upper(), 5), -(f.get("cvss_score") or 0)),
        )
        evidence = [cls._finding_summary(f) for f in ordered_findings[:cls.MAX_FINDINGS_FOR_LLM]]
        ordered_checks = sorted(
            cls._compact_policy_checks(policy),
            key=lambda c: (0 if str(c.get("status", "")).upper() == "FAIL" else 1 if str(c.get("status", "")).upper() == "UNKNOWN" else 2,
                           severity_rank.get(str(c.get("severity", "MEDIUM")).upper(), 5)),
        )
        policy_context = {
            "sector": policy.get("sector"),
            "policy_source": policy.get("policy_source"),
            "applicable_sector_control_pack": str(policy.get("applicable_canonical_text", ""))[:50000],
            "custom_policy_filename": policy.get("uploaded_policy_filename"),
            "custom_policy_text": str(policy.get("uploaded_policy_text", ""))[:50000],
            "checks": ordered_checks,
        }
        prompt = json.dumps({"findings": evidence, "compliance": policy_context}, indent=2, ensure_ascii=False)
        code_files = getattr(cls, "_prompt_code_files", {})
        system = (
            "You are a senior application-security remediation assistant. Produce only JSON: "
            "{\"items\":[...],\"patches\":[{\"finding_id\":string,\"path\":string,\"unified_diff\":string,\"rationale\":string,\"validation\":string}]}. "
            "Return patches only for supplied repository files, using valid git unified diffs with repository-relative a/ and b/ paths (never absolute filesystem paths). Use only supplied evidence. Do not invent CVEs/CVSS, include credentials, or write destructive commands."
        )
        raw = cls._call_llm_bounded(
            prompt + "\n\nRelevant repository files:\n" + json.dumps(code_files, ensure_ascii=False)[:60000],
            system,
        )
        decoded = json.loads(raw)
        rows = decoded.get("items", []) if isinstance(decoded, dict) else []
        if not isinstance(rows, list):
            raise ValueError("LLM response does not contain remediation items.")
        cls._llm_patches = decoded.get("patches", []) if isinstance(decoded, dict) and isinstance(decoded.get("patches", []), list) else []
        return [row for row in rows if isinstance(row, dict)]

    @staticmethod
    def _workflow() -> str:
        return """name: SentinelAI security gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Add your approved SentinelAI CLI/API invocation here. Keep secrets in
      # GitHub Actions secrets; never commit tokens or policy documents.
      - name: Security gate placeholder
        run: echo \"Run approved SentinelAI scan for this commit\"
"""

    @classmethod
    def generate_bundle(cls, scan_id: str) -> Dict[str, Any]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="LLM_REMEDIATION",
            event_type="REMEDIATION_START",
            message="Building an isolated remediation workspace from the completed scan evidence, repository files, and policy context.",
            tool_name="REMEDIATION_SERVICE",
        )
        workspace = cls._workspace(scan_id)
        final_path = workspace / "final_output.json"
        if not final_path.exists():
            raise FileNotFoundError("No completed scan output exists for this scan.")
        final_output = json.loads(final_path.read_text(encoding="utf-8"))
        findings = final_output.get("findings", [])
        policy = final_output.get("policy_compliance", {}) or {}
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="LLM_REMEDIATION",
            event_type="REMEDIATION_INPUTS",
            message="Selected scan findings and compliance evidence prepared for remediation analysis.",
            tool_name="REMEDIATION_SERVICE",
            payload={
                "findings_included": len(findings),
                "policy_checks_included": len(policy.get("checks", [])),
                "sector": policy.get("sector"),
                "policy_source": policy.get("policy_source"),
                "sector_control_pack_included": bool(policy.get("applicable_canonical_text")),
                "custom_policy_included": bool(policy.get("uploaded_policy_text")),
                "custom_policy_filename": policy.get("uploaded_policy_filename"),
            },
        )
        generated_at = datetime.now(timezone.utc).isoformat()

        llm_error = None
        cls._prompt_code_files = cls._relevant_code(workspace, findings)
        cls._llm_patches = []
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="LLM_REMEDIATION",
            event_type="LLM_REQUEST_START",
            message=("Primary LLM request dispatched; waiting for acknowledgement and remediation response. "
                     "Sending verified findings, CVSS data, compliance controls, sector policy context, "
                     f"and {len(cls._prompt_code_files)} relevant repository file(s)."),
            tool_name="REMEDIATION_SERVICE",
        )
        try:
            llm_items = cls._llm_items(findings, policy)
            generation_mode = "LLM_ASSISTED_REVIEW"
            AuditLogService.log_event(
                scan_id=scan_id,
                stage="LLM_REMEDIATION",
                event_type="LLM_REQUEST_COMPLETE",
                message=(f"LLM remediation analysis complete: {len(llm_items)} recommendation(s), "
                         f"{len(cls._llm_patches)} patch proposal(s)."),
                tool_name="REMEDIATION_SERVICE",
            )
        except Exception as exc:
            llm_items = []
            llm_error = str(exc)
            generation_mode = "EVIDENCE_ONLY_REVIEW"
            AuditLogService.log_event(
                scan_id=scan_id,
                stage="LLM_REMEDIATION",
                event_type="LLM_FALLBACK",
                message=f"LLM remediation unavailable; generated evidence-only guidance. {exc}",
                tool_name="REMEDIATION_SERVICE",
            )

        deterministic_items = cls._deterministic_items(findings, policy)
        repo_path = workspace / "repository"
        if not repo_path.is_dir():
            repo_path = workspace / "extracted_repository"
        applied_changes = cls._apply_patches(repo_path, cls._llm_patches) if repo_path.is_dir() else []
        if applied_changes:
            AuditLogService.log_event(
                scan_id=scan_id, stage="LLM_REMEDIATION", event_type="REMEDIATION_PATCH_APPLIED",
                message=f"Applied {len(applied_changes)} validated LLM patch(es) to the isolated remediation workspace.",
                tool_name="REMEDIATION_SERVICE", payload={"changes": applied_changes},
            )
        if cls._llm_patches and len(applied_changes) < len(cls._llm_patches):
            AuditLogService.log_event(
                scan_id=scan_id, stage="LLM_REMEDIATION", event_type="REMEDIATION_PATCH_REJECTED",
                message=(f"{len(cls._llm_patches) - len(applied_changes)} LLM patch proposal(s) were not applied; "
                         "the diff failed path or git validation."),
                tool_name="REMEDIATION_SERVICE",
                payload={"proposed": len(cls._llm_patches), "applied": len(applied_changes)},
            )
        plan = {
            "scan_id": scan_id,
            "generated_at": generated_at,
            "generation_mode": generation_mode,
            "important": "Only the isolated cloned remediation workspace was changed. The original scan report and source repository were not modified; run a new scan before committing or pushing.",
            "source_findings": [cls._finding_summary(item) for item in findings],
            "failed_policy_checks": [item for item in policy.get("checks", []) if str(item.get("status", "")).upper() == "FAIL"],
            "llm_recommendations": llm_items,
            "llm_patches": cls._llm_patches,
            "applied_changes": applied_changes,
            "evidence_based_actions": deterministic_items,
            "llm_error": llm_error,
            "patch_rejections": getattr(cls, "_patch_rejections", []),
        }
        plan_path = workspace / "remediation_plan.json"
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

        report = [
            "# SentinelAI Remediation Report", "", f"Scan: `{scan_id}`", f"Generated: {generated_at}", "",
            "## Outcome", f"- Confirmed findings before remediation: {len(findings)}",
            f"- Failed compliance controls before remediation: {len(plan['failed_policy_checks'])}",
            f"- Changes applied in isolated remediation workspace: {len(applied_changes)}; original scan workspace/report preserved.", "",
            "## Required review", "Apply only reviewed recommendations on a separate branch, run tests and a new SentinelAI scan, then open a pull request.", "",
            "## Finding remediation guidance",
        ]
        for item in deterministic_items:
            finding = item["finding"]
            report.extend([
                f"### {finding.get('id') or 'Finding'} — {finding.get('title') or 'Untitled'}",
                f"- Severity: {finding.get('severity', 'UNKNOWN')}; CVSS: {finding.get('cvss_score', 'not provided')}",
                f"- Location: {finding.get('file_path', 'not provided')}:{finding.get('line_number', '')}",
                f"- Recommended action: {item['recommended_change']}", f"- Verify: {item['validation']}", "",
            ])
        report_path = workspace / "remediation_report.md"
        report_path.write_text("\n".join(report), encoding="utf-8")
        remediation_pdf_path = workspace / "remediation_report.pdf"
        cls._write_pdf(
            remediation_pdf_path, scan_id, findings, policy, applied_changes, generated_at,
            recommendations=llm_items, patches=cls._llm_patches, llm_error=llm_error,
        )

        workflow_path = workspace / "sentinelai-security.yml"
        workflow_path.write_text(cls._workflow(), encoding="utf-8")
        policy_path = workspace / "remediation_policy_context.json"
        compact_policy = {
            "sector": policy.get("sector"),
            "policy_source": policy.get("policy_source"),
            "applicable_canonical_text": str(policy.get("applicable_canonical_text", ""))[:50000],
            "uploaded_policy_filename": policy.get("uploaded_policy_filename"),
            "checks": cls._compact_policy_checks(policy),
        }
        policy_path.write_text(json.dumps(compact_policy, indent=2, ensure_ascii=False), encoding="utf-8")

        # Never zip the cloned repository or previous scan artifacts. The
        # export contains only the review materials that the user may add to
        # a branch after inspection.
        bundle_base = workspace / "sentinelai_remediation_bundle"
        archive_path = Path(f"{bundle_base}.zip")
        original_report = workspace / "report.pdf"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for artifact in (plan_path, report_path, workflow_path, remediation_pdf_path, policy_path):
                bundle.write(artifact, artifact.name)
            if original_report.exists():
                bundle.write(original_report, "original_scan_report.pdf")
            # Stream the isolated, patched codebase without .git, runtime
            # output, or virtual environments into the download.
            if repo_path.is_dir():
                for source in repo_path.rglob("*"):
                    if not source.is_file() or ".git" in source.parts or "__pycache__" in source.parts:
                        continue
                    relative = source.relative_to(repo_path)
                    if any(part.lower() in {".venv", "node_modules"} for part in relative.parts):
                        continue
                    bundle.write(source, str(Path("codebase") / relative))
        result = {
            "scan_id": scan_id, "generation_mode": generation_mode, "findings_before": len(findings),
            "failed_controls_before": len(plan["failed_policy_checks"]), "changes_applied": len(applied_changes), "llm_error": llm_error,
            "recommendations_count": len(llm_items), "patches_proposed": len(cls._llm_patches),
            "patches_rejected": len(getattr(cls, "_patch_rejections", [])),
            "has_bundle": archive_path.exists(), "status": "GENERATED",
            "artifacts": {"plan": plan_path.name, "report": remediation_pdf_path.name, "original_report": original_report.name if original_report.exists() else None, "ci_workflow": workflow_path.name, "bundle": archive_path.name},
        }
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="LLM_REMEDIATION",
            event_type="REMEDIATION_BUNDLE_READY",
            message=f"Remediation bundle generated with {len(applied_changes)} isolated source change(s); original scan report preserved.",
            tool_name="REMEDIATION_SERVICE",
            model_used=generation_mode,
            payload={"artifacts": result["artifacts"], "changes_applied": len(applied_changes)},
        )
        return result
