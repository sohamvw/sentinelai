import json
import os
from typing import List, Dict, Any
from app.services.audit_log_service import AuditLogService


class ChainCorrelationService:

    @staticmethod
    def _load_list_artifact(path: str) -> List[Dict[str, Any]]:
        """Load a list artifact without making a successful scan depend on it."""
        try:
            with open(path, "r", encoding="utf-8") as artifact:
                value = json.load(artifact)
                return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    @classmethod
    def correlate_and_chain(
        cls,
        scan_id: str,
        workspace_path: str,
        verified_findings: List[Dict[str, Any]],
        policy_results: Dict[str, Any] = None,
        raw_findings_count: int = 0,
    ) -> Dict[str, Any]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_4_CORRELATION",
            event_type="STAGE_START",
            message="Analyzing vulnerability dependencies and building attack chain bounds..."
        )

        chains = []
        high_critical = [f for f in verified_findings if f.get("severity") in ["HIGH", "CRITICAL"]]
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for finding in high_critical:
            file_path = finding.get("file_path")
            if file_path:
                by_file.setdefault(file_path, []).append(finding)

        # A shared source file is observable repository evidence of a common
        # component. It is not, on its own, proof of an exploitable path, so
        # describe it as a review queue instead of inventing a narrative.
        for file_path, related in by_file.items():
            if len(related) < 2:
                continue
            chains.append({
                "chain_id": f"COMPONENT-{len(chains) + 1:02d}",
                "title": f"Multiple verified findings in {file_path}",
                "impact": "Shared-component correlation only. Manual data-flow review is required before claiming an attack path.",
                "linked_finding_ids": [f.get("finding_id") for f in related],
                "severity": "CRITICAL" if any(f.get("severity") == "CRITICAL" for f in related) else "HIGH",
                "correlation_basis": "same_file",
                "verification_status": "REVIEW_REQUIRED",
            })

        policy_results = policy_results or {"sector": "general_saas", "policy_source": "sector_baseline", "checks": []}
        raw_findings = cls._load_list_artifact(os.path.join(workspace_path, "stage2_multi_hunter_findings.json"))
        reviewed_findings = cls._load_list_artifact(os.path.join(workspace_path, "stage3_all_findings.json"))
        if not reviewed_findings:
            reviewed_findings = [dict(f, status=f.get("status", "CONFIRMED")) for f in verified_findings]
        rejected_findings = [f for f in reviewed_findings if f.get("status") == "FALSE_POSITIVE"]
        unresolved_findings = [f for f in reviewed_findings if f.get("status") in {"UNKNOWN", "UNRESOLVED"}]

        def severity_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
            return {severity: sum(1 for item in items if item.get("severity", "MEDIUM").upper() == severity)
                    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

        def tool_name(item: Dict[str, Any]) -> str:
            return str(item.get("source") or item.get("tool") or item.get("scanner") or "Unknown scanner")

        # These are evidence-backed scan outcomes.  This is not an ML model
        # benchmark, so SentinelAI does not ask users for labels or fabricate
        # false-negative, recall, F1, or accuracy values.
        tools: Dict[str, Dict[str, Any]] = {}
        for item in raw_findings:
            name = tool_name(item)
            row = tools.setdefault(name, {
                "tool": name, "total": 0, "confirmed": 0,
                "false_positives": 0, "unresolved": 0,
            })
            row["total"] += 1
        for item in reviewed_findings:
            name = tool_name(item)
            row = tools.setdefault(name, {
                "tool": name, "total": 0, "confirmed": 0,
                "false_positives": 0, "unresolved": 0,
            })
            status = str(item.get("status", "UNRESOLVED")).upper()
            if status == "CONFIRMED":
                row["confirmed"] += 1
            elif status == "FALSE_POSITIVE":
                row["false_positives"] += 1
            else:
                row["unresolved"] += 1
        for row in tools.values():
            resolved = row["confirmed"] + row["false_positives"]
            row["reviewed_rate"] = round((resolved / row["total"]) * 100, 1) if row["total"] else 0.0
            row["confirmed_rate"] = round((row["confirmed"] / row["total"]) * 100, 1) if row["total"] else 0.0

        final_output = {
            "scan_id": scan_id,
            "raw_findings_count": raw_findings_count or len(raw_findings),
            "total_findings": len(verified_findings),
            "critical_count": len([f for f in verified_findings if f.get("severity") == "CRITICAL"]),
            "high_count": len([f for f in verified_findings if f.get("severity") == "HIGH"]),
            "medium_count": len([f for f in verified_findings if f.get("severity") == "MEDIUM"]),
            "low_count": len([f for f in verified_findings if f.get("severity") == "LOW"]),
            "findings": verified_findings,
            "raw_findings": raw_findings,
            "reviewed_findings": reviewed_findings,
            "rejected_findings": rejected_findings,
            "unresolved_findings": unresolved_findings,
            "verification_matrix": {
                "raw_total": raw_findings_count or len(raw_findings),
                "reviewed_total": len(reviewed_findings),
                "confirmed_total": len(verified_findings),
                "false_positive_total": len(rejected_findings),
                "unresolved_total": len(unresolved_findings),
                "raw_by_severity": severity_counts(raw_findings),
                "confirmed_by_severity": severity_counts(verified_findings),
                "per_tool": sorted(tools.values(), key=lambda row: (-row["total"], row["tool"].lower())),
                "metric_notice": "Per-scanner outcomes from this scan: confirmed findings, false positives, and findings that need further review.",
            },
            "chains": chains,
            "policy_compliance": policy_results
        }

        # Save stage4_correlated_findings.json & final_output.json
        stage4_path = f"{workspace_path}/stage4_correlated_findings.json"
        final_path = f"{workspace_path}/final_output.json"

        try:
            with open(stage4_path, "w", encoding="utf-8") as f:
                json.dump(chains, f, indent=2)
            with open(final_path, "w", encoding="utf-8") as f:
                json.dump(final_output, f, indent=2)
        except Exception as e:
            print(f"[ChainCorrelationService] Error saving outputs: {e}")

        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_4_CORRELATION",
            event_type="STAGE_COMPLETE",
            message=f"Stage 4 complete. Built {len(chains)} attack chains. Finalized canonical finding output."
        )

        return final_output
