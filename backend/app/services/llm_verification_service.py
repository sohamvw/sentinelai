"""
Stage 3 — LLM verification + dedupe + CVSS scoring.

Responsibilities
----------------
1. **Deterministic pre-dedupe.** Findings that point at the same (file, line)
   with overlapping evidence are already collapsed in Stage 2. Here we do a
   second pass: collapse findings that have the *same root cause* even if
   they landed on different lines (e.g. multiple AST rules all flagging the
   same f-string SQL injection).
2. **Skip the LLM when the answer is obvious.** A Trivy finding with a CVE
   id and CVSS ≥ 9.0 from NVD is *already* confirmed. Sending it back
   through the LLM just to ask "is this real?" is wasteful and risks the
   LLM downgrading a high-confidence CVE.
3. **Batched LLM verification.** Remaining ambiguous findings are batched
   (up to 8 at a time) so a single LLM call processes multiple findings.
   CVSS belongs to authoritative dependency/CVE evidence, never to an LLM.
"""
import json
import os
import re
from typing import List, Dict, Any, Optional, Tuple

from app.services.llm_provider_service import LLMProviderService
from app.services.audit_log_service import AuditLogService


# CVSS v3.1 base-score table. We only ship the metric values we actually
# emit in our prompts; the verifier fills in any unknown metric as the
# "worst" default for the dimension to stay conservative.
_CVSS_METRICS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        # PR depends on scope; we approximate using the "U" (unchanged) row
        "N": {"N": 0.85, "L": 0.62, "H": 0.27}.get("N", 0.85),
        "L": {"N": 0.85, "L": 0.62, "H": 0.27}.get("L", 0.62),
        "H": {"N": 0.85, "L": 0.62, "H": 0.27}.get("H", 0.27),
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 6.42, "C": 7.52},  # base shift; we don't compute Impact sub-score
    "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0, "L": 0.22, "H": 0.56},
}


def compute_cvss_score(vector: str) -> Optional[float]:
    """
    Parse a CVSS v3.1 vector and return a base score (0.0 - 10.0). Returns
    None if the vector can't be parsed. This is a simplified scorer that
    matches the official spec for the common combinations we use; for the
    full formula, see https://www.first.org/cvss/v3.1/specification-document.
    """
    if not vector or not isinstance(vector, str):
        return None
    if not vector.startswith("CVSS:3"):
        return None
    parts = vector.split("/")
    metrics: Dict[str, str] = {}
    for p in parts[1:]:
        kv = p.split(":", 1)
        if len(kv) == 2:
            metrics[kv[0]] = kv[1]
    # Required metrics
    for required in ("AV", "AC", "UI", "S", "C", "I", "A"):
        if required not in metrics:
            return None
    pr = metrics.get("PR", "N")
    # PR weighting depends on scope
    pr_table = {
        ("N", "U"): {"N": 0.85, "L": 0.62, "H": 0.27},
        ("C", "U"): {"N": 0.85, "L": 0.68, "H": 0.5},
        ("N", "C"): {"N": 0.85, "L": 0.62, "H": 0.27},
        ("C", "C"): {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    pr_value = pr_table.get((pr, metrics["S"]), {}).get(metrics["PR"], 0.62)

    iss = 1.0 - (1 - _CVSS_METRICS["C"][metrics["C"]]) * \
                  (1 - _CVSS_METRICS["I"][metrics["I"]]) * \
                  (1 - _CVSS_METRICS["A"][metrics["A"]])
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * _CVSS_METRICS["AV"][metrics["AV"]] * \
                              _CVSS_METRICS["AC"][metrics["AC"]] * \
                              pr_value * \
                              _CVSS_METRICS["UI"][metrics["UI"]]
    if impact <= 0:
        return 0.0

    if metrics["S"] == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    # Round to one decimal (CVSS spec)
    return round(base, 1)


def severity_from_score(score: Optional[float]) -> str:
    """Map a 0-10 CVSS score to a severity bucket (CVSS v3.1 spec)."""
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


# ---------------------------------------------------------------------------
# Deterministic pre-dedupe
# ---------------------------------------------------------------------------

def _deterministic_dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapse findings that have the *same title* in the *same file* —
    a heuristic that catches the case where the AST scanner emits two
    separate findings ("unsafe dynamic query construction" and "SQL
    injection via f-string") for the same line.
    """
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in findings:
        key = (f.get("file_path", ""), (f.get("title") or "").lower())
        if key not in seen:
            seen[key] = dict(f)
            continue
        # Keep the higher severity and merge evidence
        existing = seen[key]
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if sev_rank.get(f.get("severity", "MEDIUM").upper(), 5) < sev_rank.get(existing.get("severity", "MEDIUM").upper(), 5):
            existing["severity"] = f.get("severity", existing["severity"])
        for e in f.get("evidence", []) or []:
            if e and e not in existing.get("evidence", []):
                existing.setdefault("evidence", []).append(e)
        for c in f.get("cve_ids", []) or []:
            if c and c not in existing.get("cve_ids", []):
                existing.setdefault("cve_ids", []).append(c)
    return list(seen.values())


# ---------------------------------------------------------------------------
# LLM verification — batched
# ---------------------------------------------------------------------------

_BATCH_SIZE = 6
_MAX_LLM_FINDINGS = int(os.getenv("SENTINEL_MAX_LLM_FINDINGS", "24"))


def _should_skip_llm(finding: Dict[str, Any]) -> bool:
    """
    True iff the finding has a CVE id AND a CVSS score already attached —
    i.e. Stage 2b already enriched it from NVD/OSV. Sending it back
    through the LLM adds nothing and risks the LLM downgrading it.
    """
    cves = finding.get("cve_ids") or []
    score = finding.get("cvss_score")
    return bool(cves) and isinstance(score, (int, float)) and score >= 7.0


def _verify_batch(findings: List[Dict[str, Any]], active_model: str, policy_context: str = "") -> List[Dict[str, Any]]:
    """Run one LLM call that verifies all findings in a batch."""
    if not findings:
        return []

    findings_block = "\n\n".join(
        f"--- FINDING {i} ---\n{json.dumps(f, indent=2)[:1500]}"
        for i, f in enumerate(findings)
    )
    prompt = f"""
You are SentinelAI's Stage 3 Definitive Security Judge.
For EACH of the following {len(findings)} findings, decide whether it is a real vulnerability or a false positive.

For every finding, return a JSON object in the "verdicts" array with this exact shape:
{{
  "index": <0-based integer matching the finding number above>,
  "verdict": "CONFIRMED" or "FALSE_POSITIVE",
  "confidence": float between 0.0 and 1.0,
  "reasoning": "one short paragraph",
  "remediation": "concrete code fix"
}}

Rules:
- Be conservative. Only mark FALSE_POSITIVE if you can articulate WHY this
  is genuinely safe (e.g. the input is sanitized elsewhere, the function
  is unreachable, the value is hard-coded).
- Do not create, change, or estimate CVSS, CVE, CPE, PURL, or affected
  version data. Preserve source-backed values already in the finding.
- Compliance-control statuses are deterministic assessment evidence. Use them
  only to explain impact/remediation; do not invent, upgrade, or override a
  control result.

Findings to verify:
{findings_block}

Applicable compliance-control evidence (may be empty):
{policy_context or "No policy context was supplied for this scan."}
"""
    system_prompt = (
        "You are a definitive security engineer conducting code review. "
        "Eliminate false alarms strictly while ensuring zero true "
        "vulnerabilities are missed."
    )

    response_str = LLMProviderService.call_llm(
        prompt=prompt,
        system_prompt=system_prompt,
        json_mode=True,
    )

    verdicts: List[Dict[str, Any]] = []
    try:
        stripped = response_str.strip()
        if stripped.startswith("```"):
            m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
            if m:
                stripped = m.group(1)
        parsed = json.loads(stripped)
        if isinstance(parsed, dict) and "verdicts" in parsed:
            verdicts = parsed["verdicts"]
        elif isinstance(parsed, list):
            verdicts = parsed
        else:
            verdicts = []
    except Exception:
        # A malformed or unavailable model response is not evidence that a
        # vulnerability is real.  The caller records the scanner finding as
        # unresolved so it remains visible for human review.
        verdicts = []

    # Index verdicts back to their findings
    by_index = {int(v.get("index", -1)): v for v in verdicts}
    return [by_index.get(i, {}) for i in range(len(findings))]


class LLMVerificationService:

    @classmethod
    def verify_findings(
        cls,
        scan_id: str,
        workspace_path: str,
        raw_findings: List[Dict[str, Any]],
        policy_results: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_3_LLM_VERIFICATION",
            event_type="STAGE_START",
            message=(
                f"Starting Stage 3 LLM verification on {len(raw_findings)} "
                f"raw findings (batched, CVSS-enriched)..."
            ),
        )

        # 1. Deterministic pre-dedupe
        deduped = _deterministic_dedupe(raw_findings)
        relevant_checks = [
            {
                "control_id": check.get("rule_id"), "requirement": check.get("rule"),
                "status": check.get("status"), "source": f"{check.get('act', '')} {check.get('section', '')}".strip(),
                "evidence": check.get("evidence"),
            }
            for check in (policy_results or {}).get("checks", [])
            if check.get("status") in {"FAIL", "PARTIAL", "UNKNOWN"}
        ][:30]
        policy_context = json.dumps({
            "sector": (policy_results or {}).get("sector"),
            "controls": relevant_checks,
        }, ensure_ascii=False)

        # 2. Split into "skip LLM" (CVE + CVSS >= 7) and "needs LLM"
        # All input findings are backed by real scanner output.
        to_verify: List[Dict[str, Any]] = []
        auto_confirmed: List[Dict[str, Any]] = []
        for f in deduped:
            if _should_skip_llm(f):
                item = dict(f)
                item["status"] = "CONFIRMED"
                item["confidence"] = 0.99
                item["reasoning"] = (
                    f"Pre-verified by CVE database: {', '.join(f.get('cve_ids', []))} "
                    f"with CVSS {f.get('cvss_score')}."
                )
                item["remediation"] = "Update affected dependency to a patched version."
                auto_confirmed.append(item)
            else:
                to_verify.append(f)

        verified: List[Dict[str, Any]] = list(auto_confirmed)
        reviewed: List[Dict[str, Any]] = list(auto_confirmed)

        # Large benchmark repositories can produce thousands of valid
        # scanner records. Never turn that into an unbounded LLM queue. The
        # highest-priority records are verified; every deferred record remains
        # visible as unresolved evidence and is available for later review.
        if len(to_verify) > _MAX_LLM_FINDINGS:
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            to_verify.sort(key=lambda f: (sev_rank.get(str(f.get("severity", "MEDIUM")).upper(), 5), -(f.get("cvss_score") or 0)))
            deferred = to_verify[_MAX_LLM_FINDINGS:]
            to_verify = to_verify[:_MAX_LLM_FINDINGS]
            for finding in deferred:
                item = dict(finding)
                item["status"] = "UNRESOLVED"
                item["confidence"] = 0.0
                item["reasoning"] = f"Deferred after the {_MAX_LLM_FINDINGS}-finding LLM verification budget; scanner evidence retained for review."
                item["remediation"] = "Review this scanner result manually or run a focused verification pass."
                reviewed.append(item)
            AuditLogService.log_event(
                scan_id=scan_id,
                stage="STAGE_3_LLM_VERIFICATION",
                event_type="VERIFICATION_BUDGET_APPLIED",
                message=f"Deferred {len(deferred)} findings as unresolved; verifying top {_MAX_LLM_FINDINGS} findings with the LLM.",
            )

        # 3. LLM verification in batches
        for i in range(0, len(to_verify), _BATCH_SIZE):
            batch = to_verify[i:i + _BATCH_SIZE]
            try:
                verdicts = _verify_batch(
                    batch,
                    LLMProviderService.get_settings().get("primary_model", "qwen/qwen-2.5-coder-32b-instruct"),
                    policy_context,
                )
            except Exception as provider_error:
                # A dead/expired provider must never hold the whole scan open.
                # Preserve this batch and every later batch for human review,
                # checkpoint them, and allow Stage 4/report generation to run.
                remaining = to_verify[i:]
                reason = f"LLM verification unavailable; scanner evidence retained for review ({provider_error})."
                for pending in remaining:
                    item = dict(pending)
                    item["status"] = "UNRESOLVED"
                    item["confidence"] = 0.0
                    item["reasoning"] = reason
                    item["remediation"] = "Retry LLM verification later or review the scanner evidence manually."
                    reviewed.append(item)
                    AuditLogService.log_event(
                        scan_id=scan_id,
                        stage="STAGE_3_LLM_VERIFICATION",
                        event_type="UNRESOLVED_PROVIDER_FAILURE",
                        message=f"Preserved '{pending.get('title')}' as unresolved after provider failure.",
                        model_used=LLMProviderService.get_settings().get("primary_model", "?"),
                    )
                try:
                    with open(f"{workspace_path}/stage3_checkpoint.json", "w", encoding="utf-8") as checkpoint:
                        json.dump({"scan_id": scan_id, "processed": len(to_verify), "verified": verified, "reviewed": reviewed}, checkpoint, indent=2)
                except OSError:
                    pass
                break
            for finding, eval_res in zip(batch, verdicts):
                # A missing/malformed provider response is not confirmation.
                # Preserve the raw scanner artifact and mark it unresolved.
                verdict = (eval_res or {}).get("verdict", "UNKNOWN").upper()
                if verdict != "CONFIRMED":
                    item = dict(finding)
                    item["status"] = verdict if verdict == "FALSE_POSITIVE" else "UNRESOLVED"
                    item["confidence"] = float((eval_res or {}).get("confidence", 0) or 0)
                    item["reasoning"] = (eval_res or {}).get(
                        "reasoning",
                        "The automated verification response was unavailable or incomplete; human review is required.",
                    )
                    item["remediation"] = (eval_res or {}).get("remediation", "Review this scanner result manually.")
                    reviewed.append(item)
                    event_type = "FALSE_POSITIVE_REJECTED" if verdict == "FALSE_POSITIVE" else "UNRESOLVED"
                    AuditLogService.log_event(
                        scan_id=scan_id,
                        stage="STAGE_3_LLM_VERIFICATION",
                        event_type=event_type,
                        message=(
                            f"{verdict} '{finding.get('title')}' "
                            f"in {finding.get('file_path')}:L{finding.get('line_number')}"
                        ),
                        model_used=LLMProviderService.get_settings().get("primary_model", "?"),
                        payload=item,
                    )
                    continue
                item = dict(finding)
                item["status"] = "CONFIRMED"
                item["confidence"] = float((eval_res or {}).get("confidence", 0.9) or 0.9)
                item["reasoning"] = (eval_res or {}).get("reasoning", "")
                item["remediation"] = (eval_res or {}).get("remediation", "")
                verified.append(item)
                reviewed.append(item)

                AuditLogService.log_event(
                    scan_id=scan_id,
                    stage="STAGE_3_LLM_VERIFICATION",
                    event_type="FINDING_VERIFIED",
                    message=(
                        f"CONFIRMED '{finding.get('title')}' in "
                        f"{finding.get('file_path')}:L{finding.get('line_number')} "
                        f"(CVSS: {item.get('cvss_score', 'not source-backed')})"
                    ),
                    model_used=LLMProviderService.get_settings().get("primary_model", "?"),
                    payload=item,
                )

            # Durable checkpoint: if the process is interrupted, the evidence
            # processed so far is still available for recovery/reporting.
            try:
                with open(f"{workspace_path}/stage3_checkpoint.json", "w", encoding="utf-8") as checkpoint:
                    json.dump({"scan_id": scan_id, "processed": i + len(batch), "verified": verified, "reviewed": reviewed}, checkpoint, indent=2)
            except OSError:
                pass

        # 4. Sort by CVSS desc, then severity
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        verified.sort(
            key=lambda f: (
                -(f.get("cvss_score") or 0),
                sev_rank.get(f.get("severity", "MEDIUM").upper(), 5),
            )
        )

        # 5. Save artifact
        output_path = f"{workspace_path}/stage3_verified_findings.json"
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(verified, f, indent=2)
            with open(f"{workspace_path}/stage3_all_findings.json", "w", encoding="utf-8") as f:
                json.dump(reviewed, f, indent=2)
        except Exception as e:
            print(f"[LLMVerificationService] Error saving stage3 findings: {e}")

        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_3_LLM_VERIFICATION",
            event_type="STAGE_COMPLETE",
            message=(
                f"Stage 3 complete. {len(verified)} confirmed, "
                f"{len([f for f in reviewed if f.get('status') == 'FALSE_POSITIVE'])} rejected, "
                f"{len([f for f in reviewed if f.get('status') == 'UNRESOLVED'])} unresolved "
                f"({len(auto_confirmed)} auto-confirmed by CVE)."
            ),
        )

        return verified
