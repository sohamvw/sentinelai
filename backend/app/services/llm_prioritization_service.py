"""
Stage 1 — Repository tree mapping + LLM-driven file prioritization.

Why this stage exists
---------------------
Multi-tool scanners (Semgrep, Bandit, Trivy, Gitleaks, Bearer, SpotBugs) are
expensive. Running every one of them against every file in a 10k-file monorepo
is wasteful. Stage 1 trims the working set down to the files that are
*security-relevant*, ranked by priority:

  1. Always pick the files that look like auth / payment / config / entry
     points, regardless of what the LLM says. These are non-negotiable.
  2. Hand the LLM a compact directory-level tree (not a flat file list) so it
     can use spatial reasoning to spot which directories are critical.
  3. Combine the LLM's selection with the heuristic selection, de-duplicate,
     and cap the result so Stage 2 doesn't blow up.

The output is:
  - `tree.json` — the compact tree artifact
  - `stage1_llm_selection.json` — the LLM response (for audit)
  - the returned dict — used by the scan pipeline to drive Stage 2
"""
import json
import os
import re
from collections import defaultdict
from typing import Dict, Any, List

from app.services.llm_provider_service import LLMProviderService
from app.services.audit_log_service import AuditLogService


# Files that are *always* security-relevant. Even if the LLM disagrees, these
# must be scanned. Patterns are case-insensitive substrings; one match is
# enough to flag the file.
HIGH_PRIORITY_PATH_PATTERNS = [
    # Auth / identity / session
    r"auth", r"login", r"logout", r"register", r"sign[_-]?up",
    r"password", r"session", r"jwt", r"oauth", r"token", r"permission",
    r"role", r"rbac", r"acl", r"credential", r"verify[_-]?otp",
    # Money / payments
    r"payment", r"checkout", r"billing", r"invoice", r"stripe",
    r"paypal", r"razorpay", r"order", r"cart",
    # Sensitive data handling
    r"card", r"kyc", r"aadhaar", r"pan", r"ssn", r"phi",
    r"medical", r"patient", r"health",
    # Configuration / entry points
    r"config", r"settings", r"\.env", r"secret", r"credential",
    r"main\.(py|js|ts|go|java)", r"app\.(py|js|ts)",
    r"server\.(py|js|ts|go)", r"index\.(js|ts)",
    r"router", r"routes?/", r"endpoints?/",
    # Database
    r"models?\.(py|js|ts|go)", r"schema", r"migration",
    r"alembic", r"sequelize", r"prisma", r"sqlalchemy",
    # API surface
    r"api/", r"controllers?/", r"handlers?/", r"views?\.py",
    r"middleware", r"guards?",
    # Infrastructure
    r"dockerfile", r"docker-compose", r"terraform", r"k8s",
    r"kubernetes", r"helm", r"ansible",
    # Build / CI
    r"\.github/workflows", r"jenkins", r"gitlab-ci", r"circleci",
    # NOTE: test code is intentionally NOT a priority match here. The
    # exclusion list below drops most test files; if a test file is a real
    # attack surface (e.g. test_seed.py with hardcoded creds) the LLM can
    # still surface it via `additional_files`.
]

# Files that should *never* be selected, even by the LLM — they're noise.
EXCLUDED_PATH_PATTERNS = [
    r"node_modules/", r"dist/", r"build/", r"\.next/",
    r"coverage/", r"\.venv/", r"venv/",
    r"\.git/", r"__pycache__/",
    r"\.lock\.json$", r"package-lock\.json$", r"yarn\.lock$",
    r"\.min\.js$", r"\.min\.css$",
    r"static/assets?/", r"public/assets?/",
    r"docs?/", r"README\.md$", r"CHANGELOG\.md$",
    r"\.png$", r"\.jpg$", r"\.jpeg$", r"\.gif$", r"\.svg$",
    r"\.ico$", r"\.woff", r"\.ttf$", r"\.eot$",
    r"\.mp4$", r"\.mp3$", r"\.wav$", r"\.pdf$", r"\.zip$",
    r"migrations?/\d{3,}_",  # auto-generated alembic migrations (low signal)
]


def _is_excluded(path: str) -> bool:
    p = path.lower().replace("\\", "/")
    for pat in EXCLUDED_PATH_PATTERNS:
        if re.search(pat, p):
            return True
    return False


def _is_high_priority(path: str) -> bool:
    p = path.lower().replace("\\", "/")
    for pat in HIGH_PRIORITY_PATH_PATTERNS:
        if re.search(pat, p):
            return True
    return False


def _build_directory_tree(file_paths: List[str], max_depth: int = 4) -> Dict[str, Any]:
    """
    Convert a flat list of file paths into a compact directory tree. The tree
    shape is what an LLM can reason about spatially — 'auth/' has 5 files,
    'api/routes/' has 12 — much cheaper than passing every filename.
    """
    tree: Dict[str, Any] = {"_files": [], "_total": 0}

    def _insert(node: Dict[str, Any], parts: List[str], full_path: str) -> None:
        if not parts:
            return
        head, *rest = parts
        if not rest:
            # Leaf file
            node["_files"].append(full_path)
        else:
            child = node.setdefault(head, {"_files": [], "_total": 0})
            _insert(child, rest, full_path)

    for fp in file_paths:
        if _is_excluded(fp):
            continue
        parts = fp.split("/")[: max_depth + 1]
        _insert(tree, parts, fp)

    # Compute totals
    def _totals(node: Dict[str, Any]) -> int:
        n = len(node.get("_files", []))
        for k, v in node.items():
            if k == "_files":
                continue
            if isinstance(v, dict):
                n += _totals(v)
        node["_total"] = n
        return n

    _totals(tree)
    return tree


def _tree_to_compact_dict(node: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """Convert internal tree into a JSON-friendly form, dropping noise dirs."""
    if depth > 5:
        return {"_count": node.get("_total", 0)}
    out: Dict[str, Any] = {}
    children: List[tuple] = []
    for k, v in node.items():
        if k == "_files":
            continue
        if isinstance(v, dict):
            children.append((k, v))
    # Sort: directories with more files first (security-critical dirs come up top)
    children.sort(key=lambda kv: kv[1].get("_total", 0), reverse=True)
    for k, v in children[:20]:  # cap per-level to 20 entries
        out[k] = _tree_to_compact_dict(v, depth + 1)
    if node.get("_files"):
        out["_files"] = sorted(node["_files"])[:10]  # max 10 file names per dir
    out["_count"] = node.get("_total", 0)
    return out


class Stage1LLMPrioritizationService:

    @classmethod
    def run(cls, scan_id: str, workspace_path: str, repository_model: Any) -> Dict[str, Any]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_1_TREE_MAPPING",
            event_type="STAGE_START",
            message="Building repository tree metadata & invoking LLM file prioritization harness..."
        )

        # 1. Collect every file path
        all_files: List[Any] = list(getattr(repository_model, "files", {}).values())
        file_paths: List[str] = []
        file_info_by_path: Dict[str, Any] = {}
        for f in all_files:
            rel = str(getattr(f, "relative_path", "")).replace("\\", "/")
            if not rel:
                continue
            file_paths.append(rel)
            file_info_by_path[rel] = f

        # 2. Deterministic heuristic pre-selection
        heuristic_priority_1 = sorted(
            [p for p in file_paths if _is_high_priority(p) and not _is_excluded(p)]
        )
        excluded_by_heuristic = sorted(
            [p for p in file_paths if _is_excluded(p)]
        )

        # Cap the heuristic priority-1 list — repos can have hundreds of routes
        # and we don't want to push the LLM too hard. 200 is plenty.
        heuristic_priority_1_capped = heuristic_priority_1[:200]

        # 3. Build compact directory tree for the LLM
        compact_tree = _tree_to_compact_dict(_build_directory_tree(file_paths))

        # 4. Trim tree if it's still too large (LLM context is precious)
        tree_metadata = {
            "total_files": len(file_paths),
            "total_after_exclusion": len(file_paths) - len(excluded_by_heuristic),
            "heuristic_priority_1_count": len(heuristic_priority_1),
            "heuristic_priority_1_sample": heuristic_priority_1_capped[:60],
            "directory_tree": compact_tree,
        }

        # Save tree.json artifact
        tree_json_path = os.path.join(workspace_path, "tree.json")
        try:
            with open(tree_json_path, "w", encoding="utf-8") as f:
                json.dump(tree_metadata, f, indent=2)
        except Exception as e:
            print(f"[Stage1] Error saving tree.json: {e}")

        # 5. LLM selection — only feed the compact tree, never the full file list
        prompt = f"""
You are SentinelAI's Stage 1 Repository Analyzer.
We have already pre-selected the obvious security-critical files (auth, payment, config, entry points, database models, API routes, infra).
Your job is to add any *additional* files that a human security reviewer would flag but the heuristic would miss — for example:
- Custom middleware that handles user input
- Webhook handlers
- File-upload endpoints
- Database migration files
- Internal admin endpoints
- Custom cryptography or hashing modules
- Environment variable / secrets loaders
- Logging modules that may leak sensitive data

Repository directory tree (each directory shows file count; high counts first):
{json.dumps(compact_tree, indent=2)[:6000]}

Heuristic priority-1 candidate sample (these are already in the scan set, you do NOT need to re-pick them):
{heuristic_priority_1_capped[:40]}

Return ONLY a valid JSON object:
{{
  "framework": "main framework/language",
  "confidence": 0.0-1.0,
  "additional_files": [{{ "path": "...", "priority": 1, "reason": "..." }}],
  "excluded_files": [{{ "path": "...", "reason": "..." }}]
}}
"""
        system_prompt = (
            "You are a senior security researcher analyzing repository folder "
            "trees to map security-critical files. Be conservative — only "
            "suggest files that genuinely need scanning."
        )

        cfg = LLMProviderService.get_settings()
        active_model = cfg.get("primary_model", "qwen/qwen-2.5-coder-32b-instruct")

        llm_response_str = LLMProviderService.call_llm(
            prompt=prompt,
            system_prompt=system_prompt,
            json_mode=True,
        )

        # 6. Parse LLM response (with robust fallback)
        llm_additional: List[Dict[str, Any]] = []
        llm_excluded: List[Dict[str, Any]] = []
        llm_framework = "Unknown"
        llm_confidence = 0.0
        try:
            # Sometimes the LLM wraps JSON in ```json fences
            stripped = llm_response_str.strip()
            if stripped.startswith("```"):
                m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
                if m:
                    stripped = m.group(1)
            parsed = json.loads(stripped)
            llm_framework = parsed.get("framework", "Unknown")
            llm_confidence = float(parsed.get("confidence", 0.0))
            llm_additional = parsed.get("additional_files", []) or []
            llm_excluded = parsed.get("excluded_files", []) or []
        except Exception as e:
            # LLM failed or returned invalid JSON - proceed with heuristic-only results
            print(f"[Stage1] LLM response parse failed: {e}; proceeding with heuristic-only file selection.")
            llm_framework = "Unknown"
            llm_confidence = 0.0
            llm_additional = []
            llm_excluded = []

        # 7. Merge heuristic priority-1 + LLM additional; de-duplicate
        all_selected: List[Dict[str, Any]] = []
        seen_paths: set = set()

        for p in heuristic_priority_1_capped:
            if p in seen_paths:
                continue
            seen_paths.add(p)
            all_selected.append({
                "path": p,
                "priority": 1,
                "reason": "Heuristic match: security-critical path",
                "source": "heuristic",
            })

        for entry in llm_additional:
            p = str(entry.get("path", "")).strip()
            if not p or p in seen_paths:
                continue
            if _is_excluded(p):
                continue
            seen_paths.add(p)
            all_selected.append({
                "path": p,
                "priority": int(entry.get("priority", 2) or 2),
                "reason": entry.get("reason", "LLM suggestion"),
                "source": "llm",
            })

        # If the LLM identified a *broader* framework we hadn't tagged, use it
        framework = llm_framework
        confidence = llm_confidence

        # 8. Cap final list (Stage 2 will iterate this; we don't want unbounded)
        MAX_FILES = 300
        priority1 = [f for f in all_selected if f["priority"] == 1][:MAX_FILES]
        priority2 = [f for f in all_selected if f["priority"] == 2][:MAX_FILES]
        priority3 = [f for f in all_selected if f["priority"] == 3][:50]
        final = priority1 + priority2 + priority3

        selection_result = {
            "framework": framework,
            "confidence": confidence,
            "selected_files": final,
            "excluded_files": llm_excluded + [
                {"path": p, "reason": "heuristic-excluded: noise asset / build artifact"}
                for p in excluded_by_heuristic[:30]
            ],
            "stats": {
                "total_files_in_repo": len(file_paths),
                "excluded_by_heuristic": len(excluded_by_heuristic),
                "heuristic_priority_1": len(heuristic_priority_1),
                "llm_additional": len(llm_additional),
                "final_selected": len(final),
            },
        }

        # Save stage1_llm_selection.json artifact
        selection_json_path = os.path.join(workspace_path, "stage1_llm_selection.json")
        try:
            with open(selection_json_path, "w", encoding="utf-8") as f:
                json.dump(selection_result, f, indent=2)
        except Exception as e:
            print(f"[Stage1] Error saving stage1_llm_selection.json: {e}")

        AuditLogService.log_event(
            scan_id=scan_id,
            stage="STAGE_1_TREE_MAPPING",
            event_type="STAGE_COMPLETE",
            message=(
                f"Stage 1 complete. Detected framework '{framework}'. "
                f"Selected {len(final)} priority files "
                f"(heuristic: {len(heuristic_priority_1_capped)}, llm additional: {len(llm_additional)})."
            ),
            model_used=active_model,
            payload={
                "framework": framework,
                "selected_count": len(final),
                "stats": selection_result["stats"],
            },
        )

        return selection_result
