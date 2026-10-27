"""
CVE lookup service for SentinelAI.

After Stage 2 collects dependency-level vulnerability findings (Trivy), this
service enriches each finding with a CVSS v3.1 score and an authoritative
CVE description by querying:

  1. Local SQLite/Postgres database (cve_reference, kev_flags) — fast, offline
  2. OSV.dev  (https://api.osv.dev/v1/query) — open-source vulnerability
     database. Free, no auth, very fast, excellent for npm/PyPI/Maven packages.
  3. NVD CVE 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0) — the
     canonical US National Vulnerability Database.

The local DB is populated by CVEIngestionService.refresh_all() (run daily).
If a CVE is missing locally, OSV/NVD are queried and results are cached.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, List, Optional

from app.core.config import settings
from app.models.cve_reference import CVERepository


_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "..", "runtime", "cve_cache",
)
os.makedirs(_CACHE_DIR, exist_ok=True)


# In-process cache: avoids re-hitting the network within the same scan.
_MEMO: Dict[str, Dict[str, Any]] = {}


def _cache_key(query: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(query, sort_keys=True).encode("utf-8")).hexdigest()[:32]


def _cache_path(key: str) -> str:
    return os.path.join(_CACHE_DIR, f"{key}.json")


def _read_cache(key: str) -> Optional[Dict[str, Any]]:
    if key in _MEMO:
        return _MEMO[key]
    p = _cache_path(key)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            _MEMO[key] = data
            return data
        except Exception:
            return None
    return None


def _write_cache(key: str, data: Dict[str, Any]) -> None:
    _MEMO[key] = data
    try:
        with open(_cache_path(key), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _http_post_json(url: str, payload: Dict[str, Any], timeout: int = 15) -> Optional[Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "SentinelAI/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
        return None


def _http_get_json(url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelAI/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
        return None


# ---------------------------------------------------------------------------
# OSV.dev lookup
# ---------------------------------------------------------------------------

def _lookup_osv(pkg_name: str, pkg_version: str, ecosystem: str = "PyPI") -> Dict[str, Any]:
    """
    Query OSV.dev for vulnerabilities affecting a given package + version.
    Returns a list of {id, summary, cvss_score, cvss_vector, aliases}.
    """
    if not pkg_name:
        return {"vulns": [], "source": "osv", "error": "missing package name"}

    payload = {
        "package": {"name": pkg_name, "ecosystem": ecosystem},
        "version": pkg_version or "",
    }
    key = _cache_key({"src": "osv", **payload})
    cached = _read_cache(key)
    if cached is not None:
        return cached

    data = _http_post_json("https://api.osv.dev/v1/query", payload)
    if not data:
        return _write_cache(key, {"vulns": [], "source": "osv", "error": "network error"}) and {"vulns": [], "source": "osv", "error": "network error"}

    vulns_out: List[Dict[str, Any]] = []
    for v in data.get("vulns", []) or []:
        # OSV sometimes returns aliases that include CVE-xxxx-xxxx
        aliases = v.get("aliases", []) or []
        cve_ids = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
        if v.get("id", "").startswith("CVE-"):
            cve_ids.append(v["id"])

        cvss_score = None
        cvss_vector = None
        for sev in v.get("severity", []) or []:
            if isinstance(sev, dict):
                score = sev.get("score", "")
                # OSV scores look like "CVSS:3.1/AV:N/AC:L/..." or numeric
                if "CVSS:3" in str(score):
                    cvss_vector = score
                try:
                    cvss_score = float(score)
                except (TypeError, ValueError):
                    pass

        # OSV also exposes a database_specific block with GHSA data
        ghsa = (v.get("database_specific") or {}).get("severity", "")
        if not cvss_score and ghsa:
            sev_to_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.5}
            cvss_score = sev_to_score.get(ghsa.upper())

        vulns_out.append({
            "id": v.get("id", ""),
            "summary": (v.get("summary") or v.get("details", ""))[:500],
            "cve_ids": cve_ids,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
        })

    result = {"vulns": vulns_out, "source": "osv"}
    _write_cache(key, result)
    return result


# ---------------------------------------------------------------------------
# NVD lookup (per-CVE-id)
# ---------------------------------------------------------------------------

def _lookup_nvd(cve_id: str) -> Dict[str, Any]:
    """Fetch a single CVE record from NVD. Returns cvss_score + vector."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return {"cve_id": cve_id, "cvss_score": None, "cvss_vector": None, "source": "nvd", "error": "invalid id"}

    key = _cache_key({"src": "nvd", "cve": cve_id})
    cached = _read_cache(key)
    if cached is not None:
        return cached

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
    data = _http_get_json(url, timeout=20)
    if not data or not data.get("vulnerabilities"):
        return _write_cache(key, {"cve_id": cve_id, "cvss_score": None, "cvss_vector": None, "source": "nvd", "error": "not found"}) and {"cve_id": cve_id, "cvss_score": None, "cvss_vector": None, "source": "nvd", "error": "not found"}

    item = data["vulnerabilities"][0].get("cve", {})
    metrics = item.get("metrics", {}) or {}

    # Try CVSS v3.1 first, then v3.0
    cvss_score = None
    cvss_vector = None
    for key_name in ("cvssMetricV31", "cvssMetricV30"):
        mlist = metrics.get(key_name, []) or []
        if mlist:
            primary = mlist[0].get("cvssData", {}) or {}
            try:
                cvss_score = float(primary.get("baseScore", 0) or 0)
            except (TypeError, ValueError):
                cvss_score = None
            cvss_vector = primary.get("vectorString", "")
            break

    descriptions = item.get("descriptions", []) or []
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = (d.get("value") or "")[:500]
            break

    result = {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "description": description,
        "source": "nvd",
    }
    _write_cache(key, result)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_dependency_vuln(
    pkg_name: str,
    pkg_version: str,
    ecosystem: str = "PyPI",
) -> Dict[str, Any]:
    """
    Look up vulnerabilities for a single (package, version) tuple. Returns
    the best-available CVSS score, vector, and a short description.

    Priority:
    1. Local DB (cve_reference) — fast, offline, authoritative
    2. OSV.dev — excellent for open-source ecosystems
    3. NVD — canonical source for CVSS vectors
    """
    # First, try to find CVEs for this package from the local DB
    # Note: cve_reference is indexed by CVE ID, not package name.
    # We still need OSV/NVD to find which CVEs affect a given package.
    # But if Stage 2 already found a CVE ID (from Trivy), we can look it up locally.

    osv_result = _lookup_osv(pkg_name, pkg_version, ecosystem)
    vulns = osv_result.get("vulns", []) or []
    best = None
    if vulns:
        # Pick the highest-CVSS vuln
        vulns.sort(key=lambda v: (v.get("cvss_score") or 0), reverse=True)
        best = vulns[0]

    enriched: Dict[str, Any] = {
        "pkg": pkg_name,
        "version": pkg_version,
        "ecosystem": ecosystem,
        "osv_vulns": vulns,
        "primary_cve": (best or {}).get("cve_ids", [None])[0] if best else None,
        "cvss_score": (best or {}).get("cvss_score"),
        "cvss_vector": (best or {}).get("cvss_vector"),
        "summary": (best or {}).get("summary", ""),
        "kev_flag": False,
    }

    # If we have a CVE ID, check local DB first for authoritative CVSS + KEV flag
    if enriched["primary_cve"]:
        cve_id = enriched["primary_cve"]
        local_cve = CVERepository.get_by_cve(cve_id)
        if local_cve:
            # Use local DB data (authoritative)
            enriched["cvss_score"] = local_cve.get("cvss_score")
            enriched["cvss_vector"] = local_cve.get("cvss_vector")
            enriched["summary"] = local_cve.get("description", enriched["summary"])
            # Check KEV flag
            kev = CVERepository.get_kev_flag(cve_id)
            enriched["kev_flag"] = kev is not None
        else:
            # Fall back to NVD for CVSS vector + description
            nvd = _lookup_nvd(cve_id)
            if nvd.get("cvss_score") is not None:
                enriched["cvss_score"] = nvd["cvss_score"]
                enriched["cvss_vector"] = nvd["cvss_vector"]
            if nvd.get("description"):
                enriched["summary"] = nvd["description"]

    return enriched


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    In-place enrichment of a list of Stage 2 findings. For each finding
    with a `package` and `version` (or evidence that mentions them), we
    attach CVE/CVSS data. Findings without dependency context are passed
    through unchanged.
    """
    for f in findings:
        pkg, ver, eco = _extract_pkg(f)
        if not pkg:
            continue
        try:
            enriched = enrich_dependency_vuln(pkg, ver, eco)
        except Exception as e:
            print(f"[CVELookup] Enrichment failed for {pkg}@{ver}: {e}")
            continue
        if enriched.get("primary_cve"):
            f.setdefault("cve_ids", []).append(enriched["primary_cve"])
        if enriched.get("cvss_score") is not None:
            f["cvss_score"] = enriched["cvss_score"]
        if enriched.get("cvss_vector"):
            f["cvss_vector"] = enriched["cvss_vector"]
        if enriched.get("summary") and not f.get("severity_summary"):
            f["severity_summary"] = enriched["summary"]
    return findings


def _extract_pkg(finding: Dict[str, Any]) -> tuple:
    """
    Best-effort extract (package, version, ecosystem) from a finding. The
    shapes come from Trivy's JSON output and from common lockfile parsers.
    """
    ev = " ".join(finding.get("evidence", []) or [])
    eco = "PyPI"
    if "npm" in ev.lower() or "package.json" in (finding.get("file_path", "") or "").lower():
        eco = "npm"
    elif "pom.xml" in (finding.get("file_path", "") or "").lower() or "gradle" in ev.lower():
        eco = "Maven"
    elif "go.mod" in (finding.get("file_path", "") or "").lower():
        eco = "Go"
    elif "cargo.toml" in (finding.get("file_path", "") or "").lower():
        eco = "crates.io"
    elif "gemfile" in (finding.get("file_path", "") or "").lower():
        eco = "RubyGems"

    # Trivy evidence looks like "Package: foo@1.2.3"
    import re
    m = re.search(r"Package:\s*([A-Za-z0-9_.@/-]+)@([0-9][A-Za-z0-9._+-]*)", ev)
    if m:
        return m.group(1), m.group(2), eco
    return "", "", eco
