"""
CVE Ingestion Service
Downloads NVD CVE 2.0 feed and CISA KEV catalog, upserts into local database.
Designed to run as a background refresh job (daily/weekly).
"""
import gzip
import json
import csv
import io
import os
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from app.models.cve_reference import CVERepository


# NVD 2.0 API endpoints
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FEED_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

# CISA KEV Catalog (updated URL as of 2024)
KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# Default years to fetch (current year + previous 2 years)
DEFAULT_YEARS = [datetime.now(timezone.utc).year, datetime.now(timezone.utc).year - 1, datetime.now(timezone.utc).year - 2]

# Request timeout
REQUEST_TIMEOUT = 120


class CVEIngestionService:

    @classmethod
    def download_nvd_feed(cls, year: int) -> List[Dict[str, Any]]:
        """
        Download and parse NVD 2.0 JSON feed for a specific year.
        Returns list of CVE dicts ready for upsert.
        """
        url = NVD_FEED_URL_TEMPLATE.format(year=year)
        print(f"[CVEIngestion] Downloading NVD feed for {year}: {url}")

        try:
            req = Request(url, headers={"User-Agent": "SentinelAI/1.0"})
            with urlopen(req, timeout=REQUEST_TIMEOUT) as response:
                if response.status != 200:
                    raise RuntimeError(f"NVD feed HTTP {response.status}")
                gz_data = response.read()

            # Decompress gzip
            with gzip.GzipFile(fileobj=io.BytesIO(gz_data)) as gz:
                json_data = gz.read().decode("utf-8")

            data = json.loads(json_data)
            vulnerabilities = data.get("vulnerabilities", [])
            print(f"[CVEIngestion] NVD {year}: {len(vulnerabilities)} vulnerabilities")

            cves = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break

                # Extract CVSS v3.1 metrics
                cvss_score = None
                cvss_vector = ""
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        cvss_data = m.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString", "")
                        break

                # Determine severity from CVSS score
                severity = "UNKNOWN"
                if cvss_score is not None:
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    elif cvss_score > 0:
                        severity = "LOW"

                # Published / last modified dates
                published_date = cve.get("published")
                last_modified = cve.get("lastModified")

                cves.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "severity": severity,
                    "published_date": published_date,
                    "last_modified": last_modified,
                    "raw_json": cve,
                    "source": "NVD",
                })

            return cves

        except Exception as e:
            print(f"[CVEIngestion] Error downloading NVD {year}: {e}")
            return []

    @classmethod
    def download_kev_csv(cls) -> List[Dict[str, Any]]:
        """
        Download and parse CISA Known Exploited Vulnerabilities CSV.
        Returns list of KEV dicts ready for upsert.
        """
        print(f"[CVEIngestion] Downloading KEV catalog: {KEV_CSV_URL}")

        try:
            req = Request(KEV_CSV_URL, headers={"User-Agent": "SentinelAI/1.0"})
            with urlopen(req, timeout=REQUEST_TIMEOUT) as response:
                if response.status != 200:
                    raise RuntimeError(f"KEV CSV HTTP {response.status}")
                csv_data = response.read().decode("utf-8")

            reader = csv.DictReader(io.StringIO(csv_data))
            kev_entries = []
            for row in reader:
                cve_id = row.get("cveID", "").strip().upper()
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                kev_entries.append({
                    "cve_id": cve_id,
                    "added_date": row.get("dateAdded", "").strip() or None,
                    "vuln_name": row.get("vulnerabilityName", "").strip(),
                    "short_description": row.get("shortDescription", "").strip(),
                    "required_action": row.get("requiredAction", "").strip(),
                    "due_date": row.get("dueDate", "").strip() or None,
                })

            print(f"[CVEIngestion] KEV catalog: {len(kev_entries)} entries")
            return kev_entries

        except Exception as e:
            print(f"[CVEIngestion] Error downloading KEV: {e}")
            return []

    @classmethod
    def refresh_all(cls, years: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Full refresh: download NVD feeds for given years + KEV catalog,
        upsert into database. Returns summary counts.
        """
        if years is None:
            years = DEFAULT_YEARS

        print(f"[CVEIngestion] Starting full refresh for years: {years}")

        # Download and upsert NVD feeds
        total_cves = 0
        for year in years:
            cves = cls.download_nvd_feed(year)
            if cves:
                inserted = CVERepository.upsert_many(cves)
                total_cves += inserted
                print(f"[CVEIngestion] Upserted {inserted} CVEs from {year}")

        # Download and upsert KEV
        kev_entries = cls.download_kev_csv()
        kev_count = 0
        if kev_entries:
            kev_count = CVERepository.upsert_kev_many(kev_entries)
            print(f"[CVEIngestion] Upserted {kev_count} KEV entries")

        # Return summary
        summary = {
            "cves_upserted": total_cves,
            "kev_upserted": kev_count,
            "years_processed": years,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_cves_in_db": CVERepository.count_cves(),
            "total_kev_in_db": CVERepository.count_kev(),
        }
        print(f"[CVEIngestion] Refresh complete: {summary}")
        return summary

    @classmethod
    def refresh_incremental(cls) -> Dict[str, Any]:
        """
        Incremental refresh: only fetch current year NVD + KEV.
        Faster for daily runs.
        """
        current_year = datetime.now(timezone.utc).year
        return cls.refresh_all(years=[current_year])


def init_db():
    from app.core.database import init_db as _init_db
    _init_db()


# CLI entry point for manual runs
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--incremental":
        result = CVEIngestionService.refresh_incremental()
    else:
        result = CVEIngestionService.refresh_all()
    print(json.dumps(result, indent=2))