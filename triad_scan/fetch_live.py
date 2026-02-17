import os
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Iterable

import aiohttp
from sqlalchemy.dialects.sqlite import insert

from triad_scan.db import init_db, AsyncSessionLocal, VulnerabilityORM

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _iso8601_z(dt: datetime) -> str:
    # NVD accepts ISO-8601 timestamps; using UTC with "Z" keeps it unambiguous.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _extract_cvss_score(vuln_obj: dict) -> Optional[float]:
    """
    NVD 2.0 schema can include cvssMetricV31 / cvssMetricV30 / (older).
    For CRITICAL filtering, v3.x is expected; still, be defensive.
    """
    metrics = (vuln_obj.get("cve") or {}).get("metrics") or {}

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            cvss_data = (arr[0].get("cvssData") or {})
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)

    return None


def _extract_cve_id(vuln_obj: dict) -> Optional[str]:
    cve = vuln_obj.get("cve") or {}
    cve_id = cve.get("id")
    return cve_id if isinstance(cve_id, str) else None


async def fetch_nvd_critical_50(session: aiohttp.ClientSession) -> list[dict]:
    """
    Pull the most recent CRITICAL CVEs by using a sliding window (last 30 days)
    and resultsPerPage=50.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=30)

    params = {
        "resultsPerPage": "50",
        "startIndex": "0",
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": _iso8601_z(start),
        "pubEndDate": _iso8601_z(now),
    }

    async with session.get(NVD_CVES_URL, params=params) as resp:
        resp.raise_for_status()
        data = await resp.json()

    vulns = data.get("vulnerabilities")
    return vulns if isinstance(vulns, list) else []


async def fetch_cisa_kev_set(session: aiohttp.ClientSession) -> set[str]:
    async with session.get(CISA_KEV_URL) as resp:
        resp.raise_for_status()
        data = await resp.json()

    vulns = data.get("vulnerabilities", [])
    kev_ids: set[str] = set()

    if isinstance(vulns, list):
        for item in vulns:
            cve_id = item.get("cveID")
            if isinstance(cve_id, str):
                kev_ids.add(cve_id)

    return kev_ids


async def store_vulnerabilities(rows: Iterable[dict[str, Any]]) -> int:
    """
    Insert rows into SQLite without duplicates (unique cve_id).
    Returns count of attempted inserts (not necessarily committed rows if duplicates existed).
    """
    async with AsyncSessionLocal() as db:
        stmt = insert(VulnerabilityORM).values(list(rows)).on_conflict_do_nothing(
            index_elements=["cve_id"]
        )
        result = await db.execute(stmt)
        await db.commit()

    # SQLite rowcount is reliable enough for "inserted vs ignored" in many cases,
    # but can vary; treat it as best-effort telemetry.
    return int(getattr(result, "rowcount", 0) or 0)


async def main() -> None:
    await init_db()

    headers = {
        "User-Agent": "Triad-Scan/1.0",
    }

    # Optional: set NVD_API_KEY to increase rate limits (header name per NVD 2.0).
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        kev_ids = await fetch_cisa_kev_set(session)
        nvd_vulns = await fetch_nvd_critical_50(session)

    to_insert: list[dict[str, Any]] = []

    for v in nvd_vulns:
        cve_id = _extract_cve_id(v)
        if not cve_id:
            continue

        score = _extract_cvss_score(v)
        if score is None:
            continue

        to_insert.append(
            {
                "cve_id": cve_id,
                "cvss_score": score,
                "is_known_exploited": (cve_id in kev_ids),
            }
        )

    inserted = await store_vulnerabilities(to_insert)
    print(f"Prepared: {len(to_insert)} | Inserted (non-duplicate): {inserted}")


if __name__ == "__main__":
    asyncio.run(main())
