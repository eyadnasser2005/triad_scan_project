import asyncio
from typing import Dict, List

from triad_scan.db import AsyncSessionLocal, AssetORM, VulnerabilityORM
from triad_scan.engine import Asset, Vulnerability, build_ranked_remediation_list


async def load_assets() -> List[Asset]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(AssetORM.__table__.select())).fetchall()
    return [
        Asset(
            id=r.id,
            cpe_string=r.cpe_string,
            confidentiality=r.confidentiality,
            integrity=r.integrity,
            availability=r.availability,
        )
        for r in rows
    ]


async def load_vulns_with_cpes(affected_cpes_by_cve: Dict[str, List[str]]) -> List[Vulnerability]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(VulnerabilityORM.__table__.select())).fetchall()

    vulns = []
    for r in rows:
        vulns.append(
            Vulnerability(
                id=r.id,
                cve_id=r.cve_id,
                cvss_score=r.cvss_score,
                is_known_exploited=r.is_known_exploited,
                affected_cpes=affected_cpes_by_cve.get(r.cve_id, []),
            )
        )
    return vulns


async def main():
    # You will pass in the per-CVE affected CPE list from your NVD parsing step.
    # Example placeholder:
    affected_cpes_by_cve = {
        # "CVE-2024-12345": ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"]
    }

    assets = await load_assets()
    vulns = await load_vulns_with_cpes(affected_cpes_by_cve)

    ranked = build_ranked_remediation_list(assets, vulns)

    for item in ranked[:25]:
        print(
            f"{item.risk_score:>6} | {item.nist_category} | "
            f"{item.cve_id} | KEV={item.kev} | CVSS={item.cvss_score} | "
            f"Asset#{item.asset_id} | {item.match_basis}"
        )


if __name__ == "__main__":
    asyncio.run(main())
