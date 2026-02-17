import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Tuple

import matplotlib.pyplot as plt
import numpy as np
from fpdf import FPDF  # fpdf2 recommended

from triad_scan.db import AsyncSessionLocal, AssetORM, VulnerabilityORM
from triad_scan.engine import (
    Asset,
    Vulnerability,
    RemediationItem,
    build_ranked_remediation_list,
)

REPORT_TITLE = "Triad-Scan: Vulnerability Remediation Plan"

# Optional: produced by your NVD ingestion step (recommended).
# Format: {"CVE-2024-12345": ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", ...], ...}
AFFECTED_CPES_PATH = os.path.join("triad_scan", "affected_cpes.json")


# -------------------- Helpers: Load DB + CPE map --------------------

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


async def load_vulns(affected_cpes_by_cve: Dict[str, List[str]]) -> List[Vulnerability]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(VulnerabilityORM.__table__.select())).fetchall()
    return [
        Vulnerability(
            id=r.id,
            cve_id=r.cve_id,
            cvss_score=r.cvss_score,
            is_known_exploited=r.is_known_exploited,
            affected_cpes=affected_cpes_by_cve.get(r.cve_id, []),
        )
        for r in rows
    ]


def load_affected_cpes_map() -> Dict[str, List[str]]:
    if not os.path.exists(AFFECTED_CPES_PATH):
        return {}
    with open(AFFECTED_CPES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    # defensive normalization
    out: Dict[str, List[str]] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, list):
                out[k] = [x for x in v if isinstance(x, str)]
    return out


# -------------------- Risk model for heatmap --------------------

def compute_likelihood(item: RemediationItem) -> float:
    """
    Likelihood proxy (0..10):
    - base = CVSS (already 0..10)
    - add +2 if KEV, capped at 10
    """
    lk = float(item.cvss_score) + (2.0 if item.kev else 0.0)
    return min(10.0, lk)


def compute_impact(item: RemediationItem) -> float:
    """
    Impact proxy (0..10):
    - CIA average already in 1..10
    """
    return float(item.cia_avg)


def to_bucket(x: float) -> int:
    """
    0=Low, 1=Medium, 2=High
    """
    if x < 4.0:
        return 0
    if x < 7.0:
        return 1
    return 2


def incident_response_phase(item: RemediationItem) -> str:
    """
    Simple, audit-friendly mapping:
    - Highest urgency: KEV & high risk => Containment
    - High risk but not KEV => Identification
    - Medium risk => Eradication (patching/removal)
    - Low risk => Recovery (hardening / validation)
    """
    # risk_score can be >100 due to CIA scaling + KEV bonus
    if item.kev and item.risk_score >= 70:
        return "Containment"
    if item.risk_score >= 70:
        return "Identification"
    if item.risk_score >= 40:
        return "Eradication"
    return "Recovery"


# -------------------- Heatmap generation --------------------

def generate_heatmap_png(items: List[RemediationItem], out_path: str) -> None:
    """
    3x3 heatmap: Impact vs Likelihood, counting findings.
    Rows: Impact (Low..High), Cols: Likelihood (Low..High)
    """
    grid = np.zeros((3, 3), dtype=int)

    for it in items:
        imp = to_bucket(compute_impact(it))
        lk = to_bucket(compute_likelihood(it))
        grid[imp, lk] += 1

    fig = plt.figure()
    ax = fig.add_subplot(111)
    im = ax.imshow(grid, origin="lower")  # low-low bottom-left

    ax.set_xticks([0, 1, 2])
    ax.set_yticks([0, 1, 2])
    ax.set_xticklabels(["Low", "Medium", "High"])
    ax.set_yticklabels(["Low", "Medium", "High"])
    ax.set_xlabel("Likelihood")
    ax.set_ylabel("Impact")
    ax.set_title("Risk Heatmap (Impact vs Likelihood)")

    # annotate counts
    for i in range(3):
        for j in range(3):
            ax.text(j, i, str(grid[i, j]), ha="center", va="center")

    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)


# -------------------- PDF (FPDF) --------------------

class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, REPORT_TITLE, ln=True, align="C")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def build_pdf(
    out_pdf: str,
    heatmap_png: str,
    ranked: List[RemediationItem],
    generated_at: str,
    top_n: int = 10,
) -> None:
    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Executive summary
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0,
        6,
        (
            f"Generated: {generated_at}\n"
            f"Findings (ranked matches): {len(ranked)}\n"
            "Scoring: Risk = (CVSS × ((C+I+A)/3)) + (20 if KEV)\n"
            "NIST CSF 2.0 mapping: ID.RA (Risk Assessment) for each correlated finding."
        ),
    )
    pdf.ln(2)

    # Heatmap
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Risk Heatmap", ln=True)
    pdf.ln(2)
    # Fit image to page width with margins
    img_w = 180
    pdf.image(heatmap_png, w=img_w)
    pdf.ln(4)

    # Top risks table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Top {min(top_n, len(ranked))} Risks (Ranked Remediation List)", ln=True)
    pdf.ln(1)

    # Table header
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(28, 6, "Risk", border=1)
    pdf.cell(30, 6, "CVE", border=1)
    pdf.cell(16, 6, "CVSS", border=1)
    pdf.cell(14, 6, "KEV", border=1)
    pdf.cell(18, 6, "CIA Avg", border=1)
    pdf.cell(30, 6, "NIST", border=1)
    pdf.cell(54, 6, "IR Phase", border=1, ln=True)

    pdf.set_font("Helvetica", "", 9)
    for it in ranked[:top_n]:
        pdf.cell(28, 6, f"{it.risk_score:.2f}", border=1)
        pdf.cell(30, 6, it.cve_id, border=1)
        pdf.cell(16, 6, f"{it.cvss_score:.1f}", border=1)
        pdf.cell(14, 6, "Yes" if it.kev else "No", border=1)
        pdf.cell(18, 6, f"{it.cia_avg:.2f}", border=1)
        pdf.cell(30, 6, it.nist_category, border=1)
        pdf.cell(54, 6, incident_response_phase(it), border=1, ln=True)

    pdf.ln(4)

    # Notes / audit trail
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Analyst Notes (Audit-Ready)", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0,
        6,
        (
            "• Correlation basis: CPE 2.3 string matching (exact match or vendor/product match with version wildcards).\n"
            "• Likelihood proxy: CVSS (+2 if KEV, capped at 10).\n"
            "• Impact proxy: CIA average of the target asset.\n"
            "• Recommended workflow: execute Containment for KEV + highest-risk items, then Eradication (patch/remove), then validation."
        ),
    )

    pdf.output(out_pdf)


# -------------------- Main --------------------

async def main() -> None:
    affected = load_affected_cpes_map()
    assets = await load_assets()
    vulns = await load_vulns(affected)

    ranked = build_ranked_remediation_list(assets, vulns)

    # If correlation data is missing, ranked may be empty; still create a report.
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    heatmap_path = os.path.join("reports", "triad_scan_heatmap.png")
    pdf_path = os.path.join("reports", "Triad-Scan_Vulnerability_Remediation_Plan.pdf")

    generate_heatmap_png(ranked, heatmap_path)
    build_pdf(pdf_path, heatmap_path, ranked, generated_at=ts, top_n=10)

    print(f"Report created: {pdf_path}")


if __name__ == "__main__":
    asyncio.run(main())
