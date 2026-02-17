from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, List, Tuple
import re


# ---------- Data Contracts (lightweight, no DB coupling) ----------

@dataclass(frozen=True)
class Asset:
    id: int
    cpe_string: str
    confidentiality: int
    integrity: int
    availability: int


@dataclass(frozen=True)
class Vulnerability:
    id: int
    cve_id: str
    cvss_score: float
    is_known_exploited: bool
    affected_cpes: Sequence[str]  # pulled from NVD per-CVE (not required to be stored yet)


@dataclass(frozen=True)
class RemediationItem:
    asset_id: int
    asset_cpe: str
    cve_id: str
    cvss_score: float
    kev: bool
    cia_avg: float
    risk_score: float
    nist_category: str
    match_basis: str  # short explanation for audit trail


# ---------- CPE correlation ----------

_CPE_PREFIX = "cpe:2.3:"


def _norm_cpe(cpe: str) -> str:
    cpe = cpe.strip()
    return cpe.lower()


def _split_cpe23(cpe: str) -> Optional[List[str]]:
    """
    Returns CPE 2.3 fields (part, vendor, product, version, ...).
    If not CPE 2.3, return None.
    """
    cpe = _norm_cpe(cpe)
    if not cpe.startswith(_CPE_PREFIX):
        return None
    fields = cpe[len(_CPE_PREFIX):].split(":")
    # CPE 2.3 normally has 11 components after prefix; accept shorter defensively
    return fields if len(fields) >= 3 else None


def cpe_correlates(asset_cpe: str, vuln_cpe: str) -> Tuple[bool, str]:
    """
    Practical matching for v1:
    - Exact match
    - Vendor+Product match (same v/p), and version wildcarding permitted:
      If either side has version '*' or '-' treat as wildcard
      Else versions must match
    """
    a = _split_cpe23(asset_cpe)
    v = _split_cpe23(vuln_cpe)
    if not a or not v:
        return False, "non-cpe23"

    # Fields: part(0), vendor(1), product(2), version(3)...
    if _norm_cpe(asset_cpe) == _norm_cpe(vuln_cpe):
        return True, "exact"

    if a[1] != v[1] or a[2] != v[2]:
        return False, "vendor_product_mismatch"

    a_ver = a[3] if len(a) > 3 else "*"
    v_ver = v[3] if len(v) > 3 else "*"

    wild = {"*", "-"}
    if a_ver in wild or v_ver in wild:
        return True, "vendor_product_wild_version"

    if a_ver == v_ver:
        return True, "vendor_product_version_match"

    return False, "version_mismatch"


# ---------- Scoring ----------

def risk_score(cvss: float, c: int, i: int, a: int, kev: bool) -> float:
    cia_avg = (c + i + a) / 3.0
    bonus = 20.0 if kev else 0.0
    return (cvss * cia_avg) + bonus


# ---------- NIST CSF 2.0 mapping ----------

def nist_category_for_match(vuln: Vulnerability) -> str:
    """
    v1 mapping (audit-safe):
    - All matches represent a Risk Assessment activity => ID.RA
    You can expand later (e.g., PR.IP, DE.CM, RS.MI) with additional signals.
    """
    return "ID.RA"


# ---------- Engine ----------

def build_ranked_remediation_list(
    assets: Iterable[Asset],
    vulns: Iterable[Vulnerability],
) -> List[RemediationItem]:
    items: List[RemediationItem] = []

    for asset in assets:
        for vuln in vulns:
            # correlate against any affected CPE in that CVE
            matched = False
            basis = "no_match"
            for vcpe in vuln.affected_cpes:
                ok, why = cpe_correlates(asset.cpe_string, vcpe)
                if ok:
                    matched = True
                    basis = why
                    break

            if not matched:
                continue

            cia_avg = (asset.confidentiality + asset.integrity + asset.availability) / 3.0
            score = risk_score(
                cvss=vuln.cvss_score,
                c=asset.confidentiality,
                i=asset.integrity,
                a=asset.availability,
                kev=vuln.is_known_exploited,
            )

            items.append(
                RemediationItem(
                    asset_id=asset.id,
                    asset_cpe=asset.cpe_string,
                    cve_id=vuln.cve_id,
                    cvss_score=vuln.cvss_score,
                    kev=vuln.is_known_exploited,
                    cia_avg=cia_avg,
                    risk_score=round(score, 2),
                    nist_category=nist_category_for_match(vuln),
                    match_basis=basis,
                )
            )

    # Ranked Remediation List: highest business impact first
    items.sort(key=lambda x: (x.risk_score, x.cvss_score), reverse=True)
    return items
