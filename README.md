# Triad-Scan

Triad-Scan is a small Python project that pulls live CVE data from NIST, checks it against CISA’s Known Exploited Vulnerabilities list, matches those vulnerabilities to assets using CPE strings, calculates a CIA-weighted risk score, and generates a ranked remediation PDF.

This is meant to show practical vulnerability management automation and risk prioritization aligned to NIST CSF 2.0 (ID.RA – Risk Assessment).

---

# Quick Start (5 Minutes)

You do **not** need to add your own assets.
The project includes a simple seeding script so you can test everything immediately.

## 1) Requirements

* Python 3.10+
* Internet connection

## 2) Clone and Install

```bash
git clone https://github.com/eyadnasser2005/triad-scan.git
cd triad-scan
```

Create a virtual environment and install dependencies:

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

# Run the Demo

### Step 1 — Seed Example Assets

This adds a couple of example CPE-based assets with CIA weights.

```bash
python -m triad_scan.seed_assets
```

You do not need to modify anything.

---

### Step 2 — Fetch Live CVEs + KEV Data

```bash
python -m triad_scan.fetch_live
```

This:

* Pulls the latest 50 CRITICAL CVEs
* Cross-checks them against the CISA KEV catalog
* Stores them in SQLite (no duplicates)

---

### Step 3 — Generate the Report

```bash
python -m triad_scan.report
```

Open:

```
reports/Triad-Scan_Vulnerability_Remediation_Plan.pdf
```

That’s it.

---

# What the Report Shows

* Ranked remediation list (highest business risk first)
* CIA-weighted scoring
* KEV bonus for known exploited vulnerabilities
* NIST CSF 2.0 mapping (ID.RA)
* Incident Response phase mapping (Identification, Containment, etc.)
* Risk heatmap (Impact vs Likelihood)

---

# How Risk Is Calculated

Risk = (CVSS × ((C + I + A) / 3)) + 20 (if KEV)

* CVSS = technical severity
* CIA weights = business impact (1–10 per asset)
* KEV bonus = real-world exploitation signal

---

# Optional: Use Your Own Assets

If desired, you can edit:

```
triad_scan/seed_assets.py
```

Replace the example CPE strings with your own software inventory and rerun:

```bash
python -m triad_scan.seed_assets
```

---

# Verify It Worked

To check the database:

```bash
python -m triad_scan.check_db
```

To confirm duplicates are prevented:

```bash
python -m triad_scan.fetch_live
python -m triad_scan.fetch_live
```

The second run should insert 0 or near 0 new CVEs.

---

# Summary

Triad-Scan demonstrates:

* Live vulnerability ingestion
* KEV enrichment
* CPE-based attack surface correlation
* Quantitative risk scoring
* NIST CSF alignment
* Incident Response support
* Professional remediation reporting

