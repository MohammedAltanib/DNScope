# DNScope 🔍

![Banner](images/ban.png)

A Python tool for analysing **DNS Internet Background Radiation (IBR)** from PCAP/PCAPNG files. Built as part of the **Bachelor Project in Cyber Security at Noroff University College** using the [Cloud Telescope](https://doi.org/10.21227/zkyy-gk56) dataset.

**Author:** Mohammed Altanib

---

## Overview

DNScope extracts, structures, and analyses DNS traffic from raw passive packet captures. The pipeline converts compressed PCAPs into a unified Parquet dataset and produces visualisations and summary tables for three research questions.

| RQ  | Question |
|-----|----------|
| RQ1 | DNS share of IBR across regions and time |
| RQ2 | Dominant query types and response codes |
| RQ3 | Source networks and geographic distribution |

---

## Pipeline

```
ZIP/PCAP -> CSV (tshark) -> Parquet -> Merged Parquet -> Results
```

1. **Decrypt and unzip** raw archive into individual PCAP files
2. **Extract DNS** fields to temporary CSV files using tshark
3. **Convert CSV to Parquet** using `csv_to_parquet_addcols.py`, which adds `src_24` and `eTLD+1` columns
4. **Merge** all Parquet files into one unified dataset using `merge.py`
5. **Analyse** the merged Parquet file using the research-question scripts and/or `Results.py`

---

## Scripts

| Script | Purpose |
|--------|---------|
| `fast_extract.py` | PCAP/ZIP to CSV via tshark |
| `csv_to_parquet_addcols.py` | CSV to Parquet with `src_24` and `eTLD+1` |
| `merge.py` | Merge all Parquet files into one |
| `Results.py` | Combined analysis workflow used during development |
| `dnscope_mini_figs.py` | Generate figures from merged Parquet |
| `RQ1.py` | DNS share analysis (RQ1) |
| `RQ2.py` | Query and response structure analysis (RQ2) |
| `RQ3.py` | Source network and geographic analysis (RQ3) |

---

## Research Question Scripts

The original analysis was developed in `Results.py` and in the accompanying Jupyter Notebook.

For clarity and artefact review, the RQ2 and RQ3 logic has also been separated into standalone scripts:

- `RQ2.py`: reproduces the DNS query/response structure analysis, including QTYPE, RCODE, queries vs responses, and top eTLD+1 domains.
- `RQ3.py`: reproduces the source network and geographic analysis, including source /24 prefixes and country-level GeoIP mapping.

For RQ3 country-level results, the external MaxMind database file `GeoLite2-Country.mmdb` is required and should be placed in the project root before running the script.

---

## Jupyter Notebook

A Jupyter Notebook is also included as supporting material. It contains the working analysis notes and shows the analysis process used during the project from start to finish.

The standalone Python scripts are provided for reproducibility and artefact review, while the notebook documents the exploratory workflow.

---

## How to Use

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python fast_extract.py
python csv_to_parquet_addcols.py
python merge.py

python RQ1.py
python RQ2.py
python RQ3.py

python Results.py
```

---

## Usage in Jupyter / Anaconda

```python
from Results import dnscope_mini

results = dnscope_mini(
    src="e3_merged.parquet",
    out="run_out",
    topn=20,
    show=True
)

daily       = results["daily"]           # RQ1: daily DNS counts
regional    = results["regional_daily"]  # RQ1: per-region counts
qtype_rcode = results["qtype_rcode"]     # RQ2: QTYPE x RCODE
daily_any   = results["daily_any"]       # RQ2: ANY share per day
top_src24   = results["top_src24"]       # RQ3: top /24 prefixes
top_etld1   = results["top_etld1"]       # RQ3: top domains
```

---

## Output

```
run_out/
├── tables/
│   ├── daily_global.csv         RQ1 - DNS events per day
│   ├── regional_daily.csv       RQ1 - per-region daily counts
│   ├── qtype_rcode.csv          RQ2 - QTYPE x RCODE counts
│   ├── daily_any.csv            RQ2 - ANY query share per day
│   ├── top_src24.csv            RQ3 - top /24 source prefixes
│   └── top_etld1.csv            RQ3 - top eTLD+1 domains
└── figs/
    ├── daily_dns.png            RQ1 - daily DNS events
    ├── regional_daily_*.png     RQ1 - per-region charts
    ├── qtype_rcode_heatmap.png  RQ2 - QTYPE x RCODE heatmap
    ├── daily_any_pct.png        RQ2 - ANY share over time
    ├── top_src24.png            RQ3 - top /24 bar chart
    └── top_etld1.png            RQ3 - top domains bar chart
```

---

## Dataset

Developed and tested using the [Cloud Telescope IBR Dataset](https://doi.org/10.21227/zkyy-gk56), collected between October 2023 and March 2024 across 26 AWS regions, comprising 530 million packets.

Large raw PCAP files are not included in this repository because of file size and privacy limitations.

---

## Requirements

See `requirements.txt` for the full list of dependencies.

Main libraries:

- `duckdb`
- `pandas`
- `matplotlib`
- `pyarrow`
- `tldextract`
- `geoip2`

For RQ3 country-level mapping, `GeoLite2-Country.mmdb` is required as an external GeoIP database.

---

## License

MIT License - see `LICENSE` for details.
