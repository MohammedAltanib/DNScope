# DNScope 🔍

![Banner](images/banner2.png)

A Python tool for analyzing **DNS Internet Background Radiation (IBR)** from PCAP/PCAPNG files. Built as part of the **Bachelor Project (C8 – Noroff University, Cyber Security)** using **Cloud Telescope** datasets.
---
# DNS-in-IBR — Processing log (concise)

**Author:** Mohammed Altanib

**One-line summary:** Decrypted/unzipped PCAPs → temporary CSVs → Parquet files → now merging ~21k Parquet files. Two scripts used.

## Steps
1. **Decrypted / unzipped** raw archive (`cloud_telescope_raw_dataset_3.zip`) → `/mnt/data/dataset3_full/e3/`  
2. **Extracted DNS** to temporary CSVs using `tshark` → `/tmp/dns_fast_8xjoxii_/dns_*.csv`  
3. **Converted CSV → Parquet** with `csv_to_parquet_addcols.py` (adds `src_24`, `eTLD+1`) → `/mnt/data/dataset3_parquet/e3/dns_*.parquet`  
4. **Merging now:** merging ~21k Parquet files into unified dataset using two scripts (conversion + merge).

## Core scripts
- `fast_extract.py` — pcap → CSV (tshark)
- `csv_to_parquet_addcols.py` — CSV → Parquet (adds analysis columns)
- merge step executed with provided merge script (batch Parquet merger)

**Note:** Schema consistency and disk space checked before final merge.


