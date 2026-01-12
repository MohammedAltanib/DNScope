# DNScope 🔍

![Banner](images/banner2.png)

A Python tool for analysing **DNS Internet Background Radiation (IBR)** from PCAP/PCAPNG files. Built as part of the **Bachelor Project (C8 – Noroff University, Cyber Security)** using **Cloud Telescope** datasets.
---
# DNS-in-IBR — Processing log (concise)

**Author:** Mohammed Altanib

**One-line summary:** Decrypted/unzipped PCAPs → temporary CSVs → Parquet files → now merging ~21k Parquet files. Two scripts used.

## Steps
1. **Decrypted / unzipped** raw archive (`cloud_telescope_raw_dataset_3.zip`) → `/mnt/data/dataset3_full/e3/`  
2. **Extracted DNS** to temporary CSVs using `tshark` → `/tmp/dns_fast_8xjoxii_/dns_*.csv`  
3. **Converted CSV → Parquet** with `csv_to_parquet_addcols.py` (adds `src_24`, `eTLD+1`) → `/mnt/data/dataset3_parquet/e3/dns_*.parquet`  
4. **Merging now:** merging ~21k Parquet files into unified dataset using two scripts (conversion + merge).
5. **Analyse the complete required parquet file.
 
## Core scripts
- `fast_extract.py` — pcap → CSV (tshark)
- `csv_to_parquet_addcols.py` — CSV → Parquet (adds analysis columns)
- merge step executed with the provided merge script (batch Parquet merger)

**Note:** Schema consistency and disk space checked before final merge.

## How to use?

##0 python3 -m venv ~/your-dir/venv2
source ~/your-dir/venv2/bin/activate
pip install -r requirements.txt

##1 fast_extract.py ( this code is turning your ZIP file into CSV

##2 csv_to_parquet_addcols.py ( this code is turning your CSV file into parquet " check the code and modify as you please ")

##3 merge.py ( this code is merging all parquet into 1 )

##4 dnscope_mini_figs.py ( this code is extracting all the results from the 1 parquet file and creating figures " modify as you please ")

## Anaconda-path
You can use another way to get the results for each questions
below I will share what i personally used for each qeustions
